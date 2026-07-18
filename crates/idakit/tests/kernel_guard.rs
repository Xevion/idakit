//! Enforces that every `Database` method reaching a live kernel re-points `g_main` first.
//!
//! `Database` is `Send`: a single-owner kernel handle that moves between threads. Soundness rests
//! on every kernel-touching call running `claim::ensure_kernel_thread` first, which re-steals
//! `g_main` when the database has migrated. That guard is placed by hand at each direct-`sys::`
//! site (the `raw.rs` firewall and its `forward!` macro cover the rest), so a new `Database` method
//! that calls the FFI directly could ship without it, sound only until a database actually moves,
//! when a deadlock or crash follows.
//!
//! This kernel-free source scan closes that gap. `Database` is the crate's only `Send` type, so it
//! is the only receiver that can migrate; a `sys::` call on any other (`!Send`) view or handle
//! cannot have moved since the guarded `Database` leaf that produced it. The rule is therefore
//! exactly: every method in an `impl Database` block whose body calls a bare `idakit_sys` kernel
//! function must also call `ensure_kernel_thread`, or appear in [`GUARD_ALLOW`] because a guarded
//! `Database` method it calls first already covers the thread. Kernel-free source (the `*_ids`
//! facade-alignment emitters, pure flag tests) lives in `#[cfg(test)]` free functions, never in an
//! `impl Database`, so it is out of scope by construction.
//!
//! Two things are deliberately not a reach. The guard layer itself ([`EXCLUDED`]: `raw.rs`, the
//! `forward!` macro, `claim.rs`) is skipped, since that is where each wrapper's guard is decided,
//! and its hand-written facade-state readers (`was_trapped`, `qerrno`) touch no `g_main`-gated
//! function. And a three-segment `sys::FlagType::empty()` is a pure value constructor on a
//! sys-defined flag or enum type, not a kernel call, so only a two-segment `sys::snake_case_fn`
//! counts.

use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// `impl Database` methods that reach `sys::` yet carry no local guard, because a guarded
/// `Database` method they call first already re-pointed `g_main` on this thread.
const GUARD_ALLOW: &[&str] = &[
    // Reaches `sys::tinfo_named` only after `self.type_named` (guarded), so the thread is claimed.
    "type_ref",
];

/// Guard-layer files skipped by the scan: `raw.rs` (the FFI firewall and its `forward!` entries,
/// where each wrapper's guard is decided and facade-state readers touch no `g_main`), `macros.rs`
/// (defines `forward!`, which bakes the guard in), and `claim.rs` (the guard itself).
const EXCLUDED: &[&str] = &["raw.rs", "macros.rs", "claim.rs"];

/// The crate's `src/` tree, read once as `(path, text)` pairs, sorted for stable diagnostics.
fn sources() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    collect_rs(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let text =
                fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            (p, text)
        })
        .collect()
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| EXCLUDED.contains(&n))
        {
            out.push(path);
        }
    }
}

/// Whether `ty`'s final path segment is `Database`, so a method on it has a `Send` receiver.
///
/// Matches both the inherent `impl Database` and any `impl Trait for Database`, since a trait
/// method (a `Drop`, say) runs on whatever thread holds the database and can migrate too.
fn is_database(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Database"))
}

/// The dotted path segments of a call target, e.g. `["sys", "cfg_build"]`, or `None` when the
/// callee is not a plain path (a method call, a closure invocation).
fn call_segments(call: &syn::ExprCall) -> Option<Vec<String>> {
    let syn::Expr::Path(p) = &*call.func else {
        return None;
    };
    Some(
        p.path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect(),
    )
}

/// Scans one method body for a kernel reach (an `idakit_sys` call) and a guard (an
/// `ensure_kernel_thread` call), recursing through closures and nested blocks.
#[derive(Default)]
struct BodyScan {
    reaches_kernel: bool,
    has_guard: bool,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(segs) = call_segments(node) {
            // A bare kernel function is `sys::snake_case_fn` (two segments). A three-segment
            // `sys::FlagType::empty()` constructs a sys-defined flag/enum value and touches no
            // kernel, so it must not count as a reach.
            if segs.len() == 2
                && matches!(segs[0].as_str(), "sys" | "idakit_sys")
                && segs[1].starts_with(|c: char| c.is_ascii_lowercase())
            {
                self.reaches_kernel = true;
            }
            if segs.last().map(String::as_str) == Some("ensure_kernel_thread") {
                self.has_guard = true;
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// Flags `impl Database` methods that reach the kernel but never guard.
struct GuardCheck<'a> {
    path: &'a Path,
    on_database: bool,
    violations: &'a mut Vec<String>,
}

impl<'ast> Visit<'ast> for GuardCheck<'_> {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let outer = self.on_database;
        self.on_database = is_database(&node.self_ty);
        syn::visit::visit_item_impl(self, node);
        self.on_database = outer;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !self.on_database {
            return;
        }
        let mut scan = BodyScan::default();
        scan.visit_block(&node.block);
        let name = node.sig.ident.to_string();
        if scan.reaches_kernel && !scan.has_guard && !GUARD_ALLOW.contains(&name.as_str()) {
            self.violations.push(format!(
                "{}: Database::{name} calls idakit_sys directly but never runs \
                 ensure_kernel_thread(); a migrated database would touch the kernel on the wrong \
                 thread",
                self.path.display()
            ));
        }
    }
}

/// Every `impl Database` method that reaches the FFI runs the migration guard first.
#[test]
fn database_kernel_methods_are_guarded() {
    let mut violations = Vec::new();
    for (path, src) in sources() {
        let file =
            syn::parse_file(&src).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        GuardCheck {
            path: &path,
            on_database: false,
            violations: &mut violations,
        }
        .visit_file(&file);
    }
    assert!(
        violations.is_empty(),
        "every Database method that calls idakit_sys must first run \
         claim::ensure_kernel_thread(); Database is Send, so it may have migrated threads. Add the \
         guard, or if a guarded Database method it calls first already claims the thread, add the \
         method to GUARD_ALLOW:\n{}",
        violations.join("\n")
    );
}
