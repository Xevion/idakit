//! Enforces the crate's `#[doc(alias)]` policy with two static source scans.
//!
//! Check A (validity) asserts every alias names a real SDK symbol, so an alias can never drift
//! into a facade or made-up name. Check B (completeness) asserts every public method that reaches
//! the kernel through the `raw.rs` firewall (`self.db.<forwarder>`) carries an alias, so a new
//! wrapper cannot ship without pointing an SDK reader at it.
//!
//! Both are kernel-free and run on every `just test`. Check A needs the SDK headers, whose dir
//! arrives as `IDA_SDK_INCLUDE` from `idakit-sys`'s build script; when it is unset (an unusual
//! build with no SDK) Check A skips rather than fails.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// Public methods that reach the kernel yet carry no alias by design, for one of two reasons: the
/// method name already *is* the SDK symbol (an alias would duplicate it, which clippy rejects), or
/// the value is a composite over several forwarders that each carry their own alias.
const COMPLETENESS_ALLOW: &[&str] = &[
    // Name already equals the SDK symbol.
    "next_head",
    "prev_head",
    "set_enum_width",
    "is_public_name",
    "is_weak_name",
    "sel",
    "color",
    "align",
    "comb",
    "flags",
    "has_external_refs",
    "has_jump_or_flow_xref",
    // Composite over many forwarders; no single SDK symbol.
    "info",
    "accept_eula",
];

/// Alias strings that are intentionally not SDK identifiers. Empty by policy: an alias that names
/// no SDK symbol is a defect, not an exception. Kept as the documented escape hatch.
const VALIDITY_ALLOW: &[&str] = &[];

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
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every string literal inside a `#[doc(alias(...))]` attribute in `src`, macro bodies included.
///
/// A hand rolled scan (not `syn`) so aliases written inside `macro_rules!` bodies, which `syn`
/// leaves as opaque tokens, are still validated.
fn alias_strings(src: &str) -> Vec<String> {
    const NEEDLE: &str = "doc(alias(";
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = src[i..].find(NEEDLE) {
        let mut j = i + rel + NEEDLE.len();
        let mut depth = 1i32;
        while j < bytes.len() && depth > 0 {
            match bytes[j] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                b'"' => {
                    let mut k = j + 1;
                    let mut lit = String::new();
                    while k < bytes.len() && bytes[k] != b'"' {
                        if bytes[k] == b'\\' && k + 1 < bytes.len() {
                            lit.push(bytes[k + 1] as char);
                            k += 2;
                        } else {
                            lit.push(bytes[k] as char);
                            k += 1;
                        }
                    }
                    out.push(lit);
                    j = k;
                }
                _ => {}
            }
            j += 1;
        }
        i = j;
    }
    out
}

/// Every C identifier declared anywhere in the SDK headers, or `None` when `IDA_SDK_INCLUDE` is
/// unset. Deliberately permissive (any identifier-shaped token, comments included): the goal is to
/// reject facade and typo names that appear nowhere in the SDK, not to model C++ scoping.
fn sdk_identifiers() -> Option<HashSet<String>> {
    let dir = option_env!("IDA_SDK_INCLUDE")?;
    let mut headers = Vec::new();
    collect_headers(Path::new(dir), &mut headers);
    let mut idents = HashSet::new();
    for header in headers {
        let text = fs::read_to_string(&header).unwrap_or_default();
        let mut cur = String::new();
        for ch in text.chars() {
            if ch == '_' || ch.is_ascii_alphanumeric() {
                cur.push(ch);
            } else if !cur.is_empty() {
                idents.insert(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            idents.insert(cur);
        }
    }
    Some(idents)
}

fn collect_headers(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_headers(&path, out);
        } else if path.extension().is_some_and(|e| e == "h" || e == "hpp") {
            out.push(path);
        }
    }
}

/// Check A: every `#[doc(alias)]` value names a real SDK symbol.
#[test]
fn every_alias_names_a_real_sdk_symbol() {
    let Some(idents) = sdk_identifiers() else {
        eprintln!("skipping: IDA_SDK_INCLUDE unset (no SDK headers to validate aliases against)");
        return;
    };
    let mut violations = Vec::new();
    for (path, src) in sources() {
        for alias in alias_strings(&src) {
            let leaf = alias.rsplit("::").next().unwrap_or(&alias);
            if leaf.is_empty() || idents.contains(leaf) || VALIDITY_ALLOW.contains(&alias.as_str())
            {
                continue;
            }
            violations.push(format!(
                "{}: alias {alias:?} (leaf `{leaf}`) is not an SDK identifier",
                path.display()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "every #[doc(alias)] must name a real SDK symbol; fix the name or, if it is genuinely \
         not an SDK identifier, add it to VALIDITY_ALLOW:\n{}",
        violations.join("\n")
    );
}

/// Whether `attr` is a `#[doc(alias(...))]`.
fn is_doc_alias(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("doc")
        && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string().contains("alias"))
}

/// Whether `expr` is exactly the field access `self.db`.
fn is_self_db(expr: &syn::Expr) -> bool {
    let syn::Expr::Field(field) = expr else {
        return false;
    };
    let syn::Member::Named(name) = &field.member else {
        return false;
    };
    name == "db" && matches!(&*field.base, syn::Expr::Path(p) if p.path.is_ident("self"))
}

/// Whether `expr` is the bare receiver `self`.
fn is_self(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::Path(p) if p.path.is_ident("self"))
}

/// Detects a call that crosses the kernel firewall: `self.db.<method>(...)` (a view over a
/// `&Database`), or `self.<forwarder>(...)` (a `Database` method calling one of `raw.rs`'s
/// `pub(crate)` forwarders).
struct KernelReach<'a> {
    forwarders: &'a HashSet<String>,
    found: bool,
}

impl<'ast> Visit<'ast> for KernelReach<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if is_self_db(&node.receiver)
            || (is_self(&node.receiver) && self.forwarders.contains(&node.method.to_string()))
        {
            self.found = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// The `pub(crate)` forwarder names in `raw.rs` (`fn name(&self` / `fn name(&mut self`), both the
/// hand-written wrappers and the `forward!` macro entries. Read from source, so the check tracks
/// `raw.rs` as it grows rather than hard-coding the set.
fn forwarders() -> HashSet<String> {
    let raw = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/raw.rs"))
        .expect("read raw.rs");
    let mut set = HashSet::new();
    for (idx, _) in raw.match_indices("fn ") {
        let rest = &raw[idx + 3..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && rest[name.len()..].trim_start().starts_with("(&") {
            set.insert(name);
        }
    }
    set
}

/// Flags public methods that reach the kernel but lack an alias.
struct Completeness<'a> {
    path: &'a Path,
    forwarders: &'a HashSet<String>,
    violations: &'a mut Vec<String>,
}

impl<'ast> Visit<'ast> for Completeness<'_> {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            let mut reach = KernelReach {
                forwarders: self.forwarders,
                found: false,
            };
            reach.visit_block(&node.block);
            let name = node.sig.ident.to_string();
            if reach.found
                && !node.attrs.iter().any(is_doc_alias)
                && !COMPLETENESS_ALLOW.contains(&name.as_str())
            {
                self.violations.push(format!(
                    "{}: pub fn {name} reaches the kernel but carries no #[doc(alias)]",
                    self.path.display()
                ));
            }
        }
        syn::visit::visit_impl_item_fn(self, node);
    }
}

/// Check B: every public method that reaches the kernel carries an alias.
#[test]
fn forwarding_methods_carry_an_alias() {
    let forwarders = forwarders();
    let mut violations = Vec::new();
    for (path, src) in sources() {
        let file =
            syn::parse_file(&src).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        Completeness {
            path: &path,
            forwarders: &forwarders,
            violations: &mut violations,
        }
        .visit_file(&file);
    }
    assert!(
        violations.is_empty(),
        "every public method that forwards to the kernel must carry a #[doc(alias)] naming the \
         SDK symbol it wraps; add one, or if it maps to no single symbol add it to \
         COMPLETENESS_ALLOW:\n{}",
        violations.join("\n")
    );
}
