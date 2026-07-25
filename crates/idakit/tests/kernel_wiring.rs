//! Source-scan guard: every test file under `tests/kernel/` is actually pulled into the harness.
//!
//! The harness enumerates its tests through `inventory`, which only sees a submission that linked
//! in, and a module linked in only because `tests/kernel.rs` names it with `#[path]`. So a new test
//! file that nobody wires up still compiles, registers nothing, runs nothing, and reports green,
//! which is the one failure mode a self-registering harness cannot notice by itself. This is the
//! outside view that can: the files on disk against the modules the binary declares.
//!
//! Kernel-free, so it runs under nextest like any other test.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use assert2::assert;

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Every `.rs` under `tests/kernel/`, as a path relative to `tests/` with forward slashes, which is
/// the spelling a `#[path]` attribute uses.
fn files_on_disk(dir: &Path, root: &Path, found: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).expect("tests/kernel is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            files_on_disk(&path, root, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let relative = path.strip_prefix(root).expect("under tests/");
            let mut spelling = String::new();
            for component in relative.components() {
                if !spelling.is_empty() {
                    spelling.push('/');
                }
                spelling.push_str(&component.as_os_str().to_string_lossy());
            }
            found.insert(spelling);
        }
    }
}

/// The paths `tests/kernel.rs` declares with `#[path = "..."]`.
fn paths_declared(source: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("#[path = \""))
        .filter_map(|rest| rest.split_once('"'))
        .map(|(path, _)| path.to_owned())
        .collect()
}

#[test]
fn every_kernel_test_file_is_wired_into_the_harness() {
    let tests = tests_dir();
    let mut on_disk = BTreeSet::new();
    files_on_disk(&tests.join("kernel"), &tests, &mut on_disk);
    assert!(!on_disk.is_empty(), "tests/kernel/ has no test files");

    let source = std::fs::read_to_string(tests.join("kernel.rs")).expect("tests/kernel.rs exists");
    let declared = paths_declared(&source);

    let unwired: Vec<&String> = on_disk.difference(&declared).collect();
    assert!(
        unwired.is_empty(),
        "these files are never linked into the harness, so their tests silently never run: \
         {unwired:?}\nadd a #[path] module for each in tests/kernel.rs"
    );

    let missing: Vec<&String> = declared.difference(&on_disk).collect();
    assert!(
        missing.is_empty(),
        "tests/kernel.rs names files that do not exist: {missing:?}"
    );
}

#[test]
fn declared_paths_are_recognised() {
    // The scan is textual, so it is worth pinning what it accepts against what the file writes.
    let source = "#[path = \"kernel/name.rs\"]\nmod name;\n    #[path = \"kernel/write/x.rs\"]\n";
    let declared = paths_declared(source);
    assert!(declared.contains("kernel/name.rs"));
    assert!(declared.contains("kernel/write/x.rs"));
    assert!(declared.len() == 2);
}
