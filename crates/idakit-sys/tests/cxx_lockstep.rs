//! Pins the whole `cxx` family to one generation, which the bridge's ABI depends on.
//!
//! `cxx-gen` writes the C++ half of each bridge and `cxxbridge-macro` the Rust half, both baking
//! their patch version into every symbol (`gen$cxxbridge1$197$...`). Moving one side alone still
//! builds, then fails at link. Kernel-free.

use std::collections::BTreeMap;

use assert2::assert;

/// `(package, version)` for every `cxx*` entry in a lockfile's text.
fn cxx_packages(lock: &str) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let mut name: Option<String> = None;
    for line in lock.lines() {
        if let Some(rest) = line.strip_prefix("name = \"") {
            let pkg = rest.trim_end_matches('"');
            name = pkg.starts_with("cxx").then(|| pkg.to_owned());
        } else if let Some(rest) = line.strip_prefix("version = \"")
            && let Some(pkg) = name.take()
        {
            found.insert(pkg, rest.trim_end_matches('"').to_owned());
        }
    }
    found
}

/// The generation every `cxx*` crate agrees on, or `None` when they disagree.
///
/// Only the patch number compares: `cxx-gen` tracks the family at `0.7.N`, the rest at `1.0.N`.
fn shared_generation(packages: &BTreeMap<String, String>) -> Option<String> {
    let mut generations = packages
        .values()
        .map(|v| v.rsplit('.').next().expect("version has a patch"));
    let first = generations.next()?.to_owned();
    generations.all(|g| g == first).then_some(first)
}

#[test]
fn cxx_crates_share_one_generation() {
    let lock = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock");
    let text = std::fs::read_to_string(lock).expect("read workspace Cargo.lock");
    let packages = cxx_packages(&text);

    assert!(!packages.is_empty(), "no cxx packages in the lockfile");
    assert!(
        shared_generation(&packages).is_some(),
        "cxx crates are out of lockstep: {packages:?}"
    );
}

#[test]
fn a_skewed_lockfile_is_rejected() {
    let skewed = "\
[[package]]
name = \"cxx\"
version = \"1.0.199\"

[[package]]
name = \"cxx-gen\"
version = \"0.7.197\"
";
    let packages = cxx_packages(skewed);
    assert!(packages.len() == 2);
    assert!(shared_generation(&packages).is_none());
}

#[test]
fn a_matched_lockfile_is_accepted() {
    let matched = "\
[[package]]
name = \"cxx\"
version = \"1.0.197\"

[[package]]
name = \"cxx-gen\"
version = \"0.7.197\"

[[package]]
name = \"serde\"
version = \"1.0.228\"
";
    let packages = cxx_packages(matched);
    assert!(packages.len() == 2, "only cxx packages are collected");
    assert!(shared_generation(&packages) == Some("197".to_owned()));
}
