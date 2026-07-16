//! Asserts every `#[doc(alias)]` in this crate's hand-written source names a real SDK symbol.
//!
//! The mirror of `idakit`'s Check A, scoped to the flag and return-code layers here (`SegPerm`,
//! `FrameVarFlags`, ...). The generated `cxx`-bridge reexport aliases are not scanned: they are
//! stamped from the small, hand-verified `idakit-sys-codegen` `sdk_alias` map and are correct by
//! construction. Needs the SDK headers via `IDA_SDK_INCLUDE` (emitted by this crate's build
//! script); skips when they are absent.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Alias strings intentionally not SDK identifiers. Empty by policy; the documented escape hatch.
const VALIDITY_ALLOW: &[&str] = &[];

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

/// Every identifier-shaped token declared anywhere in the SDK headers, or `None` when
/// `IDA_SDK_INCLUDE` is unset.
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

#[test]
fn every_alias_names_a_real_sdk_symbol() {
    let Some(idents) = sdk_identifiers() else {
        eprintln!("skipping: IDA_SDK_INCLUDE unset (no SDK headers to validate aliases against)");
        return;
    };
    assert!(
        !idents.is_empty(),
        "IDA_SDK_INCLUDE is set but no identifiers were extracted from any header; the header \
         glob is broken and this check would pass vacuously"
    );

    let mut checked = 0usize;
    let mut violations = Vec::new();
    for (path, src) in sources() {
        for alias in alias_strings(&src) {
            checked += 1;
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
        checked > 0,
        "no #[doc(alias(...))] attributes were found under src/; the source glob is broken and \
         this check would pass vacuously"
    );
    assert!(
        violations.is_empty(),
        "every #[doc(alias)] must name a real SDK symbol; fix the name or, if it is genuinely \
         not an SDK identifier, add it to VALIDITY_ALLOW:\n{}",
        violations.join("\n")
    );
}

#[cfg(test)]
mod parser_tests {
    use assert2::assert;
    use rstest::rstest;

    use super::alias_strings;

    #[rstest]
    #[case::single(r#"#[doc(alias("FOO"))]"#, &["FOO"])]
    #[case::multiple(r#"#[doc(alias("FOO", "BAR", "BAZ"))]"#, &["FOO", "BAR", "BAZ"])]
    #[case::none("no attribute here", &[])]
    #[case::two_attrs(
        r#"#[doc(alias("A"))] struct X; #[doc(alias("B"))] struct Y;"#,
        &["A", "B"]
    )]
    #[case::qualified(r#"#[doc(alias("netnode::altval"))]"#, &["netnode::altval"])]
    fn extracts_every_literal(#[case] src: &str, #[case] expect: &[&str]) {
        let found = alias_strings(src);
        let found: Vec<&str> = found.iter().map(String::as_str).collect();
        assert!(found == expect);
    }
}
