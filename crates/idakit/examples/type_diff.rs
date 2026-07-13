//! Cross-database type diff: which named types two databases share, agree on, or disagree on.
//!
//! Resolves every named type in each database into an owned snapshot (which outlives the database
//! it came from), pairs the two sets by name, and classifies each shared type as identical (same
//! canonical key) or drifted (a structural diff). Useful for asking whether two binaries agree on a
//! shared library's ABI, or how a type changed between two revisions.
//!
//! Run: cargo run -p idakit --example type_diff -- path/to/a.i64 path/to/b.i64

use std::fmt::Write as _;

use idakit::prelude::*;

/// How many drifted types to list in the overview, and to expand in full below it.
const OVERVIEW: usize = 25;
const CLOSE_UP: usize = 6;
/// Cap the lines shown per expanded type, so a wholesale rework stays one screen. The diff renders
/// within `BUDGET`, folding a wide value onto its own lines rather than clipping it; the 4-space
/// indent the detail block adds keeps the whole line within a terminal width.
const MAX_LINES: usize = 12;
const BUDGET: usize = 84;
/// Column the type name is padded to in the overview.
const NAME_COL: usize = 36;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let a = args.next().expect("usage: type_diff <a.i64> <b.i64>");
    let b = args.next().expect("usage: type_diff <a.i64> <b.i64>");

    // One kernel, two databases opened in turn; `with_open` closes each once its catalog is taken.
    // A `TypeCatalog` is an owned, Send snapshot, so both survive their database for the diff.
    Ida::run(move |ida| -> Result<()> {
        ida.call(move |idb| -> Result<()> {
            let ca = idb.with_open(&a, |idb| Ok(idb.type_catalog()))?;
            let cb = idb.with_open(&b, |idb| Ok(idb.type_catalog()))?;
            report(&label(&a), &ca, &label(&b), &cb);
            Ok(())
        })?
    })??;

    println!("\nTYPE_DIFF OK");
    Ok(())
}

/// Diff two catalogs by name and print the shared/identical/drifted/unique breakdown, an overview
/// of the drifted types, and a full look at the smallest (most interpretable) drifts.
fn report(la: &str, a: &TypeCatalog, lb: &str, b: &TypeCatalog) {
    println!("Comparing named types across two databases");
    println!("  A  {la:<24} {} types", a.len());
    println!("  B  {lb:<24} {} types", b.len());

    let d = a.diff(b);
    println!();
    println!(
        "  shared {}    identical {}    drifted {}    A-only {}    B-only {}",
        d.shared(),
        d.identical().len(),
        d.drifted().len(),
        d.only_left().len(),
        d.only_right().len(),
    );
    if d.drifted().is_empty() {
        return;
    }

    // Fewest changes first: a two-field retype reads; a wholesale rework is just a count.
    let mut drifted: Vec<&(String, TypeDiff)> = d.drifted().iter().collect();
    drifted.sort_by_key(|(_, td)| td.len());

    println!("\ndrifted, fewest changes first   (+ added, - removed, ~ changed):");
    for (name, td) in drifted.iter().take(OVERVIEW) {
        println!("  {:<NAME_COL$}  {}", clip(name, NAME_COL), tally(td));
    }
    if drifted.len() > OVERVIEW {
        println!("  ... and {} more", drifted.len() - OVERVIEW);
    }

    println!("\ndetail ({} fewest-changed):", drifted.len().min(CLOSE_UP));
    for (name, d) in drifted.iter().take(CLOSE_UP) {
        println!("  {name}");
        let text = format!("{d:BUDGET$}");
        let lines: Vec<&str> = text.lines().collect();
        for line in lines.iter().take(MAX_LINES) {
            println!("    {line}");
        }
        if lines.len() > MAX_LINES {
            println!("    ... and {} more lines", lines.len() - MAX_LINES);
        }
    }
}

/// Truncate `s` to `max` characters, marking a cut with an ellipsis.
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        s.chars().take(max - 1).chain(['…']).collect()
    }
}

/// A one-line summary of a diff: `+added -removed ~changed` plus any size change.
fn tally(d: &TypeDiff) -> String {
    let mut parts: Vec<String> = Vec::new();
    if d.added() > 0 {
        parts.push(format!("+{}", d.added()));
    }
    if d.removed() > 0 {
        parts.push(format!("-{}", d.removed()));
    }
    if d.changed() > 0 {
        parts.push(format!("~{}", d.changed()));
    }
    let mut out = format!("{:<12}", parts.join(" "));
    if let Some((l, r)) = d.size_change() {
        let _ = write!(out, "size {} -> {}", hex(l), hex(r));
    }
    out.trim_end().to_owned()
}

/// An optional byte size as hex (`?` when unknown).
fn hex(size: Option<u64>) -> String {
    size.map_or_else(|| "?".to_owned(), |v| format!("{v:#x}"))
}

/// The file name of a path, for a compact label.
fn label(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map_or_else(|| path.to_owned(), |s| s.to_string_lossy().into_owned())
}
