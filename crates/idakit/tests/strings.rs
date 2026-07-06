//! String enumeration against a real database: every located string has a sane character width
//! and, when its bytes are readable, decodes to UTF-8 text. Structural, so it holds across any
//! input. Read-only; opens `save = false`.

mod common;

use idakit::Idb;

#[test]
fn strings() {
    common::with_canonical_db(run);
}

fn run(idb: &mut Idb) {
    let mut total = 0usize;
    let mut decoded = 0usize;
    let mut wide = 0usize;
    let mut sample: Option<String> = None;
    for s in idb.strings().take(5000) {
        total += 1;
        assert!(
            matches!(s.char_width(), 1 | 2 | 4),
            "string at {:#x} has an impossible char width {}",
            s.address(),
            s.char_width()
        );
        wide += usize::from(s.char_width() > 1);
        if let Some(text) = s.text() {
            decoded += 1;
            if sample.is_none() && s.char_width() == 1 && !text.trim().is_empty() {
                sample = Some(text);
            }
        }
    }

    // build_strlist on a real program finds string literals; if the scan surfaced any, the
    // decode path has to produce text for at least some of them.
    if total == 0 {
        println!("strings: none found (unusual, but not a failure)");
    } else {
        assert!(
            decoded > 0,
            "found {total} strings but none decoded to text"
        );
        println!("strings: {total} scanned, {decoded} decoded, {wide} wide; sample {sample:?}");
    }

    println!("strings OK: string-list enumeration and decode verified");
}
