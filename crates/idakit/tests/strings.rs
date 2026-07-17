//! String enumeration against a real database: every located string has a sane character width,
//! decodes to its known text, list order is address-ascending with no stuck cursor, and the
//! iterator stays exhausted (no `size_hint` underflow) once drained. Read-only; opens
//! `save = false`.

mod common;

use idakit::prelude::*;

#[test]
fn strings() {
    common::with_canonical_db(run);
}

// libstdc++'s null-construction guard message: baked into rodata by every build of the
// library, regardless of stripping, so it survives a fixture swap where a fixed address would not.
const ANCHOR_TEXT: &str = "basic_string: construction from null is not valid";

fn run(idb: &mut Database) {
    let mut strings = idb.strings();
    let mut total = 0usize;
    let mut decoded = 0usize;
    let mut wide = 0usize;
    let mut prev_address = None;
    let mut found_anchor = false;

    for s in &mut strings {
        total += 1;
        assert!(
            matches!(s.char_width(), 1 | 2 | 4),
            "string at {:#x} has an impossible char width {}",
            s.address(),
            s.char_width()
        );
        wide += usize::from(s.char_width() > 1);

        // IDA's string list is address-ascending; a stuck cursor repeats the previous address.
        assert!(
            prev_address.is_none_or(|prev| prev < s.address()),
            "string list is not strictly increasing at {:#x}",
            s.address()
        );
        prev_address = Some(s.address());

        if let Some(text) = s.text() {
            decoded += 1;
            if !found_anchor && text == ANCHOR_TEXT {
                found_anchor = true;
                assert!(
                    s.escaped().as_deref() == Some(ANCHOR_TEXT),
                    "anchor escaped mismatch: {:?}",
                    s.escaped()
                );
                assert!(
                    format!("{s:?}").contains(ANCHOR_TEXT),
                    "Debug impl dropped the decoded text"
                );
            }
        }
    }

    assert!(total > 0, "string list enumeration yielded nothing");
    assert!(
        found_anchor,
        "expected known string {ANCHOR_TEXT:?} not found in string list"
    );
    assert!(
        decoded > 0,
        "found {total} strings but none decoded to text"
    );

    // A fully drained iterator must stay exhausted, and its size_hint must not underflow past
    // zero if the cursor overshoots `count`.
    assert!(strings.next().is_none());
    assert!(strings.size_hint() == (0, Some(0)));

    println!("strings: {total} scanned, {decoded} decoded, {wide} wide");
    println!("strings OK: string-list enumeration and decode verified");
}
