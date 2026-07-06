//! Stack-frame extraction against a real database: find functions with frames, verify each
//! variable carries an offset/size/kind, and that IDA's reserved return-address and saved-register
//! slots are classified as special. Read-only; opens `save = false`.

mod common;

use idakit::prelude::*;

#[test]
fn frame() {
    common::with_canonical_db(run);
}

fn run(idb: &mut Database) {
    let mut with_frame = 0usize;
    let mut with_special = 0usize;
    let mut with_typed = 0usize;
    let mut example = None;
    for f in idb.functions().take(4000) {
        let Some(frame) = f.frame().expect("frame walk").filter(|fr| !fr.is_empty()) else {
            continue;
        };
        with_frame += 1;
        if frame.slots().iter().any(StackSlot::is_special) {
            with_special += 1;
        }
        if frame.slots().iter().any(|v| v.ty().is_some()) {
            with_typed += 1;
        }
        if example.is_none() {
            example = Some((f.address(), frame));
        }
    }

    assert!(
        with_frame > 0,
        "some function in the sample should have a stack frame"
    );
    let (address, frame) = example.expect("with_frame > 0 implies an example");

    println!(
        "example frame at {address:#x}: size={} vars={}",
        frame.size(),
        frame.len()
    );
    for v in frame.slots() {
        let shape = v.ty().map(|id| &frame.type_of(id).shape);
        println!(
            "  {:>14} @ {:>+#8x} size={:<3} ty={:?}",
            v.name().unwrap_or("<reserved>"),
            v.offset(),
            v.size(),
            shape,
        );
    }
    println!(
        "{with_frame} framed functions in sample, {with_special} with reserved slots, \
         {with_typed} with a structured-typed variable"
    );

    assert!(
        frame.size() > 0,
        "a non-empty frame should have a positive total size"
    );
    assert!(
        with_special > 0,
        "IDA's reserved return-address/saved-register slots should be classified"
    );
    assert!(
        with_typed > 0,
        "some frame variable in the sample should carry a structured type"
    );

    println!("frame OK: stack-frame extraction verified");
}
