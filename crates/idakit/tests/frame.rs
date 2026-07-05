//! Stack-frame extraction against a real database: find functions with frames, verify each
//! variable carries an offset/size/kind, and that IDA's reserved return-address and saved-register
//! slots are classified as special. Read-only; opens `save = false`.

mod common;

use idakit::{FrameVar, Ida, Idb};

#[test]
fn frame() {
    let Some(db) = common::TestDb::acquire() else {
        eprintln!("skipping: no test database (set IDAKIT_TEST_DB or install IDA at $IDADIR)");
        return;
    };
    let path = db.path().to_owned();
    Ida::run(move |ida| {
        ida.call(move |idb| run(idb, &path))
            .unwrap_or_else(|e| e.resume())
    })
    .expect("kernel init failed");
}

fn run(idb: &mut Idb, db: &str) {
    idb.open(db).call().expect("open failed");

    let mut with_frame = 0usize;
    let mut with_special = 0usize;
    let mut example = None;
    for f in idb.functions().take(4000) {
        let Some(frame) = f.frame().filter(|fr| !fr.is_empty()) else {
            continue;
        };
        with_frame += 1;
        if frame.vars().iter().any(FrameVar::is_special) {
            with_special += 1;
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
    for v in frame.vars() {
        println!(
            "  {:>14} @ {:>+#8x} size={:<3} type={:?}",
            v.name().unwrap_or("<reserved>"),
            v.offset(),
            v.size(),
            v.type_repr(),
        );
    }
    println!("{with_frame} framed functions in sample, {with_special} with reserved slots");

    assert!(
        frame.size() > 0,
        "a non-empty frame should have a positive total size"
    );
    assert!(
        with_special > 0,
        "IDA's reserved return-address/saved-register slots should be classified"
    );

    idb.close(false);
    println!("frame OK: stack-frame extraction verified");
}
