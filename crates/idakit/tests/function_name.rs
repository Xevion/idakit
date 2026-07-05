//! Function-name classification against a real database: every function entry has a non-empty
//! name and classifies into exactly one of user/auto/dummy, so [`Function::name`] is honestly
//! non-optional. Read-only; opens `save = false`. Skips when no test database is present.

mod common;

use idakit::{FunctionName, Idb};

#[test]
fn function_names_are_total() {
    let Some(db) = common::TestDb::acquire() else {
        eprintln!("skipping: no test database (set IDAKIT_TEST_DB or install IDA at $IDADIR)");
        return;
    };
    let path = db.path().to_owned();
    idakit::Ida::run(move |ida| {
        ida.call(move |idb| run(idb, &path))
            .unwrap_or_else(|e| e.resume())
    })
    .expect("kernel init failed");
}

// The tripwire behind dropping the `Option` from `name()`: sweep every function entry and
// assert it carries a non-empty name. Proven across the corpus (PE + ELF, 112k funcs), this
// fails loudly should a future or exotic database ever yield a nameless function head.
fn run(idb: &mut Idb, db: &str) {
    idb.open(db).call().expect("open failed");

    let (mut user, mut auto, mut dummy) = (0usize, 0usize, 0usize);
    let mut total = 0usize;
    for f in idb.functions() {
        let name = f.name();
        assert!(
            !name.is_empty(),
            "function {:#x} has an empty name",
            f.address().get()
        );
        match name {
            FunctionName::User(_) => user += 1,
            FunctionName::Auto(_) => auto += 1,
            FunctionName::Dummy(_) => dummy += 1,
        }
        total += 1;
    }
    assert!(total > 0, "expected at least one function");

    idb.close(false);
    println!("function names OK: {total} funcs -- {user} user, {auto} auto, {dummy} dummy");
}
