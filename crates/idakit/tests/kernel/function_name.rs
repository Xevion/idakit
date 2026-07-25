//! Function-name classification against a real database: every function entry has a non-empty
//! name and classifies into exactly one of user/auto/dummy, so [`Function::name`] is honestly
//! non-optional. Read-only; opens `save = false`. Skips when no test database is present.

use idakit::prelude::*;
use idakit_runner_macros::kernel_test;

#[kernel_test(read_only)]
fn function_names_are_total() {
    crate::common::with_canonical_db(run);
}

// The tripwire behind dropping the `Option` from `name()`: sweep every function entry and
// assert it carries a non-empty name. Proven across the corpus (PE + ELF, 112k funcs), this
// fails loudly should a future or exotic database ever yield a nameless function head.
fn run(idb: &mut Database) {
    let (mut user, mut auto, mut dummy) = (0usize, 0usize, 0usize);
    let mut total = 0usize;
    for f in idb.functions() {
        let name = f.name();
        assert!(
            !name.is_empty(),
            "function {:#x} has an empty name",
            f.address().get()
        );
        match &name {
            FunctionName::User(text) => {
                user += 1;
                // Cross-invariant: a User name is an explicit label at that address, so the
                // whole-database name lookup must return exactly the same text.
                assert!(
                    idb.name(f.address()).as_deref() == Some(text.as_str()),
                    "Database::name disagrees with Function::name's User text at {:#x}",
                    f.address().get()
                );
            }
            FunctionName::Auto(_) => auto += 1,
            FunctionName::Dummy(_) => dummy += 1,
        }
        total += 1;
    }
    assert!(total > 0, "expected at least one function");

    println!("function names OK: {total} funcs, {user} user, {auto} auto, {dummy} dummy");
}
