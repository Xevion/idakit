//! The warm database each forked child inherits, bridged to test bodies through [`DbRef`].
//!
//! The daemon opens the database once and publishes a raw pointer to it before any fork; every
//! child inherits that pointer through copy-on-write and reaches the kernel through it. A child
//! touches the database only on its own (copied) main thread, the `g_main` owner, so the single
//! shared pointer is sound despite the `Send + !Sync` [`Database`] never being shared across live
//! threads.

use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

use idakit::Database;
use idakit::corpus::WorkingCopy;

/// The open database, published once by the daemon before it forks, read by each child.
static DATABASE: AtomicPtr<Database> = AtomicPtr::new(ptr::null_mut());

/// A borrowed handle to the warm database, injected into an rstest case through the `db` fixture.
///
/// A hand-written `#[kernel_test]` case reaches the same database through [`db_ref`] directly.
/// Access is scoped through [`with`](DbRef::with): the `&mut Database` lives only for the closure,
/// so it cannot escape or alias.
pub struct DbRef(*mut Database);

impl DbRef {
    /// Runs `f` against the warm database this child inherited, returning its result.
    ///
    /// The `&mut Database` is confined to `f`, which is why access is scoped rather than a returned
    /// borrow: two live `&mut` to the one shared database would alias. Do not nest `with` calls.
    ///
    /// # Panics
    /// If the daemon never published a database (a `DbRef` built outside a forked child).
    pub fn with<R>(&self, f: impl FnOnce(&mut Database) -> R) -> R {
        assert!(
            !self.0.is_null(),
            "no warm database published (not in a daemon child?)"
        );
        // SAFETY: the daemon publishes this pointer once before forking; a child dereferences it
        // only on its own main thread, and `f` holds the sole `&mut` for its scope.
        f(unsafe { &mut *self.0 })
    }
}

/// A [`DbRef`] to the warm database, the value behind the harness's `db` rstest fixture.
///
/// A test crate exposes the fixture with a one-line forwarder so rstest can inject it:
/// `#[fixture] fn db() -> DbRef { idakit_test::db_ref() }`.
#[must_use]
pub fn db_ref() -> DbRef {
    DbRef(DATABASE.load(Ordering::SeqCst))
}

/// Publishes the open database so the next fork's children can reach it. Called once by the daemon.
pub(crate) fn publish(database: &mut Database) {
    DATABASE.store(ptr::from_mut(database), Ordering::SeqCst);
}

/// Resolves the database the daemon opens: an explicit non-empty path argument, else a working copy
/// of the corpus canonical fixture.
///
/// The returned [`WorkingCopy`] (when a copy was made) must outlive the open database, since
/// dropping it deletes the file. `None` alongside the path means the caller passed an explicit path
/// that is opened in place.
///
/// # Panics
/// If no path was given and no corpus is configured, or the working copy cannot be made; the daemon
/// has nothing to serve in either case.
pub(crate) fn resolve(db_arg: Option<String>) -> (Option<WorkingCopy>, String) {
    if let Some(path) = db_arg.filter(|s| !s.is_empty()) {
        return (None, path);
    }
    let source =
        idakit::corpus::canonical().expect("no corpus configured (set IDAKIT_CORPUS_MANIFEST)");
    let working = idakit::corpus::working_copy(&source).expect("corpus working copy");
    let path = working.path().to_owned();
    (Some(working), path)
}
