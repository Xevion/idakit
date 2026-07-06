//! Shared helpers for the kernel-touching integration tests.
// Each test binary pulls in this whole module but uses only a subset of it.
#![allow(dead_code)]

pub mod checks;
pub mod corpus;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use idakit::{Ida, Idb};

/// Open the shared test database (see [`TestDb::source`]) on the kernel thread, run `body`
/// against it, and close it (`save = false`). Every dedicated single-DB test is this shape, so
/// the acquire, kernel bring-up, open, and panic-resume live here once. Silently returns (skips)
/// when no test database is available -- matching the corpus matrix's "no corpus, no cases"
/// stance -- and a caught assertion panic re-raises with its real message, so failures keep their
/// location.
pub fn with_canonical_db(body: impl FnOnce(&mut Idb) + Send + 'static) {
    let Some(db) = TestDb::acquire() else {
        return;
    };
    let path = db.path().to_owned();
    Ida::run(move |ida| {
        ida.call(move |idb| {
            idb.open(&path).call().expect("open failed");
            body(idb);
            idb.close(false);
        })
        .unwrap_or_else(|e| e.resume())
    })
    .expect("kernel init failed");
}

/// A private, disposable copy of the test database, removed on drop.
///
/// IDA takes an exclusive lock on a `.i64` while it is open, so every kernel test opens its
/// *own* copy via [`TestDb::acquire`] rather than the shared [`source`](TestDb::source) file
/// -- otherwise tests flake against a live GUI session and against each other. Hold the guard
/// for as long as the database is open; dropping it deletes the copy. Pass it straight to
/// [`Idb::open`](idakit::Idb::open) -- it is [`AsRef<str>`] -- or via [`path`](TestDb::path).
///
/// The conversion trait is `AsRef`, deliberately, not `From`/`Into`: a by-value `From<TestDb>`
/// would move the guard out and drop it, deleting the copy the caller is about to open.
pub struct TestDb {
    scratch: PathBuf,
    db: PathBuf,
}

impl TestDb {
    /// A private copy of the canonical [`source`](Self::source) database to open, or `None`
    /// to skip when no source exists.
    pub fn acquire() -> Option<Self> {
        Self::source().map(Self::copy_of)
    }

    /// The shared canonical database path: an explicit `IDAKIT_TEST_DB` override (an absolute
    /// `.i64`, rarely used), else the corpus manifest's [`canonical`](corpus::canonical) fixture
    /// -- the one binary the dedicated tests open, identical on every platform so their
    /// assertions never depend on the host. `None` when no corpus is configured, which skips the
    /// dedicated tests. Read this directly only for lock-free byte access (advisory locks don't
    /// block plain reads), e.g. a truncated fixture; to *open* a database, take a copy with
    /// [`acquire`](Self::acquire).
    pub fn source() -> Option<PathBuf> {
        if let Ok(db) = std::env::var("IDAKIT_TEST_DB")
            && !db.is_empty()
        {
            return Some(PathBuf::from(db));
        }
        corpus::canonical()
    }

    /// A private copy of `src` in a scratch dir, removed on drop. Panics if the source is
    /// present but the copy fails -- out of scratch space is a real error, not a skip.
    pub fn copy_of(src: impl AsRef<Path>) -> Self {
        let src = src.as_ref();
        let file_name = src.file_name().expect("source db has a file name");
        let unique = format!(
            "idakit-testdb-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );

        // Try each root in turn; on any failure (e.g. a RAM-backed dir out of space) drop the
        // partial copy and fall through to the next.
        let mut last_err = None;
        for root in scratch_roots() {
            let scratch = root.join(&unique);
            let db = scratch.join(file_name);
            if std::fs::create_dir_all(&scratch).is_err() {
                continue;
            }
            match std::fs::copy(src, &db) {
                Ok(_) => return Self { scratch, db },
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&scratch);
                    last_err = Some(e);
                }
            }
        }
        panic!("could not copy test db {src:?} into any scratch dir: {last_err:?}");
    }

    /// Path to the private copy, to hand to [`Idb::open`](idakit::Idb::open).
    #[must_use]
    pub fn path(&self) -> &str {
        self.db.to_str().expect("scratch db path is valid UTF-8")
    }
}

impl AsRef<str> for TestDb {
    fn as_ref(&self) -> &str {
        self.path()
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

/// Per-process suffix so several copies held at once never collide (`process::id` alone
/// isn't enough: one test may hold two).
static NEXT: AtomicU32 = AtomicU32::new(0);

/// Scratch roots in preference order. A RAM-backed dir avoids disk thrash when the platform
/// offers one at a well-known path (Linux `/dev/shm`); every other OS falls through to the
/// portable temp dir ([`std::env::temp_dir`] is `%TEMP%`/`$TMPDIR`), so nothing here is
/// Linux-only by dependency -- `/dev/shm` is just an opportunistic fast path. Override both
/// with `IDAKIT_TEST_SCRATCH`.
fn scratch_roots() -> Vec<PathBuf> {
    if let Ok(dir) = std::env::var("IDAKIT_TEST_SCRATCH")
        && !dir.is_empty()
    {
        return vec![PathBuf::from(dir)];
    }
    let mut roots = Vec::new();
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        roots.push(shm);
    }
    roots.push(std::env::temp_dir());
    roots
}
