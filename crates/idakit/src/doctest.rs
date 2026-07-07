//! Hidden harness for runnable doctests.
//!
//! [`with_db`] resolves the canonical corpus fixture (via [`crate::corpus::canonical`]), opens a
//! disposable copy on the kernel thread, runs the closure, and closes without saving. When no
//! corpus is configured it returns `Ok(())` without touching the kernel, so a doctest runs where a
//! database is present and passes (skips) everywhere else. Doctests reach it through hidden `#`
//! lines, so the marshalling never shows in the rendered example.
//!
//! The copy lands in a RAM-backed scratch dir (unlike the matrix's corpus-colocated
//! [`crate::corpus::working_copy`]): a doctest opens one small fixture, so RAM is the fast choice.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::Result;
use crate::prelude::{Database, Ida};

/// Open the canonical corpus fixture on the kernel thread, run `f` against it, and close it
/// without saving.
///
/// Returns `Ok(())` without bringing up the kernel when no corpus is configured, so a doctest
/// passes on a machine with no database. The fixture is copied to a scratch directory first
/// (idalib locks an open `.i64`), and the copy is deleted when this returns.
pub fn with_db(f: impl FnOnce(&mut Database) -> Result<()> + Send + 'static) -> Result<()> {
    let Some(source) = crate::corpus::canonical() else {
        return Ok(());
    };
    let copy = WorkingCopy::of(&source);
    let path = copy.path().to_owned();
    Ida::run(move |ida| {
        ida.call(move |db| {
            db.open(&path).call()?;
            let outcome = f(db);
            db.close(false);
            outcome
        })
        .unwrap_or_else(|e| e.resume())
    })
    .expect("doctest kernel bring-up failed")
}

/// A disposable copy of a fixture, removed on drop.
struct WorkingCopy {
    dir: PathBuf,
    path: PathBuf,
}

static NEXT: AtomicU32 = AtomicU32::new(0);

impl WorkingCopy {
    /// Copy `src` into a fresh scratch directory. Panics if the copy fails: a configured corpus
    /// with no scratch space is a real error, not a skip.
    fn of(src: &Path) -> Self {
        let unique = format!(
            "idakit-doctest-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let dir = scratch_root().join(unique);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        let file_name = src.file_name().expect("fixture has a file name");
        let path = dir.join(file_name);
        std::fs::copy(src, &path).expect("copy fixture into scratch");
        Self { dir, path }
    }

    fn path(&self) -> &str {
        self.path.to_str().expect("scratch path is valid UTF-8")
    }
}

impl Drop for WorkingCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Prefer a RAM-backed scratch dir (Linux `/dev/shm`) and fall back to the portable temp dir.
fn scratch_root() -> PathBuf {
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        return shm;
    }
    std::env::temp_dir()
}
