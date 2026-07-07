//! Hidden harness for runnable doctests.
//!
//! [`with_db`] resolves the canonical corpus fixture, opens a disposable copy on the kernel
//! thread, runs the closure, and closes without saving. When no corpus is configured it returns
//! `Ok(())` without touching the kernel, so a doctest runs where a database is present and passes
//! (skips) everywhere else. Doctests reach it through hidden `#` lines, so the marshalling never
//! shows in the rendered example.
//!
//! Fixture resolution mirrors the integration suite: a git-ignored `.env` points
//! `IDAKIT_CORPUS_MANIFEST` at a manifest, and its `[corpus].canonical` names the one database
//! used. (This duplicates a slice of `tests/common`; folding the two onto this module is a
//! follow-up.)

use std::path::{Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::Deserialize;

use crate::error::Result;
use crate::prelude::{Database, Ida};

/// Open the canonical corpus fixture on the kernel thread, run `f` against it, and close it
/// without saving.
///
/// Returns `Ok(())` without bringing up the kernel when no corpus is configured, so a doctest
/// passes on a machine with no database. The fixture is copied to a scratch directory first
/// (idalib locks an open `.i64`), and the copy is deleted when this returns.
pub fn with_db(f: impl FnOnce(&mut Database) -> Result<()> + Send + 'static) -> Result<()> {
    let Some(source) = canonical() else {
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

/// The manifest-designated canonical fixture, or `None` when no corpus is configured or the
/// entry names no openable file.
fn canonical() -> Option<PathBuf> {
    let (manifest, root) = parse()?;
    let target = manifest.corpus?.canonical?;
    manifest
        .fixture
        .into_iter()
        .find(|e| e.path == target && e.opens.runnable())
        .map(|e| root.join(&e.path))
        .filter(|p| p.is_file())
}

static LOAD_ENV: Once = Once::new();

/// Load the `.env`, locate the manifest, and parse it alongside its parent directory (the root
/// fixture paths are relative to). `None` when no corpus is configured or the manifest is missing
/// or malformed.
fn parse() -> Option<(Manifest, PathBuf)> {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    let manifest = manifest_path()?;
    let text = std::fs::read_to_string(&manifest).ok()?;
    let parsed = toml::from_str::<Manifest>(&text).ok()?;
    let root = manifest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    Some((parsed, root))
}

fn manifest_path() -> Option<PathBuf> {
    let raw = std::env::var("IDAKIT_CORPUS_MANIFEST").ok()?;
    let path = PathBuf::from(raw);
    (!path.as_os_str().is_empty() && path.is_file()).then_some(path)
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    corpus: Option<Corpus>,
    #[serde(default)]
    fixture: Vec<Entry>,
}

#[derive(Deserialize)]
struct Corpus {
    canonical: Option<String>,
}

#[derive(Deserialize)]
struct Entry {
    path: String,
    #[serde(default)]
    opens: Opens,
}

/// `opens` is a bool for 64-bit fixtures and the string `"parked"` for 32-bit ones this build
/// can't open yet, so it deserializes as either shape. Only the bool `true` case is openable.
#[derive(Deserialize)]
#[serde(untagged)]
enum Opens {
    Bool(bool),
    // The manifest carries the word (e.g. "parked"); the value itself is never inspected here.
    Word(#[allow(dead_code)] String),
}

impl Default for Opens {
    fn default() -> Self {
        Opens::Bool(false)
    }
}

impl Opens {
    fn runnable(&self) -> bool {
        matches!(self, Opens::Bool(true))
    }
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
