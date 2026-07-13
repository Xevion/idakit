//! Manifest-driven corpus resolution shared by the doctest harness and the integration suite.
//!
//! The corpus is machine-specific and out-of-tree, so its location is not hardcoded: a git-ignored
//! `.env` (loaded automatically) sets `IDAKIT_CORPUS_MANIFEST` to the manifest path, and every
//! machine (and CI) provides its own. Absent the `.env` or manifest, [`fixtures`] returns empty and
//! [`canonical`] returns `None`, so callers skip with no cases to run.
//!
//! The manifest is the source of truth: each `[[fixture]]` gives a `path` (relative to the
//! manifest), whether it `opens` under our 64-bit build, and an optional `skip_checks` list naming
//! invariants that legitimately do not apply (e.g. a raw ROM has no symbols). Only openable
//! fixtures are returned; unknown manifest fields are ignored.
//!
//! This module owns only the resolution and data model. The copy-destination policy stays with
//! each caller: [`working_copy`] copies beside the corpus (so large matrix fixtures under fan-out
//! never fill a RAM disk), whereas the doctest harness and single-DB tests copy to RAM.

use std::path::{Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::Deserialize;

static LOAD_ENV: Once = Once::new();
static NEXT_COPY: AtomicU32 = AtomicU32::new(0);

/// A discovered fixture: a display name, its absolute path, and the checks it opts out of.
pub struct Fixture {
    /// Display name, derived from the file stem (see [`display_name`]).
    pub name: String,
    /// Absolute path to the fixture on disk.
    pub path: PathBuf,
    /// Checks the manifest declares inapplicable to this fixture.
    pub skip_checks: Vec<String>,
}

impl Fixture {
    /// Whether `check` is declared inapplicable to this fixture in the manifest.
    #[must_use]
    pub fn skips(&self, check: &str) -> bool {
        self.skip_checks.iter().any(|c| c == check)
    }
}

/// Every openable fixture in the manifest, resolved to an absolute path and sorted by name.
/// Empty when no corpus is configured.
#[must_use]
pub fn fixtures() -> Vec<Fixture> {
    let Some((parsed, root)) = parse() else {
        return Vec::new();
    };
    let mut out: Vec<Fixture> = parsed
        .fixture
        .into_iter()
        .filter(|e| e.opens.runnable())
        .map(|e| Fixture {
            name: display_name(&e.path),
            path: root.join(&e.path),
            skip_checks: e.skip_checks,
        })
        .filter(|f| f.path.is_file())
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The manifest-designated canonical fixture: the one deterministic database the dedicated
/// single-DB tests and doctests open.
///
/// Identical on every platform, so their assertions never depend on which binary a host happens
/// to carry. `None` when no corpus is configured, no `[corpus].canonical` is set, or it names no
/// openable fixture.
#[must_use]
pub fn canonical() -> Option<PathBuf> {
    let (parsed, root) = parse()?;
    let target = parsed.corpus?.canonical?;
    parsed
        .fixture
        .into_iter()
        .find(|e| e.path == target && e.opens.runnable())
        .map(|e| root.join(&e.path))
        .filter(|p| p.is_file())
}

/// Load the `.env`, locate the manifest, and parse it, returning it alongside its parent dir
/// (the root every fixture `path` is relative to). `None` when no corpus is configured or the
/// manifest is missing or malformed.
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

/// A private, disposable copy of a fixture, removed on drop. idalib mutates a database in place
/// and locks it, so every case opens its own copy rather than the read-only master.
pub struct WorkingCopy {
    dir: PathBuf,
    path: PathBuf,
}

impl WorkingCopy {
    /// Path to the copy, to hand to `Database::open`.
    #[must_use]
    pub fn path(&self) -> &str {
        self.path.to_str().expect("scratch path is valid UTF-8")
    }
}

impl Drop for WorkingCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Copy `src` into a scratch dir co-located with the corpus.
///
/// This keeps large fixtures off a RAM-backed `/tmp` or `/dev/shm` (which would compete with the
/// kernel's working set under fan-out). The location is derived from the manifest, not hardcoded
/// or configured.
///
/// # Errors
///
/// `Err` if the scratch dir cannot be created or the copy fails.
pub fn working_copy(src: &Path) -> std::io::Result<WorkingCopy> {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        NEXT_COPY.fetch_add(1, Ordering::Relaxed)
    );
    let dir = scratch_root().join(unique);
    std::fs::create_dir_all(&dir)?;
    let file_name = src.file_name().expect("fixture has a file name");
    let path = dir.join(file_name);
    std::fs::copy(src, &path)?;
    Ok(WorkingCopy { dir, path })
}

fn scratch_root() -> PathBuf {
    manifest_path()
        .and_then(|m| m.parent().map(|p| p.join(".scratch")))
        .unwrap_or_else(std::env::temp_dir)
}

/// A fixture's display name: its file stem with `.` replaced by `_` so it reads as one identifier.
#[must_use]
pub fn display_name(rel: &str) -> String {
    Path::new(rel).file_stem().map_or_else(
        || "unknown".into(),
        |s| s.to_string_lossy().replace('.', "_"),
    )
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    corpus: Option<Corpus>,
    #[serde(default)]
    fixture: Vec<Entry>,
}

/// The manifest's global `[corpus]` table. Only the fields the callers consume are modeled.
#[derive(Deserialize)]
struct Corpus {
    /// Relative `path` of the one fixture the dedicated single-DB tests open (see [`canonical`]).
    canonical: Option<String>,
}

#[derive(Deserialize)]
struct Entry {
    path: String,
    #[serde(default)]
    opens: Opens,
    #[serde(default)]
    skip_checks: Vec<String>,
}

/// `opens` is `true`/`false` for 64-bit fixtures and the string `"parked"` for 32-bit ones our
/// build can't open yet, so it deserializes as either shape. Only the bool `true` case is openable.
#[derive(Deserialize)]
#[serde(untagged)]
enum Opens {
    Bool(bool),
    // The manifest carries the word (e.g. "parked"); the value itself is never inspected here.
    Word(#[allow(dead_code)] String),
}

impl Default for Opens {
    fn default() -> Self {
        Self::Bool(false)
    }
}

impl Opens {
    fn runnable(&self) -> bool {
        matches!(self, Self::Bool(true))
    }
}
