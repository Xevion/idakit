//! Manifest-driven corpus resolution shared by the doctest harness and the integration suite.
//!
//! The corpus is machine-specific and out-of-tree, so its location is not hardcoded: a git-ignored
//! `.env` (loaded automatically) sets `IDAKIT_CORPUS_MANIFEST` to the manifest path, and every
//! machine (and CI) provides its own. Absent the `.env` or manifest, [`fixtures`] returns empty and
//! [`canonical`] returns `None`, so callers skip with no cases to run.
//!
//! The manifest is the source of truth: each `[[fixture]]` gives a `path` (relative to the
//! manifest), whether it `opens` under our 64-bit build, an optional `skip_checks` list naming
//! invariants that legitimately do not apply (e.g. a raw ROM has no symbols), and an optional
//! `decompiler` flag (default `true`) declaring whether Hex-Rays covers this fixture's
//! architecture at all. Only openable fixtures are returned; unknown manifest fields are ignored.
//!
//! This module owns only the resolution and data model. The copy-destination policy stays with
//! each caller: [`working_copy`] copies beside the corpus (so large matrix fixtures under fan-out
//! never fill a RAM disk), whereas the doctest harness and single-DB tests copy to RAM.

#![cfg_attr(coverage_nightly, coverage(off))]

use std::path::{Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::Deserialize;

static LOAD_ENV: Once = Once::new();
static NEXT_COPY: AtomicU32 = AtomicU32::new(0);

/// A discovered fixture: a display name, its absolute path, the checks it opts out of, and
/// whether Hex-Rays covers its architecture.
pub struct Fixture {
    /// Display name, derived from the file stem (see [`display_name`]).
    pub name: String,
    /// Absolute path to the fixture on disk.
    pub path: PathBuf,
    /// Checks the manifest declares inapplicable to this fixture.
    pub skip_checks: Vec<String>,
    /// Whether Hex-Rays covers this fixture's architecture. Defaults to `true`: a fixture with
    /// no explicit `decompiler = false` is expected to decompile.
    pub decompiler: bool,
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
            decompiler: e.decompiler,
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

/// The first manifest fixture explicitly parked as unopenable under this 64-bit build
/// (`opens = "parked"`; today that means a 32-bit IDA1 `.idb`). `None` when no corpus is
/// configured or none is parked.
///
/// For fault-injection tests proving the 64-bit build rejects such a database with a real
/// error rather than a crash; not part of the corpus matrix's own fixture set.
#[must_use]
pub fn parked_fixture() -> Option<PathBuf> {
    let (parsed, root) = parse()?;
    parsed
        .fixture
        .into_iter()
        .find(|e| e.opens.parked())
        .map(|e| root.join(&e.path))
        .filter(|p| p.is_file())
}

/// Outcome of locating and parsing the corpus manifest: absent (nothing configured, every
/// caller skips), malformed (configured but broken, a real misconfiguration), or parsed
/// alongside the root every fixture `path` is relative to.
enum Loaded {
    NotConfigured,
    Malformed(String),
    Parsed(Manifest, PathBuf),
}

/// Load the `.env` and locate + parse the manifest, distinguishing "not configured" from
/// "configured but broken" so [`validate`] can fail loudly on the latter while [`parse`]'s
/// lenient callers keep skipping on either.
fn load() -> Loaded {
    LOAD_ENV.call_once(|| {
        let _ = dotenvy::dotenv();
    });
    let raw = match std::env::var("IDAKIT_CORPUS_MANIFEST") {
        Ok(raw) if !raw.is_empty() => raw,
        _ => return Loaded::NotConfigured,
    };
    let manifest = PathBuf::from(raw);
    if !manifest.is_file() {
        return Loaded::Malformed(format!(
            "IDAKIT_CORPUS_MANIFEST={manifest:?} does not point to a file"
        ));
    }
    let text = match std::fs::read_to_string(&manifest) {
        Ok(text) => text,
        Err(e) => return Loaded::Malformed(format!("failed to read {manifest:?}: {e}")),
    };
    let parsed = match toml::from_str::<Manifest>(&text) {
        Ok(parsed) => parsed,
        Err(e) => return Loaded::Malformed(format!("failed to parse {manifest:?}: {e}")),
    };
    let root = manifest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    Loaded::Parsed(parsed, root)
}

/// Locate and parse the manifest, returning it alongside its parent dir (the root every
/// fixture `path` is relative to). `None` when no corpus is configured *or* the manifest is
/// missing or malformed; callers that need to tell those apart use [`validate`] instead.
fn parse() -> Option<(Manifest, PathBuf)> {
    match load() {
        Loaded::Parsed(parsed, root) => Some((parsed, root)),
        Loaded::NotConfigured | Loaded::Malformed(_) => None,
    }
}

/// Validate the corpus configuration, distinguishing "nothing configured" from "configured but
/// broken".
///
/// [`fixtures`] and [`canonical`] both collapse every failure mode to an empty/`None` result, so
/// a caller that only checks those cannot tell a genuinely absent corpus (`IDAKIT_CORPUS_MANIFEST`
/// unset) from a misconfigured one (the variable points nowhere, the manifest is malformed TOML,
/// or it declares fixtures whose files do not exist). Both would otherwise run zero cases and
/// report success. Call this once at the top of a corpus-driven entry point and fail loudly on
/// `Err` instead of silently passing with no coverage.
///
/// # Errors
///
/// `Err` with a diagnostic message if `IDAKIT_CORPUS_MANIFEST` is set but: the path it names is
/// not a file, the file cannot be read, the TOML fails to parse, no `[[fixture]]` entry has
/// `opens = true`, an `opens = true` fixture's `path` does not resolve to a real file, or
/// `[corpus].canonical` names a path with no matching `opens = true` fixture.
pub fn validate() -> Result<(), String> {
    let (parsed, root) = match load() {
        Loaded::NotConfigured => return Ok(()),
        Loaded::Malformed(reason) => return Err(reason),
        Loaded::Parsed(parsed, root) => (parsed, root),
    };

    let openable: Vec<&Entry> = parsed
        .fixture
        .iter()
        .filter(|e| e.opens.runnable())
        .collect();
    if openable.is_empty() {
        return Err(format!(
            "corpus manifest at {root:?} declares {} fixture(s) but none have opens = true",
            parsed.fixture.len()
        ));
    }

    let missing: Vec<PathBuf> = openable
        .iter()
        .map(|e| root.join(&e.path))
        .filter(|p| !p.is_file())
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "corpus manifest declares {} openable fixture(s) whose file does not exist: {missing:?}",
            missing.len()
        ));
    }

    if let Some(canonical) = parsed.corpus.as_ref().and_then(|c| c.canonical.as_ref())
        && !openable.iter().any(|e| e.path == *canonical)
    {
        return Err(format!(
            "corpus manifest's [corpus].canonical = {canonical:?} names no opens = true fixture"
        ));
    }

    Ok(())
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
/// `Err` if the scratch dir cannot be created, the copy fails, or the copy cannot be made
/// writable.
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
    make_writable(&path)?;
    Ok(WorkingCopy { dir, path })
}

/// Clear the read-only bit [`std::fs::copy`] carries over from the source.
///
/// Masters are write-protected so a stray open of one fails loudly instead of silently unpacking
/// over the corpus. `fs::copy` preserves the mode, and idalib rewrites a database in place on
/// open, so the copy would fail to open without this.
///
/// # Errors
///
/// `Err` if the file's metadata or permissions cannot be set.
pub fn make_writable(path: &Path) -> std::io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = perms.mode();
        perms.set_mode(mode | 0o600);
    }
    #[cfg(not(unix))]
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(path, perms)
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
    #[serde(default = "default_decompiler")]
    decompiler: bool,
}

// Absent `decompiler` means "expected to decompile": a fixture that silently stops decompiling
// becomes a loud test failure rather than a vacuous pass.
fn default_decompiler() -> bool {
    true
}

/// `opens` is `true`/`false` for 64-bit fixtures and the string `"parked"` for 32-bit ones our
/// build can't open yet, so it deserializes as either shape. Only the bool `true` case is openable.
#[derive(Deserialize)]
#[serde(untagged)]
enum Opens {
    Bool(bool),
    Word(String),
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

    /// Whether the manifest explicitly parks this fixture (word value `"parked"`): a real
    /// database our 64-bit build declines to open, kept for fault-injection tests that assert
    /// the rejection rather than for the corpus matrix.
    fn parked(&self) -> bool {
        matches!(self, Self::Word(w) if w == "parked")
    }
}
