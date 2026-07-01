//! Shared helpers for the kernel-touching integration tests.

use std::path::PathBuf;

/// The database an integration test should open, or `None` to skip.
///
/// `IDAKIT_TEST_DB` (an absolute `.i64`) wins when set. Otherwise fall back to
/// `$IDADIR/libida.so.i64` (IDADIR default `~/ida-pro-9.3`) when it exists -- the runtime's
/// own database is present wherever the build links, so the suite runs with no per-checkout
/// setup. `None` (skip) only when neither is available.
pub fn test_db() -> Option<String> {
    if let Ok(db) = std::env::var("IDAKIT_TEST_DB")
        && !db.is_empty()
    {
        return Some(db);
    }
    let idadir = std::env::var("IDADIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/ida-pro-9.3")
    });
    let path = PathBuf::from(idadir).join("libida.so.i64");
    path.exists().then(|| path.to_string_lossy().into_owned())
}
