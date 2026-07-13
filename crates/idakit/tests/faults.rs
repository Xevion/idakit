//! Fault injection: feed `open` bad and corrupt inputs and assert the kernel rejects each
//! with an `Err` while the process survives to run the assertion. nextest isolates every test
//! in its own process, so a kernel fatal that escapes the facade's traps (a crash, an
//! `abort`, or a deadlock hitting the `slow-timeout`) surfaces as that one test failing.
//!
//! The bad-input cases here need no database fixture; the corrupt-copy cases gate on
//! [`common::TestDb::source`] and skip without it.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use assert2::assert;
use idakit::prelude::*;

mod common;

/// A throwaway file under the temp dir, deleted on drop. The kernel tests run serially
/// (the `serial-kernel` nextest group), so a fixed per-test name cannot collide.
struct Scratch(PathBuf);

impl Scratch {
    /// Write `bytes` to a fresh temp file named `name`.
    fn new(name: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(name);
        fs::write(&path, bytes).expect("write scratch file");
        Self(path)
    }

    /// The first `len` bytes of `src`, a header-truncated database. Reads only the prefix,
    /// never the whole (potentially huge) source.
    fn truncated(name: &str, src: impl AsRef<Path>, len: usize) -> Self {
        let mut file = fs::File::open(src).expect("open source db");
        let mut buf = vec![0u8; len];
        let n = file.read(&mut buf).expect("read source prefix");
        buf.truncate(n);
        Self::new(name, &buf)
    }

    fn path(&self) -> String {
        self.0.to_str().expect("utf-8 temp path").to_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Open `path` and assert the kernel rejected it with an `Err` (rather than succeeding or
/// killing the process). Runs as the kernel job body so the test stays at one indent level.
fn open_is_rejected(idb: &mut Database, path: &str) {
    let result = idb.open(path).call();
    assert!(result.is_err(), "open of {path:?} should be rejected");
}

/// Drive `open_is_rejected` against `path` on the kernel thread.
fn assert_open_rejected(path: String) {
    Ida::run(move |ida| {
        ida.call(move |idb| open_is_rejected(idb, &path))
            .unwrap_or_else(|e| e.resume());
    })
    .expect("kernel init failed");
}

#[test]
fn nonexistent_path_is_rejected() {
    let missing = std::env::temp_dir().join("idakit-faults-missing.i64");
    assert_open_rejected(missing.to_string_lossy().into_owned());
}

#[test]
fn empty_file_is_rejected() {
    let scratch = Scratch::new("idakit-faults-empty.i64", b"");
    assert_open_rejected(scratch.path());
}

#[test]
fn garbage_bytes_are_rejected() {
    let scratch = Scratch::new("idakit-faults-garbage.i64", &[0xABu8; 4096]);
    assert_open_rejected(scratch.path());
}

#[test]
fn directory_path_is_rejected() {
    assert_open_rejected(std::env::temp_dir().to_string_lossy().into_owned());
}

/// A Java class newer than IDA's loader supports (major 69 = Java 25) is rejected through the
/// `msg()` channel, which in headless routes to a no-op sink and never reaches stderr. The
/// `KernelExit` diagnostic must still carry the loader's reason. It was `None` while only the
/// stderr channel was captured.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "the rejection makes idalib exit(); trapping it needs the Linux-only exit trap"
)]
fn unsupported_java_class_reports_reason() {
    // Minimal class file: magic, minor=0, major=69, a one-entry constant pool, then zeroed
    // section counts, enough for IDA's Java loader to recognize the format and reject the version.
    const TOO_NEW_CLASS: &[u8] = &[
        0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x45, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let scratch = Scratch::new("idakit-faults-toonew.class", TOO_NEW_CLASS);
    let path = scratch.path();
    Ida::run(move |ida| {
        ida.call(move |idb| {
            let err = idb
                .open(&path)
                .call()
                .expect_err("too-new class should be rejected");
            assert!(let Error::KernelExit { diagnostic, .. } = &err);
            let diag = diagnostic.as_deref().unwrap_or("");
            assert!(
                diag.contains("Java file format"),
                "KernelExit diagnostic should carry the loader reason, got {diagnostic:?}"
            );
        })
        .unwrap_or_else(|e| e.resume());
    })
    .expect("kernel init failed");
}

#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "a corrupt-header database makes idalib call exit(); trapping that needs the \
              GOT-redirect exit trap, which is Linux-only (elsewhere the process just exits)"
)]
fn truncated_database_is_rejected() {
    let Some(db) = common::TestDb::source() else {
        return;
    };
    let scratch = Scratch::truncated("idakit-faults-truncated.i64", &db, 4096);
    assert_open_rejected(scratch.path());
}
