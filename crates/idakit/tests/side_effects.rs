//! Process-level side effects of kernel bring-up: idakit forces idalib into headless mode
//! and (later) snapshots signals / routes console output. Each case asserts the guarantee
//! holds after `Ida::run` brings the kernel up; nextest's per-test process isolation keeps
//! the process-global env from leaking between cases.

use assert2::assert;
use idakit::kernel::Ida;
use idakit_sys::get_batch;
use rstest::rstest;

/// Bring-up sets `TVHEADLESS=1` so libidalib never attempts GUI/Qt init.
#[test]
fn bring_up_sets_headless_env() {
    Ida::run(|_ida| ()).expect("kernel init failed");
    assert!(std::env::var("TVHEADLESS").as_deref() == Ok("1"));
}

/// Omitting `.batch(...)`/`.maybe_batch(...)` entirely takes the documented "batch on" default,
/// the same state [`batch_maybe_matches_expected`]'s `maybe_none_matches_omitted_default` case
/// reaches through `.maybe_batch(None)`.
#[test]
fn batch_omitted_defaults_on() {
    Ida::new().run(|_ida| ()).expect("kernel init failed");
    // SAFETY: reads the `batch` global after bring-up on the kernel thread.
    assert!(unsafe { get_batch() } == 1);
}

/// `.maybe_batch(None)` reaches the same "batch on" default as omitting the setter outright;
/// `.maybe_batch(Some(true))` reaches the identical state explicitly; `Some(false)` flips it off.
#[rstest]
#[case::maybe_none_matches_omitted_default(None, 1)]
#[case::maybe_some_true_matches_default(Some(true), 1)]
#[case::maybe_some_false_disables(Some(false), 0)]
fn batch_maybe_matches_expected(#[case] batch: Option<bool>, #[case] expected: std::ffi::c_int) {
    Ida::new()
        .maybe_batch(batch)
        .run(|_ida| ())
        .expect("kernel init failed");
    // SAFETY: reads the `batch` global after bring-up on the kernel thread.
    assert!(unsafe { get_batch() } == expected);
}
