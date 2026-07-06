//! Process-level side effects of kernel bring-up: idakit forces idalib into headless mode
//! and (later) snapshots signals / routes console output. Each case asserts the guarantee
//! holds after `Ida::run` brings the kernel up; nextest's per-test process isolation keeps
//! the process-global env from leaking between cases.

use assert2::assert;
use idakit::kernel::Ida;
use idakit_sys::idakit_get_batch;

/// Bring-up sets `TVHEADLESS=1` so libidalib never attempts GUI/Qt init.
#[test]
fn bring_up_sets_headless_env() {
    Ida::run(|_ida| ()).expect("kernel init failed");
    assert!(std::env::var("TVHEADLESS").as_deref() == Ok("1"));
}

/// Default bring-up enables IDA's `batch` global (headless prompt/dialog suppression).
#[test]
fn batch_defaults_on() {
    Ida::run(|_ida| ()).expect("kernel init failed");
    // SAFETY: reads the `batch` global after bring-up on the kernel thread.
    assert!(unsafe { idakit_get_batch() } == 1);
}

/// The `batch(false)` builder flag leaves IDA interactive.
#[test]
fn batch_flag_disables() {
    Ida::new()
        .batch(false)
        .run(|_ida| ())
        .expect("kernel init failed");
    // SAFETY: reads the `batch` global after bring-up on the kernel thread.
    assert!(unsafe { idakit_get_batch() } == 0);
}
