//! Process-level side effects of kernel bring-up: idakit forces idalib into headless mode
//! and (later) snapshots signals / routes console output. Each case asserts the guarantee
//! holds after `Ida::run` brings the kernel up; nextest's per-test process isolation keeps
//! the process-global env from leaking between cases.

use assert2::assert;
use idakit::Ida;

/// Bring-up sets `TVHEADLESS=1` so libidalib never attempts GUI/Qt init.
#[test]
fn bring_up_sets_headless_env() {
    Ida::run(|_ida| ()).expect("kernel init failed");
    assert!(std::env::var("TVHEADLESS").as_deref() == Ok("1"));
}
