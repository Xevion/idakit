//! The `Ida::new()` kernel builder: configured bring-up terminating in `run()` / `here()`,
//! with plain `Ida::run` / `Ida::here` staying as the zero-config shortcuts.

use assert2::assert;
use idakit::kernel::Ida;
use rstest::rstest;

/// Omitting `.stack_size(...)`/`.maybe_stack_size(...)` entirely brings the kernel up
/// successfully on the documented 8 MiB default, the same outcome
/// [`stack_size_maybe_succeeds`]'s `maybe_none_matches_omitted` case reaches through
/// `.maybe_stack_size(None)`.
#[test]
fn new_run_returns_closure_value() {
    let out = Ida::new().run(|_ida| 7).expect("kernel init failed");
    assert!(out == 7);
}

#[test]
fn new_run_honors_stack_size() {
    let out = Ida::new()
        .stack_size(16 << 20)
        .run(|_ida| 9)
        .expect("kernel init failed");
    assert!(out == 9);
}

/// `.maybe_stack_size(None)` reaches the same successful bring-up as omitting the setter
/// outright (see [`new_run_returns_closure_value`]); `Some(8 << 20)` explicitly requests the
/// documented default, and a larger custom value still succeeds.
#[rstest]
#[case::maybe_none_matches_omitted(None)]
#[case::explicit_documented_default(Some(8 << 20))]
#[case::larger_custom_size(Some(32 << 20))]
fn stack_size_maybe_succeeds(#[case] stack_size: Option<usize>) {
    let out = Ida::new()
        .maybe_stack_size(stack_size)
        .run(|_ida| 11)
        .expect("kernel init failed");
    assert!(out == 11);
}

#[test]
fn new_here_brings_up_kernel() {
    // here() runs init on the calling thread, which must own an ample stack (~3 MiB+);
    // nextest's test thread is too small, so drive it from a thread sized like the kernel's.
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(|| {
            // here() hands back the !Send Database bound to this thread; dropping it releases the kernel.
            let idb = Ida::new().here().expect("kernel init failed");
            drop(idb);
        })
        .expect("spawn")
        .join()
        .expect("here thread panicked");
}
