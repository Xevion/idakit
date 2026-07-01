//! The `Ida::new()` kernel builder: configured bring-up terminating in `run()` / `here()`,
//! with plain `Ida::run` / `Ida::here` staying as the zero-config shortcuts.

use assert2::assert;
use idakit::Ida;

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

#[test]
fn new_here_brings_up_kernel() {
    // here() runs init on the calling thread, which must own an ample stack (~3 MiB+);
    // nextest's test thread is too small, so drive it from a thread sized like the kernel's.
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(|| {
            // here() hands back the !Send Idb bound to this thread; dropping it releases the kernel.
            let idb = Ida::new().here().expect("kernel init failed");
            drop(idb);
        })
        .expect("spawn")
        .join()
        .expect("here thread panicked");
}
