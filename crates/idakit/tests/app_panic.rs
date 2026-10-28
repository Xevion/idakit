//! A panic in the `Ida::run` app closure still joins the kernel thread before it propagates.
//!
//! The kernel thread closes the open database after the app hands back its handle. If the app
//! panics, that close must finish before the panic leaves `run`, or the caller's process exit
//! races libida's atexit teardown against a thread still inside the kernel. A slow thread-local
//! destructor on the kernel thread stands in for that close: it only runs at thread exit, so the
//! flag it sets is visible after `run` unwinds only if `run` joined the thread.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use assert2::{assert, check};
use idakit::kernel::Ida;

static KERNEL_THREAD_EXITED: AtomicBool = AtomicBool::new(false);

struct SlowExit;

impl Drop for SlowExit {
    fn drop(&mut self) {
        thread::sleep(Duration::from_millis(300));
        KERNEL_THREAD_EXITED.store(true, Ordering::SeqCst);
    }
}

thread_local! {
    static EXIT_PROBE: SlowExit = const { SlowExit };
}

#[test]
fn app_panic_joins_the_kernel_thread() {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        Ida::run(|ida| {
            ida.call(|_idb| EXIT_PROBE.with(|_| ()))
                .expect("arm the exit probe on the kernel thread");
            panic!("app boom");
        })
    }));

    let payload = outcome.expect_err("the app panic must propagate out of run");
    check!(payload.downcast_ref::<&str>() == Some(&"app boom"));
    assert!(
        KERNEL_THREAD_EXITED.load(Ordering::SeqCst),
        "run returned its panic while the kernel thread was still alive"
    );
}
