//! The fatal-trap mechanism in isolation. [`idakit_test_fatal`] runs a chosen fatal inside the
//! facade's `guarded<>` wrapper; the trap must convert it to [`IDAKIT_EXIT_TRAPPED`] rather than
//! terminate the process. nextest isolates each test in its own process, so a fatal that escapes
//! the trap fails only that test. The shim compiles under the `test-shims` feature, which the
//! crate's self dev-dependency enables for these tests.

use idakit_sys::{
    IDAKIT_EXIT_TRAPPED, IDAKIT_FATAL_ABORT, IDAKIT_FATAL_EXIT, IDAKIT_FATAL_INTERR,
    idakit_test_fatal,
};

#[test]
fn exit_inside_guarded_call_is_trapped() {
    // SAFETY: the shim calls exit() inside guarded<>; the trap longjmps back instead of exiting.
    let rc = unsafe { idakit_test_fatal(IDAKIT_FATAL_EXIT) };
    assert_eq!(rc, IDAKIT_EXIT_TRAPPED);
}

#[test]
fn abort_inside_guarded_call_is_trapped() {
    // SAFETY: the shim calls abort() inside guarded<>; the trap longjmps back instead of aborting.
    let rc = unsafe { idakit_test_fatal(IDAKIT_FATAL_ABORT) };
    assert_eq!(rc, IDAKIT_EXIT_TRAPPED);
}

// Unlike exit/abort (trapped by the shim's direct longjmp), interr relies on idalib throwing
// interr_exc_t across the libida boundary for guarded<> to catch. That throw is only trapped on
// Linux; off it the exception is not caught and the process aborts, so the check runs there only.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "interr trapping needs a catchable throw across the libida boundary (Linux-only)"
)]
fn interr_inside_guarded_call_is_trapped() {
    // SAFETY: the shim calls interr() inside guarded<>; set_interr_throws makes it a catchable
    // interr_exc_t, so the guard returns instead of terminating.
    let rc = unsafe { idakit_test_fatal(IDAKIT_FATAL_INTERR) };
    assert_eq!(rc, IDAKIT_EXIT_TRAPPED);
}
