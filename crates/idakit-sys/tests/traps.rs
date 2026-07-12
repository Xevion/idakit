//! The fatal-trap mechanism in isolation. [`idakit_test_fatal`] runs a chosen fatal inside the
//! facade's `guarded<>` wrapper; the trap must convert it to [`IDAKIT_EXIT_TRAPPED`] rather than
//! terminate the process. nextest isolates each test in its own process, so a fatal that escapes
//! the trap fails only that test.

use idakit_sys::{
    IDAKIT_EXIT_TRAPPED, IDAKIT_FATAL_ABORT, IDAKIT_FATAL_EXIT, IDAKIT_FATAL_INTERR, WriteOutcome,
    drop_probe_count, drop_probe_make, ext_classify, ext_throw_coded, ext_throw_interr,
    ext_throw_plain_int, idakit_test_fatal, idakit_test_fatal_through_cxx, make_addr_cursor,
    probe_throw,
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

// Force the dangerous topology the ordinary trap tests never hit: a
// guarded<> setjmp ABOVE a cxx `Result`-shim, with the fatal firing from C++ BELOW the shim, so
// the trap's longjmp must unwind *through* the cxx-generated try/catch landing-pad frame. If a
// longjmp past a cxx shim corrupted the C++ runtime or the stack, these would crash or hang
// rather than return the sentinel cleanly. (idakit's real code never builds this topology; the
// probe is synthetic, to establish the empirical boundary.)

#[test]
fn exit_longjmp_across_cxx_shim_is_trapped() {
    // SAFETY: the guard arms guarded<>, then reaches exit() through the cxx shim; the trap
    // longjmps back across that shim frame instead of exiting.
    let rc = unsafe { idakit_test_fatal_through_cxx(IDAKIT_FATAL_EXIT) };
    assert_eq!(rc, IDAKIT_EXIT_TRAPPED);
}

#[test]
fn abort_longjmp_across_cxx_shim_is_trapped() {
    // SAFETY: as above, for the abort() path.
    let rc = unsafe { idakit_test_fatal_through_cxx(IDAKIT_FATAL_ABORT) };
    assert_eq!(rc, IDAKIT_EXIT_TRAPPED);
}

// An interr is a *throw* (interr_exc_t : std::exception), not a longjmp. Fired below a cxx shim,
// cxx's own `catch (std::exception const&)` intercepts it first, so it becomes a bridge Err (the
// guard sees the shim return, not a trap) rather than reaching guarded<>'s interr catch. The guard
// entry reports this interception as rc == 1. Linux-only: interr throws across the libida boundary
// only there.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "interr throws across the libida boundary only on Linux"
)]
fn interr_across_cxx_shim_is_intercepted_by_cxx() {
    // SAFETY: the guard reaches interr() through the cxx shim; cxx catches the throw and the shim
    // returns an Err, so the guard returns 1 (intercepted) rather than IDAKIT_EXIT_TRAPPED.
    let rc = unsafe { idakit_test_fatal_through_cxx(IDAKIT_FATAL_INTERR) };
    assert_eq!(
        rc, 1,
        "cxx should intercept the interr throw before the trap"
    );
}

// What cxx's default trycatch actually surfaces. Its generated shim
// catches only `std::exception const&`, giving back a flat `cxx::Exception` whose `what()` is the
// C++ message and nothing else (no qerrno, no structured context). A non-std::exception throw
// (kind 2) escapes the catch and std::terminate()s the process, so it is documented, not run.
#[test]
fn cxx_surfaces_std_exception_as_flat_err() {
    let runtime_err = probe_throw(0).unwrap_err();
    assert_eq!(runtime_err.what(), "probe_throw: runtime_error from C++");

    let range_err = probe_throw(1).unwrap_err();
    assert!(
        range_err.what().contains("out_of_range"),
        "out_of_range should surface via std::exception::what(), got: {}",
        range_err.what()
    );
}

// The custom `rust::behavior::trycatch` in probe_ext_cxx.h widens what the
// bridge shims catch. cxx's default terminates on a non-`std::exception` throw; the `catch (...)`
// arm turns it into an ordinary `Err`. (If the override had failed to take, `throw 42` would
// std::terminate and abort this test process instead of returning here.)
#[test]
fn custom_trycatch_catches_non_std_exception() {
    let err = ext_throw_plain_int().unwrap_err();
    assert!(
        err.what().contains("non-std::exception"),
        "catch(...) arm should surface a non-std::exception throw as Err, got: {}",
        err.what()
    );
}

// An interr_exc_t carries only an int code and inherits the uninformative base what()
// ("std::exception"). The custom `catch (const interr_exc_t&)` arm is what makes the code legible.
#[test]
fn custom_trycatch_enriches_interr_with_its_code() {
    let err = ext_throw_interr(42).unwrap_err();
    assert!(
        err.what().contains("code=42"),
        "interr arm should format the code into the message, got: {}",
        err.what()
    );
}

// The enrichment boundary: a `cxx::Exception` carries only `what()`, one flat string, no
// qerrno/typed context. Structured data can ride only AS that string. Here a code is encoded into
// the throw message and re-parsed Rust-side. idakit's production path instead treats the throw as a
// bare failure signal and re-derives qerrno/reason from the kernel (Database::last_reason()), so the
// C++ body needs no message at all (see crates/idakit/tests/cxx_error.rs).
#[test]
fn cxx_exception_only_carries_a_string_code_must_be_encoded() {
    let err = ext_throw_coded(7).unwrap_err();
    let msg = err.what();
    let code: i32 = msg
        .strip_prefix("idakit:qerrno=")
        .expect("encoded code prefix")
        .parse()
        .expect("code parses back out of the message");
    assert_eq!(code, 7, "the only channel is the what() string");
}

// A `self: Pin<&mut Self>` receiver on a cxx opaque type binds to a NON-const
// C++ member and mutates. The generated shim takes `&AddrCursor::advance` as a non-const member
// pointer; here the mutation persists across separate calls (advance then seek then read back).
#[test]
fn pin_mut_self_mutates_opaque_across_calls() {
    let mut cursor = make_addr_cursor(0x1000);
    assert_eq!(
        cursor.pos(),
        0x1000,
        "&self const member reads initial state"
    );

    cursor.pin_mut().advance(0x10);
    assert_eq!(cursor.pos(), 0x1010, "Pin<&mut Self> advance persisted");

    cursor.pin_mut().advance(0x08);
    assert_eq!(
        cursor.pos(),
        0x1018,
        "a second mutation stacks on the first"
    );

    cursor.pin_mut().seek(0x2000);
    assert_eq!(cursor.pos(), 0x2000, "Pin<&mut Self> seek persisted");
}

// A cxx shared enum returned by value. cxx emits its own C++ enum and, on the
// Rust side, a `#[repr(transparent)] struct { repr: i32 }` with associated consts; it can hold
// any i32, so this match REQUIRES the wildcard arm (there is no exhaustive variant set to match).
#[test]
fn shared_enum_crosses_by_value_and_needs_a_wildcard() {
    fn label(o: WriteOutcome) -> &'static str {
        match o {
            WriteOutcome::Applied => "applied",
            WriteOutcome::Rejected => "rejected",
            WriteOutcome::NoChange => "nochange",
            _ => "unknown", // mandatory: the type is a newtype over i32, not a closed enum
        }
    }
    assert_eq!(label(ext_classify(0)), "applied");
    assert_eq!(label(ext_classify(1)), "rejected");
    assert_eq!(label(ext_classify(2)), "nochange");
    assert_eq!(label(ext_classify(99)), "nochange");
    // The raw discriminant is directly readable, which is what idakit's num_enum layer consumes.
    assert_eq!(ext_classify(1).repr, 1);
}

// Dropping a cxx `UniquePtr<T>` runs the C++ deleter. DropProbe's destructor bumps a
// process-global counter (nextest gives each test its own process, so it starts at 0). This is the
// same generated `$unique_ptr$...$drop` glue that backs the cfg bridge's `FlowChart`, so a
// UniquePtr field needs no manual free function or hand-written Drop impl.
#[test]
fn cxx_unique_ptr_runs_cpp_deleter_on_drop() {
    assert_eq!(drop_probe_count(), 0, "counter should start clean");
    let probe = drop_probe_make();
    assert!(!probe.is_null(), "make should hand back a live handle");
    assert_eq!(
        drop_probe_count(),
        0,
        "the deleter must not run while the UniquePtr is alive"
    );
    drop(probe);
    assert_eq!(
        drop_probe_count(),
        1,
        "dropping the UniquePtr must run the C++ destructor exactly once"
    );
}
