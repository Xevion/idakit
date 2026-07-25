//! The registry every `#[kernel_test]` submits itself to, plus the warm-worker context that lets
//! an unmodified test body reach the worker's already-open database.
//!
//! Registration is by [`inventory`] rather than a hand-kept list, so a test file that is included
//! in the harness binary contributes its tests by existing. Nothing enumerates them at the call
//! site, and nothing has to be updated when one is added or renamed.

use std::cell::Cell;
use std::marker::PhantomData;
use std::ptr::NonNull;

use idakit::prelude::Ida;

/// One registered kernel test.
///
/// Submitted by [`kernel_test`](idakit_runner_macros::kernel_test), never constructed by hand.
pub struct KernelTest {
    /// The `module_path!()` of the test's own module, which prefixes its case name.
    pub module: &'static str,
    /// The test function's identifier.
    pub name: &'static str,
    /// Whether the test mutates the database.
    pub isolation: Isolation,
    /// The test body, which panics to fail.
    pub run: fn(),
}

inventory::collect!(KernelTest);

impl KernelTest {
    /// The case name the harness lists and reports, `module::path::test_name` with the harness
    /// binary's own crate segment dropped.
    pub fn case_name(&self) -> String {
        let module = self.module.split_once("::").map_or("", |(_, rest)| rest);
        if module.is_empty() {
            self.name.to_owned()
        } else {
            format!("{module}::{}", self.name)
        }
    }
}

/// Whether a test needs a database no other test has touched.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Shares one open database with its neighbours, which is what makes the harness fast.
    ReadOnly,
    /// Gets a freshly reopened database, since its writes would otherwise leak into later tests.
    Writes,
}

thread_local! {
    /// The worker's kernel, live only for the duration of one case.
    ///
    /// A pointer rather than a reference because the `Ida` lives in the worker's serve loop, whose
    /// frame outlives every case but has no lifetime a `thread_local` could name.
    static WARM: Cell<Option<NonNull<Ida>>> = const { Cell::new(None) };
}

/// Runs `body` against the warm kernel, or returns `None` if this thread has no worker.
pub fn with_warm_kernel<R>(body: impl FnOnce(&Ida) -> R) -> Option<R> {
    let ida = WARM.get()?;
    // SAFETY: `WARM` is only ever set by `Warm`, whose lifetime is a strict subset of the borrow it
    // was created from, and cleared on drop. A case therefore cannot observe a stale pointer.
    Some(body(unsafe { ida.as_ref() }))
}

/// Publishes `ida` to this thread's test bodies until dropped.
///
/// The lifetime is what keeps [`with_warm_kernel`]'s dereference sound: the guard cannot outlive
/// the borrow it was made from.
pub struct Warm<'a>(PhantomData<&'a Ida>);

impl<'a> Warm<'a> {
    /// Makes `ida` the warm kernel for this thread.
    pub fn new(ida: &'a Ida) -> Self {
        WARM.set(Some(NonNull::from(ida)));
        Self(PhantomData)
    }
}

impl Drop for Warm<'_> {
    fn drop(&mut self) {
        WARM.set(None);
    }
}
