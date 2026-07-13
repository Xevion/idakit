//! Hosts IDA's kernel thread and marshals closures onto it.
//!
//! Brings IDA's single-threaded, thread-affine kernel up, either on the current thread
//! ([`Ida::here`]) or on a dedicated `"idakit-kernel"` thread ([`Ida::run`]), and gates it
//! behind a process-wide claim (`KernelClaim`) so only one [`Database`] is ever live.

use std::ffi::c_int;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::thread;

use idakit_sys as sys;

use crate::Database;
use crate::claim;
use crate::error::{CallError, InitError, Result, panic_payload_str};

/// At most one [`Database`] may be live: the kernel is a process global.
static KERNEL_LIVE: AtomicBool = AtomicBool::new(false);
/// Library initialization runs once ever; later claims only re-run [`claim::steal_main`].
static KERNEL_INITED: AtomicBool = AtomicBool::new(false);

/// Exclusive hold on the kernel; dropping frees it for the next claim.
pub(crate) struct KernelClaim;

impl KernelClaim {
    fn acquire() -> Result<Self, InitError> {
        if KERNEL_LIVE.swap(true, Ordering::AcqRel) {
            Err(InitError::AlreadyRunning)
        } else {
            Ok(Self)
        }
    }
}

impl Drop for KernelClaim {
    fn drop(&mut self) {
        KERNEL_LIVE.store(false, Ordering::Release);
    }
}

type Job = Box<dyn FnOnce(&mut Database) + Send>;

/// A `Send + Clone` handle to the kernel; marshals closures to it from any thread.
#[derive(Clone)]
pub struct Ida {
    tx: Sender<Job>,
}

/// Default kernel-thread stack size: the OS main thread's 8 MiB, idalib's native habitat.
///
/// Library initialization alone overflows below ~3 MiB; spawned stacks don't autogrow.
const KERNEL_STACK_DEFAULT: usize = 8 << 20;

impl Ida {
    /// Starts configuring kernel bring-up.
    ///
    /// Chains setters (`stack_size`, and policies as they land), then finishes with
    /// `.run(app)` or `.here()`. The [`run`](Self::run) and [`here`](Self::here) shortcuts
    /// skip the builder for the defaults.
    #[expect(
        clippy::new_ret_no_self,
        reason = "deliberate builder entry (Command::new style), not a constructor returning Self"
    )]
    pub fn new() -> IdaConfigBuilder {
        IdaConfig::builder()
    }

    /// Brings the kernel up on the current thread and returns the open database.
    ///
    /// No kernel thread, no closure. The `!Send` [`Database`] lives here, and dropping it
    /// releases the kernel. For scripts, tests, and CLIs that own their thread; prefer
    /// [`run`](Self::run) when the current thread must stay free or many threads drive the
    /// kernel. Configure bring-up with [`new`](Self::new).
    ///
    /// # Errors
    /// [`InitError::AlreadyRunning`] if a kernel is already live in the process,
    /// [`InitError::Claim`] if the kernel thread could not be claimed, or
    /// [`InitError::InitLibrary`] if the underlying library failed to initialize.
    #[doc(alias("init_library"))]
    pub fn here() -> Result<Database, InitError> {
        IdaConfig::builder().here()
    }

    /// Spawns the kernel thread and runs `app` on the current thread with an [`Ida`] handle.
    ///
    /// `app` marshals work onto the kernel via [`call`](Self::call), and this returns once
    /// `app` does. Uses an 8 MiB kernel stack; size it with
    /// [`run_with_stack`](Self::run_with_stack). Configure bring-up with [`new`](Self::new).
    /// A panic in `app` propagates inline, since `app` runs on the caller's thread.
    ///
    /// # Errors
    /// [`InitError::AlreadyRunning`] if a kernel is already live in the process,
    /// [`InitError::Claim`] if the kernel thread could not be claimed, or
    /// [`InitError::InitLibrary`] if the underlying library failed to initialize. Never for a
    /// panic in `app`.
    #[doc(alias("init_library"))]
    pub fn run<R, F>(app: F) -> Result<R, InitError>
    where
        F: FnOnce(Self) -> R,
    {
        IdaConfig::builder().run(app)
    }

    /// [`run`](Self::run) with an explicit kernel-stack size.
    ///
    /// Raise it above 8 MiB only for unusually deep decompilation; the reservation commits
    /// lazily.
    ///
    /// # Errors
    /// Same as [`run`](Self::run).
    pub fn run_with_stack<R, F>(stack_size: usize, app: F) -> Result<R, InitError>
    where
        F: FnOnce(Self) -> R,
    {
        IdaConfig::builder().stack_size(stack_size).run(app)
    }

    /// Runs a closure against the open database on the kernel thread, from any thread.
    ///
    /// A panic in `f` is caught on the kernel thread and returned as
    /// [`CallError::Panicked`], leaving the kernel alive for later calls.
    ///
    /// # Errors
    /// [`CallError::Panicked`] if `f` panics, or [`CallError::Disconnected`] if the kernel
    /// thread is gone.
    pub fn call<R, F>(&self, f: F) -> Result<R, CallError>
    where
        F: FnOnce(&mut Database) -> R + Send + 'static,
        R: Send + 'static,
    {
        let (rtx, rrx) = channel::<thread::Result<R>>();
        if self
            .tx
            .send(Box::new(move |idb| {
                // AssertUnwindSafe: `&mut Database` isn't UnwindSafe. A panic mid-write
                // may leave kernel state inconsistent; we keep the actor alive and
                // hand the panic back as an error rather than unwind the kernel.
                let _ = rtx.send(catch_unwind(AssertUnwindSafe(|| f(idb))));
            }))
            .is_err()
        {
            return Err(CallError::Disconnected);
        }
        match rrx.recv() {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(payload)) => Err(CallError::Panicked(payload)),
            Err(_) => Err(CallError::Disconnected),
        }
    }
}

/// Kernel bring-up configuration, built via [`Ida::new`].
///
/// Finishes with [`run`](IdaConfigBuilder::run) or [`here`](IdaConfigBuilder::here). Policy
/// setters (console, signals, batch, ...) land here as they're implemented.
#[derive(bon::Builder)]
pub struct IdaConfig {
    /// Kernel-thread stack in bytes; ignored by [`here`](IdaConfigBuilder::here), which runs
    /// on the current thread. Defaults to 8 MiB; raise only for deep decompilation.
    #[builder(default = KERNEL_STACK_DEFAULT)]
    stack_size: usize,

    /// IDA's `batch` mode: suppress dialogs and auto-answer prompts so a malformed database
    /// can't block bring-up on a hidden prompt. On by default (headless); turn off for an
    /// interactive host such as a GUI plugin.
    #[builder(default = true)]
    batch: bool,
}

impl IdaConfig {
    /// Brings the kernel up on a dedicated thread and runs `app`; see [`Ida::run`].
    ///
    /// # Errors
    /// Propagates [`Ida::run`]'s error.
    ///
    /// # Panics
    /// If the OS refuses to spawn the kernel thread.
    pub fn run<R, F>(self, app: F) -> Result<R, InitError>
    where
        F: FnOnce(Ida) -> R,
    {
        let _claim = KernelClaim::acquire()?;

        let (tx, rx) = channel::<Job>();
        let (setup_tx, setup_rx) = channel::<Result<(), InitError>>();

        let stack_size = self.stack_size;
        let kernel = thread::Builder::new()
            .name("idakit-kernel".into())
            .stack_size(stack_size)
            .spawn(move || {
                let setup = bring_up_kernel(&self);
                let ok = setup.is_ok();
                let _ = setup_tx.send(setup);
                if !ok {
                    return;
                }

                let mut idb = Database::new();
                while let Ok(job) = rx.recv() {
                    // Jobs catch their own closure's panic (see `call`); guard the
                    // pump too so no stray panic can unwind and kill the kernel.
                    let _ = catch_unwind(AssertUnwindSafe(|| job(&mut idb)));
                }
            })
            .expect("spawn kernel thread");

        // Don't hand out a handle until the kernel is up.
        match setup_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = kernel.join();
                return Err(e);
            }
            Err(_) => {
                let _ = kernel.join();
                return Err(InitError::KernelGone);
            }
        }

        let result = app(Ida { tx });
        // `app` has returned, so its handle and any clones it joined are dropped and
        // the pump has exited; join to reap the kernel thread. The pump guards every
        // job, so a panic here is an unexpected kernel-setup failure; surface it
        // rather than let it vanish, but don't poison the app's own result.
        if let Err(payload) = kernel.join() {
            let reason = panic_payload_str(&*payload).unwrap_or("<non-string panic payload>");
            tracing::error!("idakit: kernel thread panicked after init: {reason}");
        }
        Ok(result)
    }

    /// Brings the kernel up on the current thread and returns the [`Database`]; see [`Ida::here`].
    ///
    /// # Errors
    /// Propagates [`Ida::here`]'s error.
    pub fn here(self) -> Result<Database, InitError> {
        let claim = KernelClaim::acquire()?;
        bring_up_kernel(&self)?;
        Ok(Database::owned(claim))
    }
}

use ida_config_builder::{IsComplete, State};

/// Finishes the builder in place, without an intervening `.build()`.
impl<S: State> IdaConfigBuilder<S> {
    /// Brings the kernel up on a dedicated thread and runs `app`; see [`Ida::run`].
    ///
    /// # Errors
    /// Propagates [`Ida::run`]'s error.
    pub fn run<R, F>(self, app: F) -> Result<R, InitError>
    where
        S: IsComplete,
        F: FnOnce(Ida) -> R,
    {
        self.build().run(app)
    }

    /// Brings the kernel up on the current thread and returns the [`Database`]; see [`Ida::here`].
    ///
    /// # Errors
    /// Propagates [`Ida::here`]'s error.
    pub fn here(self) -> Result<Database, InitError>
    where
        S: IsComplete,
    {
        self.build().here()
    }
}

/// Reclaims the kernel main thread for the caller via [`claim::steal_main`], initializes the
/// library once, then applies the per-bring-up policy (`batch`).
///
/// The steal is correct on any thread (OS-main or spawned).
fn bring_up_kernel(cfg: &IdaConfig) -> Result<(), InitError> {
    claim::steal_main().map_err(|reason| InitError::Claim { reason })?;
    if !KERNEL_INITED.swap(true, Ordering::AcqRel) {
        // SAFETY: on the (now) kernel thread, once, before any other kernel call.
        let rc = unsafe { sys::idakit_init_library() };
        if rc != 0 {
            KERNEL_INITED.store(false, Ordering::Release); // let a retry re-init
            return Err(InitError::InitLibrary { code: rc });
        }
    }
    // `batch` is a process global; the current request's choice wins on every bring-up.
    // SAFETY: kernel thread, after init.
    unsafe { sys::idakit_set_batch(cfg.batch as c_int) };
    Ok(())
}
