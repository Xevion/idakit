//! Idiomatic Rust bindings for IDA Pro's `idalib` (9.x).
//!
//! # The kernel thread
//!
//! The IDA kernel is single-threaded and thread-affine. [`Ida::here`] brings it up *on
//! the current thread* and hands back the open [`Idb`] -- no kernel thread, no closure --
//! for programs that own their thread (scripts, tests, CLIs):
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut idb = idakit::Ida::here()?;
//! idb.open("/path/to/db.i64").call()?;
//! for func in idb.functions() {
//!     println!("{:#x} {}", func.ea().get(), func.name().unwrap_or_default());
//! }
//! idb.close(false);
//! # Ok(())
//! # }
//! ```
//!
//! When the current thread must stay free (GUI/async) or many threads drive the kernel,
//! [`Ida::run`] hosts it on a dedicated thread and runs your app on the caller; any
//! thread marshals work onto the kernel with [`Ida::call`]:
//!
//! ```no_run
//! use idakit::{Ida, Idb};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! Ida::run(|ida| {
//!     ida.call(|idb: &mut Idb| -> idakit::Result<()> {
//!         idb.open("/path/to/db.i64").call()?;
//!         idb.close(false);
//!         Ok(())
//!     })?
//! })??;
//! # Ok(())
//! # }
//! ```
//!
//! The kernel is a process global: only one `Idb` is live at a time (a second
//! [`here`](Ida::here)/[`run`](Ida::run) yields [`InitError::AlreadyRunning`]).
//!
//! # Read/write separation
//!
//! [`Idb`] is `!Send + !Sync`, so it stays on the kernel thread. Reads borrow `&Idb` and
//! return lightweight views ([`Func`], [`Segment`], ...); writes take `&mut Idb`, so a read
//! view can't be held across a mutation.
//!
//! # Building
//!
//! Linking needs a real IDA install (`IDADIR`, holding `libida.so`); the build compiles
//! a small C++ facade against the IDA SDK headers, fetched to match the installed IDA
//! version (override with `IDA_SDK_DIR`). Databases must be 64-bit `.i64` -- the facade
//! is compiled `__EA64__`.
#![deny(missing_docs)]

use std::cell::Cell;
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::thread;

use idakit_sys as sys;

mod claim;
pub mod ctree;
mod decompile;
mod ea;
mod error;
mod ffi;
mod func;
mod insn;
mod meta;
mod name;
mod raw;
mod segment;
mod ty;
mod xref;

pub use ctree::{AssignOp, BinOp, UnOp};
pub use decompile::{Cfunc, CtreeCounts};
pub use ea::{BADADDR, Ea, Offset};
pub use error::{CallError, Error, InitError, Qerrno, Result};
pub use func::{Chunk, Chunks, Func, FuncImage, Functions, Instructions};
pub use insn::{
    Access, DecodeError, Dtype, Flow, Insn, Isa, Mem, Operand, OperandKind, Reg, RegClass,
};
pub use meta::Meta;
pub use name::{Name, Names};
pub use segment::{Segment, Segments};
pub use ty::{Member, Members, TypeInfo};
pub use xref::{CodeRef, DataRef, Xref, XrefKind, Xrefs};

/// At most one [`Idb`] may be live: the kernel is a process global.
static KERNEL_LIVE: AtomicBool = AtomicBool::new(false);
/// `init_library` runs once ever; later claims only re-steal `g_main`.
static KERNEL_INITED: AtomicBool = AtomicBool::new(false);

/// Exclusive hold on the kernel; dropping frees it for the next claim.
struct KernelClaim;

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

/// The open database. `!Send + !Sync`, so it stays on the kernel thread. Reads borrow
/// `&Idb` (returning [`Func`]/[`Segment`] views); writes take `&mut Idb`, so a read
/// view can't be held across a write.
pub struct Idb {
    /// Interior mutability lets `decompile(&self)` init Hex-Rays lazily.
    hexrays_ready: Cell<bool>,
    /// `Some` for an in-place `Idb`; `None` for the actor's, whose claim `run` holds.
    _claim: Option<KernelClaim>,
    _not_send: PhantomData<*const ()>,
}

/// Database-open builder: `idb.open(path).run_auto(true).call()`. `path` stays a
/// positional argument; options chain before the terminal `.call()`.
#[bon::bon]
impl Idb {
    /// Open a database file. Re-opening after [`close`](Self::close) works.
    ///
    /// With `run_auto` set, IDA's auto-analysis runs and this blocks until it drains,
    /// turning a raw binary into a fully analyzed database; it defaults to `false`,
    /// which opens an already-analyzed `.i64` as-is.
    #[builder]
    pub fn open(
        &mut self,
        #[builder(start_fn)] path: &str,
        #[builder(default)] run_auto: bool,
    ) -> Result<()> {
        let rc = ffi::with_cstr(path, "path", |p| self.open_database(p, run_auto))?;
        if rc == idakit_sys::IDAKIT_EXIT_TRAPPED {
            // IDA hit an unrecoverable condition and tried to terminate the process; the
            // facade trapped the exit() and handed control back, with whatever it printed.
            return Err(self.kernel_exit_error());
        }
        if rc != 0 {
            // The return value IS the error_t (eOS=1 means "see errno", e.g. ENOENT).
            let qerrno = Qerrno::from_code(rc);
            return Err(Error::Open {
                path: path.to_owned(),
                reason: self.error_reason(qerrno),
                qerrno,
            });
        }
        // run_auto only enables the analysis queue; block until it drains so callers
        // observe a fully analyzed database. Analysis runs kernel code, so it can trap too.
        if run_auto && self.auto_wait() == idakit_sys::IDAKIT_EXIT_TRAPPED {
            return Err(self.kernel_exit_error());
        }
        Ok(())
    }
}

impl Idb {
    /// The actor's `Idb`; `run` holds its claim.
    fn new() -> Self {
        Self {
            hexrays_ready: Cell::new(false),
            _claim: None,
            _not_send: PhantomData,
        }
    }

    /// An in-place `Idb` that releases the kernel when dropped.
    fn owned(claim: KernelClaim) -> Self {
        Self {
            hexrays_ready: Cell::new(false),
            _claim: Some(claim),
            _not_send: PhantomData,
        }
    }

    /// Close the current database, optionally saving analysis back to the `.i64`.
    pub fn close(&mut self, save: bool) {
        self.close_database(save);
    }

    /// Record EULA acceptance in IDA's registry (`$HOME/.idapro`), a one-time setup per
    /// home. Headless `idalib` refuses to [`open`](Self::open) a database until this is
    /// set, aborting with [`Error::KernelExit`] (`"License not yet accepted, cannot run in
    /// batch mode"`). Returns whether the registry now reads accepted.
    pub fn accept_eula(&self) -> bool {
        self.reg_accept_eula()
    }

    /// Build a [`Error::KernelExit`] from the facade's trap state -- the code IDA passed to
    /// `exit()` and whatever it printed on the way out (captured, when the call captured).
    fn kernel_exit_error(&self) -> Error {
        let captured = self.last_output();
        let trimmed = captured.trim();
        Error::KernelExit {
            code: self.last_exit_code(),
            diagnostic: (!trimmed.is_empty()).then(|| trimmed.to_owned()),
        }
    }

    /// A typed cursor at `ea`; does not verify a function lives there (absence
    /// surfaces lazily). Use [`functions`](Self::functions) to enumerate real ones.
    #[inline]
    #[must_use]
    pub fn func(&self, ea: Ea) -> Func<'_> {
        Func::new(ea, self)
    }

    /// Iterate every function in the database, in kernel order.
    #[inline]
    #[must_use]
    pub fn functions(&self) -> Functions<'_> {
        Functions::new(self)
    }

    /// Iterate every segment in the database, in kernel order.
    #[inline]
    #[must_use]
    pub fn segments(&self) -> Segments<'_> {
        Segments::new(self)
    }

    /// Decode the instruction at `ea` into an owned, `Send` [`Insn`] -- mnemonic, semantic
    /// operands, and control-flow facts, all resolved here on the kernel thread.
    ///
    /// `Err` if no instruction decodes there ([`DecodeError::NotCode`]) or the database's
    /// processor has no decoder ([`DecodeError::UnsupportedProcessor`]); only x86/x64 are
    /// modelled. An [`Insn`] that is returned is fully decoded -- there is no partial or
    /// fallback result.
    pub fn decode(&self, ea: Ea) -> Result<Insn, DecodeError> {
        // SAFETY: `InsnRaw` is an all-integer POD, so an all-zero bit pattern is a valid
        // value; the facade overwrites it before it reports success.
        let mut raw: sys::InsnRaw = unsafe { std::mem::zeroed() };
        match self.decode_insn(ea, &mut raw) {
            0 => Ok(insn::insn_from_raw(&raw)),
            -2 => Err(DecodeError::UnsupportedProcessor),
            -3 => Err(DecodeError::UnsupportedOperand {
                ea: ea.get(),
                op: raw.err_op,
                optype: raw.err_optype,
            }),
            // -1 (no instruction) and any other negative rc.
            _ => Err(DecodeError::NotCode { ea: ea.get() }),
        }
    }

    /// Whether the kernel classifies the item at `ea` as an instruction. This is the gate
    /// [`Func::instructions`] walks by: [`decode`](Self::decode) will happily turn arbitrary
    /// bytes into an [`Insn`], so only `is_code` separates real instructions from data (or a
    /// function's alignment tail) that merely happens to decode.
    #[must_use]
    pub fn is_code(&self, ea: Ea) -> bool {
        (self.get_flags(ea) & sys::MS_CLS) == sys::FF_CODE
    }

    /// Whether the kernel classifies the item at `ea` as a data definition.
    #[must_use]
    pub fn is_data(&self, ea: Ea) -> bool {
        (self.get_flags(ea) & sys::MS_CLS) == sys::FF_DATA
    }

    /// Start of the defined item (instruction or data) covering `ea`; `ea` itself when it is
    /// already a head or falls in undefined bytes.
    #[must_use]
    pub fn item_head(&self, ea: Ea) -> Ea {
        Ea::try_new(self.get_item_head(ea)).unwrap_or(ea)
    }

    /// One-past-the-last address of the item at `ea` -- the next item's head, and the natural
    /// step to advance a linear walk. Undefined bytes advance one at a time.
    #[must_use]
    pub fn item_end(&self, ea: Ea) -> Ea {
        Ea::try_new(self.get_item_end(ea)).unwrap_or(ea)
    }

    /// Next defined item head after `ea`, searching up to (but not reaching) `max`; `None`
    /// when no head lies in that span.
    #[must_use]
    pub fn next_head(&self, ea: Ea, max: Ea) -> Option<Ea> {
        Ea::try_new(self.get_next_head(ea, max))
    }

    /// Previous defined item head before `ea`, searching down to `min`; `None` when no head
    /// lies in that span.
    #[must_use]
    pub fn prev_head(&self, ea: Ea, min: Ea) -> Option<Ea> {
        Ea::try_new(self.get_prev_head(ea, min))
    }

    // TODO: basic blocks and CFG over the decoded instruction stream.
    // TODO: enumerate strings, imports/exports, and entry points.

    /// Read bytes at `ea` into `buf`, returning how many were supplied. Zero-alloc;
    /// reuse one buffer on hot loops. [`bytes`](Self::bytes) is the owning shortcut.
    pub fn read_into(&self, ea: Ea, buf: &mut [u8]) -> usize {
        let got = self.get_bytes(ea, buf.as_mut_ptr().cast(), buf.len());
        (got.max(0) as usize).min(buf.len())
    }

    // TODO: patch_bytes (the write half of read_into) and binary/pattern search over the image.

    /// Read up to `len` bytes at `ea` into a fresh vector (empty on failure).
    #[must_use]
    pub fn bytes(&self, ea: Ea, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let got = self.read_into(ea, &mut buf);
        buf.truncate(got);
        buf
    }

    /// Lazily iterate every cross-reference targeting `ea` -- its callers and the data
    /// that points at it (ordinary sequential flow excluded).
    #[inline]
    #[must_use]
    pub fn xrefs_to(&self, ea: Ea) -> Xrefs<'_> {
        Xrefs::new(self.xref_open(ea, true))
    }

    /// Lazily iterate every cross-reference originating at `ea` -- what the code there
    /// calls, jumps to, or reads (ordinary sequential flow excluded).
    #[inline]
    #[must_use]
    pub fn xrefs_from(&self, ea: Ea) -> Xrefs<'_> {
        Xrefs::new(self.xref_open(ea, false))
    }

    /// Resolve a named type and its member layout. `Err` if no such type exists.
    pub fn type_named(&self, name: &str) -> Result<TypeInfo<'_>> {
        let handle = ffi::with_cstr(name, "name", |p| self.type_open(p))?;
        if handle.is_null() {
            return Err(Error::TypeNotFound {
                name: name.to_owned(),
            });
        }
        Ok(TypeInfo::from_handle(handle, self))
    }

    /// Decompile the function at `ea` and materialize its ctree. Sugar for
    /// [`func(ea)`](Self::func)`.`[`ctree()`](Func::ctree).
    pub fn ctree(&self, ea: Ea) -> Result<ctree::Ctree> {
        self.func(ea).ctree()
    }

    /// Decompile the function containing `ea` (inits Hex-Rays on first use).
    pub fn decompile(&self, ea: Ea) -> Result<Cfunc<'_>> {
        if !self.hexrays_ready.get() {
            let rc = self.hexrays_init();
            if rc != 1 {
                return Err(Error::HexRaysInit { code: rc });
            }
            self.hexrays_ready.set(true);
        }
        let (handle, reason) = self.decompile_at(ea);
        if handle.is_null() {
            // A trapped fatal exit() during decompilation is a dead kernel, not an ordinary
            // decompile miss -- surface it as such.
            if self.was_trapped() {
                return Err(self.kernel_exit_error());
            }
            return Err(Error::Decompile {
                ea: ea.get(),
                reason,
            });
        }
        Ok(Cfunc::from_handle(handle, self))
    }

    /// Rename the item at `ea`.
    pub fn rename(&mut self, ea: Ea, name: &str) -> Result<()> {
        let ok = ffi::with_cstr(name, "name", |p| self.set_name(ea, p))?;
        if ok {
            Ok(())
        } else {
            let (qerrno, reason) = self.last_reason();
            Err(Error::WriteRejected {
                op: "rename",
                ea: ea.get(),
                qerrno,
                reason,
            })
        }
    }

    // TODO: read comments back (the read half of set_comment).

    /// Set the comment at `ea`. `repeatable` repeats it at every reference.
    pub fn set_comment(&mut self, ea: Ea, text: &str, repeatable: bool) -> Result<()> {
        let ok = ffi::with_cstr(text, "comment", |p| self.set_cmt(ea, p, repeatable))?;
        if ok {
            Ok(())
        } else {
            let (qerrno, reason) = self.last_reason();
            Err(Error::WriteRejected {
                op: "set_comment",
                ea: ea.get(),
                qerrno,
                reason,
            })
        }
    }
}

type Job = Box<dyn FnOnce(&mut Idb) + Send>;

/// A `Send + Clone` handle to the kernel; marshal closures to it from any thread.
#[derive(Clone)]
pub struct Ida {
    tx: Sender<Job>,
}

/// Default kernel-thread stack: the OS main thread's 8 MiB, idalib's native habitat.
/// (`init_library` alone overflows below ~3 MiB; spawned stacks don't autogrow.)
const KERNEL_STACK_DEFAULT: usize = 8 << 20;

impl Ida {
    /// Bring the kernel up *on the current thread* and return the open database -- no
    /// kernel thread, no closure. The `!Send` [`Idb`] lives here; dropping it releases
    /// the kernel. For scripts, tests, and CLIs that own their thread. Prefer
    /// [`run`](Self::run) when the current thread must stay free or many threads drive
    /// the kernel.
    pub fn here() -> Result<Idb, InitError> {
        let claim = KernelClaim::acquire()?;
        bring_up_kernel()?;
        Ok(Idb::owned(claim))
    }

    /// Spawn the kernel thread and run `app` on the current thread with an [`Ida`]
    /// handle, marshaling work onto the kernel via [`call`](Self::call). Returns once
    /// `app` does. 8 MiB kernel stack; size it with [`run_with_stack`](Self::run_with_stack).
    ///
    /// `Err` only on kernel setup; a panic in `app` propagates inline (it runs here).
    pub fn run<R, F>(app: F) -> Result<R, InitError>
    where
        F: FnOnce(Ida) -> R,
    {
        Self::run_with_stack(KERNEL_STACK_DEFAULT, app)
    }

    /// [`run`](Self::run) with an explicit kernel-stack size. Raise it above 8 MiB only
    /// for unusually deep decompilation; the reservation commits lazily.
    pub fn run_with_stack<R, F>(stack_size: usize, app: F) -> Result<R, InitError>
    where
        F: FnOnce(Ida) -> R,
    {
        let _claim = KernelClaim::acquire()?;

        let (tx, rx) = channel::<Job>();
        let (setup_tx, setup_rx) = channel::<Result<(), InitError>>();

        let kernel = thread::Builder::new()
            .name("idakit-kernel".into())
            .stack_size(stack_size)
            .spawn(move || {
                let setup = bring_up_kernel();
                let ok = setup.is_ok();
                let _ = setup_tx.send(setup);
                if !ok {
                    return;
                }

                let mut idb = Idb::new();
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
        // job, so a panic here is an unexpected kernel-setup failure -- surface it
        // rather than let it vanish, but don't poison the app's own result.
        if let Err(payload) = kernel.join() {
            let reason =
                error::panic_payload_str(&*payload).unwrap_or("<non-string panic payload>");
            tracing::error!("idakit: kernel thread panicked after init: {reason}");
        }
        Ok(result)
    }

    /// Run a closure against the open database on the kernel thread, from any thread.
    /// A panic in `f` is caught on the kernel thread and returned as
    /// [`CallError::Panicked`], leaving the kernel alive for later calls.
    pub fn call<R, F>(&self, f: F) -> Result<R, CallError>
    where
        F: FnOnce(&mut Idb) -> R + Send + 'static,
        R: Send + 'static,
    {
        let (rtx, rrx) = channel::<thread::Result<R>>();
        if self
            .tx
            .send(Box::new(move |idb| {
                // AssertUnwindSafe: `&mut Idb` isn't UnwindSafe. A panic mid-write
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

/// Steal `g_main` for the calling thread, then initialize the library. The steal is
/// correct on any thread (OS-main or spawned); init runs at most once per process.
fn bring_up_kernel() -> Result<(), InitError> {
    claim::steal_main().map_err(|reason| InitError::Claim { reason })?;
    if KERNEL_INITED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    // SAFETY: on the (now) kernel thread, once, before any other kernel call.
    let rc = unsafe { sys::init_library(0, ptr::null_mut()) };
    if rc == 0 {
        Ok(())
    } else {
        KERNEL_INITED.store(false, Ordering::Release); // let a retry re-init
        Err(InitError::InitLibrary { code: rc })
    }
}
