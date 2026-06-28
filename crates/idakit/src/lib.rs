//! Idiomatic Rust bindings for IDA Pro's `idalib` (9.x).
//!
//! # The kernel thread
//!
//! The IDA kernel is single-threaded and thread-affine: it must be driven from the one
//! thread that initialized it. [`Ida::run`] spawns a dedicated *kernel thread*, claims
//! the kernel on it, then runs your application on the calling thread (typically the OS
//! main thread, so the host keeps it for its own runtime). Any thread holding an
//! [`Ida`] handle marshals work onto the kernel thread with [`Ida::call`].
//!
//! # Read/write separation
//!
//! The open database is an [`Idb`]. It is `!Send + !Sync`, so it exists only inside a
//! kernel-thread job — it never crosses a thread boundary. Reads borrow `&Idb` and hand
//! back lightweight views ([`Func`], [`Segment`], …); writes take `&mut Idb`. The borrow
//! checker therefore stops a read view from being held across a mutation.
//!
//! ```no_run
//! use idakit::{Ida, Idb};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! Ida::run(|ida| {
//!     ida.call(|idb: &mut Idb| -> idakit::Result<()> {
//!         idb.open("/path/to/db.i64").call()?;
//!         for func in idb.functions() {
//!             println!("{:#x} {}", func.ea().get(), func.name().unwrap_or_default());
//!         }
//!         idb.close(false);
//!         Ok(())
//!     })?
//! })??;
//! # Ok(())
//! # }
//! ```
//!
//! # Building
//!
//! Linking needs a real IDA install (`IDADIR`, holding `libida.so`); the build compiles
//! a small C++ facade against the IDA SDK headers, fetched to match the installed IDA
//! version (override with `IDA_SDK_DIR`). Databases must be 64-bit `.i64` — the facade
//! is compiled `__EA64__`.
#![deny(missing_docs)]

use std::cell::Cell;
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
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
mod raw;
mod segment;
mod ty;
mod xref;

pub use ctree::{AssignOp, BinOp, UnOp};
pub use decompile::{Cfunc, CtreeCounts};
pub use ea::{BADADDR, Ea, Offset};
pub use error::{CallError, Error, InitError, Qerrno, Result};
pub use func::{Func, Functions};
pub use segment::{Segment, Segments};
pub use ty::{Member, Members, TypeInfo};
pub use xref::{CodeRef, DataRef, Xref, XrefKind};

/// The open database. `!Send + !Sync`, so it exists only on the kernel thread.
/// Reads borrow `&Idb` (returning [`Func`]/[`Segment`] views); writes take
/// `&mut Idb`, so a read view can't be held across a write.
pub struct Idb {
    /// Interior mutability lets `decompile(&self)` init Hex-Rays lazily.
    hexrays_ready: Cell<bool>,
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
        // observe a fully analyzed database.
        if run_auto {
            self.auto_wait();
        }
        Ok(())
    }
}

impl Idb {
    fn new() -> Self {
        Self {
            hexrays_ready: Cell::new(false),
            _not_send: PhantomData,
        }
    }

    /// Close the current database, optionally saving analysis back to the `.i64`.
    pub fn close(&mut self, save: bool) {
        self.close_database(save);
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

    /// Read bytes at `ea` into `buf`, returning how many were supplied. Zero-alloc;
    /// reuse one buffer on hot loops. [`bytes`](Self::bytes) is the owning shortcut.
    pub fn read_into(&self, ea: Ea, buf: &mut [u8]) -> usize {
        let got = self.get_bytes(ea, buf.as_mut_ptr().cast(), buf.len());
        (got.max(0) as usize).min(buf.len())
    }

    /// Read up to `len` bytes at `ea` into a fresh vector (empty on failure).
    #[must_use]
    pub fn bytes(&self, ea: Ea, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let got = self.read_into(ea, &mut buf);
        buf.truncate(got);
        buf
    }

    /// All cross-references targeting `ea`. Owned `Vec`: the facade is a bulk
    /// count-then-fill API, not a cursor.
    #[must_use]
    pub fn xrefs_to(&self, ea: Ea) -> Vec<Xref> {
        // Count (cap 0 writes nothing), then fill exact buffers.
        let n = self.xrefs_to_raw(ea, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0);
        if n == 0 {
            return Vec::new();
        }
        let mut from = vec![0u64; n];
        let mut types = vec![0u8; n];
        let mut iscode = vec![0u8; n];
        let written = self.xrefs_to_raw(
            ea,
            from.as_mut_ptr(),
            types.as_mut_ptr(),
            iscode.as_mut_ptr(),
            n,
        );
        let written = written.min(n);
        (0..written)
            .filter_map(|i| Xref::from_raw(from[i], types[i], iscode[i]))
            .collect()
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

/// Kernel-thread stack. `init_library` recurses deep through `init_kernel`, and a
/// spawned thread's stack is fixed (no autogrow), so reserve generously; the
/// reservation is committed lazily.
const KERNEL_STACK: usize = 256 << 20;

impl Ida {
    /// Spawn the kernel thread, claim the kernel on it, and run `app` on the current
    /// thread with an [`Ida`] handle. Returns once `app` returns; the kernel thread
    /// then shuts down after every handle is dropped. Call once, typically from the
    /// OS main thread so the host keeps it for its own runtime.
    ///
    /// `Err` only on kernel *setup* failure ([`InitError`]); a panic in `app` itself
    /// propagates inline, since `app` runs on the caller's own thread.
    pub fn run<R, F>(app: F) -> Result<R, InitError>
    where
        F: FnOnce(Ida) -> R,
    {
        let (tx, rx) = channel::<Job>();
        let (setup_tx, setup_rx) = channel::<Result<(), InitError>>();

        let kernel = thread::Builder::new()
            .name("idakit-kernel".into())
            .stack_size(KERNEL_STACK)
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
        // job, so a panic here is an unexpected kernel-setup failure — surface it
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

/// Claim the kernel "main" thread and initialize the library, on the kernel thread.
fn bring_up_kernel() -> Result<(), InitError> {
    claim::steal_main().map_err(|reason| InitError::Claim { reason })?;
    // SAFETY: on the (now) kernel thread, once, before any other kernel call.
    let rc = unsafe { sys::init_library(0, ptr::null_mut()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(InitError::InitLibrary { code: rc })
    }
}
