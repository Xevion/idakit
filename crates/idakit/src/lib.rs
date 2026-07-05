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

use idakit_sys as sys;

mod bytes;
mod claim;
pub mod ctree;
mod decompile;
mod ea;
mod error;
mod ffi;
mod func;
mod insn;
mod kernel;
mod meta;
mod name;
mod raw;
mod search;
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
pub use kernel::{Ida, IdaConfig, IdaConfigBuilder};
pub use meta::Meta;
pub use name::{Name, Names};
pub use search::{Matches, Pattern};
pub use segment::{Segment, Segments};
pub use ty::{Member, Members, TypeInfo};
pub use xref::{CodeRef, DataRef, Xref, XrefKind, Xrefs};

use crate::kernel::KernelClaim;

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
        #[builder(start_fn)] path: impl AsRef<str>,
        #[builder(default)] run_auto: bool,
    ) -> Result<()> {
        let path = path.as_ref();
        let rc = ffi::with_cstr(path, "path", |p| self.open_database(p, run_auto))?;
        if rc == sys::IDAKIT_EXIT_TRAPPED {
            // IDA hit an unrecoverable condition and tried to terminate the process; the
            // facade trapped the exit() and handed control back, with whatever it printed.
            return Err(self.kernel_exit_error());
        }
        if rc != 0 {
            // open_database's return value is an internal status, not an error_t: a locked
            // database returns 4 (which reads as eFileTooLarge) though the real failure is in
            // get_qerrno(). Read IDA's own error channel, as the write paths do.
            let (qerrno, reason) = self.last_reason();
            return Err(Error::Open {
                path: path.to_owned(),
                qerrno,
                reason: reason.unwrap_or_else(|| format!("open failed (status {rc})")),
            });
        }
        // run_auto only enables the analysis queue; block until it drains so callers
        // observe a fully analyzed database. Analysis runs kernel code, so it can trap too.
        if run_auto && self.auto_wait() == sys::IDAKIT_EXIT_TRAPPED {
            return Err(self.kernel_exit_error());
        }
        Ok(())
    }
}

impl Idb {
    /// The actor's `Idb`; `run` holds its claim.
    pub(crate) fn new() -> Self {
        Self {
            hexrays_ready: Cell::new(false),
            _claim: None,
            _not_send: PhantomData,
        }
    }

    /// An in-place `Idb` that releases the kernel when dropped.
    pub(crate) fn owned(claim: KernelClaim) -> Self {
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
    pub(crate) fn kernel_exit_error(&self) -> Error {
        let captured = self.last_output();
        let trimmed = captured.trim();
        Error::KernelExit {
            code: self.last_exit_code(),
            diagnostic: (!trimmed.is_empty()).then(|| trimmed.to_owned()),
        }
    }
}
