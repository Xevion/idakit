//! Idiomatic Rust bindings for IDA Pro's `idalib` (9.x).
//!
//! # The kernel thread
//!
//! The IDA kernel is single-threaded and thread-affine. [`Ida::here`](crate::kernel::Ida::here) brings it up *on
//! the current thread* and hands back the open [`Database`] -- no kernel thread, no closure --
//! for programs that own their thread (scripts, tests, CLIs):
//!
//! ```no_run
//! use idakit::kernel::Ida;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut idb = Ida::here()?;
//! idb.open("/path/to/db.i64").call()?;
//! for function in idb.functions() {
//!     println!("{:#x} {}", function.address().get(), function.name());
//! }
//! idb.close(false);
//! # Ok(())
//! # }
//! ```
//!
//! When the current thread must stay free (GUI/async) or many threads drive the kernel,
//! [`Ida::run`](crate::kernel::Ida::run) hosts it on a dedicated thread and runs your app on the caller; any
//! thread marshals work onto the kernel with [`Ida::call`](crate::kernel::Ida::call):
//!
//! ```no_run
//! use idakit::prelude::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! Ida::run(|ida| {
//!     ida.call(|idb: &mut Database| -> Result<()> {
//!         idb.open("/path/to/db.i64").call()?;
//!         idb.close(false);
//!         Ok(())
//!     })?
//! })??;
//! # Ok(())
//! # }
//! ```
//!
//! The kernel is a process global: only one `Database` is live at a time (a second
//! [`here`](crate::kernel::Ida::here)/[`run`](crate::kernel::Ida::run) yields
//! [`InitError::AlreadyRunning`](crate::error::InitError::AlreadyRunning)).
//!
//! # Read/write separation
//!
//! [`Database`] is `!Send + !Sync`, so it stays on the kernel thread. Reads borrow `&Database` and
//! return lightweight views ([`Function`](crate::function::Function), [`Segment`](crate::segment::Segment), ...); writes take `&mut Database`, so a read
//! view can't be held across a mutation.
//!
//! # Building
//!
//! Linking needs a real IDA install (`IDADIR`, holding `libida.so`); the build compiles
//! a small C++ facade against the IDA SDK headers, fetched to match the installed IDA
//! version (override with `IDA_SDK_DIR`). Databases must be 64-bit `.i64` -- the facade
//! is compiled `__EA64__`.
#![deny(missing_docs)]
#![deny(
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::invalid_rust_codeblocks,
    rustdoc::bare_urls,
    rustdoc::unescaped_backticks,
    rustdoc::redundant_explicit_links
)]

use std::cell::Cell;
use std::marker::PhantomData;

pub use idakit_sys as sys;

pub mod address;
pub mod arena;
pub mod bitness;
mod bytes;
mod claim;
pub mod ctree;
mod data;
pub mod decompile;
#[doc(hidden)]
pub mod doctest;
pub mod error;
pub mod export;
mod ffi;
pub mod flowchart;
pub mod function;
pub mod import;
pub mod instruction;
pub mod kernel;
pub mod meta;
pub mod name;
mod raw;
pub mod search;
pub mod segment;
pub mod stack;
pub mod strings;
pub mod types;
pub mod xref;

/// Re-exports of the crate's primary types, for a single glob import
/// (`use idakit::prelude::*;`).
pub mod prelude {
    pub use crate::Database;
    pub use crate::address::Address;
    pub use crate::bitness::Bitness;
    pub use crate::ctree::{AssignOp, BinOp, UnOp};
    pub use crate::decompile::{CtreeCounts, DecompiledFunction};
    pub use crate::error::{CallError, Error, InitError, PatternRejection, Qerrno, Result};
    pub use crate::export::{Export, Exports};
    pub use crate::flowchart::{BasicBlock, BasicBlockId, BasicBlockKind, ExternalExit, FlowChart};
    pub use crate::function::{
        Function, FunctionChunk, FunctionChunks, FunctionName, FunctionSnapshot, Functions,
        Instructions, InstructionsIn,
    };
    pub use crate::import::{Import, Imports};
    pub use crate::instruction::{
        Access, DecodeError, Flow, Instruction, Isa, Memory, Operand, OperandDataType, OperandKind,
        Register, RegisterClass,
    };
    pub use crate::kernel::{Ida, IdaConfig, IdaConfigBuilder};
    pub use crate::meta::DatabaseInfo;
    pub use crate::name::{Name, Names};
    pub use crate::search::{Matches, Pattern};
    pub use crate::segment::{Segment, SegmentClass, Segments};
    pub use crate::stack::{StackFrame, StackSlot, StackSlotKind};
    pub use crate::strings::{StringLiteral, Strings};
    pub use crate::types::{
        AggregateKind, CanonicalMember, CanonicalOptions, CanonicalType, CatalogDiff, Change,
        ChangeKind, EnumMember, NamedType, NamedTypes, Type, TypeCatalog, TypeDiff, TypeId,
        TypeIdentity, TypeKey, TypeMember, TypeShape, TypeTable, TypeValue, canonicalize,
    };
    pub use crate::xref::{CodeXref, DataXref, Xref, XrefKind, XrefOrigin, Xrefs};
}

use crate::error::{Error, Result};
use crate::kernel::KernelClaim;

/// The open database. `!Send + !Sync`, so it stays on the kernel thread. Reads borrow
/// `&Database` (returning [`Function`](crate::function::Function)/[`Segment`](crate::segment::Segment) views); writes take `&mut Database`, so a read
/// view can't be held across a write.
pub struct Database {
    /// Interior mutability lets `decompile(&self)` init Hex-Rays lazily.
    hexrays_ready: Cell<bool>,
    /// `Some` for an in-place `Database`; `None` for the actor's, whose claim `run` holds.
    _claim: Option<KernelClaim>,
    _not_send: PhantomData<*const ()>,
}

/// Database-open builder: `idb.open(path).run_auto(true).call()`. `path` stays a
/// positional argument; options chain before the terminal `.call()`.
#[bon::bon]
impl Database {
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

impl Database {
    /// The actor's `Database`; `run` holds its claim.
    pub(crate) fn new() -> Self {
        Self {
            hexrays_ready: Cell::new(false),
            _claim: None,
            _not_send: PhantomData,
        }
    }

    /// An in-place `Database` that releases the kernel when dropped.
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

    /// Open `path`, run `f` against the open database, and close it (without saving) on every exit:
    /// a normal return, an early `?`, or a panic. The read-only scoping the two-database workflows
    /// want, so a `close` can't be forgotten:
    /// `let catalog = idb.with_open(&path, |idb| Ok(idb.type_catalog()))?;`. Opens without
    /// auto-analysis (an already-analyzed `.i64`); use [`open`](Self::open) directly when you need
    /// `run_auto`, or to save on close.
    pub fn with_open<T>(
        &mut self,
        path: impl AsRef<str>,
        f: impl FnOnce(&mut Database) -> Result<T>,
    ) -> Result<T> {
        self.open(path).call()?;
        let closer = CloseOnDrop { db: self };
        f(&mut *closer.db)
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

/// Closes the borrowed database on drop, so [`Database::with_open`] releases it on every exit path,
/// including a panic unwinding through the caller's closure.
struct CloseOnDrop<'db> {
    db: &'db mut Database,
}

impl Drop for CloseOnDrop<'_> {
    fn drop(&mut self) {
        self.db.close(false);
    }
}
