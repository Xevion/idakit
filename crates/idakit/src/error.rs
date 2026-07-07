//! [`Error`]: the crate's error type for operational calls.
//!
//! The kernel boundary has its own error types: [`CallError`] (a job panicked or the kernel
//! is gone) and [`InitError`] (kernel setup failed). This mirrors how `std`/tokio model a
//! task boundary.

use std::any::Any;
use std::fmt;

use snafu::Snafu;

use crate::ctree::ExtractError;
use crate::instruction::DecodeError;

/// IDA's `error_t` code, with the documented generic values named.
///
/// Carried by the operational errors below. The raw integer is available via [`Qerrno::code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Qerrno {
    /// `eOk`: no error.
    Ok,
    /// `eOS`: an OS error; the real reason is the C `errno`.
    Os,
    /// `eDiskFull`.
    DiskFull,
    /// `eReadError`.
    ReadError,
    /// `eFileTooLarge`.
    FileTooLarge,
    /// A code outside the documented generic set.
    Other(i32),
}

impl Qerrno {
    /// Classify a raw `error_t`.
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Os,
            2 => Self::DiskFull,
            3 => Self::ReadError,
            4 => Self::FileTooLarge,
            other => Self::Other(other),
        }
    }

    /// The raw `error_t` integer.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::Os => 1,
            Self::DiskFull => 2,
            Self::ReadError => 3,
            Self::FileTooLarge => 4,
            Self::Other(c) => c,
        }
    }
}

/// `": {reason}"` when present, empty otherwise.
///
/// Used for the optional tail of an [`Error::WriteRejected`] message.
struct ReasonTail<'a>(&'a Option<String>);

impl fmt::Display for ReasonTail<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(reason) => write!(f, ": {reason}"),
            None => Ok(()),
        }
    }
}

/// Why a [`Pattern`](crate::search::Pattern) constructor rejected its input.
///
/// Carried by [`Error::PatternRejected`] as a typed reason rather than an opaque message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatternRejection {
    /// A [`hex`](crate::search::Pattern::hex) token was neither a hex byte, a nibble pattern
    /// (`4?`/`?B`), nor a wildcard (`?`/`??`).
    BadToken {
        /// The offending token, verbatim.
        token: String,
        /// Its zero-based position in the whitespace-split pattern.
        index: usize,
    },

    /// A [`code_mask`](crate::search::Pattern::code_mask) mask character was not one of `x`/`X`
    /// (match) or `?`/`.` (wildcard).
    BadMaskChar {
        /// The offending mask character.
        ch: char,
        /// Its zero-based position in the mask string.
        index: usize,
    },

    /// A mask's length did not match the byte sequence it applies to
    /// ([`bytes`](crate::search::Pattern::bytes)/[`code_mask`](crate::search::Pattern::code_mask)).
    MaskMismatch {
        /// Number of pattern bytes.
        bytes: usize,
        /// Number of mask entries.
        mask: usize,
    },

    /// The pattern pins no bit to match on because it is empty or all wildcards. A search on
    /// it could only ever match nothing, so it is rejected rather than run. `total` is the
    /// compiled length in bytes.
    NoAnchor {
        /// Total pattern bytes (every one a full wildcard).
        total: usize,
    },

    /// IDA's parser rejected an [`ida`](crate::search::Pattern::ida) pattern outright (an empty
    /// string, an unterminated `"`). `detail` is IDA's own diagnostic, when it gave one.
    Unparseable {
        /// IDA's parser message, when non-empty.
        detail: Option<String>,
    },
}

impl fmt::Display for PatternRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadToken { token, index } => {
                write!(
                    f,
                    "token {token:?} at position {index} is not a hex byte, nibble, or wildcard"
                )
            }
            Self::BadMaskChar { ch, index } => {
                write!(
                    f,
                    "mask character {ch:?} at position {index} is not one of x, ?, ."
                )
            }
            Self::MaskMismatch { bytes, mask } => {
                write!(
                    f,
                    "mask length {mask} does not match pattern length {bytes}"
                )
            }
            Self::NoAnchor { total: 0 } => f.write_str("pattern is empty"),
            Self::NoAnchor { total } => {
                write!(f, "pattern pins no concrete bits ({total} wildcard bytes)")
            }
            Self::Unparseable { detail: Some(d) } => write!(f, "could not parse ({d})"),
            Self::Unparseable { detail: None } => f.write_str("could not parse"),
        }
    }
}

/// A failure from an idiomatic `idakit` operation.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    /// The database file could not be opened. `reason` is IDA's own error text via
    /// `get_qerrno` (e.g. `"Resource temporarily unavailable"` when another process holds
    /// the database open).
    #[snafu(display("failed to open database {path:?}: {reason}"))]
    Open {
        /// The database path that failed to open.
        path: String,
        /// IDA's `error_t` for the failure.
        qerrno: Qerrno,
        /// Human-readable failure reason, from `get_qerrno`/`qstrerror`.
        reason: String,
    },

    /// `reason` comes from Hex-Rays' `hexrays_failure_t` (the real decompile-error
    /// channel; the kernel's `qerrno` is not set on this path).
    #[snafu(display("decompilation failed at {address:#x}: {reason}"))]
    Decompile {
        /// Address that failed to decompile.
        address: u64,
        /// Hex-Rays failure description.
        reason: String,
    },

    /// A structured type walk (a ctree or a stack frame) could not be materialized; carries the
    /// [`ExtractError`].
    #[snafu(display("type extraction failed at {address:#x}: {source}"))]
    Extract {
        /// Address whose types failed to materialize.
        address: u64,
        /// The underlying extraction error.
        source: ExtractError,
    },

    /// Instruction decoding failed; carries the [`DecodeError`]. [`decode`](crate::Database::decode)
    /// returns [`DecodeError`] directly, but `#[snafu(context(false))]` gives a `From` so `?`
    /// flattens it into an [`Error`] in code that returns the crate [`Result`].
    #[snafu(display("{source}"), context(false))]
    Decode {
        /// The underlying decode error.
        source: DecodeError,
    },

    /// The Hex-Rays decompiler could not be initialized.
    #[snafu(display("hex-rays decompiler unavailable (init returned {code})"))]
    HexRaysInit {
        /// The initializer's return code.
        code: i32,
    },

    /// No type with the requested name exists in the database.
    #[snafu(display("no type named {name:?} in the database"))]
    TypeNotFound {
        /// The type name that was not found.
        name: String,
    },

    /// No function covers the requested address (e.g. building a
    /// [`FlowChart`](crate::flowchart::FlowChart) at an address IDA has not attributed to any function).
    #[snafu(display("no function at {address:#x}"))]
    NoFunction {
        /// The address that lies in no function.
        address: u64,
    },

    /// A basic block reported an `fc_block_type_t` outside the modelled set, whether from a
    /// newer IDA SDK that added a block terminator, or a corrupt flow chart. Empirically
    /// unreachable on 9.3. A loud version-drift guard rather than a silently absorbed
    /// catch-all value.
    #[snafu(display("unmodeled block kind {raw} in the flow chart at {block:#x}"))]
    UnknownBlockKind {
        /// Start address of the block whose kind did not map.
        block: u64,
        /// The raw `fc_block_type_t` byte outside the modelled set.
        raw: u8,
    },

    /// A binary search pattern was rejected while building a [`Pattern`](crate::search::Pattern)
    /// (e.g. via [`hex`](crate::search::Pattern::hex)). `kind` is a typed reason; see [`PatternRejection`].
    #[snafu(display("invalid search pattern {pattern:?}: {kind}"))]
    PatternRejected {
        /// The pattern string that was rejected.
        pattern: String,
        /// Why it was rejected.
        kind: PatternRejection,
    },

    /// A write (`op` names the kernel op, e.g. `"rename"`) was rejected. `reason` is
    /// present only when the kernel left a usable `error_t` (best-effort, since not
    /// every rejection path sets one).
    #[snafu(display("{op} failed at {address:#x}{}", ReasonTail(reason)))]
    WriteRejected {
        /// The kernel operation that was rejected (e.g. `"rename"`).
        op: &'static str,
        /// Address the write targeted.
        address: u64,
        /// IDA's `error_t`, when one was set.
        qerrno: Qerrno,
        /// Human-readable reason, when the kernel left one.
        reason: Option<String>,
    },

    /// A string argument contained an interior NUL byte.
    #[snafu(display("argument {arg} contains an interior NUL byte"))]
    InteriorNul {
        /// The argument name that contained the NUL.
        arg: &'static str,
    },

    /// The kernel tried to terminate the process with `exit(code)` mid-operation.
    ///
    /// IDA's reaction to an unrecoverable condition such as an unaccepted license. The
    /// facade trapped the exit and returned control, but the kernel has already torn
    /// itself down, so the [`Database`](crate::Database) is unusable and a fresh process is
    /// needed to run IDA again. `diagnostic` is whatever IDA printed on its way out (captured,
    /// not leaked), e.g. `"License not yet accepted, cannot run in batch mode"`.
    #[snafu(display(
        "the IDA kernel aborted the process (exit code {code}){}",
        ReasonTail(diagnostic)
    ))]
    KernelExit {
        /// The code IDA passed to `exit()`.
        code: i32,
        /// What IDA printed before exiting, when it printed anything.
        diagnostic: Option<String>,
    },

    /// A marshaled [`call`](crate::kernel::Ida::call) did not return, because the kernel closure
    /// panicked or the thread is gone. `?` converts a [`CallError`] into this via [`From`], flattening
    /// the call boundary into one [`Result`]. The panic payload is reduced to its message.
    /// Handle [`CallError`] directly to inspect or [`resume`](CallError::resume) it.
    #[snafu(display("kernel call did not return: {reason}"))]
    Kernel {
        /// Why the call did not return.
        reason: String,
    },
}

/// `Result` specialised to this crate's [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Lets `ida.call(...)?` flatten `Result<Result<T, Error>, CallError>` to `Result<T, Error>`.
/// Lossy: a [`CallError::Panicked`] payload is reduced to its message (see [`Error::Kernel`]).
impl From<CallError> for Error {
    fn from(e: CallError) -> Self {
        Error::Kernel {
            reason: e.to_string(),
        }
    }
}

/// Why a marshaled [`call`](crate::kernel::Ida::call) did not return a value.
pub enum CallError {
    /// The closure panicked on the kernel thread. The original payload is kept so it
    /// can be inspected with [`message`](CallError::message) or re-raised with
    /// [`resume`](CallError::resume), so nothing is lost to stringification.
    Panicked(Box<dyn Any + Send + 'static>),

    /// The kernel thread is gone, having shut down or died before returning a value.
    Disconnected,
}

impl CallError {
    /// The panic message, when the payload was a `&str` or `String`.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Panicked(payload) => panic_payload_str(&**payload),
            Self::Disconnected => None,
        }
    }

    /// Re-raise the original panic on the current thread. [`Disconnected`] carries no
    /// payload, so it panics with a generic message instead.
    ///
    /// [`Disconnected`]: CallError::Disconnected
    pub fn resume(self) -> ! {
        match self {
            Self::Panicked(payload) => std::panic::resume_unwind(payload),
            Self::Disconnected => panic!("the kernel thread is gone"),
        }
    }
}

/// The string behind a caught panic payload, when it was a `&str`/`String`.
pub(crate) fn panic_payload_str(payload: &(dyn Any + Send)) -> Option<&str> {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Panicked(_) => match self.message() {
                Some(message) => write!(f, "the kernel closure panicked: {message}"),
                None => f.write_str("the kernel closure panicked (non-string payload)"),
            },
            Self::Disconnected => f.write_str("the kernel thread is gone"),
        }
    }
}

impl fmt::Debug for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Panicked(_) => f
                .debug_tuple("Panicked")
                .field(&self.message().unwrap_or("<non-string payload>"))
                .finish(),
            Self::Disconnected => f.write_str("Disconnected"),
        }
    }
}

impl std::error::Error for CallError {}

/// Why the kernel thread could not be brought up in [`run`](crate::kernel::Ida::run).
#[derive(Debug, Snafu)]
pub enum InitError {
    /// The kernel "main" thread could not be re-claimed (unrecognized
    /// `is_main_thread` prologue, or the re-claim did not take).
    #[snafu(display("could not claim the kernel thread: {reason}"))]
    Claim {
        /// Why the kernel thread could not be claimed.
        reason: String,
    },

    /// `init_library` returned a non-zero code.
    #[snafu(display("init_library failed (code {code})"))]
    InitLibrary {
        /// `init_library`'s non-zero return code.
        code: i32,
    },

    /// The kernel thread exited before reporting setup status.
    #[snafu(display("the kernel thread exited before initializing"))]
    KernelGone,

    /// A kernel is already live; the kernel is a process global, so drop the existing
    /// [`Database`](crate::Database) before [`here`](crate::kernel::Ida::here)/[`run`](crate::kernel::Ida::run) again.
    #[snafu(display("a kernel is already live in this process"))]
    AlreadyRunning,
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Each error variant renders its operation, hex address, and reason, and omits the
    /// reason clause when there is none.
    #[rstest]
    #[case::decompile(
        Error::Decompile { address: 0x1400_1000, reason: "no function".to_owned() },
        "decompilation failed at 0x14001000: no function",
    )]
    #[case::write_rejected_with_reason(
        Error::WriteRejected {
            op: "set_comment",
            address: 0x40_1000,
            qerrno: Qerrno::Os,
            reason: Some("permission denied".to_owned()),
        },
        "set_comment failed at 0x401000: permission denied",
    )]
    #[case::write_rejected_no_reason(
        Error::WriteRejected { op: "rename", address: 0x40_1000, qerrno: Qerrno::Ok, reason: None },
        "rename failed at 0x401000",
    )]
    #[case::open(
        Error::Open {
            path: "/tmp/x.i64".into(),
            qerrno: Qerrno::Os,
            reason: "No such file or directory".to_owned(),
        },
        "failed to open database \"/tmp/x.i64\": No such file or directory",
    )]
    #[case::extract(
        Error::Extract { address: 0x1400_1000, source: ExtractError::WalkFailed },
        "type extraction failed at 0x14001000: the facade could not walk the ctree (null cfunc)",
    )]
    #[case::kernel(
        Error::Kernel { reason: "the kernel thread is gone".to_owned() },
        "kernel call did not return: the kernel thread is gone",
    )]
    fn error_displays(#[case] err: Error, #[case] expect: &str) {
        assert!(err.to_string() == expect);
    }

    /// `?` on a `call` result flattens through this `From` into [`Error::Kernel`].
    #[test]
    fn call_error_flattens_into_error() {
        let err: Error = CallError::Disconnected.into();
        assert!(err.to_string() == "kernel call did not return: the kernel thread is gone");
        assert!(let Error::Kernel { .. } = err);
    }

    /// `Qerrno` round-trips its raw code, with the named codes mapping by value and any
    /// other code preserved through `Other`.
    #[rstest]
    #[case(0, Qerrno::Ok)]
    #[case(1, Qerrno::Os)]
    #[case(2, Qerrno::DiskFull)]
    #[case(3, Qerrno::ReadError)]
    #[case(4, Qerrno::FileTooLarge)]
    #[case(7, Qerrno::Other(7))]
    fn qerrno_round_trips_codes(#[case] code: i32, #[case] expect: Qerrno) {
        assert!(Qerrno::from_code(code) == expect);
        assert!(expect.code() == code);
    }
}
