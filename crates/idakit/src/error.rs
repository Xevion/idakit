//! The crate error types. Operational calls return [`Result`]; the kernel boundary
//! has its own [`CallError`] (a job panicked / the kernel is gone) and [`InitError`]
//! (kernel setup failed), mirroring how `std`/tokio model a task boundary.

use std::any::Any;
use std::fmt;

use snafu::Snafu;

use crate::ctree::ExtractError;

/// IDA's `error_t` code, with the documented generic values named. Carried by the
/// operational errors below; the raw integer is available via [`Qerrno::code`].
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

/// `": {reason}"` when present, empty otherwise — for the optional tail of a
/// [`Error::WriteRejected`] message.
struct ReasonTail<'a>(&'a Option<String>);

impl fmt::Display for ReasonTail<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(reason) => write!(f, ": {reason}"),
            None => Ok(()),
        }
    }
}

/// A failure from an idiomatic `idakit` operation.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    /// The database file could not be opened.
    #[snafu(display("failed to open database {path:?}: {reason}"))]
    Open {
        /// The database path that failed to open.
        path: String,
        /// IDA's `error_t` for the failure.
        qerrno: Qerrno,
        /// Human-readable failure reason.
        reason: String,
    },

    /// `reason` comes from Hex-Rays' `hexrays_failure_t` (the real decompile-error
    /// channel; the kernel's `qerrno` is not set on this path).
    #[snafu(display("decompilation failed at {ea:#x}: {reason}"))]
    Decompile {
        /// Address that failed to decompile.
        ea: u64,
        /// Hex-Rays failure description.
        reason: String,
    },

    /// Decompiled, but the ctree could not be materialized; carries the [`ExtractError`].
    #[snafu(display("ctree extraction failed at {ea:#x}: {source}"))]
    Extract {
        /// Address whose ctree failed to materialize.
        ea: u64,
        /// The underlying extraction error.
        source: ExtractError,
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

    /// A write (`op` names the kernel op, e.g. `"rename"`) was rejected. `reason` is
    /// present only when the kernel left a usable `error_t` — best-effort, since not
    /// every rejection path sets one.
    #[snafu(display("{op} failed at {ea:#x}{}", ReasonTail(reason)))]
    WriteRejected {
        /// The kernel operation that was rejected (e.g. `"rename"`).
        op: &'static str,
        /// Address the write targeted.
        ea: u64,
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

    /// A marshaled [`call`](crate::Ida::call) did not return: the kernel closure panicked or
    /// the thread is gone. `?` converts a [`CallError`] into this via [`From`], flattening
    /// the call boundary into one [`Result`]; the panic payload is reduced to its message.
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

/// Why a marshaled [`call`](crate::Ida::call) did not return a value.
pub enum CallError {
    /// The closure panicked on the kernel thread. The original payload is kept so it
    /// can be inspected with [`message`](CallError::message) or re-raised with
    /// [`resume`](CallError::resume) — nothing is lost to stringification.
    Panicked(Box<dyn Any + Send + 'static>),

    /// The kernel thread is gone: it shut down or died before returning a value.
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

/// Why the kernel thread could not be brought up in [`run`](crate::Ida::run).
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
    /// [`Idb`](crate::Idb) before [`here`](crate::Ida::here)/[`run`](crate::Ida::run) again.
    #[snafu(display("a kernel is already live in this process"))]
    AlreadyRunning,
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    /// Each error variant renders its operation, hex address, and reason — and omits the
    /// reason clause when there is none.
    #[rstest]
    #[case::decompile(
        Error::Decompile { ea: 0x1400_1000, reason: "no function".to_owned() },
        "decompilation failed at 0x14001000: no function",
    )]
    #[case::write_rejected_with_reason(
        Error::WriteRejected {
            op: "set_comment",
            ea: 0x40_1000,
            qerrno: Qerrno::Os,
            reason: Some("permission denied".to_owned()),
        },
        "set_comment failed at 0x401000: permission denied",
    )]
    #[case::write_rejected_no_reason(
        Error::WriteRejected { op: "rename", ea: 0x40_1000, qerrno: Qerrno::Ok, reason: None },
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
        Error::Extract { ea: 0x1400_1000, source: ExtractError::WalkFailed },
        "ctree extraction failed at 0x14001000: the facade could not walk the ctree (null cfunc)",
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
