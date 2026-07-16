//! Error types for idiomatic `idakit` calls.
//!
//! The kernel boundary has its own error types: [`CallError`] (a job panicked or the kernel
//! is gone) and [`InitError`] (kernel setup failed). This mirrors how `std`/tokio model a
//! task boundary.

use std::any::Any;
use std::fmt;

use snafu::Snafu;

use crate::decompiler::ctree::ExtractError;
use crate::instruction::DecodeError;
use crate::netnode::NetnodeBytesError;
use crate::types::TypeWriteError;

/// IDA's error code, with the documented generic values named.
///
/// Carried by the operational errors below. The raw integer is available via [`Qerrno::code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(alias("error_t"))]
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
    /// Classify a raw error code.
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

    /// The raw error code integer.
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

impl fmt::Display for Qerrno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Ok => "no error",
            Self::Os => "OS error (see errno)",
            Self::DiskFull => "disk full",
            Self::ReadError => "read error",
            Self::FileTooLarge => "file too large",
            Self::Other(_) => "unrecognized error",
        };
        write!(f, "{label} (code {})", self.code())
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
    /// The database file could not be opened. `reason` is IDA's own error text (e.g.
    /// `"Resource temporarily unavailable"` when another process holds the database open).
    #[snafu(display("failed to open database {path:?}: {reason}"))]
    Open {
        /// The database path that failed to open.
        path: String,
        /// IDA's error code for the failure.
        qerrno: Qerrno,
        /// Human-readable failure reason, from IDA's own error text.
        reason: String,
    },

    /// `reason` comes from Hex-Rays' own failure channel, not the kernel's error code
    /// (which is not set on this path).
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
    #[snafu(display("hex-rays decompiler could not be initialized"))]
    HexRaysInit,

    /// No type with the requested name exists in the database. Raised by the type-read lookups
    /// ([`Database::type_named`](crate::Database::type_named),
    /// [`NamedType::resolve`](crate::types::NamedType::resolve)); the type-write surface reports an
    /// absent type as [`TypeWriteError::NoType`] instead.
    #[snafu(display("no type named {name:?} in the database"))]
    TypeNotFound {
        /// The type name that was not found.
        name: String,
    },

    /// One or more type declarations could not be added to the database's type library. `reason`
    /// is IDA's own diagnostics, captured off the message channel.
    #[snafu(display("could not define type {decl:?}: {reason}"))]
    TypeDefineFailed {
        /// The declaration text that failed.
        decl: String,
        /// IDA's diagnostics.
        reason: String,
    },

    /// No function covers the requested address (e.g. building a
    /// [`FlowChart`](crate::flowchart::FlowChart) at an address IDA has not attributed to any function).
    #[snafu(display("no function at {address:#x}"))]
    NoFunction {
        /// The address that lies in no function.
        address: u64,
    },

    /// A basic block reported a block kind outside the modelled set, whether from a newer
    /// IDA version that added a block terminator, or a corrupt flow chart. Empirically
    /// unreachable today. A loud version-drift guard rather than a silently absorbed
    /// catch-all value.
    #[snafu(display("unmodeled block kind {raw} in the flow chart at {block:#x}"))]
    UnknownBlockKind {
        /// Start address of the block whose kind did not map.
        block: u64,
        /// The raw block-kind byte outside the modelled set.
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

    /// A netnode value/sup/hash write was given bytes outside the SDK's `1..=MAXSPECSIZE`
    /// domain; carries the typed [`NetnodeBytesError`]. `?` flattens it into the crate
    /// [`Result`] via [`From`] (`context(false)`).
    #[snafu(display("{source}"), context(false))]
    InvalidNetnodeBytes {
        /// The underlying validation failure.
        source: NetnodeBytesError,
    },

    /// A write (`op` names the kernel op, e.g. `"rename"`) was rejected. `reason` is
    /// present only when the kernel left a usable error code (best-effort, since not
    /// every rejection path sets one).
    #[snafu(display("{op} failed at {address:#x}{}", ReasonTail(reason)))]
    WriteRejected {
        /// The kernel operation that was rejected (e.g. `"rename"`).
        op: &'static str,
        /// Address the write targeted.
        address: u64,
        /// IDA's error code, when one was set.
        qerrno: Qerrno,
        /// Human-readable reason, when the kernel left one.
        reason: Option<String>,
    },

    /// A type-write operation failed; carries the typed [`TypeWriteError`]. `?` flattens it into
    /// the crate [`Result`] via [`From`] (`context(false)`), so every type-write routes through
    /// one [`Result`].
    #[snafu(display("{source}"), context(false))]
    TypeWrite {
        /// The underlying type-write error.
        source: TypeWriteError,
    },

    /// A string argument contained an interior NUL byte.
    #[snafu(display("argument {arg} contains an interior NUL byte"))]
    InteriorNul {
        /// The argument name that contained the NUL.
        arg: &'static str,
    },

    /// A value could not be serialized for netnode storage (a postcard encoding failure).
    #[cfg(feature = "serde")]
    #[snafu(display("could not serialize value for netnode storage: {reason}"))]
    SerializeFailed {
        /// The encoder's failure description.
        reason: String,
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
        Self::Kernel {
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

    /// Re-raise the original panic on the current thread.
    ///
    /// # Panics
    /// Always, by design: it resumes the caught unwind, or panics with a generic message for
    /// [`Disconnected`], which carries no payload.
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
#[derive(Debug, Snafu, PartialEq, Eq)]
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
        Error::Extract { address: 0x1400_1000, source: ExtractError::BadEa },
        "type extraction failed at 0x14001000: a node carries the BADADDR sentinel as a required address",
    )]
    #[case::kernel(
        Error::Kernel { reason: "the kernel thread is gone".to_owned() },
        "kernel call did not return: the kernel thread is gone",
    )]
    #[case::type_define_failed(
        Error::TypeDefineFailed { decl: "struct {".to_owned(), reason: "expected '}'".to_owned() },
        "could not define type \"struct {\": expected '}'",
    )]
    #[case::hex_rays_init(Error::HexRaysInit, "hex-rays decompiler could not be initialized")]
    #[case::type_not_found(
        Error::TypeNotFound { name: "FOO_STRUCT".to_owned() },
        "no type named \"FOO_STRUCT\" in the database",
    )]
    #[case::no_function(
        Error::NoFunction { address: 0x1000 },
        "no function at 0x1000",
    )]
    #[case::unknown_block_kind(
        Error::UnknownBlockKind { block: 0x2000, raw: 200 },
        "unmodeled block kind 200 in the flow chart at 0x2000",
    )]
    #[case::pattern_rejected(
        Error::PatternRejected {
            pattern: "?? gg".to_owned(),
            kind: PatternRejection::BadToken { token: "gg".to_owned(), index: 1 },
        },
        "invalid search pattern \"?? gg\": token \"gg\" at position 1 is not a hex byte, nibble, or wildcard",
    )]
    #[case::interior_nul(
        Error::InteriorNul { arg: "name" },
        "argument name contains an interior NUL byte",
    )]
    #[case::kernel_exit_with_diagnostic(
        Error::KernelExit { code: 1, diagnostic: Some("license not accepted".to_owned()) },
        "the IDA kernel aborted the process (exit code 1): license not accepted",
    )]
    #[case::kernel_exit_no_diagnostic(
        Error::KernelExit { code: 1, diagnostic: None },
        "the IDA kernel aborted the process (exit code 1)",
    )]
    #[case::decode_flattens_through(
        Error::from(DecodeError::NotCode { address: 0x1400_1000 }),
        "no instruction at 0x14001000",
    )]
    #[case::type_write_flattens_through(
        Error::from(TypeWriteError::NoType { name: "FOO".to_owned() }),
        "no type named \"FOO\" in the local type library",
    )]
    #[case::invalid_netnode_bytes_flattens_through(
        Error::from(NetnodeBytesError::TooLarge { len: 1025, cap: 1024 }),
        "netnode value is 1025 bytes, exceeding the 1024-byte MAXSPECSIZE cap",
    )]
    fn error_displays(#[case] err: Error, #[case] expect: &str) {
        assert!(err.to_string() == expect);
    }

    /// [`PatternRejection`] renders its own message independent of the [`Error::PatternRejected`]
    /// wrapper, including the `total == 0` special-case wording for [`PatternRejection::NoAnchor`].
    #[rstest]
    #[case::bad_token(
        PatternRejection::BadToken { token: "zz".to_owned(), index: 3 },
        "token \"zz\" at position 3 is not a hex byte, nibble, or wildcard",
    )]
    #[case::bad_mask_char(
        PatternRejection::BadMaskChar { ch: '!', index: 2 },
        "mask character '!' at position 2 is not one of x, ?, .",
    )]
    #[case::mask_mismatch(
        PatternRejection::MaskMismatch { bytes: 4, mask: 3 },
        "mask length 3 does not match pattern length 4",
    )]
    #[case::no_anchor_empty(
        PatternRejection::NoAnchor { total: 0 },
        "pattern is empty",
    )]
    #[case::no_anchor_all_wildcards(
        PatternRejection::NoAnchor { total: 3 },
        "pattern pins no concrete bits (3 wildcard bytes)",
    )]
    #[case::unparseable_with_detail(
        PatternRejection::Unparseable { detail: Some("unterminated quote".to_owned()) },
        "could not parse (unterminated quote)",
    )]
    #[case::unparseable_without_detail(
        PatternRejection::Unparseable { detail: None },
        "could not parse",
    )]
    fn pattern_rejection_displays(#[case] kind: PatternRejection, #[case] expect: &str) {
        assert!(kind.to_string() == expect);
    }

    /// `?` on a `call` result flattens through this `From` into [`Error::Kernel`].
    #[test]
    fn call_error_flattens_into_error() {
        let err: Error = CallError::Disconnected.into();
        assert!(err.to_string() == "kernel call did not return: the kernel thread is gone");
        assert!(let Error::Kernel { .. } = err);
    }

    /// `Qerrno` round-trips its raw code, with the named codes mapping by value and any
    /// other code preserved through `Other`, including negative and extreme codes.
    #[rstest]
    #[case(0, Qerrno::Ok)]
    #[case(1, Qerrno::Os)]
    #[case(2, Qerrno::DiskFull)]
    #[case(3, Qerrno::ReadError)]
    #[case(4, Qerrno::FileTooLarge)]
    #[case(7, Qerrno::Other(7))]
    #[case(-1, Qerrno::Other(-1))]
    #[case(i32::MIN, Qerrno::Other(i32::MIN))]
    #[case(i32::MAX, Qerrno::Other(i32::MAX))]
    fn qerrno_round_trips_codes(#[case] code: i32, #[case] expect: Qerrno) {
        assert!(Qerrno::from_code(code) == expect);
        assert!(expect.code() == code);
    }

    mod qerrno_proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            // Every raw i32 round-trips through from_code/code, across the whole domain.
            #[test]
            fn from_code_code_roundtrips(code in any::<i32>()) {
                prop_assert_eq!(Qerrno::from_code(code).code(), code);
            }
        }
    }

    /// `Display` names the error and carries its raw code.
    #[rstest]
    #[case(Qerrno::Ok, "no error (code 0)")]
    #[case(Qerrno::DiskFull, "disk full (code 2)")]
    #[case(Qerrno::Other(9), "unrecognized error (code 9)")]
    #[case(Qerrno::Other(-1), "unrecognized error (code -1)")]
    fn qerrno_display_carries_code(#[case] qerrno: Qerrno, #[case] expect: &str) {
        assert!(qerrno.to_string() == expect);
    }

    /// Two `InitError`s with equal payloads compare equal.
    #[test]
    fn init_error_eq() {
        assert!(InitError::InitLibrary { code: 3 } == InitError::InitLibrary { code: 3 });
        assert!(InitError::InitLibrary { code: 3 } != InitError::InitLibrary { code: 4 });
        assert!(InitError::KernelGone == InitError::KernelGone);
    }

    #[rstest]
    #[case::claim(
        InitError::Claim { reason: "unrecognized prologue".to_owned() },
        "could not claim the kernel thread: unrecognized prologue",
    )]
    #[case::init_library(
        InitError::InitLibrary { code: 3 },
        "init_library failed (code 3)",
    )]
    #[case::kernel_gone(InitError::KernelGone, "the kernel thread exited before initializing")]
    #[case::already_running(InitError::AlreadyRunning, "a kernel is already live in this process")]
    fn init_error_displays(#[case] err: InitError, #[case] expect: &str) {
        assert!(err.to_string() == expect);
    }

    /// A `&str` panic payload is recovered by `message()`, rendered in `Display`, and re-raised
    /// verbatim by `resume()`.
    #[test]
    fn call_error_panicked_str_payload() {
        let err = CallError::Panicked(Box::new("boom"));
        assert!(err.message() == Some("boom"));
        assert!(err.to_string() == "the kernel closure panicked: boom");
        assert!(format!("{err:?}") == "Panicked(\"boom\")");
    }

    /// A `String` panic payload is recovered the same way as a `&str` one.
    #[test]
    fn call_error_panicked_string_payload() {
        let err = CallError::Panicked(Box::new(String::from("kaboom")));
        assert!(err.message() == Some("kaboom"));
        assert!(err.to_string() == "the kernel closure panicked: kaboom");
    }

    /// A non-string payload has no recoverable message, and renders a generic placeholder.
    #[test]
    fn call_error_panicked_non_string_payload() {
        let err = CallError::Panicked(Box::new(42i32));
        assert!(err.message().is_none());
        assert!(err.to_string() == "the kernel closure panicked (non-string payload)");
        assert!(format!("{err:?}") == "Panicked(\"<non-string payload>\")");
    }

    #[test]
    fn call_error_disconnected_display_and_debug() {
        assert!(CallError::Disconnected.message().is_none());
        assert!(CallError::Disconnected.to_string() == "the kernel thread is gone");
        assert!(format!("{:?}", CallError::Disconnected) == "Disconnected");
    }

    /// `resume()` re-raises the original panic payload unchanged, not a re-stringified copy.
    #[test]
    fn call_error_resume_reraises_the_original_panic() {
        let result =
            std::panic::catch_unwind(|| CallError::Panicked(Box::new("original message")).resume());
        let payload = result.expect_err("resume always panics");
        assert!(payload.downcast_ref::<&str>() == Some(&"original message"));
    }

    /// `Disconnected` has no payload to resume, so it panics with a generic message instead.
    #[test]
    fn call_error_resume_disconnected_panics_generically() {
        let result = std::panic::catch_unwind(|| CallError::Disconnected.resume());
        assert!(result.is_err());
    }

    /// A value that could not be encoded for netnode storage renders its encoder reason.
    #[cfg(feature = "serde")]
    #[test]
    fn serialize_failed_display() {
        let err = Error::SerializeFailed {
            reason: "sequence too long".to_owned(),
        };
        assert!(
            err.to_string() == "could not serialize value for netnode storage: sequence too long"
        );
    }
}
