//! The crate error type; every fallible call returns [`Result`].

use snafu::Snafu;

/// A failure from an idiomatic `idakit` operation.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("failed to open database {path:?} (code {code})"))]
    Open { path: String, code: i32 },

    #[snafu(display("decompilation failed at {ea:#x}"))]
    Decompile { ea: u64 },

    #[snafu(display("hex-rays decompiler unavailable (init returned {code})"))]
    HexRaysInit { code: i32 },

    #[snafu(display("no type named {name:?} in the database"))]
    TypeNotFound { name: String },

    /// A write (`rename` / `set_comment`) was rejected by the kernel.
    #[snafu(display("{op} failed at {ea:#x}"))]
    WriteRejected { op: &'static str, ea: u64 },

    #[snafu(display("argument {arg} contains an interior NUL byte"))]
    InteriorNul { arg: &'static str },
}

/// `Result` specialised to this crate's [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn displays_hex_addresses() {
        let e = Error::Decompile { ea: 0x1400_1000 };
        assert!(e.to_string() == "decompilation failed at 0x14001000");
    }

    #[test]
    fn open_renders_path_and_code() {
        let e = Error::Open {
            path: "/tmp/x.i64".into(),
            code: 3,
        };
        assert!(e.to_string() == "failed to open database \"/tmp/x.i64\" (code 3)");
    }
}
