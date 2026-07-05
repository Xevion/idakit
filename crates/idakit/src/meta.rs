//! [`Meta`]: an owned snapshot of database-wide metadata.

use std::ops::Range;

use crate::Idb;
use crate::address::Address;
use crate::bitness::Bitness;
use crate::ffi::read_string;

/// An owned, `Send` snapshot of database-wide metadata, from [`Idb::meta`].
///
/// Every field is resolved and copied out at snapshot time, so a `Meta` carries no borrow on
/// the [`Idb`] and can be inspected on any thread. Reading it is a handful of kernel calls,
/// so grab it once rather than per field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    /// Application addressing width, or `None` if the database reports an unrecognized one.
    pub bitness: Option<Bitness>,
    /// Preferred load address (image base), when the format records one.
    pub image_base: Option<Address>,
    /// Processor module id (e.g. `metapc`).
    pub processor: Option<String>,
    /// Human-readable input file format (e.g. `Portable executable for 80386 (PE)`).
    pub file_type: Option<String>,
    /// Full path of the analyzed input file.
    pub input_path: Option<String>,
    /// Base file name of the input.
    pub root_filename: Option<String>,
}

impl Idb {
    /// The database's address bounds as `min..max` (max exclusive), the natural default
    /// range for a whole-image [`search`](Self::search); `None` for a database with no
    /// mapped content.
    #[must_use]
    pub fn address_range(&self) -> Option<Range<Address>> {
        let min = Address::try_new(self.min_ea())?;
        let max = Address::try_new(self.max_ea())?;
        Some(min..max)
    }

    /// Snapshot the database's metadata into an owned, `Send` [`Meta`].
    #[must_use]
    pub fn meta(&self) -> Meta {
        Meta {
            bitness: self.bitness(),
            image_base: Address::try_new(self.image_base()),
            processor: read_string(|buf, cap| self.proc_name(buf, cap)),
            file_type: read_string(|buf, cap| self.file_type_name(buf, cap)),
            input_path: read_string(|buf, cap| self.input_path(buf, cap)),
            root_filename: read_string(|buf, cap| self.root_filename(buf, cap)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Meta;

    const fn assert_send<T: Send>() {}

    // A detached snapshot is only worth having if it can leave the kernel thread.
    const _: () = assert_send::<Meta>();
}
