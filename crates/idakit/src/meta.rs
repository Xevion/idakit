//! Snapshots database-wide metadata into an owned, `Send` [`DatabaseInfo`].

use std::ops::Range;

use crate::Database;
use crate::address::Address;
use crate::bitness::Bitness;

/// An owned, `Send` snapshot of database-wide metadata, from [`Database::info`].
///
/// Every field is resolved and copied out at snapshot time, so a `DatabaseInfo` carries no borrow
/// on the [`Database`] and can be inspected on any thread. Reading it is a handful of kernel
/// calls, so grab it once rather than per field.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(alias("idainfo"))]
pub struct DatabaseInfo {
    /// Application addressing width, or `None` if the database reports an unrecognized one.
    pub bitness: Option<Bitness>,
    /// Preferred load address (image base), when the format records one.
    #[doc(alias("get_imagebase"))]
    pub image_base: Option<Address>,
    /// Processor module id (e.g. `metapc`).
    #[doc(alias("inf_get_procname"))]
    pub processor: Option<String>,
    /// Human-readable input file format (e.g. `Portable executable for 80386 (PE)`).
    #[doc(alias("get_file_type_name"))]
    pub file_type: Option<String>,
    /// Full path of the analyzed input file.
    #[doc(alias("get_input_file_path"))]
    pub input_path: Option<String>,
    /// Base file name of the input.
    pub root_filename: Option<String>,
}

impl Database {
    /// The database's address bounds as `min..max` (max exclusive), the natural default
    /// range for a whole-image [`search`](Self::search); `None` for a database with no
    /// mapped content.
    #[must_use]
    #[doc(alias("inf_get_min_ea", "inf_get_max_ea"))]
    pub fn address_range(&self) -> Option<Range<Address>> {
        let min = Address::try_new(self.min_ea())?;
        let max = Address::try_new(self.max_ea())?;
        Some(min..max)
    }

    /// Snapshot the database's metadata into an owned, `Send` [`DatabaseInfo`].
    #[must_use]
    pub fn info(&self) -> DatabaseInfo {
        DatabaseInfo {
            bitness: self.bitness(),
            image_base: Address::try_new(self.image_base()),
            processor: self.proc_name(),
            file_type: self.file_type_name(),
            input_path: self.input_path(),
            root_filename: self.root_filename(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DatabaseInfo;

    const fn assert_send<T: Send>() {}

    // A detached snapshot is only worth having if it can leave the kernel thread.
    const _: () = assert_send::<DatabaseInfo>();
}
