//! Snapshots database-wide metadata into an owned, `Send` [`DatabaseInfo`].

use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::Database;
use crate::address::Address;
use crate::bitness::Bitness;

/// An owned, `Send` snapshot of database-wide metadata, from [`Database::info`].
///
/// Every field is resolved and copied out at snapshot time, so a `DatabaseInfo` carries no borrow
/// on the [`Database`] and can be inspected on any thread. Reading it is a handful of kernel
/// calls, so grab it once rather than per field.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use assert2::assert;
    use rstest::rstest;

    use super::DatabaseInfo;
    use crate::address::Address;
    use crate::bitness::Bitness;

    const fn assert_send<T: Send>() {}

    // A detached snapshot is only worth having if it can leave the kernel thread.
    const _: () = assert_send::<DatabaseInfo>();

    fn sample() -> DatabaseInfo {
        DatabaseInfo {
            bitness: Some(Bitness::Bits64),
            image_base: Some(Address::new_const(0x1400_0000)),
            processor: Some("metapc".to_owned()),
            file_type: None,
            input_path: None,
            root_filename: Some("sample.exe".to_owned()),
        }
    }

    /// Every field absent, the emptiest snapshot a database can report.
    fn empty() -> DatabaseInfo {
        DatabaseInfo {
            bitness: None,
            image_base: None,
            processor: None,
            file_type: None,
            input_path: None,
            root_filename: None,
        }
    }

    /// Every field present, the densest snapshot a database can report.
    fn dense() -> DatabaseInfo {
        DatabaseInfo {
            bitness: Some(Bitness::Bits32),
            image_base: Some(Address::new_const(0)),
            processor: Some("arm".to_owned()),
            file_type: Some("ELF for ARM".to_owned()),
            input_path: Some("/path/to/binary".to_owned()),
            root_filename: Some("binary".to_owned()),
        }
    }

    fn hash_of(info: &DatabaseInfo) -> u64 {
        let mut hasher = DefaultHasher::new();
        info.hash(&mut hasher);
        hasher.finish()
    }

    /// Equal snapshots hash equally.
    #[test]
    fn equal_snapshots_hash_equally() {
        assert!(hash_of(&sample()) == hash_of(&sample()));
    }

    /// Snapshots differing in any single field are unequal.
    #[test]
    fn differing_snapshots_are_not_equal() {
        let mut other = sample();
        other.processor = Some("arm".to_owned());
        assert!(other != sample());

        let mut other = sample();
        other.bitness = None;
        assert!(other != sample());
    }

    #[rstest]
    #[case::empty(empty())]
    #[case::sample(sample())]
    #[case::dense(dense())]
    fn serde_round_trips(#[case] info: DatabaseInfo) {
        let json = serde_json::to_string(&info).unwrap();
        let back: DatabaseInfo = serde_json::from_str(&json).unwrap();
        assert!(back == info);
    }
}
