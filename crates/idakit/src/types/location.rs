//! [`StorageLocation`], where a value lives: a parameter, a return value, or a decompiled local.
//!
//! The SDK models all three with one `argloc_t` (a decompiler local's `vdloc_t` derives from it),
//! so idakit does too. Two readings differ by owner, and the docs on each variant say which: a
//! local's register carries no in-register offset, and a local's stack offset is based on the
//! function's lowest stack pointer, where a parameter's is an offset into its stack arguments.

use idakit_sys as sys;
use serde::{Deserialize, Serialize};

use crate::address::Address;

/// Where a parameter, return value, or local variable lives.
///
/// [`Register`](StorageLocation::Register) and [`Stack`](StorageLocation::Stack) cover essentially
/// every x86-64 value; the pair, register-relative, scattered, and static forms are artifacts of
/// other architectures' calling conventions (AArch64 register pairs, AAPCS struct-scatter, MIPS and
/// PPC register-relative), rare to absent on x86-64.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[doc(alias("argloc_t", "vdloc_t"))]
pub enum StorageLocation {
    /// In one register, starting `offset` bytes into it. A decompiler local's offset is always 0.
    #[doc(alias("ALOC_REG1"))]
    Register {
        /// Register number.
        register: u32,
        /// Byte offset from the start of the register.
        #[doc(alias("regoff"))]
        offset: u16,
    },
    /// Split across a register pair, the low half in `low` and the high half in `high`.
    /// Arises for values wider than one register on register-based ABIs; absent on x86-64.
    #[doc(alias("ALOC_REG2"))]
    RegisterPair {
        /// Register number holding the low half.
        low: u32,
        /// Register number holding the high half.
        high: u32,
    },
    /// On the stack, at this offset: into the stack arguments for a parameter, from the
    /// function's lowest stack pointer for a decompiled local.
    #[doc(alias("ALOC_STACK"))]
    Stack(i64),
    /// Register-relative, at `[register + offset]`. Uncommon.
    #[doc(alias("ALOC_RREL"))]
    RegisterRelative {
        /// Base register number.
        register: u32,
        /// Byte offset added to the base register.
        offset: i64,
    },
    /// At a fixed global address. Uncommon.
    #[doc(alias("ALOC_STATIC"))]
    Static(Address),
    /// Scattered across several register or stack fragments, each covering a byte range of the
    /// value. Arises from struct-by-value on register ABIs; effectively absent on x86-64.
    #[doc(alias("ALOC_DIST"))]
    Scattered(Vec<StoragePiece>),
    /// A processor-specific custom location, carrying its raw location type (7 or higher), which
    /// idakit does not structure further.
    #[doc(alias("ALOC_CUSTOM"))]
    Custom(u32),
    /// No location: a local the decompiler left unallocated, or a prototype whose locations were
    /// not computed.
    #[doc(alias("ALOC_NONE"))]
    Unallocated,
}

impl StorageLocation {
    /// Decode the facade's flattened location. `atype` selects the variant; the remaining fields
    /// form a union, so only the ones it names are read.
    pub(crate) fn from_wire(loc: &sys::ArgLoc) -> Self {
        Self::decode(loc.atype, loc.reg1, loc.reg2, loc.regoff, loc.sval, || {
            loc.pieces.iter().map(StoragePiece::from_wire).collect()
        })
    }

    fn decode(
        atype: u32,
        reg1: u32,
        reg2: u32,
        regoff: u16,
        sval: i64,
        pieces: impl FnOnce() -> Vec<StoragePiece>,
    ) -> Self {
        match atype {
            0 => Self::Unallocated,
            1 => Self::Stack(sval),
            2 => Self::Scattered(pieces()),
            3 => Self::Register {
                register: reg1,
                offset: regoff,
            },
            4 => Self::RegisterPair {
                low: reg1,
                high: reg2,
            },
            5 => Self::RegisterRelative {
                register: reg1,
                offset: sval,
            },
            6 => Self::Static(Address::new_const(sval as u64)),
            custom => Self::Custom(custom),
        }
    }
}

/// One fragment of a [`Scattered`](StorageLocation::Scattered) value, naming where it lives and
/// which byte range of the whole value it covers.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[doc(alias("argpart_t"))]
pub struct StoragePiece {
    /// Where this fragment lives: a register or stack slot, never itself scattered.
    pub location: StorageLocation,
    /// Byte offset of this fragment within the whole value.
    pub offset: u32,
    /// Byte size of this fragment.
    pub size: u32,
}

impl StoragePiece {
    fn from_wire(piece: &sys::LocPiece) -> Self {
        Self {
            location: StorageLocation::decode(
                piece.atype,
                piece.reg,
                0,
                piece.regoff,
                piece.sval,
                Vec::new,
            ),
            offset: piece.off,
            size: piece.size,
        }
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    fn wire(atype: u32, reg1: u32, reg2: u32, regoff: u16, sval: i64) -> sys::ArgLoc {
        sys::ArgLoc {
            atype,
            reg1,
            reg2,
            regoff,
            sval,
            pieces: Vec::new(),
        }
    }

    /// Each location type maps to its variant, reading only the fields that type selects, and a
    /// custom location (7 or higher) keeps its raw type.
    #[rstest]
    #[case::unallocated(wire(0, 9, 9, 9, 9), StorageLocation::Unallocated)]
    #[case::stack(wire(1, 9, 9, 9, -8), StorageLocation::Stack(-8))]
    #[case::register(wire(3, 5, 9, 2, 9), StorageLocation::Register { register: 5, offset: 2 })]
    #[case::register_pair(wire(4, 5, 6, 9, 9), StorageLocation::RegisterPair { low: 5, high: 6 })]
    #[case::register_relative(
        wire(5, 5, 9, 9, 16),
        StorageLocation::RegisterRelative { register: 5, offset: 16 }
    )]
    #[case::static_(
        wire(6, 9, 9, 9, 0x1000),
        StorageLocation::Static(Address::new_const(0x1000))
    )]
    #[case::custom_lower_bound(wire(7, 9, 9, 9, 9), StorageLocation::Custom(7))]
    #[case::custom_above_lower_bound(wire(42, 9, 9, 9, 9), StorageLocation::Custom(42))]
    fn from_wire_maps_each_location_type(
        #[case] loc: sys::ArgLoc,
        #[case] expected: StorageLocation,
    ) {
        assert!(StorageLocation::from_wire(&loc) == expected);
    }

    /// A scattered location decodes each fragment as its own location, register offset included.
    #[test]
    fn from_wire_scattered_decodes_its_fragments() {
        let mut loc = wire(2, 0, 0, 0, 0);
        loc.pieces = vec![
            sys::LocPiece {
                atype: 1,
                reg: 0,
                regoff: 0,
                sval: 16,
                off: 0,
                size: 8,
            },
            sys::LocPiece {
                atype: 3,
                reg: 4,
                regoff: 4,
                sval: 0,
                off: 8,
                size: 4,
            },
        ];
        assert!(
            StorageLocation::from_wire(&loc)
                == StorageLocation::Scattered(vec![
                    StoragePiece {
                        location: StorageLocation::Stack(16),
                        offset: 0,
                        size: 8,
                    },
                    StoragePiece {
                        location: StorageLocation::Register {
                            register: 4,
                            offset: 4,
                        },
                        offset: 8,
                        size: 4,
                    },
                ])
        );
    }
}
