//! The declarative domain manifest driving the generator engine in [`super`].
//!
//! Every [`Domain`] here is one slice of the facade, one per file; [`domains`] lists them in
//! emission order. This directory is data only, except the netnode domain, which is
//! matrix-generated in the sibling `netnode` module. The engine that turns a [`Domain`] into the
//! Rust bridge, the C++ header, and the `cxx` glue lives in the sibling `gen.rs`.

use std::sync::OnceLock;

use super::model::*;

mod bytes;
mod cfg;
mod export;
mod function;
mod hexrays;
mod import;
mod instruction;
mod meta;
mod name;
pub(super) mod netnode;
mod range;
mod reference;
mod segment;
mod strings;
mod type_build;
mod types;

use self::bytes::BYTES;
use self::cfg::CFG;
use self::export::EXPORT;
use self::function::FUNCTION;
use self::hexrays::HEXRAYS;
use self::import::IMPORT;
use self::instruction::INSTRUCTION;
use self::meta::META;
use self::name::NAME;
use self::range::RANGE;
use self::reference::REFERENCE;
use self::segment::SEGMENT;
use self::strings::STRINGS;
use self::type_build::TYPE_BUILD;
use self::types::TY;

const N: &[Arg] = args!(n: I32);

/// Shared arg lists for the recurring multi-use shapes (the single-arg `EA`/`IDX` twins live near
/// their first domain). Each is one genuine family, not a coincidental type match: `FC_N` keys a
/// flowchart block, `CF` a decompiled function, `FLAGS` a name-flag predicate, `INNER` a wrapped
/// `TInfo`.
const FC_N: &[Arg] = args!(fc: ExternRef("FlowChart"), n: Usize);
const CF: &[Arg] = args!(cf: ExternRef("CFunc"));
const FLAGS: &[Arg] = args!(flags: U64);
const INNER: &[Arg] = args!(inner: ExternRef("TInfo"));

const EA: &[Arg] = args!(ea: U64);

const IDX: &[Arg] = args!(idx: Usize);

/// The netnode domain: IDA's persistent per-database key/value + blob store. A `netnode` is a value
/// type over a single `nodeidx_t` id, so every function is keyed by a bare `node: u64` (the id) with
/// no opaque handle; the bodies reconstruct a `netnode` on the C++ side and call its inline methods.
/// Tags are the SDK's 8-bit array selectors (`atag`/`stag`/`htag`/`vtag`, or a user tag), passed as
/// `u32` and narrowed. Covers node lifecycle, the node value, the alt/sup/hash/char/blob arrays,
/// their `_ea`/`_idx8` conveniences, the array shifts, and the ranged/bulk deletes; only `altadjust`
/// is deferred. All bodies are hand-written in `facade/netnode_custom.cc`.
// TODO: netnode_altadjust -- needs a cxx extern "Rust" visitor sink, not a raw C callback
/// Every domain fed into the unified bridge, in emission order.
///
/// The hand-written domains are `const`; the netnode domain is built (and leaked to `'static`) by
/// [`netnode::domain`] on first use, so this aggregation is a memoized function, not a `const`.
pub fn domains() -> &'static [&'static Domain] {
    static DOMAINS: OnceLock<Vec<&'static Domain>> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        vec![
            &SEGMENT,
            &IMPORT,
            &RANGE,
            &FUNCTION,
            &EXPORT,
            &META,
            &NAME,
            &STRINGS,
            &CFG,
            &REFERENCE,
            &BYTES,
            &INSTRUCTION,
            &HEXRAYS,
            &TYPE_BUILD,
            &TY,
            netnode::domain(),
        ]
    })
}
