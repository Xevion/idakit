//! [`FlowChart`]: an owned, `Send` control-flow graph of one function.
//!
//! IDA builds a function's whole flow chart eagerly (`qflow_chart_t`), so -- unlike the lazy
//! [`Function`]/[`Segment`](crate::Segment) views that re-query per accessor -- a CFG is a
//! snapshot from the start. It is materialized on the kernel thread and handed back as an
//! owned [`FlowChart`] any worker can traverse: an append-only arena of [`BasicBlock`]s keyed by
//! [`BasicBlockId`], with successor/predecessor edges as block handles. A [`BasicBlock`] carries
//! only its address range; pair it with [`Database::instructions_in`] to walk the instructions
//! inside.
//!
//! The arena holds only the function's *own* basic blocks, so every [`BasicBlock`] has a
//! non-empty range. A tail-jump or call *out* of the function is an [`ExternalExit`] on the
//! source block, not a block of its own: IDA represents those targets as zero-length stub
//! blocks (`start == end`, decided purely by index past `nproper`), which idakit lifts to typed
//! edges so the arena stays real code and out-of-function targets stay addressable.

use std::ffi::{c_int, c_void};
use std::ops::Range;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::VariantArray;

use idakit_sys as sys;

use crate::Database;
use crate::address::Address;
use crate::arena::{Arena, Idx};
use crate::error::{Error, Result};

/// A handle into a [`FlowChart`]'s block arena. Edges are lists of these; block 0 is the entry.
pub type BasicBlockId = Idx<BasicBlock>;

/// How a basic block ends (`fc_block_type_t` from `gdl.hpp`, IDA 9.3): the kind of
/// control-flow transfer that terminates it.
///
/// Only the six in-function terminators appear: the SDK's external kinds (`fcb_extern`,
/// `fcb_enoret`) name zero-length stubs for out-of-function targets, which idakit lifts to
/// [`ExternalExit`]s rather than blocks -- so a real [`BasicBlock`] is never one of them.
///
/// A closed set: `TryFrom<u8>` rejects any `fc_block_type_t` outside it (a newer SDK's value
/// surfaces as [`Error::UnknownBlockKind`](crate::Error::UnknownBlockKind) at CFG build, a
/// deliberate version-drift break) rather than absorbing it into a catch-all every downstream
/// `match` would then have to carry.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, TryFromPrimitive, IntoPrimitive, VariantArray,
)]
#[repr(u8)]
pub enum BasicBlockKind {
    /// `fcb_normal`: falls through or branches within the function.
    Normal = 0,
    /// `fcb_indjump`: ends with an indirect jump (a switch dispatch, a jump table).
    IndirectJump = 1,
    /// `fcb_ret`: returns from the function.
    Return = 2,
    /// `fcb_cndret`: conditionally returns.
    CondReturn = 3,
    /// `fcb_noret`: does not return -- ends in a no-return call (`exit`, `abort`).
    NoReturn = 4,
    /// `fcb_error`: control runs past the function's end (a decoding/analysis error).
    Error = 7,
}

impl BasicBlockKind {
    /// Whether the block returns from the function (`fcb_ret`/`fcb_cndret`).
    #[inline]
    #[must_use]
    pub fn is_return(self) -> bool {
        matches!(self, Self::Return | Self::CondReturn)
    }

    /// Whether the block does not return -- it ends in a no-return call (`exit`, `abort`) with
    /// no fall-through (`fcb_noret`). A tail call to a no-return target is an
    /// [`ExternalExit`] with [`noreturn`](ExternalExit::noreturn) set, not this.
    #[inline]
    #[must_use]
    pub fn is_noreturn(self) -> bool {
        matches!(self, Self::NoReturn)
    }
}

/// A control-flow edge that leaves the function: a tail-jump or tail-call from a [`BasicBlock`]
/// to `target`, an address in no block of this graph. IDA carries these as zero-length stub
/// blocks; idakit lifts them to edges (see the module docs). Read them with
/// [`BasicBlock::exits`]; internal edges are [`BasicBlock::successors`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExternalExit {
    /// The out-of-function address this block transfers to.
    pub target: Address,
    /// Whether IDA knows the target never returns -- a tail call to `exit`/`abort`
    /// (`fcb_enoret`).
    pub noreturn: bool,
}

/// One basic block: a straight-line run of code with a single entry and single exit,
/// [`kind`](Self::kind) naming how it ends. Yielded by [`FlowChart::blocks`]. The range is
/// always non-empty -- external stubs are [`ExternalExit`]s, not blocks.
#[derive(Clone, Debug)]
pub struct BasicBlock {
    range: Range<Address>,
    kind: BasicBlockKind,
    succ: Vec<BasicBlockId>,
    pred: Vec<BasicBlockId>,
    exits: Vec<ExternalExit>,
}

impl BasicBlock {
    /// The block's half-open address range `[start, end)`.
    #[inline]
    #[must_use]
    pub fn range(&self) -> Range<Address> {
        self.range.clone()
    }

    /// First address of the block.
    #[inline]
    #[must_use]
    pub fn start(&self) -> Address {
        self.range.start
    }

    /// One-past-the-last address of the block.
    #[inline]
    #[must_use]
    pub fn end(&self) -> Address {
        self.range.end
    }

    /// How the block ends -- see [`BasicBlockKind`].
    #[inline]
    #[must_use]
    pub fn kind(&self) -> BasicBlockKind {
        self.kind
    }

    /// The blocks this one can transfer control to, *within* the function. Out-of-function
    /// tail-jumps and calls are [`exits`](Self::exits).
    #[inline]
    #[must_use]
    pub fn successors(&self) -> &[BasicBlockId] {
        &self.succ
    }

    /// The blocks that can transfer control here. Empty when the CFG was built with
    /// `predecessors(false)`.
    #[inline]
    #[must_use]
    pub fn predecessors(&self) -> &[BasicBlockId] {
        &self.pred
    }

    /// The out-of-function targets this block transfers to -- tail-jumps and tail-calls that
    /// leave the function, each an [`ExternalExit`]. Empty when the CFG was built with
    /// `externals(false)`. Internal edges are [`successors`](Self::successors).
    #[inline]
    #[must_use]
    pub fn exits(&self) -> &[ExternalExit] {
        &self.exits
    }
}

/// An owned, `Send` control-flow graph of one function. Materialize with
/// [`Function::flowchart`](crate::Function::flowchart)/[`Database::flowchart`], then traverse
/// the [`BasicBlock`] arena by [`BasicBlockId`]. Detached from the kernel, so it analyzes on any
/// thread.
#[derive(Debug)]
pub struct FlowChart {
    blocks: Arena<BasicBlock>,
    entry: BasicBlockId,
    function: Address,
}

impl FlowChart {
    /// The entry address of the function this graph was built from.
    #[inline]
    #[must_use]
    pub fn function(&self) -> Address {
        self.function
    }

    /// The entry block, where execution enters the function (always block 0).
    #[inline]
    #[must_use]
    pub fn entry(&self) -> BasicBlockId {
        self.entry
    }

    /// Borrow the block behind a handle.
    #[inline]
    #[must_use]
    pub fn block(&self, id: BasicBlockId) -> &BasicBlock {
        &self.blocks[id]
    }

    /// The number of basic blocks.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the graph has no blocks.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Iterate every `(BasicBlockId, &BasicBlock)` in index order -- the entry block first.
    pub fn blocks(&self) -> impl ExactSizeIterator<Item = (BasicBlockId, &BasicBlock)> {
        self.blocks.iter()
    }

    /// The block whose range contains `address`, if any.
    #[must_use]
    pub fn block_at(&self, address: Address) -> Option<BasicBlockId> {
        self.blocks
            .iter()
            .find_map(|(id, b)| (b.range.start <= address && address < b.range.end).then_some(id))
    }
}

impl Database {
    /// Build the control-flow graph of the function containing `address` with default options:
    /// external exits recorded, predecessors computed, calls do not split a block. `Err` with
    /// [`Error::NoFunction`] when no function covers `address`. For the knobs, use
    /// [`Function::flowchart_with`](crate::Function::flowchart_with).
    pub fn flowchart(&self, address: Address) -> Result<FlowChart> {
        self.build_flowchart(address, 0)
    }

    /// The shared build path behind [`flowchart`](Self::flowchart) and the `flowchart_with`
    /// builder: constructs the flow chart, extracts every block and edge into an owned arena,
    /// and frees the kernel object before returning -- so the result is a detached `Send`
    /// snapshot.
    pub(crate) fn build_flowchart(&self, address: Address, flags: c_int) -> Result<FlowChart> {
        // SAFETY: the kernel is claimed for the lifetime of `&self`. The returned handle is
        // owned by this call and freed once, below.
        let handle = unsafe { sys::idakit_cfg_build(address.get(), flags) };
        if handle.is_null() {
            return Err(Error::NoFunction {
                address: address.get(),
            });
        }
        let blocks = extract(handle);
        // SAFETY: `handle` came from `idakit_cfg_build`, is non-null, and is freed exactly
        // once here; nothing borrows it afterwards. Freed before propagating an extract error
        // so the handle never leaks on the unmodeled-kind path.
        unsafe { sys::idakit_cfg_free(handle) };
        let blocks = blocks?;

        let function = blocks.iter().next().map_or(address, |(_, b)| b.start());
        Ok(FlowChart {
            blocks,
            entry: BasicBlockId::from_raw(0),
            function,
        })
    }
}

/// Compose an `FC_` flag word from the builder's booleans. `externals`/`predecessors` are the
/// enabled state, so *disabling* either sets the corresponding `NO*` flag.
pub(crate) fn flowchart_flags(call_ends: bool, externals: bool, predecessors: bool) -> c_int {
    let mut flags = 0;
    if call_ends {
        flags |= sys::FC_CALL_ENDS;
    }
    if !externals {
        flags |= sys::FC_NOEXT;
    }
    if !predecessors {
        flags |= sys::FC_NOPREDS;
    }
    flags
}

/// `fcb_enoret` from `gdl.hpp`: an external stub whose target never returns. Externals are
/// lifted to [`ExternalExit`]s, so this raw value survives only as the `noreturn` bit.
const FCB_ENORET: u8 = 5;

/// Drain a built flow chart into an owned block arena. The first `nproper` kernel blocks are
/// the function's own -- allocated in order, so allocation `i` is `BasicBlockId::from_raw(i)`,
/// matching the raw edge indices. The rest are zero-length external stubs: never allocated,
/// only read (their `start` is a jump target) when a proper block's edge points at one.
fn extract(handle: *const c_void) -> Result<Arena<BasicBlock>> {
    // SAFETY (every call below): `handle` is a live flow chart; indices are kept in range by
    // the loop bounds and the facade's own checks; out-params are valid locals.
    let nproper = unsafe { sys::idakit_cfg_nproper(handle) };
    let mut blocks = Arena::new();
    for i in 0..nproper {
        let (mut start, mut end, mut kind) = (0u64, 0u64, 0i32);
        unsafe { sys::idakit_cfg_block(handle, i, &mut start, &mut end, &mut kind) };
        let raw = kind as u8;
        let kind = BasicBlockKind::try_from(raw)
            .map_err(|_| Error::UnknownBlockKind { block: start, raw })?;
        let (succ, exits) = successors(handle, i, nproper);
        blocks.alloc(BasicBlock {
            range: block_range(start, end),
            kind,
            succ,
            pred: predecessors(handle, i, nproper),
            exits,
        });
    }
    Ok(blocks)
}

/// Split block `n`'s successor edges: targets below `nproper` are internal [`BasicBlockId`]s,
/// the rest are external stubs read into [`ExternalExit`]s (target = stub start, `noreturn`
/// from its `fcb_enoret` kind).
fn successors(
    handle: *const c_void,
    n: c_int,
    nproper: c_int,
) -> (Vec<BasicBlockId>, Vec<ExternalExit>) {
    // SAFETY (every call): `handle` live, `n` in `[0, nproper)`, `i` in `[0, count)`, `j`
    // returned in range by the facade.
    let count = unsafe { sys::idakit_cfg_nsucc(handle, n) };
    let mut succ = Vec::new();
    let mut exits = Vec::new();
    for i in 0..count {
        let j = unsafe { sys::idakit_cfg_succ(handle, n, i) };
        if j < 0 {
            continue;
        }
        if j < nproper {
            if let Ok(id) = u32::try_from(j) {
                succ.push(BasicBlockId::from_raw(id));
            }
        } else {
            let (mut start, mut end, mut kind) = (0u64, 0u64, 0i32);
            unsafe { sys::idakit_cfg_block(handle, j, &mut start, &mut end, &mut kind) };
            exits.push(ExternalExit {
                target: Address::try_new(start).expect("external stub start is BADADDR"),
                noreturn: kind as u8 == FCB_ENORET,
            });
        }
    }
    (succ, exits)
}

/// The block at index `n`'s predecessor handles. All are internal: external stubs are pure
/// sinks, so no proper block has one as a predecessor -- an out-of-range index is dropped
/// defensively.
fn predecessors(handle: *const c_void, n: c_int, nproper: c_int) -> Vec<BasicBlockId> {
    // SAFETY: as in `successors`.
    let count = unsafe { sys::idakit_cfg_npred(handle, n) };
    (0..count)
        .filter_map(|i| {
            let j = unsafe { sys::idakit_cfg_pred(handle, n, i) };
            (0..nproper)
                .contains(&j)
                .then(|| u32::try_from(j).ok().map(BasicBlockId::from_raw))
                .flatten()
        })
        .collect()
}

/// A basic block's `[start, end)` as typed addresses. Real flow-chart blocks always have
/// valid bounds; a `BADADDR` here would mean a corrupt chart, so the niche is asserted.
fn block_range(start: u64, end: u64) -> Range<Address> {
    let start = Address::try_new(start).expect("flow-chart block start is BADADDR");
    let end = Address::try_new(end).expect("flow-chart block end is BADADDR");
    start..end
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    const fn assert_send<T: Send>() {}

    // The reason FlowChart is an owned arena and not a borrowed view: it must cross the kernel
    // thread. A later non-Send field would fail this.
    const _: () = assert_send::<FlowChart>();

    /// Discriminants match `fc_block_type_t` (gdl.hpp, IDA 9.3), and `u8`/`TryFrom` round-trip.
    #[rstest]
    #[case(BasicBlockKind::Normal, 0)]
    #[case(BasicBlockKind::IndirectJump, 1)]
    #[case(BasicBlockKind::Return, 2)]
    #[case(BasicBlockKind::CondReturn, 3)]
    #[case(BasicBlockKind::NoReturn, 4)]
    #[case(BasicBlockKind::Error, 7)]
    fn block_kind_raw_matches_sdk(#[case] kind: BasicBlockKind, #[case] raw: u8) {
        assert!(u8::from(kind) == raw);
        assert!(BasicBlockKind::try_from(raw).ok() == Some(kind));
    }

    /// A byte outside the modelled set is rejected, not absorbed: the SDK's external kinds
    /// (`fcb_enoret` = 5, `fcb_extern` = 6, lifted to [`ExternalExit`]s) and any other value.
    #[rstest]
    #[case(5)]
    #[case(6)]
    #[case(8)]
    #[case(200)]
    #[case(0xff)]
    fn unmodeled_block_kinds_are_rejected(#[case] raw: u8) {
        assert!(BasicBlockKind::try_from(raw).is_err());
    }

    /// The folded predicates agree with the raw variants they group.
    #[rstest]
    #[case(BasicBlockKind::Return, true, false)]
    #[case(BasicBlockKind::CondReturn, true, false)]
    #[case(BasicBlockKind::NoReturn, false, true)]
    #[case(BasicBlockKind::Normal, false, false)]
    #[case(BasicBlockKind::IndirectJump, false, false)]
    #[case(BasicBlockKind::Error, false, false)]
    fn block_kind_predicates(#[case] kind: BasicBlockKind, #[case] ret: bool, #[case] noret: bool) {
        assert!(kind.is_return() == ret);
        assert!(kind.is_noreturn() == noret);
    }

    /// Completeness: every variant round-trips through its raw discriminant, so a newly added
    /// variant that forgets a discriminant fails here.
    #[test]
    fn every_variant_round_trips() {
        for &kind in BasicBlockKind::VARIANTS {
            assert!(BasicBlockKind::try_from(u8::from(kind)).ok() == Some(kind));
        }
    }

    /// The three booleans map onto the right `FC_` bits, and disabling is what sets a flag.
    #[test]
    fn cfg_flags_compose() {
        assert!(flowchart_flags(false, true, true) == 0);
        assert!(flowchart_flags(true, true, true) == sys::FC_CALL_ENDS);
        assert!(flowchart_flags(false, false, true) == sys::FC_NOEXT);
        assert!(flowchart_flags(false, true, false) == sys::FC_NOPREDS);
        assert!(
            flowchart_flags(true, false, false)
                == sys::FC_CALL_ENDS | sys::FC_NOEXT | sys::FC_NOPREDS
        );
    }
}
