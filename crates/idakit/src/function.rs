//! [`Function`]: a borrowed view of one function, keyed by its entry [`Address`].

use std::ops::Range;

use idakit_sys as sys;

use crate::Idb;
use crate::address::Address;
use crate::cfg::{Cfg, cfg_flags};
use crate::ctree::Ctree;
use crate::decompile::DecompiledFunction;
use crate::error::{Error, Result};
use crate::ffi::read_string;
use crate::frame::Frame;
use crate::instruction::Instruction;
use crate::reference::References;
use crate::ty::{TypeImage, walk_type};

impl Idb {
    /// A typed cursor at `address`; does not verify a function lives there (absence
    /// surfaces lazily). Use [`functions`](Self::functions) to enumerate real ones.
    #[inline]
    #[must_use]
    pub fn function(&self, address: Address) -> Function<'_> {
        Function::new(address, self)
    }

    /// Iterate every function in the database, in kernel order.
    #[inline]
    #[must_use]
    pub fn functions(&self) -> Functions<'_> {
        Functions::new(self)
    }
}

/// A borrowed view of one function, valid while the database stays open.
#[derive(Clone, Copy)]
pub struct Function<'db> {
    address: Address,
    db: &'db Idb,
}

impl<'db> Function<'db> {
    #[inline]
    pub(crate) fn new(address: Address, db: &'db Idb) -> Self {
        Self { address, db }
    }

    /// The function's entry address.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The function's name and how IDA assigned it -- see [`FunctionName`]. A function entry
    /// always has a name (an address-derived placeholder at worst), so this is not optional.
    #[must_use]
    pub fn name(&self) -> FunctionName {
        let text =
            read_string(|buf, cap| self.db.func_name(self.address, buf, cap)).unwrap_or_default();
        FunctionName::from_flags(self.db.get_flags(self.address), text)
    }

    /// The one-line C prototype, or `None` if the kernel has no type info.
    #[must_use]
    pub fn prototype(&self) -> Option<String> {
        read_string(|buf, cap| self.db.func_type(self.address, buf, cap))
    }

    /// Walk this function's stored prototype into an owned [`TypeImage`] -- the structured
    /// counterpart to [`prototype`](Self::prototype), whose root is a
    /// [`TypeKind::Function`](crate::TypeKind::Function). `Ok(None)` if the kernel has no type
    /// info for the function.
    pub fn prototype_type(&self) -> Result<Option<TypeImage>> {
        // SAFETY: the kernel is claimed for `self.db`; the walk's out-params are valid locals.
        walk_type(|v, ctx, root| unsafe {
            sys::idakit_func_type_walk(self.address.get(), v, ctx, root)
        })
        .map_err(|source| Error::Extract {
            address: self.address.get(),
            source,
        })
    }

    /// Lazily iterate this function's chunks: the entry chunk first, then any tail chunks in
    /// address order. A contiguous function yields exactly one [`Chunk`].
    #[must_use]
    pub fn chunks(&self) -> Chunks<'db> {
        Chunks::new(self.address, self.db)
    }

    /// Lazily iterate this function's instructions, in address order within each chunk,
    /// across every chunk. Data items and the alignment tail are skipped -- see
    /// [`Instructions`].
    #[must_use]
    pub fn instructions(&self) -> Instructions<'db> {
        Instructions::new(self.db, self.address)
    }

    /// The function's exclusive end address -- the entry chunk's `end_ea`. `None` only if
    /// the entry is no longer a function.
    #[must_use]
    pub fn end(&self) -> Option<Address> {
        Address::try_new(self.db.func_end(self.address))
    }

    /// The entry chunk's size in bytes (`end - start`), or `0` if the end is unavailable.
    /// A chunked function's tail chunks lie outside this span -- walk [`chunks`](Self::chunks)
    /// for the full extent.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.end().map_or(0, |end| self.address.distance_to(end))
    }

    /// Whether IDA flags this as a library function (`FUNC_LIB`).
    #[must_use]
    pub fn is_lib(&self) -> bool {
        self.db.func_flags(self.address) & sys::FUNC_LIB != 0
    }

    /// Whether this is a thunk -- a trampoline that jumps straight to another function
    /// (`FUNC_THUNK`).
    #[must_use]
    pub fn is_thunk(&self) -> bool {
        self.db.func_flags(self.address) & sys::FUNC_THUNK != 0
    }

    /// Whether this function does not return (`FUNC_NORET`) -- e.g. `exit`, `abort`.
    #[must_use]
    pub fn is_noreturn(&self) -> bool {
        self.db.func_flags(self.address) & sys::FUNC_NORET != 0
    }

    /// Lazily iterate cross-references targeting this function's entry.
    #[must_use]
    pub fn references_to(&self) -> References<'db> {
        self.db.references_to(self.address)
    }

    /// Lazily iterate cross-references originating at this function's entry.
    #[must_use]
    pub fn references_from(&self) -> References<'db> {
        self.db.references_from(self.address)
    }

    /// Decompile this function.
    pub fn decompile(&self) -> Result<DecompiledFunction<'db>> {
        self.db.decompile(self.address)
    }

    /// Decompile and materialize the ctree in one step ([`decompile`](Self::decompile) then
    /// [`DecompiledFunction::ctree`]). Use the two-step form when you also need the [`DecompiledFunction`] itself.
    pub fn ctree(&self) -> Result<Ctree> {
        let cfunc = self.decompile()?;
        cfunc.ctree().map_err(|source| Error::Extract {
            address: self.address.get(),
            source,
        })
    }

    /// Snapshot this function's stack frame, or `Ok(None)` if it has none. The disassembly-level
    /// stack layout, no decompilation needed; see [`Idb::frame`].
    pub fn frame(&self) -> Result<Option<Frame>> {
        self.db.frame(self.address)
    }

    /// Snapshot this view's scalar facts into an owned [`FunctionImage`] that can leave the
    /// kernel thread.
    #[must_use]
    pub fn image(&self) -> FunctionImage {
        FunctionImage {
            address: self.address,
            name: self.name(),
            prototype: self.prototype(),
        }
    }
}

#[bon::bon]
impl<'db> Function<'db> {
    /// Build this function's control-flow graph with default options. The whole function is
    /// covered, tail chunks included. See [`Cfg`] and [`cfg_with`](Self::cfg_with) for the
    /// knobs.
    pub fn cfg(&self) -> Result<Cfg> {
        self.db.cfg(self.address)
    }

    /// Build this function's CFG with non-default options: `call_ends` splits a block after
    /// every call instruction, `externals(false)` drops the out-of-function
    /// [`ExternalExit`](crate::ExternalExit) edges (jump/call targets outside the function),
    /// and `predecessors(false)` skips predecessor lists (a cheaper build when only forward
    /// edges are needed).
    #[builder]
    pub fn cfg_with(
        &self,
        #[builder(default = false)] call_ends: bool,
        #[builder(default = true)] externals: bool,
        #[builder(default = true)] predecessors: bool,
    ) -> Result<Cfg> {
        self.db
            .build_cfg(self.address, cfg_flags(call_ends, externals, predecessors))
    }
}

/// An owned, `Send` snapshot of a function's scalar facts, detached from the database.
/// `Function` borrows a `!Send` [`Idb`]; collect images inside an [`Ida::call`](crate::Ida::call)
/// job to carry results back out.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FunctionImage {
    /// Entry address.
    pub address: Address,
    /// Name and how IDA assigned it.
    pub name: FunctionName,
    /// One-line C prototype, if the kernel had type info.
    pub prototype: Option<String>,
}

/// A function's name together with how IDA assigned it, from [`Function::name`].
///
/// Derefs to the name text, so it reads as the `str` it carries; match the variant to branch
/// on provenance. Every function entry has a name -- IDA names even an unnamed one, at least
/// with an address-derived placeholder -- so `name()` yields this directly, never an `Option`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FunctionName {
    /// An explicit name: user-assigned, or an imported/mangled symbol (`FF_NAME`).
    User(String),
    /// A name IDA generated from analysis -- a recognized stub, library match, or thunk, e.g.
    /// `nullsub_0` or `j_malloc` (`FF_NAME | FF_LABL`).
    Auto(String),
    /// An address-derived placeholder for an otherwise-unnamed function, e.g. `sub_401000`
    /// (`FF_LABL`).
    Dummy(String),
}

impl FunctionName {
    /// The name text, whatever its provenance.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::User(s) | Self::Auto(s) | Self::Dummy(s) => s,
        }
    }

    /// Whether this is an explicit name -- user-assigned or an imported symbol.
    #[inline]
    #[must_use]
    pub fn is_user(&self) -> bool {
        matches!(self, Self::User(_))
    }

    /// Whether IDA generated this name from analysis.
    #[inline]
    #[must_use]
    pub fn is_auto(&self) -> bool {
        matches!(self, Self::Auto(_))
    }

    /// Whether this is an address-derived placeholder.
    #[inline]
    #[must_use]
    pub fn is_dummy(&self) -> bool {
        matches!(self, Self::Dummy(_))
    }

    /// Classify from an address's flags and its resolved name text. The two name bits
    /// partition cleanly: `FF_NAME` alone is an explicit name, both bits an IDA-generated
    /// one, `FF_LABL` alone a placeholder. A function entry always carries one of the three,
    /// so the flag-less case folds to [`Dummy`](Self::Dummy) -- unreachable in practice,
    /// pinned by the name sweep test. The bit logic mirrors IDA's `has_user_name`/
    /// `has_auto_name`/`has_dummy_name`, held in step by the alignment test.
    fn from_flags(flags: u64, text: String) -> Self {
        let named = flags & sys::FF_NAME != 0;
        let labeled = flags & sys::FF_LABL != 0;
        match (named, labeled) {
            (true, false) => Self::User(text),
            (true, true) => Self::Auto(text),
            _ => Self::Dummy(text),
        }
    }
}

/// Consume the classification into the owned name string it carries.
impl From<FunctionName> for String {
    #[inline]
    fn from(name: FunctionName) -> Self {
        match name {
            FunctionName::User(s) | FunctionName::Auto(s) | FunctionName::Dummy(s) => s,
        }
    }
}

impl std::ops::Deref for FunctionName {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for FunctionName {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Debug for Function<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Function")
            .field("address", &self.address)
            .field("name", &self.name())
            .finish()
    }
}

// Identity is the entry address alone; the `db` borrow is incidental and must not
// participate, so these are hand-written rather than derived.
impl PartialEq for Function<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.address == o.address
    }
}
impl Eq for Function<'_> {}
impl std::hash::Hash for Function<'_> {
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.address.hash(s);
    }
}
impl Ord for Function<'_> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.address.cmp(&o.address)
    }
}
impl PartialOrd for Function<'_> {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// Lazy iterator over every function in the database, in kernel order.
pub struct Functions<'db> {
    db: &'db Idb,
    next: usize,
    count: usize,
}

impl<'db> Functions<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Idb) -> Self {
        Self {
            db,
            next: 0,
            count: db.func_qty(),
        }
    }
}

impl<'db> Iterator for Functions<'db> {
    type Item = Function<'db>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.count {
            let raw = self.db.func_ea(self.next);
            self.next += 1;
            if let Some(address) = Address::try_new(raw) {
                return Some(Function::new(address, self.db));
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.count - self.next))
    }
}

/// A contiguous address range belonging to a function: `[start, end)`.
///
/// A function is one chunk when contiguous, or several when the compiler scattered its body
/// into tail chunks placed elsewhere. Yielded by [`Function::chunks`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Chunk {
    /// First address of the chunk.
    pub start: Address,
    /// One-past-the-last address of the chunk.
    pub end: Address,
}

/// Lazy iterator over a function's chunks, entry chunk first then tail chunks in address
/// order, from [`Function::chunks`].
pub struct Chunks<'db> {
    db: &'db Idb,
    address: Address,
    next: i32,
    count: i32,
}

impl<'db> Chunks<'db> {
    #[inline]
    pub(crate) fn new(address: Address, db: &'db Idb) -> Self {
        Self {
            db,
            address,
            next: 0,
            count: db.func_chunk_qty(address),
        }
    }
}

impl Iterator for Chunks<'_> {
    type Item = Chunk;

    fn next(&mut self) -> Option<Chunk> {
        if self.next >= self.count {
            return None;
        }
        let idx = self.next;
        self.next += 1;
        let (mut start, mut end): (u64, u64) = (0, 0);
        if self.db.func_chunk(self.address, idx, &mut start, &mut end) == 0 {
            return None;
        }
        Some(Chunk {
            start: Address::try_new(start)?,
            end: Address::try_new(end)?,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some((self.count - self.next).max(0) as usize))
    }
}

/// Lazy iterator over a function's instructions, across all its chunks.
///
/// Code-gated: it decodes only addresses the kernel classifies as code ([`Idb::is_code`])
/// and steps over data items (jump tables, embedded constants) and the alignment tail. This
/// gate is the point of the iterator -- [`Idb::decode`] turns any bytes into an [`Instruction`], so
/// a plain linear decode past a function's `ret` yields garbage; `is_code` keeps the stream
/// to real instructions.
pub struct Instructions<'db> {
    db: &'db Idb,
    chunks: Chunks<'db>,
    /// `(next address to examine, current chunk end)`; `None` until the first chunk loads and
    /// again once the last chunk drains.
    cursor: Option<(Address, Address)>,
}

impl<'db> Instructions<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Idb, address: Address) -> Self {
        Self {
            db,
            chunks: Chunks::new(address, db),
            cursor: None,
        }
    }
}

impl Iterator for Instructions<'_> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Instruction> {
        loop {
            let (address, end) = match self.cursor {
                Some((address, end)) if address < end => (address, end),
                _ => {
                    let chunk = self.chunks.next()?;
                    self.cursor = Some((chunk.start, chunk.end));
                    continue;
                }
            };
            // Step past this item before deciding to yield, so every branch advances; the
            // kernel's item end is `address + len` for a decoded instruction, and skips a whole
            // data item in one go. The `> address` guard keeps a pathological zero-width item from
            // stalling the walk.
            let stepped = self.db.item_end(address);
            self.cursor = Some((if stepped > address { stepped } else { end }, end));
            if self.db.is_code(address)
                && let Ok(instruction) = self.db.decode(address)
            {
                return Some(instruction);
            }
        }
    }
}

impl Idb {
    /// Lazily decode the instructions in the half-open range `[range.start, range.end)`,
    /// code-gated like [`Function::instructions`]. The ranged twin of that walk -- pass a
    /// [`Block`](crate::Block)'s [`range`](crate::Block::range) to iterate one basic block.
    #[must_use]
    pub fn instructions_in(&self, range: Range<Address>) -> InstructionsIn<'_> {
        InstructionsIn {
            db: self,
            cursor: range.start,
            end: range.end,
        }
    }
}

/// Lazy iterator over the instructions in a fixed `[start, end)` range, code-gated like
/// [`Instructions`]. From [`Idb::instructions_in`].
pub struct InstructionsIn<'db> {
    db: &'db Idb,
    cursor: Address,
    end: Address,
}

impl Iterator for InstructionsIn<'_> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Instruction> {
        while self.cursor < self.end {
            let address = self.cursor;
            // Step past this item before deciding to yield, so every branch advances; the
            // `> address` guard keeps a zero-width item from stalling the walk (cf. Instructions).
            let stepped = self.db.item_end(address);
            self.cursor = if stepped > address { stepped } else { self.end };
            if self.db.is_code(address)
                && let Ok(instruction) = self.db.decode(address)
            {
                return Some(instruction);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    const fn assert_send<T: Send>() {}

    // Both owned so they can cross the kernel-thread boundary, unlike the borrowed Function view.
    const _: () = assert_send::<FunctionImage>();
    const _: () = assert_send::<FunctionName>();

    #[test]
    fn from_flags_classifies_by_the_two_name_bits() {
        assert!(
            FunctionName::from_flags(sys::FF_NAME, "s".into()) == FunctionName::User("s".into())
        );
        assert!(
            FunctionName::from_flags(sys::FF_NAME | sys::FF_LABL, "s".into())
                == FunctionName::Auto("s".into())
        );
        assert!(
            FunctionName::from_flags(sys::FF_LABL, "s".into()) == FunctionName::Dummy("s".into())
        );
        // No name flag at all folds to a placeholder (unreachable for a function entry).
        assert!(FunctionName::from_flags(0, "s".into()) == FunctionName::Dummy("s".into()));
    }

    #[test]
    fn from_flags_ignores_unrelated_bits() {
        // Bits outside the two name bits (code/data class, etc.) must not perturb it.
        let noise = 0xFFFF_FFFF_FFFF_3FFFu64; // every bit except FF_NAME (0x4000) and FF_LABL (0x8000)
        assert!(
            FunctionName::from_flags(noise | sys::FF_NAME, "x".into())
                == FunctionName::User("x".into())
        );
        assert!(
            FunctionName::from_flags(noise | sys::FF_LABL, "x".into())
                == FunctionName::Dummy("x".into())
        );
    }

    #[test]
    fn accessors_project_text_and_kind() {
        let u = FunctionName::User("main".into());
        assert!(u.as_str() == "main");
        assert!(&*u == "main");
        assert!(format!("{u}") == "main");
        assert!(String::from(u.clone()) == "main");
        assert!(u.is_user() && !u.is_auto() && !u.is_dummy());
        assert!(FunctionName::Dummy("sub_1000".into()).is_dummy());
        assert!(FunctionName::Auto("nullsub_0".into()).is_auto());
    }

    #[test]
    fn from_flags_matches_ida_predicates() {
        // Our FF_NAME/FF_LABL derivation must agree with IDA's own has_*_name predicates for
        // every combination of the two name bits, regardless of surrounding flag bits -- so a
        // future SDK that redefines the bits, or a typo in our constants, fails here.
        for extra in [0u64, 0x1234_5678, u64::MAX] {
            let extra = extra & !(sys::FF_NAME | sys::FF_LABL);
            for &bits in &[0, sys::FF_NAME, sys::FF_LABL, sys::FF_NAME | sys::FF_LABL] {
                let flags = extra | bits;
                let ours = FunctionName::from_flags(flags, String::new());
                // SAFETY: has_*_name are pure bit tests over `flags` -- no kernel state, no
                // open database required.
                let (user, auto, dummy) = unsafe {
                    (
                        sys::idakit_has_user_name(flags) != 0,
                        sys::idakit_has_auto_name(flags) != 0,
                        sys::idakit_has_dummy_name(flags) != 0,
                    )
                };
                assert!(ours.is_user() == user);
                assert!(ours.is_auto() == auto);
                // IDA's dummy always maps to ours; ours additionally absorbs the no-name case.
                assert!(ours.is_dummy() == (!user && !auto));
                if dummy {
                    assert!(ours.is_dummy());
                }
            }
        }
    }
}
