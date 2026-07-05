//! [`Func`]: a borrowed view of one function, keyed by its entry [`Ea`].

use std::ops::Range;

use idakit_sys as sys;

use crate::Idb;
use crate::cfg::{Cfg, cfg_flags};
use crate::ctree::Ctree;
use crate::decompile::Cfunc;
use crate::ea::Ea;
use crate::error::{Error, Result};
use crate::ffi::read_string;
use crate::insn::Insn;
use crate::xref::Xrefs;

impl Idb {
    /// A typed cursor at `ea`; does not verify a function lives there (absence
    /// surfaces lazily). Use [`functions`](Self::functions) to enumerate real ones.
    #[inline]
    #[must_use]
    pub fn func(&self, ea: Ea) -> Func<'_> {
        Func::new(ea, self)
    }

    /// Iterate every function in the database, in kernel order.
    #[inline]
    #[must_use]
    pub fn functions(&self) -> Functions<'_> {
        Functions::new(self)
    }

    // TODO: basic blocks and CFG over the decoded instruction stream.
}

/// A borrowed view of one function, valid while the database stays open.
#[derive(Clone, Copy)]
pub struct Func<'db> {
    ea: Ea,
    db: &'db Idb,
}

impl<'db> Func<'db> {
    #[inline]
    pub(crate) fn new(ea: Ea, db: &'db Idb) -> Self {
        Self { ea, db }
    }

    /// The function's entry address.
    #[inline]
    #[must_use]
    pub const fn ea(&self) -> Ea {
        self.ea
    }

    /// The function's display name, or `None` if unavailable.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        read_string(|buf, cap| self.db.func_name(self.ea, buf, cap))
    }

    /// The one-line C prototype, or `None` if the kernel has no type info.
    #[must_use]
    pub fn prototype(&self) -> Option<String> {
        read_string(|buf, cap| self.db.func_type(self.ea, buf, cap))
    }

    /// Lazily iterate this function's chunks: the entry chunk first, then any tail chunks in
    /// address order. A contiguous function yields exactly one [`Chunk`].
    #[must_use]
    pub fn chunks(&self) -> Chunks<'db> {
        Chunks::new(self.ea, self.db)
    }

    /// Lazily iterate this function's instructions, in address order within each chunk,
    /// across every chunk. Data items and the alignment tail are skipped -- see
    /// [`Instructions`].
    #[must_use]
    pub fn instructions(&self) -> Instructions<'db> {
        Instructions::new(self.db, self.ea)
    }

    /// The function's exclusive end address -- the entry chunk's `end_ea`. `None` only if
    /// the entry is no longer a function.
    #[must_use]
    pub fn end(&self) -> Option<Ea> {
        Ea::try_new(self.db.func_end(self.ea))
    }

    /// The entry chunk's size in bytes (`end - start`), or `0` if the end is unavailable.
    /// A chunked function's tail chunks lie outside this span -- walk [`chunks`](Self::chunks)
    /// for the full extent.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.end().map_or(0, |end| (end - self.ea).max(0) as u64)
    }

    /// Whether IDA flags this as a library function (`FUNC_LIB`).
    #[must_use]
    pub fn is_lib(&self) -> bool {
        self.db.func_flags(self.ea) & sys::FUNC_LIB != 0
    }

    /// Whether this is a thunk -- a trampoline that jumps straight to another function
    /// (`FUNC_THUNK`).
    #[must_use]
    pub fn is_thunk(&self) -> bool {
        self.db.func_flags(self.ea) & sys::FUNC_THUNK != 0
    }

    /// Whether this function does not return (`FUNC_NORET`) -- e.g. `exit`, `abort`.
    #[must_use]
    pub fn is_noreturn(&self) -> bool {
        self.db.func_flags(self.ea) & sys::FUNC_NORET != 0
    }

    /// Lazily iterate cross-references targeting this function's entry.
    #[must_use]
    pub fn xrefs_to(&self) -> Xrefs<'db> {
        self.db.xrefs_to(self.ea)
    }

    /// Lazily iterate cross-references originating at this function's entry.
    #[must_use]
    pub fn xrefs_from(&self) -> Xrefs<'db> {
        self.db.xrefs_from(self.ea)
    }

    /// Decompile this function.
    pub fn decompile(&self) -> Result<Cfunc<'db>> {
        self.db.decompile(self.ea)
    }

    /// Decompile and materialize the ctree in one step ([`decompile`](Self::decompile) then
    /// [`Cfunc::ctree`]). Use the two-step form when you also need the [`Cfunc`] itself.
    pub fn ctree(&self) -> Result<Ctree> {
        let cfunc = self.decompile()?;
        cfunc.ctree().map_err(|source| Error::Extract {
            ea: self.ea.get(),
            source,
        })
    }

    /// Snapshot this view's scalar facts into an owned [`FuncImage`] that can leave the
    /// kernel thread.
    #[must_use]
    pub fn image(&self) -> FuncImage {
        FuncImage {
            ea: self.ea,
            name: self.name(),
            prototype: self.prototype(),
        }
    }
}

#[bon::bon]
impl<'db> Func<'db> {
    /// Build this function's control-flow graph with default options. The whole function is
    /// covered, tail chunks included. See [`Cfg`] and [`cfg_with`](Self::cfg_with) for the
    /// knobs.
    pub fn cfg(&self) -> Result<Cfg> {
        self.db.cfg(self.ea)
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
            .build_cfg(self.ea, cfg_flags(call_ends, externals, predecessors))
    }
}

/// An owned, `Send` snapshot of a function's scalar facts, detached from the database.
/// `Func` borrows a `!Send` [`Idb`]; collect images inside an [`Ida::call`](crate::Ida::call)
/// job to carry results back out.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FuncImage {
    /// Entry address.
    pub ea: Ea,
    /// Display name, if the kernel had one.
    pub name: Option<String>,
    /// One-line C prototype, if the kernel had type info.
    pub prototype: Option<String>,
}

impl std::fmt::Debug for Func<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Func")
            .field("ea", &self.ea)
            .field("name", &self.name())
            .finish()
    }
}

// Identity is the entry address alone; the `db` borrow is incidental and must not
// participate, so these are hand-written rather than derived.
impl PartialEq for Func<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.ea == o.ea
    }
}
impl Eq for Func<'_> {}
impl std::hash::Hash for Func<'_> {
    fn hash<H: std::hash::Hasher>(&self, s: &mut H) {
        self.ea.hash(s);
    }
}
impl Ord for Func<'_> {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.ea.cmp(&o.ea)
    }
}
impl PartialOrd for Func<'_> {
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
    type Item = Func<'db>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.count {
            let raw = self.db.func_ea(self.next);
            self.next += 1;
            if let Some(ea) = Ea::try_new(raw) {
                return Some(Func::new(ea, self.db));
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
/// into tail chunks placed elsewhere. Yielded by [`Func::chunks`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Chunk {
    /// First address of the chunk.
    pub start: Ea,
    /// One-past-the-last address of the chunk.
    pub end: Ea,
}

/// Lazy iterator over a function's chunks, entry chunk first then tail chunks in address
/// order, from [`Func::chunks`].
pub struct Chunks<'db> {
    db: &'db Idb,
    ea: Ea,
    next: i32,
    count: i32,
}

impl<'db> Chunks<'db> {
    #[inline]
    pub(crate) fn new(ea: Ea, db: &'db Idb) -> Self {
        Self {
            db,
            ea,
            next: 0,
            count: db.func_chunk_qty(ea),
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
        if self.db.func_chunk(self.ea, idx, &mut start, &mut end) == 0 {
            return None;
        }
        Some(Chunk {
            start: Ea::try_new(start)?,
            end: Ea::try_new(end)?,
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
/// gate is the point of the iterator -- [`Idb::decode`] turns any bytes into an [`Insn`], so
/// a plain linear decode past a function's `ret` yields garbage; `is_code` keeps the stream
/// to real instructions.
pub struct Instructions<'db> {
    db: &'db Idb,
    chunks: Chunks<'db>,
    /// `(next address to examine, current chunk end)`; `None` until the first chunk loads and
    /// again once the last chunk drains.
    cursor: Option<(Ea, Ea)>,
}

impl<'db> Instructions<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Idb, ea: Ea) -> Self {
        Self {
            db,
            chunks: Chunks::new(ea, db),
            cursor: None,
        }
    }
}

impl Iterator for Instructions<'_> {
    type Item = Insn;

    fn next(&mut self) -> Option<Insn> {
        loop {
            let (ea, end) = match self.cursor {
                Some((ea, end)) if ea < end => (ea, end),
                _ => {
                    let chunk = self.chunks.next()?;
                    self.cursor = Some((chunk.start, chunk.end));
                    continue;
                }
            };
            // Step past this item before deciding to yield, so every branch advances; the
            // kernel's item end is `ea + len` for a decoded instruction, and skips a whole
            // data item in one go. The `> ea` guard keeps a pathological zero-width item from
            // stalling the walk.
            let stepped = self.db.item_end(ea);
            self.cursor = Some((if stepped > ea { stepped } else { end }, end));
            if self.db.is_code(ea)
                && let Ok(insn) = self.db.decode(ea)
            {
                return Some(insn);
            }
        }
    }
}

impl Idb {
    /// Lazily decode the instructions in the half-open range `[range.start, range.end)`,
    /// code-gated like [`Func::instructions`]. The ranged twin of that walk -- pass a
    /// [`Block`](crate::Block)'s [`range`](crate::Block::range) to iterate one basic block.
    #[must_use]
    pub fn instructions_in(&self, range: Range<Ea>) -> InstructionsIn<'_> {
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
    cursor: Ea,
    end: Ea,
}

impl Iterator for InstructionsIn<'_> {
    type Item = Insn;

    fn next(&mut self) -> Option<Insn> {
        while self.cursor < self.end {
            let ea = self.cursor;
            // Step past this item before deciding to yield, so every branch advances; the
            // `> ea` guard keeps a zero-width item from stalling the walk (cf. Instructions).
            let stepped = self.db.item_end(ea);
            self.cursor = if stepped > ea { stepped } else { self.end };
            if self.db.is_code(ea)
                && let Ok(insn) = self.db.decode(ea)
            {
                return Some(insn);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::FuncImage;

    const fn assert_send<T: Send>() {}

    // The reason FuncImage exists: unlike Func, it can cross the kernel-thread boundary.
    const _: () = assert_send::<FuncImage>();
}
