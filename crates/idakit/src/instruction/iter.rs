//! Lazy iterators over decoded instructions: [`Instructions`] and [`InstructionsIn`].

use std::ops::Range;

use super::Instruction;
use crate::Database;
use crate::address::Address;
use crate::function::FunctionChunks;

/// A lazy iterator over a function's instructions, across all its chunks, from
/// [`Function::instructions`](crate::function::Function::instructions).
///
/// Code-gated, decoding only addresses the kernel classifies as code ([`Database::is_code`])
/// and stepping over data items (jump tables, embedded constants) and the alignment tail.
/// [`Database::decode`] turns any bytes into an [`Instruction`], so a plain linear decode past a
/// function's `ret` yields garbage; `is_code` keeps the stream to real instructions.
pub struct Instructions<'db> {
    db: &'db Database,
    chunks: FunctionChunks<'db>,
    /// `(next address to examine, current chunk end)`; `None` until the first chunk loads and
    /// again once the last chunk drains.
    cursor: Option<(Address, Address)>,
}

impl<'db> Instructions<'db> {
    #[inline]
    pub(crate) fn new(db: &'db Database, address: Address) -> Self {
        Self {
            db,
            chunks: FunctionChunks::new(address, db),
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

impl Database {
    /// Lazily decodes the instructions in the half-open range `[range.start, range.end)`,
    /// code-gated like [`Function::instructions`](crate::function::Function::instructions).
    ///
    /// The ranged twin of that walk. Pass a
    /// [`BasicBlock`](crate::flowchart::BasicBlock)'s [`range`](crate::flowchart::BasicBlock::range)
    /// to iterate one basic block.
    #[must_use]
    pub fn instructions_in(&self, range: Range<Address>) -> InstructionsIn<'_> {
        InstructionsIn {
            db: self,
            cursor: range.start,
            end: range.end,
        }
    }
}

/// A lazy iterator over the instructions in a fixed `[start, end)` range, code-gated like
/// [`Instructions`], from [`Database::instructions_in`].
pub struct InstructionsIn<'db> {
    db: &'db Database,
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
