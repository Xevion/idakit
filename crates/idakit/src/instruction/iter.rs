//! Lazy iterators over decoded instructions: [`Instructions`] and [`InstructionsIn`].

use std::fmt;
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
    chunks: FunctionChunks,
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

impl fmt::Debug for Instructions<'_> {
    // Skips the borrowed `&Database`; only the chunk cursor is printable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Instructions")
            .field("chunks", &self.chunks)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
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

impl fmt::Debug for InstructionsIn<'_> {
    // Skips the borrowed `&Database`; only the walk bounds are printable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstructionsIn")
            .field("cursor", &self.cursor)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
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
    use crate::function::FunctionChunk;

    #[test]
    fn instructions_debug_renders_the_chunk_cursor() {
        let db = Database::new();
        let start = Address::new_const(0x1000);
        let end = Address::new_const(0x1010);
        let iter = Instructions {
            db: &db,
            chunks: FunctionChunks::from_chunks(vec![FunctionChunk { start, end }]),
            cursor: Some((start, end)),
        };
        let rendered = format!("{iter:?}");
        assert!(rendered.starts_with("Instructions"));
        assert!(rendered.contains("cursor"));
    }

    #[test]
    fn instructions_in_debug_renders_the_walk_bounds() {
        let db = Database::new();
        let iter = InstructionsIn {
            db: &db,
            cursor: Address::new_const(0x1000),
            end: Address::new_const(0x1010),
        };
        let rendered = format!("{iter:?}");
        assert!(rendered.starts_with("InstructionsIn"));
        assert!(rendered.contains("cursor"));
        assert!(rendered.contains("end"));
    }
}
