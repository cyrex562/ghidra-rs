//! Port of `ghidra.program.model.correlate.HashEntry`.
//!
//! Cross-reference container for different n-grams that share a particular hash.
//!
//! # Ownership
//!
//! Java's `HashEntry` holds a `LinkedList<InstructHash>` of the n-grams' starting instructions,
//! which are owned by their `Block`s. Here every `HashEntry` lives in the arena of the
//! [`HashStore`](super::HashStore) that owns it (named by [`CorrelateHashEntryId`]), and it refers
//! to each starting instruction by [`InstructHashRef`]: the owning block's id plus the
//! instruction's index in that block.

use super::block::{Block, CorrelateBlockId};
use super::hash::Hash;
use super::instruct_hash::InstructHash;

/// Handle to a [`HashEntry`] within the arena of the [`HashStore`](super::HashStore) that owns
/// it.
///
/// The value is the entry's index in that store's arena; it is only meaningful to that store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorrelateHashEntryId(pub u32);

impl CorrelateHashEntryId {
    /// The arena slot this handle names.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// A reference to an [`InstructHash`]: its block, and its position within that block.
///
/// Stands in for the Java object reference an `InstructHash` list element holds. Two references
/// are equal exactly when they name the same instruction, matching Java's identity-based
/// `LinkedList.remove(Object)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstructHashRef {
    /// The block containing the instruction.
    pub block: CorrelateBlockId,
    /// The instruction's index within the block ([`InstructHash::index`]).
    pub index: usize,
}

impl InstructHashRef {
    /// A reference to the given instruction.
    pub fn of(inst: &InstructHash) -> Self {
        Self { block: inst.block, index: inst.index }
    }

    /// Resolve this reference against the owning store's block arena.
    ///
    /// Panics if the reference does not name an instruction in `blocks`.
    pub fn resolve<'a>(&self, blocks: &'a [Block]) -> &'a InstructHash {
        &blocks[self.block.index()].inst_list[self.index]
    }
}

/// Cross-reference container for different n-grams that share a particular hash.
///
/// Port of `ghidra.program.model.correlate.HashEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashEntry {
    /// Hash being shared across n-grams. The n-gram length is contained in the hash.
    pub hash: Hash,
    /// (Starting instruction of) n-grams with this hash.
    pub inst_list: Vec<InstructHashRef>,
}

impl HashEntry {
    /// Create an entry for `h`, with no n-grams yet.
    ///
    /// Port of `HashEntry(Hash)`.
    pub fn new(h: Hash) -> Self {
        Self { hash: h, inst_list: Vec::new() }
    }

    /// Returns true if any two n-grams of this entry share the same parent block.
    ///
    /// As in Java, this marks each block's `is_visited` flag while scanning and clears every flag
    /// it may have set before returning. `blocks` is the owning store's block arena.
    ///
    /// Port of `hasDuplicateBlocks()`.
    pub fn has_duplicate_blocks(&self, blocks: &mut [Block]) -> bool {
        let mut res = false;
        for cur in &self.inst_list {
            let block = &mut blocks[cur.block.index()];
            if block.is_visited {
                // Multiple InstructHashes from one block
                res = true;
                break;
            }
            block.is_visited = true;
        }
        for cur in &self.inst_list {
            blocks[cur.block.index()].is_visited = false;
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::correlate::test_support::block_of;

    fn blocks() -> Vec<Block> {
        vec![
            block_of(CorrelateBlockId(0), &["A", "B", "C"]),
            block_of(CorrelateBlockId(1), &["A", "B"]),
        ]
    }

    fn r(block: u32, index: usize) -> InstructHashRef {
        InstructHashRef { block: CorrelateBlockId(block), index }
    }

    #[test]
    fn a_new_entry_has_no_n_grams() {
        let e = HashEntry::new(Hash::new(5, 3));
        assert_eq!(e.hash, Hash::new(5, 3));
        assert!(e.inst_list.is_empty());
    }

    #[test]
    fn duplicate_blocks_are_detected_and_visited_flags_are_cleared() {
        let mut blocks = blocks();
        let mut e = HashEntry::new(Hash::new(5, 1));
        e.inst_list = vec![r(0, 0), r(1, 0)];
        assert!(!e.has_duplicate_blocks(&mut blocks));
        assert!(blocks.iter().all(|b| !b.is_visited));

        e.inst_list = vec![r(0, 0), r(1, 1), r(0, 2)];
        assert!(e.has_duplicate_blocks(&mut blocks));
        assert!(blocks.iter().all(|b| !b.is_visited));

        e.inst_list.clear();
        assert!(!e.has_duplicate_blocks(&mut blocks));
    }

    #[test]
    fn references_resolve_to_the_named_instruction() {
        let blocks = blocks();
        let inst = r(1, 1).resolve(&blocks);
        assert_eq!(inst.block, CorrelateBlockId(1));
        assert_eq!(inst.index, 1);
        assert_eq!(inst.instruction.get_mnemonic_string(), "B");
        assert_eq!(InstructHashRef::of(inst), r(1, 1));
    }
}
