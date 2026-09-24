//! Port of `ghidra.program.model.correlate.InstructHash`.
//!
//! # Shape
//!
//! Java is a concrete class that nothing extends, so this is a plain `struct`
//! (per `scripts/shape_rules.py`).
//!
//! # Ownership
//!
//! In Java an `InstructHash` holds a reference to its containing `Block` and a table of the
//! `HashEntry`s its n-grams belong to, while `Block` and `HashEntry` hold `InstructHash`es back.
//! That cycle is a mutable graph owned by one `HashStore`, so here the back-references are arena
//! handles ([`CorrelateBlockId`], [`CorrelateHashEntryId`]) into the owning store rather than
//! shared pointers. `Block`, `HashEntry` and `HashStore` are not ported yet; the handles are
//! placeholders in [`crate::program::seam_stubs`].
//!
//! Java's fields are `protected` (package-visible to `Block`, `HashStore`, `HashEntry` and
//! `HashedFunctionAddressCorrelation`), so they are public here: those consumers read and
//! mutate them directly.

use std::collections::HashMap;
use std::sync::Arc;

use super::hash::Hash;
use crate::program::model::listing::Instruction;
use crate::program::seam_stubs::{CorrelateBlockId, CorrelateHashEntryId};

/// An instruction within a basic block, together with the n-gram hashes that start at it.
///
/// Port of `ghidra.program.model.correlate.InstructHash`.
pub struct InstructHash {
    /// True if a 1-1 match has been found for this instruction.
    pub is_matched: bool,
    /// Index of this instruction within its block.
    pub index: usize,
    /// The containing basic block.
    pub block: CorrelateBlockId,
    /// The underlying assembly instruction.
    pub instruction: Arc<dyn Instruction>,
    /// Different length hashes, within a single basic block, over multiple instructions.
    ///
    /// `None` mirrors Java's `null` array (not yet calculated, or released once matched); a
    /// `None` element mirrors a `null` slot (no hash for that n-gram length).
    pub n_grams: Option<Vec<Option<Hash>>>,
    /// Cross-reference for n-grams/instructions sharing the same hash.
    pub hash_entries: HashMap<Hash, CorrelateHashEntryId>,
}

impl InstructHash {
    /// Build an (unmatched) instruction, associating it with its position `index` in the basic
    /// block `block`.
    pub fn new(instruction: Arc<dyn Instruction>, block: CorrelateBlockId, index: usize) -> Self {
        Self {
            is_matched: false,
            index,
            block,
            instruction,
            n_grams: None,
            hash_entries: HashMap::new(),
        }
    }

    /// Returns the containing basic block.
    pub fn get_block(&self) -> CorrelateBlockId {
        self.block
    }

    /// If the `length` instructions, starting with this one, are all unmatched, return true.
    ///
    /// Java delegates to `block.allUnknown(index, length)`, which scans the block's instruction
    /// array. The block is owned by the `HashStore` arena rather than reachable from `self`, so
    /// the caller passes the containing block's instruction list, `block_inst_list` (the list
    /// whose element `index` is `self`).
    ///
    /// # Panics
    ///
    /// Panics if `index + length` runs past the end of `block_inst_list`, as Java's array
    /// access throws `ArrayIndexOutOfBoundsException`.
    pub fn all_unknown(&self, block_inst_list: &[InstructHash], length: usize) -> bool {
        block_inst_list[self.index..self.index + length]
            .iter()
            .all(|inst| !inst.is_matched)
    }

    /// Clear out structures associated with the main sort.
    pub fn clear_sort(&mut self) {
        self.hash_entries = HashMap::new();
    }

    /// Clear out the n-gram array to an uninitialized list of `size` slots.
    pub fn clear_n_grams(&mut self, size: usize) {
        self.n_grams = Some(vec![None; size]);
    }
}

impl std::fmt::Debug for InstructHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstructHash")
            .field("is_matched", &self.is_matched)
            .field("index", &self.index)
            .field("block", &self.block)
            .field("n_grams", &self.n_grams)
            .field("hash_entries", &self.hash_entries)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::correlate::hash_calculator::tests::MockInstruction;

    fn block_of(n: usize) -> Vec<InstructHash> {
        (0..n)
            .map(|i| InstructHash::new(Arc::new(MockInstruction), CorrelateBlockId(7), i))
            .collect()
    }

    #[test]
    fn new_is_unmatched_with_no_hashes() {
        let ih = InstructHash::new(Arc::new(MockInstruction), CorrelateBlockId(3), 5);
        assert!(!ih.is_matched);
        assert_eq!(ih.index, 5);
        assert_eq!(ih.get_block(), CorrelateBlockId(3));
        assert!(ih.n_grams.is_none());
        assert!(ih.hash_entries.is_empty());
        assert_eq!(ih.instruction.get_mnemonic_string(), "NOP");
    }

    #[test]
    fn clear_n_grams_allocates_empty_slots() {
        let mut ih = InstructHash::new(Arc::new(MockInstruction), CorrelateBlockId(0), 0);
        ih.clear_n_grams(3);
        assert_eq!(ih.n_grams.as_deref(), Some(&[None, None, None][..]));
        ih.clear_n_grams(0);
        assert_eq!(ih.n_grams.as_deref(), Some(&[][..]));
    }

    #[test]
    fn clear_sort_drops_cross_references_but_keeps_n_grams() {
        let mut ih = InstructHash::new(Arc::new(MockInstruction), CorrelateBlockId(0), 0);
        ih.clear_n_grams(1);
        let h = Hash::new(0x1234, 1);
        ih.n_grams.as_mut().unwrap()[0] = Some(h);
        ih.hash_entries.insert(h, CorrelateHashEntryId(9));
        ih.clear_sort();
        assert!(ih.hash_entries.is_empty());
        assert_eq!(ih.n_grams.as_ref().unwrap()[0], Some(h));
    }

    #[test]
    fn all_unknown_checks_window_starting_at_self() {
        let mut insts = block_of(5);
        insts[3].is_matched = true;

        // Window [1, 3) is all unmatched; [1, 4) includes the matched instruction 3.
        assert!(insts[1].all_unknown(&insts, 2));
        assert!(!insts[1].all_unknown(&insts, 3));
        // A window starting past the matched instruction.
        assert!(insts[4].all_unknown(&insts, 1));
        // Zero-length window is vacuously unknown (Java's loop body never runs).
        assert!(insts[3].all_unknown(&insts, 0));
        // A window starting at the matched instruction itself.
        assert!(!insts[3].all_unknown(&insts, 1));
    }

    #[test]
    #[should_panic]
    fn all_unknown_past_end_of_block_panics() {
        let insts = block_of(2);
        insts[1].all_unknown(&insts, 2);
    }
}
