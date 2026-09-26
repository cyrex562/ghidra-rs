//! Port of `ghidra.program.model.correlate.Block`.
//!
//! This holds basic-block information for matching algorithms. It is used as a node to traverse
//! the control-flow graph. It serves as a container for hashing information associated with
//! Instructions in the block. It holds disambiguating hashes (calculated primarily from
//! basic-block parent/child relationships) to help separate identical or near identical
//! sequences of Instructions within one function.
//!
//! # Ownership
//!
//! Java's `Block` owns an `InstructHash[]`, and each `InstructHash` points back at its `Block`.
//! Here the owning [`HashStore`](super::HashStore) keeps every `Block` in an arena, a block owns
//! its instructions in a `Vec<InstructHash>`, and each instruction refers back to its block by
//! [`CorrelateBlockId`], the block's slot in that arena.

use crate::program::model::block::CodeBlock;
use crate::program::model::mem::MemoryAccessException;

use super::hash::Hash;
use super::hash_calculator::HashCalculator;
use super::instruct_hash::InstructHash;

/// Handle to a [`Block`] within the arena of the [`HashStore`](super::HashStore) that owns it.
///
/// The value is the block's index in that store's arena; it is only meaningful to that store.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorrelateBlockId(pub u32);

impl CorrelateBlockId {
    /// The arena slot this handle names.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// A basic block within the function, together with the hashing state of its instructions.
///
/// Port of `ghidra.program.model.correlate.Block`. Java's fields are `protected` (package-visible
/// to `HashStore`, `HashEntry` and the disambiguation strategies, which read and mutate them
/// directly), so they are public here; `matchHash` is private in Java and stays private, read
/// through [`get_match_hash`](Self::get_match_hash).
pub struct Block {
    /// True if a 1-to-1 match for this block has been found.
    pub is_matched: bool,
    /// True if the algorithm has visited this block before.
    pub is_visited: bool,
    /// The underlying basic-block being described.
    pub orig_block: Box<dyn CodeBlock>,
    /// If the block has been matched, this value is fed to hashes to deconflict further matches.
    match_hash: i32,
    /// Instructions (and corresponding hashing info) for this block. Java starts this as `null`
    /// until the store attaches the array; here it starts empty.
    pub inst_list: Vec<InstructHash>,
}

impl Block {
    /// Create an unmatched, unvisited block describing `code_block`, with no instructions yet.
    ///
    /// Port of `Block(CodeBlock)`.
    pub fn new(code_block: Box<dyn CodeBlock>) -> Self {
        Self {
            is_matched: false,
            is_visited: false,
            orig_block: code_block,
            match_hash: 0, // Should be zero for an unknown block
            inst_list: Vec::new(),
        }
    }

    /// Clear out structures associated with the main sort.
    ///
    /// Port of `clearSort()`.
    pub fn clear_sort(&mut self) {
        for element in &mut self.inst_list {
            element.clear_sort();
        }
    }

    /// Set up the block match deconfliction value. This is fed into the n-gram hashes for
    /// instructions contained by this block to uniquely associate the n-grams with this block (and
    /// the matching block on the other side).
    ///
    /// `index` is the 1-up index used to uniquely label this block. The transformation expands
    /// bit diversity within the 32-bit value; each step is invertible modulo 2^32 (Java `int`
    /// arithmetic wraps, as it does here), so no information in `index` is lost.
    ///
    /// Port of `setMatched(int)`.
    pub fn set_matched(&mut self, index: i32) {
        self.is_matched = true;
        let mut match_hash = index.wrapping_mul(7919);
        match_hash = match_hash.wrapping_add(511);
        match_hash = match_hash.wrapping_mul(4691);
        self.match_hash = match_hash;
    }

    /// The main deconfliction hash feed; 0 until the block is matched.
    ///
    /// Port of `getMatchHash()`.
    pub fn get_match_hash(&self) -> i32 {
        self.match_hash
    }

    /// Whether the indicated n-gram, within this block, consists entirely of unmatched
    /// instructions.
    ///
    /// Port of `allUnknown(int, int)`. Panics if the n-gram runs past the end of the block, as
    /// Java's array access throws.
    pub fn all_unknown(&self, startindex: usize, length: usize) -> bool {
        self.inst_list[startindex..startindex + length].iter().all(|inst| !inst.is_matched)
    }

    /// Calculate an n-gram hash of `gram_size` instructions starting at `inst_hash` (an
    /// instruction of this block), using the hash function `hash_calc`.
    ///
    /// Port of `hashGram(int, InstructHash, HashCalculator)`.
    pub fn hash_gram(
        &self,
        gram_size: usize,
        inst_hash: &InstructHash,
        hash_calc: &dyn HashCalculator,
    ) -> Result<i32, MemoryAccessException> {
        let mut hash_val = Hash::SEED;
        for cur_hash in &self.inst_list[inst_hash.index..inst_hash.index + gram_size] {
            hash_val = hash_calc.calc_hash(hash_val, cur_hash.instruction.as_ref())?;
        }
        Ok(hash_val)
    }

    /// Calculate n-gram hashes used for matching (for instructions in this basic block). The
    /// exact hashes generated can be changed to get different looks at the data over multiple
    /// matching passes.
    ///
    /// * `min_length` -- the minimum length of an n-gram to calculate
    /// * `max_length` -- the maximum length of an n-gram
    /// * `whole_block` -- a hash of the whole block should be calculated even if its size is
    ///   below `min_length`
    /// * `match_only` -- hashes should only be calculated for previously matched, or small,
    ///   blocks
    /// * `hash_calc` -- the hash function for this matching pass
    ///
    /// Port of `calcHashes(int, int, boolean, boolean, HashCalculator)`.
    pub fn calc_hashes(
        &mut self,
        mut min_length: usize,
        mut max_length: usize,
        whole_block: bool,
        match_only: bool,
        hash_calc: &dyn HashCalculator,
    ) -> Result<(), MemoryAccessException> {
        let len = self.inst_list.len();
        if whole_block && len < min_length {
            // Block is too small for even the smallest n-gram: exactly 1 whole-block n-gram.
            min_length = len;
            max_length = len;
        } else if match_only && self.match_hash == 0 && len > 8 {
            // This block has not been matched and is big: don't generate n-grams for it.
            for inst in &mut self.inst_list {
                if !inst.is_matched {
                    inst.clear_n_grams(0); // No possibility of matching with tiny pieces
                }
            }
            return Ok(());
        }
        for i in 0..len {
            // Calculate hashes starting with instruction i
            if self.inst_list[i].is_matched {
                continue; // If already matched, no hashes with this instruction
            }
            if i + min_length > len {
                // We cannot fit the minimum hash size
                self.inst_list[i].clear_n_grams(0);
                continue;
            }
            let maxind = (i + max_length).min(len);
            // Number of hashes we generate for this instruction. Java computes this as an `int`;
            // a `max_length` below `min_length` makes it non-positive, which Java's
            // `new Hash[num]` would reject, so it is rejected here too.
            let num = (maxind + 1)
                .checked_sub(i + min_length)
                .expect("NegativeArraySizeException: maxLength is less than minLength");
            self.inst_list[i].clear_n_grams(num);
            // If an n-gram contains the block's starting instruction (and the block is big) this
            // is encoded in the hash by changing the initial hash accumulator value.
            let mut accum = if i == 0 && len > 8 { Hash::SEED } else { Hash::ALTERNATE_SEED };

            // Perform the intermediate hashes, 0 to min_length-1
            for j in 0..min_length.saturating_sub(1) {
                if accum != 0 {
                    let inst = &self.inst_list[i + j];
                    if inst.is_matched {
                        // Could be matched/unmatched instructions in window
                        accum = 0;
                        break;
                    }
                    accum = hash_calc.calc_hash(accum, inst.instruction.as_ref())?;
                }
            }

            // Extend to final hashes, saving the resulting n-gram each time
            for j in 0..num {
                // Hash in one more value
                if accum != 0 {
                    let inst = &self.inst_list[i + j + min_length - 1];
                    if inst.is_matched {
                        accum = 0;
                    } else {
                        accum = hash_calc.calc_hash(accum, inst.instruction.as_ref())?;
                    }
                }
                // Create a hash record, XORing in the non-zero value if the block was matched
                let n_gram = if accum != 0 {
                    Some(Hash::new(accum ^ self.match_hash, (min_length + j) as i32))
                } else {
                    None
                };
                self.inst_list[i].n_grams.as_mut().expect("n-grams were just cleared")[j] = n_gram;
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Block")
            .field("is_matched", &self.is_matched)
            .field("is_visited", &self.is_visited)
            .field("match_hash", &self.match_hash)
            .field("inst_list", &self.inst_list)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::correlate::test_support::{block_of, TestInst};
    use crate::program::model::correlate::MnemonicHashCalculator;
    use crate::program::model::listing::Instruction;

    const ID: CorrelateBlockId = CorrelateBlockId(0);

    /// The mnemonic hash of a run of instructions, folded from `seed` as the n-gram loops do.
    fn chain(seed: i32, mnemonics: &[&str]) -> i32 {
        mnemonics.iter().fold(seed, |acc, m| {
            let inst = TestInst {
                address: crate::program::model::correlate::test_support::addr(0),
                length: 4,
                mnemonic: m.to_string(),
            };
            MnemonicHashCalculator.calc_hash(acc, &inst as &dyn Instruction).unwrap()
        })
    }

    fn n_grams(block: &Block, i: usize) -> Option<Vec<Option<Hash>>> {
        block.inst_list[i].n_grams.clone()
    }

    #[test]
    fn a_new_block_is_unmatched_with_a_zero_match_hash() {
        let block = Block::new(crate::program::model::correlate::test_support::TestBlock::boxed(&[(0x10, 0x1f)]));
        assert!(!block.is_matched);
        assert!(!block.is_visited);
        assert_eq!(block.get_match_hash(), 0);
        assert!(block.inst_list.is_empty());
        assert_eq!(block.orig_block.get_first_start_address().offset(), 0x10);
    }

    #[test]
    fn set_matched_derives_the_match_hash_from_the_index_with_int_wraparound() {
        let mut block = block_of(ID, &["A"]);
        block.set_matched(1);
        assert!(block.is_matched);
        // ((1 * 7919) + 511) * 4691
        assert_eq!(block.get_match_hash(), 39_545_130);
        block.set_matched(2);
        assert_eq!(block.get_match_hash(), 76_693_159);
        // 1_000_000 * 7919 overflows a Java int; the result wraps as Java's does.
        block.set_matched(1_000_000);
        assert_eq!(block.get_match_hash(), 859_253_997);
    }

    #[test]
    fn all_unknown_checks_the_window() {
        let mut block = block_of(ID, &["A", "B", "C", "D"]);
        block.inst_list[2].is_matched = true;
        assert!(block.all_unknown(0, 2));
        assert!(!block.all_unknown(1, 2));
        assert!(block.all_unknown(3, 1));
        assert!(block.all_unknown(2, 0));
    }

    #[test]
    fn hash_gram_folds_the_window_from_the_main_seed() {
        let block = block_of(ID, &["A", "B", "C", "D"]);
        let h = block.hash_gram(2, &block.inst_list[1], &MnemonicHashCalculator).unwrap();
        assert_eq!(h, chain(Hash::SEED, &["B", "C"]));
        assert_ne!(h, chain(Hash::SEED, &["C", "B"]));
    }

    #[test]
    fn calc_hashes_small_block_uses_the_alternate_seed_and_every_window_that_fits() {
        let mut block = block_of(ID, &["A", "B", "C"]);
        block.calc_hashes(2, 3, false, false, &MnemonicHashCalculator).unwrap();

        // Instruction 0: n-grams of length 2 and 3.
        assert_eq!(
            n_grams(&block, 0),
            Some(vec![
                Some(Hash::new(chain(Hash::ALTERNATE_SEED, &["A", "B"]), 2)),
                Some(Hash::new(chain(Hash::ALTERNATE_SEED, &["A", "B", "C"]), 3)),
            ])
        );
        // Instruction 1: only the length-2 n-gram fits.
        assert_eq!(n_grams(&block, 1), Some(vec![Some(Hash::new(chain(Hash::ALTERNATE_SEED, &["B", "C"]), 2))]));
        // Instruction 2: cannot fit the minimum size.
        assert_eq!(n_grams(&block, 2), Some(vec![]));
    }

    #[test]
    fn calc_hashes_big_block_seeds_only_the_block_start_with_the_main_seed() {
        let names = ["A", "B", "C", "D", "E", "F", "G", "H", "I"];
        let mut block = block_of(ID, &names);
        block.calc_hashes(2, 2, false, false, &MnemonicHashCalculator).unwrap();

        assert_eq!(n_grams(&block, 0), Some(vec![Some(Hash::new(chain(Hash::SEED, &["A", "B"]), 2))]));
        assert_eq!(n_grams(&block, 1), Some(vec![Some(Hash::new(chain(Hash::ALTERNATE_SEED, &["B", "C"]), 2))]));
    }

    #[test]
    fn calc_hashes_whole_block_makes_one_n_gram_of_a_short_block() {
        let mut block = block_of(ID, &["A", "B"]);
        block.calc_hashes(4, 6, true, false, &MnemonicHashCalculator).unwrap();

        assert_eq!(n_grams(&block, 0), Some(vec![Some(Hash::new(chain(Hash::ALTERNATE_SEED, &["A", "B"]), 2))]));
        assert_eq!(n_grams(&block, 1), Some(vec![]));

        // Without whole_block, the short block gets no n-grams at all.
        let mut block = block_of(ID, &["A", "B"]);
        block.calc_hashes(4, 6, false, false, &MnemonicHashCalculator).unwrap();
        assert_eq!(n_grams(&block, 0), Some(vec![]));
    }

    #[test]
    fn calc_hashes_match_only_skips_big_unmatched_blocks_but_hashes_matched_ones() {
        let names = ["A", "B", "C", "D", "E", "F", "G", "H", "I"];
        let mut block = block_of(ID, &names);
        block.calc_hashes(2, 2, false, true, &MnemonicHashCalculator).unwrap();
        for i in 0..names.len() {
            assert_eq!(n_grams(&block, i), Some(vec![]));
        }

        // Once matched, the same pass hashes it, XORing in the match hash.
        block.set_matched(1);
        block.calc_hashes(2, 2, false, true, &MnemonicHashCalculator).unwrap();
        assert_eq!(
            n_grams(&block, 1),
            Some(vec![Some(Hash::new(chain(Hash::ALTERNATE_SEED, &["B", "C"]) ^ 39_545_130, 2))])
        );
    }

    #[test]
    fn calc_hashes_leaves_matched_instructions_alone_and_voids_windows_crossing_them() {
        let mut block = block_of(ID, &["A", "B", "C", "D"]);
        block.inst_list[2].is_matched = true;
        block.calc_hashes(2, 3, false, false, &MnemonicHashCalculator).unwrap();

        // Window A,B is clean; A,B,C crosses the matched instruction.
        assert_eq!(
            n_grams(&block, 0),
            Some(vec![Some(Hash::new(chain(Hash::ALTERNATE_SEED, &["A", "B"]), 2)), None])
        );
        // Every window from B crosses C.
        assert_eq!(n_grams(&block, 1), Some(vec![None, None]));
        // The matched instruction itself is not touched.
        assert_eq!(n_grams(&block, 2), None);
        assert_eq!(n_grams(&block, 3), Some(vec![]));
    }

    #[test]
    fn clear_sort_clears_every_instructions_cross_references() {
        let mut block = block_of(ID, &["A", "B"]);
        block.inst_list[0]
            .hash_entries
            .insert(Hash::new(1, 1), crate::program::model::correlate::CorrelateHashEntryId(0));
        block.inst_list[1]
            .hash_entries
            .insert(Hash::new(2, 1), crate::program::model::correlate::CorrelateHashEntryId(1));
        block.clear_sort();
        assert!(block.inst_list.iter().all(|i| i.hash_entries.is_empty()));
    }
}
