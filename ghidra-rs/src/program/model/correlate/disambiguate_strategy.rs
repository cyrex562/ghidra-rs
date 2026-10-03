//! Port of `ghidra.program.model.correlate.DisambiguateStrategy`.

use thiserror::Error;

use crate::program::model::mem::MemoryAccessException;
use crate::util::exception::CancelledException;

use super::hash::Hash;
use super::hash_store::HashStore;
use super::instruct_hash::InstructHash;

/// The checked exceptions `DisambiguateStrategy.calcHashes` declares.
#[derive(Error, Debug)]
pub enum DisambiguateError {
    /// The task monitor was cancelled. Java: `CancelledException`.
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    /// An instruction's bytes could not be read. Java: `MemoryAccessException`.
    #[error(transparent)]
    MemoryAccess(#[from] MemoryAccessException),
}

/// A way of generating secondary hashes that separate an n-gram (and its block) from other
/// blocks with similar instructions.
///
/// Port of the interface `ghidra.program.model.correlate.DisambiguateStrategy`, an open extension
/// point (disambiguation by bytes, by parent, by parent with order, by child).
pub trait DisambiguateStrategy {
    /// Generate (possibly multiple) hashes that can be used to disambiguate an n-gram and its
    /// block from other blocks with similar instructions.
    ///
    /// * `inst_hash` -- the instruction hash (the first instruction of the n-gram)
    /// * `match_size` -- the number of instructions to match
    /// * `store` -- the store owning `inst_hash`, through which its block and the other blocks
    ///   of the function are reached
    ///
    /// Returns the list of disambiguating hashes.
    fn calc_hashes(
        &self,
        inst_hash: &InstructHash,
        match_size: i32,
        store: &HashStore,
    ) -> Result<Vec<Hash>, DisambiguateError>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::correlate::test_support::{addr, TestBlock, TestListing};
    use crate::program::model::correlate::NgramMatch;
    use crate::util::task::DummyMonitor;

    /// A strategy in the shape of Java's `DisambiguateByParent`: it reads blocks through the
    /// store, here the n-gram's own block, and uses a matched block's match hash.
    struct ByOwnBlock;

    impl DisambiguateStrategy for ByOwnBlock {
        fn calc_hashes(
            &self,
            inst_hash: &InstructHash,
            _match_size: i32,
            store: &HashStore,
        ) -> Result<Vec<Hash>, DisambiguateError> {
            store.get_monitor().check_cancelled()?;
            let block = store.block(inst_hash.block);
            let start = block.orig_block.get_first_start_address();
            let same = store.get_block(&start).expect("block by start address");
            let mut res = Vec::new();
            if same.get_match_hash() != 0 {
                res.push(Hash::new(same.get_match_hash(), 1));
            }
            Ok(res)
        }
    }

    #[test]
    fn a_strategy_reaches_blocks_through_the_store() {
        let mut listing = TestListing::default();
        listing.place(0x1000, 4, &["A", "B"]);
        let mut store =
            HashStore::new(vec![TestBlock::boxed(&[(0x1000, 0x1007)])], &listing, Arc::new(DummyMonitor));
        let block = store.get_block(&addr(0x1000)).unwrap().inst_list[0].block;
        let strategy: &dyn DisambiguateStrategy = &ByOwnBlock;

        let hashes = strategy.calc_hashes(&store.block(block).inst_list[0], 1, &store).unwrap();
        assert!(hashes.is_empty());

        let (mut insts, mut blocks) = (Vec::new(), Vec::new());
        store.calc_hashes(1, 1, false, false, &crate::program::model::correlate::MnemonicHashCalculator).unwrap();
        store.insert_hashes();
        store.match_hash(&NgramMatch { block, startindex: 0, endindex: 0 }, &mut insts, &mut blocks);
        let hashes = strategy.calc_hashes(&store.block(block).inst_list[1], 1, &store).unwrap();
        assert_eq!(hashes, vec![Hash::new(39_545_130, 1)]);
    }

    #[test]
    fn errors_carry_either_checked_exception() {
        let e: DisambiguateError = CancelledException::default().into();
        assert!(matches!(e, DisambiguateError::Cancelled(_)));
        assert_eq!(e.to_string(), "Operation cancelled: Operation cancelled");
        let e: DisambiguateError = MemoryAccessException::new("bad read").into();
        assert!(matches!(e, DisambiguateError::MemoryAccess(_)));
    }
}
