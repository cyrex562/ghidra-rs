//! Port of `ghidra.program.model.correlate.HashStore`.
//!
//! `HashStore` is a sorted, basic-block aware, store for Instruction "n-grams" to help quickly
//! match similar sequences of Instructions between two functions. The Instructions comprising a
//! single n-gram are hashed for quick lookup by the main matching algorithm
//! (`HashedFunctionAddressCorrelation`). Hash diversity is important to minimize collisions, even
//! though the number of hashes calculated for a single function pair match is small.
//!
//! Hashes are built and sorted respectively using [`calc_hashes`](HashStore::calc_hashes) and
//! [`insert_hashes`](HashStore::insert_hashes). The main sort is on the number of collisions for a
//! hash (indicating that there are duplicate or near duplicate instruction sequences); the hashes
//! with fewer (or no) duplicates come first. The secondary sort is on "n", the number of
//! Instructions in the n-gram, which effectively describes the significance of the match, or how
//! unlikely the match is to occur at random. The main matching algorithm effectively creates a
//! `HashStore` for both functions, and then in a loop calls
//!
//! * [`get_first_entry`](HashStore::get_first_entry) on one side to get the most significant
//!   possible match
//! * [`get_entry`](HashStore::get_entry) to see if there is a matching n-gram on the other side
//!
//! If there is a match it is declared to the store with [`match_hash`](HashStore::match_hash),
//! allowing overlapping n-grams to be removed and deconflicting information to be updated. If
//! there is no match, hashes can be removed with [`remove_hash`](HashStore::remove_hash) to allow
//! new hashes to move to the top of the sort.
//!
//! The store uses a couple of methods to help deconflict very similar sequences of instructions
//! within the same function. Primarily, the sort is basic-block aware. All n-grams are contained
//! within a single basic block, and when an initial match is found, hashes for other n-grams
//! within that block (and its matching block on the other side) are modified so that n-grams
//! within that block pair can only match each other.
//!
//! # Ownership
//!
//! The Java object graph (blocks own instructions, instructions point back at their block and at
//! the hash entries their n-grams belong to, hash entries list instructions) is owned here by the
//! store as two arenas: `blocks` (named by [`CorrelateBlockId`]) and `entries` (named by
//! [`CorrelateHashEntryId`]). Java drops a `HashEntry` once nothing references it; the arena
//! instead keeps every entry's slot until [`clear_sort`](HashStore::clear_sort), which is
//! behaviorally the same, since a dropped entry is by then unreachable from the sort structures.
//!
//! # Construction
//!
//! Java's constructor, `HashStore(Function, TaskMonitor)`, builds the basic blocks itself with
//! `new BasicBlockModel(program).getCodeBlocksContaining(function.getBody(), monitor)` and reads
//! each block's instructions from `program.getListing()`. Here the caller supplies those two
//! inputs -- the function body's basic blocks and the program's listing -- and
//! [`HashStore::new`] performs the rest of Java's construction (`createBlock` for each block)
//! unchanged. The `Function` and `Program` Java keeps in fields are never read after
//! construction, so they are not stored.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::block::CodeBlock;
use crate::program::model::listing::{Instruction, Listing};
use crate::program::model::mem::MemoryAccessException;
use crate::util::task::TaskMonitor;

use super::block::{Block, CorrelateBlockId};
use super::hash::Hash;
use super::hash_calculator::HashCalculator;
use super::hash_entry::{CorrelateHashEntryId, HashEntry, InstructHashRef};
use super::instruct_hash::InstructHash;

/// Explicitly labels (one side of) a matching n-gram pair.
///
/// Port of `HashStore.NgramMatch`. Java default-constructs it with a `null` block; here the block
/// defaults to the first arena slot, and [`HashStore::extend_match`] sets every field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NgramMatch {
    /// The block in which the n-gram match occurs.
    pub block: CorrelateBlockId,
    /// Index of the first instruction in the match.
    pub startindex: usize,
    /// Index of the last instruction in the match.
    pub endindex: usize,
}

/// The position of a [`HashEntry`] in the main matching sort.
///
/// Port of `HashStore.HashOrderComparator`: sort first preferring the smallest number of
/// duplicate n-grams, then prefer the bigger (more significant) n-gram, then order by hash value
/// (as signed integers, Java's `Long.compare` of two widened `int`s).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MatchKey {
    count: usize,
    size: std::cmp::Reverse<i32>,
    value: i32,
}

impl MatchKey {
    fn of(entry: &HashEntry) -> Self {
        Self {
            count: entry.inst_list.len(),
            size: std::cmp::Reverse(entry.hash.size),
            value: entry.hash.value,
        }
    }
}

/// A sorted, basic-block aware store of instruction n-gram hashes for one function.
///
/// Port of `ghidra.program.model.correlate.HashStore`.
pub struct HashStore {
    monitor: Arc<dyn TaskMonitor>,
    /// Arena of every block created, indexed by [`CorrelateBlockId`].
    blocks: Vec<Block>,
    /// All blocks for the function, by start address. Java: `blockList`.
    block_list: BTreeMap<Address, CorrelateBlockId>,
    /// Arena of every hash entry created since the last [`clear_sort`](Self::clear_sort).
    entries: Vec<HashEntry>,
    /// Hash entries, sorted by hash. Java: `hashSort`.
    hash_sort: BTreeMap<Hash, CorrelateHashEntryId>,
    /// The same entries, in preferred order for the matching strategy. Java: `matchSort`, a
    /// `TreeSet` under `HashOrderComparator`; the key is the comparator's view of the entry.
    match_sort: BTreeMap<MatchKey, CorrelateHashEntryId>,
    /// Count of blocks that have been matched.
    matched_block_count: i32,
    /// Count of instructions that have been matched so far.
    matched_instruction_count: i32,
    /// Total number of instructions in the function.
    total_instructions: i32,
}

impl HashStore {
    /// Build the store for a function from its basic blocks.
    ///
    /// * `code_blocks` -- the basic blocks of the function's body (Java:
    ///   `new BasicBlockModel(program).getCodeBlocksContaining(function.getBody(), monitor)`)
    /// * `listing` -- the listing of the function's program, used to find each block's
    ///   instructions
    /// * `monitor` -- the task monitor, handed to disambiguation strategies via
    ///   [`get_monitor`](Self::get_monitor)
    ///
    /// Port of `HashStore(Function, TaskMonitor)`; see the module docs for why the blocks and
    /// listing are arguments.
    pub fn new(
        code_blocks: impl IntoIterator<Item = Box<dyn CodeBlock>>,
        listing: &dyn Listing,
        monitor: Arc<dyn TaskMonitor>,
    ) -> Self {
        let mut store = Self {
            monitor,
            blocks: Vec::new(),
            block_list: BTreeMap::new(),
            entries: Vec::new(),
            hash_sort: BTreeMap::new(),
            match_sort: BTreeMap::new(),
            matched_block_count: 0,
            matched_instruction_count: 0,
            total_instructions: 0,
        };
        for code_block in code_blocks {
            store.create_block(code_block, listing);
        }
        store
    }

    /// Total number of instructions in the whole function.
    ///
    /// Port of `getTotalInstructions()`.
    pub fn get_total_instructions(&self) -> i32 {
        self.total_instructions
    }

    /// Number of instructions that have been matched so far.
    ///
    /// Port of `numMatchedInstructions()`.
    pub fn num_matched_instructions(&self) -> i32 {
        self.matched_instruction_count
    }

    /// Create the basic [`Block`] structure, walking the instructions and creating
    /// [`InstructHash`] structures.
    ///
    /// Port of `createBlock(CodeBlock)`. Java's `Address.add`/`next` throw on running off the end
    /// of the address space; here that ends the walk of the current range.
    fn create_block(&mut self, code_block: Box<dyn CodeBlock>, listing: &dyn Listing) {
        let id = CorrelateBlockId(self.blocks.len() as u32);
        let start = code_block.get_first_start_address();
        let mut inst_list = Vec::new();
        let mut index = 0;
        for range in code_block.address_ranges_ordered(true) {
            let mut cur = range.min_address().clone();
            let max = range.max_address();
            while cur <= *max {
                // Inclusive of final address
                let next = match listing.get_instruction_at(&cur) {
                    Some(instruct) => {
                        let length = instruct.get_length();
                        inst_list.push(InstructHash::new(instruct, id, index));
                        index += 1;
                        self.total_instructions += 1;
                        cur.add(length as i64)
                    }
                    None => cur.next(),
                };
                match next {
                    Ok(next) => cur = next,
                    Err(_) => break,
                }
            }
        }
        let mut res = Block::new(code_block);
        res.inst_list = inst_list;
        self.blocks.push(res);
        self.block_list.insert(start, id);
    }

    /// The instruction a reference names.
    pub fn instruct_hash(&self, inst: InstructHashRef) -> &InstructHash {
        inst.resolve(&self.blocks)
    }

    fn instruct_hash_mut(&mut self, inst: InstructHashRef) -> &mut InstructHash {
        &mut self.blocks[inst.block.index()].inst_list[inst.index]
    }

    /// The block a handle names.
    pub fn block(&self, id: CorrelateBlockId) -> &Block {
        &self.blocks[id.index()]
    }

    /// The hash entry a handle names.
    pub fn hash_entry(&self, id: CorrelateHashEntryId) -> &HashEntry {
        &self.entries[id.index()]
    }

    /// Whether any two n-grams of the given entry share the same parent block.
    ///
    /// Runs [`HashEntry::has_duplicate_blocks`] against this store's blocks.
    pub fn has_duplicate_blocks(&mut self, id: CorrelateHashEntryId) -> bool {
        self.entries[id.index()].has_duplicate_blocks(&mut self.blocks)
    }

    /// Remove `inst` from the given entry's list, updating both sort structures. The entry must
    /// already have been removed from `match_sort`.
    fn detach_from_entry(&mut self, id: CorrelateHashEntryId, cur_hash: &Hash, inst: InstructHashRef) {
        let entry = &mut self.entries[id.index()];
        if let Some(pos) = entry.inst_list.iter().position(|i| *i == inst) {
            entry.inst_list.remove(pos);
        }
        if entry.inst_list.is_empty() {
            self.hash_sort.remove(cur_hash);
        } else {
            // Now that the list is updated, reinsert
            let key = MatchKey::of(entry);
            self.match_sort.entry(key).or_insert(id);
        }
    }

    /// Low level insert of an n-gram into the store.
    ///
    /// Port of `insertNGram(Hash, InstructHash)`.
    fn insert_n_gram(&mut self, cur_hash: Hash, inst: InstructHashRef) {
        let id = match self.hash_sort.get(&cur_hash) {
            Some(&id) => {
                // Remove old entry, so we can affect its sort position
                self.match_sort.remove(&MatchKey::of(&self.entries[id.index()]));
                id
            }
            None => {
                let id = CorrelateHashEntryId(self.entries.len() as u32);
                self.entries.push(HashEntry::new(cur_hash));
                self.hash_sort.insert(cur_hash, id);
                id
            }
        };
        self.entries[id.index()].inst_list.push(inst);
        self.instruct_hash_mut(inst).hash_entries.insert(cur_hash, id);
        let key = MatchKey::of(&self.entries[id.index()]);
        self.match_sort.entry(key).or_insert(id); // (Re)insert the hash into the sort
    }

    /// Insert all n-gram hashes for a particular instruction.
    ///
    /// Port of `insertInstructionNGrams(InstructHash)`.
    fn insert_instruction_n_grams(&mut self, inst: InstructHashRef) {
        let n_grams = self.instruct_hash(inst).n_grams.clone().expect("n-grams have not been calculated");
        for cur_hash in n_grams {
            let Some(cur_hash) = cur_hash else { break };
            self.insert_n_gram(cur_hash, inst);
        }
    }

    /// Low level removal of a particular n-gram from the sort.
    ///
    /// Port of `removeNGram(InstructHash, Hash)`.
    fn remove_n_gram(&mut self, inst: InstructHashRef, cur_hash: &Hash) {
        let id = self
            .instruct_hash_mut(inst)
            .hash_entries
            .remove(cur_hash)
            .expect("n-gram is not in the store");
        // Remove from match_sort before modifying the list
        self.match_sort.remove(&MatchKey::of(&self.entries[id.index()]));
        self.detach_from_entry(id, cur_hash, inst);
    }

    /// Remove all n-grams associated with a particular instruction.
    ///
    /// Port of `removeInstructionNGrams(InstructHash)`. As in Java, the instruction's own
    /// cross-reference table is left as is.
    fn remove_instruction_n_grams(&mut self, inst: InstructHashRef) {
        let inst_hash = self.instruct_hash(inst);
        let n_grams = inst_hash.n_grams.clone().expect("n-grams have not been calculated");
        for cur_hash in n_grams.into_iter().flatten() {
            let Some(&id) = self.instruct_hash(inst).hash_entries.get(&cur_hash) else {
                continue;
            };
            // Remove from match_sort before modifying the list
            self.match_sort.remove(&MatchKey::of(&self.entries[id.index()]));
            self.detach_from_entry(id, &cur_hash, inst);
        }
    }

    /// Remove a particular hash entry. This may affect multiple instructions.
    ///
    /// Port of `removeHash(HashEntry)`.
    pub fn remove_hash(&mut self, id: CorrelateHashEntryId) {
        let entry = &self.entries[id.index()];
        let hash = entry.hash;
        self.match_sort.remove(&MatchKey::of(entry));
        self.hash_sort.remove(&hash);
        let insts = entry.inst_list.clone();
        for inst in insts {
            self.instruct_hash_mut(inst).hash_entries.remove(&hash);
        }
    }

    /// Calculate hashes for all blocks.
    ///
    /// * `min_length` -- the minimum length of an n-gram for these passes
    /// * `max_length` -- the maximum length of an n-gram for these passes
    /// * `whole_block` -- allows blocks that are smaller than the minimum length to be considered
    ///   as 1 n-gram
    /// * `match_only` -- only generates n-grams for sequences in previously matched blocks
    /// * `hash_calc` -- the hash function
    ///
    /// Port of `calcHashes(int, int, boolean, boolean, HashCalculator)`.
    pub fn calc_hashes(
        &mut self,
        min_length: usize,
        max_length: usize,
        whole_block: bool,
        match_only: bool,
        hash_calc: &dyn HashCalculator,
    ) -> Result<(), MemoryAccessException> {
        for &id in self.block_list.values() {
            self.blocks[id.index()].calc_hashes(min_length, max_length, whole_block, match_only, hash_calc)?;
        }
        Ok(())
    }

    /// Insert all hashes associated with unknown (i.e. not matched) blocks and instructions.
    ///
    /// Port of `insertHashes()`.
    pub fn insert_hashes(&mut self) {
        let ids: Vec<CorrelateBlockId> = self.block_list.values().copied().collect();
        for id in ids {
            for index in 0..self.blocks[id.index()].inst_list.len() {
                let inst = InstructHashRef { block: id, index };
                if self.instruct_hash(inst).is_matched {
                    continue;
                }
                self.insert_instruction_n_grams(inst);
            }
        }
    }

    /// Mark a particular n-gram hash and instruction as having a match. The set of instructions
    /// covered by the n-gram are removed, and data structures are updated.
    ///
    /// * `m` -- the n-gram being declared as a match
    /// * `inst_result` -- collects the explicit set of instructions matched
    /// * `block_result` -- collects the explicit set of blocks matched. Java collects each
    ///   block's `CodeBlock`; the store owns those, so this collects the block handles, whose
    ///   [`Block::orig_block`] is that `CodeBlock`.
    ///
    /// Port of `matchHash(NgramMatch, List<Instruction>, List<CodeBlock>)`.
    pub fn match_hash(
        &mut self,
        m: &NgramMatch,
        inst_result: &mut Vec<Arc<dyn Instruction>>,
        block_result: &mut Vec<CorrelateBlockId>,
    ) {
        let block_id = m.block;
        for index in m.startindex..=m.endindex {
            // For every instruction involved in this n-gram
            let inst = InstructHashRef { block: block_id, index };
            let cur = self.instruct_hash_mut(inst);
            inst_result.push(Arc::clone(&cur.instruction)); // Store match explicitly
            cur.is_matched = true;
            self.matched_instruction_count += 1;
            self.remove_instruction_n_grams(inst);
            self.instruct_hash_mut(inst).n_grams = None; // Free up memory we won't use anymore
        }
        if self.blocks[block_id.index()].is_matched {
            return; // Not the first time we matched this block
        }
        self.matched_block_count += 1;
        let block = &mut self.blocks[block_id.index()];
        block.set_matched(self.matched_block_count);
        let match_hash = block.get_match_hash();
        block_result.push(block_id);
        for i in 0..block.inst_list.len() {
            let inst = InstructHashRef { block: block_id, index: i };
            let cur = self.instruct_hash(inst);
            if cur.is_matched {
                continue; // For each remaining unknown instruction
            }
            let num = cur.n_grams.as_ref().expect("n-grams have not been calculated").len();
            for j in 0..num {
                let cur = self.instruct_hash(inst);
                let Some(cur_hash) = cur.n_grams.as_ref().expect("n-grams present")[j] else {
                    continue;
                };
                if !cur.hash_entries.contains_key(&cur_hash) {
                    continue; // Only hashes still in the pool
                }
                self.remove_n_gram(inst, &cur_hash); // Remove from the store
                // Update hash to reflect matched block
                let new_hash = Hash::new(cur_hash.value ^ match_hash, cur_hash.size);
                self.instruct_hash_mut(inst).n_grams.as_mut().expect("n-grams present")[j] = Some(new_hash);
                self.insert_n_gram(new_hash, inst); // Reinsert the hash
            }
        }
    }

    /// Try to extend a match on a pair of n-grams to the instructions right before and right
    /// after the n-grams. The match is extended if the instruction adjacent to the n-gram, and its
    /// corresponding pair on the other side, hash to the same value using the hash function. The
    /// [`NgramMatch`] objects are updated to reflect the original n-gram match plus any additional
    /// extension.
    ///
    /// * `n_gram_size` -- the original size of the matching n-gram
    /// * `src_store`, `src_instruct` -- the first instruction in the "source" n-gram, and the
    ///   store owning it
    /// * `src_match` -- the "source" [`NgramMatch`] to populate
    /// * `dest_store`, `dest_instruct` -- the first instruction in the "destination" n-gram, and
    ///   the store owning it
    /// * `dest_match` -- the "destination" [`NgramMatch`] to populate
    /// * `hash_calc` -- the hash function
    ///
    /// Port of the static `extendMatch(int, InstructHash, NgramMatch, InstructHash, NgramMatch,
    /// HashCalculator)`. Java reaches each instruction's block through the instruction itself;
    /// here the blocks live in the stores, so the stores are passed alongside.
    #[allow(clippy::too_many_arguments)]
    pub fn extend_match(
        n_gram_size: usize,
        src_store: &HashStore,
        src_instruct: &InstructHash,
        src_match: &mut NgramMatch,
        dest_store: &HashStore,
        dest_instruct: &InstructHash,
        dest_match: &mut NgramMatch,
        hash_calc: &dyn HashCalculator,
    ) -> Result<(), MemoryAccessException> {
        src_match.block = src_instruct.block;
        src_match.startindex = src_instruct.index;
        src_match.endindex = src_match.startindex + n_gram_size - 1;
        dest_match.block = dest_instruct.block;
        dest_match.startindex = dest_instruct.index;
        dest_match.endindex = dest_match.startindex + n_gram_size - 1;
        let src_list = &src_store.block(src_match.block).inst_list;
        let dest_list = &dest_store.block(dest_match.block).inst_list;
        let same = |src: &InstructHash, dest: &InstructHash| -> Result<bool, MemoryAccessException> {
            if src.is_matched || dest.is_matched {
                return Ok(false); // If instruction already matched, can't extend
            }
            let src_val = hash_calc.calc_hash(Hash::ALTERNATE_SEED, src.instruction.as_ref())?;
            let dest_val = hash_calc.calc_hash(Hash::ALTERNATE_SEED, dest.instruction.as_ref())?;
            Ok(src_val == dest_val) // If they differ, we can't extend
        };
        // Try to extend to earlier instructions (can't go past beginning of block)
        while src_match.startindex > 0 && dest_match.startindex > 0 {
            if !same(&src_list[src_match.startindex - 1], &dest_list[dest_match.startindex - 1])? {
                break;
            }
            src_match.startindex -= 1;
            dest_match.startindex -= 1;
        }
        // Try to extend to later instructions (can't go past end of block)
        let src_max = src_list.len() - 1;
        let dest_max = dest_list.len() - 1;
        while src_match.endindex < src_max && dest_match.endindex < dest_max {
            if !same(&src_list[src_match.endindex + 1], &dest_list[dest_match.endindex + 1])? {
                break;
            }
            src_match.endindex += 1;
            dest_match.endindex += 1;
        }
        Ok(())
    }

    /// Unmatched instructions across the whole function, in block address order.
    ///
    /// Port of `getUnmatchedInstructions()`.
    pub fn get_unmatched_instructions(&self) -> Vec<Arc<dyn Instruction>> {
        self.block_list
            .values()
            .flat_map(|id| self.blocks[id.index()].inst_list.iter())
            .filter(|inst| !inst.is_matched)
            .map(|inst| Arc::clone(&inst.instruction))
            .collect()
    }

    /// Clear the main sort structures, but preserve blocks and instructions.
    ///
    /// Port of `clearSort()`. This also releases every hash entry, which the cleared structures
    /// were the last to reference.
    pub fn clear_sort(&mut self) {
        self.hash_sort.clear();
        self.match_sort.clear();
        self.entries.clear();
        for &id in self.block_list.values() {
            self.blocks[id.index()].clear_sort();
        }
    }

    /// True if there are no n-grams left in the sort.
    ///
    /// Port of `isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.match_sort.is_empty()
    }

    /// The first entry in the sort: the least number of matching n-grams and the biggest n-gram.
    /// `None` if the sort is empty (Java throws `NoSuchElementException`).
    ///
    /// Port of `getFirstEntry()`.
    pub fn get_first_entry(&self) -> Option<CorrelateHashEntryId> {
        self.match_sort.values().next().copied()
    }

    /// The entry (set of n-grams) matching the given hash, if any.
    ///
    /// Port of `getEntry(Hash)`.
    pub fn get_entry(&self, hash: &Hash) -> Option<CorrelateHashEntryId> {
        self.hash_sort.get(hash).copied()
    }

    /// The basic block with the given start address, if any.
    ///
    /// Port of `getBlock(Address)`.
    pub fn get_block(&self, addr: &Address) -> Option<&Block> {
        self.block_list.get(addr).map(|id| &self.blocks[id.index()])
    }

    /// The task monitor for this store.
    ///
    /// Port of `getMonitor()`.
    pub fn get_monitor(&self) -> &dyn TaskMonitor {
        self.monitor.as_ref()
    }
}

impl std::fmt::Debug for HashStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashStore")
            .field("blocks", &self.blocks)
            .field("block_list", &self.block_list)
            .field("entries", &self.entries)
            .field("hash_sort", &self.hash_sort)
            .field("matched_block_count", &self.matched_block_count)
            .field("matched_instruction_count", &self.matched_instruction_count)
            .field("total_instructions", &self.total_instructions)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::correlate::test_support::{addr, TestBlock, TestInst, TestListing};
    use crate::program::model::correlate::MnemonicHashCalculator;
    use crate::util::task::DummyMonitor;

    fn chain(seed: i32, mnemonics: &[&str]) -> i32 {
        mnemonics.iter().fold(seed, |acc, m| {
            let inst = TestInst { address: addr(0), length: 4, mnemonic: m.to_string() };
            MnemonicHashCalculator.calc_hash(acc, &inst as &dyn Instruction).unwrap()
        })
    }

    fn alt(mnemonics: &[&str]) -> Hash {
        Hash::new(chain(Hash::ALTERNATE_SEED, mnemonics), mnemonics.len() as i32)
    }

    fn offsets(insts: &[Arc<dyn Instruction>]) -> Vec<i64> {
        insts.iter().map(|i| i.get_min_address().offset()).collect()
    }

    /// Blocks A (0x1000: MOV ADD SUB) and B (0x2000: MOV ADD JMP), supplied B first.
    fn two_block_store() -> HashStore {
        let mut listing = TestListing::default();
        listing.place(0x1000, 4, &["MOV", "ADD", "SUB"]);
        listing.place(0x2000, 4, &["MOV", "ADD", "JMP"]);
        HashStore::new(
            vec![TestBlock::boxed(&[(0x2000, 0x200b)]), TestBlock::boxed(&[(0x1000, 0x100b)])],
            &listing,
            Arc::new(DummyMonitor),
        )
    }

    fn block_id(store: &HashStore, start: i64) -> CorrelateBlockId {
        store.block_list[&addr(start)]
    }

    fn inst_ref(store: &HashStore, start: i64, index: usize) -> InstructHashRef {
        InstructHashRef { block: block_id(store, start), index }
    }

    #[test]
    fn construction_models_each_blocks_instructions_in_address_order() {
        let mut listing = TestListing::default();
        listing.place(0x1000, 4, &["MOV", "ADD"]);
        // A block spanning two ranges, with undefined bytes before its first instruction.
        listing.place(0x3002, 2, &["PUSH"]);
        listing.place(0x3004, 4, &["POP"]);
        listing.place(0x3100, 4, &["RET"]);
        let store = HashStore::new(
            vec![TestBlock::boxed(&[(0x3000, 0x3007), (0x3100, 0x3103)]), TestBlock::boxed(&[(0x1000, 0x1007)])],
            &listing,
            Arc::new(DummyMonitor),
        );

        assert_eq!(store.get_total_instructions(), 5);
        assert_eq!(store.num_matched_instructions(), 0);
        let c = store.get_block(&addr(0x3000)).expect("block at 0x3000");
        let names: Vec<String> = c.inst_list.iter().map(|i| i.instruction.get_mnemonic_string()).collect();
        assert_eq!(names, vec!["PUSH", "POP", "RET"]);
        assert_eq!(c.inst_list.iter().map(|i| i.index).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert!(store.get_block(&addr(0x3002)).is_none());
        // Unmatched instructions come block by block in start-address order.
        assert_eq!(
            offsets(&store.get_unmatched_instructions()),
            vec![0x1000, 0x1004, 0x3002, 0x3004, 0x3100]
        );
        assert!(store.is_empty());
        assert!(store.get_first_entry().is_none());
        assert!(!store.get_monitor().is_cancelled());
    }

    #[test]
    fn inserted_hashes_cross_reference_instructions_and_entries() {
        let mut store = two_block_store();
        store.calc_hashes(2, 2, false, false, &MnemonicHashCalculator).unwrap();
        store.insert_hashes();

        let shared = store.get_entry(&alt(&["MOV", "ADD"])).expect("MOV ADD entry");
        // Blocks are walked in address order, so A's n-gram is listed first.
        assert_eq!(
            store.hash_entry(shared).inst_list,
            vec![inst_ref(&store, 0x1000, 0), inst_ref(&store, 0x2000, 0)]
        );
        assert_eq!(store.instruct_hash(inst_ref(&store, 0x2000, 0)).hash_entries[&alt(&["MOV", "ADD"])], shared);
        assert!(!store.has_duplicate_blocks(shared));
        assert!(store.get_entry(&alt(&["ADD", "SUB"])).is_some());
        assert!(store.get_entry(&alt(&["ADD", "JMP"])).is_some());
        assert!(store.get_entry(&alt(&["SUB", "JMP"])).is_none());
        assert!(!store.is_empty());
    }

    #[test]
    fn the_sort_prefers_fewer_duplicates_then_bigger_n_grams_then_smaller_values() {
        // X and Y are identical, so each of their hashes has two n-grams; Z's is unique.
        let mut listing = TestListing::default();
        listing.place(0x1000, 4, &["P", "Q", "R"]);
        listing.place(0x2000, 4, &["P", "Q", "R"]);
        listing.place(0x3000, 4, &["S", "T"]);
        let mut store = HashStore::new(
            vec![
                TestBlock::boxed(&[(0x1000, 0x100b)]),
                TestBlock::boxed(&[(0x2000, 0x200b)]),
                TestBlock::boxed(&[(0x3000, 0x3007)]),
            ],
            &listing,
            Arc::new(DummyMonitor),
        );
        store.calc_hashes(2, 3, false, false, &MnemonicHashCalculator).unwrap();
        store.insert_hashes();

        let mut order = Vec::new();
        while let Some(id) = store.get_first_entry() {
            let entry = store.hash_entry(id);
            order.push((entry.inst_list.len(), entry.hash));
            store.remove_hash(id);
        }
        let (pq, qr) = (alt(&["P", "Q"]), alt(&["Q", "R"]));
        let (first2, second2) = if pq.value < qr.value { (pq, qr) } else { (qr, pq) };
        assert_eq!(
            order,
            vec![(1, alt(&["S", "T"])), (2, alt(&["P", "Q", "R"])), (2, first2), (2, second2)]
        );
        assert!(store.is_empty());
    }

    #[test]
    fn remove_hash_drops_the_entry_and_its_cross_references() {
        let mut store = two_block_store();
        store.calc_hashes(2, 2, false, false, &MnemonicHashCalculator).unwrap();
        store.insert_hashes();
        let id = store.get_entry(&alt(&["MOV", "ADD"])).unwrap();

        store.remove_hash(id);

        assert!(store.get_entry(&alt(&["MOV", "ADD"])).is_none());
        assert!(store.instruct_hash(inst_ref(&store, 0x1000, 0)).hash_entries.is_empty());
        assert!(store.instruct_hash(inst_ref(&store, 0x2000, 0)).hash_entries.is_empty());
        // The two unique n-grams remain.
        let first = store.get_first_entry().unwrap();
        assert_eq!(store.hash_entry(first).inst_list.len(), 1);
    }

    #[test]
    fn match_hash_consumes_the_n_gram_and_rekeys_the_rest_of_the_block() {
        let mut store = two_block_store();
        store.calc_hashes(2, 2, false, false, &MnemonicHashCalculator).unwrap();
        store.insert_hashes();
        let a = block_id(&store, 0x1000);

        let mut insts = Vec::new();
        let mut blocks = Vec::new();
        store.match_hash(&NgramMatch { block: a, startindex: 1, endindex: 2 }, &mut insts, &mut blocks);

        assert_eq!(offsets(&insts), vec![0x1004, 0x1008]);
        assert_eq!(blocks, vec![a]);
        assert_eq!(store.num_matched_instructions(), 2);
        assert!(store.block(a).is_matched);
        assert_eq!(store.block(a).get_match_hash(), 39_545_130);
        assert!(store.instruct_hash(inst_ref(&store, 0x1000, 1)).n_grams.is_none());
        // ADD SUB's only n-gram is gone, and with it the entry.
        assert!(store.get_entry(&alt(&["ADD", "SUB"])).is_none());
        // A's remaining MOV ADD n-gram is re-keyed by the block's match hash, so it can only pair
        // with an n-gram of the matching block on the other side.
        let rekeyed = Hash::new(alt(&["MOV", "ADD"]).value ^ 39_545_130, 2);
        assert_eq!(store.instruct_hash(inst_ref(&store, 0x1000, 0)).n_grams, Some(vec![Some(rekeyed)]));
        let id = store.get_entry(&rekeyed).expect("re-keyed entry");
        assert_eq!(store.hash_entry(id).inst_list, vec![inst_ref(&store, 0x1000, 0)]);
        let id = store.get_entry(&alt(&["MOV", "ADD"])).expect("B's entry");
        assert_eq!(store.hash_entry(id).inst_list, vec![inst_ref(&store, 0x2000, 0)]);
        assert_eq!(offsets(&store.get_unmatched_instructions()), vec![0x1000, 0x2000, 0x2004, 0x2008]);

        // A second match in an already-matched block matches instructions but not the block.
        let mut blocks = Vec::new();
        store.match_hash(&NgramMatch { block: a, startindex: 0, endindex: 0 }, &mut insts, &mut blocks);
        assert!(blocks.is_empty());
        assert_eq!(store.num_matched_instructions(), 3);
        assert_eq!(store.block(a).get_match_hash(), 39_545_130);
        assert!(store.get_entry(&rekeyed).is_none());

        // The next newly matched block gets the next index.
        let b = block_id(&store, 0x2000);
        store.match_hash(&NgramMatch { block: b, startindex: 2, endindex: 2 }, &mut insts, &mut blocks);
        assert_eq!(blocks, vec![b]);
        assert_eq!(store.block(b).get_match_hash(), 76_693_159);
    }

    #[test]
    fn clear_sort_empties_the_sort_but_keeps_blocks_and_instructions() {
        let mut store = two_block_store();
        store.calc_hashes(2, 2, false, false, &MnemonicHashCalculator).unwrap();
        store.insert_hashes();

        store.clear_sort();

        assert!(store.is_empty());
        assert!(store.get_entry(&alt(&["MOV", "ADD"])).is_none());
        assert!(store.instruct_hash(inst_ref(&store, 0x1000, 0)).hash_entries.is_empty());
        assert_eq!(store.get_total_instructions(), 6);

        // A new pass can be built from scratch.
        store.calc_hashes(3, 3, false, false, &MnemonicHashCalculator).unwrap();
        store.insert_hashes();
        assert!(store.get_entry(&alt(&["MOV", "ADD", "SUB"])).is_some());
    }

    fn single_block_store(mnemonics: &[&str]) -> HashStore {
        let mut listing = TestListing::default();
        listing.place(0x1000, 4, mnemonics);
        HashStore::new(
            vec![TestBlock::boxed(&[(0x1000, 0x1000 + 4 * mnemonics.len() as i64 - 1)])],
            &listing,
            Arc::new(DummyMonitor),
        )
    }

    #[test]
    fn extend_match_grows_the_pair_while_neighbours_hash_alike() {
        let src = single_block_store(&["A", "B", "C", "D"]);
        let dest = single_block_store(&["A", "B", "C", "E"]);
        let (mut sm, mut dm) = (NgramMatch::default(), NgramMatch::default());

        HashStore::extend_match(
            2,
            &src,
            src.instruct_hash(inst_ref(&src, 0x1000, 1)),
            &mut sm,
            &dest,
            dest.instruct_hash(inst_ref(&dest, 0x1000, 1)),
            &mut dm,
            &MnemonicHashCalculator,
        )
        .unwrap();

        // A matches A before the n-gram; D differs from E after it.
        assert_eq!(sm, NgramMatch { block: block_id(&src, 0x1000), startindex: 0, endindex: 2 });
        assert_eq!(dm, NgramMatch { block: block_id(&dest, 0x1000), startindex: 0, endindex: 2 });
    }

    #[test]
    fn extend_match_stops_at_matched_instructions() {
        let mut src = single_block_store(&["A", "B", "C", "D"]);
        let dest = single_block_store(&["A", "B", "C", "D"]);
        src.instruct_hash_mut(inst_ref(&src, 0x1000, 0)).is_matched = true;
        let (mut sm, mut dm) = (NgramMatch::default(), NgramMatch::default());

        HashStore::extend_match(
            2,
            &src,
            src.instruct_hash(inst_ref(&src, 0x1000, 1)),
            &mut sm,
            &dest,
            dest.instruct_hash(inst_ref(&dest, 0x1000, 1)),
            &mut dm,
            &MnemonicHashCalculator,
        )
        .unwrap();

        assert_eq!((sm.startindex, sm.endindex), (1, 3));
        assert_eq!((dm.startindex, dm.endindex), (1, 3));
    }

    #[test]
    fn has_duplicate_blocks_sees_repeats_within_one_block() {
        let mut store = single_block_store(&["A", "B", "A", "B"]);
        store.calc_hashes(2, 2, false, false, &MnemonicHashCalculator).unwrap();
        store.insert_hashes();
        let id = store.get_entry(&alt(&["A", "B"])).unwrap();
        assert_eq!(store.hash_entry(id).inst_list.len(), 2);
        assert!(store.has_duplicate_blocks(id));
        assert!(store.blocks.iter().all(|b| !b.is_visited));
    }
}
