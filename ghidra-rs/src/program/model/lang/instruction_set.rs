//! Port of `ghidra.program.model.lang.InstructionSet`.
//!
//! A set of instructions organized as a graph of basic blocks: the
//! [`InstructionBlock`]s the disassembler produced, keyed by start address, with the branch and
//! fall-through flows between them.
//!
//! # Shape
//!
//! Java's blocks are shared objects that the disassembler keeps mutating after they join the set
//! (it resumes a block after a delay slot, records how many of its instructions were added, and
//! marks conflicts the set's iterator must then respect). That is a graph of mutable nodes, so
//! the set is an arena (decision 2026-09-24, `OWNERSHIP_MIGRATION.md`): it owns its blocks and
//! hands out [`BlockId`]s, and the block iterator is a detached cursor ([`BlockIterator`]) that
//! takes the set as a call-time argument, so a caller can mark a block between steps exactly as
//! Java's iterator allows ("if the last block returned from the iterator is marked as a conflict
//! before the next call, then this iterator will respect the conflict").

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;

use crate::program::database::register::address_range_object_map::AddressRangeObjectMap;
use crate::program::model::address::{Address, AddressFactory, AddressSet, AddressSetView};
use crate::program::model::lang::instruction_block::InstructionBlock;
use crate::program::model::lang::instruction_error::InstructionError;

/// Identifies a block of one [`InstructionSet`]: the Java object reference, as an arena index.
/// Only meaningful for the set that issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId(usize);

/// A set of instructions organized as a graph of basic blocks.
///
/// Port of `ghidra.program.model.lang.InstructionSet`; see the module docs.
pub struct InstructionSet<I> {
    /// Every block ever added, empty ones included; a [`BlockId`] indexes this.
    blocks: Vec<InstructionBlock<I>>,
    block_map: HashMap<Address, BlockId>,
    block_range_map: AddressRangeObjectMap<BlockId>,
    start_addresses: HashSet<Address>,
    empty_blocks: Vec<BlockId>,
    address_set: AddressSet,
    instruction_count: usize,
}

impl<I> InstructionSet<I> {
    /// Construct a new, empty `InstructionSet`.
    ///
    /// Java quirk faithfully reproduced: the `AddressFactory` constructor parameter is unused by
    /// `InstructionSet`'s constructor body (`addressSet = new AddressSet();` is the only
    /// statement) -- kept here, unused, for call-site signature fidelity.
    pub fn new(_addr_factory: &dyn AddressFactory) -> Self {
        InstructionSet {
            blocks: Vec::new(),
            block_map: HashMap::new(),
            block_range_map: AddressRangeObjectMap::new(),
            start_addresses: HashSet::new(),
            empty_blocks: Vec::new(),
            address_set: AddressSet::new(),
            instruction_count: 0,
        }
    }

    /// Add an instruction block to this instruction set, returning its id.
    ///
    /// If the block is empty it will only be added to the empty-list and will not be added to the
    /// maps or block iterator.
    ///
    /// # Panics
    /// If a block already exists in this set with the same start address (Java's
    /// `AssertException`: "More than one block exists with the same start address"). Java
    /// tolerates re-adding the *same* block object; a block moved into the arena cannot be added
    /// twice.
    pub fn add_block(&mut self, block: InstructionBlock<I>) -> BlockId {
        let id = BlockId(self.blocks.len());
        if block.is_empty() {
            // multiple empty blocks at the same address are possible
            self.blocks.push(block);
            self.empty_blocks.push(id);
            return id;
        }

        let is_start = block.is_flow_start()
            || match block.get_flow_from_address() {
                Some(flow_from) => self.block_range_map.get_object(&flow_from).is_none(),
                None => true,
            };
        if is_start {
            self.start_addresses.insert(block.get_start_address());
        }

        let start_addr = block.get_start_address();
        let max_addr = block.get_max_address();
        if self.block_map.contains_key(&start_addr) {
            panic!("More than one block exists with the same start address");
        }
        self.block_map.insert(start_addr.clone(), id);

        self.address_set.add_range(&start_addr, &max_addr);
        self.instruction_count += block.get_instruction_count();
        self.block_range_map.set_object(start_addr, max_addr, id);
        self.blocks.push(block);
        id
    }

    /// The block with the given id.
    ///
    /// # Panics
    /// If `id` was not issued by this set.
    pub fn block(&self, id: BlockId) -> &InstructionBlock<I> {
        &self.blocks[id.0]
    }

    /// The block with the given id, for marking conflicts, flow-from addresses and added counts
    /// after it joined the set. Its address range must not change.
    ///
    /// # Panics
    /// If `id` was not issued by this set.
    pub fn block_mut(&mut self, id: BlockId) -> &mut InstructionBlock<I> {
        &mut self.blocks[id.0]
    }

    /// The id of the non-empty block containing the specified address, else of an (empty) block
    /// starting there, or `None` if not found.
    pub fn get_instruction_block_containing(&self, address: &Address) -> Option<BlockId> {
        if let Some(id) = self.block_range_map.get_object(address) {
            return Some(id);
        }
        // try returning an empty block if one exists
        self.block_map.get(address).copied()
    }

    /// Find the first block within this `InstructionSet` which intersects the specified range.
    /// This method should be used sparingly since it uses a brute-force search. Returns `None` if
    /// no block within this `InstructionSet` intersects the range.
    ///
    /// Like Java's `HashMap` iteration order, this crate's `HashMap` iteration order is
    /// unspecified; since block start addresses are unique, the result does not depend on it.
    pub fn find_first_intersecting_block(&self, min: &Address, max: &Address) -> Option<BlockId> {
        let mut intersect_block: Option<BlockId> = None;
        for &id in self.block_map.values() {
            let block = self.block(id);
            let block_min = block.get_start_address();
            if block_min > *max {
                continue;
            }
            let block_max = block.get_max_address();
            if block_max < *min {
                continue;
            }
            if let Some(current) = intersect_block {
                if self.block(current).get_start_address() < block_min {
                    continue;
                }
            }
            intersect_block = Some(id);
        }
        intersect_block
    }

    /// The instruction at the specified address within this instruction set, or `None` if not
    /// found.
    pub fn get_instruction_at(&self, address: &Address) -> Option<&I> {
        self.get_instruction_block_containing(address)
            .and_then(|id| self.block(id).get_instruction_at(address))
    }

    /// The minimum address for this instruction set, or `None` if empty.
    pub fn get_min_address(&self) -> Option<Address> {
        self.address_set.min_address()
    }

    /// The address set that makes up all the instructions contained in this set.
    pub fn get_address_set(&self) -> &AddressSet {
        &self.address_set
    }

    /// The number of instructions in this instruction set.
    pub fn get_instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// True if this set has a block starting at `block_addr`.
    pub fn contains_block_at(&self, block_addr: &Address) -> bool {
        self.block_map.contains_key(block_addr)
    }

    /// True if this instruction set intersects the specified range.
    pub fn intersects(&self, min_address: &Address, max_address: &Address) -> bool {
        self.address_set.intersects_range(min_address, max_address)
    }

    /// A cursor over the blocks in this instruction set, giving preference to fall-through
    /// flows. It will not follow any flows from a block that has a conflict. If the last block
    /// returned is marked as a conflict (through [`InstructionSet::block_mut`]) before the next
    /// step, the cursor respects the conflict: it follows block flows on the fly and doesn't
    /// pre-compute the blocks to return. Blocks with no flow path from a start block are not
    /// visited. Port of `iterator()`.
    pub fn block_iterator(&self) -> BlockIterator {
        BlockIterator::new(self)
    }

    /// The blocks [`InstructionSet::block_iterator`] visits, for a caller that does not modify
    /// the set while iterating.
    pub fn iter(&self) -> Blocks<'_, I> {
        Blocks { set: self, cursor: self.block_iterator() }
    }

    /// All empty blocks, which likely contain a conflict error. Port of `emptyBlockIterator()`.
    pub fn empty_block_iterator(&self) -> impl Iterator<Item = &InstructionBlock<I>> + '_ {
        self.empty_blocks.iter().map(move |&id| self.block(id))
    }

    /// The conflicts of this set. If a block is not reachable from a non-conflicted block, its
    /// conflicts (if any) will not be included.
    pub fn get_conflicts(&self) -> Vec<&InstructionError> {
        self.iter().filter_map(InstructionBlock::get_instruction_conflict).collect()
    }
}

impl<I> fmt::Display for InstructionSet<I> {
    /// Port of `InstructionSet.toString()`, which delegates to `addressSet.toString()`. This
    /// crate's `AddressSet` has no `Display` port yet, so its own `toString()` behavior
    /// (`"[empty]\n"` when empty, else `printRanges()`) is inlined here instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.address_set.is_empty() {
            writeln!(f, "[empty]")
        } else {
            write!(f, "{}", self.address_set.print_ranges())
        }
    }
}

/// Cursor over the blocks of an [`InstructionSet`], giving preference to fall-through flows.
/// The set is a call-time argument; see [`InstructionSet::block_iterator`].
///
/// Port of the inner class `InstructionSet.BlockIterator`.
pub struct BlockIterator {
    current_block: Option<BlockId>,
    visited_block_set: HashSet<Address>,
    flow_queue: FlowQueue,
}

impl BlockIterator {
    fn new<I>(set: &InstructionSet<I>) -> Self {
        let mut flow_queue = FlowQueue::new();
        for start_addr in &set.start_addresses {
            flow_queue.add(start_addr.clone());
        }
        BlockIterator { current_block: None, visited_block_set: HashSet::new(), flow_queue }
    }

    /// Port of `hasNext()`.
    pub fn has_next<I>(&mut self, set: &InstructionSet<I>) -> bool {
        if self.flow_queue.is_empty() {
            self.add_flows(set, self.current_block);
        }
        !self.flow_queue.is_empty()
    }

    /// Port of `next()`: the next block, or `None` when there are no more.
    pub fn next<I>(&mut self, set: &InstructionSet<I>) -> Option<BlockId> {
        self.add_flows(set, self.current_block);

        self.current_block = if self.flow_queue.is_empty() {
            None
        } else {
            self.flow_queue.remove_next().and_then(|addr| set.block_map.get(&addr).copied())
        };

        if let Some(id) = self.current_block {
            self.visited_block_set.insert(set.block(id).get_start_address());
        }
        self.current_block
    }

    fn add_flows<I>(&mut self, set: &InstructionSet<I>, block: Option<BlockId>) {
        let Some(block) = block.map(|id| set.block(id)) else {
            return;
        };

        if !block.has_instruction_error() {
            // Only add fall-through flow if block has no conflict.
            if let Some(fall_through) = block.get_fall_through() {
                if !set.start_addresses.contains(&fall_through)
                    && self.is_not_visited_and_has_block(set, &fall_through)
                {
                    self.flow_queue.add_to_front(fall_through);
                }
            }
        }

        // Java returns early when the conflict's instruction address is null; that address is
        // never null here.
        let conflict_addr =
            block.get_instruction_conflict().map(InstructionError::get_instruction_address);

        for address in block.get_branch_flows() {
            if !set.start_addresses.contains(address)
                && self.is_not_visited_and_has_block(set, address)
                && Self::flows_from_before_cutoff(set, address, conflict_addr.as_ref())
            {
                self.flow_queue.add(address.clone());
            }
        }
    }

    /// Port of `flowsFromBeforeCutoff`.
    ///
    /// Java quirk faithfully reproduced: when `cutoffAddr` is non-null, Java calls
    /// `block.getFlowFromAddress().compareTo(cutoffAddr)` with **no null check**, so a
    /// destination block whose own flow-from address is unset throws `NullPointerException`
    /// there. This port panics the same way.
    fn flows_from_before_cutoff<I>(
        set: &InstructionSet<I>,
        block_addr: &Address,
        cutoff_addr: Option<&Address>,
    ) -> bool {
        let Some(cutoff_addr) = cutoff_addr else {
            return true;
        };
        let Some(&id) = set.block_map.get(block_addr) else {
            return false; // block not available
        };
        set.block(id)
            .get_flow_from_address()
            .expect(
                "InstructionBlock::get_flow_from_address() was None in flows_from_before_cutoff \
                 (mirrors Java's InstructionBlock.getFlowFromAddress().compareTo(...) \
                 NullPointerException when the flow-from address is unset)",
            )
            < *cutoff_addr
    }

    fn is_not_visited_and_has_block<I>(&self, set: &InstructionSet<I>, block_addr: &Address) -> bool {
        if self.visited_block_set.contains(block_addr) {
            return false;
        }
        set.block_map.contains_key(block_addr)
    }
}

/// The blocks of an [`InstructionSet`] in [`BlockIterator`] order, borrowing the set.
pub struct Blocks<'a, I> {
    set: &'a InstructionSet<I>,
    cursor: BlockIterator,
}

impl<'a, I> Iterator for Blocks<'a, I> {
    type Item = &'a InstructionBlock<I>;

    fn next(&mut self) -> Option<Self::Item> {
        let set = self.set;
        self.cursor.next(set).map(|id| set.block(id))
    }
}

impl<'a, I> IntoIterator for &'a InstructionSet<I> {
    type Item = &'a InstructionBlock<I>;
    type IntoIter = Blocks<'a, I>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Port of the package-private static nested class `InstructionSet.FlowQueue`.
///
/// A sorted queue of pending flow-target addresses, with an optional "front" override so a
/// fall-through flow can be visited ahead of the natural (sorted) order.
struct FlowQueue {
    set: BTreeSet<Address>,
    first: Option<Address>,
}

impl FlowQueue {
    fn new() -> Self {
        FlowQueue { set: BTreeSet::new(), first: None }
    }

    fn add_to_front(&mut self, address: Address) {
        self.set.insert(address.clone());
        self.first = Some(address);
    }

    fn add(&mut self, address: Address) {
        self.set.insert(address);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn contains(&self, address: &Address) -> bool {
        self.set.contains(address)
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    fn remove_next(&mut self) -> Option<Address> {
        let next = match self.first.take() {
            Some(addr) => addr,
            None => self.set.iter().next().cloned()?,
        };
        self.set.remove(&next);
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::instruction_block::test_support::RangeInstruction;

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn addr_factory() -> DefaultAddressFactory {
        DefaultAddressFactory::new(vec![])
    }

    type Block = InstructionBlock<RangeInstruction>;

    /// A block of one instruction covering `min..=max`.
    fn block(min: i64, max: i64) -> Block {
        let mut block = InstructionBlock::new(ram_addr(min));
        block.add_instruction(RangeInstruction::new(ram_addr(min), ram_addr(max)));
        block
    }

    fn flow_start(mut block: Block) -> Block {
        block.set_start_of_flow(true);
        block
    }

    fn flowed_from(mut block: Block, from: i64) -> Block {
        block.set_flow_from_address(Some(ram_addr(from)));
        block
    }

    fn starts(set: &InstructionSet<RangeInstruction>) -> Vec<i64> {
        set.iter().map(|b| b.get_start_address().offset()).collect()
    }

    #[test]
    fn empty_block_goes_only_to_empty_block_iterator() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let mut empty: Block = InstructionBlock::new(ram_addr(0x1000));
        empty.set_instruction_memory_error(ram_addr(0x1000), None, "no memory".to_string());

        let id = set.add_block(empty);

        assert!(!set.contains_block_at(&ram_addr(0x1000)));
        assert_eq!(set.iter().count(), 0);
        let collected: Vec<_> = set.empty_block_iterator().collect();
        assert_eq!(collected.len(), 1);
        assert!(std::ptr::eq(collected[0], set.block(id)));
        assert!(collected[0].has_instruction_error());
    }

    #[test]
    fn add_block_tracks_address_set_and_instruction_count() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let mut b = flow_start(block(0x1000, 0x1001));
        b.add_instruction(RangeInstruction::new(ram_addr(0x1002), ram_addr(0x1003)));

        set.add_block(b);

        assert!(set.contains_block_at(&ram_addr(0x1000)));
        assert_eq!(set.get_instruction_count(), 2);
        assert_eq!(set.get_min_address(), Some(ram_addr(0x1000)));
        assert!(set.intersects(&ram_addr(0x1000), &ram_addr(0x1003)));
        assert!(!set.intersects(&ram_addr(0x2000), &ram_addr(0x2001)));
    }

    #[test]
    #[should_panic(expected = "More than one block exists with the same start address")]
    fn add_block_rejects_distinct_block_at_same_start_address() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        set.add_block(flow_start(block(0x1000, 0x1001)));
        set.add_block(flow_start(block(0x1000, 0x1001)));
    }

    #[test]
    fn get_instruction_block_containing_finds_block_by_range_then_by_empty_map() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let id = set.add_block(flow_start(block(0x1000, 0x1003)));

        assert_eq!(set.get_instruction_block_containing(&ram_addr(0x1001)), Some(id));
        assert!(set.get_instruction_block_containing(&ram_addr(0x9000)).is_none());
    }

    #[test]
    fn get_instruction_at_delegates_to_containing_block() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        set.add_block(flow_start(block(0x1000, 0x1003)));

        let instr = set.get_instruction_at(&ram_addr(0x1000)).unwrap();
        assert_eq!(instr.min, ram_addr(0x1000));
        assert!(set.get_instruction_at(&ram_addr(0x1001)).is_none(), "offcut is not an instruction");
        assert!(set.get_instruction_at(&ram_addr(0x9000)).is_none());
    }

    #[test]
    fn find_first_intersecting_block_picks_smallest_start_among_intersecting() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let a = set.add_block(flow_start(block(0x1000, 0x1003)));
        set.add_block(flow_start(block(0x2000, 0x2003)));

        assert_eq!(set.find_first_intersecting_block(&ram_addr(0x1002), &ram_addr(0x2002)), Some(a));
        assert!(set.find_first_intersecting_block(&ram_addr(0x9000), &ram_addr(0x9003)).is_none());
    }

    #[test]
    fn iterator_follows_fallthrough_before_branch_targets() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);

        let mut start = flow_start(block(0x1000, 0x1003));
        start.set_fall_through(Some(ram_addr(0x3000)));
        start.add_branch_flow(ram_addr(0x2000));
        set.add_block(start);
        set.add_block(flowed_from(block(0x2000, 0x2003), 0x1002));
        set.add_block(flowed_from(block(0x3000, 0x3003), 0x1002));

        // The fall-through (0x3000) is queued to the front, ahead of the lower branch target.
        assert_eq!(starts(&set), vec![0x1000, 0x3000, 0x2000]);
    }

    #[test]
    fn iterator_does_not_follow_flows_from_a_block_with_a_conflict() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);

        let mut start = flow_start(block(0x1000, 0x1003));
        start.set_instruction_memory_error(ram_addr(0x1004), None, String::new());
        start.set_fall_through(Some(ram_addr(0x2000)));
        set.add_block(start);
        set.add_block(flowed_from(block(0x2000, 0x2003), 0x1002));

        assert_eq!(starts(&set), vec![0x1000]);
    }

    #[test]
    fn a_conflict_only_cuts_off_branches_from_at_or_after_it() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);

        let mut start = flow_start(block(0x1000, 0x1003));
        start.add_instruction(RangeInstruction::new(ram_addr(0x1004), ram_addr(0x1007)));
        start.add_branch_flow(ram_addr(0x2000));
        start.add_branch_flow(ram_addr(0x3000));
        start.set_instruction_memory_error(ram_addr(0x1004), None, String::new());
        set.add_block(start);
        // flowed from before the conflict: followed
        set.add_block(flowed_from(block(0x2000, 0x2003), 0x1000));
        // flowed from the conflicted instruction itself: cut off
        set.add_block(flowed_from(block(0x3000, 0x3003), 0x1004));

        assert_eq!(starts(&set), vec![0x1000, 0x2000]);
    }

    #[test]
    fn a_conflict_marked_between_steps_is_respected() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let mut start = flow_start(block(0x1000, 0x1003));
        start.set_fall_through(Some(ram_addr(0x2000)));
        let start = set.add_block(start);
        set.add_block(flowed_from(block(0x2000, 0x2003), 0x1002));

        let mut cursor = set.block_iterator();
        assert_eq!(cursor.next(&set), Some(start));
        // Java: "If the last block returned from the iterator is marked as a conflict before the
        // next call, then this iterator will respect the conflict."
        set.block_mut(start).set_instruction_memory_error(ram_addr(0x1002), None, String::new());
        assert!(!cursor.has_next(&set));
        assert_eq!(cursor.next(&set), None);
    }

    #[test]
    fn iterator_skips_unreachable_blocks_with_no_flow_path_from_a_start() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        set.add_block(flow_start(block(0x1000, 0x1003)));
        // Its flow-from (0x1002) lies inside a known block, so it is not a start, and nothing
        // flows to it.
        set.add_block(flowed_from(block(0x5000, 0x5003), 0x1002));

        assert_eq!(starts(&set), vec![0x1000]);
    }

    #[test]
    fn a_block_flowing_from_outside_the_set_is_a_start() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        set.add_block(flowed_from(block(0x5000, 0x5003), 0x9000));
        set.add_block(block(0x6000, 0x6003));
        assert_eq!(starts(&set), vec![0x5000, 0x6000]);
    }

    #[test]
    fn get_conflicts_collects_errors_reachable_via_the_iterator() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let mut start = flow_start(block(0x1000, 0x1003));
        start.set_instruction_memory_error(ram_addr(0x1004), None, String::new());
        set.add_block(start);

        let conflicts = set.get_conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].get_instruction_address(), ram_addr(0x1004));
    }

    #[test]
    fn display_reports_empty_bracket_marker_when_no_blocks_added() {
        let factory = addr_factory();
        let set: InstructionSet<RangeInstruction> = InstructionSet::new(&factory);
        assert_eq!(set.to_string(), "[empty]\n");
    }

    #[test]
    fn display_delegates_to_address_set_print_ranges_when_non_empty() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        set.add_block(flow_start(block(0x1000, 0x1003)));

        assert_eq!(set.to_string(), set.get_address_set().print_ranges());
        assert!(!set.to_string().is_empty());
    }

    #[test]
    fn into_iterator_impl_matches_iter() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        set.add_block(flow_start(block(0x1000, 0x1003)));

        let via_into_iter: Vec<Address> = (&set).into_iter().map(|b| b.get_start_address()).collect();
        let via_iter: Vec<Address> = set.iter().map(|b| b.get_start_address()).collect();
        assert_eq!(via_into_iter, via_iter);
    }

    /// Proves the `flowsFromBeforeCutoff` NullPointerException quirk: once the start block
    /// reports a conflict, a branch target whose flow-from address was cleared after it joined
    /// the set panics when the iterator checks whether it flowed from before the cutoff.
    #[test]
    #[should_panic(expected = "was None in flows_from_before_cutoff")]
    fn iterating_panics_if_branch_target_flow_from_is_unset_past_a_conflict() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let mut start = flow_start(block(0x1000, 0x1003));
        start.set_instruction_memory_error(ram_addr(0x1004), None, String::new());
        start.add_branch_flow(ram_addr(0x3000));
        set.add_block(start);
        // Valid flow-from (inside `start`) at add-time, so it is not a start address...
        let target = set.add_block(flowed_from(block(0x3000, 0x3003), 0x1002));
        // ...then cleared, as a real post-add `set_flow_from_address(None)` can.
        set.block_mut(target).set_flow_from_address(None);

        let _ = set.iter().count();
    }

    #[test]
    fn flow_queue_add_to_front_overrides_and_is_removed_first() {
        let mut queue = FlowQueue::new();
        queue.add(ram_addr(0x3000));
        queue.add(ram_addr(0x1000));
        queue.add_to_front(ram_addr(0x2000));

        assert!(queue.contains(&ram_addr(0x1000)));
        assert_eq!(queue.remove_next(), Some(ram_addr(0x2000)));
        // After the front override is consumed, remaining order falls back to sorted order.
        assert_eq!(queue.remove_next(), Some(ram_addr(0x1000)));
        assert_eq!(queue.remove_next(), Some(ram_addr(0x3000)));
        assert!(queue.is_empty());
        assert_eq!(queue.remove_next(), None);
    }
}
