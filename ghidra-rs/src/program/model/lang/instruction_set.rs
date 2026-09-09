//! Port of `ghidra.program.model.lang.InstructionSet`.
//!
//! A set of instructions organized as a graph of basic blocks, built up out of
//! [`InstructionBlock`]s (already ported as a trait; see that module's docs for why).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crate::program::database::register::address_range_object_map::AddressRangeObjectMap;
use crate::program::model::address::{Address, AddressFactory, AddressSet, AddressSetView};
use crate::program::model::lang::instruction_block::InstructionBlock;
use crate::program::model::listing::Instruction;
use crate::program::seam_stubs::InstructionError as InstructionErrorSeam;

/// Wraps `Arc<dyn InstructionBlock>` with pointer-identity equality so it can be stored as the
/// value type of [`AddressRangeObjectMap`], whose coalescing logic needs `T: PartialEq`. Java's
/// `InstructionBlock` never overrides `equals()`/`hashCode()`, so `AddressRangeObjectMap`'s
/// "is this the same value as the adjacent range" checks there are reference-identity checks too
/// -- `Arc::ptr_eq` is the exact Rust equivalent, not merely a stand-in.
#[derive(Clone)]
struct BlockHandle(Arc<dyn InstructionBlock>);

impl PartialEq for BlockHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for BlockHandle {}

/// A set of instructions organized as a graph of basic blocks.
///
/// Port of `ghidra.program.model.lang.InstructionSet`.
pub struct InstructionSet {
    block_map: HashMap<Address, Arc<dyn InstructionBlock>>,
    block_range_map: AddressRangeObjectMap<BlockHandle>,
    start_addresses: HashSet<Address>,
    empty_blocks: Vec<Arc<dyn InstructionBlock>>,
    address_set: AddressSet,
    instruction_count: usize,
}

impl InstructionSet {
    /// Construct a new, empty `InstructionSet`.
    ///
    /// Java quirk faithfully reproduced: the `AddressFactory` constructor parameter is entirely
    /// unused by `InstructionSet`'s constructor body (`addressSet = new AddressSet();` is the
    /// only statement) -- kept here, unused, purely for call-site signature fidelity.
    pub fn new(_addr_factory: &dyn AddressFactory) -> Self {
        InstructionSet {
            block_map: HashMap::new(),
            block_range_map: AddressRangeObjectMap::new(),
            start_addresses: HashSet::new(),
            empty_blocks: Vec::new(),
            address_set: AddressSet::new(),
            instruction_count: 0,
        }
    }

    /// Add an instruction block to this instruction set.
    ///
    /// If the block is empty it will only be added to the empty-list and will not be added to the
    /// maps or block iterator.
    ///
    /// # Panics
    /// Panics if a different block already exists in this set with the same start address
    /// (mirrors Java's `AssertException`: "More than one block exists with the same start
    /// address").
    pub fn add_block(&mut self, block: Arc<dyn InstructionBlock>) {
        if block.is_empty() {
            // multiple empty blocks at the same address are possible
            self.empty_blocks.push(block);
            return;
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

        let old_block = self.block_map.insert(start_addr.clone(), block.clone());
        if let Some(old) = &old_block {
            if !Arc::ptr_eq(old, &block) {
                panic!("More than one block exists with the same start address");
            }
        }

        self.address_set.add_range(&start_addr, &max_addr);
        self.instruction_count += block.get_instruction_count();
        self.block_range_map.set_object(start_addr, max_addr, BlockHandle(block));
    }

    /// Returns the non-empty `InstructionBlock` containing the specified address, or `None` if
    /// not found.
    pub fn get_instruction_block_containing(&self, address: &Address) -> Option<Arc<dyn InstructionBlock>> {
        if let Some(handle) = self.block_range_map.get_object(address) {
            return Some(handle.0);
        }
        // try returning an empty block if one exists
        self.block_map.get(address).cloned()
    }

    /// Find the first block within this `InstructionSet` which intersects the specified range.
    /// This method should be used sparingly since it uses a brute-force search. Returns `None` if
    /// no block within this `InstructionSet` intersects the range.
    ///
    /// Note: like Java's `HashMap` iteration order, this crate's `HashMap` iteration order is
    /// unspecified, so if more than one intersecting block shares the minimum start address
    /// among all intersecting blocks, which one is returned is not deterministic -- exactly
    /// mirroring the original's reliance on `blockMap.values()` iteration order.
    pub fn find_first_intersecting_block(&self, min: &Address, max: &Address) -> Option<Arc<dyn InstructionBlock>> {
        let mut intersect_block: Option<Arc<dyn InstructionBlock>> = None;
        for block in self.block_map.values() {
            let block_min = block.get_start_address();
            if block_min.cmp(max) == std::cmp::Ordering::Greater {
                continue;
            }
            let block_max = block.get_max_address();
            if block_max.cmp(min) == std::cmp::Ordering::Less {
                continue;
            }
            if let Some(current) = &intersect_block {
                if current.get_start_address().cmp(&block_min) == std::cmp::Ordering::Less {
                    continue;
                }
            }
            intersect_block = Some(block.clone());
        }
        intersect_block
    }

    /// Returns the instruction at the specified address within this instruction set, or `None`
    /// if not found.
    pub fn get_instruction_at(&self, address: &Address) -> Option<Arc<dyn Instruction>> {
        self.get_instruction_block_containing(address)
            .and_then(|block| block.get_instruction_at(address))
    }

    /// Returns the minimum address for this instruction set, or `None` if empty.
    pub fn get_min_address(&self) -> Option<Address> {
        self.address_set.min_address()
    }

    /// Returns the address set that makes up all the instructions contained in this set.
    pub fn get_address_set(&self) -> &AddressSet {
        &self.address_set
    }

    /// Returns the number of instructions in this instruction set.
    pub fn get_instruction_count(&self) -> usize {
        self.instruction_count
    }

    pub fn contains_block_at(&self, block_addr: &Address) -> bool {
        self.block_map.contains_key(block_addr)
    }

    /// Returns true if this instruction set intersects the specified range.
    pub fn intersects(&self, min_address: &Address, max_address: &Address) -> bool {
        self.address_set.intersects_range(min_address, max_address)
    }

    /// Returns an iterator over the blocks in this instruction set, giving preference to
    /// fall-through flows. This iterator will not follow any flows from a block that has a
    /// conflict. If the last block returned from the iterator is marked as a conflict before the
    /// next call, then this iterator will respect the conflict. In other words, this iterator
    /// follows block flows on the fly and doesn't pre-compute the blocks to return. Also, if any
    /// blocks in this set don't have a flow path from the start block, they will not be included
    /// in this iterator.
    pub fn iter(&self) -> BlockIterator<'_> {
        BlockIterator::new(self)
    }

    /// Returns an iterator over all empty blocks, which likely contain a conflict error.
    pub fn empty_block_iterator(&self) -> impl Iterator<Item = Arc<dyn InstructionBlock>> + '_ {
        self.empty_blocks.iter().cloned()
    }

    /// Returns a list of conflicts for this set. If a block is not reachable from a
    /// non-conflicted block, its conflicts (if any) will not be included.
    ///
    /// Minor documented divergence from Java: `InstructionBlock::get_instruction_conflict`
    /// returns `Option<Box<dyn InstructionError>>`, so a block that (inconsistently) reports
    /// `has_instruction_error() == true` while returning `None` here is simply skipped rather
    /// than inserting a `null` placeholder the way Java's un-null-checked `List.add` would --
    /// `InstructionBlock`'s own docs pair the two methods 1:1, so this is unreachable for any
    /// well-behaved implementation.
    pub fn get_conflicts(&self) -> Vec<Box<dyn InstructionErrorSeam>> {
        let mut conflicts = Vec::new();
        for block in self.iter() {
            if block.has_instruction_error() {
                if let Some(conflict) = block.get_instruction_conflict() {
                    conflicts.push(conflict);
                }
            }
        }
        conflicts
    }
}

impl fmt::Display for InstructionSet {
    /// Port of `InstructionSet.toString()`, which just delegates to `addressSet.toString()`.
    /// This crate's `AddressSet` has no `Display` port yet, so its own `toString()` behavior
    /// (`"[empty]\n"` when empty, else `printRanges()`) is inlined here instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.address_set.is_empty() {
            writeln!(f, "[empty]")
        } else {
            write!(f, "{}", self.address_set.print_ranges())
        }
    }
}

/// Iterator over the [`InstructionBlock`]s of an [`InstructionSet`], giving preference to
/// fall-through flows.
///
/// Port of the inner class `InstructionSet.BlockIterator`.
pub struct BlockIterator<'a> {
    set: &'a InstructionSet,
    current_block: Option<Arc<dyn InstructionBlock>>,
    visited_block_set: HashSet<Address>,
    flow_queue: FlowQueue,
}

impl<'a> BlockIterator<'a> {
    fn new(set: &'a InstructionSet) -> Self {
        let mut flow_queue = FlowQueue::new();
        for start_addr in &set.start_addresses {
            flow_queue.add(start_addr.clone());
        }
        BlockIterator { set, current_block: None, visited_block_set: HashSet::new(), flow_queue }
    }

    fn add_flows(&mut self, block: Option<&Arc<dyn InstructionBlock>>) {
        let block = match block {
            Some(block) => block,
            None => return,
        };

        if !block.has_instruction_error() {
            // Only add fall-through flow if block has no conflict.
            if let Some(fall_through) = block.get_fall_through() {
                if !self.set.start_addresses.contains(&fall_through)
                    && self.is_not_visited_and_has_block(&fall_through)
                {
                    self.flow_queue.add_to_front(fall_through);
                }
            }
        }

        let mut conflict_addr: Option<Address> = None;
        if block.has_instruction_error() {
            conflict_addr = block.get_instruction_conflict().map(|c| c.get_instruction_address());
            if conflict_addr.is_none() {
                return;
            }
        }

        for address in block.get_branch_flows() {
            if !self.set.start_addresses.contains(&address)
                && self.is_not_visited_and_has_block(&address)
                && self.flows_from_before_cutoff(&address, conflict_addr.as_ref())
            {
                self.flow_queue.add(address);
            }
        }
    }

    /// Port of `flowsFromBeforeCutoff`.
    ///
    /// Java quirk faithfully reproduced: when `cutoffAddr` is non-null, Java calls
    /// `block.getFlowFromAddress().compareTo(cutoffAddr)` with **no null check** on
    /// `getFlowFromAddress()`'s result, so a destination block whose own flow-from address is
    /// unset throws `NullPointerException` there. This port panics the same way (via
    /// `Option::expect`) rather than silently treating a missing flow-from as satisfying or
    /// failing the cutoff check. See
    /// `iterating_panics_if_branch_target_flow_from_is_unset_past_a_conflict` below.
    fn flows_from_before_cutoff(&self, block_addr: &Address, cutoff_addr: Option<&Address>) -> bool {
        let cutoff_addr = match cutoff_addr {
            None => return true,
            Some(addr) => addr,
        };
        let block = match self.set.block_map.get(block_addr) {
            Some(block) => block,
            None => return false, // block not available
        };
        block
            .get_flow_from_address()
            .expect(
                "InstructionBlock::get_flow_from_address() was None in flows_from_before_cutoff \
                 (mirrors Java's InstructionBlock.getFlowFromAddress().compareTo(...) \
                 NullPointerException when the flow-from address is unset)",
            )
            .cmp(cutoff_addr)
            == std::cmp::Ordering::Less
    }

    fn is_not_visited_and_has_block(&self, block_addr: &Address) -> bool {
        if self.visited_block_set.contains(block_addr) {
            return false;
        }
        self.set.block_map.contains_key(block_addr)
    }
}

impl<'a> Iterator for BlockIterator<'a> {
    type Item = Arc<dyn InstructionBlock>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current_block.clone();
        self.add_flows(current.as_ref());

        self.current_block = if self.flow_queue.is_empty() {
            None
        } else {
            self.flow_queue.remove_next().and_then(|addr| self.set.block_map.get(&addr).cloned())
        };

        if let Some(block) = &self.current_block {
            self.visited_block_set.insert(block.get_start_address());
        }

        self.current_block.clone()
    }
}

impl<'a> IntoIterator for &'a InstructionSet {
    type Item = Arc<dyn InstructionBlock>;
    type IntoIter = BlockIterator<'a>;

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
    use crate::program::model::lang::instruction_block_flow::InstructionBlockFlow as ConcreteBlockFlow;
    use crate::program::model::listing::instruction::tests::mock_instruction;
    use crate::program::seam_stubs::{InstructionBlockFlow, InstructionErrorType, RegisterValue};
    use std::cell::RefCell;
    use std::sync::Mutex;

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn addr_factory() -> DefaultAddressFactory {
        DefaultAddressFactory::new(vec![])
    }

    /// Real, in-memory `InstructionBlock` implementation used only by these tests: a contiguous
    /// run of instructions plus the flow bookkeeping (`fallthrough`/branch flows/flow-from/error)
    /// that `InstructionSet`'s block-graph logic reads.
    struct TestBlock {
        start: Address,
        instructions: Vec<Arc<dyn Instruction>>,
        max_addr: Option<Address>,
        is_start_of_flow: bool,
        branch_flows: Vec<Address>,
        fallthrough: Option<Address>,
        // `RefCell` (rather than a plain field) so a test can clear this *after* the block has
        // already been added to an `InstructionSet` and wrapped in `Arc<dyn InstructionBlock>`
        // -- mirroring a real `InstructionBlock::set_flow_from_address(None)` call happening
        // post-add, via `force_clear_flow_from` below.
        flow_from: RefCell<Option<Address>>,
        has_error: bool,
        conflict_instruction_address: Mutex<Option<Address>>,
    }

    impl TestBlock {
        fn new(start: Address) -> Self {
            TestBlock {
                start,
                instructions: Vec::new(),
                max_addr: None,
                is_start_of_flow: false,
                branch_flows: Vec::new(),
                fallthrough: None,
                flow_from: RefCell::new(None),
                has_error: false,
                conflict_instruction_address: Mutex::new(None),
            }
        }

        fn with_instruction(mut self, min: Address, max: Address) -> Self {
            self.max_addr = Some(max.clone());
            self.instructions.push(mock_instruction(min, max));
            self
        }

        fn with_fallthrough(mut self, addr: Address) -> Self {
            self.fallthrough = Some(addr);
            self
        }

        fn with_branch_flow(mut self, addr: Address) -> Self {
            self.branch_flows.push(addr);
            self
        }

        fn with_flow_from(self, addr: Address) -> Self {
            *self.flow_from.borrow_mut() = Some(addr);
            self
        }

        /// Test-only hook: clears `flow_from` through `&self`, so it can be called via a
        /// concrete `Arc<TestBlock>` handle kept alongside the `Arc<dyn InstructionBlock>` that
        /// was actually inserted into an `InstructionSet`.
        fn force_clear_flow_from(&self) {
            *self.flow_from.borrow_mut() = None;
        }

        fn with_flow_start(mut self) -> Self {
            self.is_start_of_flow = true;
            self
        }

        fn with_error_at(mut self, conflict_instruction_address: Address) -> Self {
            self.has_error = true;
            *self.conflict_instruction_address.lock().unwrap() = Some(conflict_instruction_address);
            self
        }

        fn arc(self) -> Arc<dyn InstructionBlock> {
            Arc::new(self)
        }
    }

    struct TestInstructionError {
        instruction_address: Address,
    }

    impl crate::program::seam_stubs::InstructionError for TestInstructionError {
        fn get_instruction_address(&self) -> Address {
            self.instruction_address.clone()
        }
    }

    impl InstructionBlock for TestBlock {
        fn set_start_of_flow(&mut self, is_start: bool) {
            self.is_start_of_flow = is_start;
        }
        fn is_flow_start(&self) -> bool {
            self.is_start_of_flow
        }
        fn get_start_address(&self) -> Address {
            self.start.clone()
        }
        fn get_max_address(&self) -> Address {
            self.max_addr.clone().unwrap_or_else(|| self.start.clone())
        }
        fn get_instruction_at(&self, address: &Address) -> Option<Arc<dyn Instruction>> {
            self.instructions.iter().find(|i| &i.get_min_address() == address).cloned()
        }
        fn find_first_intersecting_instruction(
            &self,
            min: &Address,
            max: &Address,
        ) -> Option<Arc<dyn Instruction>> {
            self.instructions
                .iter()
                .find(|i| i.get_min_address() <= *max && i.get_max_address() >= *min)
                .cloned()
        }
        fn add_instruction(&mut self, instruction: Arc<dyn Instruction>) {
            self.max_addr = Some(instruction.get_max_address());
            self.instructions.push(instruction);
        }
        fn add_block_flow(&mut self, _block_flow: Box<dyn InstructionBlockFlow>) {}
        fn add_branch_flow(&mut self, destination_address: Address) {
            self.branch_flows.push(destination_address);
        }
        fn set_fall_through(&mut self, fallthrough_address: Option<Address>) {
            self.fallthrough = fallthrough_address;
        }
        fn get_branch_flows(&self) -> Vec<Address> {
            self.branch_flows.clone()
        }
        fn get_block_flows(&self) -> Option<Vec<Box<dyn InstructionBlockFlow>>> {
            None
        }
        fn get_fall_through(&self) -> Option<Address> {
            self.fallthrough.clone()
        }
        fn set_instruction_error(
            &mut self,
            _error_type: InstructionErrorType,
            intended_instruction_address: Address,
            _conflict_address: Address,
            _flow_from_address: Option<Address>,
            _message: String,
        ) {
            self.has_error = true;
            *self.conflict_instruction_address.lock().unwrap() = Some(intended_instruction_address);
        }
        fn set_parse_conflict(
            &mut self,
            _conflict_address: Address,
            _context_value: Box<dyn RegisterValue>,
            _flow_from_address: Option<Address>,
            _message: String,
        ) {
            self.has_error = true;
        }
        fn clear_conflict(&mut self) {
            self.has_error = false;
            *self.conflict_instruction_address.lock().unwrap() = None;
        }
        fn get_instruction_conflict(&self) -> Option<Box<dyn InstructionErrorSeam>> {
            if !self.has_error {
                return None;
            }
            self.conflict_instruction_address.lock().unwrap().clone().map(|addr| {
                Box::new(TestInstructionError { instruction_address: addr }) as Box<dyn InstructionErrorSeam>
            })
        }
        fn iter_instructions(&self) -> Box<dyn Iterator<Item = Arc<dyn Instruction>> + '_> {
            Box::new(self.instructions.iter().cloned())
        }
        fn get_last_instruction_address(&self) -> Option<Address> {
            self.instructions.last().map(|i| i.get_min_address())
        }
        fn is_empty(&self) -> bool {
            self.instructions.is_empty()
        }
        fn get_instruction_count(&self) -> usize {
            self.instructions.len()
        }
        fn get_instructions_added_count(&self) -> i32 {
            self.instructions.len() as i32
        }
        fn set_instructions_added_count(&mut self, _count: i32) {}
        fn get_flow_from_address(&self) -> Option<Address> {
            self.flow_from.borrow().clone()
        }
        fn set_flow_from_address(&mut self, flow_from: Option<Address>) {
            *self.flow_from.borrow_mut() = flow_from;
        }
        fn has_instruction_error(&self) -> bool {
            self.has_error
        }
    }

    #[test]
    fn empty_block_goes_only_to_empty_block_iterator() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let empty = TestBlock::new(ram_addr(0x1000)).arc();

        set.add_block(empty.clone());

        assert!(!set.contains_block_at(&ram_addr(0x1000)));
        assert_eq!(set.iter().count(), 0);
        let collected: Vec<_> = set.empty_block_iterator().collect();
        assert_eq!(collected.len(), 1);
        assert!(Arc::ptr_eq(&collected[0], &empty));
    }

    #[test]
    fn add_block_tracks_address_set_and_instruction_count() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let block = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1001))
            .with_instruction(ram_addr(0x1002), ram_addr(0x1003))
            .with_flow_start()
            .arc();

        set.add_block(block);

        assert!(set.contains_block_at(&ram_addr(0x1000)));
        assert_eq!(set.get_instruction_count(), 2);
        assert_eq!(set.get_min_address(), Some(ram_addr(0x1000)));
        assert!(set.intersects(&ram_addr(0x1000), &ram_addr(0x1003)));
        assert!(!set.intersects(&ram_addr(0x2000), &ram_addr(0x2001)));
    }

    #[test]
    fn re_adding_the_same_block_reference_is_a_no_op() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let block = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1001))
            .with_flow_start()
            .arc();

        set.add_block(block.clone());
        set.add_block(block);
        assert_eq!(set.get_instruction_count(), 2);
    }

    #[test]
    #[should_panic(expected = "More than one block exists with the same start address")]
    fn add_block_rejects_distinct_block_at_same_start_address() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let first = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1001))
            .with_flow_start()
            .arc();
        let second = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1001))
            .with_flow_start()
            .arc();

        set.add_block(first);
        set.add_block(second);
    }

    #[test]
    fn get_instruction_block_containing_finds_block_by_range_then_by_empty_map() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let block = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .arc();
        set.add_block(block.clone());

        let found = set.get_instruction_block_containing(&ram_addr(0x1001));
        assert!(found.is_some());
        assert!(Arc::ptr_eq(&found.unwrap(), &block));
        assert!(set.get_instruction_block_containing(&ram_addr(0x9000)).is_none());
    }

    #[test]
    fn get_instruction_at_delegates_to_containing_block() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let block = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .arc();
        set.add_block(block);

        let instr = set.get_instruction_at(&ram_addr(0x1000));
        assert!(instr.is_some());
        assert_eq!(instr.unwrap().get_min_address(), ram_addr(0x1000));
        assert!(set.get_instruction_at(&ram_addr(0x9000)).is_none());
    }

    #[test]
    fn find_first_intersecting_block_picks_smallest_start_among_intersecting() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let a = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .arc();
        let b = TestBlock::new(ram_addr(0x2000))
            .with_instruction(ram_addr(0x2000), ram_addr(0x2003))
            .with_flow_start()
            .arc();
        set.add_block(a.clone());
        set.add_block(b);

        let found = set.find_first_intersecting_block(&ram_addr(0x1002), &ram_addr(0x2002));
        assert!(found.is_some());
        assert!(Arc::ptr_eq(&found.unwrap(), &a));
        assert!(set.find_first_intersecting_block(&ram_addr(0x9000), &ram_addr(0x9003)).is_none());
    }

    #[test]
    fn iterator_follows_fallthrough_before_branch_targets() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);

        let start = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .with_fallthrough(ram_addr(0x2000))
            .with_branch_flow(ram_addr(0x3000))
            .arc();
        let fallthrough_target = TestBlock::new(ram_addr(0x2000))
            .with_instruction(ram_addr(0x2000), ram_addr(0x2003))
            .with_flow_from(ram_addr(0x1002))
            .arc();
        let branch_target = TestBlock::new(ram_addr(0x3000))
            .with_instruction(ram_addr(0x3000), ram_addr(0x3003))
            .with_flow_from(ram_addr(0x1002))
            .arc();

        set.add_block(start.clone());
        set.add_block(fallthrough_target.clone());
        set.add_block(branch_target.clone());

        let order: Vec<Address> = set.iter().map(|b| b.get_start_address()).collect();
        assert_eq!(order, vec![ram_addr(0x1000), ram_addr(0x2000), ram_addr(0x3000)]);
    }

    #[test]
    fn iterator_does_not_follow_flows_from_a_block_with_a_conflict() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);

        let start = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .with_error_at(ram_addr(0x1004))
            .with_fallthrough(ram_addr(0x2000))
            .arc();
        let fallthrough_target = TestBlock::new(ram_addr(0x2000))
            .with_instruction(ram_addr(0x2000), ram_addr(0x2003))
            .with_flow_from(ram_addr(0x1002))
            .arc();

        set.add_block(start);
        set.add_block(fallthrough_target);

        // The conflicted start block's own fall-through flow is suppressed (`has_instruction_error()`
        // guards fall-through), and its conflict has no branch flows to add, so the iterator only
        // ever yields the start block itself.
        let order: Vec<Address> = set.iter().map(|b| b.get_start_address()).collect();
        assert_eq!(order, vec![ram_addr(0x1000)]);
    }

    #[test]
    fn iterator_skips_unreachable_blocks_with_no_flow_path_from_a_start() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let start = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .arc();
        // Not a flow start, and its recorded flow-from address (0x1002) falls inside `start`'s
        // own range -- so `add_block` does *not* auto-promote it to a start address (unlike a
        // block with no recorded flow-from at all, which always is; see `add_block`'s docs).
        // Since nothing ever actually flows to 0x5000 (no branch/fallthrough targets it), it's
        // genuinely unreachable from `start`.
        let orphan = TestBlock::new(ram_addr(0x5000))
            .with_instruction(ram_addr(0x5000), ram_addr(0x5003))
            .with_flow_from(ram_addr(0x1002))
            .arc();

        set.add_block(start);
        set.add_block(orphan);

        let order: Vec<Address> = set.iter().map(|b| b.get_start_address()).collect();
        assert_eq!(order, vec![ram_addr(0x1000)]);
    }

    #[test]
    fn get_conflicts_collects_errors_reachable_via_the_iterator() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let start = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .with_error_at(ram_addr(0x1004))
            .arc();
        set.add_block(start);

        let conflicts = set.get_conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].get_instruction_address(), ram_addr(0x1004));
    }

    #[test]
    fn display_reports_empty_bracket_marker_when_no_blocks_added() {
        let factory = addr_factory();
        let set = InstructionSet::new(&factory);
        assert_eq!(set.to_string(), "[empty]\n");
    }

    #[test]
    fn display_delegates_to_address_set_print_ranges_when_non_empty() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let block = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .arc();
        set.add_block(block);

        assert_eq!(set.to_string(), set.get_address_set().print_ranges());
        assert!(!set.to_string().is_empty());
    }

    #[test]
    fn into_iterator_impl_matches_iter() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let block = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .arc();
        set.add_block(block);

        let via_into_iter: Vec<Address> = (&set).into_iter().map(|b| b.get_start_address()).collect();
        let via_iter: Vec<Address> = set.iter().map(|b| b.get_start_address()).collect();
        assert_eq!(via_into_iter, via_iter);
    }

    /// Proves the `flowsFromBeforeCutoff` NullPointerException quirk documented on
    /// `BlockIterator::flows_from_before_cutoff`: once the start block reports a conflict, any
    /// branch-flow target whose own flow-from address is unset panics when the iterator checks
    /// whether it flowed from before the conflict's cutoff address.
    ///
    /// Reachability note: `add_block` always auto-promotes a block with *no* recorded flow-from
    /// to a start address (see its docs), and start-classified addresses are filtered out of the
    /// branch-flow loop before `flows_from_before_cutoff` is ever called -- so a block can only
    /// hit this panic if its flow-from was valid (non-null, pointing inside an already-known
    /// block's range) *at add-time* and was cleared afterward. That is exactly what real
    /// `InstructionBlock::set_flow_from_address(None)` calls can do post-add, so this test
    /// reproduces that sequencing: add `branch_target` with a valid flow-from (so `add_block`
    /// does not treat it as a start), then clear it through a retained concrete `Arc<TestBlock>`
    /// handle before iterating.
    #[test]
    #[should_panic(expected = "was None in flows_from_before_cutoff")]
    fn iterating_panics_if_branch_target_flow_from_is_unset_past_a_conflict() {
        let factory = addr_factory();
        let mut set = InstructionSet::new(&factory);
        let start = TestBlock::new(ram_addr(0x1000))
            .with_instruction(ram_addr(0x1000), ram_addr(0x1003))
            .with_flow_start()
            .with_error_at(ram_addr(0x1004))
            .with_branch_flow(ram_addr(0x3000))
            .arc();
        // Valid flow-from (inside `start`'s own range) at add-time, so `branch_target` is not
        // auto-promoted to a start address.
        let branch_target = Arc::new(
            TestBlock::new(ram_addr(0x3000))
                .with_instruction(ram_addr(0x3000), ram_addr(0x3003))
                .with_flow_from(ram_addr(0x1002)),
        );

        set.add_block(start);
        set.add_block(branch_target.clone());
        // Now clear it, mirroring a real post-add `set_flow_from_address(None)` call.
        branch_target.force_clear_flow_from();

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

    #[test]
    fn concrete_instruction_block_flow_satisfies_the_seam_marker_trait_used_by_instruction_block() {
        // `InstructionSet` itself never constructs an `InstructionBlockFlow`, but
        // `InstructionBlock::add_block_flow`/`get_block_flows` (which this set's blocks may be
        // asked to hold) are typed in terms of the `seam_stubs::InstructionBlockFlow` marker
        // trait; confirm the real, concrete type from `instruction_block_flow` composes with it.
        use crate::program::model::lang::instruction_block_flow::InstructionBlockFlowType;
        let flow = ConcreteBlockFlow::new(ram_addr(0x2000), Some(ram_addr(0x1000)), InstructionBlockFlowType::Branch);
        let boxed: Box<dyn InstructionBlockFlow> = Box::new(flow);
        let mut block = TestBlock::new(ram_addr(0x1000));
        block.add_block_flow(boxed);
    }
}
