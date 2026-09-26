//! Fixtures shared by this package's tests: simple instructions, a listing that serves them, and
//! basic blocks over explicit address sets.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::program::model::address::{
    Address, AddressRange, AddressRangeIterator, AddressSet, AddressSetView, AddressSpace,
    AddressSpaceType, BoxedAddressIterator,
};
use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
use crate::program::model::block::{CodeBlock, CodeBlockModel};
use crate::program::model::listing::{Instruction, InstructionStub, StubListing};
use crate::program::seam_stubs::EmptyCodeBlockReferenceIterator;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use super::block::{Block, CorrelateBlockId};
use super::instruct_hash::InstructHash;

pub fn ram() -> Arc<AddressSpace> {
    AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
}

pub fn addr(offset: i64) -> Address {
    Address::new(ram(), offset)
}

/// An instruction with just an address, a length and a mnemonic.
pub struct TestInst {
    pub address: Address,
    pub length: i32,
    pub mnemonic: String,
}

impl InstructionStub for TestInst {
    fn get_min_address(&self) -> Address {
        self.address.clone()
    }
    fn get_membuffer_address(&self) -> Address {
        self.address.clone()
    }
    fn get_length(&self) -> i32 {
        self.length
    }
    fn get_mnemonic_string(&self) -> String {
        self.mnemonic.clone()
    }
}

pub fn inst(offset: i64, length: i32, mnemonic: &str) -> Arc<dyn Instruction> {
    Arc::new(TestInst { address: addr(offset), length, mnemonic: mnemonic.to_string() })
}

/// A listing holding instructions by start address.
#[derive(Default)]
pub struct TestListing {
    pub instructions: BTreeMap<Address, Arc<dyn Instruction>>,
}

impl TestListing {
    /// Lay out the mnemonics back to back from `start`, each `length` bytes long.
    pub fn place(&mut self, start: i64, length: i32, mnemonics: &[&str]) {
        for (i, m) in mnemonics.iter().enumerate() {
            let offset = start + i as i64 * length as i64;
            self.instructions.insert(addr(offset), inst(offset, length, m));
        }
    }
}

impl StubListing for TestListing {
    fn get_instruction_at(&self, addr: &Address) -> Option<Arc<dyn Instruction>> {
        self.instructions.get(addr).cloned()
    }
}

/// A basic block over an explicit address set, with no flow.
pub struct TestBlock {
    pub set: AddressSet,
}

impl TestBlock {
    pub fn boxed(ranges: &[(i64, i64)]) -> Box<dyn CodeBlock> {
        let mut set = AddressSet::new();
        for &(start, end) in ranges {
            set.add_range(&addr(start), &addr(end));
        }
        Box::new(TestBlock { set })
    }
}

impl CodeBlock for TestBlock {
    fn get_destinations(
        &self,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
        Ok(Box::new(EmptyCodeBlockReferenceIterator))
    }
    fn get_model(&self) -> Box<dyn CodeBlockModel> {
        unimplemented!("not exercised by these tests")
    }
}

impl AddressSetView for TestBlock {
    fn contains(&self, address: &Address) -> bool {
        self.set.contains(address)
    }
    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        self.set.contains_range(start, end)
    }
    fn contains_set(&self, set: &dyn AddressSetView) -> bool {
        self.set.contains_set(set)
    }
    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
    fn min_address(&self) -> Option<Address> {
        self.set.min_address()
    }
    fn max_address(&self) -> Option<Address> {
        self.set.max_address()
    }
    fn num_address_ranges(&self) -> usize {
        self.set.num_address_ranges()
    }
    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        self.set.address_ranges()
    }
    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.set.address_ranges_ordered(forward)
    }
    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.set.address_ranges_from(start, forward)
    }
    fn num_addresses(&self) -> u64 {
        self.set.num_addresses()
    }
    fn addresses(&self, forward: bool) -> BoxedAddressIterator {
        self.set.addresses(forward)
    }
    fn addresses_from(&self, start: &Address, forward: bool) -> BoxedAddressIterator {
        self.set.addresses_from(start, forward)
    }
    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        self.set.intersects_set(set)
    }
    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        self.set.intersects_range(start, end)
    }
    fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
        self.set.intersect(set)
    }
    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        self.set.intersect_range(start, end)
    }
    fn union(&self, set: &dyn AddressSetView) -> AddressSet {
        self.set.union(set)
    }
    fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
        self.set.subtract(set)
    }
    fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
        self.set.xor(set)
    }
    fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
        self.set.has_same_addresses(set)
    }
    fn first_range(&self) -> Option<AddressRange> {
        self.set.first_range()
    }
    fn last_range(&self) -> Option<AddressRange> {
        self.set.last_range()
    }
    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        self.set.range_containing(address)
    }
    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        self.set.find_first_address_in_common(set)
    }
}

/// A standalone block (not in any store) holding the given mnemonics, 4 bytes apart from 0x1000.
pub fn block_of(id: CorrelateBlockId, mnemonics: &[&str]) -> Block {
    let mut block = Block::new(TestBlock::boxed(&[(0x1000, 0x1000 + 4 * mnemonics.len() as i64 - 1)]));
    block.inst_list = mnemonics
        .iter()
        .enumerate()
        .map(|(i, m)| InstructHash::new(inst(0x1000 + 4 * i as i64, 4, m), id, i))
        .collect();
    block
}
