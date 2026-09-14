//! Port of `ghidra.app.plugin.match.SubroutineMatchSet`.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::block::CodeBlockModel;
use crate::program::model::listing::Program;
use crate::program::model::symbol::SymbolTable;
use crate::util::task::DummyMonitor;

use super::SubroutineMatch;

/// A collection of subroutine matches found between two programs, together with the programs and
/// code-block models involved.
///
/// Behaves like `Vec<SubroutineMatch>` via `Deref`/`DerefMut`, mirroring the Java class's
/// `extends ArrayList<SubroutineMatch>`. Same shape as this crate's sibling
/// [`FunctionMatchSet`](crate::app::plugin::match::FunctionMatchSet) (`ghidra.app.plugin.match.FunctionMatchSet`),
/// except this port of `SubroutineMatchSet` measures function length via an explicit
/// [`CodeBlockModel`] rather than `Program::getFunctionManager().getFunctionContaining`, matching
/// its Java original's own constructor parameters.
///
/// Port of `ghidra.app.plugin.match.SubroutineMatchSet`.
pub struct SubroutineMatchSet {
    /// The program from which the matching was initiated.
    pub a_program: Arc<dyn Program>,
    /// The program being matched.
    pub b_program: Arc<dyn Program>,
    a_model: Box<dyn CodeBlockModel>,
    b_model: Box<dyn CodeBlockModel>,
    matches: Vec<SubroutineMatch>,
}

impl SubroutineMatchSet {
    /// Creates a new, empty match set between `a_program`/`a_model` and `b_program`/`b_model`.
    ///
    /// Port of `SubroutineMatchSet(Program aProgram, CodeBlockModel aModel, Program bProgram,
    /// CodeBlockModel bModel)`. Java's constructor also eagerly captures
    /// `aProgram.getSymbolTable()`/`bProgram.getSymbolTable()` into `aSymbolTable`/`bSymbolTable`
    /// fields; per [`FunctionMatchSet`](crate::app::plugin::match::FunctionMatchSet)'s identical
    /// precedent (see its own module docs), this port does not store those handles as fields --
    /// `Program::get_symbol_table` returns `&mut dyn SymbolTable` borrowed from `&mut self`, which
    /// cannot be held alongside the `Arc<dyn Program>` fields here -- and instead computes them on
    /// demand in [`Self::get_a_table`]/[`Self::get_b_table`].
    pub fn new(
        a_program: Arc<dyn Program>,
        a_model: Box<dyn CodeBlockModel>,
        b_program: Arc<dyn Program>,
        b_model: Box<dyn CodeBlockModel>,
    ) -> Self {
        SubroutineMatchSet {
            a_program,
            b_program,
            a_model,
            b_model,
            matches: Vec::new(),
        }
    }

    /// Returns the matches as an array, in their current (insertion) order.
    ///
    /// Port of `SubroutineMatch[] getMatches()`.
    pub fn get_matches(&self) -> Vec<SubroutineMatch> {
        self.matches.clone()
    }

    /// Returns the length, in addresses, of the code block containing `addr` according to
    /// `model`.
    ///
    /// Port of `int getLength(Address addr, CodeBlockModel model)`. Java calls
    /// `model.getCodeBlockAt(addr, null)` -- passing a `null` `TaskMonitor` -- and returns `0` if
    /// that call throws *or* if it returns `null` (a subsequent `block.getNumAddresses()` NPE,
    /// also caught by the same blanket `catch (Exception e)`). [`DummyMonitor`] stands in for the
    /// `null` monitor (matching this crate's convention elsewhere for a null/no-op
    /// `TaskMonitor`); both the `Err` (cancelled) and `Ok(None)` (no block at that address) cases
    /// are folded into the same `0` result, mirroring Java's blanket catch.
    pub fn get_length_in(&self, addr: &Address, model: &dyn CodeBlockModel) -> i32 {
        match model.get_code_block_at(addr, &DummyMonitor) {
            Ok(Some(block)) => block.num_addresses() as i32,
            Ok(None) | Err(_) => 0,
        }
    }

    /// Same as [`Self::get_length_in`], assuming `addr` is in `a_program`, using [`Self::a_model`].
    ///
    /// Port of `int getLength(Address addr)`.
    pub fn get_length(&self, addr: &Address) -> i32 {
        self.get_length_in(addr, self.a_model.as_ref())
    }

    /// Returns the code-block model for `a_program`.
    ///
    /// Ported from the package-private `SubroutineMatchSet.getAModel`.
    pub(crate) fn a_model(&self) -> &dyn CodeBlockModel {
        self.a_model.as_ref()
    }

    /// Returns the code-block model for `b_program`.
    ///
    /// Ported from the package-private `SubroutineMatchSet.getBModel`.
    pub(crate) fn b_model(&self) -> &dyn CodeBlockModel {
        self.b_model.as_ref()
    }

    /// Returns the symbol table for `a_program`, if it is currently uniquely owned.
    ///
    /// Ported from the package-private `SubroutineMatchSet.getATable`. See [`Self::new`]'s docs
    /// for why this is computed on demand rather than cached in a field.
    pub(crate) fn get_a_table(&mut self) -> Option<&mut dyn SymbolTable> {
        Arc::get_mut(&mut self.a_program)?.get_symbol_table()
    }

    /// Returns the symbol table for `b_program`, if it is currently uniquely owned.
    ///
    /// Ported from the package-private `SubroutineMatchSet.getBTable`. See [`Self::new`]'s docs.
    pub(crate) fn get_b_table(&mut self) -> Option<&mut dyn SymbolTable> {
        Arc::get_mut(&mut self.b_program)?.get_symbol_table()
    }
}

impl Deref for SubroutineMatchSet {
    type Target = Vec<SubroutineMatch>;

    fn deref(&self) -> &Vec<SubroutineMatch> {
        &self.matches
    }
}

impl DerefMut for SubroutineMatchSet {
    fn deref_mut(&mut self) -> &mut Vec<SubroutineMatch> {
        &mut self.matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::block::{CodeBlock, CodeBlockIterator, CodeBlockReferenceIterator};
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::FlowType;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;
    use std::io;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct NoListingProgram;
    impl crate::framework::model::DomainObject for NoListingProgram {}
    impl Program for NoListingProgram {
        fn get_name(&self) -> String {
            "no-listing".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    fn no_listing_program() -> Arc<dyn Program> {
        Arc::new(NoListingProgram)
    }

    struct MockSymbolTable;
    impl SymbolTable for MockSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
    }

    struct ProgramWithSymbolTable {
        table: MockSymbolTable,
    }
    impl crate::framework::model::DomainObject for ProgramWithSymbolTable {}
    impl Program for ProgramWithSymbolTable {
        fn get_name(&self) -> String {
            "with-table".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.table)
        }
    }

    fn program_with_symbol_table() -> Arc<dyn Program> {
        Arc::new(ProgramWithSymbolTable { table: MockSymbolTable })
    }

    /// A single-entry `CodeBlock` covering a fixed address range, for [`SingleEntryModel`].
    /// Delegates every [`crate::program::model::address::AddressSetView`] method to an inner,
    /// already-fully-implemented [`AddressSet`], since that trait declares no defaults.
    struct FixedBlock {
        set: AddressSet,
    }
    impl crate::program::model::address::AddressSetView for FixedBlock {
        fn contains(&self, address: &Address) -> bool {
            self.set.contains(address)
        }
        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            self.set.contains_range(start, end)
        }
        fn contains_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
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
        fn address_ranges(&self) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            self.set.address_ranges()
        }
        fn address_ranges_ordered(
            &self,
            forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            self.set.address_ranges_ordered(forward)
        }
        fn address_ranges_from(
            &self,
            start: &Address,
            forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            self.set.address_ranges_from(start, forward)
        }
        fn num_addresses(&self) -> u64 {
            self.set.num_addresses()
        }
        fn addresses(&self, forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            self.set.addresses(forward)
        }
        fn addresses_from(
            &self,
            start: &Address,
            forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            self.set.addresses_from(start, forward)
        }
        fn intersects_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            self.set.intersects_set(set)
        }
        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.set.intersects_range(start, end)
        }
        fn intersect(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.set.intersect(set)
        }
        fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
            self.set.intersect_range(start, end)
        }
        fn union(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.set.union(set)
        }
        fn subtract(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.set.subtract(set)
        }
        fn xor(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.set.xor(set)
        }
        fn has_same_addresses(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            self.set.has_same_addresses(set)
        }
        fn first_range(&self) -> Option<crate::program::model::address::AddressRange> {
            self.set.first_range()
        }
        fn last_range(&self) -> Option<crate::program::model::address::AddressRange> {
            self.set.last_range()
        }
        fn range_containing(&self, address: &Address) -> Option<crate::program::model::address::AddressRange> {
            self.set.range_containing(address)
        }
        fn find_first_address_in_common(
            &self,
            set: &dyn crate::program::model::address::AddressSetView,
        ) -> Option<Address> {
            self.set.find_first_address_in_common(set)
        }
    }
    impl CodeBlock for FixedBlock {
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("not exercised by these tests")
        }
        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not exercised by these tests")
        }
    }

    /// A `CodeBlockModel` returning a fixed block for one specific address, and `None` for every
    /// other address (standing in for "no block found", the `Ok(None)` branch of
    /// [`SubroutineMatchSet::get_length_in`]).
    struct SingleEntryModel {
        entry: Address,
        block_len: u64,
    }
    impl CodeBlockModel for SingleEntryModel {
        fn get_name(&self) -> String {
            "SingleEntryModel".to_string()
        }
        fn get_code_block_at(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            if *addr != self.entry {
                return Ok(None);
            }
            let end = Address::new(addr.space().clone(), addr.offset() + self.block_len as i64 - 1);
            Ok(Some(Box::new(FixedBlock {
                set: AddressSet::from_range(crate::program::model::address::AddressRange::new(
                    addr.clone(),
                    end,
                )),
            })))
        }
        fn get_flow_type(&self, _block: &dyn CodeBlock) -> Box<dyn FlowType> {
            unimplemented!("not exercised by these tests")
        }
        fn get_block_name(&self, _block: &dyn CodeBlock) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by these tests")
        }
        fn get_first_code_block_containing(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            Ok(None)
        }
        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_code_blocks_containing(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockIterator>, CancelledException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_num_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            Ok(0)
        }
        fn get_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_num_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            Ok(0)
        }
        fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn model_with_block_at(entry: Address, len: u64) -> Box<dyn CodeBlockModel> {
        Box::new(SingleEntryModel { entry, block_len: len })
    }

    fn empty_model() -> Box<dyn CodeBlockModel> {
        Box::new(SingleEntryModel { entry: addr(-1), block_len: 0 })
    }

    #[test]
    fn new_creates_empty_set_with_programs() {
        let a = no_listing_program();
        let b = no_listing_program();
        let set = SubroutineMatchSet::new(Arc::clone(&a), empty_model(), Arc::clone(&b), empty_model());
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(Arc::ptr_eq(&set.a_program, &a));
        assert!(Arc::ptr_eq(&set.b_program, &b));
    }

    #[test]
    fn deref_supports_vec_like_push_and_len() {
        let mut set = SubroutineMatchSet::new(
            no_listing_program(),
            empty_model(),
            no_listing_program(),
            empty_model(),
        );
        set.push(SubroutineMatch::new("reason a"));
        set.push(SubroutineMatch::new("reason b"));
        assert_eq!(set.len(), 2);
        assert_eq!(set.first().unwrap().get_reason(), "reason a");
    }

    #[test]
    fn get_matches_returns_current_contents() {
        let mut set = SubroutineMatchSet::new(
            no_listing_program(),
            empty_model(),
            no_listing_program(),
            empty_model(),
        );
        set.push(SubroutineMatch::new("only"));
        let matches = set.get_matches();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_reason(), "only");
    }

    #[test]
    fn get_length_in_returns_the_containing_blocks_address_count() {
        let set = SubroutineMatchSet::new(
            no_listing_program(),
            model_with_block_at(addr(0x1000), 16),
            no_listing_program(),
            empty_model(),
        );
        assert_eq!(set.get_length_in(&addr(0x1000), set.a_model()), 16);
    }

    #[test]
    fn get_length_in_returns_zero_when_no_block_found() {
        let set = SubroutineMatchSet::new(
            no_listing_program(),
            model_with_block_at(addr(0x1000), 16),
            no_listing_program(),
            empty_model(),
        );
        assert_eq!(set.get_length_in(&addr(0x2000), set.a_model()), 0);
    }

    #[test]
    fn get_length_delegates_to_a_model() {
        let set = SubroutineMatchSet::new(
            no_listing_program(),
            model_with_block_at(addr(0x1000), 8),
            no_listing_program(),
            model_with_block_at(addr(0x1000), 999),
        );
        // Uses a_model, not b_model, despite both having a block at the same address.
        assert_eq!(set.get_length(&addr(0x1000)), 8);
    }

    #[test]
    fn get_a_table_returns_symbol_table_when_uniquely_owned() {
        let mut set = SubroutineMatchSet::new(
            program_with_symbol_table(),
            empty_model(),
            no_listing_program(),
            empty_model(),
        );
        assert!(set.get_a_table().is_some());
    }

    #[test]
    fn get_a_table_returns_none_when_shared() {
        let a = program_with_symbol_table();
        let _clone = Arc::clone(&a);
        let mut set = SubroutineMatchSet::new(a, empty_model(), no_listing_program(), empty_model());
        assert!(set.get_a_table().is_none());
    }

    #[test]
    fn get_b_table_returns_symbol_table_when_uniquely_owned() {
        let mut set = SubroutineMatchSet::new(
            no_listing_program(),
            empty_model(),
            program_with_symbol_table(),
            empty_model(),
        );
        assert!(set.get_b_table().is_some());
    }
}
