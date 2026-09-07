//! Port of `ghidra.program.database.code.CodeUnitKeyIterator`.
//!
//! Java's constructor takes only a `CodeManager` and relies on that manager's own (package-
//! private) `getCodeUnitAt(long)` overload to resolve each raw address-map key directly, without
//! decoding it to an `Address` first. This port's [`CodeManager`] trait only carries the public
//! `getCodeUnitAt(Address)` overload -- the package-private raw-key overload was out of scope for
//! that port -- so this port takes an explicit [`AddressMap`] reference and decodes each key
//! itself before calling [`CodeManager::get_code_unit_at`]. Same observable result.

use crate::program::database::code::code_manager::CodeManager;
use crate::program::database::map::AddressMap;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::code_unit_iterator::CodeUnitIterator;
use crate::program::seam_stubs::AddressKeyIteratorLike;
use std::sync::Arc;

/// Converts an [`AddressKeyIteratorLike`] into a [`CodeUnitIterator`].
///
/// Port of `ghidra.program.database.code.CodeUnitKeyIterator`. See the module docs for the
/// `AddressMap` deviation.
pub struct CodeUnitKeyIterator<'a> {
    code_mgr: &'a dyn CodeManager,
    addr_map: &'a dyn AddressMap,
    it: Box<dyn AddressKeyIteratorLike>,
    forward: bool,
}

impl<'a> CodeUnitKeyIterator<'a> {
    /// Constructs a new `CodeUnitKeyIterator`. `code_mgr` is used to resolve the code unit at each
    /// decoded address; `addr_map` decodes the raw keys `it` yields; `forward` is the direction
    /// to iterate.
    pub fn new(
        code_mgr: &'a dyn CodeManager,
        addr_map: &'a dyn AddressMap,
        it: Box<dyn AddressKeyIteratorLike>,
        forward: bool,
    ) -> Self {
        CodeUnitKeyIterator {
            code_mgr,
            addr_map,
            it,
            forward,
        }
    }
}

impl<'a> Iterator for CodeUnitKeyIterator<'a> {
    type Item = Arc<dyn CodeUnit>;

    fn next(&mut self) -> Option<Arc<dyn CodeUnit>> {
        loop {
            let key = if self.forward {
                if !self.it.has_next() {
                    return None;
                }
                self.it.next()?
            } else {
                if !self.it.has_previous() {
                    return None;
                }
                self.it.previous()?
            };
            let addr = self.addr_map.decode_address(key);
            if let Some(cu) = self.code_mgr.get_code_unit_at(&addr) {
                return Some(cu);
            }
        }
    }
}

impl<'a> CodeUnitIterator for CodeUnitKeyIterator<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::manager_db::ManagerDB;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType, KeyRange};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::ProcessorContextView;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::instruction::Instruction;
    use crate::program::model::listing::CommentType;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, ReferenceManager, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CodeUnitComments, CommentHistory, DataIterator, InstructionIterator, InstructionSet};
    use crate::program::util::CodeUnitInsertionException;
    use crate::program::model::listing::program::Program;
    use crate::docking::settings::settings::Settings;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::io;

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    struct MockAddressMap {
        base: Address,
    }

    impl AddressMap for MockAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }
        fn decode_address(&self, value: i64) -> Address {
            Address::new(self.base.space().clone(), value)
        }
        fn get_address_factory(
            &self,
        ) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn crate::program::model::address::AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(MockAddressMap {
                base: self.base.clone(),
            })
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            self.base.clone()
        }
    }

    struct VecKeyIterator {
        keys: Vec<i64>,
        forward_pos: usize,
        backward_pos: usize,
    }

    impl VecKeyIterator {
        fn new(keys: Vec<i64>) -> Self {
            let len = keys.len();
            VecKeyIterator {
                keys,
                forward_pos: 0,
                backward_pos: len,
            }
        }
    }

    impl AddressKeyIteratorLike for VecKeyIterator {
        fn has_next(&mut self) -> bool {
            self.forward_pos < self.keys.len()
        }
        fn has_previous(&mut self) -> bool {
            self.backward_pos > 0
        }
        fn next(&mut self) -> Option<i64> {
            if self.forward_pos < self.keys.len() {
                let v = self.keys[self.forward_pos];
                self.forward_pos += 1;
                Some(v)
            } else {
                None
            }
        }
        fn previous(&mut self) -> Option<i64> {
            if self.backward_pos > 0 {
                self.backward_pos -= 1;
                Some(self.keys[self.backward_pos])
            } else {
                None
            }
        }
    }

    /// A minimal `CodeUnit` whose only meaningful behavior is reporting its own address; every
    /// other method is unreachable from these tests.
    struct MockCodeUnit {
        address: Address,
    }

    impl MemBuffer for MockCodeUnit {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

    impl PropertySet for MockCodeUnit {}
    impl Settings for MockCodeUnit {}

    impl CodeUnit for MockCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            String::new()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            *test_addr == self.address
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            unimplemented!("not needed for this test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this test")
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            0
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    /// A `CodeManager` whose only meaningful behavior is `get_code_unit_at`, resolving a fixed
    /// set of present addresses; every other method is unreachable from these tests.
    struct MapBackedCodeManager {
        present: BTreeMap<i64, ()>,
    }

    impl ManagerDB for MapBackedCodeManager {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            Ok(())
        }
        fn delete_address_range(&mut self, _start_addr: &Address, _end_addr: &Address) -> io::Result<()> {
            Ok(())
        }
        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl CodeManager for MapBackedCodeManager {
        fn activate_context_locking(&mut self) {}

        fn add_instructions(
            &mut self,
            _instruction_set: &dyn InstructionSet,
            _overwrite: bool,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this test")
        }

        fn create_instruction(
            &mut self,
            _address: Address,
            _prototype: Arc<dyn InstructionPrototype>,
            _mem_buf: &dyn MemBuffer,
            _context: &dyn ProcessorContextView,
            _length: i32,
        ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this test")
        }

        fn create_data(
            &mut self,
            _address: Address,
            _data_type: Box<dyn DataType>,
            _length: i32,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!("not exercised by this test")
        }

        fn get_code_unit_at(&self, address: &Address) -> Option<Arc<dyn CodeUnit>> {
            if self.present.contains_key(&address.offset()) {
                Some(Arc::new(MockCodeUnit {
                    address: address.clone(),
                }))
            } else {
                None
            }
        }

        fn get_code_unit_after(&self, _address: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_before(&self, _address: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_containing(&self, _address: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_user_defined_properties(&self) -> Vec<String> {
            Vec::new()
        }
        fn remove_user_defined_property(&mut self, _property_name: &str) {}
        fn get_property_map(
            &self,
            _property_name: &str,
        ) -> Option<Box<dyn crate::program::model::util::PropertyMap>> {
            None
        }
        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _address: &Address,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: CommentType,
            _set: &dyn AddressSetView,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_comment_address_count(&self) -> i64 {
            0
        }
        fn get_comment_address_iterator(
            &self,
            _comment_type: CommentType,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not exercised by this test")
        }
        fn get_any_comment_address_iterator(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not exercised by this test")
        }
        fn get_instruction_at(&self, _address: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_defined_data_at(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_instruction_before(&self, _address: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_after(&self, _address: &Address) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_instruction_containing(
            &self,
            _address: &Address,
            _use_prototype_length: bool,
        ) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_data_at(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_before(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_after(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_containing(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_after(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_before(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_containing(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_ranges(
            &self,
            _set: &dyn AddressSetView,
            _initialized_memory_only: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn AddressSetView>, CancelledException> {
            unimplemented!("not exercised by this test")
        }
        fn get_undefined_data_at(&self, _address: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_after(
            &self,
            _address: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_first_undefined_data(
            &self,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_before(
            &self,
            _address: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn update_data_references(&mut self, _data: &dyn Data) {}
        fn clear_comments(&mut self, _start: &Address, _end: &Address) {}
        fn clear_properties(
            &mut self,
            _start: &Address,
            _end: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn clear_code_units(
            &mut self,
            _start: &Address,
            _end: &Address,
            _clear_context: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn clear_all(&mut self, _clear_context: bool, _monitor: &dyn TaskMonitor) {}
        fn get_num_instructions(&self) -> i32 {
            0
        }
        fn get_num_defined_data(&self) -> i32 {
            0
        }
        fn get_code_units_from(&self, _start: &Address, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_code_units_in(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_instructions_from(
            &self,
            _address: &Address,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_defined_data_from(&self, _address: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_instructions_in(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_data_from(&self, _start: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_data_in(&self, _set: &dyn AddressSetView, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_defined_data_in(
            &self,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this test")
        }
        fn check_context_write(
            &self,
            _start: &Address,
            _end: &Address,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn is_undefined(&self, _start: &Address, _end: &Address) -> bool {
            true
        }
        fn clear_data(
            &mut self,
            _data_type_ids: &HashSet<i64>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn get_reference_mgr(&mut self) -> &mut dyn ReferenceManager {
            unimplemented!("not exercised by this test")
        }
        fn invalidate_code_unit_cache(&mut self) {}
        fn memory_changed(&mut self, _start: &Address, _end: &Address) {}
        fn fall_through_changed(
            &mut self,
            _from_addr: &Address,
            _new_fall_through_ref: Option<Arc<dyn Reference>>,
        ) {
        }
        fn get_comment(&self, _comment_type: CommentType, _address: &Address) -> Option<String> {
            None
        }
        fn get_all_comments(&self, _address: &Address) -> Box<dyn CodeUnitComments> {
            struct MockComments;
            impl CodeUnitComments for MockComments {}
            Box::new(MockComments)
        }
        fn set_comment(
            &mut self,
            _address: &Address,
            _comment_type: CommentType,
            _comment: Option<String>,
        ) {
        }
        fn get_comment_history(
            &self,
            _address: &Address,
            _comment_type: CommentType,
        ) -> Vec<Box<dyn CommentHistory>> {
            Vec::new()
        }
        fn replace_data_types(&mut self, _data_type_replacement_map: &HashMap<i64, i64>) {}
        fn re_disassemble_all_instructions(
            &mut self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::program::database::code::code_manager::ReDisassembleAllInstructionsError>
        {
            unimplemented!("not exercised by this test")
        }
        fn get_instruction_from_record(
            &self,
            _record: &crate::framework::db::DBRecord,
        ) -> Option<Arc<dyn Instruction>> {
            None
        }
    }

    #[test]
    fn forward_iteration_skips_keys_with_no_code_unit() {
        let mut present = BTreeMap::new();
        present.insert(0x1000, ());
        present.insert(0x3000, ());
        let code_mgr = MapBackedCodeManager { present };
        let addr_map = MockAddressMap { base: space().address(0) };
        let keys = VecKeyIterator::new(vec![0x1000, 0x2000, 0x3000]);

        let mut iter = CodeUnitKeyIterator::new(&code_mgr, &addr_map, Box::new(keys), true);
        assert_eq!(iter.next().unwrap().get_min_address(), space().address(0x1000));
        assert_eq!(iter.next().unwrap().get_min_address(), space().address(0x3000));
        assert!(iter.next().is_none());
    }

    #[test]
    fn backward_iteration_walks_in_reverse() {
        let mut present = BTreeMap::new();
        present.insert(0x1000, ());
        present.insert(0x2000, ());
        let code_mgr = MapBackedCodeManager { present };
        let addr_map = MockAddressMap { base: space().address(0) };
        let keys = VecKeyIterator::new(vec![0x1000, 0x2000]);

        let mut iter = CodeUnitKeyIterator::new(&code_mgr, &addr_map, Box::new(keys), false);
        assert_eq!(iter.next().unwrap().get_min_address(), space().address(0x2000));
        assert_eq!(iter.next().unwrap().get_min_address(), space().address(0x1000));
        assert!(iter.next().is_none());
    }

    #[test]
    fn empty_when_no_keys_resolve() {
        let code_mgr = MapBackedCodeManager {
            present: BTreeMap::new(),
        };
        let addr_map = MockAddressMap { base: space().address(0) };
        let keys = VecKeyIterator::new(vec![0x1000]);

        let mut iter = CodeUnitKeyIterator::new(&code_mgr, &addr_map, Box::new(keys), true);
        assert!(iter.next().is_none());
    }
}
