//! Port of `ghidra.program.database.code.CodeUnitRecordIterator`.
//!
//! Merges an [`InstructionIterator`] and a [`DataIterator`] into one [`CodeUnitIterator`], filling
//! every gap between them (within the given address set) with `codeMgr.getUndefinedAt(address)`.
//!
//! Both source iterators yield code units at increasing (or, `forward == false`, decreasing)
//! addresses; this walks all three sequences (instructions, data, and the raw address set) in
//! lock step, at each step picking whichever of the two defined code units starts first (in the
//! iteration direction) provided it actually covers the current address, and falling back to an
//! undefined code unit otherwise.

use std::sync::Arc;

use crate::program::database::code::code_manager::CodeManager;
use crate::program::model::address::{Address, AddressSetView, BoxedAddressIterator};
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::code_unit_iterator::CodeUnitIterator;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::data_iterator::DataIterator;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::instruction_iterator::InstructionIterator;

/// Which of the two source iterators a lookahead code unit came from, standing in for the
/// `nextDefined == nextInst` reference-identity check Java's `findNext()` performs -- not
/// expressible here since selecting a value out of `Option<Arc<..>>`/`Option<Box<..>>` moves it,
/// so the "which one was it" fact is tracked explicitly instead.
enum Pick {
    Instruction,
    Data,
}

/// Combines an Instruction iterator and Data iterator into a code unit iterator.
///
/// Port of `ghidra.program.database.code.CodeUnitRecordIterator`.
pub struct CodeUnitRecordIterator<'cm> {
    code_mgr: &'cm dyn CodeManager,
    inst_it: Box<dyn InstructionIterator>,
    data_it: Box<dyn DataIterator>,
    addr_it: BoxedAddressIterator,
    forward: bool,

    next_addr: Option<Address>,
    next_inst: Option<Arc<dyn Instruction>>,
    next_data: Option<Box<dyn Data>>,
    next_cu: Option<Arc<dyn CodeUnit>>,
}

impl<'cm> CodeUnitRecordIterator<'cm> {
    /// Constructs a new `CodeUnitRecordIterator`.
    ///
    /// # Arguments
    /// * `code_mgr` - the code manager
    /// * `inst_it` - the instruction iterator
    /// * `data_it` - the data iterator
    /// * `set` - the address set (required)
    /// * `forward` - the iterator direction
    pub fn new(
        code_mgr: &'cm dyn CodeManager,
        mut inst_it: Box<dyn InstructionIterator>,
        mut data_it: Box<dyn DataIterator>,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> Self {
        let mut addr_it = set.addresses(forward);
        let next_addr = addr_it.next();
        let next_data = data_it.next();
        let next_inst = inst_it.next();
        CodeUnitRecordIterator {
            code_mgr,
            inst_it,
            data_it,
            addr_it,
            forward,
            next_addr,
            next_inst,
            next_data,
            next_cu: None,
        }
    }

    /// Port of the private `CodeUnitRecordIterator.findNext()`.
    fn find_next(&mut self) {
        while self.next_addr.is_some() && self.next_cu.is_none() {
            let next_addr = self.next_addr.clone().unwrap();

            let mut pick = match (&self.next_inst, &self.next_data) {
                (None, None) => None,
                (Some(_), None) => Some(Pick::Instruction),
                (None, Some(_)) => Some(Pick::Data),
                (Some(inst), Some(data)) => {
                    let c = inst.get_min_address().cmp(&data.get_min_address());
                    let c = if self.forward { c } else { c.reverse() };
                    if c == std::cmp::Ordering::Less {
                        Some(Pick::Instruction)
                    } else {
                        Some(Pick::Data)
                    }
                }
            };

            if let Some(candidate) = &pick {
                let contains = match candidate {
                    Pick::Instruction => self.next_inst.as_ref().unwrap().contains(&next_addr),
                    Pick::Data => self.next_data.as_ref().unwrap().contains(&next_addr),
                };
                if !contains {
                    pick = None;
                }
            }

            let next_defined: Option<Arc<dyn CodeUnit>> = match pick {
                Some(Pick::Instruction) => {
                    let instruction = self.next_inst.take().unwrap();
                    self.next_inst = self.inst_it.next();
                    Some(instruction as Arc<dyn CodeUnit>)
                }
                Some(Pick::Data) => {
                    let data = self.next_data.take().unwrap();
                    self.next_data = self.data_it.next();
                    let data: Arc<dyn Data> = Arc::from(data);
                    Some(data as Arc<dyn CodeUnit>)
                }
                None => self
                    .code_mgr
                    .get_undefined_data_at(&next_addr)
                    .map(|data| data as Arc<dyn CodeUnit>),
            };

            self.next_addr = self.get_next_addr(next_addr, next_defined.as_deref());
            self.next_cu = next_defined;
        }
    }

    /// Port of the private `CodeUnitRecordIterator.getNextAddr(Address, CodeUnit)`.
    fn get_next_addr(&mut self, addr: Address, cu: Option<&dyn CodeUnit>) -> Option<Address> {
        let Some(cu) = cu else {
            return self.addr_it.next();
        };
        let mut addr = Some(addr);
        if self.forward {
            let end = cu.get_max_address();
            while let Some(current) = addr.clone() {
                if current <= end {
                    addr = self.addr_it.next();
                } else {
                    break;
                }
            }
        } else {
            let start = cu.get_min_address();
            while let Some(current) = addr.clone() {
                if current >= start {
                    addr = self.addr_it.next();
                } else {
                    break;
                }
            }
        }
        addr
    }
}

impl<'cm> Iterator for CodeUnitRecordIterator<'cm> {
    type Item = Arc<dyn CodeUnit>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_cu.is_none() {
            self.find_next();
        }
        self.next_cu.take()
    }
}

impl<'cm> CodeUnitIterator for CodeUnitRecordIterator<'cm> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::code::code_manager::ReDisassembleAllInstructionsError;
    use crate::program::database::manager_db::ManagerDB;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::listing::CommentType;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::symbol::{Reference, ReferenceManager};
    use crate::program::seam_stubs::{CodeUnitComments, CommentHistory, InstructionSet};
    use crate::program::util::CodeUnitInsertionException;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;
    use std::collections::{HashMap, HashSet};
    use std::io;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    /// A `CodeUnit` fixture with just enough behavior for merge-order assertions: an address
    /// range and a fixed mnemonic distinguishing instructions from data in test output.
    struct FixtureCodeUnit {
        min: Address,
        max: Address,
        mnemonic: &'static str,
    }

    impl MemBuffer for FixtureCodeUnit {
        fn get_address(&self) -> Address {
            self.min.clone()
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
    }
    impl crate::program::model::util::PropertySet for FixtureCodeUnit {}
    impl CodeUnit for FixtureCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            self.mnemonic.to_string()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn crate::program::model::symbol::Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.min.clone()
        }
        fn get_max_address(&self) -> Address {
            self.max.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            self.mnemonic.to_string()
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
            (self.max.offset() - self.min.offset() + 1) as i32
        }
        fn get_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            *test_addr >= self.min && *test_addr <= self.max
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
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
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not exercised by these tests")
        }
        fn get_external_reference(
            &self,
            _op_index: i32,
        ) -> Option<Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            0
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }

    impl crate::program::model::lang::ProcessorContextView for FixtureCodeUnit {
        fn get_base_context_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register(&self, _name: &str) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_value(&self, _register: &crate::program::model::lang::register::Register, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(
            &self,
            _register: &crate::program::model::lang::register::Register,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }
        fn has_value(&self, _register: &crate::program::model::lang::register::Register) -> bool {
            false
        }
    }
    impl crate::program::model::lang::ProcessorContext for FixtureCodeUnit {
        fn set_value(
            &mut self,
            _register: &crate::program::model::lang::register::Register,
            _value: i128,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn set_register_value(
            &mut self,
            _value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(
            &mut self,
            _register: &crate::program::model::lang::register::Register,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }
    impl Instruction for FixtureCodeUnit {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            unimplemented!("not exercised by these tests")
        }
        fn get_register(&self, _operand_index: i32) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_op_objects(&self, _operand_index: i32) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }
        fn get_input_objects(&self) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }
        fn get_result_objects(&self) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }
        fn get_default_operand_representation(&self, _operand_index: i32) -> String {
            String::new()
        }
        fn get_default_operand_representation_list(
            &self,
            _operand_index: i32,
        ) -> Option<Vec<crate::program::model::listing::instruction::OperandValue>> {
            None
        }
        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }
        fn get_operand_type(&self, _operand_index: i32) -> i32 {
            0
        }
        fn get_operand_ref_type(&self, _operand_index: i32) -> crate::program::model::symbol::RefType {
            crate::program::model::symbol::RefType::Data
        }
        fn get_default_fall_through_offset(&self) -> i32 {
            self.get_length()
        }
        fn get_default_fall_through(&self) -> Option<Address> {
            None
        }
        fn get_fall_through(&self) -> Option<Address> {
            None
        }
        fn get_fall_from(&self) -> Option<Address> {
            None
        }
        fn get_flows(&self) -> Option<Vec<Address>> {
            None
        }
        fn get_default_flows(&self) -> Option<Vec<Address>> {
            None
        }
        fn get_flow_type(&self) -> crate::program::model::symbol::RefType {
            crate::program::model::symbol::RefType::FallThrough
        }
        fn is_fallthrough(&self) -> bool {
            true
        }
        fn has_fallthrough(&self) -> bool {
            true
        }
        fn get_flow_override(&self) -> crate::program::model::listing::FlowOverride {
            crate::program::model::listing::FlowOverride::None
        }
        fn set_flow_override(&mut self, _flow_override: crate::program::model::listing::FlowOverride) {}
        fn set_length_override(&mut self, _length: i32) -> Result<(), CodeUnitInsertionException> {
            Ok(())
        }
        fn is_length_overridden(&self) -> bool {
            false
        }
        fn get_parsed_length(&self) -> i32 {
            self.get_length()
        }
        fn get_parsed_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_pcode(&self) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }
        fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }
        fn get_pcode_for_operand(&self, _operand_index: i32) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }
        fn get_delay_slot_depth(&self) -> i32 {
            0
        }
        fn is_in_delay_slot(&self) -> bool {
            false
        }
        fn get_next(&self) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
            None
        }
        fn set_fall_through(&mut self, _addr: Option<Address>) {}
        fn clear_fall_through_override(&mut self) {}
        fn is_fall_through_overridden(&self) -> bool {
            false
        }
        fn get_instruction_context(&self) -> Arc<dyn crate::program::seam_stubs::InstructionContext> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn instruction(min: i64, max: i64) -> Arc<dyn Instruction> {
        Arc::new(FixtureCodeUnit {
            min: space().address(min),
            max: space().address(max),
            mnemonic: "INST",
        })
    }

    fn data(min: i64, max: i64) -> Box<dyn Data> {
        // `FixtureCodeUnit` does not implement `Data`; a bare `Instruction` value works equally
        // well as a `Data` stand-in for these tests since only `CodeUnit` methods
        // (`get_min_address`/`get_max_address`/`contains`) are ever exercised on it here, and the
        // iterator only distinguishes "came from `data_it`" vs "came from `inst_it`" structurally
        // (by which field it was pulled from), not by an `instanceof Data` check.
        struct DataFixture(FixtureCodeUnit);
        impl MemBuffer for DataFixture {
            fn get_address(&self) -> Address {
                MemBuffer::get_address(&self.0)
            }
            fn get_byte(&self, o: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
                MemBuffer::get_byte(&self.0, o)
            }
            fn get_bytes(&self, b: &mut [u8], o: i32) -> usize {
                MemBuffer::get_bytes(&self.0, b, o)
            }
            fn is_big_endian(&self) -> bool {
                MemBuffer::is_big_endian(&self.0)
            }
        }
        impl crate::program::model::util::PropertySet for DataFixture {}
        impl CodeUnit for DataFixture {
            fn get_address_string(&self, s: bool, p: bool) -> String {
                self.0.get_address_string(s, p)
            }
            fn get_label(&self) -> Option<String> {
                None
            }
            fn get_symbols(&self) -> Vec<Arc<dyn crate::program::model::symbol::Symbol>> {
                Vec::new()
            }
            fn get_primary_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
                None
            }
            fn get_min_address(&self) -> Address {
                self.0.get_min_address()
            }
            fn get_max_address(&self) -> Address {
                self.0.get_max_address()
            }
            fn get_mnemonic_string(&self) -> String {
                "db".to_string()
            }
            fn get_comment(&self, _c: CommentType) -> Option<String> {
                None
            }
            fn get_comment_as_array(&self, _c: CommentType) -> Vec<String> {
                Vec::new()
            }
            fn set_comment(&mut self, _c: CommentType, _v: Option<String>) {}
            fn set_comment_as_array(&mut self, _c: CommentType, _v: &[String]) {}
            fn get_length(&self) -> i32 {
                self.0.get_length()
            }
            fn get_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
                Ok(Vec::new())
            }
            fn get_bytes_in_code_unit(
                &self,
                _b: &mut [u8],
                _o: i32,
            ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
                Ok(())
            }
            fn contains(&self, addr: &Address) -> bool {
                self.0.contains(addr)
            }
            fn compare_to(&self, addr: &Address) -> i32 {
                self.0.compare_to(addr)
            }
            fn add_mnemonic_reference(
                &mut self,
                _r: Address,
                _t: crate::program::model::symbol::RefType,
                _s: crate::program::model::symbol::SourceType,
            ) {
            }
            fn remove_mnemonic_reference(&mut self, _r: &Address) {}
            fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
                Vec::new()
            }
            fn get_operand_references(&self, _i: i32) -> Vec<Arc<dyn Reference>> {
                Vec::new()
            }
            fn get_primary_reference(&self, _i: i32) -> Option<Arc<dyn Reference>> {
                None
            }
            fn add_operand_reference(
                &mut self,
                _i: i32,
                _r: Address,
                _t: crate::program::model::symbol::RefType,
                _s: crate::program::model::symbol::SourceType,
            ) {
            }
            fn remove_operand_reference(&mut self, _i: i32, _r: &Address) {}
            fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
                Vec::new()
            }
            fn get_reference_iterator_to(&self) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
                Box::new(crate::program::model::symbol::EmptyReferenceIterator)
            }
            fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
                unimplemented!("not exercised by these tests")
            }
            fn get_external_reference(
                &self,
                _i: i32,
            ) -> Option<Arc<dyn crate::program::model::symbol::ExternalReference>> {
                None
            }
            fn remove_external_reference(&mut self, _i: i32) {}
            fn set_primary_memory_reference(&mut self, _r: Arc<dyn Reference>) {}
            fn set_stack_reference(
                &mut self,
                _i: i32,
                _o: i32,
                _s: crate::program::model::symbol::SourceType,
                _t: crate::program::model::symbol::RefType,
            ) {
            }
            fn set_register_reference(
                &mut self,
                _i: i32,
                _r: &crate::program::model::lang::register::Register,
                _s: crate::program::model::symbol::SourceType,
                _t: crate::program::model::symbol::RefType,
            ) {
            }
            fn get_num_operands(&self) -> i32 {
                1
            }
            fn get_address(&self, _i: i32) -> Option<Address> {
                None
            }
            fn get_scalar(&self, _i: i32) -> Option<crate::program::model::scalar::Scalar> {
                None
            }
            fn as_data(&self) -> Option<&dyn Data> {
                Some(self)
            }
        }
        impl crate::docking::settings::settings::Settings for DataFixture {}
        impl Data for DataFixture {
            fn get_value(&self) -> Option<Box<dyn std::any::Any>> {
                None
            }
            fn get_value_class(&self) -> Option<std::any::TypeId> {
                None
            }
            fn has_string_value(&self) -> bool {
                false
            }
            fn is_constant(&self) -> bool {
                false
            }
            fn is_writable(&self) -> bool {
                true
            }
            fn is_volatile(&self) -> bool {
                false
            }
            fn is_defined(&self) -> bool {
                true
            }
            fn get_data_type(&self) -> Box<dyn DataType> {
                struct D;
                impl DataType for D {}
                Box::new(D)
            }
            fn get_base_data_type(&self) -> Box<dyn DataType> {
                struct D;
                impl DataType for D {}
                Box::new(D)
            }
            fn get_value_references(&self) -> Vec<Box<dyn crate::program::seam_stubs::Reference>> {
                Vec::new()
            }
            fn add_value_reference(&mut self, _a: Address, _t: Box<dyn crate::program::seam_stubs::RefType>) {}
            fn remove_value_reference(&mut self, _a: Address) {}
            fn get_field_name(&self) -> Option<String> {
                None
            }
            fn get_path_name(&self) -> String {
                String::new()
            }
            fn get_component_path_name(&self) -> String {
                String::new()
            }
            fn is_pointer(&self) -> bool {
                false
            }
            fn is_union(&self) -> bool {
                false
            }
            fn is_structure(&self) -> bool {
                false
            }
            fn is_array(&self) -> bool {
                false
            }
            fn is_dynamic(&self) -> bool {
                false
            }
            fn get_parent(&self) -> Option<Box<dyn Data>> {
                None
            }
            fn get_root(&self) -> Box<dyn Data> {
                unimplemented!("not exercised by these tests")
            }
            fn get_root_offset(&self) -> i32 {
                0
            }
            fn get_parent_offset(&self) -> i32 {
                0
            }
            fn get_component(&self, _i: i32) -> Option<Box<dyn Data>> {
                None
            }
            fn get_component_by_path(&self, _p: &[i32]) -> Option<Box<dyn Data>> {
                None
            }
            fn get_component_path(&self) -> Vec<i32> {
                Vec::new()
            }
            fn get_num_components(&self) -> i32 {
                0
            }
            #[allow(deprecated)]
            fn get_component_at(&self, _o: i32) -> Option<Box<dyn Data>> {
                None
            }
            fn get_component_containing(&self, _o: i32) -> Option<Box<dyn Data>> {
                None
            }
            fn get_components_containing(&self, _o: i32) -> Option<Vec<Box<dyn Data>>> {
                None
            }
            fn get_primitive_at(&self, _o: i32) -> Option<Box<dyn Data>> {
                None
            }
            fn get_component_index(&self) -> i32 {
                -1
            }
            fn get_component_level(&self) -> i32 {
                0
            }
            fn get_default_value_representation(&self) -> String {
                String::new()
            }
            fn get_default_label_prefix(
                &self,
                _o: &dyn crate::program::model::data::data_type_display_options::DataTypeDisplayOptions,
            ) -> Option<String> {
                None
            }
        }

        Box::new(DataFixture(FixtureCodeUnit {
            min: space().address(min),
            max: space().address(max),
            mnemonic: "db",
        }))
    }

    struct VecInstructionIterator(std::vec::IntoIter<Arc<dyn Instruction>>);
    impl Iterator for VecInstructionIterator {
        type Item = Arc<dyn Instruction>;
        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }
    impl InstructionIterator for VecInstructionIterator {}

    struct VecDataIterator(std::vec::IntoIter<Box<dyn Data>>);
    impl Iterator for VecDataIterator {
        type Item = Box<dyn Data>;
        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
    }
    impl DataIterator for VecDataIterator {}

    /// A `CodeManager` whose only meaningful behavior is `get_undefined_data_at`, reporting a
    /// single-byte "undefined" placeholder for any address not already covered by the fixture's
    /// instructions/data; every other method is unreachable from these tests.
    struct GapFillingCodeManager;

    impl ManagerDB for GapFillingCodeManager {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            Ok(())
        }
        fn delete_address_range(&mut self, _start_addr: &Address, _end_addr: &Address) -> io::Result<()> {
            Ok(())
        }
        fn move_address_range(&mut self, _from_addr: &Address, _to_addr: &Address, _length: u64) -> io::Result<()> {
            Ok(())
        }
    }

    impl CodeManager for GapFillingCodeManager {
        fn activate_context_locking(&mut self) {}
        fn add_instructions(&mut self, _instruction_set: &dyn InstructionSet, _overwrite: bool) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this test")
        }
        fn create_instruction(
            &mut self,
            _address: Address,
            _prototype: Arc<dyn InstructionPrototype>,
            _mem_buf: &dyn MemBuffer,
            _context: &dyn crate::program::model::lang::ProcessorContextView,
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
        fn get_code_unit_at(&self, _address: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
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
        fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn crate::program::model::util::PropertyMap>> {
            None
        }
        fn get_code_unit_iterator_from(&self, _property: &str, _address: &Address, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_code_unit_iterator_in(&self, _property: &str, _addr_set: &dyn AddressSetView, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_comment_code_unit_iterator(&self, _comment_type: CommentType, _set: &dyn AddressSetView) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_comment_address_count(&self) -> i64 {
            0
        }
        fn get_comment_address_iterator(&self, _comment_type: CommentType, _set: &dyn AddressSetView, _forward: bool) -> BoxedAddressIterator {
            unimplemented!("not exercised by this test")
        }
        fn get_any_comment_address_iterator(&self, _set: &dyn AddressSetView, _forward: bool) -> BoxedAddressIterator {
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
        fn get_instruction_containing(&self, _address: &Address, _use_prototype_length: bool) -> Option<Arc<dyn Instruction>> {
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
        fn get_undefined_data_at(&self, address: &Address) -> Option<Arc<dyn Data>> {
            Some(Arc::from(data(address.offset(), address.offset())))
        }
        fn get_undefined_data_after(&self, _address: &Address, _monitor: &dyn TaskMonitor) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_first_undefined_data(&self, _set: &dyn AddressSetView, _monitor: &dyn TaskMonitor) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_before(&self, _address: &Address, _monitor: &dyn TaskMonitor) -> Option<Arc<dyn Data>> {
            None
        }
        fn update_data_references(&mut self, _data: &dyn Data) {}
        fn clear_comments(&mut self, _start: &Address, _end: &Address) {}
        fn clear_properties(&mut self, _start: &Address, _end: &Address, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            Ok(())
        }
        fn clear_code_units(&mut self, _start: &Address, _end: &Address, _clear_context: bool, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
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
        fn get_code_units_in(&self, _set: &dyn AddressSetView, _forward: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_instructions_from(&self, _address: &Address, _forward: bool) -> Box<dyn InstructionIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_defined_data_from(&self, _address: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_instructions_in(&self, _set: &dyn AddressSetView, _forward: bool) -> Box<dyn InstructionIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_data_from(&self, _start: &Address, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_data_in(&self, _set: &dyn AddressSetView, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this test")
        }
        fn get_defined_data_in(&self, _set: &dyn AddressSetView, _forward: bool) -> Box<dyn DataIterator> {
            unimplemented!("not exercised by this test")
        }
        fn check_context_write(&self, _start: &Address, _end: &Address) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn is_undefined(&self, _start: &Address, _end: &Address) -> bool {
            true
        }
        fn clear_data(&mut self, _data_type_ids: &HashSet<i64>, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            Ok(())
        }
        fn get_reference_mgr(&mut self) -> &mut dyn ReferenceManager {
            unimplemented!("not exercised by this test")
        }
        fn invalidate_code_unit_cache(&mut self) {}
        fn memory_changed(&mut self, _start: &Address, _end: &Address) {}
        fn fall_through_changed(&mut self, _from_addr: &Address, _new_fall_through_ref: Option<Arc<dyn Reference>>) {}
        fn get_comment(&self, _comment_type: CommentType, _address: &Address) -> Option<String> {
            None
        }
        fn get_all_comments(&self, _address: &Address) -> Box<dyn CodeUnitComments> {
            struct MockComments;
            impl CodeUnitComments for MockComments {}
            Box::new(MockComments)
        }
        fn set_comment(&mut self, _address: &Address, _comment_type: CommentType, _comment: Option<String>) {}
        fn get_comment_history(&self, _address: &Address, _comment_type: CommentType) -> Vec<Box<dyn CommentHistory>> {
            Vec::new()
        }
        fn replace_data_types(&mut self, _data_type_replacement_map: &HashMap<i64, i64>) {}
        fn re_disassemble_all_instructions(&mut self, _monitor: &dyn TaskMonitor) -> Result<(), ReDisassembleAllInstructionsError> {
            unimplemented!("not exercised by this test")
        }
        fn get_instruction_from_record(&self, _record: &crate::framework::db::DBRecord) -> Option<Arc<dyn Instruction>> {
            None
        }
    }

    #[test]
    fn merges_instructions_data_and_undefined_gaps_in_forward_order() {
        // Layout over [0x1000, 0x100b]:
        //   0x1000-0x1001  instruction
        //   0x1002-0x1002  <undefined gap, filled by the code manager>
        //   0x1003-0x1004  data
        //   0x1005-0x1006  <undefined gap>
        //   0x1007-0x1008  instruction
        let code_mgr = GapFillingCodeManager;
        let inst_it: Box<dyn InstructionIterator> = Box::new(VecInstructionIterator(
            vec![instruction(0x1000, 0x1001), instruction(0x1007, 0x1008)].into_iter(),
        ));
        let data_it: Box<dyn DataIterator> = Box::new(VecDataIterator(
            vec![data(0x1003, 0x1004)].into_iter(),
        ));
        let set = AddressSet::from_range(crate::program::model::address::AddressRange::new(space().address(0x1000), space().address(0x1008)));

        let iter = CodeUnitRecordIterator::new(&code_mgr, inst_it, data_it, &set, true);
        let mnemonics: Vec<(i64, i64, String)> = iter
            .map(|cu| (cu.get_min_address().offset(), cu.get_max_address().offset(), cu.get_mnemonic_string()))
            .collect();

        assert_eq!(
            mnemonics,
            vec![
                (0x1000, 0x1001, "INST".to_string()),
                (0x1002, 0x1002, "db".to_string()), // the gap filler happens to share Data's mnemonic
                (0x1003, 0x1004, "db".to_string()),
                (0x1005, 0x1005, "db".to_string()),
                (0x1006, 0x1006, "db".to_string()),
                (0x1007, 0x1008, "INST".to_string()),
            ]
        );
    }

    #[test]
    fn backward_iteration_visits_the_same_code_units_in_reverse() {
        let code_mgr = GapFillingCodeManager;
        let inst_it: Box<dyn InstructionIterator> = Box::new(VecInstructionIterator(
            vec![instruction(0x1007, 0x1008), instruction(0x1000, 0x1001)].into_iter(),
        ));
        let data_it: Box<dyn DataIterator> = Box::new(VecDataIterator(
            vec![data(0x1003, 0x1004)].into_iter(),
        ));
        let set = AddressSet::from_range(crate::program::model::address::AddressRange::new(space().address(0x1000), space().address(0x1008)));

        let iter = CodeUnitRecordIterator::new(&code_mgr, inst_it, data_it, &set, false);
        let mins: Vec<i64> = iter.map(|cu| cu.get_min_address().offset()).collect();

        assert_eq!(mins, vec![0x1007, 0x1006, 0x1005, 0x1003, 0x1002, 0x1000]);
    }

    #[test]
    fn empty_address_set_yields_nothing() {
        let code_mgr = GapFillingCodeManager;
        let inst_it: Box<dyn InstructionIterator> = Box::new(VecInstructionIterator(Vec::new().into_iter()));
        let data_it: Box<dyn DataIterator> = Box::new(VecDataIterator(Vec::new().into_iter()));
        let set = AddressSet::new();

        let mut iter = CodeUnitRecordIterator::new(&code_mgr, inst_it, data_it, &set, true);
        assert!(iter.next().is_none());
    }
}
