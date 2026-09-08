//! Port of `ghidra.program.database.code.InstructionRecordIterator`.
//!
//! Converts a raw instruction-table [`RecordIterator`] into an [`InstructionIterator`], resolving
//! each record through a [`CodeUnitCache`] the same way `CodeManager` does.

use std::sync::Arc;

use crate::framework::db::RecordIterator;
use crate::program::database::code::code_unit_cache::CodeUnitCache;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::instruction_iterator::InstructionIterator;

/// Converts a record iterator into an instruction iterator.
///
/// Port of `ghidra.program.database.code.InstructionRecordIterator`.
pub struct InstructionRecordIterator<'a> {
    cache: Arc<CodeUnitCache>,
    it: Box<dyn RecordIterator + 'a>,
    forward: bool,
}

impl<'a> InstructionRecordIterator<'a> {
    /// Constructs a new `InstructionRecordIterator`.
    ///
    /// # Arguments
    /// * `cache` - the cache used to resolve records into `InstructionDB` instances
    /// * `it` - the record iterator
    /// * `forward` - the direction of the iterator
    pub fn new(cache: Arc<CodeUnitCache>, it: Box<dyn RecordIterator + 'a>, forward: bool) -> Self {
        InstructionRecordIterator { cache, it, forward }
    }
}

impl<'a> Iterator for InstructionRecordIterator<'a> {
    type Item = Arc<dyn Instruction>;

    /// Port of the private `InstructionRecordIterator.findNext()`, folded into `next()` per this
    /// crate's `Iterator`-based convention for these iterators (see
    /// [`CodeUnitIterator`](crate::program::model::listing::code_unit_iterator::CodeUnitIterator)'s
    /// module docs for why). Java's `catch (IOException e) {}` -- which simply stops the loop --
    /// becomes treating an `Err` the same as an exhausted iterator (`Ok(None)`).
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let record = if self.forward {
                self.it.next().ok().flatten()?
            } else {
                self.it.previous().ok().flatten()?
            };
            if let Some(instruction) = self.cache.get_instruction(&record) {
                return Some(instruction);
            }
        }
    }
}

impl<'a> InstructionIterator for InstructionRecordIterator<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBRecord, Field};
    use crate::program::database::code::code_unit_owner::CodeUnitOwner;
    use crate::program::database::code::inst_db_adapter::{self, FLAGS_COL, PROTO_ID_COL};
    use crate::program::database::code::test_support::TestCodeUnitOwner;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::instruction_prototype::{
        GetPseudoParserContextError, InstructionPrototype,
    };
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::{InstructionContext, Mask, ProcessorContextView};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::instruction::OperandValue;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::pcode::{PatchEncoder, PcodeOp, PcodeOverride};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::RefType;
    use crate::program::seam_stubs::ParserContext as SeamParserContext;
    use std::io;

    /// A minimal fixed-length `InstructionPrototype`; nothing beyond `get_length` is exercised.
    struct MockPrototype {
        length: i32,
    }

    impl InstructionPrototype for MockPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn SeamParserContext>, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_pseudo_parser_context(
            &self,
            _address: &Address,
            _buffer: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn SeamParserContext>, GetPseudoParserContextError> {
            unimplemented!("not exercised by these tests")
        }
        fn has_delay_slots(&self) -> bool {
            false
        }
        fn has_cross_build_dependency(&self) -> bool {
            false
        }
        fn has_next2_dependency(&self) -> bool {
            false
        }
        fn get_mnemonic(&self, _context: &dyn InstructionContext) -> String {
            "NOP".to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_instruction_mask(&self) -> Option<Box<dyn Mask>> {
            None
        }
        fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn Mask>> {
            None
        }
        fn get_flow_type(&self, _context: &dyn InstructionContext) -> RefType {
            RefType::FallThrough
        }
        fn get_delay_slot_depth(&self, _context: &dyn InstructionContext) -> i32 {
            0
        }
        fn get_delay_slot_byte_count(&self) -> i32 {
            0
        }
        fn is_in_delay_slot(&self) -> bool {
            false
        }
        fn get_num_operands(&self) -> i32 {
            0
        }
        fn get_op_type(&self, _operand_index: i32, _context: &dyn InstructionContext) -> i32 {
            0
        }
        fn get_fall_through(&self, _context: &dyn InstructionContext) -> Option<Address> {
            None
        }
        fn get_fall_through_offset(&self, _context: &dyn InstructionContext) -> i32 {
            self.length
        }
        fn get_flows(&self, _context: &dyn InstructionContext) -> Option<Vec<Address>> {
            None
        }
        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }
        fn get_op_representation_list(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Vec<OperandValue>> {
            None
        }
        fn get_address(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Address> {
            None
        }
        fn get_register(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_scalar(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Scalar> {
            None
        }
        fn get_op_objects(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Vec<OperandValue> {
            Vec::new()
        }
        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> RefType {
            RefType::Data
        }
        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }
        fn get_input_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }
        fn get_result_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }
        fn get_pcode(
            &self,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }
        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn PatchEncoder,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> io::Result<()> {
            Ok(())
        }
        fn get_pcode_for_operand(
            &self,
            _context: &dyn InstructionContext,
            _operand_index: i32,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }
        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct VecRecordIterator {
        records: Vec<DBRecord>,
        forward_pos: usize,
        backward_pos: usize,
    }

    impl VecRecordIterator {
        fn new(records: Vec<DBRecord>) -> Self {
            let len = records.len();
            VecRecordIterator {
                records,
                forward_pos: 0,
                backward_pos: len,
            }
        }
    }

    impl RecordIterator for VecRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            if self.forward_pos < self.records.len() {
                let record = self.records[self.forward_pos].clone();
                self.forward_pos += 1;
                Ok(Some(record))
            } else {
                Ok(None)
            }
        }

        fn has_next(&self) -> bool {
            self.forward_pos < self.records.len()
        }

        fn has_previous(&self) -> io::Result<bool> {
            Ok(self.backward_pos > 0)
        }

        fn previous(&mut self) -> io::Result<Option<DBRecord>> {
            if self.backward_pos > 0 {
                self.backward_pos -= 1;
                Ok(Some(self.records[self.backward_pos].clone()))
            } else {
                Ok(None)
            }
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn owner() -> (Arc<TestCodeUnitOwner>, Arc<dyn CodeUnitOwner>) {
        let owner = Arc::new(TestCodeUnitOwner::new(space(), 0x1000, vec![0u8; 0x100]));
        let dynamic: Arc<dyn CodeUnitOwner> = owner.clone();
        (owner, dynamic)
    }

    fn instruction_record(addr: i64, proto_id: i32) -> DBRecord {
        let mut record = DBRecord::new(inst_db_adapter::schema(), Field::Long(Some(addr)));
        record.set_field(PROTO_ID_COL, Field::Int(Some(proto_id)));
        record.set_field(FLAGS_COL, Field::Byte(Some(0)));
        record
    }

    #[test]
    fn forward_iteration_yields_instructions_in_record_order() {
        let (test_owner, dyn_owner) = owner();
        test_owner.put_instruction_prototype(1, Arc::new(MockPrototype { length: 2 }));
        test_owner.put_instruction_prototype(2, Arc::new(MockPrototype { length: 4 }));
        let cache = Arc::new(CodeUnitCache::new(dyn_owner, 10));
        let records = vec![instruction_record(0x1000, 1), instruction_record(0x1010, 2)];
        let it = VecRecordIterator::new(records);

        let mut iter = InstructionRecordIterator::new(cache, Box::new(it), true);
        let first = iter.next().expect("first instruction");
        assert_eq!(first.get_min_address(), space().address(0x1000));
        let second = iter.next().expect("second instruction");
        assert_eq!(second.get_min_address(), space().address(0x1010));
        assert!(iter.next().is_none());
    }

    #[test]
    fn backward_iteration_walks_in_reverse() {
        let (test_owner, dyn_owner) = owner();
        test_owner.put_instruction_prototype(1, Arc::new(MockPrototype { length: 2 }));
        test_owner.put_instruction_prototype(2, Arc::new(MockPrototype { length: 4 }));
        let cache = Arc::new(CodeUnitCache::new(dyn_owner, 10));
        let records = vec![instruction_record(0x1000, 1), instruction_record(0x1010, 2)];
        let it = VecRecordIterator::new(records);

        let mut iter = InstructionRecordIterator::new(cache, Box::new(it), false);
        let first = iter.next().expect("first instruction (reverse)");
        assert_eq!(first.get_min_address(), space().address(0x1010));
        let second = iter.next().expect("second instruction (reverse)");
        assert_eq!(second.get_min_address(), space().address(0x1000));
        assert!(iter.next().is_none());
    }

    #[test]
    fn empty_record_iterator_yields_nothing() {
        let (_test_owner, dyn_owner) = owner();
        let cache = Arc::new(CodeUnitCache::new(dyn_owner, 10));
        let it = VecRecordIterator::new(Vec::new());

        let mut iter = InstructionRecordIterator::new(cache, Box::new(it), true);
        assert!(iter.next().is_none());
    }
}
