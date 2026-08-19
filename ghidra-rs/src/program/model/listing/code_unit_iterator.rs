use crate::program::model::listing::CodeUnit;
use std::sync::Arc;

/// Iterator that returns code units.
///
/// Mirrors Ghidra's `CodeUnitIterator`, which extends `java.util.Iterator<CodeUnit>`.
///
/// This is a marker supertrait over [`Iterator`] rather than a hand-rolled
/// `has_next`/`next_code_unit` pair, matching [`FunctionIterator`] and
/// [`InstructionIterator`]. The pair form is what produced the double-consume bug recorded in
/// AGENTS.md: `while it.has_next() { v.push(it.next()) }` advances the cursor twice per turn
/// and silently drops every other element. With `Iterator` there is one cursor-advancing
/// operation and `for`/`while let` cannot express that mistake.
///
/// [`FunctionIterator`]: crate::program::model::listing::function_iterator::FunctionIterator
/// [`InstructionIterator`]: crate::program::model::listing::instruction_iterator::InstructionIterator
pub trait CodeUnitIterator: Iterator<Item = Arc<dyn CodeUnit>> {}

/// Empty code unit iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyCodeUnitIterator;

impl Iterator for EmptyCodeUnitIterator {
    type Item = Arc<dyn CodeUnit>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl CodeUnitIterator for EmptyCodeUnitIterator {}

/// List-based code unit iterator.
///
/// Wraps a vector of code units and iterates over them by consuming ownership.
pub struct CodeUnitIteratorAdapter {
    iter: std::vec::IntoIter<Arc<dyn CodeUnit>>,
}

impl CodeUnitIteratorAdapter {
    /// Creates an adapter over the supplied code units.
    pub fn new(code_units: Vec<Arc<dyn CodeUnit>>) -> Self {
        Self {
            iter: code_units.into_iter(),
        }
    }
}

impl Iterator for CodeUnitIteratorAdapter {
    type Item = Arc<dyn CodeUnit>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl CodeUnitIterator for CodeUnitIteratorAdapter {}

/// Creates an empty code unit iterator.
pub fn empty() -> Box<dyn CodeUnitIterator> {
    Box::new(EmptyCodeUnitIterator)
}

/// Creates a code unit iterator from a vector of code units.
pub fn of(code_units: Vec<Arc<dyn CodeUnit>>) -> Box<dyn CodeUnitIterator> {
    Box::new(CodeUnitIteratorAdapter::new(code_units))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::lang::register::Register;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;

    struct TestCodeUnit {
        min_address: Address,
        max_address: Address,
    }

    impl MemBuffer for TestCodeUnit {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.min_address.clone()
        }
    }
    impl PropertySet for TestCodeUnit {}

    impl TestCodeUnit {
        fn new(offset: i64) -> Self {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Self {
                min_address: Address::new(space.clone(), offset),
                max_address: Address::new(space, offset + 1),
            }
        }
    }

    impl CodeUnit for TestCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:x}", self.min_address.offset())
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<Arc<dyn crate::program::model::symbol::Symbol>> {
            vec![]
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }

        fn get_min_address(&self) -> Address {
            self.min_address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.max_address.clone()
        }

        fn get_mnemonic_string(&self) -> String {
            "test".to_string()
        }

        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            vec![]
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

        fn contains(&self, _test_addr: &Address) -> bool {
            false
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
            unimplemented!("not needed for this smoke test")
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
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
            _reg: &Register,
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

    #[test]
    fn empty_iterator_has_no_code_units() {
        let mut iterator = EmptyCodeUnitIterator;

        assert!(iterator.next().is_none());
        assert_eq!(iterator.count(), 0);
    }

    #[test]
    fn adapter_iterates_code_units_and_then_returns_none() {
        let code_units: Vec<Arc<dyn CodeUnit>> = vec![
            Arc::new(TestCodeUnit::new(0x1000)),
            Arc::new(TestCodeUnit::new(0x1002)),
        ];
        let mut iterator = CodeUnitIteratorAdapter::new(code_units);

        assert_eq!(iterator.next().unwrap().get_min_address().offset(), 0x1000);
        assert_eq!(iterator.next().unwrap().get_min_address().offset(), 0x1002);
        assert!(iterator.next().is_none());
    }

    #[test]
    fn adapter_yields_every_element_when_driven_by_a_for_loop() {
        // The regression this shape exists to prevent: a has_next/next pair let a caller
        // advance the cursor twice per turn and drop every other element, and it compiled.
        let code_units: Vec<Arc<dyn CodeUnit>> = (0..6)
            .map(|i| Arc::new(TestCodeUnit::new(0x1000 + i * 2)) as Arc<dyn CodeUnit>)
            .collect();

        let seen: Vec<i64> = CodeUnitIteratorAdapter::new(code_units)
            .map(|cu| cu.get_min_address().offset())
            .collect();

        assert_eq!(seen, vec![0x1000, 0x1002, 0x1004, 0x1006, 0x1008, 0x100A]);
    }

    #[test]
    fn empty_iterator_multiple_calls() {
        let mut iterator = EmptyCodeUnitIterator;

        for _ in 0..5 {
            assert!(iterator.next().is_none());
        }
    }

    #[test]
    fn adapter_with_single_code_unit() {
        let code_units: Vec<Arc<dyn CodeUnit>> = vec![Arc::new(TestCodeUnit::new(0x5000))];
        let mut iterator = CodeUnitIteratorAdapter::new(code_units);

        assert_eq!(iterator.next().unwrap().get_min_address().offset(), 0x5000);
        assert!(iterator.next().is_none());
    }
}
