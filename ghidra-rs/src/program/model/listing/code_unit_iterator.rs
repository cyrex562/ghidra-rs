use crate::program::model::listing::CodeUnit;
use std::sync::Arc;

/// Iterator that returns code units.
///
/// This mirrors Ghidra's `CodeUnitIterator`, using `Option` in place of
/// Java's null return when no code unit is available.
pub trait CodeUnitIterator {
    /// Returns true when another code unit is available.
    fn has_next(&self) -> bool;

    /// Returns the next code unit, or `None` when no code unit is available.
    /// NOTE: This deviates from the standard Rust Iterator trait by returning None
    /// instead of panicking when exhausted, matching Java's behavior.
    fn next_code_unit(&mut self) -> Option<Arc<dyn CodeUnit>>;
}

/// Empty code unit iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyCodeUnitIterator;

impl CodeUnitIterator for EmptyCodeUnitIterator {
    fn has_next(&self) -> bool {
        false
    }

    fn next_code_unit(&mut self) -> Option<Arc<dyn CodeUnit>> {
        None
    }
}

/// Adapter from a vector of code units to a `CodeUnitIterator`.
pub struct CodeUnitIteratorAdapter {
    code_units: Vec<Arc<dyn CodeUnit>>,
    index: usize,
}

impl CodeUnitIteratorAdapter {
    /// Creates an adapter over the supplied code units.
    pub fn new(code_units: Vec<Arc<dyn CodeUnit>>) -> Self {
        Self {
            code_units,
            index: 0,
        }
    }
}

impl CodeUnitIterator for CodeUnitIteratorAdapter {
    fn has_next(&self) -> bool {
        self.index < self.code_units.len()
    }

    fn next_code_unit(&mut self) -> Option<Arc<dyn CodeUnit>> {
        if !self.has_next() {
            return None;
        }
        let code_unit = self.code_units[self.index].clone();
        self.index += 1;
        Some(code_unit)
    }
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
    use crate::program::seam_stubs::{CommentType, MemBuffer};

    struct TestCodeUnit {
        min_address: Address,
        max_address: Address,
    }

    impl MemBuffer for TestCodeUnit {
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
            format!("{:x}", self.min_address.offset)
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

        assert!(!iterator.has_next());
        assert!(iterator.next_code_unit().is_none());
    }

    #[test]
    fn adapter_iterates_code_units_and_then_returns_none() {
        let code_units: Vec<Arc<dyn CodeUnit>> = vec![
            Arc::new(TestCodeUnit::new(0x1000)),
            Arc::new(TestCodeUnit::new(0x1002)),
        ];
        let mut iterator = CodeUnitIteratorAdapter::new(code_units);

        assert!(iterator.has_next());
        assert_eq!(
            iterator.next_code_unit().unwrap().get_min_address().offset,
            0x1000
        );
        assert!(iterator.has_next());
        assert_eq!(
            iterator.next_code_unit().unwrap().get_min_address().offset,
            0x1002
        );
        assert!(!iterator.has_next());
        assert!(iterator.next_code_unit().is_none());
    }

    #[test]
    fn empty_iterator_multiple_calls() {
        let mut iterator = EmptyCodeUnitIterator;

        for _ in 0..5 {
            assert!(!iterator.has_next());
            assert!(iterator.next_code_unit().is_none());
        }
    }

    #[test]
    fn adapter_with_single_code_unit() {
        let code_units: Vec<Arc<dyn CodeUnit>> = vec![Arc::new(TestCodeUnit::new(0x5000))];
        let mut iterator = CodeUnitIteratorAdapter::new(code_units);

        assert!(iterator.has_next());
        assert_eq!(
            iterator.next_code_unit().unwrap().get_min_address().offset,
            0x5000
        );
        assert!(!iterator.has_next());
        assert!(iterator.next_code_unit().is_none());
    }
}
