//! Port of `ghidra.program.database.code.CommentTypeFilterIterator`.

use std::sync::Arc;

use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::code_unit_iterator::CodeUnitIterator;
use crate::program::model::listing::CommentType;

/// Filters the given code unit iterator to only return code units that have a comment of the
/// given type.
///
/// Port of `ghidra.program.database.code.CommentTypeFilterIterator`.
pub struct CommentTypeFilterIterator {
    it: Box<dyn CodeUnitIterator>,
    comment_type: CommentType,
}

impl CommentTypeFilterIterator {
    /// Constructs a new `CommentTypeFilterIterator`. `it` is the code unit iterator whose items
    /// are tested for the comment type, and `comment_type` is the type of comment to search for.
    pub fn new(it: Box<dyn CodeUnitIterator>, comment_type: CommentType) -> Self {
        CommentTypeFilterIterator { it, comment_type }
    }
}

impl Iterator for CommentTypeFilterIterator {
    type Item = Arc<dyn CodeUnit>;

    fn next(&mut self) -> Option<Arc<dyn CodeUnit>> {
        for cu in self.it.by_ref() {
            if cu.get_comment(self.comment_type).is_some() {
                return Some(cu);
            }
        }
        None
    }
}

impl CodeUnitIterator for CommentTypeFilterIterator {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::code_unit_iterator::CodeUnitIteratorAdapter;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::docking::settings::settings::Settings;

    struct MockCodeUnit {
        comment: Option<String>,
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
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
            mock_address(0)
        }
    }

    impl PropertySet for MockCodeUnit {}
    impl Settings for MockCodeUnit {}

    impl CodeUnit for MockCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "00000000".to_string()
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
            mock_address(0)
        }
        fn get_max_address(&self) -> Address {
            mock_address(0)
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            self.comment.clone()
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

    fn units() -> Vec<Arc<dyn CodeUnit>> {
        vec![
            Arc::new(MockCodeUnit { comment: None }),
            Arc::new(MockCodeUnit {
                comment: Some("has one".to_string()),
            }),
            Arc::new(MockCodeUnit { comment: None }),
            Arc::new(MockCodeUnit {
                comment: Some("also has one".to_string()),
            }),
        ]
    }

    #[test]
    fn filters_to_only_code_units_with_a_comment() {
        let inner: Box<dyn CodeUnitIterator> = Box::new(CodeUnitIteratorAdapter::new(units()));
        let mut iter = CommentTypeFilterIterator::new(inner, CommentType::Eol);

        let mut comments = Vec::new();
        while let Some(cu) = iter.next() {
            comments.push(cu.get_comment(CommentType::Eol).unwrap());
        }
        assert_eq!(comments, vec!["has one", "also has one"]);
    }

    #[test]
    fn empty_when_none_have_a_comment() {
        let no_comments = vec![
            Arc::new(MockCodeUnit { comment: None }) as Arc<dyn CodeUnit>,
            Arc::new(MockCodeUnit { comment: None }) as Arc<dyn CodeUnit>,
        ];
        let inner: Box<dyn CodeUnitIterator> = Box::new(CodeUnitIteratorAdapter::new(no_comments));
        let mut iter = CommentTypeFilterIterator::new(inner, CommentType::Plate);
        assert!(iter.next().is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let inner: Box<dyn CodeUnitIterator> = Box::new(CodeUnitIteratorAdapter::new(units()));
        let iter: Box<dyn CodeUnitIterator> =
            Box::new(CommentTypeFilterIterator::new(inner, CommentType::Eol));
        let count = iter.count();
        assert_eq!(count, 2);
    }
}
