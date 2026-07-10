use std::fmt;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::CodeUnit;
use crate::program::model::scalar::Scalar;

/// A row object for the Scalar table that contains the necessary elements for the table.
///
/// Port of `ghidra.app.plugin.core.scalartable.ScalarRowObject`.
pub struct ScalarRowObject {
    code_unit: Arc<dyn CodeUnit>,
    address: Address,
    scalar: Scalar,
}

impl ScalarRowObject {
    /// Create a new ScalarRowObject.
    ///
    /// # Arguments
    /// * `code_unit` - The code unit containing the scalar
    /// * `scalar` - The scalar value to display
    ///
    /// # Panics
    /// Panics if `code_unit` is None (checked by the Arc requirement).
    pub fn new(code_unit: Arc<dyn CodeUnit>, scalar: Scalar) -> Self {
        let address = code_unit.get_min_address();
        Self {
            code_unit,
            address,
            scalar,
        }
    }

    /// Get the address of this scalar.
    pub fn get_address(&self) -> Address {
        self.address.clone()
    }

    /// Get the code unit containing this scalar.
    pub fn get_code_unit(&self) -> Arc<dyn CodeUnit> {
        self.code_unit.clone()
    }

    /// Get the scalar value.
    pub fn get_scalar(&self) -> Scalar {
        self.scalar
    }
}

impl fmt::Display for ScalarRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ {}", self.scalar, self.address)
    }
}

impl fmt::Debug for ScalarRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScalarRowObject")
            .field("scalar", &self.scalar)
            .field("address", &self.address)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::CodeUnit;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol};
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, MemBuffer};
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::program::Program;
    use std::sync::Arc;

    struct MockCodeUnitImpl {
        min_address: Address,
        length: i32,
    }

    impl MemBuffer for MockCodeUnitImpl {
        fn get_address(&self) -> Address {
            self.min_address.clone()
        }
    }
    impl PropertySet for MockCodeUnitImpl {}

    impl CodeUnit for MockCodeUnitImpl {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.min_address.offset())
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
            self.min_address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
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
            self.length
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.length as usize])
        }
        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            buffer.fill(0x90);
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.min_address.offset()
                && test_addr.offset() < self.min_address.offset() + self.length as i64
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            (self.min_address.offset() - addr.offset()) as i32
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
            unimplemented!()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!()
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

    fn create_mock_code_unit(offset: i64) -> Arc<dyn CodeUnit> {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let address = Address::new(space, offset);
        Arc::new(MockCodeUnitImpl {
            min_address: address,
            length: 4,
        })
    }

    #[test]
    fn test_new_and_getters() {
        let code_unit = create_mock_code_unit(0x1000);
        let scalar = Scalar::new_with_signedness(8, 0x42, false);
        let row = ScalarRowObject::new(code_unit, scalar);

        assert_eq!(row.get_scalar(), scalar);
        assert_eq!(row.get_address().offset(), 0x1000);
    }

    #[test]
    fn test_display_format() {
        let code_unit = create_mock_code_unit(0x2000);
        let scalar = Scalar::new_with_signedness(8, 0x55, false);
        let row = ScalarRowObject::new(code_unit, scalar);

        let display_str = row.to_string();
        assert!(display_str.contains("0x55"));
        assert!(display_str.contains("@"));
    }

    #[test]
    fn test_debug_format() {
        let code_unit = create_mock_code_unit(0x3000);
        let scalar = Scalar::new(16, 0x1234);
        let row = ScalarRowObject::new(code_unit, scalar);

        let debug_str = format!("{:?}", row);
        assert!(debug_str.contains("ScalarRowObject"));
        assert!(debug_str.contains("scalar"));
        assert!(debug_str.contains("address"));
    }

    #[test]
    fn test_different_address_values() {
        let code_unit1 = create_mock_code_unit(0x1000);
        let code_unit2 = create_mock_code_unit(0x2000);
        let scalar = Scalar::new(8, 0xFF);

        let row1 = ScalarRowObject::new(code_unit1, scalar);
        let row2 = ScalarRowObject::new(code_unit2, scalar);

        assert_eq!(row1.get_address().offset(), 0x1000);
        assert_eq!(row2.get_address().offset(), 0x2000);
    }

    #[test]
    fn test_different_scalar_values() {
        let code_unit = create_mock_code_unit(0x1000);
        let scalar1 = Scalar::new_with_signedness(8, 0x10, false);
        let scalar2 = Scalar::new_with_signedness(8, 0x20, false);

        let row1 = ScalarRowObject::new(code_unit.clone(), scalar1);
        let row2 = ScalarRowObject::new(code_unit, scalar2);

        assert_eq!(row1.get_scalar(), scalar1);
        assert_eq!(row2.get_scalar(), scalar2);
    }

    #[test]
    fn test_code_unit_reference_preserved() {
        let code_unit = create_mock_code_unit(0x1000);
        let scalar = Scalar::new(8, 42);
        let row = ScalarRowObject::new(code_unit.clone(), scalar);

        let retrieved_unit = row.get_code_unit();
        assert_eq!(
            retrieved_unit.get_min_address().offset(),
            code_unit.get_min_address().offset()
        );
    }
}
