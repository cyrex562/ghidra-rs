use std::sync::Arc;
use crate::program::model::listing::CodeUnit;
use std::fmt;

/// Container holding a CodeUnit along with cached mnemonic and arity information.
///
/// Port of `ghidra.program.util.CodeUnitContainer`.
pub struct CodeUnitContainer {
    code_unit: Arc<dyn CodeUnit>,
    mnemonic: String,
    arity: i32,
}

impl Clone for CodeUnitContainer {
    fn clone(&self) -> Self {
        Self {
            code_unit: Arc::clone(&self.code_unit),
            mnemonic: self.mnemonic.clone(),
            arity: self.arity,
        }
    }
}

impl CodeUnitContainer {
    /// Constructs a new `CodeUnitContainer` from a `CodeUnit`.
    ///
    /// The mnemonic string and arity (number of operands) are cached during construction.
    pub fn new(code_unit: Arc<dyn CodeUnit>) -> Self {
        let mnemonic = code_unit.get_mnemonic_string();
        let arity = code_unit.get_num_operands();
        Self {
            code_unit,
            mnemonic,
            arity,
        }
    }

    /// Returns a reference to the underlying `CodeUnit`.
    pub fn get_code_unit(&self) -> &Arc<dyn CodeUnit> {
        &self.code_unit
    }

    /// Returns the cached mnemonic string for this code unit.
    pub fn get_mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Returns the cached arity (number of operands) for this code unit.
    pub fn get_arity(&self) -> i32 {
        self.arity
    }
}

impl fmt::Display for CodeUnitContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address_str = self.code_unit.get_address_string(false, true);
        write!(f, "{} @ {}", self.mnemonic, address_str)
    }
}

impl fmt::Debug for CodeUnitContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeUnitContainer")
            .field("mnemonic", &self.mnemonic)
            .field("arity", &self.arity)
            .field("address", &self.code_unit.get_address_string(false, true))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::listing::CodeUnit as _;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, MemBuffer};

    fn addr(offset: i64) -> Address {
        Address::new(
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
            offset,
        )
    }

    struct MockCodeUnit {
        mnemonic: String,
        num_operands: i32,
        address: Address,
    }

    impl MockCodeUnit {
        fn new(mnemonic: &str, num_operands: i32, address: Address) -> Arc<dyn CodeUnit> {
            Arc::new(Self {
                mnemonic: mnemonic.to_string(),
                num_operands,
                address,
            })
        }
    }

    impl fmt::Display for MockCodeUnit {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.mnemonic)
        }
    }

    impl MemBuffer for MockCodeUnit {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

    impl PropertySet for MockCodeUnit {}

    impl CodeUnit for MockCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            self.address.to_string()
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
            self.address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.address.clone()
        }

        fn get_mnemonic_string(&self) -> String {
            self.mnemonic.clone()
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

        fn get_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(vec![])
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            for byte in buffer.iter_mut() {
                *byte = 0;
            }
            Ok(())
        }

        fn contains(&self, test_addr: &Address) -> bool {
            test_addr == &self.address
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            if addr < &self.address {
                1
            } else if addr > &self.address {
                -1
            } else {
                0
            }
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {}

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            vec![]
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            vec![]
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {}

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_external_reference(&self, _index: i32) -> Option<Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }

        fn get_references_from(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            vec![]
        }

        fn get_reference_iterator_to(
            &self,
        ) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            unimplemented!()
        }

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(
            &mut self,
            _reference: Arc<dyn crate::program::model::symbol::Reference>,
        ) {
        }

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
            self.num_operands
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }

    #[test]
    fn construction_caches_mnemonic_and_arity() {
        let addr = addr(0x1000);
        let code_unit = MockCodeUnit::new("MOV", 2, addr.clone());
        let container = CodeUnitContainer::new(code_unit);

        assert_eq!(container.get_mnemonic(), "MOV");
        assert_eq!(container.get_arity(), 2);
    }

    #[test]
    fn get_code_unit_returns_reference() {
        let addr = addr(0x2000);
        let code_unit = MockCodeUnit::new("JMP", 1, addr.clone());
        let container = CodeUnitContainer::new(code_unit.clone());

        assert!(Arc::ptr_eq(container.get_code_unit(), &code_unit));
    }

    #[test]
    fn display_includes_mnemonic_and_address() {
        let addr = addr(0x3000);
        let code_unit = MockCodeUnit::new("ADD", 3, addr.clone());
        let container = CodeUnitContainer::new(code_unit);

        let output = container.to_string();
        assert!(output.contains("ADD"));
        assert!(output.contains("3000"));
    }

    #[test]
    fn zero_operands() {
        let addr = addr(0x4000);
        let code_unit = MockCodeUnit::new("NOP", 0, addr.clone());
        let container = CodeUnitContainer::new(code_unit);

        assert_eq!(container.get_arity(), 0);
    }

    #[test]
    fn multiple_operands() {
        let addr = addr(0x5000);
        let code_unit = MockCodeUnit::new("IMUL", 3, addr.clone());
        let container = CodeUnitContainer::new(code_unit);

        assert_eq!(container.get_arity(), 3);
    }

    #[test]
    fn different_mnemonics() {
        let addr = addr(0x6000);
        let code_unit = MockCodeUnit::new("PUSH", 1, addr.clone());
        let container = CodeUnitContainer::new(code_unit);

        assert_eq!(container.get_mnemonic(), "PUSH");
    }

    #[test]
    fn debug_display() {
        let addr = addr(0x7000);
        let code_unit = MockCodeUnit::new("XOR", 2, addr.clone());
        let container = CodeUnitContainer::new(code_unit);

        let debug_str = format!("{:?}", container);
        assert!(debug_str.contains("XOR"));
        assert!(debug_str.contains("2"));
    }
}
