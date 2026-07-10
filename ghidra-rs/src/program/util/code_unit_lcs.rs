use crate::generic::algorithms::LcsTrait;
use crate::program::util::CodeUnitContainer;

pub struct CodeUnitLcs<'a> {
    x_list: &'a [CodeUnitContainer],
    y_list: &'a [CodeUnitContainer],
}

impl<'a> CodeUnitLcs<'a> {
    pub fn new(x_list: &'a [CodeUnitContainer], y_list: &'a [CodeUnitContainer]) -> Self {
        Self { x_list, y_list }
    }
}

impl<'a> LcsTrait<CodeUnitContainer> for CodeUnitLcs<'a> {
    fn length_of_x(&self) -> usize {
        self.x_list.len()
    }

    fn length_of_y(&self) -> usize {
        self.y_list.len()
    }

    fn value_of_x(&self, index: usize) -> CodeUnitContainer
    where
        CodeUnitContainer: Clone,
    {
        self.x_list[index].clone()
    }

    fn value_of_y(&self, index: usize) -> CodeUnitContainer
    where
        CodeUnitContainer: Clone,
    {
        self.y_list[index].clone()
    }

    fn matches(&self, x: &CodeUnitContainer, y: &CodeUnitContainer) -> bool {
        x.get_arity() == y.get_arity() && x.get_mnemonic() == y.get_mnemonic()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::listing::CodeUnit as _;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, MemBuffer};
    use crate::util::task::DummyMonitor;
    use std::fmt;
    use std::sync::Arc;

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

    use crate::program::model::listing::CodeUnit;

    #[test]
    fn empty_lists() {
        let lcs = CodeUnitLcs::new(&[], &[]);
        assert_eq!(lcs.length_of_x(), 0);
        assert_eq!(lcs.length_of_y(), 0);
    }

    #[test]
    fn single_element_lists_match() {
        let addr1 = addr(0x1000);
        let addr2 = addr(0x2000);
        let code_unit1 = MockCodeUnit::new("MOV", 2, addr1);
        let code_unit2 = MockCodeUnit::new("MOV", 2, addr2);
        let container1 = CodeUnitContainer::new(code_unit1);
        let container2 = CodeUnitContainer::new(code_unit2);

        let lcs = CodeUnitLcs::new(&[container1.clone()], &[container2]);
        let monitor = DummyMonitor;
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].get_mnemonic(), "MOV");
        assert_eq!(result[0].get_arity(), 2);
    }

    #[test]
    fn matching_mnemonics_and_arity() {
        let addr1 = addr(0x1000);
        let addr2 = addr(0x2000);
        let addr3 = addr(0x3000);
        let code_unit1 = MockCodeUnit::new("MOV", 2, addr1);
        let code_unit2 = MockCodeUnit::new("MOV", 2, addr2);
        let code_unit3 = MockCodeUnit::new("MOV", 2, addr3);
        let container1 = CodeUnitContainer::new(code_unit1);
        let container2 = CodeUnitContainer::new(code_unit2);
        let container3 = CodeUnitContainer::new(code_unit3);

        let lcs = CodeUnitLcs::new(&[container1], &[container2, container3]);
        let monitor = DummyMonitor;
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn different_mnemonics() {
        let addr1 = addr(0x1000);
        let addr2 = addr(0x2000);
        let code_unit1 = MockCodeUnit::new("MOV", 2, addr1);
        let code_unit2 = MockCodeUnit::new("JMP", 1, addr2);
        let container1 = CodeUnitContainer::new(code_unit1);
        let container2 = CodeUnitContainer::new(code_unit2);

        let lcs = CodeUnitLcs::new(&[container1], &[container2]);
        assert!(!lcs.matches(&lcs.x_list[0], &lcs.y_list[0]));
    }

    #[test]
    fn different_arity() {
        let addr1 = addr(0x1000);
        let addr2 = addr(0x2000);
        let code_unit1 = MockCodeUnit::new("MOV", 2, addr1);
        let code_unit2 = MockCodeUnit::new("MOV", 3, addr2);
        let container1 = CodeUnitContainer::new(code_unit1);
        let container2 = CodeUnitContainer::new(code_unit2);

        let lcs = CodeUnitLcs::new(&[container1], &[container2]);
        assert!(!lcs.matches(&lcs.x_list[0], &lcs.y_list[0]));
    }

    #[test]
    fn partial_sequence_match() {
        let addr1 = addr(0x1000);
        let addr2 = addr(0x1001);
        let addr3 = addr(0x1002);
        let addr4 = addr(0x2000);
        let addr5 = addr(0x2001);
        let addr6 = addr(0x2002);

        let c1 = CodeUnitContainer::new(MockCodeUnit::new("MOV", 2, addr1));
        let c2 = CodeUnitContainer::new(MockCodeUnit::new("ADD", 3, addr2));
        let c3 = CodeUnitContainer::new(MockCodeUnit::new("JMP", 1, addr3));

        let c4 = CodeUnitContainer::new(MockCodeUnit::new("MOV", 2, addr4));
        let c5 = CodeUnitContainer::new(MockCodeUnit::new("XOR", 2, addr5));
        let c6 = CodeUnitContainer::new(MockCodeUnit::new("JMP", 1, addr6));

        let lcs = CodeUnitLcs::new(&[c1, c2, c3], &[c4, c5, c6]);
        let monitor = DummyMonitor;
        let result = lcs.get_lcs(&monitor).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].get_mnemonic(), "MOV");
        assert_eq!(result[1].get_mnemonic(), "JMP");
    }
}
