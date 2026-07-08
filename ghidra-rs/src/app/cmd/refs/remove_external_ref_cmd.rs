use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;

/// Command for removing external references.
pub struct RemoveExternalRefCmd {
    from_addr: Address,
    op_index: i32,
    status: Option<String>,
}

impl RemoveExternalRefCmd {
    /// Constructs a new command for removing an external reference.
    ///
    /// # Arguments
    ///
    /// * `from_addr` - the address of the codeunit making the external reference.
    /// * `op_index` - the operand index.
    pub fn new(from_addr: Address, op_index: i32) -> Self {
        RemoveExternalRefCmd {
            from_addr,
            op_index,
            status: None,
        }
    }
}

impl Command<dyn Program + 'static> for RemoveExternalRefCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(ref_mgr) = program.get_reference_manager() else {
            self.status = Some("Reference manager not available".to_string());
            return false;
        };

        let refs = ref_mgr.get_references_from_operand(self.from_addr.clone(), self.op_index);
        for reference in refs {
            if reference.is_external_reference() {
                ref_mgr.delete(reference);
            }
        }

        true
    }

    fn status_msg(&self) -> Option<String> {
        self.status.clone()
    }

    fn name(&self) -> String {
        "Remove External Reference".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{
        ExternalLocation, Namespace, RefType, ReferenceIterator, ReferenceManager, SourceType,
        Symbol,
    };
    use crate::program::model::address::{AddressIterator, AddressSetView};
    use crate::program::model::lang::Register;
    use crate::program::model::listing::Variable;
    use crate::util::exception::InvalidInputException;
    use std::any::Any;
    use std::sync::Arc;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockReference {
        from_addr: Address,
        to_addr: Address,
        op_index: i32,
        is_external: bool,
    }

    impl MockReference {
        fn new(from_addr: Address, to_addr: Address, op_index: i32, is_external: bool) -> Self {
            MockReference {
                from_addr,
                to_addr,
                op_index,
                is_external,
            }
        }
    }

    impl crate::program::model::symbol::Reference for MockReference {
        fn from_address(&self) -> Address {
            self.from_addr
        }

        fn to_address(&self) -> Address {
            self.to_addr
        }

        fn is_primary(&self) -> bool {
            false
        }

        fn symbol_id(&self) -> i64 {
            -1
        }

        fn reference_type(&self) -> RefType {
            RefType::Data
        }

        fn operand_index(&self) -> i32 {
            self.op_index
        }

        fn is_mnemonic_reference(&self) -> bool {
            false
        }

        fn is_operand_reference(&self) -> bool {
            true
        }

        fn is_stack_reference(&self) -> bool {
            false
        }

        fn is_external_reference(&self) -> bool {
            self.is_external
        }

        fn is_entry_point_reference(&self) -> bool {
            false
        }

        fn is_memory_reference(&self) -> bool {
            true
        }

        fn is_register_reference(&self) -> bool {
            false
        }

        fn is_offset_reference(&self) -> bool {
            false
        }

        fn is_shifted_reference(&self) -> bool {
            false
        }

        fn source(&self) -> SourceType {
            SourceType::User
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MockReferenceManager {
        references: Vec<Arc<dyn crate::program::model::symbol::Reference>>,
        deleted_references: Vec<Arc<dyn crate::program::model::symbol::Reference>>,
    }

    impl ReferenceManager for MockReferenceManager {
        fn add_reference(&mut self, reference: Arc<dyn crate::program::model::symbol::Reference>) -> Arc<dyn crate::program::model::symbol::Reference> {
            reference
        }

        fn add_stack_reference(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _stack_offset: i32,
            _ref_type: RefType,
            _source: SourceType,
        ) -> Arc<dyn crate::program::model::symbol::Reference> {
            unimplemented!()
        }

        fn add_register_reference(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _register: &Register,
            _ref_type: RefType,
            _source: SourceType,
        ) -> Arc<dyn crate::program::model::symbol::Reference> {
            unimplemented!()
        }

        fn add_memory_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn crate::program::model::symbol::Reference> {
            unimplemented!()
        }

        fn add_offset_mem_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _to_addr_is_base: bool,
            _offset: i64,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn crate::program::model::symbol::Reference> {
            unimplemented!()
        }

        fn add_shifted_mem_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _shift_value: i32,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn crate::program::model::symbol::Reference> {
            unimplemented!()
        }

        fn add_external_reference(
            &mut self,
            _from_addr: Address,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source: SourceType,
            _op_index: i32,
            _ref_type: RefType,
        ) -> Result<Arc<dyn crate::program::model::symbol::Reference>, crate::program::model::symbol::reference_manager::AddExternalReferenceError> {
            unimplemented!()
        }

        fn add_external_reference_in_namespace(
            &mut self,
            _from_addr: Address,
            _ext_namespace: Arc<dyn Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source: SourceType,
            _op_index: i32,
            _ref_type: RefType,
        ) -> Result<Arc<dyn crate::program::model::symbol::Reference>, crate::program::model::symbol::reference_manager::AddExternalReferenceError> {
            unimplemented!()
        }

        fn add_external_reference_for_location(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _location: Arc<dyn ExternalLocation>,
            _source: SourceType,
            _ref_type: RefType,
        ) -> Result<Arc<dyn crate::program::model::symbol::Reference>, InvalidInputException> {
            unimplemented!()
        }

        fn remove_all_references_from_range(&mut self, _begin_addr: Address, _end_addr: Address) {}

        fn remove_all_references_from(&mut self, _from_addr: Address) {}

        fn remove_all_references_to(&mut self, _to_addr: Address) {}

        fn get_references_to_variable(&self, _var: &dyn Variable) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_referenced_variable(&self, _reference: &dyn crate::program::model::symbol::Reference) -> Option<Box<dyn Variable>> {
            None
        }

        fn set_primary(&mut self, _reference: Arc<dyn crate::program::model::symbol::Reference>, _is_primary: bool) {}

        fn has_flow_references_from(&self, _addr: Address) -> bool {
            false
        }

        fn get_flow_references_from(&self, _addr: Address) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_external_references(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }

        fn get_references_to(&self, _addr: Address) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }

        fn get_reference_iterator(&self, _start_addr: Address) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }

        fn get_reference(
            &self,
            _from_addr: Address,
            _to_addr: Address,
            _op_index: i32,
        ) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }

        fn get_references_from(&self, _addr: Address) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_references_from_operand(
            &self,
            _from_addr: Address,
            _op_index: i32,
        ) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            self.references.clone()
        }

        fn has_references_from_operand(&self, _from_addr: Address, _op_index: i32) -> bool {
            false
        }

        fn has_references_from(&self, _from_addr: Address) -> bool {
            false
        }

        fn get_primary_reference_from(
            &self,
            _addr: Address,
            _op_index: i32,
        ) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }

        fn get_reference_source_iterator(
            &self,
            _start_addr: Address,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }

        fn get_reference_source_iterator_in_set(
            &self,
            _addr_set: Option<&dyn AddressSetView>,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }

        fn get_reference_destination_iterator(
            &self,
            _start_addr: Address,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }

        fn get_reference_destination_iterator_in_set(
            &self,
            _addr_set: Option<&dyn AddressSetView>,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }

        fn get_reference_count_to(&self, _to_addr: Address) -> i32 {
            0
        }

        fn get_reference_count_from(&self, _from_addr: Address) -> i32 {
            0
        }

        fn get_reference_destination_count(&self) -> i32 {
            0
        }

        fn get_reference_source_count(&self) -> i32 {
            0
        }

        fn has_references_to(&self, _to_addr: Address) -> bool {
            false
        }

        fn update_ref_type(
            &mut self,
            reference: Arc<dyn crate::program::model::symbol::Reference>,
            _ref_type: RefType,
        ) -> Arc<dyn crate::program::model::symbol::Reference> {
            reference
        }

        fn set_association(&mut self, _symbol: Arc<dyn Symbol>, _reference: Arc<dyn crate::program::model::symbol::Reference>) {}

        fn remove_association(&mut self, _reference: Arc<dyn crate::program::model::symbol::Reference>) {}

        fn delete(&mut self, reference: Arc<dyn crate::program::model::symbol::Reference>) {
            self.deleted_references.push(reference);
        }

        fn get_reference_level(&self, _to_addr: Address) -> i8 {
            0
        }
    }

    struct MockProgram {
        ref_mgr: Option<MockReferenceManager>,
    }

    impl DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }

        fn get_reference_manager(&mut self) -> Option<&mut dyn ReferenceManager> {
            self.ref_mgr
                .as_mut()
                .map(|m| m as &mut dyn ReferenceManager)
        }
    }

    #[test]
    fn command_name_is_correct() {
        let cmd = RemoveExternalRefCmd::new(addr(0x1000), 0);
        assert_eq!(cmd.name(), "Remove External Reference");
    }

    #[test]
    fn apply_to_removes_external_references() {
        let external_ref: Arc<dyn crate::program::model::symbol::Reference> =
            Arc::new(MockReference::new(addr(0x1000), addr(0x2000), 0, true));
        let non_external_ref: Arc<dyn crate::program::model::symbol::Reference> =
            Arc::new(MockReference::new(addr(0x1000), addr(0x3000), 0, false));

        let mut program = MockProgram {
            ref_mgr: Some(MockReferenceManager {
                references: vec![external_ref.clone(), non_external_ref.clone()],
                deleted_references: vec![],
            }),
        };

        let mut cmd = RemoveExternalRefCmd::new(addr(0x1000), 0);
        assert!(cmd.apply_to(&mut program));

        let deleted = &program.ref_mgr.as_ref().unwrap().deleted_references;
        assert_eq!(deleted.len(), 1);
        assert!(deleted[0].is_external_reference());
    }

    #[test]
    fn apply_to_succeeds_when_no_external_references() {
        let non_external_ref: Arc<dyn crate::program::model::symbol::Reference> =
            Arc::new(MockReference::new(addr(0x1000), addr(0x3000), 0, false));

        let mut program = MockProgram {
            ref_mgr: Some(MockReferenceManager {
                references: vec![non_external_ref],
                deleted_references: vec![],
            }),
        };

        let mut cmd = RemoveExternalRefCmd::new(addr(0x1000), 0);
        assert!(cmd.apply_to(&mut program));

        let deleted = &program.ref_mgr.as_ref().unwrap().deleted_references;
        assert_eq!(deleted.len(), 0);
    }

    #[test]
    fn apply_to_succeeds_with_empty_references() {
        let mut program = MockProgram {
            ref_mgr: Some(MockReferenceManager {
                references: vec![],
                deleted_references: vec![],
            }),
        };

        let mut cmd = RemoveExternalRefCmd::new(addr(0x1000), 0);
        assert!(cmd.apply_to(&mut program));

        let deleted = &program.ref_mgr.as_ref().unwrap().deleted_references;
        assert_eq!(deleted.len(), 0);
    }

    #[test]
    fn apply_to_fails_when_reference_manager_not_available() {
        let mut program = MockProgram { ref_mgr: None };
        let mut cmd = RemoveExternalRefCmd::new(addr(0x1000), 0);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("Reference manager not available".to_string())
        );
    }

    #[test]
    fn status_is_none_on_success() {
        let mut program = MockProgram {
            ref_mgr: Some(MockReferenceManager {
                references: vec![],
                deleted_references: vec![],
            }),
        };

        let mut cmd = RemoveExternalRefCmd::new(addr(0x1000), 0);
        cmd.apply_to(&mut program);

        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn constructor_stores_address_and_operand_index() {
        let cmd = RemoveExternalRefCmd::new(addr(0x1234), 2);
        assert_eq!(cmd.from_addr, addr(0x1234));
        assert_eq!(cmd.op_index, 2);
    }

    #[test]
    fn apply_to_removes_all_external_references() {
        let ext_ref1: Arc<dyn crate::program::model::symbol::Reference> =
            Arc::new(MockReference::new(addr(0x1000), addr(0x2000), 0, true));
        let ext_ref2: Arc<dyn crate::program::model::symbol::Reference> =
            Arc::new(MockReference::new(addr(0x1000), addr(0x3000), 0, true));
        let non_external_ref: Arc<dyn crate::program::model::symbol::Reference> =
            Arc::new(MockReference::new(addr(0x1000), addr(0x4000), 0, false));

        let mut program = MockProgram {
            ref_mgr: Some(MockReferenceManager {
                references: vec![ext_ref1, ext_ref2, non_external_ref],
                deleted_references: vec![],
            }),
        };

        let mut cmd = RemoveExternalRefCmd::new(addr(0x1000), 0);
        assert!(cmd.apply_to(&mut program));

        let deleted = &program.ref_mgr.as_ref().unwrap().deleted_references;
        assert_eq!(deleted.len(), 2);
        assert!(deleted.iter().all(|r| r.is_external_reference()));
    }
}
