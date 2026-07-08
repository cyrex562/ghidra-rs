use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::symbol::Reference;

/// Command class for setting a reference to be primary. Any other reference that was
/// primary at that address will no longer be primary.
pub struct SetPrimaryRefCmd {
    from_addr: Address,
    op_index: i32,
    to_addr: Address,
    is_primary: bool,
    status: Option<String>,
}

impl SetPrimaryRefCmd {
    /// Creates a command for setting whether or not a reference is the primary reference.
    /// If `is_primary` is true, any other reference that was primary at that address will
    /// no longer be primary.
    ///
    /// # Arguments
    ///
    /// * `reference` - the reference.
    /// * `is_primary` - true to make the reference primary, false to make it non-primary.
    pub fn from_reference(reference: &dyn Reference, is_primary: bool) -> Self {
        Self::new(
            reference.from_address(),
            reference.operand_index(),
            reference.to_address(),
            is_primary,
        )
    }

    /// Creates a command for setting whether or not a reference is the primary reference.
    /// If `is_primary` is true, any other reference that was primary at that address will
    /// no longer be primary.
    ///
    /// # Arguments
    ///
    /// * `from_addr` - the address of the codeunit making the reference.
    /// * `op_index` - the operand index.
    /// * `to_addr` - the address being referred to.
    /// * `is_primary` - true to make the reference primary, false to make it non-primary.
    pub fn new(from_addr: Address, op_index: i32, to_addr: Address, is_primary: bool) -> Self {
        SetPrimaryRefCmd {
            from_addr,
            op_index,
            to_addr,
            is_primary,
            status: None,
        }
    }
}

impl Command<dyn Program + 'static> for SetPrimaryRefCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(ref_mgr) = program.get_reference_manager() else {
            self.status = Some("Reference not found".to_string());
            return false;
        };

        let Some(reference) =
            ref_mgr.get_reference(self.from_addr.clone(), self.to_addr.clone(), self.op_index)
        else {
            self.status = Some("Reference not found".to_string());
            return false;
        };

        ref_mgr.set_primary(reference, self.is_primary);

        true
    }

    fn status_msg(&self) -> Option<String> {
        self.status.clone()
    }

    fn name(&self) -> String {
        "Set Primary Reference".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::reference_manager::AddExternalReferenceError;
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
        is_primary: bool,
    }

    impl Reference for MockReference {
        fn from_address(&self) -> Address {
            self.from_addr
        }

        fn to_address(&self) -> Address {
            self.to_addr
        }

        fn is_primary(&self) -> bool {
            self.is_primary
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
            false
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
        reference: Option<Arc<dyn Reference>>,
        last_primary_call: Option<bool>,
    }

    impl ReferenceManager for MockReferenceManager {
        fn add_reference(&mut self, reference: Arc<dyn Reference>) -> Arc<dyn Reference> {
            reference
        }

        fn add_stack_reference(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _stack_offset: i32,
            _ref_type: RefType,
            _source: SourceType,
        ) -> Arc<dyn Reference> {
            unimplemented!()
        }

        fn add_register_reference(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _register: &Register,
            _ref_type: RefType,
            _source: SourceType,
        ) -> Arc<dyn Reference> {
            unimplemented!()
        }

        fn add_memory_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn Reference> {
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
        ) -> Arc<dyn Reference> {
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
        ) -> Arc<dyn Reference> {
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
        ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
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
        ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
            unimplemented!()
        }

        fn add_external_reference_for_location(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _location: Arc<dyn ExternalLocation>,
            _source: SourceType,
            _ref_type: RefType,
        ) -> Result<Arc<dyn Reference>, InvalidInputException> {
            unimplemented!()
        }

        fn remove_all_references_from_range(&mut self, _begin_addr: Address, _end_addr: Address) {}

        fn remove_all_references_from(&mut self, _from_addr: Address) {}

        fn remove_all_references_to(&mut self, _to_addr: Address) {}

        fn get_references_to_variable(&self, _var: &dyn Variable) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_referenced_variable(&self, _reference: &dyn Reference) -> Option<Box<dyn Variable>> {
            None
        }

        fn set_primary(&mut self, _reference: Arc<dyn Reference>, is_primary: bool) {
            self.last_primary_call = Some(is_primary);
        }

        fn has_flow_references_from(&self, _addr: Address) -> bool {
            false
        }

        fn get_flow_references_from(&self, _addr: Address) -> Vec<Arc<dyn Reference>> {
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
        ) -> Option<Arc<dyn Reference>> {
            self.reference.clone()
        }

        fn get_references_from(&self, _addr: Address) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_references_from_operand(
            &self,
            _from_addr: Address,
            _op_index: i32,
        ) -> Vec<Arc<dyn Reference>> {
            Vec::new()
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
        ) -> Option<Arc<dyn Reference>> {
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
            reference: Arc<dyn Reference>,
            _ref_type: RefType,
        ) -> Arc<dyn Reference> {
            reference
        }

        fn set_association(&mut self, _symbol: Arc<dyn Symbol>, _reference: Arc<dyn Reference>) {}

        fn remove_association(&mut self, _reference: Arc<dyn Reference>) {}

        fn delete(&mut self, _reference: Arc<dyn Reference>) {}

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
        let cmd = SetPrimaryRefCmd::new(addr(0x1000), 0, addr(0x2000), true);
        assert_eq!(cmd.name(), "Set Primary Reference");
    }

    #[test]
    fn from_reference_extracts_fields() {
        let reference = MockReference {
            from_addr: addr(0x1000),
            to_addr: addr(0x2000),
            op_index: 1,
            is_primary: false,
        };
        let cmd = SetPrimaryRefCmd::from_reference(&reference, true);
        assert_eq!(cmd.from_addr, addr(0x1000));
        assert_eq!(cmd.to_addr, addr(0x2000));
        assert_eq!(cmd.op_index, 1);
        assert!(cmd.is_primary);
    }

    #[test]
    fn apply_to_sets_primary_when_reference_found() {
        let mock_ref: Arc<dyn Reference> = Arc::new(MockReference {
            from_addr: addr(0x1000),
            to_addr: addr(0x2000),
            op_index: 0,
            is_primary: false,
        });
        let mut program = MockProgram {
            ref_mgr: Some(MockReferenceManager {
                reference: Some(mock_ref),
                last_primary_call: None,
            }),
        };
        let mut cmd = SetPrimaryRefCmd::new(addr(0x1000), 0, addr(0x2000), true);

        assert!(cmd.apply_to(&mut program));
        assert_eq!(
            program.ref_mgr.as_ref().unwrap().last_primary_call,
            Some(true)
        );
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_returns_false_when_reference_not_found() {
        let mut program = MockProgram {
            ref_mgr: Some(MockReferenceManager {
                reference: None,
                last_primary_call: None,
            }),
        };
        let mut cmd = SetPrimaryRefCmd::new(addr(0x1000), 0, addr(0x2000), true);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), Some("Reference not found".to_string()));
    }

    #[test]
    fn apply_to_returns_false_when_reference_manager_not_available() {
        let mut program = MockProgram { ref_mgr: None };
        let mut cmd = SetPrimaryRefCmd::new(addr(0x1000), 0, addr(0x2000), true);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), Some("Reference not found".to_string()));
    }
}
