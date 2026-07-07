use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure::Structure;
use crate::program::model::listing::Program;

/// Behavior a concrete "create structure" command must supply.
///
/// Mirrors the two package-private abstract methods that Java subclasses of
/// `AbstractCreateStructureCmd` implement: `createStructure(Address, Program)` and
/// `initializeStructureData(Program, Structure)`. Rust has no inheritance, so a subclass has no
/// way to reach the base struct's private `structureName`/`structureAddress` fields through
/// inherited package-private getters; [`AbstractCreateStructureCmd`] instead passes them in
/// explicitly as `name`/`address` parameters.
///
/// Both methods return `Result::Err` in place of Java's `IllegalArgumentException`, which
/// `AbstractCreateStructureCmd::apply_to` catches and turns into a failed command with a status
/// message.
pub trait CreateStructureBehavior {
    /// Creates the [`Structure`] to be attached to the program at `address`.
    fn create_structure(
        &mut self,
        address: &Address,
        name: &str,
        program: &mut dyn Program,
    ) -> Result<Box<dyn Structure>, String>;

    /// Populates `structure` with data and returns the [`DataType`] that represents the newly
    /// created structure.
    fn initialize_structure_data(
        &mut self,
        program: &mut dyn Program,
        structure: &mut dyn Structure,
        address: &Address,
    ) -> Result<Box<dyn DataType>, String>;
}

/// A base to hold duplicate information for commands that create structures.
///
/// Port of `ghidra.app.cmd.data.AbstractCreateStructureCmd`. This struct implements the logic of
/// the Java `applyTo(Program)` method so that child implementations need only supply a
/// [`CreateStructureBehavior`], which stands in for the Java abstract methods `createStructure`
/// and `initializeStructureData`.
pub struct AbstractCreateStructureCmd {
    status_message: Option<String>,
    structure_name: String,
    new_data_type: Option<Box<dyn DataType>>,
    structure_address: Address,
    behavior: Box<dyn CreateStructureBehavior>,
}

impl AbstractCreateStructureCmd {
    /// Initializes this command to create a structure with the given name and address, using
    /// `behavior` to perform the subclass-specific work when [`apply_to`](Command::apply_to) is
    /// called.
    pub(crate) fn new(
        name: impl Into<String>,
        address: Address,
        behavior: Box<dyn CreateStructureBehavior>,
    ) -> Self {
        AbstractCreateStructureCmd {
            status_message: None,
            structure_name: name.into(),
            new_data_type: None,
            structure_address: address,
            behavior,
        }
    }

    /// Gets the new structure data type which was created.
    pub fn get_new_data_type(&self) -> Option<&dyn DataType> {
        self.new_data_type.as_deref()
    }

    pub(crate) fn get_structure_address(&self) -> &Address {
        &self.structure_address
    }

    pub(crate) fn get_structure_name(&self) -> &str {
        &self.structure_name
    }
}

impl Command<dyn Program + 'static> for AbstractCreateStructureCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let mut structure = match self.behavior.create_structure(
            &self.structure_address,
            &self.structure_name,
            program,
        ) {
            Ok(structure) => structure,
            Err(message) => {
                self.status_message = Some(message);
                return false;
            }
        };

        match self.behavior.initialize_structure_data(
            program,
            structure.as_mut(),
            &self.structure_address,
        ) {
            Ok(data_type) => {
                self.new_data_type = Some(data_type);
                true
            }
            Err(message) => {
                self.status_message = Some(message);
                false
            }
        }
    }

    fn status_msg(&self) -> Option<String> {
        self.status_message.clone()
    }

    fn name(&self) -> String {
        "Create Structure".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::composite::Composite;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockStructure;
    impl DataType for MockStructure {}
    impl Composite for MockStructure {}
    impl Structure for MockStructure {}

    struct MockProgram;
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
    }

    struct SucceedingBehavior;
    impl CreateStructureBehavior for SucceedingBehavior {
        fn create_structure(
            &mut self,
            _address: &Address,
            _name: &str,
            _program: &mut dyn Program,
        ) -> Result<Box<dyn Structure>, String> {
            Ok(Box::new(MockStructure))
        }

        fn initialize_structure_data(
            &mut self,
            _program: &mut dyn Program,
            _structure: &mut dyn Structure,
            _address: &Address,
        ) -> Result<Box<dyn DataType>, String> {
            Ok(Box::new(MockDataType))
        }
    }

    struct FailingCreateBehavior;
    impl CreateStructureBehavior for FailingCreateBehavior {
        fn create_structure(
            &mut self,
            _address: &Address,
            _name: &str,
            _program: &mut dyn Program,
        ) -> Result<Box<dyn Structure>, String> {
            Err("cannot create structure here".to_string())
        }

        fn initialize_structure_data(
            &mut self,
            _program: &mut dyn Program,
            _structure: &mut dyn Structure,
            _address: &Address,
        ) -> Result<Box<dyn DataType>, String> {
            unreachable!("create_structure fails before this is called")
        }
    }

    struct FailingInitializeBehavior;
    impl CreateStructureBehavior for FailingInitializeBehavior {
        fn create_structure(
            &mut self,
            _address: &Address,
            _name: &str,
            _program: &mut dyn Program,
        ) -> Result<Box<dyn Structure>, String> {
            Ok(Box::new(MockStructure))
        }

        fn initialize_structure_data(
            &mut self,
            _program: &mut dyn Program,
            _structure: &mut dyn Structure,
            _address: &Address,
        ) -> Result<Box<dyn DataType>, String> {
            Err("data conflicts with existing data".to_string())
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn name_is_create_structure() {
        let cmd = AbstractCreateStructureCmd::new(
            "foo",
            test_address(0x1000),
            Box::new(SucceedingBehavior),
        );
        assert_eq!(cmd.name(), "Create Structure");
    }

    #[test]
    fn new_command_has_no_status_message_or_data_type() {
        let cmd = AbstractCreateStructureCmd::new(
            "foo",
            test_address(0x1000),
            Box::new(SucceedingBehavior),
        );
        assert_eq!(cmd.status_msg(), None);
        assert!(cmd.get_new_data_type().is_none());
    }

    #[test]
    fn apply_to_succeeds_and_sets_new_data_type() {
        let mut cmd = AbstractCreateStructureCmd::new(
            "foo",
            test_address(0x1000),
            Box::new(SucceedingBehavior),
        );
        let mut program = MockProgram;

        assert!(cmd.apply_to(&mut program));
        assert!(cmd.get_new_data_type().is_some());
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_fails_when_create_structure_fails() {
        let mut cmd = AbstractCreateStructureCmd::new(
            "foo",
            test_address(0x1000),
            Box::new(FailingCreateBehavior),
        );
        let mut program = MockProgram;

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("cannot create structure here".to_string())
        );
        assert!(cmd.get_new_data_type().is_none());
    }

    #[test]
    fn apply_to_fails_when_initialize_structure_data_fails() {
        let mut cmd = AbstractCreateStructureCmd::new(
            "foo",
            test_address(0x1000),
            Box::new(FailingInitializeBehavior),
        );
        let mut program = MockProgram;

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("data conflicts with existing data".to_string())
        );
        assert!(cmd.get_new_data_type().is_none());
    }

    #[test]
    fn structure_address_and_name_are_accessible() {
        let address = test_address(0x2000);
        let cmd = AbstractCreateStructureCmd::new(
            "my_struct",
            address.clone(),
            Box::new(SucceedingBehavior),
        );
        assert_eq!(cmd.get_structure_address().offset(), address.offset());
        assert_eq!(cmd.get_structure_name(), "my_struct");
    }
}
