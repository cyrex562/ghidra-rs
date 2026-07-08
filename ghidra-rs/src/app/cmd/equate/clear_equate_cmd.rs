use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::symbol::{Equate, EquateTable};

/// Command for removing an equate reference at a location.
pub struct ClearEquateCmd {
    equate_name: String,
    addr: Address,
    op_index: i32,
    msg: Option<String>,
}

impl ClearEquateCmd {
    /// Creates a command to remove an equate reference at a location.
    ///
    /// # Arguments
    ///
    /// * `equate_name` - the name of the equate to be removed.
    /// * `addr` - the address of the current location.
    /// * `op_index` - the operand index of the current location.
    pub fn new(equate_name: impl Into<String>, addr: Address, op_index: i32) -> Self {
        ClearEquateCmd {
            equate_name: equate_name.into(),
            addr,
            op_index,
            msg: None,
        }
    }
}

impl Command<dyn Program + 'static> for ClearEquateCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(equate_table) = program.get_equate_table() else {
            self.msg = Some("No equate table available for program.".to_string());
            return false;
        };

        if let Some(equate) = equate_table.equate(&self.equate_name) {
            let reference_count = equate.reference_count();
            if reference_count <= 1 {
                equate_table.remove_equate(&self.equate_name);
            } else if let Some(equate) = equate_table.equate_mut(&self.equate_name) {
                equate.remove_reference(&self.addr, self.op_index as i16);
            }
        }

        true
    }

    fn status_msg(&self) -> Option<String> {
        self.msg.clone()
    }

    fn name(&self) -> String {
        "Remove Equate".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Listing;
    use crate::program::model::symbol::{EquateTable, SimpleEquateTable};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockProgram {
        equate_table: Option<SimpleEquateTable>,
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

        fn get_listing(&mut self) -> Option<&mut dyn Listing> {
            None
        }

        fn get_equate_table(&mut self) -> Option<&mut dyn EquateTable> {
            self.equate_table
                .as_mut()
                .map(|table| table as &mut dyn EquateTable)
        }
    }

    #[test]
    fn command_name_is_correct() {
        let cmd = ClearEquateCmd::new("FLAG", addr(0x1000), 0);
        assert_eq!(cmd.name(), "Remove Equate");
    }

    #[test]
    fn apply_to_removes_equate_when_only_one_reference() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("FLAG", 0x80).unwrap();
        let equate = table.equate_mut("FLAG").unwrap();
        equate.add_reference(addr(0x1000), 0);

        let mut program = MockProgram {
            equate_table: Some(table),
        };

        let mut cmd = ClearEquateCmd::new("FLAG", addr(0x1000), 0);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);

        let equate_table = program.equate_table.as_ref().unwrap();
        assert!(equate_table.equate("FLAG").is_none());
    }

    #[test]
    fn apply_to_removes_reference_when_multiple_references_exist() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("FLAG", 0x80).unwrap();
        let equate = table.equate_mut("FLAG").unwrap();
        equate.add_reference(addr(0x1000), 0);
        equate.add_reference(addr(0x2000), 0);
        equate.add_reference(addr(0x1000), 1);

        let mut program = MockProgram {
            equate_table: Some(table),
        };

        let mut cmd = ClearEquateCmd::new("FLAG", addr(0x1000), 0);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);

        let equate_table = program.equate_table.as_ref().unwrap();
        let equate = equate_table.equate("FLAG").unwrap();
        assert_eq!(equate.reference_count(), 2);
        assert!(equate.references_at(&addr(0x1000)).iter().all(|r| r.op_index() != 0));
    }

    #[test]
    fn apply_to_handles_nonexistent_equate() {
        let mut program = MockProgram {
            equate_table: Some(SimpleEquateTable::new()),
        };

        let mut cmd = ClearEquateCmd::new("NONEXISTENT", addr(0x1000), 0);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_fails_when_equate_table_not_available() {
        let mut program = MockProgram { equate_table: None };

        let mut cmd = ClearEquateCmd::new("FLAG", addr(0x1000), 0);
        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("No equate table available for program.".to_string())
        );
    }

    #[test]
    fn apply_to_removes_reference_at_specific_operand() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("VALUE", 5).unwrap();
        let equate = table.equate_mut("VALUE").unwrap();
        equate.add_reference(addr(0x1000), 0);
        equate.add_reference(addr(0x1000), 1);

        let mut program = MockProgram {
            equate_table: Some(table),
        };

        let mut cmd = ClearEquateCmd::new("VALUE", addr(0x1000), 0);
        assert!(cmd.apply_to(&mut program));

        let equate_table = program.equate_table.as_ref().unwrap();
        let equate = equate_table.equate("VALUE").unwrap();
        assert_eq!(equate.reference_count(), 1);
        let refs = equate.references_at(&addr(0x1000));
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].op_index(), 1);
    }
}
