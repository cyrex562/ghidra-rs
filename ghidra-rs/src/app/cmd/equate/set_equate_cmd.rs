use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::symbol::{Equate, SimpleEquate};

/// Command for setting an equate at a location.
pub struct SetEquateCmd {
    equate_name: String,
    addr: Address,
    op_index: i32,
    equate_value: i64,
    equate: Option<SimpleEquate>,
    msg: Option<String>,
}

impl SetEquateCmd {
    /// Creates a command to apply or remove an equate at a location.
    ///
    /// # Arguments
    ///
    /// * `equate_name` - the name of the equate to be applied or removed at this location.
    /// * `addr` - the address of the current location.
    /// * `op_index` - the operand index of the current location.
    /// * `equate_value` - the numeric value at the current location.
    pub fn new(equate_name: impl Into<String>, addr: Address, op_index: i32, equate_value: i64) -> Self {
        SetEquateCmd {
            equate_name: equate_name.into(),
            addr,
            op_index,
            equate_value,
            equate: None,
            msg: None,
        }
    }

    /// Returns the equate that was created or referenced by this command, if any.
    pub fn get_equate(&self) -> Option<&SimpleEquate> {
        self.equate.as_ref()
    }
}

impl Command<dyn Program + 'static> for SetEquateCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(equate_table) = program.get_equate_table() else {
            self.msg = Some("No equate table available for program.".to_string());
            return false;
        };

        let existing_value = equate_table.equate(&self.equate_name).map(|e| e.value());

        if let Some(value) = existing_value {
            if value != self.equate_value {
                self.msg = Some(format!(
                    "Equate named {} already exists with value of {}.",
                    self.equate_name, value
                ));
                self.equate = equate_table.equate(&self.equate_name).cloned();
                return false;
            }
        }
        else if let Err(err) = equate_table.create_equate(&self.equate_name, self.equate_value) {
            self.msg = Some(if err.contains("already exists") {
                format!("Equate named {} already exists", self.equate_name)
            } else {
                format!("Invalid equate name: {}", self.equate_name)
            });
            return false;
        }

        let Some(equate) = equate_table.equate_mut(&self.equate_name) else {
            return false;
        };
        equate.add_reference(self.addr.clone(), self.op_index as i16);
        self.equate = Some(equate.clone());

        true
    }

    fn status_msg(&self) -> Option<String> {
        self.msg.clone()
    }

    fn name(&self) -> String {
        "Set Equate".to_string()
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
        let cmd = SetEquateCmd::new("ONE", addr(0x1000), 0, 1);
        assert_eq!(cmd.name(), "Set Equate");
    }

    #[test]
    fn apply_to_creates_new_equate_and_adds_reference() {
        let mut program = MockProgram {
            equate_table: Some(SimpleEquateTable::new()),
        };
        let mut cmd = SetEquateCmd::new("ONE", addr(0x1000), 1, 1);

        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);

        let equate = cmd.get_equate().expect("equate should be set");
        assert_eq!(equate.name(), "ONE");
        assert_eq!(equate.value(), 1);
        assert_eq!(equate.reference_count(), 1);
    }

    #[test]
    fn apply_to_reuses_existing_equate_with_same_value() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("FIVE", 5).unwrap();
        let mut program = MockProgram {
            equate_table: Some(table),
        };
        let mut cmd = SetEquateCmd::new("FIVE", addr(0x2000), 2, 5);

        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);
        assert_eq!(cmd.get_equate().unwrap().reference_count(), 1);
    }

    #[test]
    fn apply_to_fails_when_equate_exists_with_different_value() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("FIVE", 5).unwrap();
        let mut program = MockProgram {
            equate_table: Some(table),
        };
        let mut cmd = SetEquateCmd::new("FIVE", addr(0x2000), 2, 6);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("Equate named FIVE already exists with value of 5.".to_string())
        );
        assert_eq!(cmd.get_equate().unwrap().value(), 5);
    }

    #[test]
    fn apply_to_fails_for_invalid_equate_name() {
        let mut program = MockProgram {
            equate_table: Some(SimpleEquateTable::new()),
        };
        let mut cmd = SetEquateCmd::new("bad name", addr(0x1000), 0, 1);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("Invalid equate name: bad name".to_string())
        );
        assert!(cmd.get_equate().is_none());
    }

    #[test]
    fn apply_to_fails_when_equate_table_not_available() {
        let mut program = MockProgram { equate_table: None };
        let mut cmd = SetEquateCmd::new("ONE", addr(0x1000), 0, 1);

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("No equate table available for program.".to_string())
        );
    }
}
