use crate::framework::cmd::Command;
use crate::program::model::listing::Program;

/// Command for removing all references to equates.
pub struct RemoveEquateCmd {
    equate_names: Vec<String>,
    msg: Option<String>,
}

impl RemoveEquateCmd {
    /// Creates a command to remove one or more equates.
    ///
    /// # Arguments
    ///
    /// * `equate_names` - one or more equate names to be removed.
    pub fn new<I>(equate_names: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        RemoveEquateCmd {
            equate_names: equate_names
                .into_iter()
                .map(|name| name.into())
                .collect(),
            msg: None,
        }
    }
}

impl Command<dyn Program + 'static> for RemoveEquateCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(equate_table) = program.get_equate_table() else {
            self.msg = Some("No equate table available for program.".to_string());
            return false;
        };

        let mut success = true;
        for name in &self.equate_names {
            if !equate_table.remove_equate(name) {
                success = false;
            }
        }

        if !success {
            self.msg = Some("Failed to remove one or more equates".to_string());
        }

        success
    }

    fn status_msg(&self) -> Option<String> {
        self.msg.clone()
    }

    fn name(&self) -> String {
        if self.equate_names.len() > 1 {
            "Remove Equates".to_string()
        } else {
            "Remove Equate".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::listing::Listing;
    use crate::program::model::symbol::{EquateTable, SimpleEquateTable};

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
    fn command_name_single_equate() {
        let cmd = RemoveEquateCmd::new(vec!["FLAG"]);
        assert_eq!(cmd.name(), "Remove Equate");
    }

    #[test]
    fn command_name_multiple_equates() {
        let cmd = RemoveEquateCmd::new(vec!["FLAG", "MASK"]);
        assert_eq!(cmd.name(), "Remove Equates");
    }

    #[test]
    fn command_name_many_equates() {
        let cmd = RemoveEquateCmd::new(vec!["A", "B", "C", "D"]);
        assert_eq!(cmd.name(), "Remove Equates");
    }

    #[test]
    fn apply_to_removes_single_equate() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("FLAG", 0x80).unwrap();
        let mut program = MockProgram {
            equate_table: Some(table),
        };

        let mut cmd = RemoveEquateCmd::new(vec!["FLAG"]);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);

        let equate_table = program.equate_table.as_ref().unwrap();
        assert!(equate_table.equate("FLAG").is_none());
    }

    #[test]
    fn apply_to_removes_multiple_equates() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("FLAG", 0x80).unwrap();
        table.create_equate("MASK", 0xFF).unwrap();
        table.create_equate("VALUE", 42).unwrap();

        let mut program = MockProgram {
            equate_table: Some(table),
        };

        let mut cmd = RemoveEquateCmd::new(vec!["FLAG", "MASK"]);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);

        let equate_table = program.equate_table.as_ref().unwrap();
        assert!(equate_table.equate("FLAG").is_none());
        assert!(equate_table.equate("MASK").is_none());
        assert!(equate_table.equate("VALUE").is_some());
    }

    #[test]
    fn apply_to_fails_when_equate_not_found() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("FLAG", 0x80).unwrap();

        let mut program = MockProgram {
            equate_table: Some(table),
        };

        let mut cmd = RemoveEquateCmd::new(vec!["NONEXISTENT"]);
        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("Failed to remove one or more equates".to_string())
        );

        let equate_table = program.equate_table.as_ref().unwrap();
        assert!(equate_table.equate("FLAG").is_some());
    }

    #[test]
    fn apply_to_fails_partially_when_some_equates_not_found() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("FLAG", 0x80).unwrap();
        table.create_equate("MASK", 0xFF).unwrap();

        let mut program = MockProgram {
            equate_table: Some(table),
        };

        let mut cmd = RemoveEquateCmd::new(vec!["FLAG", "NONEXISTENT", "MASK"]);
        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("Failed to remove one or more equates".to_string())
        );

        let equate_table = program.equate_table.as_ref().unwrap();
        assert!(equate_table.equate("FLAG").is_none());
        assert!(equate_table.equate("MASK").is_none());
    }

    #[test]
    fn apply_to_fails_when_equate_table_not_available() {
        let mut program = MockProgram { equate_table: None };

        let mut cmd = RemoveEquateCmd::new(vec!["FLAG"]);
        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some("No equate table available for program.".to_string())
        );
    }

    #[test]
    fn apply_to_succeeds_with_empty_names_list() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("FLAG", 0x80).unwrap();

        let mut program = MockProgram {
            equate_table: Some(table),
        };

        let mut cmd = RemoveEquateCmd::new(Vec::<String>::new());
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);

        let equate_table = program.equate_table.as_ref().unwrap();
        assert!(equate_table.equate("FLAG").is_some());
    }

    #[test]
    fn apply_to_removes_all_equates_when_given_all_names() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();
        table.create_equate("C", 3).unwrap();

        let mut program = MockProgram {
            equate_table: Some(table),
        };

        let mut cmd = RemoveEquateCmd::new(vec!["A", "B", "C"]);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);

        let equate_table = program.equate_table.as_ref().unwrap();
        assert!(equate_table.equate("A").is_none());
        assert!(equate_table.equate("B").is_none());
        assert!(equate_table.equate("C").is_none());
    }
}
