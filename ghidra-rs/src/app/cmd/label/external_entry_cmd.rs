use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::symbol::SymbolTable;

/// Command for setting/unsetting an external entry point.
pub struct ExternalEntryCmd {
    addr: Address,
    is_entry: bool,
    msg: Option<String>,
}

impl ExternalEntryCmd {
    /// Constructs a new command for setting/unsetting an external entry point.
    ///
    /// # Arguments
    ///
    /// * `addr` - address to set or unset as an external entry point.
    /// * `is_entry` - true if the address is to be an entry. Otherwise, false.
    pub fn new(addr: Address, is_entry: bool) -> Self {
        ExternalEntryCmd {
            addr,
            is_entry,
            msg: None,
        }
    }
}

impl Command<dyn Program + 'static> for ExternalEntryCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(symbol_table) = program.get_symbol_table() else {
            self.msg = Some("No symbol table available for program.".to_string());
            return false;
        };

        let result = if self.is_entry {
            symbol_table.add_external_entry_point(&self.addr)
        } else {
            symbol_table.remove_external_entry_point(&self.addr)
        };

        match result {
            Ok(_) => true,
            Err(e) => {
                self.msg = Some(format!("Failed to update external entry point: {}", e));
                false
            }
        }
    }

    fn status_msg(&self) -> Option<String> {
        self.msg.clone()
    }

    fn name(&self) -> String {
        format!("Set External{}", self.is_entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Listing;
    use crate::program::model::symbol::{SourceType, Symbol, SymbolType};
    use std::io;
    use std::sync::Arc;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockProgram {
        symbol_table: Option<MockSymbolTable>,
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

        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            self.symbol_table.as_mut().map(|table| table as &mut dyn SymbolTable)
        }
    }

    struct MockSymbolTable {
        external_entries: std::collections::HashSet<String>,
    }

    impl MockSymbolTable {
        fn new() -> Self {
            MockSymbolTable {
                external_entries: std::collections::HashSet::new(),
            }
        }

        fn is_external_entry(&self, a: &Address) -> bool {
            self.external_entries.contains(&a.to_string())
        }
    }

    impl SymbolTable for MockSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!()
        }

        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            unimplemented!()
        }

        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            unimplemented!()
        }

        fn add_external_entry_point(&mut self, addr: &Address) -> io::Result<()> {
            self.external_entries.insert(addr.to_string());
            Ok(())
        }

        fn remove_external_entry_point(&mut self, addr: &Address) -> io::Result<()> {
            self.external_entries.remove(&addr.to_string());
            Ok(())
        }

        fn is_external_entry_point(&self, addr: &Address) -> io::Result<bool> {
            Ok(self.is_external_entry(addr))
        }
    }

    #[test]
    fn command_name_is_set_external_true() {
        let cmd = ExternalEntryCmd::new(addr(0x1000), true);
        assert_eq!(cmd.name(), "Set Externaltrue");
    }

    #[test]
    fn command_name_is_set_external_false() {
        let cmd = ExternalEntryCmd::new(addr(0x1000), false);
        assert_eq!(cmd.name(), "Set Externalfalse");
    }

    #[test]
    fn apply_to_adds_external_entry_point() {
        let mut program = MockProgram {
            symbol_table: Some(MockSymbolTable::new()),
        };

        let mut cmd = ExternalEntryCmd::new(addr(0x1000), true);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);

        if let Some(table) = &program.symbol_table {
            assert!(table.is_external_entry(&addr(0x1000)));
        } else {
            panic!("Expected symbol table");
        }
    }

    #[test]
    fn apply_to_removes_external_entry_point() {
        let mut table = MockSymbolTable::new();
        table.external_entries.insert(addr(0x1000).to_string());

        let mut program = MockProgram {
            symbol_table: Some(table),
        };

        let mut cmd = ExternalEntryCmd::new(addr(0x1000), false);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);

        if let Some(table) = &program.symbol_table {
            assert!(!table.is_external_entry(&addr(0x1000)));
        } else {
            panic!("Expected symbol table");
        }
    }

    #[test]
    fn apply_to_fails_when_symbol_table_not_available() {
        let mut program = MockProgram {
            symbol_table: None,
        };

        let mut cmd = ExternalEntryCmd::new(addr(0x1000), true);
        assert!(!cmd.apply_to(&mut program));
        assert!(cmd
            .status_msg()
            .unwrap()
            .contains("No symbol table available"));
    }

    #[test]
    fn status_msg_is_none_on_success() {
        let mut program = MockProgram {
            symbol_table: Some(MockSymbolTable::new()),
        };

        let mut cmd = ExternalEntryCmd::new(addr(0x1000), true);
        cmd.apply_to(&mut program);
        assert_eq!(cmd.status_msg(), None);
    }
}
