use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::symbol::SymbolTable;

/// Command for setting the pinned status on a symbol.
pub struct PinSymbolCmd {
    addr: Address,
    name: String,
    pin: bool,
    msg: Option<String>,
}

impl PinSymbolCmd {
    /// Creates a command to set the pinned status of a symbol.
    ///
    /// # Arguments
    ///
    /// * `addr` - the address of the symbol.
    /// * `name` - the name of the symbol.
    /// * `pin` - whether to pin or unpin the symbol.
    pub fn new(addr: Address, name: impl Into<String>, pin: bool) -> Self {
        PinSymbolCmd {
            addr,
            name: name.into(),
            pin,
            msg: None,
        }
    }
}

impl Command<dyn Program + 'static> for PinSymbolCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let Some(symbol_table) = program.get_symbol_table() else {
            self.msg = Some("No symbol table available for program.".to_string());
            return false;
        };

        match symbol_table.get_global_symbol(&self.name, &self.addr) {
            Ok(Some(symbol)) => {
                let symbol_id = symbol.get_id();
                if let Err(_) = symbol_table.set_symbol_pinned(symbol_id, self.pin) {
                    self.msg = Some("Failed to update symbol pinned status.".to_string());
                    return false;
                }
                true
            }
            Ok(None) => {
                self.msg = Some(format!(
                    "Could not find symbol named {} at address {}",
                    self.name, self.addr
                ));
                false
            }
            Err(_) => {
                self.msg = Some("Error accessing symbol table.".to_string());
                false
            }
        }
    }

    fn status_msg(&self) -> Option<String> {
        self.msg.clone()
    }

    fn name(&self) -> String {
        format!("Set Pinned on {}", self.name)
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

    struct MockSymbol {
        id: i64,
        name: String,
        address: Address,
        pinned: bool,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }

        fn get_source(&self) -> crate::program::model::symbol::SourceType {
            SourceType::UserDefined
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    struct MockSymbolTable {
        symbols: Vec<(Arc<dyn Symbol>, bool)>,
    }

    impl MockSymbolTable {
        fn new() -> Self {
            MockSymbolTable {
                symbols: Vec::new(),
            }
        }

        fn add_symbol(&mut self, id: i64, name: &str, address: Address) {
            let symbol = MockSymbol {
                id,
                name: name.to_string(),
                address,
                pinned: false,
            };
            self.symbols.push((Arc::new(symbol) as Arc<dyn Symbol>, false));
        }

        fn is_pinned(&self, id: i64) -> Option<bool> {
            self.symbols
                .iter()
                .find(|(s, _)| s.get_id() == id)
                .map(|(_, pinned)| *pinned)
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

        fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.symbols
                .iter()
                .find(|(s, _)| s.get_id() == id)
                .map(|(s, _)| s.clone()))
        }

        fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self
                .symbols
                .iter()
                .filter(|(s, _)| s.get_address() == *addr)
                .map(|(s, _)| s.clone())
                .collect())
        }

        fn set_symbol_pinned(&mut self, symbol_id: i64, pinned: bool) -> io::Result<()> {
            for (_, is_pinned) in &mut self.symbols {
                if let Some(entry) = self.symbols.iter_mut().find(|(s, _)| s.get_id() == symbol_id) {
                    entry.1 = pinned;
                    return Ok(());
                }
            }
            Ok(())
        }
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

    #[test]
    fn command_name_is_correct() {
        let cmd = PinSymbolCmd::new(addr(0x1000), "test_label", true);
        assert_eq!(cmd.name(), "Set Pinned on test_label");
    }

    #[test]
    fn apply_to_pins_symbol() {
        let mut table = MockSymbolTable::new();
        table.add_symbol(1, "my_label", addr(0x1000));

        let mut program = MockProgram {
            symbol_table: Some(table),
        };

        let mut cmd = PinSymbolCmd::new(addr(0x1000), "my_label", true);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_unpins_symbol() {
        let mut table = MockSymbolTable::new();
        table.add_symbol(1, "my_label", addr(0x1000));

        let mut program = MockProgram {
            symbol_table: Some(table),
        };

        let mut cmd = PinSymbolCmd::new(addr(0x1000), "my_label", false);
        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_fails_when_symbol_not_found() {
        let mut program = MockProgram {
            symbol_table: Some(MockSymbolTable::new()),
        };

        let mut cmd = PinSymbolCmd::new(addr(0x1000), "nonexistent", true);
        assert!(!cmd.apply_to(&mut program));
        assert!(cmd.status_msg().unwrap().contains("Could not find symbol"));
    }

    #[test]
    fn apply_to_fails_when_symbol_table_not_available() {
        let mut program = MockProgram {
            symbol_table: None,
        };

        let mut cmd = PinSymbolCmd::new(addr(0x1000), "label", true);
        assert!(!cmd.apply_to(&mut program));
        assert!(cmd.status_msg().unwrap().contains("No symbol table"));
    }

    #[test]
    fn apply_to_fails_when_symbol_at_wrong_address() {
        let mut table = MockSymbolTable::new();
        table.add_symbol(1, "my_label", addr(0x1000));

        let mut program = MockProgram {
            symbol_table: Some(table),
        };

        let mut cmd = PinSymbolCmd::new(addr(0x2000), "my_label", true);
        assert!(!cmd.apply_to(&mut program));
        assert!(cmd.status_msg().unwrap().contains("Could not find symbol"));
    }
}
