use crate::program::model::address::Address;
use crate::program::model::symbol::{Reference, SourceType};

/// Listener notified when symbol table state changes.
///
/// This mirrors Ghidra's `SymbolTableListener` interface. The upstream Java
/// signatures use `SourceType` for the symbol arguments, so this port preserves
/// that contract.
pub trait SymbolTableListener {
    /// Notification that a symbol has been added.
    fn symbol_added(&mut self, symbol: SourceType);

    /// Notification that a symbol was removed.
    fn symbol_removed(&mut self, address: &Address, name: &str, local: bool);

    /// Notification that a symbol was renamed.
    fn symbol_renamed(&mut self, symbol: SourceType, old_name: &str);

    /// Notification that a symbol was set as the primary symbol.
    fn primary_symbol_set(&mut self, symbol: SourceType);

    /// Notification that a symbol's scope changed.
    fn symbol_scope_changed(&mut self, symbol: SourceType);

    /// Notification that an external entry point was added at an address.
    fn external_entry_point_added(&mut self, address: &Address);

    /// Notification that an external entry point was removed from an address.
    fn external_entry_point_removed(&mut self, address: &Address);

    /// Notification that a reference-to-symbol association was added.
    fn association_added(&mut self, symbol: SourceType, reference: &dyn Reference);

    /// Notification that a reference-to-symbol association was removed.
    fn association_removed(&mut self, reference: &dyn Reference);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType};

    #[derive(Default)]
    struct RecordingListener {
        events: Vec<String>,
    }

    impl SymbolTableListener for RecordingListener {
        fn symbol_added(&mut self, symbol: SourceType) {
            self.events
                .push(format!("symbol_added:{}", symbol.display_string()));
        }

        fn symbol_removed(&mut self, address: &Address, name: &str, local: bool) {
            self.events
                .push(format!("symbol_removed:{address}:{name}:{local}"));
        }

        fn symbol_renamed(&mut self, symbol: SourceType, old_name: &str) {
            self.events.push(format!(
                "symbol_renamed:{}:{old_name}",
                symbol.display_string()
            ));
        }

        fn primary_symbol_set(&mut self, symbol: SourceType) {
            self.events
                .push(format!("primary_symbol_set:{}", symbol.display_string()));
        }

        fn symbol_scope_changed(&mut self, symbol: SourceType) {
            self.events
                .push(format!("symbol_scope_changed:{}", symbol.display_string()));
        }

        fn external_entry_point_added(&mut self, address: &Address) {
            self.events
                .push(format!("external_entry_point_added:{address}"));
        }

        fn external_entry_point_removed(&mut self, address: &Address) {
            self.events
                .push(format!("external_entry_point_removed:{address}"));
        }

        fn association_added(&mut self, symbol: SourceType, reference: &dyn Reference) {
            self.events.push(format!(
                "association_added:{}:{}",
                symbol.display_string(),
                reference.to_address()
            ));
        }

        fn association_removed(&mut self, reference: &dyn Reference) {
            self.events
                .push(format!("association_removed:{}", reference.symbol_id()));
        }
    }

    #[test]
    fn listener_receives_symbol_table_event_values() {
        let mut listener = RecordingListener::default();
        let address = addr(0x1000);
        let reference = TestReference;

        listener.symbol_added(SourceType::UserDefined);
        listener.symbol_removed(&address, "label", true);
        listener.symbol_renamed(SourceType::Imported, "old_label");
        listener.primary_symbol_set(SourceType::Analysis);
        listener.symbol_scope_changed(SourceType::Default);
        listener.external_entry_point_added(&address);
        listener.external_entry_point_removed(&address);
        listener.association_added(SourceType::AI, &reference);
        listener.association_removed(&reference);

        assert_eq!(
            listener.events,
            vec![
                "symbol_added:User Defined",
                "symbol_removed:ram:0x1000:label:true",
                "symbol_renamed:Imported:old_label",
                "primary_symbol_set:Analysis",
                "symbol_scope_changed:Default",
                "external_entry_point_added:ram:0x1000",
                "external_entry_point_removed:ram:0x1000",
                "association_added:AI:ram:0x2000",
                "association_removed:42",
            ]
        );
    }

    struct TestReference;

    impl Reference for TestReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn from_address(&self) -> Address {
            addr(0x1000)
        }

        fn to_address(&self) -> Address {
            addr(0x2000)
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn symbol_id(&self) -> i64 {
            42
        }

        fn reference_type(&self) -> RefType {
            RefType::Read
        }

        fn operand_index(&self) -> i32 {
            0
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
            SourceType::UserDefined
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
