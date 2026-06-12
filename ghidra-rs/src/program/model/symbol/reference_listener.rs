use crate::program::model::symbol::Reference;

/// Listener notified when references are added, removed, or changed.
///
/// This mirrors Ghidra's `ReferenceListener` interface.
pub trait ReferenceListener {
    /// Notification that a memory reference has been added.
    fn mem_reference_added(&mut self, reference: &dyn Reference);

    /// Notification that a memory reference has been removed.
    fn mem_reference_removed(&mut self, reference: &dyn Reference);

    /// Notification that a memory reference's type has changed.
    fn mem_reference_type_changed(
        &mut self,
        new_reference: &dyn Reference,
        old_reference: &dyn Reference,
    );

    /// Notification that a memory reference is now primary.
    fn mem_reference_primary_set(&mut self, reference: &dyn Reference);

    /// Notification that a memory reference is no longer primary.
    fn mem_reference_primary_removed(&mut self, reference: &dyn Reference);

    /// Notification that a stack reference has been added.
    fn stack_reference_added(&mut self, reference: &dyn Reference);

    /// Notification that a stack reference has been removed.
    fn stack_reference_removed(&mut self, reference: &dyn Reference);

    /// Notification that an external reference has been added.
    fn external_reference_added(&mut self, reference: &dyn Reference);

    /// Notification that an external reference has been removed.
    fn external_reference_removed(&mut self, reference: &dyn Reference);

    /// Notification that an external reference name has changed.
    fn external_reference_name_changed(&mut self, reference: &dyn Reference);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType, ThunkReference};

    #[derive(Default)]
    struct RecordingListener {
        events: Vec<String>,
    }

    impl ReferenceListener for RecordingListener {
        fn mem_reference_added(&mut self, reference: &dyn Reference) {
            self.events
                .push(format!("mem_added:{}", reference.from_address()));
        }

        fn mem_reference_removed(&mut self, reference: &dyn Reference) {
            self.events
                .push(format!("mem_removed:{}", reference.from_address()));
        }

        fn mem_reference_type_changed(
            &mut self,
            new_reference: &dyn Reference,
            old_reference: &dyn Reference,
        ) {
            self.events.push(format!(
                "mem_type:{}:{}",
                new_reference.reference_type(),
                old_reference.reference_type()
            ));
        }

        fn mem_reference_primary_set(&mut self, reference: &dyn Reference) {
            self.events
                .push(format!("mem_primary_set:{}", reference.to_address()));
        }

        fn mem_reference_primary_removed(&mut self, reference: &dyn Reference) {
            self.events
                .push(format!("mem_primary_removed:{}", reference.to_address()));
        }

        fn stack_reference_added(&mut self, reference: &dyn Reference) {
            self.events
                .push(format!("stack_added:{}", reference.operand_index()));
        }

        fn stack_reference_removed(&mut self, reference: &dyn Reference) {
            self.events
                .push(format!("stack_removed:{}", reference.operand_index()));
        }

        fn external_reference_added(&mut self, reference: &dyn Reference) {
            self.events.push(format!(
                "external_added:{}",
                reference.is_external_reference()
            ));
        }

        fn external_reference_removed(&mut self, reference: &dyn Reference) {
            self.events.push(format!(
                "external_removed:{}",
                reference.is_external_reference()
            ));
        }

        fn external_reference_name_changed(&mut self, reference: &dyn Reference) {
            self.events.push(format!(
                "external_name:{}",
                reference.source().display_string()
            ));
        }
    }

    #[test]
    fn listener_receives_reference_event_values() {
        let mut listener = RecordingListener::default();
        let old_reference = ThunkReference::new(addr(0x1000), addr(0x2000));
        let new_reference = TestReference::new();

        listener.mem_reference_added(&new_reference);
        listener.mem_reference_removed(&new_reference);
        listener.mem_reference_type_changed(&new_reference, &old_reference);
        listener.mem_reference_primary_set(&new_reference);
        listener.mem_reference_primary_removed(&new_reference);
        listener.stack_reference_added(&new_reference);
        listener.stack_reference_removed(&new_reference);
        listener.external_reference_added(&new_reference);
        listener.external_reference_removed(&new_reference);
        listener.external_reference_name_changed(&new_reference);

        assert_eq!(
            listener.events,
            vec![
                "mem_added:ram:0x3000",
                "mem_removed:ram:0x3000",
                "mem_type:DATA:THUNK",
                "mem_primary_set:ram:0x4000",
                "mem_primary_removed:ram:0x4000",
                "stack_added:1",
                "stack_removed:1",
                "external_added:true",
                "external_removed:true",
                "external_name:User Defined",
            ]
        );
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct TestReference;

    impl TestReference {
        fn new() -> Self {
            Self
        }
    }

    impl Reference for TestReference {
        fn from_address(&self) -> Address {
            addr(0x3000)
        }

        fn to_address(&self) -> Address {
            addr(0x4000)
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn symbol_id(&self) -> i64 {
            7
        }

        fn reference_type(&self) -> RefType {
            RefType::Data
        }

        fn operand_index(&self) -> i32 {
            1
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
            true
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
}
