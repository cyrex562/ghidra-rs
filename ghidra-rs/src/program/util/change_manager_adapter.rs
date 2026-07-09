/// Empty/no-op implementation of `ChangeManager`.
///
/// Port of `ghidra.program.util.ChangeManagerAdapter`. All methods are no-ops, suitable
/// for contexts where change tracking is not needed.

use std::any::Any;

use crate::program::model::address::Address;
use crate::program::model::lang::Register;
use crate::program::util::{ChangeManager, ProgramEvent};

/// A no-op adapter implementation of `ChangeManager`.
///
/// All methods are empty implementations that do nothing. This is useful when you need
/// to provide a `ChangeManager` implementation but do not actually need to track or
/// process any changes.
#[derive(Debug, Default, Clone)]
pub struct ChangeManagerAdapter;

impl ChangeManagerAdapter {
    /// Creates a new `ChangeManagerAdapter`.
    pub fn new() -> Self {
        Self
    }
}

impl ChangeManager for ChangeManagerAdapter {
    fn set_changed(
        &mut self,
        _event_type: ProgramEvent,
        _old_value: Option<Box<dyn Any + Send + Sync>>,
        _new_value: Option<Box<dyn Any + Send + Sync>>,
    ) {
    }

    fn set_register_values_changed(
        &mut self,
        _register: Option<&Register>,
        _start: &Address,
        _end: &Address,
    ) {
    }

    fn set_changed_range(
        &mut self,
        _event_type: ProgramEvent,
        _start: &Address,
        _end: &Address,
        _old_value: Option<Box<dyn Any + Send + Sync>>,
        _new_value: Option<Box<dyn Any + Send + Sync>>,
    ) {
    }

    fn set_obj_changed(
        &mut self,
        _event_type: ProgramEvent,
        _affected: Option<Box<dyn Any + Send + Sync>>,
        _old_value: Option<Box<dyn Any + Send + Sync>>,
        _new_value: Option<Box<dyn Any + Send + Sync>>,
    ) {
    }

    fn set_obj_changed_at(
        &mut self,
        _event_type: ProgramEvent,
        _addr: Option<&Address>,
        _affected: Option<Box<dyn Any + Send + Sync>>,
        _old_value: Option<Box<dyn Any + Send + Sync>>,
        _new_value: Option<Box<dyn Any + Send + Sync>>,
    ) {
    }

    fn set_property_changed(
        &mut self,
        _property_name: &str,
        _code_unit_addr: &Address,
        _old_value: Option<Box<dyn Any + Send + Sync>>,
        _new_value: Option<Box<dyn Any + Send + Sync>>,
    ) {
    }

    fn set_property_range_removed(&mut self, _property_name: &str, _start: &Address, _end: &Address) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace};

    #[test]
    fn can_create_adapter() {
        let adapter = ChangeManagerAdapter::new();
        assert_eq!(adapter, ChangeManagerAdapter::default());
    }

    #[test]
    fn set_changed_no_op() {
        let mut adapter = ChangeManagerAdapter::new();
        adapter.set_changed(
            ProgramEvent::MemoryBytesChanged,
            Some(Box::new("old")),
            Some(Box::new("new")),
        );
    }

    #[test]
    fn set_register_values_changed_no_op() {
        let mut adapter = ChangeManagerAdapter::new();
        let addr_space = AddressSpace::default_space();
        let start = Address::new(&addr_space, 0x1000);
        let end = Address::new(&addr_space, 0x1100);
        adapter.set_register_values_changed(None, &start, &end);
    }

    #[test]
    fn set_changed_range_no_op() {
        let mut adapter = ChangeManagerAdapter::new();
        let addr_space = AddressSpace::default_space();
        let start = Address::new(&addr_space, 0x1000);
        let end = Address::new(&addr_space, 0x1100);
        adapter.set_changed_range(
            ProgramEvent::MemoryBytesChanged,
            &start,
            &end,
            Some(Box::new("old")),
            Some(Box::new("new")),
        );
    }

    #[test]
    fn set_obj_changed_no_op() {
        let mut adapter = ChangeManagerAdapter::new();
        adapter.set_obj_changed(
            ProgramEvent::CodeAdded,
            Some(Box::new("affected")),
            Some(Box::new("old")),
            Some(Box::new("new")),
        );
    }

    #[test]
    fn set_obj_changed_at_no_op() {
        let mut adapter = ChangeManagerAdapter::new();
        let addr_space = AddressSpace::default_space();
        let addr = Some(&Address::new(&addr_space, 0x2000));
        adapter.set_obj_changed_at(
            ProgramEvent::CodeAdded,
            addr,
            Some(Box::new("affected")),
            Some(Box::new("old")),
            Some(Box::new("new")),
        );
    }

    #[test]
    fn set_property_changed_no_op() {
        let mut adapter = ChangeManagerAdapter::new();
        let addr_space = AddressSpace::default_space();
        let addr = Address::new(&addr_space, 0x1000);
        adapter.set_property_changed(
            "color",
            &addr,
            Some(Box::new("red")),
            Some(Box::new("blue")),
        );
    }

    #[test]
    fn set_property_range_removed_no_op() {
        let mut adapter = ChangeManagerAdapter::new();
        let addr_space = AddressSpace::default_space();
        let start = Address::new(&addr_space, 0x1000);
        let end = Address::new(&addr_space, 0x1100);
        adapter.set_property_range_removed("comment", &start, &end);
    }

    #[test]
    fn adapter_is_cloneable() {
        let adapter1 = ChangeManagerAdapter::new();
        let adapter2 = adapter1.clone();
        assert_eq!(adapter1, adapter2);
    }

    #[test]
    fn adapter_is_default_constructible() {
        let _adapter: ChangeManagerAdapter = Default::default();
    }
}
