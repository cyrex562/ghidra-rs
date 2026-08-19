use std::collections::BTreeSet;
use std::rc::Rc;

use crate::program::model::lang::RegisterRef;

/// A row of the "available registers" table shown when choosing which registers to track.
///
/// Ported from `ghidra.app.plugin.core.debug.gui.register.AvailableRegisterRow`.
pub struct AvailableRegisterRow {
    number: i32,
    register: RegisterRef,
    contains: String,
    known: bool,
    selected: bool,
}

impl AvailableRegisterRow {
    /// Creates a new row for `register` at table position `number`.
    ///
    /// Eagerly computes the "contains" column (a sorted, comma-separated list of descendant
    /// register names) so the table can search it without recomputing on every render.
    pub fn new(number: i32, register: RegisterRef) -> Self {
        let contains = Self::compute_contains(&register);
        Self {
            number,
            register,
            contains,
            known: false,
            selected: false,
        }
    }

    fn compute_contains(register: &RegisterRef) -> String {
        let mut descendants = BTreeSet::new();
        Self::collect_children(register, &mut descendants);
        descendants.into_iter().collect::<Vec<_>>().join(", ")
    }

    fn collect_children(reg: &RegisterRef, set: &mut BTreeSet<String>) {
        for child in reg.borrow().child_registers() {
            set.insert(child.borrow().name().to_string());
            Self::collect_children(&child, set);
        }
    }

    /// Returns the register this row describes.
    pub fn register(&self) -> &RegisterRef {
        &self.register
    }

    /// Returns the row's table index.
    pub fn number(&self) -> i32 {
        self.number
    }

    /// Returns the register's name.
    pub fn name(&self) -> String {
        self.register.borrow().name().to_string()
    }

    /// Returns the register's bit length.
    pub fn bits(&self) -> i32 {
        self.register.borrow().bit_length()
    }

    /// Returns the register's group, or `"(none)"` if it has none.
    pub fn group(&self) -> String {
        match self.register.borrow().group() {
            Some(group) => group.to_string(),
            None => "(none)".to_string(),
        }
    }

    /// Returns whether this row is currently selected in the table.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Sets whether this row is selected in the table.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Returns whether this register's value is known.
    pub fn is_known(&self) -> bool {
        self.known
    }

    /// Sets whether this register's value is known.
    ///
    /// Note: not modifiable by the table itself.
    pub fn set_known(&mut self, known: bool) {
        self.known = known;
    }

    /// Returns the sorted, comma-separated names of this register's descendants.
    pub fn contains(&self) -> &str {
        &self.contains
    }

    /// Returns the name of this register's base register, or `""` if this register has no
    /// distinct base register.
    pub fn parent_name(&self) -> String {
        let base = self.register.borrow().get_base_register();
        if Rc::ptr_eq(&base, &self.register) {
            return String::new();
        }
        let name = base.borrow().name().to_string();
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::Register;
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(Arc::clone(space), offset)
    }

    #[test]
    fn number_and_name() {
        let space = space();
        let reg = Register::new("r0", "General register 0", addr(&space, 0), 4, false, 0);
        let row = AvailableRegisterRow::new(3, reg);

        assert_eq!(row.number(), 3);
        assert_eq!(row.name(), "r0");
        assert_eq!(row.bits(), 32);
    }

    #[test]
    fn group_defaults_to_none_placeholder() {
        let space = space();
        let reg = Register::new("r1", "General register 1", addr(&space, 4), 4, false, 0);
        let row = AvailableRegisterRow::new(0, reg);

        assert_eq!(row.group(), "(none)");
    }

    #[test]
    fn selected_and_known_are_mutable_and_default_false() {
        let space = space();
        let reg = Register::new("r2", "General register 2", addr(&space, 8), 4, false, 0);
        let mut row = AvailableRegisterRow::new(0, reg);

        assert!(!row.is_selected());
        assert!(!row.is_known());

        row.set_selected(true);
        row.set_known(true);

        assert!(row.is_selected());
        assert!(row.is_known());
    }

    #[test]
    fn parent_name_is_empty_when_register_is_its_own_base() {
        let space = space();
        let reg = Register::new("r3", "General register 3", addr(&space, 12), 4, false, 0);
        let row = AvailableRegisterRow::new(0, reg);

        assert_eq!(row.parent_name(), "");
    }

    #[test]
    fn contains_lists_descendants_sorted_and_joined() {
        let space = space();
        let parent = Register::new("eax", "32-bit accumulator", addr(&space, 16), 4, false, 0);
        let low_byte = Register::with_bit_range(
            "al",
            "low byte",
            addr(&space, 16),
            4,
            0,
            8,
            false,
            0,
        );
        let high_byte = Register::with_bit_range(
            "ah",
            "high byte",
            addr(&space, 16),
            4,
            8,
            8,
            false,
            0,
        );
        parent
            .borrow_mut()
            .set_child_registers(vec![low_byte, high_byte]);

        let row = AvailableRegisterRow::new(0, parent);

        assert_eq!(row.contains(), "ah, al");
    }
}
