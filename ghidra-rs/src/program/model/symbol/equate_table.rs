use crate::program::model::address::{
    Address, AddressIterator, AddressIteratorAdapter, AddressRange, AddressSetView,
};
use crate::program::model::symbol::{Equate, EquateReference, SimpleEquate};
use std::collections::{BTreeMap, BTreeSet};

/// Table of user-defined equates for a program.
///
/// This mirrors Ghidra's `EquateTable` model contract. `SimpleEquateTable`
/// provides an in-memory implementation suitable for model tests and callers
/// that do not require ProgramDB persistence.
pub trait EquateTable {
    /// Creates a new equate with the given name and scalar value.
    fn create_equate(&mut self, name: &str, value: i64) -> Result<&mut SimpleEquate, String>;

    /// Removes the named equate and all of its references.
    fn remove_equate(&mut self, name: &str) -> bool;

    /// Removes all equate references in the inclusive address range.
    fn delete_address_range(&mut self, start: &Address, end: &Address);

    /// Returns the equate with the given name.
    fn equate(&self, name: &str) -> Option<&SimpleEquate>;

    /// Returns the first equate for the address, operand position, and value.
    fn equate_at_value(
        &self,
        reference: &Address,
        opnd_position: i16,
        value: i64,
    ) -> Option<&SimpleEquate>;

    /// Returns equates at a given address and operand position.
    fn equates_at_operand(&self, reference: &Address, opnd_position: i16) -> Vec<&SimpleEquate>;

    /// Returns equates at a given address.
    fn equates_at(&self, reference: &Address) -> Vec<&SimpleEquate>;

    /// Returns an iterator over addresses with equate references.
    fn equate_addresses(&self) -> Box<dyn AddressIterator>;

    /// Returns all equates with the given scalar value.
    fn equates_for_value(&self, value: i64) -> Vec<&SimpleEquate>;

    /// Returns all equates.
    fn equates(&self) -> Vec<&SimpleEquate>;

    /// Returns addresses with equate references at or after the start address.
    fn equate_addresses_from(&self, start: &Address) -> Box<dyn AddressIterator>;

    /// Returns addresses with equate references that are inside the supplied set.
    fn equate_addresses_in(&self, set: &dyn AddressSetView) -> Box<dyn AddressIterator>;
}

/// In-memory equate table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimpleEquateTable {
    equates: BTreeMap<String, SimpleEquate>,
}

impl SimpleEquateTable {
    /// Creates an empty equate table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a mutable equate by name.
    pub fn equate_mut(&mut self, name: &str) -> Option<&mut SimpleEquate> {
        self.equates.get_mut(name)
    }

    fn referenced_addresses(&self) -> Vec<Address> {
        let mut addresses = BTreeSet::new();
        for equate in self.equates.values() {
            for reference in equate.references() {
                addresses.insert(reference.address().clone());
            }
        }
        addresses.into_iter().collect()
    }
}

impl EquateTable for SimpleEquateTable {
    fn create_equate(&mut self, name: &str, value: i64) -> Result<&mut SimpleEquate, String> {
        if self.equates.contains_key(name) {
            return Err(format!("{name} already exists for an equate."));
        }
        let equate = SimpleEquate::new(name, value)?;
        self.equates.insert(name.to_string(), equate);
        Ok(self.equates.get_mut(name).expect("inserted equate exists"))
    }

    fn remove_equate(&mut self, name: &str) -> bool {
        self.equates.remove(name).is_some()
    }

    fn delete_address_range(&mut self, start: &Address, end: &Address) {
        let range = AddressRange::new(start.clone(), end.clone());
        let mut empty_equates = Vec::new();
        for equate in self.equates.values_mut() {
            for reference in equate.references() {
                if !range.contains(reference.address()) {
                    continue;
                }
                if reference.dynamic_hash_value() != 0 {
                    equate.remove_dynamic_reference(
                        reference.dynamic_hash_value(),
                        reference.address(),
                    );
                } else {
                    equate.remove_reference(reference.address(), reference.op_index());
                }
            }
            if equate.reference_count() == 0 {
                empty_equates.push(equate.name().to_string());
            }
        }
        for name in empty_equates {
            self.equates.remove(&name);
        }
    }

    fn equate(&self, name: &str) -> Option<&SimpleEquate> {
        self.equates.get(name)
    }

    fn equate_at_value(
        &self,
        reference: &Address,
        opnd_position: i16,
        value: i64,
    ) -> Option<&SimpleEquate> {
        self.equates.values().find(|equate| {
            equate.value() == value
                && equate
                    .references_at(reference)
                    .iter()
                    .any(|equate_ref| equate_ref.op_index() == opnd_position)
        })
    }

    fn equates_at_operand(&self, reference: &Address, opnd_position: i16) -> Vec<&SimpleEquate> {
        self.equates
            .values()
            .filter(|equate| {
                equate
                    .references_at(reference)
                    .iter()
                    .any(|equate_ref| equate_ref.op_index() == opnd_position)
            })
            .collect()
    }

    fn equates_at(&self, reference: &Address) -> Vec<&SimpleEquate> {
        self.equates
            .values()
            .filter(|equate| !equate.references_at(reference).is_empty())
            .collect()
    }

    fn equate_addresses(&self) -> Box<dyn AddressIterator> {
        Box::new(AddressIteratorAdapter::from_vec(self.referenced_addresses()))
    }

    fn equates_for_value(&self, value: i64) -> Vec<&SimpleEquate> {
        self.equates
            .values()
            .filter(|equate| equate.value() == value)
            .collect()
    }

    fn equates(&self) -> Vec<&SimpleEquate> {
        self.equates.values().collect()
    }

    fn equate_addresses_from(&self, start: &Address) -> Box<dyn AddressIterator> {
        let addresses = self
            .referenced_addresses()
            .into_iter()
            .filter(|address| address >= start)
            .collect();
        Box::new(AddressIteratorAdapter::from_vec(addresses))
    }

    fn equate_addresses_in(&self, set: &dyn AddressSetView) -> Box<dyn AddressIterator> {
        let addresses = self
            .referenced_addresses()
            .into_iter()
            .filter(|address| set.contains(address))
            .collect();
        Box::new(AddressIteratorAdapter::from_vec(addresses))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        space.address(offset)
    }

    #[test]
    fn creates_and_removes_equates_by_name() {
        let mut table = SimpleEquateTable::new();

        table.create_equate("ONE", 1).unwrap();
        assert_eq!(table.equate("ONE").unwrap().value(), 1);
        assert!(table.create_equate("ONE", 2).is_err());
        assert!(table.create_equate("bad name", 2).is_err());
        assert!(table.remove_equate("ONE"));
        assert!(!table.remove_equate("ONE"));
        assert!(table.equate("ONE").is_none());
    }

    #[test]
    fn finds_equates_by_reference_operand_and_value() {
        let mut table = SimpleEquateTable::new();
        table
            .create_equate("FIVE", 5)
            .unwrap()
            .add_reference(addr(0x1000), 1);
        table
            .create_equate("ALSO_FIVE", 5)
            .unwrap()
            .add_reference(addr(0x1000), 2);
        table
            .create_equate("SIX", 6)
            .unwrap()
            .add_reference(addr(0x1000), 1);

        assert_eq!(
            table.equate_at_value(&addr(0x1000), 1, 5).unwrap().name(),
            "FIVE"
        );
        assert_eq!(table.equates_at_operand(&addr(0x1000), 1).len(), 2);
        assert_eq!(table.equates_at(&addr(0x1000)).len(), 3);
        assert_eq!(table.equates_for_value(5).len(), 2);
        assert!(table.equate_at_value(&addr(0x2000), 1, 5).is_none());
    }

    #[test]
    fn address_iterators_return_unique_sorted_addresses() {
        let mut table = SimpleEquateTable::new();
        let equate = table.create_equate("VALUE", 5).unwrap();
        equate.add_reference(addr(0x1004), 1);
        equate.add_reference(addr(0x1000), 1);
        equate.add_reference(addr(0x1000), 2);

        let mut iterator = table.equate_addresses();
        assert_eq!(iterator.next_address(), Some(addr(0x1000)));
        assert_eq!(iterator.next_address(), Some(addr(0x1004)));
        assert_eq!(iterator.next_address(), None);

        let mut iterator = table.equate_addresses_from(&addr(0x1001));
        assert_eq!(iterator.next_address(), Some(addr(0x1004)));
        assert_eq!(iterator.next_address(), None);
    }

    #[test]
    fn address_set_iterator_filters_referenced_addresses() {
        let mut table = SimpleEquateTable::new();
        let equate = table.create_equate("VALUE", 5).unwrap();
        equate.add_reference(addr(0x1000), 1);
        equate.add_reference(addr(0x2000), 1);

        let set = AddressSet::from_start_end(addr(0x1000), addr(0x1fff));
        let mut iterator = table.equate_addresses_in(&set);

        assert_eq!(iterator.next_address(), Some(addr(0x1000)));
        assert_eq!(iterator.next_address(), None);
    }

    #[test]
    fn delete_address_range_removes_references_and_empty_equates() {
        let mut table = SimpleEquateTable::new();
        let first = table.create_equate("FIRST", 1).unwrap();
        first.add_reference(addr(0x1000), 1);
        first.add_reference(addr(0x2000), 1);
        table
            .create_equate("SECOND", 2)
            .unwrap()
            .add_dynamic_reference(0x44, addr(0x1004));

        table.delete_address_range(&addr(0x1000), &addr(0x1fff));

        assert_eq!(table.equate("FIRST").unwrap().reference_count(), 1);
        assert!(table.equate("SECOND").is_none());
        let mut iterator = table.equate_addresses();
        assert_eq!(iterator.next_address(), Some(addr(0x2000)));
        assert_eq!(iterator.next_address(), None);
    }

    #[test]
    fn all_equates_iterate_by_name_order() {
        let mut table = SimpleEquateTable::new();
        table.create_equate("B", 2).unwrap();
        table.create_equate("A", 1).unwrap();

        let names: Vec<_> = table
            .equates()
            .into_iter()
            .map(|equate| equate.name())
            .collect();
        assert_eq!(names, vec!["A", "B"]);
    }
}
