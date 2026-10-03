//! Port of `ghidra.program.database.map.AddressMapDBAdapter`.
//!
//! The Java type is an abstract class whose static factory methods (`getAdapter`,
//! `findReadOnlyAdapter`, `upgrade`) select and migrate between concrete version-specific
//! implementations (`AddressMapDBAdapterV0`/`V1`/`AddressMapDBAdapterNoTable`). Those concrete
//! adapters have not been ported yet, so this port only models the abstract instance API each
//! version implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters.

use std::io;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressFactory};

/// Name of the database table used to store the address map.
pub const TABLE_NAME: &str = "ADDRESS MAP";

/// Current on-disk schema version for the address map table.
pub const CURRENT_VERSION: i32 = 1;

/// A single raw address map entry as persisted by an [`AddressMapDBAdapter`] (one row of the base
/// address table).
///
/// Port of `AddressMapDBAdapter.AddressMapEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressMapEntry {
    pub index: i32,
    pub name: String,
    pub segment: i32,
    pub deleted: bool,
}

impl AddressMapEntry {
    /// Constructs a new `AddressMapEntry`.
    pub fn new(index: i32, name: impl Into<String>, segment: i32, deleted: bool) -> Self {
        AddressMapEntry {
            index,
            name: name.into(),
            segment,
            deleted,
        }
    }
}

/// Database adapter for the address map.
///
/// Port of `ghidra.program.database.map.AddressMapDBAdapter`.
pub trait AddressMapDBAdapter {
    /// Deletes the table - used when upgrading.
    fn delete_table(&mut self) -> io::Result<()>;

    /// Adds a new base address to the map, given the new base address and its normalized offset
    /// (image base subtracted). Returns the array of image bases.
    fn add_base_address(&mut self, addr: &Address, normalized_offset: i64) -> Vec<Address>;

    /// Returns an array of image bases, forcing a reread from the database if `force_read` is
    /// `true`.
    fn get_base_addresses(&mut self, force_read: bool) -> io::Result<Vec<Address>>;

    /// Returns raw address map entries.
    fn get_entries(&self) -> io::Result<Vec<AddressMapEntry>>;

    /// Initialize map with the specified list of map entries (upgrade use only). Entries must be
    /// sorted by index (a missing index will cause an error).
    fn set_entries(&mut self, entries: Vec<AddressMapEntry>) -> io::Result<()>;

    /// Clears all entries in the database table.
    fn clear_all(&mut self) -> io::Result<()>;

    /// Sets the address factory to use.
    fn set_address_factory(&mut self, addr_factory: Arc<dyn AddressFactory>);

    /// Renames an overlay address space entry.
    fn rename_overlay_space(&mut self, old_name: &str, new_name: &str) -> io::Result<()>;

    /// Deletes an overlay address space entry.
    fn delete_overlay_space(&mut self, name: &str) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::cell::RefCell;

    struct MockAddressMapDBAdapter {
        entries: RefCell<Vec<AddressMapEntry>>,
        base_addresses: RefCell<Vec<Address>>,
        deleted: bool,
    }

    impl AddressMapDBAdapter for MockAddressMapDBAdapter {
        fn delete_table(&mut self) -> io::Result<()> {
            self.deleted = true;
            self.entries.borrow_mut().clear();
            Ok(())
        }

        fn add_base_address(&mut self, addr: &Address, _normalized_offset: i64) -> Vec<Address> {
            self.base_addresses.borrow_mut().push(addr.clone());
            self.base_addresses.borrow().clone()
        }

        fn get_base_addresses(&mut self, _force_read: bool) -> io::Result<Vec<Address>> {
            Ok(self.base_addresses.borrow().clone())
        }

        fn get_entries(&self) -> io::Result<Vec<AddressMapEntry>> {
            Ok(self.entries.borrow().clone())
        }

        fn set_entries(&mut self, entries: Vec<AddressMapEntry>) -> io::Result<()> {
            *self.entries.borrow_mut() = entries;
            Ok(())
        }

        fn clear_all(&mut self) -> io::Result<()> {
            self.entries.borrow_mut().clear();
            self.base_addresses.borrow_mut().clear();
            Ok(())
        }

        fn set_address_factory(&mut self, _addr_factory: Arc<dyn AddressFactory>) {}

        fn rename_overlay_space(&mut self, old_name: &str, new_name: &str) -> io::Result<()> {
            for entry in self.entries.borrow_mut().iter_mut() {
                if entry.name == old_name {
                    entry.name = new_name.to_string();
                }
            }
            Ok(())
        }

        fn delete_overlay_space(&mut self, name: &str) -> io::Result<()> {
            self.entries.borrow_mut().retain(|e| e.name != name);
            Ok(())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_usable() {
        let space = AddressSpace::new("overlay", 32, 1, AddressSpaceType::Ram, 1);
        let base = space.address(0);

        let mut adapter: Box<dyn AddressMapDBAdapter> = Box::new(MockAddressMapDBAdapter {
            entries: RefCell::new(Vec::new()),
            base_addresses: RefCell::new(Vec::new()),
            deleted: false,
        });

        adapter
            .set_entries(vec![
                AddressMapEntry::new(0, "overlay1", 0, false),
                AddressMapEntry::new(1, "overlay2", 1, false),
            ])
            .unwrap();
        assert_eq!(adapter.get_entries().unwrap().len(), 2);

        let bases = adapter.add_base_address(&base, 0);
        assert_eq!(bases, vec![base.clone()]);
        assert_eq!(adapter.get_base_addresses(false).unwrap(), vec![base]);

        adapter.rename_overlay_space("overlay1", "renamed").unwrap();
        let entries = adapter.get_entries().unwrap();
        assert!(entries.iter().any(|e| e.name == "renamed"));
        assert!(!entries.iter().any(|e| e.name == "overlay1"));

        adapter.delete_overlay_space("renamed").unwrap();
        assert_eq!(adapter.get_entries().unwrap().len(), 1);

        adapter.clear_all().unwrap();
        assert!(adapter.get_entries().unwrap().is_empty());

        adapter.delete_table().unwrap();
    }
}
