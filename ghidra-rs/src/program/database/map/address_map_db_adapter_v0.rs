//! Port of `ghidra.program.database.map.AddressMapDBAdapterV0`.
//!
//! Read-only version 0 adapter: the first real on-disk schema for the address map table (see the
//! sibling `AddressMapDBAdapterV1`, which is the current, writable schema). Every mutating
//! `AddressMapDBAdapter` method (`add_base_address`, `set_entries`, `clear_all`,
//! `rename_overlay_space`, `delete_overlay_space`) is unsupported here, matching Java's
//! `UnsupportedOperationException`s.
//!
//! Space names that no longer resolve against the current `AddressFactory` (the space was
//! deleted) get a synthetic replacement space of type `Unknown`, numbered by a locally
//! incrementing "deleted ID" counter -- matching Java's `"Deleted_" + spaceName` /
//! `AddressSpace.TYPE_UNKNOWN` handling. `AddressMapDBAdapterV0` has no "Deleted" column (that
//! was added in V1), so unlike V1 there is no way to distinguish "explicitly marked deleted"
//! from "no longer present in the factory" -- both are treated identically, matching Java's
//! `getEntries()` (`deleted = factory.getAddressSpace(spaceName) == null`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::map::address_map_db_adapter::{
    AddressMapDBAdapter, AddressMapEntry, TABLE_NAME,
};
use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
use crate::util::exception::VersionException;

const VERSION: i32 = 0;

/// Column index of the base address's space name.
pub const SPACE_NAME_COL: usize = 0;
/// Column index of the base address's segment.
pub const SEGMENT_COL: usize = 1;

/// 32 bits, matching `AddressMapDB.ADDR_OFFSET_SIZE`. That class has not been fully ported yet
/// (see `address_map_db.rs`'s module docs), so this is redefined locally; it is a stable
/// architectural constant in Java (the low 32 bits of an address-map key are the offset within a
/// base, the rest select the base), not something specific to `AddressMapDB`'s own internals.
const ADDR_OFFSET_SIZE: u32 = 32;

fn v0_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::String, FieldType::Int, FieldType::Short],
        vec!["Space Name".to_string(), "Segment".to_string(), "Not Used".to_string()],
        vec![],
    ))
}

/// Version 0 (read-only) implementation for accessing the address map table.
///
/// Port of `ghidra.program.database.map.AddressMapDBAdapterV0`.
pub struct AddressMapDBAdapterV0 {
    table: Arc<RwLock<Table>>,
    factory: Arc<dyn AddressFactory>,
    addresses: Vec<Address>,
}

impl AddressMapDBAdapterV0 {
    /// Gets a version 0 adapter for the address map table.
    ///
    /// Port of `AddressMapDBAdapterV0(DBHandle, AddressFactory)`.
    pub fn new(handle: &DBHandle, factory: Arc<dyn AddressFactory>) -> Result<Self, VersionException> {
        let table = handle
            .get_table(TABLE_NAME)
            .ok_or_else(|| VersionException::with_upgradeable(true))?;
        {
            let version = table.read().unwrap().get_schema().get_version();
            if version != VERSION {
                return Err(VersionException::with_message(format!(
                    "Expected version 0 for table {TABLE_NAME} but got {version}"
                )));
            }
        }
        let mut adapter = AddressMapDBAdapterV0 { table, factory, addresses: Vec::new() };
        adapter.read_addresses().map_err(|e| VersionException::with_message(e.to_string()))?;
        Ok(adapter)
    }

    fn read_addresses(&mut self) -> io::Result<()> {
        let table = self.table.read().unwrap();
        let mut addresses: Vec<Option<Address>> = vec![None; table.get_record_count()];
        let mut iter = table.get_record_iterator()?;
        let mut deleted_id = 1;
        while let Some(rec) = iter.next()? {
            let space_name = rec.get_field(SPACE_NAME_COL).get_string_value().unwrap_or("").to_string();
            let mut segment = rec.get_field(SEGMENT_COL).get_int_value();
            let space = match self.factory.get_address_space_by_name(&space_name) {
                Some(space) => space,
                None => {
                    let sp = AddressSpace::new(
                        &format!("Deleted_{space_name}"),
                        32,
                        1,
                        AddressSpaceType::Unknown,
                        deleted_id,
                    );
                    deleted_id += 1;
                    sp
                }
            };
            if space.size() <= 32 {
                segment = 0;
            }
            let addr = space.address((segment as i64) << ADDR_OFFSET_SIZE);
            let index = rec.get_key().get_long_value() as usize;
            if index < addresses.len() {
                addresses[index] = Some(addr);
            }
        }
        self.addresses = addresses.into_iter().flatten().collect();
        Ok(())
    }
}

impl AddressMapDBAdapter for AddressMapDBAdapterV0 {
    fn delete_table(&mut self) -> io::Result<()> {
        // Deletion is performed by the owning `DBHandle`, mirroring Java's
        // `handle.deleteTable(TABLE_NAME)`; this adapter only holds a `Table` handle, not the
        // owning `DBHandle`, so callers delete the table themselves and drop this adapter. See
        // `AddressMapDBAdapterV1::delete_table` for the same note.
        Ok(())
    }

    fn add_base_address(&mut self, _addr: &Address, _normalized_offset: i64) -> Vec<Address> {
        panic!("Not allowed to update prior version #{VERSION} of {TABLE_NAME} table.");
    }

    fn get_base_addresses(&mut self, force_read: bool) -> io::Result<Vec<Address>> {
        if force_read || self.table.read().unwrap().get_record_count() != self.addresses.len() {
            self.read_addresses()?;
        }
        Ok(self.addresses.clone())
    }

    fn get_entries(&self) -> io::Result<Vec<AddressMapEntry>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut list = Vec::new();
        while let Some(rec) = iter.next()? {
            let space_name = rec.get_field(SPACE_NAME_COL).get_string_value().unwrap_or("").to_string();
            let deleted = self.factory.get_address_space_by_name(&space_name).is_none();
            list.push(AddressMapEntry::new(
                rec.get_key().get_long_value() as i32,
                space_name,
                rec.get_field(SEGMENT_COL).get_int_value(),
                deleted,
            ));
        }
        Ok(list)
    }

    fn set_entries(&mut self, _entries: Vec<AddressMapEntry>) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "AddressMapDBAdapterV0 is read-only"))
    }

    fn clear_all(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "AddressMapDBAdapterV0 is read-only"))
    }

    fn set_address_factory(&mut self, addr_factory: Arc<dyn AddressFactory>) {
        self.factory = addr_factory;
    }

    fn rename_overlay_space(&mut self, _old_name: &str, _new_name: &str) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "AddressMapDBAdapterV0 is read-only"))
    }

    fn delete_overlay_space(&mut self, _name: &str) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "AddressMapDBAdapterV0 is read-only"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::DefaultAddressFactory;

    fn make_handle_with_table(entries: &[(&str, i32)]) -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle.create_table(TABLE_NAME.to_string(), v0_schema()).unwrap();
        let mut t = table.write().unwrap();
        for (name, segment) in entries {
            let key = t.get_next_key();
            let schema = t.get_schema();
            let mut rec = DBRecord::new(schema, Field::Long(Some(key)));
            rec.set_field(SPACE_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(SEGMENT_COL, Field::Int(Some(*segment)));
            rec.set_field(2, Field::Short(Some(0)));
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    fn factory_with(space: Arc<AddressSpace>) -> Arc<dyn AddressFactory> {
        Arc::new(DefaultAddressFactory::new(vec![space]))
    }

    #[test]
    fn missing_table_is_upgradeable_version_exception() {
        let handle = DBHandle::new().unwrap();
        let factory = factory_with(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0));
        let err = match AddressMapDBAdapterV0::new(&handle, factory) {
            Ok(_) => panic!("expected a VersionException"),
            Err(e) => e,
        };
        assert!(err.is_upgradable());
    }

    #[test]
    fn reads_base_addresses_for_known_space() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let handle = make_handle_with_table(&[("ram", 0)]);
        let factory = factory_with(space.clone());
        let mut adapter = AddressMapDBAdapterV0::new(&handle, factory).unwrap();

        let bases = adapter.get_base_addresses(false).unwrap();
        assert_eq!(bases.len(), 1);
        assert_eq!(bases[0].space(), &space);
    }

    #[test]
    fn deleted_space_gets_synthetic_unknown_space() {
        let handle = make_handle_with_table(&[("gone", 0)]);
        let factory = factory_with(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0));
        let mut adapter = AddressMapDBAdapterV0::new(&handle, factory).unwrap();

        let bases = adapter.get_base_addresses(false).unwrap();
        assert_eq!(bases.len(), 1);
        assert_eq!(bases[0].space().space_type(), AddressSpaceType::Unknown);
        assert!(bases[0].space().name().starts_with("Deleted_gone"));
    }

    #[test]
    fn get_entries_reports_deleted_flag() {
        let handle = make_handle_with_table(&[("ram", 0), ("gone", 0)]);
        let factory = factory_with(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0));
        let adapter = AddressMapDBAdapterV0::new(&handle, factory).unwrap();

        let entries = adapter.get_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].deleted);
        assert!(entries[1].deleted);
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let handle = make_handle_with_table(&[("ram", 0)]);
        let factory = factory_with(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0));
        let mut adapter = AddressMapDBAdapterV0::new(&handle, factory).unwrap();

        assert!(adapter.set_entries(Vec::new()).is_err());
        assert!(adapter.clear_all().is_err());
        assert!(adapter.rename_overlay_space("ram", "other").is_err());
        assert!(adapter.delete_overlay_space("ram").is_err());
    }

    #[test]
    #[should_panic]
    fn add_base_address_panics() {
        let handle = make_handle_with_table(&[("ram", 0)]);
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let factory = factory_with(space.clone());
        let mut adapter = AddressMapDBAdapterV0::new(&handle, factory).unwrap();
        adapter.add_base_address(&space.address(0), 0);
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_table(&[("ram", 0)]);
        let factory = factory_with(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0));
        let adapter: Box<dyn AddressMapDBAdapter> =
            Box::new(AddressMapDBAdapterV0::new(&handle, factory).unwrap());
        assert_eq!(adapter.get_entries().unwrap().len(), 1);
    }
}
