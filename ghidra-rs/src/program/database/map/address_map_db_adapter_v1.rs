//! Port of `ghidra.program.database.map.AddressMapDBAdapterV1`.
//!
//! The current, writable on-disk schema for the address map table. Unlike `AddressMapDBAdapterV0`
//! (read-only, no "Deleted" column), this version tracks deletion explicitly per row, so a
//! deleted/renamed overlay space is a *record update* (`rename_overlay_space`/
//! `delete_overlay_space`), not a factory-resolution fallback.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::map::address_map_db_adapter::{
    AddressMapDBAdapter, AddressMapEntry, CURRENT_VERSION, TABLE_NAME,
};
use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
use crate::util::exception::VersionException;

/// Column index of the base address's space name.
pub const SPACE_NAME_COL: usize = 0;
/// Column index of the base address's segment.
pub const SEGMENT_COL: usize = 1;
/// Column index of the "deleted" flag.
pub const DELETED_COL: usize = 2;

/// 32 bits, matching `AddressMapDB.ADDR_OFFSET_SIZE`. See the identical constant (and its doc
/// comment explaining the duplication) in `address_map_db_adapter_v0`.
const ADDR_OFFSET_SIZE: u32 = 32;

fn v1_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::String, FieldType::Int, FieldType::Boolean],
        vec!["Space Name".to_string(), "Segment".to_string(), "Deleted".to_string()],
        vec![],
    ))
}

/// Current (version 1) implementation for accessing the address map table.
///
/// Port of `ghidra.program.database.map.AddressMapDBAdapterV1`.
pub struct AddressMapDBAdapterV1 {
    table: Arc<RwLock<Table>>,
    factory: Arc<dyn AddressFactory>,
    addresses: Vec<Address>,
}

impl AddressMapDBAdapterV1 {
    /// Gets an adapter for the address map table, creating it if `create` is true, otherwise
    /// opening the existing table (erroring if it is missing or predates version 1).
    ///
    /// Port of `AddressMapDBAdapterV1(DBHandle, AddressFactory, boolean)`.
    pub fn new(
        handle: &mut DBHandle,
        factory: Arc<dyn AddressFactory>,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(TABLE_NAME.to_string(), v1_schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .get_table(TABLE_NAME)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version < 1 {
                return Err(VersionException::with_upgradeable(true));
            }
            if version != CURRENT_VERSION {
                return Err(VersionException::with_message(format!(
                    "Expected version {CURRENT_VERSION} for table {TABLE_NAME} but got {version}"
                )));
            }
            table
        };
        let mut adapter = AddressMapDBAdapterV1 { table, factory, addresses: Vec::new() };
        adapter.read_addresses().map_err(|e| VersionException::with_message(e.to_string()))?;
        Ok(adapter)
    }

    fn read_addresses(&mut self) -> io::Result<()> {
        let table = self.table.read().unwrap();
        let mut addresses: Vec<Option<Address>> = vec![None; table.get_record_count()];
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            let space_name =
                rec.get_field(SPACE_NAME_COL).get_string_value().unwrap_or("").to_string();
            let mut segment = rec.get_field(SEGMENT_COL).get_int_value();
            let deleted = matches!(rec.get_field(DELETED_COL), Field::Boolean(Some(true)));
            let key = rec.get_key().get_long_value();
            let existing_space = self.factory.get_address_space_by_name(&space_name);
            let space = match existing_space {
                Some(space) if !deleted => space,
                _ => {
                    // Matches a latent Java quirk: `spaceName += "_" + segment` reassigns the
                    // local `spaceName` variable when `segment != 0`, but that reassigned value
                    // is never read again (`deletedName` was already computed from the original
                    // name). This port mirrors the observable behavior (the suffix is computed
                    // and then discarded) without literally performing the dead reassignment.
                    let deleted_name = format!("Deleted_{space_name}");
                    let sp =
                        AddressSpace::new(&deleted_name, 64, 1, AddressSpaceType::Deleted, key as i32);
                    segment = 0;
                    sp
                }
            };
            let addr = space.address((segment as i64) << ADDR_OFFSET_SIZE);
            let index = key as usize;
            if index < addresses.len() {
                addresses[index] = Some(addr);
            }
        }
        self.addresses = addresses.into_iter().flatten().collect();
        Ok(())
    }
}

impl AddressMapDBAdapter for AddressMapDBAdapterV1 {
    fn delete_table(&mut self) -> io::Result<()> {
        // See the identical note on `AddressMapDBAdapterV0::delete_table`: this adapter holds
        // only a `Table` handle, not the owning `DBHandle`; callers delete the table via the
        // `DBHandle` directly.
        Ok(())
    }

    fn add_base_address(&mut self, addr: &Address, normalized_offset: i64) -> Vec<Address> {
        let mut table = self.table.write().unwrap();
        let key = self.addresses.len() as i64;
        let schema = table.get_schema();
        let mut rec = DBRecord::new(schema, Field::Long(Some(key)));
        let space = addr.space();
        rec.set_field(SPACE_NAME_COL, Field::String(Some(space.name().to_string())));
        let segment = (normalized_offset >> ADDR_OFFSET_SIZE) as i32;
        rec.set_field(SEGMENT_COL, Field::Int(Some(segment)));
        rec.set_field(DELETED_COL, Field::Boolean(Some(false)));
        if table.put_record(rec).is_err() {
            return self.addresses.clone();
        }
        let mask: i64 = (1i64 << ADDR_OFFSET_SIZE) - 1;
        let new_addr = addr.space().address(normalized_offset & !mask);
        self.addresses.push(new_addr);
        self.addresses.clone()
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
            let deleted = matches!(rec.get_field(DELETED_COL), Field::Boolean(Some(true)));
            list.push(AddressMapEntry::new(
                rec.get_key().get_long_value() as i32,
                space_name,
                rec.get_field(SEGMENT_COL).get_int_value(),
                deleted,
            ));
        }
        Ok(list)
    }

    fn set_entries(&mut self, entries: Vec<AddressMapEntry>) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        if table.get_record_count() != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "table is not empty"));
        }
        let schema = table.get_schema();
        for entry in &entries {
            if entry.index as usize != table.get_record_count() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "Bad map entry"));
            }
            let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(entry.index as i64)));
            rec.set_field(SPACE_NAME_COL, Field::String(Some(entry.name.clone())));
            rec.set_field(SEGMENT_COL, Field::Int(Some(entry.segment)));
            rec.set_field(DELETED_COL, Field::Boolean(Some(entry.deleted)));
            table.put_record(rec)?;
        }
        drop(table);
        self.read_addresses()
    }

    fn clear_all(&mut self) -> io::Result<()> {
        self.table.write().unwrap().clear_all()?;
        self.addresses = Vec::new();
        Ok(())
    }

    fn set_address_factory(&mut self, addr_factory: Arc<dyn AddressFactory>) {
        self.factory = addr_factory;
    }

    fn rename_overlay_space(&mut self, old_name: &str, new_name: &str) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let mut to_update = Vec::new();
        {
            let mut iter = table.get_record_iterator()?;
            while let Some(rec) = iter.next()? {
                let space_name =
                    rec.get_field(SPACE_NAME_COL).get_string_value().unwrap_or("").to_string();
                let deleted = matches!(rec.get_field(DELETED_COL), Field::Boolean(Some(true)));
                if !deleted && space_name == old_name {
                    to_update.push(rec);
                }
            }
        }
        for mut rec in to_update {
            rec.set_field(SPACE_NAME_COL, Field::String(Some(new_name.to_string())));
            table.put_record(rec)?;
        }
        Ok(())
    }

    fn delete_overlay_space(&mut self, name: &str) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let mut to_update = Vec::new();
        {
            let mut iter = table.get_record_iterator()?;
            while let Some(rec) = iter.next()? {
                let space_name =
                    rec.get_field(SPACE_NAME_COL).get_string_value().unwrap_or("").to_string();
                if space_name == name {
                    to_update.push(rec);
                }
            }
        }
        for mut rec in to_update {
            rec.set_field(DELETED_COL, Field::Boolean(Some(true)));
            table.put_record(rec)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::DefaultAddressFactory;

    fn factory_with(space: Arc<AddressSpace>) -> Arc<dyn AddressFactory> {
        Arc::new(DefaultAddressFactory::new(vec![space]))
    }

    #[test]
    fn create_makes_an_empty_table() {
        let mut handle = DBHandle::new().unwrap();
        let factory = factory_with(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0));
        let mut adapter = AddressMapDBAdapterV1::new(&mut handle, factory, true).unwrap();
        assert!(adapter.get_base_addresses(false).unwrap().is_empty());
    }

    #[test]
    fn opening_missing_table_without_create_is_upgradeable() {
        let mut handle = DBHandle::new().unwrap();
        let factory = factory_with(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0));
        let err = match AddressMapDBAdapterV1::new(&mut handle, factory, false) {
            Ok(_) => panic!("expected a VersionException"),
            Err(e) => e,
        };
        assert!(err.is_upgradable());
    }

    #[test]
    fn add_base_address_round_trips_through_get_base_addresses() {
        let mut handle = DBHandle::new().unwrap();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let factory = factory_with(space.clone());
        let mut adapter = AddressMapDBAdapterV1::new(&mut handle, factory, true).unwrap();

        let addr = space.address(0x1000);
        let bases = adapter.add_base_address(&addr, 0x1000);
        assert_eq!(bases.len(), 1);

        let reread = adapter.get_base_addresses(true).unwrap();
        assert_eq!(reread.len(), 1);
    }

    #[test]
    fn set_entries_populates_addresses_and_rejects_non_empty_table() {
        let mut handle = DBHandle::new().unwrap();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let factory = factory_with(space.clone());
        let mut adapter = AddressMapDBAdapterV1::new(&mut handle, factory, true).unwrap();

        adapter
            .set_entries(vec![AddressMapEntry::new(0, "ram", 0, false)])
            .unwrap();
        assert_eq!(adapter.get_base_addresses(false).unwrap().len(), 1);

        // Table is no longer empty -> rejected.
        assert!(adapter
            .set_entries(vec![AddressMapEntry::new(0, "ram", 0, false)])
            .is_err());
    }

    #[test]
    fn rename_and_delete_overlay_space_update_records() {
        let mut handle = DBHandle::new().unwrap();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let factory = factory_with(space.clone());
        let mut adapter = AddressMapDBAdapterV1::new(&mut handle, factory, true).unwrap();
        adapter
            .set_entries(vec![AddressMapEntry::new(0, "overlay1", 0, false)])
            .unwrap();

        adapter.rename_overlay_space("overlay1", "overlay2").unwrap();
        let entries = adapter.get_entries().unwrap();
        assert_eq!(entries[0].name, "overlay2");
        assert!(!entries[0].deleted);

        adapter.delete_overlay_space("overlay2").unwrap();
        let entries = adapter.get_entries().unwrap();
        assert!(entries[0].deleted);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let factory = factory_with(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0));
        let adapter: Box<dyn AddressMapDBAdapter> =
            Box::new(AddressMapDBAdapterV1::new(&mut handle, factory, true).unwrap());
        assert!(adapter.get_entries().unwrap().is_empty());
    }
}
