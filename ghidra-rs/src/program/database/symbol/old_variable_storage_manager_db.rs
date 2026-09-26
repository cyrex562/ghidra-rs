//! Port of `ghidra.program.database.symbol.OldVariableStorageManagerDB`.
//!
//! Read-only variable storage manager for the old record format utilized by the `VariableStorage`
//! table (note: the old table name has no space in it, unlike the current `"Variable Storage"`
//! table). Intended for use during upgrades only.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use crate::framework::db::DBHandle;
use crate::program::database::map::AddressMap;
use crate::program::database::symbol::old_variable_storage_db_adapter_v0v1::{
    OldVariableStorageDBAdapterV0V1, NAMESPACE_ID_COL, STORAGE_ADDR_COL, VARIABLE_STORAGE_TABLE_NAME,
};
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

/// The address space that legacy variable addresses (record keys of the old `VariableStorage`
/// table) were encoded in. Stands in for `AddressSpace.VARIABLE_SPACE`, which has not been ported
/// as a shared singleton; constructed fresh here since [`AddressSpace`] equality is structural
/// (space id + name), so every `Address` built against it compares equal regardless of which
/// `Arc` instance backs it.
pub fn variable_space() -> Arc<AddressSpace> {
    AddressSpace::new("Variable", 32, 1, AddressSpaceType::Variable, 0)
}

/// A single legacy variable-to-storage-address association.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OldVariableStorage {
    variable_addr: Address,
    storage_addr: Address,
}

/// Read-only variable storage manager for the old record format utilized by the `VariableStorage`
/// table. This adapter is intended for use during upgrades only.
///
/// Port of `ghidra.program.database.symbol.OldVariableStorageManagerDB`.
pub struct OldVariableStorageManagerDB {
    addr_map: Arc<dyn AddressMap>,
    adapter: OldVariableStorageDBAdapterV0V1,
    last_namespace_cache_id: i64,
    variable_addr_lookup_cache: HashMap<Address, OldVariableStorage>,
    storage_addr_lookup_cache: HashMap<Address, OldVariableStorage>,
}

impl OldVariableStorageManagerDB {
    /// Construct a read-only variable storage manager for the old record format.
    ///
    /// # Errors
    ///
    /// Returns an error if a database error occurs (e.g. the legacy table is missing or has an
    /// unsupported schema version).
    pub fn new(handle: &DBHandle, addr_map: Arc<dyn AddressMap>) -> io::Result<Self> {
        let adapter = OldVariableStorageDBAdapterV0V1::new(handle)?;
        Ok(OldVariableStorageManagerDB {
            addr_map,
            adapter,
            last_namespace_cache_id: -1,
            variable_addr_lookup_cache: HashMap::new(),
            storage_addr_lookup_cache: HashMap::new(),
        })
    }

    /// Returns true if the given database handle contains the legacy `VariableStorage` table
    /// (i.e. an upgrade is required). Stands in for
    /// `OldVariableStorageManagerDB.isOldVariableStorageManagerUpgradeRequired(DBHandle)`.
    pub fn is_old_variable_storage_manager_upgrade_required(handle: &DBHandle) -> bool {
        handle.get_table(VARIABLE_STORAGE_TABLE_NAME).is_some()
    }

    /// Deletes the legacy `VariableStorage` table.
    pub fn delete_table(&self, handle: &mut DBHandle) {
        handle.delete_table(VARIABLE_STORAGE_TABLE_NAME);
    }

    fn cache_namespace_storage(&mut self, namespace_id: i64) -> io::Result<()> {
        self.variable_addr_lookup_cache.clear();
        self.storage_addr_lookup_cache.clear();
        self.last_namespace_cache_id = namespace_id;
        let records = self.adapter.get_records_for_namespace(namespace_id)?;
        for rec in records {
            let variable_addr = variable_space().address(rec.get_key().get_long_value());
            let storage_addr = self
                .addr_map
                .decode_address(rec.get_long(STORAGE_ADDR_COL).unwrap_or_default());
            let var_store = OldVariableStorage {
                variable_addr: variable_addr.clone(),
                storage_addr,
            };
            self.variable_addr_lookup_cache.insert(variable_addr, var_store.clone());
            self.storage_addr_lookup_cache
                .insert(var_store.storage_addr.clone(), var_store);
        }
        Ok(())
    }

    fn get_variable_storage(&mut self, variable_addr: &Address) -> io::Result<Option<OldVariableStorage>> {
        if variable_addr.space().as_ref() != variable_space().as_ref() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "address is not a variable address",
            ));
        }
        if self.last_namespace_cache_id != -1 {
            if let Some(var_store) = self.variable_addr_lookup_cache.get(variable_addr) {
                return Ok(Some(var_store.clone()));
            }
        }
        let Some(rec) = self.adapter.get_record(variable_addr.offset())? else {
            return Ok(None);
        };
        let namespace_id = rec.get_long(NAMESPACE_ID_COL).unwrap_or_default();
        self.cache_namespace_storage(namespace_id)?;
        Ok(self.variable_addr_lookup_cache.get(variable_addr).cloned())
    }

    /// Returns the storage address for the given legacy variable address, or `None` if not found.
    ///
    /// Stands in for `OldVariableStorageManagerDB.getStorageAddress(Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `variable_addr` is not a variable address, or if a database error
    /// occurs.
    pub fn get_storage_address(&mut self, variable_addr: &Address) -> io::Result<Option<Address>> {
        Ok(self
            .get_variable_storage(variable_addr)?
            .map(|var_store| var_store.storage_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::database::symbol::old_variable_storage_db_adapter_v0v1::{
        self, SYMBOL_COUNT_COL,
    };
    use crate::program::model::address::{AddressSpace as RamAddressSpace, AddressSpaceType as RamAddressSpaceType, KeyRange};

    fn ram_space() -> Arc<RamAddressSpace> {
        RamAddressSpace::new("ram", 32, 1, RamAddressSpaceType::Ram, 1)
    }

    struct IdentityAddressMap;

    impl AddressMap for IdentityAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }
        fn decode_address(&self, value: i64) -> Address {
            Address::new(ram_space(), value)
        }
        fn get_address_factory(
            &self,
        ) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn crate::program::model::address::AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(IdentityAddressMap)
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            Address::new(ram_space(), 0)
        }
    }

    fn setup_handle() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(
                VARIABLE_STORAGE_TABLE_NAME.to_string(),
                old_variable_storage_db_adapter_v0v1::schema(),
            )
            .unwrap();
        let mut table = table.write().unwrap();
        for (addr, namespace_id) in [(0x1000i64, 5i64), (0x2000, 5), (0x3000, 6)] {
            let key = table.get_next_key();
            let mut record = DBRecord::new(old_variable_storage_db_adapter_v0v1::schema(), Field::Long(Some(key)));
            record.set_long(STORAGE_ADDR_COL, addr);
            record.set_long(NAMESPACE_ID_COL, namespace_id);
            record.set_int(SYMBOL_COUNT_COL, 1);
            table.put_record(record).unwrap();
        }
        drop(table);
        handle
    }

    use crate::framework::db::DBRecord;

    #[test]
    fn upgrade_required_reflects_table_presence() {
        let handle = DBHandle::new().unwrap();
        assert!(!OldVariableStorageManagerDB::is_old_variable_storage_manager_upgrade_required(
            &handle
        ));

        let handle = setup_handle();
        assert!(OldVariableStorageManagerDB::is_old_variable_storage_manager_upgrade_required(
            &handle
        ));
    }

    #[test]
    fn looks_up_storage_address_by_variable_address() {
        let handle = setup_handle();
        let addr_map: Arc<dyn AddressMap> = Arc::new(IdentityAddressMap);
        let mut mgr = OldVariableStorageManagerDB::new(&handle, addr_map).unwrap();

        // Keys are assigned in creation order starting at 0.
        let var_addr0 = variable_space().address(0);
        let storage0 = mgr.get_storage_address(&var_addr0).unwrap().unwrap();
        assert_eq!(storage0, Address::new(ram_space(), 0x1000));

        let var_addr2 = variable_space().address(2);
        let storage2 = mgr.get_storage_address(&var_addr2).unwrap().unwrap();
        assert_eq!(storage2, Address::new(ram_space(), 0x3000));
    }

    #[test]
    fn unknown_variable_address_returns_none() {
        let handle = setup_handle();
        let addr_map: Arc<dyn AddressMap> = Arc::new(IdentityAddressMap);
        let mut mgr = OldVariableStorageManagerDB::new(&handle, addr_map).unwrap();

        let missing = variable_space().address(999);
        assert!(mgr.get_storage_address(&missing).unwrap().is_none());
    }

    #[test]
    fn non_variable_address_is_rejected() {
        let handle = setup_handle();
        let addr_map: Arc<dyn AddressMap> = Arc::new(IdentityAddressMap);
        let mut mgr = OldVariableStorageManagerDB::new(&handle, addr_map).unwrap();

        let not_variable = Address::new(ram_space(), 0);
        assert!(mgr.get_storage_address(&not_variable).is_err());
    }
}
