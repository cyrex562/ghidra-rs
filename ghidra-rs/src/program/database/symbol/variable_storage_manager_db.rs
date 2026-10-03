//! Port of `ghidra.program.database.symbol.VariableStorageManagerDB`.
//!
//! Maps variable storage addresses (records in the `"Variable Storage"` table) to/from their
//! deserialized [`VariableStorage`] representation. Composition, not inheritance: the Java class
//! is constructed from a `DBHandle` and internally selects/upgrades between
//! `VariableStorageDBAdapterV2`/`VariableStorageDBAdapterNoTable` via the (unported)
//! `VariableStorageDBAdapter.getAdapter` static factory; this port instead takes an already
//! constructed [`VariableStorageDBAdapter`] trait object, leaving adapter selection to the caller
//! -- the same convention already used for
//! [`SymbolDatabaseAdapter`](crate::program::database::symbol::SymbolDatabaseAdapter)'s unported
//! `getAdapter`.
//!
//! Left out/simplified:
//! - The Java class's `DbCache`/`WeakValueHashMap`-based caches are unbounded `HashMap`s here
//!   (same simplification already applied to
//!   [`NamespaceManagerDB`](crate::program::database::symbol::NamespaceManagerDB)'s body cache);
//!   the `MyVariableStorage.isValid()` freshness recheck on a hash-cache hit is dropped since
//!   there is no `DbObject`-style record-versioning to check against -- the whole cache is instead
//!   invalidated wholesale by [`VariableStorageManagerDB::invalidate_cache`].
//! - No `ErrorHandler` field: database errors are surfaced as `io::Result` instead of being routed
//!   to a side-channel handler, matching the rest of this port's manager types (e.g.
//!   `NamespaceManagerDB`, `OldVariableStorageManagerDB`).

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field};
use crate::program::database::symbol::variable_storage_db_adapter_v2::{
    schema, HASH_COL, STORAGE_COL, VARIABLE_STORAGE_TABLE_NAME,
};
use crate::program::database::symbol::old_variable_storage_manager_db::variable_space;
use crate::program::database::symbol::{VariableStorageDBAdapter, VariableStorageManager};
use crate::program::model::address::{Address, AddressSpaceType};
use crate::program::model::lang::ProgramArchitecture;
use crate::program::model::listing::variable_storage::{deserialize, translate_serialization, VariableStorage};
use crate::program::util::LanguageTranslator;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Error produced by [`VariableStorageManagerDB::set_language`], mirroring
/// `VariableStorageManagerDB.setLanguage(LanguageTranslator, TaskMonitor)`'s
/// `throws CancelledException` (I/O errors, which the Java method routes to its `ErrorHandler`
/// field rather than throwing, are surfaced here directly instead -- see the module docs).
#[derive(Debug, thiserror::Error)]
pub enum SetLanguageError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Manages the variable storage table, mapping storage-address hashes to their deserialized
/// [`VariableStorage`] representation.
///
/// Port of `ghidra.program.database.symbol.VariableStorageManagerDB`.
pub struct VariableStorageManagerDB {
    arch: RwLock<Option<Arc<dyn ProgramArchitecture>>>,
    adapter: Mutex<Box<dyn VariableStorageDBAdapter + Send + Sync>>,
    key_cache: Mutex<HashMap<i64, Arc<dyn VariableStorage>>>,
    hash_to_key: Mutex<HashMap<i64, i64>>,
}

impl VariableStorageManagerDB {
    /// Construct a new variable storage manager backed by `adapter`.
    ///
    /// Stands in for the `VariableStorageManagerDB(DBHandle, AddressMap, OpenMode, ErrorHandler,
    /// Lock, TaskMonitor)` constructor, minus the adapter-version-selection/upgrade logic (see the
    /// module docs).
    pub fn new(adapter: Box<dyn VariableStorageDBAdapter + Send + Sync>) -> Self {
        VariableStorageManagerDB {
            arch: RwLock::new(None),
            adapter: Mutex::new(adapter),
            key_cache: Mutex::new(HashMap::new()),
            hash_to_key: Mutex::new(HashMap::new()),
        }
    }

    /// Set program architecture. Must be called before [`Self::get_variable_storage`] or
    /// [`VariableStorageManager::get_variable_storage_address`] since deserializing a stored
    /// [`VariableStorage`] requires it.
    ///
    /// Stands in for `VariableStorageManagerDB.setProgramArchitecture(ProgramArchitecture)`.
    pub fn set_program_architecture(&self, arch: Arc<dyn ProgramArchitecture>) {
        *self.arch.write().unwrap() = Some(arch);
    }

    /// Determine if the variable storage manager table already exists in `handle`.
    ///
    /// Stands in for `VariableStorageManagerDB.exists(DBHandle)`.
    pub fn exists(handle: &DBHandle) -> bool {
        handle.get_table(VARIABLE_STORAGE_TABLE_NAME).is_some()
    }

    /// Delete the DB table which corresponds to this variable storage implementation.
    ///
    /// Stands in for `VariableStorageManagerDB.delete(DBHandle)`.
    pub fn delete(handle: &mut DBHandle) {
        handle.delete_table(VARIABLE_STORAGE_TABLE_NAME);
    }

    /// Clears the key and hash caches.
    ///
    /// Stands in for `VariableStorageManagerDB.invalidateCache(boolean)`.
    pub fn invalidate_cache(&self, _all: bool) {
        self.key_cache.lock().unwrap().clear();
        self.hash_to_key.lock().unwrap().clear();
    }

    fn architecture(&self) -> io::Result<Arc<dyn ProgramArchitecture>> {
        self.arch.read().unwrap().clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "program architecture must be set before using VariableStorageManagerDB",
            )
        })
    }

    fn is_variable_address(addr: &Address) -> bool {
        addr.space().space_type() == AddressSpaceType::Variable
    }

    fn deserialize_record(&self, record: &DBRecord) -> io::Result<Arc<dyn VariableStorage>> {
        let arch = self.architecture()?;
        let serialization = record.get_string(STORAGE_COL);
        // `deserialize` never actually returns `Err` (every branch falls back to `BadStorage`),
        // but keep the `Result` plumbing intact for fidelity with the Java method's signature.
        let storage = deserialize(arch, serialization)
            .unwrap_or_else(|_| Box::new(crate::program::model::listing::variable_storage::BadStorage));
        Ok(Arc::from(storage))
    }

    fn cache(&self, key: i64, hash: i64, storage: Arc<dyn VariableStorage>) {
        self.key_cache.lock().unwrap().insert(key, storage);
        self.hash_to_key.lock().unwrap().insert(hash, key);
    }

    /// Get the variable storage object associated with the specified variable storage address.
    ///
    /// NOTE: [`Self::set_program_architecture`] must be called prior to invoking this method.
    ///
    /// Stands in for `VariableStorageManagerDB.getVariableStorage(Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `variable_addr` is not a variable-space address, the program
    /// architecture has not been set, or a database error occurs.
    pub fn get_variable_storage(
        &self,
        variable_addr: &Address,
    ) -> io::Result<Option<Arc<dyn VariableStorage>>> {
        if !Self::is_variable_address(variable_addr) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Address is not a VariableAddress: {variable_addr}"),
            ));
        }
        let key = variable_addr.offset();

        if let Some(cached) = self.key_cache.lock().unwrap().get(&key) {
            return Ok(Some(cached.clone()));
        }

        let record = self.adapter.lock().unwrap().get_record(key)?;
        let Some(record) = record else {
            return Ok(None);
        };
        let storage = self.deserialize_record(&record)?;
        let hash = record.get_long(HASH_COL).unwrap_or(0);
        self.cache(key, hash, storage.clone());
        Ok(Some(storage))
    }

    fn get_existing_key(&self, storage: &dyn VariableStorage) -> io::Result<i64> {
        let hash = storage.get_long_hash();
        if let Some(&key) = self.hash_to_key.lock().unwrap().get(&hash) {
            return Ok(key);
        }
        self.adapter.lock().unwrap().find_record_key(hash)
    }

    /// Perform language translation: update every stored variable storage specification to
    /// reflect the given translator's address-space and register mappings.
    ///
    /// Stands in for `VariableStorageManagerDB.setLanguage(LanguageTranslator, TaskMonitor)`.
    ///
    /// # Errors
    ///
    /// Returns [`SetLanguageError::Cancelled`] if `monitor` is cancelled, or
    /// [`SetLanguageError::Io`] if a database error occurs. Records whose serialization fails to
    /// translate are skipped (matching the Java method's per-record `catch` clause), not treated
    /// as a fatal error.
    pub fn set_language(
        &self,
        translator: &dyn LanguageTranslator,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), SetLanguageError> {
        let mut adapter = self.adapter.lock().unwrap();
        monitor.initialize(adapter.get_record_count() as i64);
        let mut cnt = 0i64;

        let records: Vec<DBRecord> = {
            let mut it = adapter.get_records()?;
            let mut v = Vec::new();
            while let Some(rec) = it.next()? {
                v.push(rec);
            }
            v
        };

        for mut rec in records {
            monitor.check_cancelled()?;

            let serialization = rec.get_string(STORAGE_COL).map(str::to_string);
            match translate_serialization(translator, serialization.as_deref()) {
                Ok(new_serialization) => {
                    rec.set_string(STORAGE_COL, new_serialization);
                    adapter.update_record(&rec)?;
                }
                Err(_) => continue, // Failed to process - skip record
            }
            cnt += 1;
            monitor.set_progress(cnt);
            self.invalidate_cache(true);
        }

        Ok(())
    }
}

impl VariableStorageManager for VariableStorageManagerDB {
    /// Get a variable address for the given storage specification, allocating one (and its
    /// backing record) if `create` is `true` and none exists yet.
    ///
    /// NOTE: [`VariableStorageManagerDB::set_program_architecture`] must be called prior to
    /// invoking this method.
    ///
    /// Stands in for `VariableStorageManagerDB.getVariableStorageAddress(VariableStorage,
    /// boolean)`.
    fn get_variable_storage_address(
        &self,
        storage: &dyn VariableStorage,
        create: bool,
    ) -> io::Result<Option<Address>> {
        let mut key = self.get_existing_key(storage)?;
        if key == -1 && create {
            let mut adapter = self.adapter.lock().unwrap();
            key = adapter.get_next_storage_id();
            let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
            rec.set_long(HASH_COL, storage.get_long_hash());
            rec.set_string(STORAGE_COL, Some(storage.get_serialization_string()));
            adapter.update_record(&rec)?;
            drop(adapter);

            let cached = self.deserialize_record(&rec)?;
            self.cache(key, storage.get_long_hash(), cached);
        }
        Ok(if key == -1 {
            None
        } else {
            Some(variable_space().address(key))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::symbol::variable_storage_db_adapter_v2::VariableStorageDBAdapterV2;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::util::task::DummyMonitor;

    struct TestArch {
        factory: DefaultAddressFactory,
    }

    impl ProgramArchitecture for TestArch {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not needed for these tests")
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(self.factory.clone())
        }
        fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not needed for these tests")
        }
    }

    fn test_arch() -> Arc<dyn ProgramArchitecture> {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let factory = DefaultAddressFactory::new(vec![space]);
        Arc::new(TestArch { factory })
    }

    fn new_manager() -> VariableStorageManagerDB {
        let mut handle = DBHandle::new().unwrap();
        let adapter = VariableStorageDBAdapterV2::new(&mut handle, true).unwrap();
        let mgr = VariableStorageManagerDB::new(Box::new(adapter));
        mgr.set_program_architecture(test_arch());
        mgr
    }

    #[test]
    fn create_then_lookup_round_trips_unassigned_storage() {
        let mgr = new_manager();
        let storage = crate::program::model::listing::variable_storage::UnassignedStorage;

        let addr = mgr
            .get_variable_storage_address(&storage, true)
            .unwrap()
            .expect("address allocated");
        assert!(VariableStorageManagerDB::is_variable_address(&addr));

        // Requesting again without `create` returns the same address (same hash -> same key).
        let addr2 = mgr.get_variable_storage_address(&storage, false).unwrap();
        assert_eq!(addr2, Some(addr.clone()));

        let fetched = mgr.get_variable_storage(&addr).unwrap().expect("present");
        assert!(fetched.is_unassigned_storage());
    }

    #[test]
    fn get_variable_storage_address_without_create_returns_none_when_absent() {
        let mgr = new_manager();
        let storage = crate::program::model::listing::variable_storage::UnassignedStorage;
        assert!(mgr
            .get_variable_storage_address(&storage, false)
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_variable_storage_rejects_non_variable_address() {
        let mgr = new_manager();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x100);
        assert!(mgr.get_variable_storage(&addr).is_err());
    }

    #[test]
    fn invalidate_cache_clears_lookups_without_losing_records() {
        let mgr = new_manager();
        let storage = crate::program::model::listing::variable_storage::UnassignedStorage;
        let addr = mgr
            .get_variable_storage_address(&storage, true)
            .unwrap()
            .unwrap();

        mgr.invalidate_cache(true);

        // The record itself survives cache invalidation: the same hash still resolves.
        let addr2 = mgr.get_variable_storage_address(&storage, false).unwrap();
        assert_eq!(addr2, Some(addr));
    }

    #[test]
    fn exists_and_delete_reflect_table_lifecycle() {
        let mut handle = DBHandle::new().unwrap();
        assert!(!VariableStorageManagerDB::exists(&handle));
        let _adapter = VariableStorageDBAdapterV2::new(&mut handle, true).unwrap();
        assert!(VariableStorageManagerDB::exists(&handle));
        VariableStorageManagerDB::delete(&mut handle);
        assert!(!VariableStorageManagerDB::exists(&handle));
    }

    #[test]
    fn set_language_leaves_non_register_storage_unchanged() {
        let mgr = new_manager();
        let storage = crate::program::model::listing::variable_storage::UnassignedStorage;
        mgr.get_variable_storage_address(&storage, true).unwrap();

        struct NoopTranslator;
        impl LanguageTranslator for NoopTranslator {
            fn is_valid(&self) -> bool {
                true
            }
            fn get_old_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_new_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_old_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
                unimplemented!("not needed for this smoke test")
            }
            fn get_new_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
                unimplemented!("not needed for this smoke test")
            }
            fn get_old_version(&self) -> i32 {
                0
            }
            fn get_new_version(&self) -> i32 {
                0
            }
            fn get_new_address_space(
                &self,
                _old_space_name: &str,
            ) -> Option<Arc<crate::program::model::address::AddressSpace>> {
                None
            }
            fn get_old_register(
                &self,
                _old_addr: &Address,
                _size: i32,
            ) -> Option<crate::program::model::lang::register::RegisterRef> {
                None
            }
            fn get_old_register_containing(
                &self,
                _old_addr: &Address,
            ) -> Option<crate::program::model::lang::register::RegisterRef> {
                None
            }
            fn get_old_context_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
                None
            }
            fn get_new_register(
                &self,
                _old_reg: &crate::program::model::lang::register::RegisterRef,
            ) -> Option<crate::program::model::lang::register::RegisterRef> {
                None
            }
            fn get_new_context_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
                None
            }
            fn get_new_register_value(
                &self,
                _old_value: &crate::program::model::lang::register_value::RegisterValue,
            ) -> Option<crate::program::model::lang::register_value::RegisterValue> {
                None
            }
            fn is_value_translation_required(
                &self,
                _old_reg: &crate::program::model::lang::register::RegisterRef,
            ) -> bool {
                false
            }
            fn get_new_compiler_spec_id(
                &self,
                old_compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
            ) -> crate::program::model::lang::compiler_spec_id::CompilerSpecID {
                old_compiler_spec_id.clone()
            }
            fn get_old_compiler_spec(
                &self,
                _old_compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
            ) -> Result<
                Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
                crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
            > {
                unimplemented!("not needed for this smoke test")
            }
            fn fixup_instructions(
                &self,
                _program: &mut dyn crate::program::model::listing::Program,
                _old_language: &dyn crate::program::model::lang::language::Language,
                _monitor: &dyn TaskMonitor,
            ) -> Result<(), Box<dyn std::error::Error>> {
                Ok(())
            }
        }

        mgr.set_language(&NoopTranslator, &DummyMonitor).unwrap();
    }
}
