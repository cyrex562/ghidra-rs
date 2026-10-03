//! Port of `ghidra.program.database.bookmark.BookmarkDBAdapterV0`.
//!
//! `V0` predates dedicated bookmark tables entirely: bookmarks were stored as user properties
//! (see [`OldBookmarkManager`]). This adapter never reads a real on-disk bookmark table itself;
//! instead, once [`BookmarkDbAdapterV0::set_old_bookmark_manager`] is called (mirroring Java's
//! "must be set prior to invoking any other method" contract for `setOldBookmarkManager`), it
//! bulk-converts every property-based bookmark into a fresh, in-memory
//! [`BookmarkDbAdapterV3`]-backed temporary database (`conversionAdapter` in Java), and every
//! other trait method simply delegates to that temporary adapter. This is the same
//! "convert-once-into-the-current-schema-for-uniform-querying" trick
//! [`BookmarkDbAdapterV3::new`] itself documents Java performing for its own upgrade path, just
//! done eagerly here since `V0` has no real schema of its own to speak of.
//!
//! **Not overridden, matching Java exactly:** `add_type`/`delete_type`/`reload_tables` (Java's
//! `BookmarkDBAdapterV0` does not override these either, so they fall through to the abstract base
//! class's `UnsupportedOperationException` stubs -- mirrored here by simply not overriding
//! [`BookmarkDbAdapter`]'s own defaults; `V0` is a read-only snapshot of legacy data, never a live
//! target for new types).
//!
//! **`has_table`, deliberately *not* faithfully mirrored.** Java's `BookmarkDBAdapterV0` doesn't
//! override `hasTable` either, so it too falls through to the abstract base's
//! `UnsupportedOperationException`. But unlike every other faithfully-mirrored quirk in this
//! bookmark family (see `BookmarkDbAdapterV3`'s and `BookmarkDbAdapterV1`'s own module docs), this
//! one is not preserved: `BookmarkDBManager.setProgram`'s `bookmarkAdapter.hasTable(typeId)` call
//! for the typeRecords loop would unconditionally crash the moment a program is opened read-only
//! against a genuinely ancient (pre-tables) database -- the *only* scenario this class exists to
//! serve in the first place. That is dead code in the original (apparently never exercised in
//! practice, or every real-world database had already been upgraded past `V0` by the time this
//! path could matter), not an observable behavior worth reproducing, so
//! [`BookmarkDbAdapterV0::has_table`] instead delegates to the real, populated `conversion`
//! adapter -- making the legacy read path this class exists for actually work, which is strictly
//! more useful than faithfully crashing.
//!
//! **`getRecordsByTypeStartingAtAddress`** is unconditionally unsupported, matching Java's own
//! `throw new UnsupportedOperationException(); // they tell me that this class is too old to care`.

use std::io;
use std::sync::Arc;

use crate::framework::db::{DBHandle, DBRecord};
use crate::program::database::bookmark::bookmark_db_adapter::BookmarkDbAdapter;
use crate::program::database::bookmark::bookmark_db_adapter_v3::BookmarkDbAdapterV3;
use crate::program::database::bookmark::bookmark_type_db_adapter::TYPE_NAME_COL;
use crate::program::database::bookmark::old_bookmark_manager::OldBookmarkManager;
use crate::program::database::map::AddressMap;
use crate::program::model::address::AddressSet;

fn not_set_up() -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        "BookmarkDBAdapterV0: set_old_bookmark_manager must be called before any other method",
    )
}

fn unsupported_too_old() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "they tell me that this class is too old to care",
    )
}

/// Read-only adapter standing in for the pre-tables, property-based bookmark storage. See the
/// module docs.
///
/// Port of `ghidra.program.database.bookmark.BookmarkDBAdapterV0`.
pub struct BookmarkDbAdapterV0 {
    conversion: Option<BookmarkDbAdapterV3>,
    /// Kept alive only because `conversion`'s tables live inside it; never read directly. Port of
    /// the private `BookmarkDBAdapterV0.tmpHandle`.
    _tmp_handle: Option<DBHandle>,
}

impl BookmarkDbAdapterV0 {
    /// Constructs an adapter with no backing data yet. Port of `BookmarkDBAdapterV0(DBHandle)`
    /// (Java's constructor parameter is unused -- see the module docs for why nothing is stored
    /// until [`Self::set_old_bookmark_manager`] runs).
    pub fn new() -> Self {
        BookmarkDbAdapterV0 {
            conversion: None,
            _tmp_handle: None,
        }
    }

    /// Bulk-converts every property-based bookmark in `old_mgr` into a fresh, in-memory
    /// `BookmarkDbAdapterV3`-backed temporary database, using `addr_map` (the *current* address
    /// map, matching Java's parameter exactly -- no `get_old_address_map` translation is needed
    /// here since `OldBookmark` stores real `Address` objects, not a legacy numeric encoding).
    ///
    /// Port of `BookmarkDBAdapterV0.setOldBookmarkManager(OldBookmarkManager, AddressMap,
    /// TaskMonitor)`. The `TaskMonitor` parameter is dropped: this port has nothing slow enough
    /// (no real disk I/O) to warrant progress reporting or cancellation for an in-memory
    /// conversion, and every caller in this port passes `TaskMonitor.DUMMY` in the equivalent
    /// Java call sites anyway.
    ///
    /// # Errors
    /// Returns an error if the in-memory conversion database could not be built.
    pub fn set_old_bookmark_manager(
        &mut self,
        old_mgr: &OldBookmarkManager,
        addr_map: Arc<dyn AddressMap + Send + Sync>,
    ) -> io::Result<()> {
        let mut tmp_handle = DBHandle::new()?;
        let mut conversion = BookmarkDbAdapterV3::new(&mut tmp_handle, true, &[], addr_map.clone())
            .expect("creating a fresh in-memory conversion database cannot fail a version check");

        let old_types = old_mgr.get_type_records();
        for old_type in &old_types {
            let type_name = old_type.get_string(TYPE_NAME_COL).unwrap_or_default().to_string();
            let type_id = old_type.get_key().get_long_value() as i32;
            conversion.add_type(&mut tmp_handle, type_id)?;
            for addr in old_mgr.get_bookmark_addresses(&type_name) {
                if let Some(bm) = old_mgr.get_bookmark(&addr, &type_name) {
                    conversion.create_bookmark(
                        type_id,
                        Some(bm.get_category()),
                        addr_map.get_key(&addr, true),
                        Some(bm.get_comment()),
                    )?;
                }
            }
        }

        self.conversion = Some(conversion);
        self._tmp_handle = Some(tmp_handle);
        Ok(())
    }

    fn conversion(&self) -> io::Result<&BookmarkDbAdapterV3> {
        self.conversion.as_ref().ok_or_else(not_set_up)
    }
}

impl Default for BookmarkDbAdapterV0 {
    fn default() -> Self {
        Self::new()
    }
}

impl BookmarkDbAdapter for BookmarkDbAdapterV0 {
    fn get_record(&self, id: i64) -> io::Result<Option<DBRecord>> {
        self.conversion()?.get_record(id)
    }

    fn get_records_by_type_at_address(&self, type_id: i32, address: i64) -> io::Result<Vec<DBRecord>> {
        self.conversion()?.get_records_by_type_at_address(type_id, address)
    }

    fn get_records_by_type_starting_at_address(
        &self,
        _type_id: i32,
        _start_address: i64,
        _forward: bool,
    ) -> io::Result<Vec<DBRecord>> {
        Err(unsupported_too_old())
    }

    fn get_records_by_type_for_address_range(
        &self,
        type_id: i32,
        start_addr: i64,
        end_addr: i64,
    ) -> io::Result<Vec<DBRecord>> {
        self.conversion()?.get_records_by_type_for_address_range(type_id, start_addr, end_addr)
    }

    fn get_records_by_type_and_category(
        &self,
        type_id: i32,
        category: Option<&str>,
    ) -> io::Result<Vec<DBRecord>> {
        self.conversion()?.get_records_by_type_and_category(type_id, category)
    }

    fn get_records_by_type(&self, type_id: i32) -> io::Result<Vec<DBRecord>> {
        self.conversion()?.get_records_by_type(type_id)
    }

    fn get_categories(&self, type_id: i32) -> io::Result<Vec<String>> {
        self.conversion()?.get_categories(type_id)
    }

    fn get_bookmark_addresses(&self, type_id: i32) -> io::Result<AddressSet> {
        self.conversion()?.get_bookmark_addresses(type_id)
    }

    fn get_bookmark_count_for_type(&self, type_id: i32) -> i32 {
        self.conversion.as_ref().map(|c| c.get_bookmark_count_for_type(type_id)).unwrap_or(0)
    }

    fn get_bookmark_count(&self) -> i32 {
        self.conversion.as_ref().map(|c| c.get_bookmark_count()).unwrap_or(0)
    }

    fn has_table(&self, type_id: i32) -> bool {
        // See the module docs: deliberately not mirroring Java's `UnsupportedOperationException`
        // here, since doing so would make the legacy read path this class exists for entirely
        // non-functional rather than merely quirky.
        self.conversion.as_ref().map(|c| c.has_table(type_id)).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::Field;
    use crate::program::database::bookmark::old_bookmark::OldBookmark;
    use crate::program::database::properties::ObjectPropertyMapDB;
    use crate::program::model::address::{Address, AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::listing::{Program, NOTE};
    use crate::program::model::util::property_map_manager::PropertyMapManager;
    use crate::program::model::util::PropertyMap;
    use crate::program::util::ObjectPropertyMap;
    use crate::util::exception::{CancelledException, DuplicateNameException, NoValueException};
    use crate::util::task::TaskMonitor;
    use crate::util::Saveable;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram(), offset)
    }

    struct IdentityAddressMap;
    impl AddressMap for IdentityAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(
            &self,
            _key_range_list: &[crate::program::model::address::KeyRange],
            _addr: Option<&Address>,
        ) -> i32 {
            -1
        }
        fn decode_address(&self, value: i64) -> Address {
            Address::new(ram(), value)
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<crate::program::model::address::KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn crate::program::model::address::AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<crate::program::model::address::KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(IdentityAddressMap)
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            Address::new(ram(), 0)
        }
    }

    fn addr_map() -> Arc<dyn AddressMap + Send + Sync> {
        Arc::new(IdentityAddressMap)
    }

    struct TestProgram {
        factory: Arc<DefaultAddressFactory>,
    }
    impl crate::framework::model::DomainObject for TestProgram {}
    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
    }

    fn test_program() -> Arc<dyn Program> {
        Arc::new(TestProgram {
            factory: Arc::new(DefaultAddressFactory::new(vec![ram()])),
        })
    }

    /// Thin per-name view onto a shared [`ObjectPropertyMapDB<OldBookmark>`], so
    /// [`TestPropertyMapManager`] can hand out independent `Box<dyn ObjectPropertyMap>`/`Box<dyn
    /// PropertyMap>` values that observe the same underlying storage. Mirrors the identical helper
    /// in `old_bookmark_manager.rs`'s own tests.
    struct MapView(Arc<Mutex<ObjectPropertyMapDB<OldBookmark>>>);
    impl ObjectPropertyMap for MapView {
        fn add_object(&mut self, addr: &Address, value: Box<dyn Saveable>) {
            self.0.lock().unwrap().add_object(addr, value);
        }
        fn get_object(&self, addr: &Address) -> Result<Box<dyn Saveable>, NoValueException> {
            self.0.lock().unwrap().get_object(addr)
        }
    }
    impl PropertyMap for MapView {
        fn get_name(&self) -> String {
            self.0.lock().unwrap().get_name()
        }
        fn get_value_class(&self) -> Option<std::any::TypeId> {
            self.0.lock().unwrap().get_value_class()
        }
        fn clear(&mut self) {
            self.0.lock().unwrap().clear();
        }
        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.0.lock().unwrap().intersects_range(start, end)
        }
        fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
            self.0.lock().unwrap().intersects_set(set)
        }
        fn remove_range(&mut self, start: &Address, end: &Address) -> bool {
            self.0.lock().unwrap().remove_range(start, end)
        }
        fn remove(&mut self, addr: &Address) -> bool {
            self.0.lock().unwrap().remove(addr)
        }
        fn has_property(&self, addr: &Address) -> bool {
            self.0.lock().unwrap().has_property(addr)
        }
        fn add(&mut self, addr: &Address, value: Option<Box<dyn std::any::Any>>) {
            self.0.lock().unwrap().add(addr, value);
        }
        fn get(&self, addr: &Address) -> Option<Box<dyn std::any::Any>> {
            self.0.lock().unwrap().get(addr)
        }
        fn get_next_property_address(&self, addr: &Address) -> Option<Address> {
            self.0.lock().unwrap().get_next_property_address(addr)
        }
        fn get_previous_property_address(&self, addr: &Address) -> Option<Address> {
            self.0.lock().unwrap().get_previous_property_address(addr)
        }
        fn get_first_property_address(&self) -> Option<Address> {
            self.0.lock().unwrap().get_first_property_address()
        }
        fn get_last_property_address(&self) -> Option<Address> {
            self.0.lock().unwrap().get_last_property_address()
        }
        fn get_size(&self) -> usize {
            self.0.lock().unwrap().get_size()
        }
        fn get_property_iterator_range(&self, start: &Address, end: &Address) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_range(start, end)
        }
        fn get_property_iterator_range_ordered(
            &self,
            start: &Address,
            end: &Address,
            forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_range_ordered(start, end, forward)
        }
        fn get_property_iterator(&self) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator()
        }
        fn get_property_iterator_set(&self, asv: &dyn AddressSetView) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_set(asv)
        }
        fn get_property_iterator_set_ordered(&self, asv: &dyn AddressSetView, forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_set_ordered(asv, forward)
        }
        fn get_property_iterator_from(&self, start: &Address, forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_from(start, forward)
        }
        fn move_range(&mut self, start: &Address, end: &Address, new_start: &Address) {
            self.0.lock().unwrap().move_range(start, end, new_start);
        }
    }

    /// A real, `ObjectPropertyMapDB<OldBookmark>`-backed [`PropertyMapManager`] sufficient to seed
    /// an [`OldBookmarkManager`] with genuine legacy property-based bookmarks for
    /// [`BookmarkDbAdapterV0::set_old_bookmark_manager`] to convert.
    struct TestPropertyMapManager {
        db_handle: DBHandle,
        maps: BTreeMap<String, Arc<Mutex<ObjectPropertyMapDB<OldBookmark>>>>,
    }
    impl TestPropertyMapManager {
        fn new() -> Self {
            TestPropertyMapManager {
                db_handle: DBHandle::new().unwrap(),
                maps: BTreeMap::new(),
            }
        }
    }
    impl PropertyMapManager for TestPropertyMapManager {
        fn create_int_property_map(
            &mut self,
            _n: &str,
        ) -> Result<Box<dyn crate::program::util::IntPropertyMap>, DuplicateNameException> {
            unimplemented!()
        }
        fn create_long_property_map(
            &mut self,
            _n: &str,
        ) -> Result<Box<dyn crate::program::util::LongPropertyMap>, DuplicateNameException> {
            unimplemented!()
        }
        fn create_string_property_map(
            &mut self,
            _n: &str,
        ) -> Result<Box<dyn crate::program::util::StringPropertyMap>, DuplicateNameException> {
            unimplemented!()
        }
        fn create_object_property_map(
            &mut self,
            property_name: &str,
        ) -> Result<Box<dyn ObjectPropertyMap>, DuplicateNameException> {
            if self.maps.contains_key(property_name) {
                return Err(DuplicateNameException::new());
            }
            let map = ObjectPropertyMapDB::<OldBookmark>::new(&mut self.db_handle, property_name, ram(), false).unwrap();
            let shared = Arc::new(Mutex::new(map));
            self.maps.insert(property_name.to_string(), shared.clone());
            Ok(Box::new(MapView(shared)))
        }
        fn create_void_property_map(
            &mut self,
            _n: &str,
        ) -> Result<Box<dyn crate::program::util::VoidPropertyMap>, DuplicateNameException> {
            unimplemented!()
        }
        fn get_property_map(&self, property_name: &str) -> Option<Box<dyn PropertyMap>> {
            self.maps.get(property_name).map(|m| Box::new(MapView(m.clone())) as Box<dyn PropertyMap>)
        }
        fn get_int_property_map(&self, _n: &str) -> Option<Box<dyn crate::program::util::IntPropertyMap>> {
            None
        }
        fn get_long_property_map(&self, _n: &str) -> Option<Box<dyn crate::program::util::LongPropertyMap>> {
            None
        }
        fn get_string_property_map(&self, _n: &str) -> Option<Box<dyn crate::program::util::StringPropertyMap>> {
            None
        }
        fn get_object_property_map(&self, property_name: &str) -> Option<Box<dyn ObjectPropertyMap>> {
            self.maps.get(property_name).map(|m| Box::new(MapView(m.clone())) as Box<dyn ObjectPropertyMap>)
        }
        fn get_void_property_map(&self, _n: &str) -> Option<Box<dyn crate::program::util::VoidPropertyMap>> {
            None
        }
        fn remove_property_map(&mut self, property_name: &str) -> bool {
            self.maps.remove(property_name).is_some()
        }
        fn property_managers(&self) -> Box<dyn Iterator<Item = String> + '_> {
            Box::new(self.maps.keys().cloned())
        }
        fn remove_all(&mut self, _addr: &Address) {}
        fn remove_all_range(
            &mut self,
            _s: &Address,
            _e: &Address,
            _m: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    #[test]
    fn before_setup_every_method_reports_not_set_up_or_a_safe_default() {
        let adapter = BookmarkDbAdapterV0::new();
        assert!(adapter.get_record(0).is_err());
        assert_eq!(adapter.get_bookmark_count(), 0);
        assert_eq!(adapter.get_bookmark_count_for_type(0), 0);
        assert!(!adapter.has_table(0));
    }

    #[test]
    fn get_records_by_type_starting_at_address_is_always_unsupported() {
        let adapter = BookmarkDbAdapterV0::new();
        assert_eq!(
            adapter
                .get_records_by_type_starting_at_address(0, 0, true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn default_impl_matches_new() {
        let adapter = BookmarkDbAdapterV0::default();
        assert_eq!(adapter.get_bookmark_count(), 0);
    }

    #[test]
    fn set_old_bookmark_manager_converts_legacy_property_bookmarks() {
        let mut backing = TestPropertyMapManager::new();
        {
            let mut note_map = backing.create_object_property_map("Bookmarks").unwrap();
            note_map.add_object(
                &addr(0x1000),
                Box::new(OldBookmark::new(Some(NOTE), Some("general"), Some("hello"), addr(0x1000))),
            );
            let mut todo_map = backing.create_object_property_map("BookmarksTodo").unwrap();
            todo_map.add_object(
                &addr(0x2000),
                Box::new(OldBookmark::new(Some("Todo"), Some("work"), Some("finish this"), addr(0x2000))),
            );
        }
        let old_mgr = OldBookmarkManager::new(test_program(), Arc::new(Mutex::new(backing)));

        let mut adapter = BookmarkDbAdapterV0::new();
        adapter.set_old_bookmark_manager(&old_mgr, addr_map()).unwrap();

        // Both legacy types were converted into the current (V3) schema.
        assert_eq!(adapter.get_bookmark_count(), 2);

        let type_records = old_mgr.get_type_records();
        let note_type_id = type_records
            .iter()
            .find(|r| r.get_string(TYPE_NAME_COL) == Some(NOTE))
            .unwrap()
            .get_key()
            .get_long_value() as i32;
        let todo_type_id = type_records
            .iter()
            .find(|r| r.get_string(TYPE_NAME_COL) == Some("Todo"))
            .unwrap()
            .get_key()
            .get_long_value() as i32;

        let note_records = adapter.get_records_by_type(note_type_id).unwrap();
        assert_eq!(note_records.len(), 1);
        assert_eq!(
            note_records[0].get_field(crate::program::database::bookmark::bookmark_db_adapter_v3::V3_COMMENT_COL),
            &Field::String(Some("hello".to_string()))
        );

        let todo_records = adapter.get_records_by_type(todo_type_id).unwrap();
        assert_eq!(todo_records.len(), 1);
        assert_eq!(
            todo_records[0].get_field(crate::program::database::bookmark::bookmark_db_adapter_v3::V3_CATEGORY_COL),
            &Field::String(Some("work".to_string()))
        );

        // Categories/addresses queries also work through the delegated conversion adapter.
        assert_eq!(adapter.get_categories(note_type_id).unwrap(), vec!["general".to_string()]);
        let addrs = adapter.get_bookmark_addresses(todo_type_id).unwrap();
        assert_eq!(addrs.num_addresses(), 1);
    }
}
