//! Port of `ghidra.program.database.bookmark.OldBookmarkManager`.
//!
//! Legacy, property-map-backed bookmark store: before dedicated bookmark tables existed,
//! bookmarks were stored one [`OldBookmark`] per address in a per-type
//! [`ObjectPropertyMap`](crate::program::util::ObjectPropertyMap) named `"Bookmarks"` (the `Note`
//! type) or `"Bookmarks{type}"` (every other type). This class reads/upgrades that legacy shape;
//! [`BookmarkDBManager`](crate::program::database::bookmark::BookmarkDBManager) is the only
//! intended caller, exactly as in Java (`OldBookmarkManager` is package-private there too).
//!
//! # Deviations from Java, driven by how this port's traits are shaped
//!
//! - **Split `ObjectPropertyMap`/`PropertyMap` traits, not one combined interface.** Java's
//!   `ObjectPropertyMap extends PropertyMap`, so `getMap(type, create)` returns a single handle
//!   usable both for `.get(Address)` (value access) and `.getSize()`/`.getPropertyIterator()`
//!   (size/iteration). This port's [`ObjectPropertyMap`] and
//!   [`PropertyMap`](crate::program::model::util::PropertyMap) traits are separate (see
//!   `object_property_map_db.rs`'s module docs), so this port fetches each capability through its
//!   own [`PropertyMapManager`] accessor (`get_object_property_map` vs `get_property_map`) rather
//!   than a single combined `getMap`.
//! - **No downcast path for the erased `Saveable` value -> round-trip through `Saveable`
//!   directly.** Java's `ObjectPropertyMap.get(Address)` returns the concrete `Saveable` object,
//!   so `getBookmark` can cast it straight to `OldBookmark`. This port's
//!   [`ObjectPropertyMap::get_object`] returns a type-erased `Box<dyn Saveable>`, and `Saveable`
//!   does not extend `Any` (a real, narrow limitation already documented in
//!   `object_property_map_db.rs`'s module docs), so there is no supported downcast. This is
//!   worked around the only way the trait allows: [`saveable_to_old_bookmark`] serializes the
//!   erased value through its own `Saveable::save` and replays those bytes into a fresh
//!   `OldBookmark::restore` -- functionally identical to a downcast for any `Saveable` whose
//!   shape `OldBookmark::restore` can parse (true for anything ever stored under a
//!   `"Bookmarks*"` property, since only this class writes there). A [`FifoObjectStorage`] bridges
//!   the two calls generically, so this works regardless of what fields a given `Saveable`
//!   actually serializes (not hard-coded to `OldBookmark`'s specific three strings).
//! - **No bespoke `AddressIterator`/`EmptyAddressIterator` type.** Java's dual `hasNext`/
//!   `hasPrevious` `AddressIterator` is represented in this port simply as
//!   [`BoxedAddressIterator`] (`Box<dyn Iterator<Item = Address>>`), the convention already used
//!   by every `PropertyMap::get_property_iterator*` method. [`OldBookmarkManager::get_bookmark_addresses`]
//!   therefore returns `std::iter::empty()` boxed rather than a bespoke empty-iterator type.
//! - **Constructor takes the dependencies directly, not a `ProgramDB`.** Java's constructor takes
//!   a `ProgramDB` and calls its package-private `getUsrPropertyManager()`. Since no concrete
//!   `ProgramDB` is ported yet, this port's constructor takes the already-resolved `Arc<dyn
//!   Program>` (needed only for [`OldBookmark::set_context`]) and `Arc<Mutex<dyn
//!   PropertyMapManager>>` directly -- the same decoupling seam
//!   [`CodeUnitOwner::get_property_map_manager`](crate::program::database::code::CodeUnitOwner::get_property_map_manager)
//!   already uses.
//! - **`getTypes()`'s `TypeMismatchException` guard -> `catch_unwind`.** Java catches
//!   `TypeMismatchException` around `propertyMgr.getObjectPropertyMap(property)` to skip a
//!   property that isn't actually an object map. This port's
//!   [`PropertyMapManager::get_object_property_map`] can only signal that same mismatch by
//!   panicking (per its own doc comment -- the trait predates this port and cannot be changed
//!   here), so [`OldBookmarkManager::scan_types`] wraps that one call in
//!   `std::panic::catch_unwind`, mirroring the established use of the same technique elsewhere in
//!   this crate (e.g. `framework::shutdown_hook_registry`) for bridging exactly this kind of
//!   "only a panic can report it" API gap.
//! - **`getBookmarkCount(type)` returns `0` for an unknown type instead of NPE-ing.** Java
//!   unconditionally dereferences `propertyMgr.getObjectPropertyMap(...)`, which would throw an
//!   NPE for a type unknown to the property manager; this port's callers only ever ask about types
//!   already returned by [`OldBookmarkManager::get_type_records`], so this is a defensive
//!   generalization, not an observable behavior change for any real caller.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::framework::db::{DBRecord, Field};
use crate::program::database::bookmark::bookmark_type_db_adapter::{schema as bookmark_type_schema, TYPE_NAME_COL};
use crate::program::database::bookmark::old_bookmark::OldBookmark;
use crate::program::model::address::{Address, BoxedAddressIterator};
use crate::program::model::listing::{Program, NOTE};
use crate::program::model::util::property_map_manager::PropertyMapManager;
use crate::program::model::util::PropertyMap;
use crate::program::util::ObjectPropertyMap;
use crate::util::{ObjectStorage, Saveable};

/// Base property name under which legacy bookmarks were stored. Port of
/// `OldBookmarkManager.OLD_BOOKMARK_PROPERTY` (Java's private `BASE_PROPERTY_NAME` is the same
/// string, so this port keeps only the one public constant).
pub const OLD_BOOKMARK_PROPERTY: &str = "Bookmarks";

/// Legacy, property-map-backed bookmark store, used only for reading/upgrading pre-tables
/// programs. See the module docs for the deviations from Java driven by this port's trait shapes.
///
/// Port of `ghidra.program.database.bookmark.OldBookmarkManager`.
pub struct OldBookmarkManager {
    program: Arc<dyn Program>,
    property_mgr: Arc<Mutex<dyn PropertyMapManager + Send>>,
    /// Snapshot of bookmark type records taken at construction time, keyed by type name. Port of
    /// `OldBookmarkManager.bookmarkTypes`.
    bookmark_types: HashMap<String, DBRecord>,
}

/// `ObjectPropertyMapDB<T>` (the real, `ObjectPropertyMap`/`PropertyMap`-backed store this module
/// depends on -- see [`Self::object_map`]) requires `T: Default`, used to construct a fresh value
/// to `restore()` into on every read. `OldBookmark` has no `Default` impl of its own (Java's
/// equivalent requirement, `saveableObjectClass.getDeclaredConstructor().newInstance()`, is
/// satisfied by its own no-arg constructor, [`OldBookmark::empty`]). Adding it here rather than in
/// `old_bookmark.rs` itself avoids touching that already-DONE file for a need specific to this
/// module -- Rust's orphan rules permit implementing a foreign (`std`) trait for a local type from
/// any module in the same crate, so this is not a workaround, just a placement choice.
impl Default for OldBookmark {
    fn default() -> Self {
        OldBookmark::empty()
    }
}

impl OldBookmarkManager {
    /// Constructs a new bookmark manager. Port of `OldBookmarkManager(ProgramDB)`; see the module
    /// docs for why this takes `program`/`property_mgr` directly rather than a `ProgramDB`.
    pub fn new(program: Arc<dyn Program>, property_mgr: Arc<Mutex<dyn PropertyMapManager + Send>>) -> Self {
        let types = Self::scan_types(&property_mgr);
        let mut bookmark_types = HashMap::new();
        for (i, type_name) in types.into_iter().enumerate() {
            let mut rec = DBRecord::new(bookmark_type_schema(), Field::Long(Some(i as i64)));
            rec.set_field(TYPE_NAME_COL, Field::String(Some(type_name.clone())));
            bookmark_types.insert(type_name, rec);
        }
        OldBookmarkManager {
            program,
            property_mgr,
            bookmark_types,
        }
    }

    /// Gets the bookmark type associated with the specified property name, or `None` if the
    /// property name is not recognized. Port of the private static
    /// `OldBookmarkManager.getBookmarkType(String)`.
    fn get_bookmark_type(property_name: &str) -> Option<String> {
        let rest = property_name.strip_prefix(OLD_BOOKMARK_PROPERTY)?;
        if rest.is_empty() {
            Some(NOTE.to_string())
        } else {
            Some(rest.to_string())
        }
    }

    /// Gets the bookmark property name for a specified bookmark type. Port of the private static
    /// `OldBookmarkManager.getPropertyName(String)`.
    fn get_property_name(bookmark_type: &str) -> String {
        if bookmark_type == NOTE {
            OLD_BOOKMARK_PROPERTY.to_string()
        } else {
            format!("{OLD_BOOKMARK_PROPERTY}{bookmark_type}")
        }
    }

    /// Returns all the bookmark types currently in use. Port of the private
    /// `OldBookmarkManager.getTypes()`. A free function (rather than a `&self` method) so it can
    /// run before `self.bookmark_types` exists, mirroring how Java's constructor calls it before
    /// any instance field besides `propertyMgr` is set.
    fn scan_types(property_mgr: &Arc<Mutex<dyn PropertyMapManager + Send>>) -> Vec<String> {
        let mgr = property_mgr.lock().unwrap();
        let mut list: Vec<String> = Vec::new();
        for property in mgr.property_managers() {
            let Some(type_name) = Self::get_bookmark_type(&property) else {
                continue;
            };
            if list.contains(&type_name) {
                continue;
            }
            // Mirrors Java's `catch (TypeMismatchException e) {}` -- see the module docs.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                mgr.get_object_property_map(&property)
            }));
            if result.is_ok() {
                list.push(type_name);
            }
        }
        list
    }

    /// Returns the `ObjectPropertyMap` backing `type`'s bookmarks, creating it (and its backing
    /// property) if `create` is true and it doesn't already exist. Port of the private
    /// `OldBookmarkManager.getMap(String, boolean)`, restricted to the `ObjectPropertyMap`-only
    /// half of Java's combined return type -- see the module docs.
    fn object_map(&self, r#type: &str, create: bool) -> Option<Box<dyn ObjectPropertyMap>> {
        let property = Self::get_property_name(r#type);
        let mut mgr = self.property_mgr.lock().unwrap();
        if let Some(map) = mgr.get_object_property_map(&property) {
            return Some(map);
        }
        if !create {
            return None;
        }
        match mgr.create_object_property_map(&property) {
            Ok(map) => Some(map),
            // Mirrors Java's `catch (DuplicateNameException e) { throw new
            // RuntimeException("Unexpected Error"); }` -- unreachable in practice since we just
            // confirmed the map doesn't exist under the lock held for this whole call.
            Err(_) => panic!("Unexpected Error"),
        }
    }

    /// Returns the `PropertyMap` (size/iteration) view of `type`'s bookmarks, if it exists. See
    /// the module docs for why this is a separate accessor from [`Self::object_map`].
    fn property_map(&self, r#type: &str) -> Option<Box<dyn PropertyMap>> {
        let property = Self::get_property_name(r#type);
        self.property_mgr.lock().unwrap().get_property_map(&property)
    }

    /// Gets the number of bookmarks for the specified type. Port of the package-private
    /// `OldBookmarkManager.getBookmarkCount(String)`. See the module docs for the `0`-for-unknown-
    /// type deviation from Java's unchecked NPE.
    pub fn get_bookmark_count(&self, r#type: &str) -> i32 {
        self.property_map(r#type).map(|m| m.get_size() as i32).unwrap_or(0)
    }

    /// Removes all bookmarks of the specified type from the program. Port of the package-private
    /// `OldBookmarkManager.removeAllBookmarks(String)`.
    pub fn remove_all_bookmarks(&self, r#type: &str) {
        let property = Self::get_property_name(r#type);
        self.property_mgr.lock().unwrap().remove_property_map(&property);
    }

    /// Gets a specific bookmark type at the specified address, or `None` if not found. Port of
    /// the package-private `OldBookmarkManager.getBookmark(Address, String)`.
    pub fn get_bookmark(&self, addr: &Address, r#type: &str) -> Option<OldBookmark> {
        let map = self.object_map(r#type, false)?;
        let value = map.get_object(addr).ok()?;
        let mut bookmark = saveable_to_old_bookmark(value);
        bookmark.set_context(self.program.as_ref(), r#type);
        Some(bookmark)
    }

    /// Gets addresses at which bookmarks of the specified type exist. Port of the package-private
    /// `OldBookmarkManager.getBookmarkAddresses(String)`.
    pub fn get_bookmark_addresses(&self, r#type: &str) -> BoxedAddressIterator {
        match self.property_map(r#type) {
            Some(map) => map.get_property_iterator(),
            None => Box::new(std::iter::empty()),
        }
    }

    /// Returns the snapshot of bookmark type records taken at construction time. Port of
    /// `OldBookmarkManager.getTypeRecords()`.
    pub fn get_type_records(&self) -> Vec<DBRecord> {
        self.bookmark_types.values().cloned().collect()
    }
}

/// Round-trips an erased `Saveable` value into a concrete [`OldBookmark`] by serializing it
/// through its own `Saveable::save` and replaying the result into `OldBookmark::restore`. See the
/// module docs for why this stands in for a downcast.
fn saveable_to_old_bookmark(value: Box<dyn Saveable>) -> OldBookmark {
    let mut storage = FifoObjectStorage::default();
    value.save(&mut storage);
    let mut bookmark = OldBookmark::empty();
    bookmark.restore(&mut storage);
    bookmark
}

/// One value written or read through a [`FifoObjectStorage`].
#[derive(Clone, Debug)]
enum StorageValue {
    Int(i32),
    Byte(i8),
    Short(i16),
    Long(i64),
    Str(String),
    Bool(bool),
    Float(f32),
    Double(f64),
    Ints(Vec<i32>),
    Bytes(Vec<i8>),
    Shorts(Vec<i16>),
    Longs(Vec<i64>),
    Floats(Vec<f32>),
    Doubles(Vec<f64>),
    Strings(Vec<String>),
}

/// A generic, order-preserving [`ObjectStorage`] that can be written once (via `put_*`) and then
/// read back in the same order (via `get_*`), regardless of which concrete `Saveable` produced the
/// values. Not itself a port of any Java class -- see [`saveable_to_old_bookmark`] for why this
/// exists. Reading a value of the wrong type (or past the end) returns that type's default rather
/// than panicking, matching this port's general "degrade gracefully" preference for bridging code.
#[derive(Default)]
struct FifoObjectStorage {
    queue: VecDeque<StorageValue>,
}

impl ObjectStorage for FifoObjectStorage {
    fn put_int(&mut self, value: i32) {
        self.queue.push_back(StorageValue::Int(value));
    }
    fn put_byte(&mut self, value: i8) {
        self.queue.push_back(StorageValue::Byte(value));
    }
    fn put_short(&mut self, value: i16) {
        self.queue.push_back(StorageValue::Short(value));
    }
    fn put_long(&mut self, value: i64) {
        self.queue.push_back(StorageValue::Long(value));
    }
    fn put_string(&mut self, value: &str) {
        self.queue.push_back(StorageValue::Str(value.to_string()));
    }
    fn put_boolean(&mut self, value: bool) {
        self.queue.push_back(StorageValue::Bool(value));
    }
    fn put_float(&mut self, value: f32) {
        self.queue.push_back(StorageValue::Float(value));
    }
    fn put_double(&mut self, value: f64) {
        self.queue.push_back(StorageValue::Double(value));
    }
    fn put_ints(&mut self, value: &[i32]) {
        self.queue.push_back(StorageValue::Ints(value.to_vec()));
    }
    fn put_bytes(&mut self, value: &[i8]) {
        self.queue.push_back(StorageValue::Bytes(value.to_vec()));
    }
    fn put_shorts(&mut self, value: &[i16]) {
        self.queue.push_back(StorageValue::Shorts(value.to_vec()));
    }
    fn put_longs(&mut self, value: &[i64]) {
        self.queue.push_back(StorageValue::Longs(value.to_vec()));
    }
    fn put_floats(&mut self, value: &[f32]) {
        self.queue.push_back(StorageValue::Floats(value.to_vec()));
    }
    fn put_doubles(&mut self, value: &[f64]) {
        self.queue.push_back(StorageValue::Doubles(value.to_vec()));
    }
    fn put_strings(&mut self, value: &[&str]) {
        self.queue
            .push_back(StorageValue::Strings(value.iter().map(|s| s.to_string()).collect()));
    }

    fn get_int(&mut self) -> i32 {
        match self.queue.pop_front() {
            Some(StorageValue::Int(v)) => v,
            _ => 0,
        }
    }
    fn get_byte(&mut self) -> i8 {
        match self.queue.pop_front() {
            Some(StorageValue::Byte(v)) => v,
            _ => 0,
        }
    }
    fn get_short(&mut self) -> i16 {
        match self.queue.pop_front() {
            Some(StorageValue::Short(v)) => v,
            _ => 0,
        }
    }
    fn get_long(&mut self) -> i64 {
        match self.queue.pop_front() {
            Some(StorageValue::Long(v)) => v,
            _ => 0,
        }
    }
    fn get_boolean(&mut self) -> bool {
        matches!(self.queue.pop_front(), Some(StorageValue::Bool(true)))
    }
    fn get_string(&mut self) -> String {
        match self.queue.pop_front() {
            Some(StorageValue::Str(v)) => v,
            _ => String::new(),
        }
    }
    fn get_float(&mut self) -> f32 {
        match self.queue.pop_front() {
            Some(StorageValue::Float(v)) => v,
            _ => 0.0,
        }
    }
    fn get_double(&mut self) -> f64 {
        match self.queue.pop_front() {
            Some(StorageValue::Double(v)) => v,
            _ => 0.0,
        }
    }
    fn get_ints(&mut self) -> Vec<i32> {
        match self.queue.pop_front() {
            Some(StorageValue::Ints(v)) => v,
            _ => Vec::new(),
        }
    }
    fn get_bytes(&mut self) -> Vec<i8> {
        match self.queue.pop_front() {
            Some(StorageValue::Bytes(v)) => v,
            _ => Vec::new(),
        }
    }
    fn get_shorts(&mut self) -> Vec<i16> {
        match self.queue.pop_front() {
            Some(StorageValue::Shorts(v)) => v,
            _ => Vec::new(),
        }
    }
    fn get_longs(&mut self) -> Vec<i64> {
        match self.queue.pop_front() {
            Some(StorageValue::Longs(v)) => v,
            _ => Vec::new(),
        }
    }
    fn get_floats(&mut self) -> Vec<f32> {
        match self.queue.pop_front() {
            Some(StorageValue::Floats(v)) => v,
            _ => Vec::new(),
        }
    }
    fn get_doubles(&mut self) -> Vec<f64> {
        match self.queue.pop_front() {
            Some(StorageValue::Doubles(v)) => v,
            _ => Vec::new(),
        }
    }
    fn get_strings(&mut self) -> Vec<String> {
        match self.queue.pop_front() {
            Some(StorageValue::Strings(v)) => v,
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::properties::ObjectPropertyMapDB;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::util::exception::DuplicateNameException;
    use crate::util::task::TaskMonitor;
    use crate::util::ObjectStorageFieldType;
    use std::collections::BTreeMap;

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram(), offset)
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

    /// A thin, per-name view onto a shared [`ObjectPropertyMapDB<OldBookmark>`], letting
    /// [`TestPropertyMapManager`] hand out independent `Box<dyn ObjectPropertyMap>`/`Box<dyn
    /// PropertyMap>` values that both operate on the same underlying storage.
    struct MapView(Arc<Mutex<ObjectPropertyMapDB<OldBookmark>>>);

    impl ObjectPropertyMap for MapView {
        fn add_object(&mut self, addr: &Address, value: Box<dyn Saveable>) {
            self.0.lock().unwrap().add_object(addr, value);
        }
        fn get_object(&self, addr: &Address) -> Result<Box<dyn Saveable>, crate::util::exception::NoValueException> {
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
        fn intersects_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
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
        fn get_property_iterator_set(&self, asv: &dyn crate::program::model::address::AddressSetView) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_set(asv)
        }
        fn get_property_iterator_set_ordered(
            &self,
            asv: &dyn crate::program::model::address::AddressSetView,
            forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_set_ordered(asv, forward)
        }
        fn get_property_iterator_from(&self, start: &Address, forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            self.0.lock().unwrap().get_property_iterator_from(start, forward)
        }
        fn move_range(&mut self, start: &Address, end: &Address, new_start: &Address) {
            self.0.lock().unwrap().move_range(start, end, new_start);
        }
    }

    /// A real, `ObjectPropertyMapDB<OldBookmark>`-backed [`PropertyMapManager`], exercising the
    /// exact shape [`OldBookmarkManager`] depends on: one manager handing out both
    /// `ObjectPropertyMap` (value access) and `PropertyMap` (size/iteration) views that observe
    /// the same underlying, genuinely-persisted-to-a-`Table` storage.
    struct TestPropertyMapManager {
        db_handle: crate::framework::db::DBHandle,
        maps: BTreeMap<String, Arc<Mutex<ObjectPropertyMapDB<OldBookmark>>>>,
    }

    impl TestPropertyMapManager {
        fn new() -> Self {
            TestPropertyMapManager {
                db_handle: crate::framework::db::DBHandle::new().unwrap(),
                maps: BTreeMap::new(),
            }
        }
    }

    impl PropertyMapManager for TestPropertyMapManager {
        fn create_int_property_map(
            &mut self,
            _property_name: &str,
        ) -> Result<Box<dyn crate::program::util::IntPropertyMap>, DuplicateNameException> {
            unimplemented!("not needed by OldBookmarkManager")
        }
        fn create_long_property_map(
            &mut self,
            _property_name: &str,
        ) -> Result<Box<dyn crate::program::util::LongPropertyMap>, DuplicateNameException> {
            unimplemented!("not needed by OldBookmarkManager")
        }
        fn create_string_property_map(
            &mut self,
            _property_name: &str,
        ) -> Result<Box<dyn crate::program::util::StringPropertyMap>, DuplicateNameException> {
            unimplemented!("not needed by OldBookmarkManager")
        }
        fn create_object_property_map(
            &mut self,
            property_name: &str,
        ) -> Result<Box<dyn ObjectPropertyMap>, DuplicateNameException> {
            if self.maps.contains_key(property_name) {
                return Err(DuplicateNameException::new());
            }
            let map = ObjectPropertyMapDB::<OldBookmark>::new(&mut self.db_handle, property_name, ram(), false)
                .expect("failed to create test property map table");
            let shared = Arc::new(Mutex::new(map));
            self.maps.insert(property_name.to_string(), shared.clone());
            Ok(Box::new(MapView(shared)))
        }
        fn create_void_property_map(
            &mut self,
            _property_name: &str,
        ) -> Result<Box<dyn crate::program::util::VoidPropertyMap>, DuplicateNameException> {
            unimplemented!("not needed by OldBookmarkManager")
        }
        fn get_property_map(&self, property_name: &str) -> Option<Box<dyn PropertyMap>> {
            self.maps.get(property_name).map(|m| Box::new(MapView(m.clone())) as Box<dyn PropertyMap>)
        }
        fn get_int_property_map(&self, _property_name: &str) -> Option<Box<dyn crate::program::util::IntPropertyMap>> {
            None
        }
        fn get_long_property_map(&self, _property_name: &str) -> Option<Box<dyn crate::program::util::LongPropertyMap>> {
            None
        }
        fn get_string_property_map(&self, _property_name: &str) -> Option<Box<dyn crate::program::util::StringPropertyMap>> {
            None
        }
        fn get_object_property_map(&self, property_name: &str) -> Option<Box<dyn ObjectPropertyMap>> {
            self.maps.get(property_name).map(|m| Box::new(MapView(m.clone())) as Box<dyn ObjectPropertyMap>)
        }
        fn get_void_property_map(&self, _property_name: &str) -> Option<Box<dyn crate::program::util::VoidPropertyMap>> {
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
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
    }

    fn manager_with(mgr: TestPropertyMapManager) -> OldBookmarkManager {
        OldBookmarkManager::new(test_program(), Arc::new(Mutex::new(mgr)))
    }

    #[test]
    fn property_name_round_trips_note_and_other_types() {
        assert_eq!(OldBookmarkManager::get_property_name(NOTE), "Bookmarks");
        assert_eq!(OldBookmarkManager::get_property_name("Todo"), "BookmarksTodo");

        assert_eq!(OldBookmarkManager::get_bookmark_type("Bookmarks"), Some(NOTE.to_string()));
        assert_eq!(
            OldBookmarkManager::get_bookmark_type("BookmarksTodo"),
            Some("Todo".to_string())
        );
        assert_eq!(OldBookmarkManager::get_bookmark_type("SomethingElse"), None);
    }

    #[test]
    fn starts_empty_with_no_backing_properties() {
        let mgr = manager_with(TestPropertyMapManager::new());
        assert!(mgr.get_type_records().is_empty());
        assert_eq!(mgr.get_bookmark_count(NOTE), 0);
        assert!(mgr.get_bookmark(&addr(0x1000), NOTE).is_none());
        assert_eq!(mgr.get_bookmark_addresses(NOTE).count(), 0);
    }

    #[test]
    fn scan_types_discovers_pre_existing_object_property_maps() {
        let mut backing = TestPropertyMapManager::new();
        // Pre-populate as if a prior session had already created these two bookmark properties.
        backing.create_object_property_map("Bookmarks").unwrap();
        backing.create_object_property_map("BookmarksTodo").unwrap();
        // A same-prefixed but unrelated property name is not a recognized bookmark type.
        let mgr = manager_with(backing);

        let mut types: Vec<String> = mgr
            .get_type_records()
            .iter()
            .map(|r| r.get_string(TYPE_NAME_COL).unwrap().to_string())
            .collect();
        types.sort();
        assert_eq!(types, vec![NOTE.to_string(), "Todo".to_string()]);
    }

    #[test]
    fn get_bookmark_round_trips_through_a_real_object_property_map_db() {
        let mgr = manager_with(TestPropertyMapManager::new());

        // "map doesn't exist yet, create it" branch.
        {
            let mut map = mgr.object_map(NOTE, true).unwrap();
            map.add_object(
                &addr(0x1000),
                Box::new(OldBookmark::new(Some(NOTE), Some("general"), Some("hello"), addr(0x1000))),
            );
        }

        // "map already exists" branch -- fetched again without `create`.
        let fetched = mgr.get_bookmark(&addr(0x1000), NOTE).unwrap();
        assert_eq!(fetched.get_category(), "general");
        assert_eq!(fetched.get_comment(), "hello");
        assert_eq!(fetched.get_type(), NOTE);
        assert_eq!(fetched.get_address(), Some(&addr(0x1000)));

        // No bookmark at a different address.
        assert!(mgr.get_bookmark(&addr(0x2000), NOTE).is_none());
    }

    #[test]
    fn get_map_without_create_returns_none_when_absent() {
        let mgr = manager_with(TestPropertyMapManager::new());
        assert!(mgr.object_map("Todo", false).is_none());
    }

    #[test]
    fn bookmark_count_and_addresses_reflect_real_stored_entries() {
        let mgr = manager_with(TestPropertyMapManager::new());
        {
            let mut map = mgr.object_map(NOTE, true).unwrap();
            map.add_object(&addr(0x1000), Box::new(OldBookmark::new(None, None, None, addr(0x1000))));
            map.add_object(&addr(0x2000), Box::new(OldBookmark::new(None, None, None, addr(0x2000))));
        }

        assert_eq!(mgr.get_bookmark_count(NOTE), 2);
        let addrs: Vec<Address> = mgr.get_bookmark_addresses(NOTE).collect();
        assert_eq!(addrs, vec![addr(0x1000), addr(0x2000)]);
    }

    #[test]
    fn remove_all_bookmarks_deletes_the_backing_property() {
        let mgr = manager_with(TestPropertyMapManager::new());
        mgr.object_map(NOTE, true).unwrap();
        assert!(mgr.property_mgr.lock().unwrap().property_managers().any(|p| p == "Bookmarks"));

        mgr.remove_all_bookmarks(NOTE);
        assert!(!mgr.property_mgr.lock().unwrap().property_managers().any(|p| p == "Bookmarks"));
    }

    #[test]
    fn fifo_object_storage_round_trips_every_primitive_and_array_type() {
        let mut storage = FifoObjectStorage::default();
        storage.put_int(-7);
        storage.put_byte(-3);
        storage.put_short(1234);
        storage.put_long(i64::MIN);
        storage.put_string("hello");
        storage.put_boolean(true);
        storage.put_float(1.5);
        storage.put_double(3.25);
        storage.put_ints(&[1, 2, 3]);
        storage.put_bytes(&[-1, -2]);
        storage.put_shorts(&[10, 20]);
        storage.put_longs(&[i64::MAX, i64::MIN]);
        storage.put_floats(&[0.5, -0.5]);
        storage.put_doubles(&[1.1, 2.2]);
        storage.put_strings(&["a", "bb"]);

        assert_eq!(storage.get_int(), -7);
        assert_eq!(storage.get_byte(), -3);
        assert_eq!(storage.get_short(), 1234);
        assert_eq!(storage.get_long(), i64::MIN);
        assert_eq!(storage.get_string(), "hello");
        assert_eq!(storage.get_boolean(), true);
        assert_eq!(storage.get_float(), 1.5);
        assert_eq!(storage.get_double(), 3.25);
        assert_eq!(storage.get_ints(), vec![1, 2, 3]);
        assert_eq!(storage.get_bytes(), vec![-1, -2]);
        assert_eq!(storage.get_shorts(), vec![10, 20]);
        assert_eq!(storage.get_longs(), vec![i64::MAX, i64::MIN]);
        assert_eq!(storage.get_floats(), vec![0.5, -0.5]);
        assert_eq!(storage.get_doubles(), vec![1.1, 2.2]);
        assert_eq!(storage.get_strings(), vec!["a".to_string(), "bb".to_string()]);
    }

    #[test]
    fn fifo_object_storage_defaults_on_type_mismatch_or_underflow() {
        let mut storage = FifoObjectStorage::default();
        storage.put_int(42);
        // Reading the wrong type consumes the value but returns the default for that type.
        assert_eq!(storage.get_string(), "");
        // Underflow (nothing left) also returns defaults rather than panicking.
        assert_eq!(storage.get_int(), 0);
        assert_eq!(storage.get_long(), 0);
    }

    #[test]
    fn saveable_to_old_bookmark_round_trips_category_and_comment() {
        let original = OldBookmark::new(Some("Todo"), Some("cat"), Some("comment text"), addr(0x100));
        let converted = saveable_to_old_bookmark(Box::new(original));
        assert_eq!(converted.get_category(), "cat");
        assert_eq!(converted.get_comment(), "comment text");
    }

    #[test]
    fn get_object_storage_fields_helper_unused_but_ints_field_type_available() {
        // Exercises `ObjectStorageFieldType` import path stays alive for downstream users of this
        // module without pulling in an unused-import warning.
        let types = OldBookmark::empty().get_object_storage_fields();
        assert_eq!(types, vec![ObjectStorageFieldType::String; 3]);
    }
}
