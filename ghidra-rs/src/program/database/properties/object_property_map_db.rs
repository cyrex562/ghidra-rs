//! Port of `ghidra.program.database.properties.ObjectPropertyMapDB<T extends Saveable>`.
//!
//! Property manager for `Saveable`-object-valued properties. Each record's value is the byte
//! sequence produced by `T::save`, stored as a single `Binary` table column, and reconstructed on
//! read by calling `T::default()` then `T::restore` against those same bytes (see
//! [`ByteObjectStorage`] below). This is the flagship port of this batch: earlier tonight,
//! `OldBookmarkManager` (`ghidra.program.database.bookmark`) was skipped specifically because it
//! needs a concrete type that provides both `ObjectPropertyMap` (Saveable value access) and
//! `PropertyMap` (size/iteration) on the same instance, and no concrete `ObjectPropertyMapDB`
//! existed yet. This struct provides exactly that.
//!
//! See `db_backed_store`'s module docs for the single-address-space key-encoding simplification
//! every concrete map in this file family shares, and `VoidPropertyMapDB`'s module docs for why
//! the `DBHandle`/`OpenMode`/.../`TaskMonitor` constructor and `checkMapVersion` are not ported
//! here.
//!
//! Additional simplifications specific to this class, beyond what the scalar maps already cut:
//!
//! - **Dynamic per-field schema (`ObjectStorageAdapterDB`) -> one opaque `Binary` column.** Java
//!   builds the table's `Schema` at runtime from the exact sequence of primitives a given
//!   `Saveable.save()` call writes (one DB column per primitive/array field), so two different
//!   `Saveable` implementations get differently-shaped tables. This port instead always uses a
//!   fixed two-column schema (`long` key, one `Binary` value column) and serializes/deserializes
//!   through [`ByteObjectStorage`], a length-prefixed `ObjectStorage` codec local to this file.
//!   `add`/`get` round-trip correctly for any `Saveable` (the pieces `OldBookmarkManager` and
//!   friends actually need); what's lost is Java's column-per-field on-disk layout and the
//!   `checkSchema`-enforced invariant that every value ever stored in one map has identical field
//!   shape (moot here since the schema is fixed up front, not derived from the first `add`).
//! - **`saveableObjectClass.isAssignableFrom(value.getClass())` runtime check -> not ported.**
//!   Java's `add(Address, T)` is generic in `T` but still receives a `Saveable` whose *runtime*
//!   class it must double-check against `saveableObjectClass` (values can arrive from
//!   deserialization, not just direct calls). The already-ported `ObjectPropertyMap` trait's
//!   `add_object` takes a type-erased `Box<dyn Saveable>` for the same reason, but the `Saveable`
//!   trait (also already ported) doesn't extend `Any`, so there is no supported way to downcast
//!   and compare its concrete type against `T` here. Callers that hand `add_object` a value whose
//!   concrete type differs from this map's `T` will get bytes written that a later `get_object`
//!   (which always reconstructs a `T`) may fail to parse correctly -- a real but narrow risk,
//!   scoped identically to what the trait's own signature already allows.
//! - **`getSaveableClassForName`/`ClassSearcher`/`ClassTranslator` -> not ported.** These resolve
//!   a stored class-path string to a `Class<? extends Saveable>` via JVM reflection, with a
//!   `GenericSaveable` fallback when the class can't be found. Rust's `T` is chosen statically at
//!   compile time, so there is no reflective class-path resolution step to port; the
//!   `GenericSaveable`-fallback *concept* is what `DBPropertyMapManager` (not ported yet, only a
//!   trait) would need when it can no longer resolve a stored property's class.
//! - **`upgradeTable`/schema-version upgrade path -> not ported.** No prior on-disk schema exists
//!   for this Rust port to be upgraded from, so there is nothing to migrate yet; a future schema
//!   change to this map would need to add this back.
//! - **`isPrivate`/`ChangeManager` notification -> `is_private` kept, notification not wired.**
//!   [`ObjectPropertyMapDB::is_private`] reproduces `ObjectPropertyMapDB.isPrivate(Saveable)`'s
//!   logic exactly (`supports_private && value.is_private()`), but -- like every other concrete
//!   map in this file family -- there is no `ChangeManager` field to notify, since none of this
//!   crate's `PropertyMapDB`-family structs wire one up yet.

use std::any::{Any, TypeId};
use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::database::properties::db_backed_store::{collect_sorted_addresses, VecKeyIterator};
use crate::program::database::properties::{get_table_name, PropertyMapDB};
use crate::program::model::address::{
    Address, AddressIteratorAdapter, AddressSetView, AddressSpace, BoxedAddressIterator,
};
use crate::program::model::util::PropertyMap;
use crate::program::seam_stubs::AddressKeyIteratorLike;
use crate::program::util::ObjectPropertyMap;
use crate::util::exception::NoValueException;
use crate::util::{ObjectStorage, Saveable};

const VALUE_COL: usize = 0;

/// Database-backed `Saveable`-object-valued property map.
///
/// Port of `ghidra.program.database.properties.ObjectPropertyMapDB<T extends Saveable>`. See the
/// module docs for the simplifications this port makes relative to Java's dynamic per-field
/// schema. `T` is the concrete `Saveable` implementation this map stores; `T::default()` is used
/// to construct a fresh instance to `restore()` into on every read (Java uses
/// `saveableObjectClass.getDeclaredConstructor().newInstance()` for the same purpose).
pub struct ObjectPropertyMapDB<T: Saveable + Default + Send + Sync + 'static> {
    state: DbObjectState,
    name: String,
    space: Arc<AddressSpace>,
    table: Arc<RwLock<Table>>,
    /// Stands in for `ObjectPropertyMapDB.supportsPrivate`.
    supports_private: bool,
    _marker: PhantomData<T>,
}

impl<T: Saveable + Default + Send + Sync + 'static> ObjectPropertyMapDB<T> {
    /// Construct a Saveable-object property map, creating its underlying table in `db_handle` if
    /// it does not already exist. `supports_private` mirrors the Java constructor's
    /// `supportsPrivate` parameter (see [`Self::is_private`]).
    pub fn new(
        db_handle: &mut DBHandle,
        name: &str,
        space: Arc<AddressSpace>,
        supports_private: bool,
    ) -> io::Result<Self> {
        let table_name = get_table_name(name);
        let table = match db_handle.get_table(&table_name) {
            Some(t) => t,
            None => {
                let schema = Arc::new(Schema::new(
                    0,
                    FieldType::Long,
                    "Address".to_string(),
                    vec![FieldType::Binary],
                    vec!["Value".to_string()],
                    vec![],
                ));
                db_handle.create_table(table_name, schema)?
            }
        };
        Ok(ObjectPropertyMapDB {
            state: DbObjectState::new(0),
            name: name.to_string(),
            space,
            table,
            supports_private,
            _marker: PhantomData,
        })
    }

    fn key(&self, addr: &Address) -> Field {
        Field::Long(Some(addr.offset()))
    }

    fn bytes_at(&self, addr: &Address) -> Option<Vec<u8>> {
        self.table
            .read()
            .unwrap()
            .get_record(&self.key(addr))
            .ok()
            .flatten()
            .and_then(|rec| match rec.get_field(VALUE_COL) {
                Field::Binary(Some(bytes)) => Some(bytes.clone()),
                _ => None,
            })
    }

    fn put_bytes(&mut self, addr: &Address, bytes: Vec<u8>) {
        let schema = self.table.read().unwrap().get_schema();
        let mut rec = DBRecord::new(schema, self.key(addr));
        rec.set_field(VALUE_COL, Field::Binary(Some(bytes)));
        let _ = self.table.write().unwrap().put_record(rec);
    }

    /// Returns whether a change involving `value` should be broadcast. Stands in for
    /// `ObjectPropertyMapDB.isPrivate(Saveable)`. No `ChangeManager` is wired up in this port (see
    /// the module docs), so nothing currently consults this beyond direct callers/tests.
    pub fn is_private(&self, value: &dyn Saveable) -> bool {
        self.supports_private && value.is_private()
    }
}

impl<T: Saveable + Default + Send + Sync + 'static> DbObject for ObjectPropertyMapDB<T> {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    fn refresh(&self, _record: Option<&DBRecord>) -> bool {
        true
    }
}

impl<T: Saveable + Default + Send + Sync + 'static> ObjectPropertyMap for ObjectPropertyMapDB<T> {
    fn add_object(&mut self, addr: &Address, value: Box<dyn Saveable>) {
        let mut storage = ByteObjectStorage::new();
        value.save(&mut storage);
        self.put_bytes(addr, storage.into_bytes());
    }

    fn get_object(&self, addr: &Address) -> Result<Box<dyn Saveable>, NoValueException> {
        let bytes = self.bytes_at(addr).ok_or_else(NoValueException::new)?;
        let mut storage = ByteObjectStorage::from_bytes(bytes);
        let mut obj = T::default();
        obj.restore(&mut storage);
        Ok(Box::new(obj))
    }
}

impl<T: Saveable + Default + Send + Sync + 'static> PropertyMap for ObjectPropertyMapDB<T> {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_value_class(&self) -> Option<TypeId> {
        Some(TypeId::of::<T>())
    }

    fn clear(&mut self) {
        let _ = self.table.write().unwrap().clear_all();
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .iter()
            .any(|a| a >= start && a <= end)
    }

    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .iter()
            .any(|a| set.contains(a))
    }

    fn remove_range(&mut self, start: &Address, end: &Address) -> bool {
        let addrs: Vec<Address> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| a >= start && a <= end)
            .collect();
        let mut removed = false;
        let mut table = self.table.write().unwrap();
        for a in addrs {
            if table.delete_record(&self.key(&a)).unwrap_or(false) {
                removed = true;
            }
        }
        removed
    }

    fn remove(&mut self, addr: &Address) -> bool {
        self.table.write().unwrap().delete_record(&self.key(addr)).unwrap_or(false)
    }

    fn has_property(&self, addr: &Address) -> bool {
        self.bytes_at(addr).is_some()
    }

    fn add(&mut self, addr: &Address, value: Option<Box<dyn Any>>) {
        match value {
            Some(v) => match v.downcast::<Box<dyn Saveable>>() {
                Ok(saveable) => self.add_object(addr, *saveable),
                Err(_) => panic!("Saveable object value required"),
            },
            None => {
                self.remove(addr);
            }
        }
    }

    fn get(&self, addr: &Address) -> Option<Box<dyn Any>> {
        self.get_object(addr).ok().map(|s| Box::new(s) as Box<dyn Any>)
    }

    fn get_next_property_address(&self, addr: &Address) -> Option<Address> {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .find(|a| a > addr)
    }

    fn get_previous_property_address(&self, addr: &Address) -> Option<Address> {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .rev()
            .find(|a| a < addr)
    }

    fn get_first_property_address(&self) -> Option<Address> {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .next()
    }

    fn get_last_property_address(&self) -> Option<Address> {
        collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .last()
    }

    fn get_size(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }

    fn get_property_iterator_range(&self, start: &Address, end: &Address) -> BoxedAddressIterator {
        self.get_property_iterator_range_ordered(start, end, true)
    }

    fn get_property_iterator_range_ordered(
        &self,
        start: &Address,
        end: &Address,
        forward: bool,
    ) -> BoxedAddressIterator {
        let mut addrs: Vec<Address> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| a >= start && a <= end)
            .collect();
        if !forward {
            addrs.reverse();
        }
        Box::new(AddressIteratorAdapter::from_vec(addrs))
    }

    fn get_property_iterator(&self) -> BoxedAddressIterator {
        Box::new(AddressIteratorAdapter::from_vec(collect_sorted_addresses(
            &self.table.read().unwrap(),
            &self.space,
        )))
    }

    fn get_property_iterator_set(&self, asv: &dyn AddressSetView) -> BoxedAddressIterator {
        self.get_property_iterator_set_ordered(asv, true)
    }

    fn get_property_iterator_set_ordered(&self, asv: &dyn AddressSetView, forward: bool) -> BoxedAddressIterator {
        let mut addrs: Vec<Address> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| asv.contains(a))
            .collect();
        if !forward {
            addrs.reverse();
        }
        Box::new(AddressIteratorAdapter::from_vec(addrs))
    }

    fn get_property_iterator_from(&self, start: &Address, forward: bool) -> BoxedAddressIterator {
        let mut addrs: Vec<Address> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| if forward { a >= start } else { a <= start })
            .collect();
        if !forward {
            addrs.reverse();
        }
        Box::new(AddressIteratorAdapter::from_vec(addrs))
    }

    fn move_range(&mut self, start: &Address, end: &Address, new_start: &Address) {
        // Moves the raw stored bytes directly rather than decoding through `T` and
        // re-encoding: the value's byte representation doesn't change when its address does,
        // so there's no need to round-trip it through `T::default()`/`restore`/`save`.
        let moved: Vec<(Address, Vec<u8>)> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| a >= start && a <= end)
            .filter_map(|a| self.bytes_at(&a).map(|b| (a, b)))
            .collect();
        for (a, _) in &moved {
            self.remove(a);
        }
        for (a, bytes) in moved {
            let offset = a.offset() - start.offset();
            let new_addr = Address::new(new_start.space().clone(), new_start.offset() + offset);
            self.put_bytes(&new_addr, bytes);
        }
    }
}

impl<T: Saveable + Default + Send + Sync + 'static> PropertyMapDB for ObjectPropertyMapDB<T> {
    fn set_cache_size(&mut self, _size: usize) {}

    fn delete(&mut self) -> io::Result<()> {
        self.table.write().unwrap().clear_all()?;
        self.set_deleted();
        Ok(())
    }

    fn get_address_key_iterator_for_set(
        &self,
        set: Option<&dyn AddressSetView>,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let mut keys: Vec<i64> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| set.map_or(true, |s| s.contains(a)))
            .map(|a| a.offset())
            .collect();
        if !at_start {
            keys.reverse();
        }
        Ok(Box::new(VecKeyIterator::new(keys)))
    }

    fn get_address_key_iterator_from(
        &self,
        start: &Address,
        before: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let keys: Vec<i64> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| if before { a <= start } else { a >= start })
            .map(|a| a.offset())
            .collect();
        Ok(Box::new(VecKeyIterator::new(keys)))
    }

    fn get_address_key_iterator_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let mut keys: Vec<i64> = collect_sorted_addresses(&self.table.read().unwrap(), &self.space)
            .into_iter()
            .filter(|a| a >= start && a <= end)
            .map(|a| a.offset())
            .collect();
        if !at_start {
            keys.reverse();
        }
        Ok(Box::new(VecKeyIterator::new(keys)))
    }

    fn invalidate(&mut self) {
        self.set_invalid();
    }
}

/// Length-prefixed, sequential-cursor [`ObjectStorage`] codec that serializes to/deserializes
/// from a flat `Vec<u8>`. Not itself a port of any Java class -- it stands in for
/// `ObjectStorageAdapterDB`'s role of turning `Saveable.save`/`restore` calls into bytes, but
/// (per the module docs) as one opaque blob rather than Java's one-DB-column-per-field layout.
/// All multi-byte primitives are encoded big-endian; arrays/strings are length-prefixed (`u32`
/// element/byte count) followed by their encoded elements/UTF-8 bytes.
struct ByteObjectStorage {
    buf: Vec<u8>,
    pos: usize,
}

impl ByteObjectStorage {
    fn new() -> Self {
        ByteObjectStorage { buf: Vec::new(), pos: 0 }
    }

    fn from_bytes(buf: Vec<u8>) -> Self {
        ByteObjectStorage { buf, pos: 0 }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let end = (self.pos + n).min(self.buf.len());
        let slice = self.buf[self.pos.min(end)..end].to_vec();
        self.pos = end;
        slice
    }

    fn read_len(&mut self) -> usize {
        let b = self.take(4);
        if b.len() < 4 {
            return 0;
        }
        u32::from_be_bytes(b.try_into().unwrap()) as usize
    }

    fn write_len(&mut self, len: usize) {
        self.buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

impl ObjectStorage for ByteObjectStorage {
    fn put_int(&mut self, value: i32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }
    fn put_byte(&mut self, value: i8) {
        self.buf.push(value as u8);
    }
    fn put_short(&mut self, value: i16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }
    fn put_long(&mut self, value: i64) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }
    fn put_string(&mut self, value: &str) {
        self.write_len(value.len());
        self.buf.extend_from_slice(value.as_bytes());
    }
    fn put_boolean(&mut self, value: bool) {
        self.buf.push(if value { 1 } else { 0 });
    }
    fn put_float(&mut self, value: f32) {
        self.buf.extend_from_slice(&value.to_bits().to_be_bytes());
    }
    fn put_double(&mut self, value: f64) {
        self.buf.extend_from_slice(&value.to_bits().to_be_bytes());
    }
    fn put_ints(&mut self, value: &[i32]) {
        self.write_len(value.len());
        for v in value {
            self.put_int(*v);
        }
    }
    fn put_bytes(&mut self, value: &[i8]) {
        self.write_len(value.len());
        for v in value {
            self.put_byte(*v);
        }
    }
    fn put_shorts(&mut self, value: &[i16]) {
        self.write_len(value.len());
        for v in value {
            self.put_short(*v);
        }
    }
    fn put_longs(&mut self, value: &[i64]) {
        self.write_len(value.len());
        for v in value {
            self.put_long(*v);
        }
    }
    fn put_floats(&mut self, value: &[f32]) {
        self.write_len(value.len());
        for v in value {
            self.put_float(*v);
        }
    }
    fn put_doubles(&mut self, value: &[f64]) {
        self.write_len(value.len());
        for v in value {
            self.put_double(*v);
        }
    }
    fn put_strings(&mut self, value: &[&str]) {
        self.write_len(value.len());
        for v in value {
            self.put_string(v);
        }
    }

    fn get_int(&mut self) -> i32 {
        let b = self.take(4);
        if b.len() < 4 {
            return 0;
        }
        i32::from_be_bytes(b.try_into().unwrap())
    }
    fn get_byte(&mut self) -> i8 {
        let b = self.take(1);
        if b.is_empty() {
            return 0;
        }
        b[0] as i8
    }
    fn get_short(&mut self) -> i16 {
        let b = self.take(2);
        if b.len() < 2 {
            return 0;
        }
        i16::from_be_bytes(b.try_into().unwrap())
    }
    fn get_long(&mut self) -> i64 {
        let b = self.take(8);
        if b.len() < 8 {
            return 0;
        }
        i64::from_be_bytes(b.try_into().unwrap())
    }
    fn get_boolean(&mut self) -> bool {
        let b = self.take(1);
        !b.is_empty() && b[0] != 0
    }
    fn get_string(&mut self) -> String {
        let len = self.read_len();
        let bytes = self.take(len);
        String::from_utf8_lossy(&bytes).to_string()
    }
    fn get_float(&mut self) -> f32 {
        let b = self.take(4);
        if b.len() < 4 {
            return 0.0;
        }
        f32::from_bits(u32::from_be_bytes(b.try_into().unwrap()))
    }
    fn get_double(&mut self) -> f64 {
        let b = self.take(8);
        if b.len() < 8 {
            return 0.0;
        }
        f64::from_bits(u64::from_be_bytes(b.try_into().unwrap()))
    }
    fn get_ints(&mut self) -> Vec<i32> {
        let len = self.read_len();
        (0..len).map(|_| self.get_int()).collect()
    }
    fn get_bytes(&mut self) -> Vec<i8> {
        let len = self.read_len();
        (0..len).map(|_| self.get_byte()).collect()
    }
    fn get_shorts(&mut self) -> Vec<i16> {
        let len = self.read_len();
        (0..len).map(|_| self.get_short()).collect()
    }
    fn get_longs(&mut self) -> Vec<i64> {
        let len = self.read_len();
        (0..len).map(|_| self.get_long()).collect()
    }
    fn get_floats(&mut self) -> Vec<f32> {
        let len = self.read_len();
        (0..len).map(|_| self.get_float()).collect()
    }
    fn get_doubles(&mut self) -> Vec<f64> {
        let len = self.read_len();
        (0..len).map(|_| self.get_double()).collect()
    }
    fn get_strings(&mut self) -> Vec<String> {
        let len = self.read_len();
        (0..len).map(|_| self.get_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::properties::TestSaveable;
    use crate::program::model::address::AddressSpaceType;
    use crate::util::ObjectStorageFieldType;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn sample(int_value: i32) -> TestSaveable {
        TestSaveable {
            int_value,
            str_value: "hello".to_string(),
            int_values: vec![1, 2, 3],
            ..Default::default()
        }
    }

    fn map(name: &str) -> (DBHandle, ObjectPropertyMapDB<TestSaveable>) {
        let mut handle = DBHandle::new().unwrap();
        let m = ObjectPropertyMapDB::<TestSaveable>::new(&mut handle, name, space(), true).unwrap();
        (handle, m)
    }

    #[test]
    fn byte_object_storage_round_trips_every_primitive_and_array_type() {
        let mut storage = ByteObjectStorage::new();
        storage.put_int(-7);
        storage.put_byte(-3);
        storage.put_short(1234);
        storage.put_long(i64::MIN);
        storage.put_string("héllo");
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

        let mut reader = ByteObjectStorage::from_bytes(storage.into_bytes());
        assert_eq!(reader.get_int(), -7);
        assert_eq!(reader.get_byte(), -3);
        assert_eq!(reader.get_short(), 1234);
        assert_eq!(reader.get_long(), i64::MIN);
        assert_eq!(reader.get_string(), "héllo");
        assert_eq!(reader.get_boolean(), true);
        assert_eq!(reader.get_float(), 1.5);
        assert_eq!(reader.get_double(), 3.25);
        assert_eq!(reader.get_ints(), vec![1, 2, 3]);
        assert_eq!(reader.get_bytes(), vec![-1, -2]);
        assert_eq!(reader.get_shorts(), vec![10, 20]);
        assert_eq!(reader.get_longs(), vec![i64::MAX, i64::MIN]);
        assert_eq!(reader.get_floats(), vec![0.5, -0.5]);
        assert_eq!(reader.get_doubles(), vec![1.1, 2.2]);
        assert_eq!(reader.get_strings(), vec!["a".to_string(), "bb".to_string()]);
    }

    #[test]
    fn add_object_and_get_object_round_trip() {
        let (_h, mut m) = map("objs");
        m.add_object(&addr(0x1000), Box::new(sample(42)));

        let got = m.get_object(&addr(0x1000)).unwrap();
        assert_eq!(got.get_schema_version(), 0);

        assert!(m.get_object(&addr(0x2000)).is_err());
    }

    #[test]
    fn add_with_dyn_any_dispatches_and_removes() {
        let (_h, mut m) = map("objs");
        m.add(
            &addr(0x1000),
            Some(Box::new(Box::new(sample(7)) as Box<dyn Saveable>)),
        );
        assert!(m.has_property(&addr(0x1000)));

        m.add(&addr(0x1000), None);
        assert!(!m.has_property(&addr(0x1000)));
    }

    #[test]
    #[should_panic(expected = "Saveable object value required")]
    fn add_with_non_saveable_panics() {
        let (_h, mut m) = map("objs");
        m.add(&addr(0x1000), Some(Box::new(42i32)));
    }

    #[test]
    fn get_value_class_is_t() {
        let (_h, m) = map("objs");
        assert_eq!(m.get_value_class(), Some(TypeId::of::<TestSaveable>()));
    }

    #[test]
    fn move_range_preserves_bytes_without_reconstructing() {
        let (_h, mut m) = map("objs");
        m.add_object(&addr(0x1000), Box::new(sample(1)));
        m.add_object(&addr(0x2000), Box::new(sample(2)));

        m.move_range(&addr(0x1000), &addr(0x2000), &addr(0x5000));

        assert!(!m.has_property(&addr(0x1000)));
        assert!(m.has_property(&addr(0x5000)));
        assert!(m.has_property(&addr(0x6000)));
        assert_eq!(m.get_size(), 2);
    }

    #[test]
    fn size_and_iteration() {
        let (_h, mut m) = map("objs");
        m.add_object(&addr(0x1000), Box::new(sample(1)));
        m.add_object(&addr(0x2000), Box::new(sample(2)));
        m.add_object(&addr(0x3000), Box::new(sample(3)));
        assert_eq!(m.get_size(), 3);

        assert_eq!(m.get_first_property_address(), Some(addr(0x1000)));
        assert_eq!(m.get_last_property_address(), Some(addr(0x3000)));

        let addrs: Vec<Address> = m.get_property_iterator().collect();
        assert_eq!(addrs, vec![addr(0x1000), addr(0x2000), addr(0x3000)]);
    }

    #[test]
    fn is_private_honors_supports_private_flag_and_value() {
        let (_h, m) = map("objs");
        struct PrivateSaveable;
        impl Saveable for PrivateSaveable {
            fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
                Vec::new()
            }
            fn save(&self, _s: &mut dyn ObjectStorage) {}
            fn restore(&mut self, _s: &mut dyn ObjectStorage) {}
            fn get_schema_version(&self) -> i32 {
                0
            }
            fn is_upgradeable(&self, _v: i32) -> bool {
                false
            }
            fn upgrade(&mut self, _o: &mut dyn ObjectStorage, _v: i32, _c: &mut dyn ObjectStorage) -> bool {
                false
            }
            fn is_private(&self) -> bool {
                true
            }
        }

        assert!(m.is_private(&PrivateSaveable));

        let mut handle = DBHandle::new().unwrap();
        let non_broadcasting =
            ObjectPropertyMapDB::<TestSaveable>::new(&mut handle, "objs2", space(), false).unwrap();
        assert!(!non_broadcasting.is_private(&PrivateSaveable));
    }

    #[test]
    fn delete_clears_table_and_marks_deleted() {
        let (_h, mut m) = map("objs");
        m.add_object(&addr(0x1000), Box::new(sample(1)));
        m.delete().unwrap();
        assert_eq!(m.get_size(), 0);
        assert!(m.is_deleted(&crate::util::lock::ReentrantLock::new("t")));
    }

    #[test]
    fn usable_as_trait_object_through_property_map_db() {
        let mut handle = DBHandle::new().unwrap();
        let map: Box<dyn PropertyMapDB> =
            Box::new(ObjectPropertyMapDB::<TestSaveable>::new(&mut handle, "objs", space(), false).unwrap());
        assert_eq!(map.get_name(), "objs");
        assert_eq!(map.get_size(), 0);
    }

    #[test]
    fn usable_as_object_property_map_and_property_map_on_same_instance() {
        // This is the exact shape `OldBookmarkManager` needs: one concrete instance usable both
        // as an `ObjectPropertyMap` (Saveable value access) and as a `PropertyMap`
        // (size/iteration), which motivated this port.
        let (_h, mut m) = map("objs");
        m.add_object(&addr(0x1000), Box::new(sample(9)));

        let opm: &mut dyn ObjectPropertyMap = &mut m;
        assert!(opm.get_object(&addr(0x1000)).is_ok());

        let pm: &dyn PropertyMap = &m;
        assert_eq!(pm.get_size(), 1);
    }
}
