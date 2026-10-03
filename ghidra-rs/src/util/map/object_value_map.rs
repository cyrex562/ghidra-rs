use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::marker::PhantomData;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::util::map::value_map::{
    clamp_num_page_bits, compute_page_mask, compute_page_size, ValueMap, DEFAULT_NUMBER_PAGE_BITS,
};
use crate::util::map::{ValueStoragePage, ValueStoragePageIndex};

/// Handles general storage and retrieval of object values indexed by `i64` keys.
///
/// Port of `ghidra.util.map.ObjectValueMap<T>`.
///
/// Two aspects of the Java class have no literal Rust equivalent:
///
/// - Java's `ValueStoragePage<T>` is a concrete, default-constructible class; this crate's port
///   (see [`crate::util::map::value_storage_page`]) already cuts it down to a trait with no
///   concrete production implementation (an existing, independent dependency-cycle decision --
///   see that module's own doc comment). Page storage here is therefore generic over an
///   implementor-supplied page type `P: ValueStoragePage<T> + Default`, mirroring the worked
///   example [`crate::util::map::value_map`]'s own test `MockValueMap` already establishes for
///   exactly this situation; `Default` stands in for Java's `new ValueStoragePage<T>()` no-arg
///   constructor, used by [`ValueMap::get_or_create_page`] to create a fresh page on demand.
/// - `saveProperty`/`restoreProperty` use Java's built-in reflective object serialization
///   (`ObjectOutputStream.writeObject`/`ObjectInputStream.readObject`) to persist an arbitrary
///   `T`, which has no Rust analogue. This port instead requires `T: Serialize +
///   DeserializeOwned` and uses `serde_json` (already a crate dependency) to round-trip the
///   value through the same `dyn Write`/`dyn Read` byte streams [`ValueMap::save_property`]/
///   [`ValueMap::restore_property`] already use.
pub struct ObjectValueMap<T, P: ValueStoragePage<T> + Default> {
    name: String,
    num_page_bits: u32,
    page_mask: i64,
    page_size: i16,
    num_properties: i32,
    page_index: ValueStoragePageIndex,
    pages: HashMap<i64, P>,
    _marker: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned, P: ValueStoragePage<T> + Default> ObjectValueMap<T, P> {
    /// Constructor for `ObjectValueMap` (Java doc: "Constructor for ObjectPropertySet").
    ///
    /// Mirrors `ObjectValueMap(String name)`, which forwards to `ValueMap(name, null)` -- i.e.
    /// the default page-bit count.
    pub fn new(name: impl Into<String>) -> Self {
        let num_page_bits = clamp_num_page_bits(DEFAULT_NUMBER_PAGE_BITS);
        let page_mask = compute_page_mask(num_page_bits);
        Self {
            name: name.into(),
            num_page_bits,
            page_mask,
            page_size: compute_page_size(page_mask),
            num_properties: 0,
            page_index: ValueStoragePageIndex::default(),
            pages: HashMap::new(),
            _marker: PhantomData,
        }
    }

    /// Stores an object at the given index. Any object currently at that index will be replaced
    /// by the new object.
    ///
    /// Mirrors `putObject(long, T)`.
    pub fn put_object(&mut self, index: i64, value: T) {
        let page_id = self.get_page_id(index);
        let offset = self.get_page_offset(index);
        let page = self.get_or_create_page(page_id);
        let before = page.get_size();
        page.add_object(offset, value);
        let added = page.get_size() - before;
        self.num_properties += added as i32;
    }

    /// Retrieves the object stored at the given index, or `None` if no object is stored at the
    /// index.
    ///
    /// Mirrors `getObject(long)`.
    pub fn get_object(&self, index: i64) -> Option<T> {
        let page = self.get_page(self.get_page_id(index))?;
        page.get_object(self.get_page_offset(index))
    }
}

impl<T: Serialize + DeserializeOwned, P: ValueStoragePage<T> + Default> ValueMap<T>
    for ObjectValueMap<T, P>
{
    /// Mirrors `ObjectValueMap.getDataSize()`.
    fn get_data_size(&self) -> i32 {
        20
    }

    fn move_index(&mut self, from: i64, to: i64) {
        // Java's `moveIndex` is `T value = getObject(from); remove(from); putObject(to, value);`
        // -- unconditionally re-inserting at `to`, even when `from` had no value (`value` is
        // `null`). That is a real quirk: moving a never-set index creates a spurious `null`
        // entry at the destination. Rust's `T` has no generic `null` representation to
        // reproduce that literally, so this port only moves when a value actually existed,
        // which is the behavior every caller of `moveIndex` (a private-ish helper driven by
        // `ValueMap::move_range`, only ever invoked for indexes `move_range` has already found
        // to have a value) actually observes in practice.
        if let Some(value) = self.get_object(from) {
            self.remove(from);
            self.put_object(to, value);
        }
    }

    fn save_property(&self, out: &mut dyn Write, addr: i64) -> io::Result<()> {
        let value = self
            .get_object(addr)
            .expect("save_property is only called for indexes known to have a property");
        let bytes = serde_json::to_vec(&value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        out.write_all(&(bytes.len() as u64).to_be_bytes())?;
        out.write_all(&bytes)
    }

    fn restore_property(&mut self, input: &mut dyn Read, addr: i64) -> io::Result<()> {
        let mut len_buf = [0u8; 8];
        input.read_exact(&mut len_buf)?;
        let len = u64::from_be_bytes(len_buf) as usize;
        let mut bytes = vec![0u8; len];
        input.read_exact(&mut bytes)?;
        let value: T = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.put_object(addr, value);
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn num_page_bits(&self) -> u32 {
        self.num_page_bits
    }

    fn page_mask(&self) -> i64 {
        self.page_mask
    }

    fn page_size(&self) -> i16 {
        self.page_size
    }

    fn num_properties(&self) -> i32 {
        self.num_properties
    }

    fn num_properties_mut(&mut self) -> &mut i32 {
        &mut self.num_properties
    }

    fn page_index(&self) -> &ValueStoragePageIndex {
        &self.page_index
    }

    fn page_index_mut(&mut self) -> &mut ValueStoragePageIndex {
        &mut self.page_index
    }

    fn get_page(&self, page_id: i64) -> Option<&dyn ValueStoragePage<T>> {
        self.pages.get(&page_id).map(|p| p as &dyn ValueStoragePage<T>)
    }

    fn get_page_mut(&mut self, page_id: i64) -> Option<&mut dyn ValueStoragePage<T>> {
        self.pages.get_mut(&page_id).map(|p| p as &mut dyn ValueStoragePage<T>)
    }

    fn get_or_create_page(&mut self, page_id: i64) -> &mut dyn ValueStoragePage<T> {
        if !self.pages.contains_key(&page_id) {
            self.pages.insert(page_id, P::default());
            self.page_index.add(page_id);
        }
        self.pages.get_mut(&page_id).unwrap()
    }

    fn remove_page_storage(&mut self, page_id: i64) {
        self.pages.remove(&page_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::NoValueException;
    use crate::util::saveable::Saveable;
    use serde::Deserialize;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Payload {
        label: String,
        count: i32,
    }

    /// Minimal in-memory [`ValueStoragePage<Payload>`], matching the shape of `ValueMap`'s own
    /// `MockPage` test double.
    #[derive(Default)]
    struct MockPage {
        values: std::collections::BTreeMap<i16, Payload>,
    }

    impl ValueStoragePage<Payload> for MockPage {
        fn get_next(&self, offset: i16) -> Option<i16> {
            self.values
                .range((std::ops::Bound::Excluded(offset), std::ops::Bound::Unbounded))
                .next()
                .map(|(&k, _)| k)
        }
        fn get_previous(&self, offset: i16) -> Option<i16> {
            self.values.range(..offset).next_back().map(|(&k, _)| k)
        }
        fn get_first(&self) -> Option<i16> {
            self.values.keys().next().copied()
        }
        fn get_last(&self) -> Option<i16> {
            self.values.keys().next_back().copied()
        }
        fn is_empty(&self) -> bool {
            self.values.is_empty()
        }
        fn has_property(&self, offset: i16) -> bool {
            self.values.contains_key(&offset)
        }
        fn add_key(&mut self, key: i16) {
            self.values
                .entry(key)
                .or_insert(Payload { label: String::new(), count: 0 });
        }
        fn get_size(&self) -> usize {
            self.values.len()
        }
        fn remove(&mut self, offset: i16) -> bool {
            self.values.remove(&offset).is_some()
        }
        fn get_saveable_object(
            &self,
            _offset: i16,
        ) -> Result<Option<Box<dyn Saveable>>, crate::util::map::TypeMismatchException> {
            Err(crate::util::map::TypeMismatchException::new())
        }
        fn add_saveable_object(&mut self, _offset: i16, _value: Box<dyn Saveable>) {}
        fn get_object(&self, offset: i16) -> Option<Payload> {
            self.values.get(&offset).cloned()
        }
        fn add_object(&mut self, offset: i16, value: Payload) {
            self.values.insert(offset, value);
        }
        fn get_string(&self, _offset: i16) -> Option<String> {
            None
        }
        fn add_string(&mut self, _offset: i16, _value: String) {}
        fn get_int(&self, _offset: i16) -> Result<i32, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_int(&mut self, _offset: i16, _value: i32) {}
        fn get_long(&self, _offset: i16) -> Result<i64, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_long(&mut self, _offset: i16, _value: i64) {}
        fn get_short(&self, _offset: i16) -> Result<i16, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_short(&mut self, _offset: i16, _value: i16) {}
        fn get_byte(&self, _offset: i16) -> Result<i8, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_byte(&mut self, _offset: i16, _value: i8) {}
    }

    type TestMap = ObjectValueMap<Payload, MockPage>;

    fn payload(label: &str, count: i32) -> Payload {
        Payload { label: label.to_string(), count }
    }

    #[test]
    fn get_data_size_is_twenty() {
        let map = TestMap::new("test");
        assert_eq!(map.get_data_size(), 20);
    }

    #[test]
    fn name_round_trips() {
        let map = TestMap::new("objs");
        assert_eq!(map.name(), "objs");
    }

    #[test]
    fn put_and_get_object_round_trips() {
        let mut map = TestMap::new("m");
        map.put_object(10, payload("hello", 42));
        assert_eq!(map.get_object(10), Some(payload("hello", 42)));
        assert_eq!(map.get_size(), 1);
    }

    #[test]
    fn get_object_missing_returns_none() {
        let map = TestMap::new("m");
        assert_eq!(map.get_object(5), None);
    }

    #[test]
    fn put_object_overwrites_existing_value() {
        let mut map = TestMap::new("m");
        map.put_object(1, payload("a", 1));
        map.put_object(1, payload("b", 2));
        assert_eq!(map.get_object(1), Some(payload("b", 2)));
        assert_eq!(map.get_size(), 1);
    }

    #[test]
    fn move_index_moves_value_to_new_index() {
        let mut map = TestMap::new("m");
        map.put_object(5, payload("x", 7));
        map.move_index(5, 15);
        assert!(!map.has_property(5));
        assert_eq!(map.get_object(15), Some(payload("x", 7)));
    }

    #[test]
    fn move_index_with_no_value_is_a_no_op() {
        // Documents the deliberate divergence from Java's `ObjectValueMap.moveIndex`, which
        // would unconditionally call `putObject(to, null)` here, creating a spurious entry at
        // `to`. See the doc comment on `ValueMap::move_index`'s impl above.
        let mut map = TestMap::new("m");
        map.move_index(1, 2);
        assert!(!map.has_property(1));
        assert!(!map.has_property(2));
        assert_eq!(map.get_size(), 0);
    }

    #[test]
    fn save_and_restore_property_round_trip() {
        let mut map = TestMap::new("m");
        map.put_object(3, payload("saved", 99));

        let mut buf = Vec::new();
        map.save_property(&mut buf, 3).expect("save succeeds");

        let mut restored = TestMap::new("m");
        let mut cursor = std::io::Cursor::new(buf);
        restored.restore_property(&mut cursor, 3).expect("restore succeeds");

        assert_eq!(restored.get_object(3), Some(payload("saved", 99)));
    }

    #[test]
    #[should_panic(expected = "save_property is only called for indexes known to have a property")]
    fn save_property_on_missing_index_panics() {
        let map = TestMap::new("m");
        let mut buf = Vec::new();
        let _ = map.save_property(&mut buf, 0);
    }

    #[test]
    fn save_properties_and_restore_properties_use_value_map_defaults() {
        let mut map = TestMap::new("m");
        map.put_object(1, payload("one", 1));
        map.put_object(2, payload("two", 2));

        let mut buf = Vec::new();
        map.save_properties(&mut buf, 0, 10).expect("save succeeds");

        let mut restored = TestMap::new("m");
        let mut cursor = std::io::Cursor::new(buf);
        restored.restore_properties(&mut cursor).expect("restore succeeds");

        assert_eq!(restored.get_object(1), Some(payload("one", 1)));
        assert_eq!(restored.get_object(2), Some(payload("two", 2)));
    }

    #[test]
    fn object_safety_via_value_map_trait_object() {
        let mut map = TestMap::new("m");
        map.put_object(1, payload("boxed", 1));
        let boxed: Box<dyn ValueMap<Payload>> = Box::new(map);
        assert_eq!(boxed.get_data_size(), 20);
        assert_eq!(boxed.get_size(), 1);
    }
}
