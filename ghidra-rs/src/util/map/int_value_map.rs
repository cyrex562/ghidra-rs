use std::collections::HashMap;
use std::io::{self, Read, Write};

use crate::util::exception::NoValueException;
use crate::util::map::value_map::{
    clamp_num_page_bits, compute_page_mask, compute_page_size, ValueMap, DEFAULT_NUMBER_PAGE_BITS,
};
use crate::util::map::{ValueStoragePage, ValueStoragePageIndex};

/// Handles general storage and retrieval of `int` values indexed by `i64` keys.
///
/// Port of `ghidra.util.map.IntValueMap`.
///
/// Java's `ValueStoragePage<T>` is a concrete, default-constructible class; this crate's port
/// (see [`crate::util::map::value_storage_page`]) already cuts it down to a trait with no
/// concrete production implementation (an existing, independent dependency-cycle decision --
/// see that module's own doc comment). Page storage here is therefore generic over an
/// implementor-supplied page type `P: ValueStoragePage<i32> + Default`, mirroring the worked
/// example [`crate::util::map::value_map`]'s own test `MockValueMap` already establishes for
/// exactly this situation; `Default` stands in for Java's `new ValueStoragePage<Integer>()`
/// no-arg constructor, used by [`ValueMap::get_or_create_page`] to create a fresh page on
/// demand.
pub struct IntValueMap<P: ValueStoragePage<i32> + Default> {
    name: String,
    num_page_bits: u32,
    page_mask: i64,
    page_size: i16,
    num_properties: i32,
    page_index: ValueStoragePageIndex,
    pages: HashMap<i64, P>,
}

impl<P: ValueStoragePage<i32> + Default> IntValueMap<P> {
    /// Constructor for `IntValueMap`.
    ///
    /// Mirrors `IntValueMap(String name)`, which forwards to `ValueMap(name, null)` -- i.e. the
    /// default page-bit count.
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
        }
    }

    /// Stores an int value at the given index. Any value currently at that index will be
    /// replaced by the new value.
    ///
    /// Mirrors `putInt(long, int)`.
    pub fn put_int(&mut self, index: i64, value: i32) {
        let page_id = self.get_page_id(index);
        let offset = self.get_page_offset(index);
        let page = self.get_or_create_page(page_id);
        let before = page.get_size();
        page.add_int(offset, value);
        let added = page.get_size() - before;
        self.num_properties += added as i32;
    }

    /// Retrieves the int value stored at the given index.
    ///
    /// # Errors
    /// Returns [`NoValueException`] if there is no int value stored at the index.
    ///
    /// Mirrors `getInt(long)`.
    pub fn get_int(&self, index: i64) -> Result<i32, NoValueException> {
        match self.get_page(self.get_page_id(index)) {
            Some(page) => page.get_int(self.get_page_offset(index)),
            None => Err(NoValueException::new()),
        }
    }
}

impl<P: ValueStoragePage<i32> + Default> ValueMap<i32> for IntValueMap<P> {
    /// Mirrors `IntValueMap.getDataSize()`.
    fn get_data_size(&self) -> i32 {
        4
    }

    fn move_index(&mut self, from: i64, to: i64) {
        // Mirrors `moveIndex`: `catch (NoValueException e) { // ignore }` -- if `from` has no
        // value, the move is silently skipped.
        if let Ok(value) = self.get_int(from) {
            self.remove(from);
            self.put_int(to, value);
        }
    }

    fn save_property(&self, out: &mut dyn Write, addr: i64) -> io::Result<()> {
        // Java wraps a `NoValueException` here in an `AssertException` ("should never happen",
        // since `ValueMap::save_properties` only calls `save_property` for indexes it has
        // already confirmed have a property). Mirrored as a panic via `expect`, matching this
        // crate's established convention for the same invariant (see `ValueMap`'s own
        // `MockValueMap::save_property` test).
        let value = self
            .get_int(addr)
            .expect("save_property is only called for indexes known to have a property");
        out.write_all(&value.to_be_bytes())
    }

    fn restore_property(&mut self, input: &mut dyn Read, addr: i64) -> io::Result<()> {
        let mut buf = [0u8; 4];
        input.read_exact(&mut buf)?;
        self.put_int(addr, i32::from_be_bytes(buf));
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

    fn get_page(&self, page_id: i64) -> Option<&dyn ValueStoragePage<i32>> {
        self.pages.get(&page_id).map(|p| p as &dyn ValueStoragePage<i32>)
    }

    fn get_page_mut(&mut self, page_id: i64) -> Option<&mut dyn ValueStoragePage<i32>> {
        self.pages.get_mut(&page_id).map(|p| p as &mut dyn ValueStoragePage<i32>)
    }

    fn get_or_create_page(&mut self, page_id: i64) -> &mut dyn ValueStoragePage<i32> {
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
    use crate::util::saveable::Saveable;

    /// Minimal in-memory [`ValueStoragePage<i32>`], matching the shape of `ValueMap`'s own
    /// `MockPage` test double.
    #[derive(Default)]
    struct MockPage {
        values: std::collections::BTreeMap<i16, i32>,
    }

    impl ValueStoragePage<i32> for MockPage {
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
            self.values.entry(key).or_insert(0);
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
        fn get_object(&self, _offset: i16) -> Option<i32> {
            None
        }
        fn add_object(&mut self, _offset: i16, _value: i32) {}
        fn get_string(&self, _offset: i16) -> Option<String> {
            None
        }
        fn add_string(&mut self, _offset: i16, _value: String) {}
        fn get_int(&self, offset: i16) -> Result<i32, NoValueException> {
            self.values.get(&offset).copied().ok_or_else(NoValueException::new)
        }
        fn add_int(&mut self, offset: i16, value: i32) {
            self.values.insert(offset, value);
        }
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

    type TestMap = IntValueMap<MockPage>;

    #[test]
    fn get_data_size_is_four() {
        let map = TestMap::new("test");
        assert_eq!(map.get_data_size(), 4);
    }

    #[test]
    fn name_round_trips() {
        let map = TestMap::new("props");
        assert_eq!(map.name(), "props");
    }

    #[test]
    fn put_and_get_int_round_trips() {
        let mut map = TestMap::new("m");
        map.put_int(10, 42);
        assert_eq!(map.get_int(10), Ok(42));
        assert_eq!(map.get_size(), 1);
    }

    #[test]
    fn get_int_missing_returns_no_value_exception() {
        let map = TestMap::new("m");
        assert!(map.get_int(5).is_err());
    }

    #[test]
    fn put_int_overwrites_existing_value() {
        let mut map = TestMap::new("m");
        map.put_int(1, 100);
        map.put_int(1, 200);
        assert_eq!(map.get_int(1), Ok(200));
        assert_eq!(map.get_size(), 1);
    }

    #[test]
    fn move_index_moves_value_to_new_index() {
        let mut map = TestMap::new("m");
        map.put_int(5, 77);
        map.move_index(5, 15);
        assert!(!map.has_property(5));
        assert_eq!(map.get_int(15), Ok(77));
    }

    #[test]
    fn move_index_with_no_value_is_a_no_op() {
        // Faithful to Java's `IntValueMap.moveIndex`, which catches `NoValueException` and
        // silently ignores a move from an index with no value -- unlike `ObjectValueMap`'s
        // `moveIndex`, which has no such guard (see `ObjectValueMap`'s own quirk test).
        let mut map = TestMap::new("m");
        map.move_index(1, 2);
        assert!(!map.has_property(1));
        assert!(!map.has_property(2));
        assert_eq!(map.get_size(), 0);
    }

    #[test]
    fn save_and_restore_property_round_trip() {
        let mut map = TestMap::new("m");
        map.put_int(3, 12345);

        let mut buf = Vec::new();
        map.save_property(&mut buf, 3).expect("save succeeds");

        let mut restored = TestMap::new("m");
        let mut cursor = std::io::Cursor::new(buf);
        restored.restore_property(&mut cursor, 3).expect("restore succeeds");

        assert_eq!(restored.get_int(3), Ok(12345));
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
        map.put_int(1, 10);
        map.put_int(2, 20);
        map.put_int(3, 30);

        let mut buf = Vec::new();
        map.save_properties(&mut buf, 0, 10).expect("save succeeds");

        let mut restored = TestMap::new("m");
        let mut cursor = std::io::Cursor::new(buf);
        restored.restore_properties(&mut cursor).expect("restore succeeds");

        assert_eq!(restored.get_int(1), Ok(10));
        assert_eq!(restored.get_int(2), Ok(20));
        assert_eq!(restored.get_int(3), Ok(30));
    }

    #[test]
    fn object_safety_via_value_map_trait_object() {
        let mut map = TestMap::new("m");
        map.put_int(1, 1);
        let boxed: Box<dyn ValueMap<i32>> = Box::new(map);
        assert_eq!(boxed.get_data_size(), 4);
        assert_eq!(boxed.get_size(), 1);
    }
}
