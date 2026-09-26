use crate::util::exception::NoValueException;
use crate::util::map::TypeMismatchException;
use crate::util::saveable::Saveable;

/// Manages property values of type int, String, Object, and "void" for a page of possible
/// addresses. Void serves as a marker for whether an address has a property. Implementors hold
/// the actual value(s) for whichever property type(s) they support and override the
/// corresponding add/get methods; accessing an unsupported type is expected to fail the same way
/// the Java original does (`ClassCastException` for the wrong scalar type, `TypeMismatchException`
/// for `Saveable` objects).
///
/// Cut to a trait to break a dependency cycle: the original class keeps a private
/// `ShortKeyIndexer`/`ShortKeySet`/`DataTable` and switches key-set implementations internally
/// (`RedBlackKeySet` <-> `BitTree` <-> `FullKeySet`) as a storage-size optimization. That
/// internal strategy is not part of the public per-offset property API and is left to
/// implementors; this trait only fixes the latter.
///
/// Port of `ghidra.util.map.ValueStoragePage`.
pub trait ValueStoragePage<T> {
    /// Returns the next offset after `offset` that has a property value, or `None` if there is
    /// none.
    fn get_next(&self, offset: i16) -> Option<i16>;

    /// Returns the previous offset before `offset` that has a property value, or `None` if there
    /// is none.
    fn get_previous(&self, offset: i16) -> Option<i16>;

    /// Returns the first offset that has a property value, or `None` if the page is empty.
    fn get_first(&self) -> Option<i16>;

    /// Returns the last offset that has a property value, or `None` if the page is empty.
    fn get_last(&self) -> Option<i16>;

    /// Returns whether this page has any offset with a property.
    fn is_empty(&self) -> bool;

    /// Returns whether the given offset has a property.
    fn has_property(&self, offset: i16) -> bool;

    /// Marks `key` as having a property, without an associated value (the "void" property type).
    fn add_key(&mut self, key: i16);

    /// Marks every offset in `[start_key, end_key]` as having a property.
    fn add_keys(&mut self, start_key: i16, end_key: i16) {
        for key in start_key..=end_key {
            self.add_key(key);
        }
    }

    /// Marks the given offset as having a property.
    fn add(&mut self, offset: i16) {
        self.add_key(offset);
    }

    /// Marks the given offset range as having a property.
    fn add_range(&mut self, start_offset: i16, end_offset: i16) {
        self.add_keys(start_offset, end_offset);
    }

    /// Returns the number of properties on this page.
    fn get_size(&self) -> usize;

    /// Removes the property at the given offset. Returns `true` if a property was removed;
    /// `false` if there was no property at `offset`.
    fn remove(&mut self, offset: i16) -> bool;

    /// Gets the `Saveable` object property at `offset`, or `None` if no value is stored.
    ///
    /// # Errors
    /// Returns [`TypeMismatchException`] if this page does not support `Saveable` object values.
    fn get_saveable_object(
        &self,
        offset: i16,
    ) -> Result<Option<Box<dyn Saveable>>, TypeMismatchException>;

    /// Adds the `Saveable` object property at `offset`.
    fn add_saveable_object(&mut self, offset: i16, value: Box<dyn Saveable>);

    /// Gets the object property at `offset`, or `None` if no value is stored.
    fn get_object(&self, offset: i16) -> Option<T>;

    /// Adds the object property at `offset`.
    fn add_object(&mut self, offset: i16, value: T);

    /// Gets the `String` property at `offset`, or `None` if no value is stored.
    fn get_string(&self, offset: i16) -> Option<String>;

    /// Adds the `String` property at `offset`.
    fn add_string(&mut self, offset: i16, value: String);

    /// Gets the `int` property at `offset`.
    ///
    /// # Errors
    /// Returns [`NoValueException`] if no value is stored for `offset`.
    fn get_int(&self, offset: i16) -> Result<i32, NoValueException>;

    /// Adds the `int` property at `offset`.
    fn add_int(&mut self, offset: i16, value: i32);

    /// Gets the `long` property at `offset`.
    ///
    /// # Errors
    /// Returns [`NoValueException`] if no value is stored for `offset`.
    fn get_long(&self, offset: i16) -> Result<i64, NoValueException>;

    /// Adds the `long` property at `offset`.
    fn add_long(&mut self, offset: i16, value: i64);

    /// Gets the `short` property at `offset`.
    ///
    /// # Errors
    /// Returns [`NoValueException`] if no value is stored for `offset`.
    fn get_short(&self, offset: i16) -> Result<i16, NoValueException>;

    /// Adds the `short` property at `offset`.
    fn add_short(&mut self, offset: i16, value: i16);

    /// Gets the `byte` property at `offset`.
    ///
    /// # Errors
    /// Returns [`NoValueException`] if no value is stored for `offset`.
    fn get_byte(&self, offset: i16) -> Result<i8, NoValueException>;

    /// Adds the `byte` property at `offset`.
    fn add_byte(&mut self, offset: i16, value: i8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::object_storage::ObjectStorage;
    use crate::util::saveable::ObjectStorageFieldType;
    use std::collections::{BTreeSet, HashMap, VecDeque};

    /// Minimal `ObjectStorage` backed by a FIFO queue of tagged ints, just enough to round-trip
    /// [`MockSaveableInt`] below.
    struct QueueStorage {
        queue: VecDeque<i32>,
    }

    impl QueueStorage {
        fn new() -> Self {
            Self { queue: VecDeque::new() }
        }
    }

    impl ObjectStorage for QueueStorage {
        fn put_int(&mut self, value: i32) {
            self.queue.push_back(value);
        }
        fn get_int(&mut self) -> i32 {
            self.queue.pop_front().expect("storage underflow")
        }

        fn put_byte(&mut self, _value: i8) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_byte(&mut self) -> i8 {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_short(&mut self, _value: i16) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_short(&mut self) -> i16 {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_long(&mut self, _value: i64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_long(&mut self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_string(&mut self, _value: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_string(&mut self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_boolean(&mut self, _value: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_boolean(&mut self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_float(&mut self, _value: f32) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_float(&mut self) -> f32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_double(&mut self, _value: f64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_double(&mut self) -> f64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_ints(&mut self, _value: &[i32]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_ints(&mut self) -> Vec<i32> {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_bytes(&mut self, _value: &[i8]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bytes(&mut self) -> Vec<i8> {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_shorts(&mut self, _value: &[i16]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_shorts(&mut self) -> Vec<i16> {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_longs(&mut self, _value: &[i64]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_longs(&mut self) -> Vec<i64> {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_floats(&mut self, _value: &[f32]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_floats(&mut self) -> Vec<f32> {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_doubles(&mut self, _value: &[f64]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_doubles(&mut self) -> Vec<f64> {
            unimplemented!("not exercised by this smoke test")
        }
        fn put_strings(&mut self, _value: &[&str]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_strings(&mut self) -> Vec<String> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A `Saveable` wrapping a single `int`, standing in for a user-defined property type.
    struct MockSaveableInt {
        value: i32,
    }

    impl Saveable for MockSaveableInt {
        fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
            vec![ObjectStorageFieldType::Int]
        }
        fn save(&self, obj_storage: &mut dyn ObjectStorage) {
            obj_storage.put_int(self.value);
        }
        fn restore(&mut self, obj_storage: &mut dyn ObjectStorage) {
            self.value = obj_storage.get_int();
        }
        fn get_schema_version(&self) -> i32 {
            1
        }
        fn is_upgradeable(&self, _old_schema_version: i32) -> bool {
            false
        }
        fn upgrade(
            &mut self,
            _old_obj_storage: &mut dyn ObjectStorage,
            _old_schema_version: i32,
            _current_obj_storage: &mut dyn ObjectStorage,
        ) -> bool {
            false
        }
        fn is_private(&self) -> bool {
            false
        }
    }

    /// Trivial mock proving `ValueStoragePage` is object-safe and usable behind
    /// `Box<dyn ValueStoragePage<T>>`. Stores each supported property type in its own map, keyed
    /// by offset, and a shared key set tracking which offsets have *any* property.
    #[derive(Default)]
    struct MockPage {
        keys: BTreeSet<i16>,
        objects: HashMap<i16, i32>,
        saveables: HashMap<i16, i32>,
        supports_saveable: bool,
        strings: HashMap<i16, String>,
        ints: HashMap<i16, i32>,
        longs: HashMap<i16, i64>,
        shorts: HashMap<i16, i16>,
        bytes: HashMap<i16, i8>,
    }

    impl MockPage {
        fn new(supports_saveable: bool) -> Self {
            Self { supports_saveable, ..Default::default() }
        }
    }

    impl ValueStoragePage<i32> for MockPage {
        fn get_next(&self, offset: i16) -> Option<i16> {
            self.keys.range((std::ops::Bound::Excluded(offset), std::ops::Bound::Unbounded)).next().copied()
        }

        fn get_previous(&self, offset: i16) -> Option<i16> {
            self.keys.range(..offset).next_back().copied()
        }

        fn get_first(&self) -> Option<i16> {
            self.keys.iter().next().copied()
        }

        fn get_last(&self) -> Option<i16> {
            self.keys.iter().next_back().copied()
        }

        fn is_empty(&self) -> bool {
            self.keys.is_empty()
        }

        fn has_property(&self, offset: i16) -> bool {
            self.keys.contains(&offset)
        }

        fn add_key(&mut self, key: i16) {
            self.keys.insert(key);
        }

        fn get_size(&self) -> usize {
            self.keys.len()
        }

        fn remove(&mut self, offset: i16) -> bool {
            self.objects.remove(&offset);
            self.saveables.remove(&offset);
            self.strings.remove(&offset);
            self.ints.remove(&offset);
            self.longs.remove(&offset);
            self.shorts.remove(&offset);
            self.bytes.remove(&offset);
            self.keys.remove(&offset)
        }

        fn get_saveable_object(
            &self,
            offset: i16,
        ) -> Result<Option<Box<dyn Saveable>>, TypeMismatchException> {
            if !self.supports_saveable {
                return Err(TypeMismatchException::new());
            }
            Ok(self.saveables.get(&offset).map(|&value| {
                let mut so: Box<dyn Saveable> = Box::new(MockSaveableInt { value: 0 });
                let mut storage = QueueStorage::new();
                storage.put_int(value);
                so.restore(&mut storage);
                so
            }))
        }

        fn add_saveable_object(&mut self, offset: i16, value: Box<dyn Saveable>) {
            self.add_key(offset);
            let mut storage = QueueStorage::new();
            value.save(&mut storage);
            self.saveables.insert(offset, storage.get_int());
        }

        fn get_object(&self, offset: i16) -> Option<i32> {
            self.objects.get(&offset).copied()
        }

        fn add_object(&mut self, offset: i16, value: i32) {
            self.add_key(offset);
            self.objects.insert(offset, value);
        }

        fn get_string(&self, offset: i16) -> Option<String> {
            self.strings.get(&offset).cloned()
        }

        fn add_string(&mut self, offset: i16, value: String) {
            self.add_key(offset);
            self.strings.insert(offset, value);
        }

        fn get_int(&self, offset: i16) -> Result<i32, NoValueException> {
            self.ints.get(&offset).copied().ok_or_else(NoValueException::new)
        }

        fn add_int(&mut self, offset: i16, value: i32) {
            self.add_key(offset);
            self.ints.insert(offset, value);
        }

        fn get_long(&self, offset: i16) -> Result<i64, NoValueException> {
            self.longs.get(&offset).copied().ok_or_else(NoValueException::new)
        }

        fn add_long(&mut self, offset: i16, value: i64) {
            self.add_key(offset);
            self.longs.insert(offset, value);
        }

        fn get_short(&self, offset: i16) -> Result<i16, NoValueException> {
            self.shorts.get(&offset).copied().ok_or_else(NoValueException::new)
        }

        fn add_short(&mut self, offset: i16, value: i16) {
            self.add_key(offset);
            self.shorts.insert(offset, value);
        }

        fn get_byte(&self, offset: i16) -> Result<i8, NoValueException> {
            self.bytes.get(&offset).copied().ok_or_else(NoValueException::new)
        }

        fn add_byte(&mut self, offset: i16, value: i8) {
            self.add_key(offset);
            self.bytes.insert(offset, value);
        }
    }

    fn boxed_page(supports_saveable: bool) -> Box<dyn ValueStoragePage<i32>> {
        Box::new(MockPage::new(supports_saveable))
    }

    #[test]
    fn object_round_trip() {
        let mut page = boxed_page(false);
        assert!(page.is_empty());
        page.add_object(5, 42);
        assert!(!page.is_empty());
        assert!(page.has_property(5));
        assert_eq!(page.get_object(5), Some(42));
        assert_eq!(page.get_object(6), None);
    }

    #[test]
    fn scalar_round_trips() {
        let mut page = boxed_page(false);
        page.add_int(1, 100);
        page.add_long(1, 200);
        page.add_short(1, 30);
        page.add_byte(1, 7);
        page.add_string(1, "hello".to_string());

        assert_eq!(page.get_int(1), Ok(100));
        assert_eq!(page.get_long(1), Ok(200));
        assert_eq!(page.get_short(1), Ok(30));
        assert_eq!(page.get_byte(1), Ok(7));
        assert_eq!(page.get_string(1), Some("hello".to_string()));
    }

    #[test]
    fn missing_scalar_is_no_value_exception() {
        let page = boxed_page(false);
        assert!(page.get_int(9).is_err());
        assert!(page.get_long(9).is_err());
        assert!(page.get_short(9).is_err());
        assert!(page.get_byte(9).is_err());
    }

    #[test]
    fn navigation_across_multiple_offsets() {
        let mut page = boxed_page(false);
        page.add(5);
        page.add(10);
        page.add(15);

        assert_eq!(page.get_first(), Some(5));
        assert_eq!(page.get_last(), Some(15));
        assert_eq!(page.get_next(5), Some(10));
        assert_eq!(page.get_next(10), Some(15));
        assert_eq!(page.get_next(15), None);
        assert_eq!(page.get_previous(15), Some(10));
        assert_eq!(page.get_previous(5), None);
    }

    #[test]
    fn add_range_marks_every_offset() {
        let mut page = boxed_page(false);
        page.add_range(3, 6);
        assert_eq!(page.get_size(), 4);
        for offset in 3..=6 {
            assert!(page.has_property(offset));
        }
        assert!(!page.has_property(7));
    }

    #[test]
    fn remove_clears_property() {
        let mut page = boxed_page(false);
        page.add_object(5, 1);
        page.add_object(9, 2);
        assert_eq!(page.get_size(), 2);

        assert!(page.remove(5));
        assert!(!page.remove(5));
        assert_eq!(page.get_size(), 1);
        assert_eq!(page.get_object(5), None);
        assert_eq!(page.get_object(9), Some(2));
    }

    #[test]
    fn saveable_object_round_trip() {
        let mut page = boxed_page(true);
        page.add_saveable_object(2, Box::new(MockSaveableInt { value: 99 }));

        let restored = page.get_saveable_object(2).expect("supported");
        let mut restored = restored.expect("value present");
        // Prove it's a real, usable Saveable: mutate through the trait and re-save.
        assert_eq!(restored.get_schema_version(), 1);
        let mut storage = QueueStorage::new();
        restored.save(&mut storage);
        assert_eq!(storage.get_int(), 99);
    }

    #[test]
    fn saveable_object_unsupported_is_type_mismatch() {
        let page = boxed_page(false);
        match page.get_saveable_object(2) {
            Err(e) => assert_eq!(e, TypeMismatchException::new()),
            Ok(_) => panic!("expected TypeMismatchException"),
        }
    }
}
