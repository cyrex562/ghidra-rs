//! Mirrors `ghidra.util.database.DBCachedObjectIndex<K, T extends DBAnnotatedObject>`: an index
//! on a field in a `DBCachedObjectStore`, giving clients access to objects by the value of an
//! indexed field.
//!
//! Its methods are inspired by `NavigableMap`, but the index permits duplicate keys (it behaves
//! like a multimap), so the Java class does not implement `NavigableMap` itself.
//!
//! The Java class holds a `DBCachedObjectStore<T>`, an `ErrorHandler`, a `DBFieldCodec<K, T, ?>`,
//! a column index, a [`FieldSpan`], and a [`Direction`], and computes every other query by
//! delegating to the store under the restriction of the field span. Porting it faithfully
//! requires `DBCachedObjectStore` to exist first, which it does not yet (it is itself a
//! cycle cut-point elsewhere in this same package). This is therefore ported as a pure trait,
//! matching the same convention already established for
//! [`DBCachedObjectStoreMap`](super::db_cached_object_store_map::DBCachedObjectStoreMap),
//! [`DBCachedObjectStoreEntrySet`](super::db_cached_object_store_entry_set::DBCachedObjectStoreEntrySet),
//! and
//! [`DBCachedObjectStoreKeySet`](super::db_cached_object_store_key_set::DBCachedObjectStoreKeySet):
//! the shape of the Java public API, with every query implemented as a default method in terms of
//! a handful of required accessors (`store`, `err_handler`, `codec`, `column_index`,
//! `field_span`, `direction`) plus one required constructor-like method,
//! [`restrict`](DBCachedObjectIndex::restrict), standing in for the Java class's protected
//! constructor (used by `head`/`tail`/`sub`/`descending` to rebuild a view over the same
//! store/codec/column with a different span/direction). A concrete implementation belongs
//! alongside the real `DBCachedObjectStore` port.
//!
//! Unlike those sibling traits (which collapse their `T extends DBAnnotatedObject` type
//! parameter into `Arc<dyn DBAnnotatedObject>`), `K` and `T` stay as trait-level generics here,
//! matching the convention already used by the extended
//! [`DBCachedObjectStore<T>`](crate::util::seam_stubs::DBCachedObjectStore) placeholder itself
//! and by [`DBAnnotatedObjectFactory<T>`](super::db_annotated_object_factory::DBAnnotatedObjectFactory):
//! `K` (the indexed field's value type) has no common representation to collapse to, and objects
//! are handed back as `Arc<T>` rather than `Arc<dyn DBAnnotatedObject>` so that `T`'s own methods
//! stay reachable without a downcast.
//!
//! Java's `Iterable<K>`/`Iterable<T>`/`Iterable<Entry<K, T>>` return types
//! ([`keys`](DBCachedObjectIndex::keys), [`values`](DBCachedObjectIndex::values),
//! [`entries`](DBCachedObjectIndex::entries)) become eagerly-collected `Vec`s, following the same
//! convention `DBCachedObjectStoreEntrySet::to_vec` established for the sibling cut-point traits
//! in this package. [`get_lazily`](DBCachedObjectIndex::get_lazily) is consequently also eager
//! here (equivalent to [`get`](DBCachedObjectIndex::get)), losing the Java method's distinguishing
//! "keys retrieved now, objects reloaded on each iteration" semantics -- there being no lazy
//! `Vec` to preserve that difference through once `Iterable` is gone.
//!
//! `firstKey`/`firstValue`/`firstEntry`/... return `null` in Java when the index (or restricted
//! view) has no matching value; those become `Option::None` here, matching the convention already
//! used by [`DBCachedObjectStoreMap::first_entry`](super::db_cached_object_store_map::DBCachedObjectStoreMap::first_entry).

use std::sync::Arc;

use crate::framework::db::field::Field;
use crate::framework::db::util::error_handler::ErrorHandler;
use crate::util::database::db_annotated_object::DBAnnotatedObject;
use crate::util::database::field_span::{self, FieldSpan};
use crate::util::database::directed_iterator::Direction;
use crate::util::seam_stubs::{DBCachedObjectStore, DBIndexFieldCodec};

/// An index on a field in a `DBCachedObjectStore`, mirroring `DBCachedObjectIndex<K, T>`.
pub trait DBCachedObjectIndex<K, T: DBAnnotatedObject>: Send + Sync {
    /// The store containing the indexed objects, mirroring the `store` field.
    fn store(&self) -> &dyn DBCachedObjectStore<T>;

    /// The error handler, mirroring the `errHandler` field.
    fn err_handler(&self) -> &dyn ErrorHandler;

    /// The codec for the indexed field/column, mirroring the `codec` field.
    fn codec(&self) -> &dyn DBIndexFieldCodec<K, T>;

    /// The column number, mirroring the `columnIndex` field.
    fn column_index(&self) -> i32;

    /// The restricted range this view is limited to, mirroring the `fieldSpan` field.
    fn field_span(&self) -> &dyn FieldSpan;

    /// The sort order / direction of iteration, mirroring the `direction` field.
    fn direction(&self) -> Direction;

    /// Rebuilds a view over the same store/codec/column, restricted to `field_span` and ordered
    /// by `direction`, mirroring the Java class's protected constructor as invoked by
    /// `head`/`tail`/`sub`/`descending`.
    fn restrict(
        &self,
        field_span: Box<dyn FieldSpan>,
        direction: Direction,
    ) -> Box<dyn DBCachedObjectIndex<K, T>>;

    /// Get the objects at an already-encoded field value, mirroring the private `get(Field)`.
    fn get_encoded(&self, encoded: &Field) -> Vec<Arc<T>> {
        match self.store().find_objects(self.column_index(), encoded) {
            Ok(objects) => objects,
            Err(e) => {
                self.err_handler().db_error(e);
                Vec::new()
            }
        }
    }

    /// Get the objects having the given value in the indexed field, mirroring `get(K)`.
    fn get(&self, key: &K) -> Vec<Arc<T>> {
        let encoded = self.codec().encode_field(key);
        if !self.field_span().contains(&encoded) {
            return Vec::new();
        }
        self.get_encoded(&encoded)
    }

    /// Get the objects having the given value in the indexed field, mirroring `getLazily(K)`.
    ///
    /// See the module docs: without a lazy `Iterable` to preserve the distinction, this is
    /// equivalent to [`get`](Self::get).
    fn get_lazily(&self, key: &K) -> Vec<Arc<T>> {
        self.get(key)
    }

    /// Get a unique object having the given value in the index field, mirroring `getOne(K)`.
    fn get_one(&self, key: &K) -> Option<Arc<T>> {
        let encoded = self.codec().encode_field(key);
        if !self.field_span().contains(&encoded) {
            return None;
        }
        match self.store().find_one_object(self.column_index(), &encoded) {
            Ok(obj) => obj,
            Err(e) => {
                self.err_handler().db_error(e);
                None
            }
        }
    }

    /// Iterate over the objects as ordered by the index, mirroring `values()`.
    fn values(&self) -> Vec<Arc<T>> {
        match self.store().iterate(self.column_index(), self.field_span(), self.direction()) {
            Ok(objects) => objects,
            Err(e) => {
                self.err_handler().db_error(e);
                Vec::new()
            }
        }
    }

    /// Iterate over the values of the indexed column, in order, mirroring `keys()`.
    ///
    /// Despite being called keys, the values may not be unique.
    fn keys(&self) -> Vec<K> {
        self.values().iter().map(|v| self.codec().get_value(v.as_ref())).collect()
    }

    /// Iterate over the entries as ordered by the index, mirroring `entries()`.
    fn entries(&self) -> Vec<(K, Arc<T>)> {
        self.values()
            .into_iter()
            .map(|v| {
                let key = self.codec().get_value(v.as_ref());
                (key, v)
            })
            .collect()
    }

    /// Check if this index is empty, mirroring `isEmpty()`.
    ///
    /// # Note
    /// This mirrors the Java method's body (`values().iterator().hasNext()`) exactly, which
    /// actually returns `true` when the index has at least one value and `false` when it is
    /// truly empty -- the inverse of what the name promises. Preserved bug-for-bug rather than
    /// fixed, since this is a faithful port of the existing (public) behavior.
    fn is_empty(&self) -> bool {
        !self.values().is_empty()
    }

    /// Check if there is any object having an already-encoded value for its indexed field,
    /// mirroring the private `containsKey(Field)`.
    fn contains_key_encoded(&self, encoded: &Field) -> bool {
        match self.store().has_record(encoded, self.column_index()) {
            Ok(has) => has,
            Err(e) => {
                self.err_handler().db_error(e);
                false
            }
        }
    }

    /// Check if there is any object having the given value for its indexed field, mirroring
    /// `containsKey(K)`.
    fn contains_key(&self, key: &K) -> bool {
        let encoded = self.codec().encode_field(key);
        if !self.field_span().contains(&encoded) {
            return false;
        }
        self.contains_key_encoded(&encoded)
    }

    /// Check if the given object is in the index, mirroring `containsValue(T)`.
    fn contains_value(&self, value: &Arc<T>) -> bool {
        let record = value.record();
        let field = record.get_field(self.column_index() as usize).clone();
        if !self.field_span().contains(&field) {
            return false;
        }
        self.store().contains(value)
    }

    /// Count the objects at an already-encoded field value, mirroring the private
    /// `countKey(Field)`.
    fn count_key_encoded(&self, encoded: &Field) -> i32 {
        match self.store().get_matching_record_count(encoded, self.column_index()) {
            Ok(n) => n,
            Err(e) => {
                self.err_handler().db_error(e);
                0
            }
        }
    }

    /// Count the number of objects whose indexed field has the given value, mirroring
    /// `countKey(K)`.
    fn count_key(&self, key: &K) -> i32 {
        let encoded = self.codec().encode_field(key);
        if !self.field_span().contains(&encoded) {
            return 0;
        }
        self.count_key_encoded(&encoded)
    }

    /// Get the first key in the index, mirroring `firstKey()`.
    fn first_key(&self) -> Option<K> {
        self.keys().into_iter().next()
    }

    /// Get the first object in the index, mirroring `firstValue()`.
    fn first_value(&self) -> Option<Arc<T>> {
        self.values().into_iter().next()
    }

    /// Get the first entry in the index, mirroring `firstEntry()`.
    fn first_entry(&self) -> Option<(K, Arc<T>)> {
        self.entries().into_iter().next()
    }

    /// Get the last key in the index, mirroring `lastKey()`.
    fn last_key(&self) -> Option<K> {
        self.descending().first_key()
    }

    /// Get the last object in the index, mirroring `lastValue()`.
    fn last_value(&self) -> Option<Arc<T>> {
        self.descending().first_value()
    }

    /// Get the last entry in the index, mirroring `lastEntry()`.
    fn last_entry(&self) -> Option<(K, Arc<T>)> {
        self.descending().first_entry()
    }

    /// Get the key before the given key, mirroring `lowerKey(K)`.
    fn lower_key(&self, key: &K) -> Option<K> {
        self.head(key, false).descending().first_key()
    }

    /// Get the value before the given key, mirroring `lowerValue(K)`.
    fn lower_value(&self, key: &K) -> Option<Arc<T>> {
        self.head(key, false).descending().first_value()
    }

    /// Get the entry before the given key, mirroring `lowerEntry(K)`.
    fn lower_entry(&self, key: &K) -> Option<(K, Arc<T>)> {
        self.head(key, false).descending().first_entry()
    }

    /// Get the key at or before the given key, mirroring `floorKey(K)`.
    fn floor_key(&self, key: &K) -> Option<K> {
        self.head(key, true).descending().first_key()
    }

    /// Get the value at or before the given key, mirroring `floorValue(K)`.
    fn floor_value(&self, key: &K) -> Option<Arc<T>> {
        self.head(key, true).descending().first_value()
    }

    /// Get the entry at or before the given key, mirroring `floorEntry(K)`.
    fn floor_entry(&self, key: &K) -> Option<(K, Arc<T>)> {
        self.head(key, true).descending().first_entry()
    }

    /// Get the key at or after the given key, mirroring `ceilingKey(K)`.
    fn ceiling_key(&self, key: &K) -> Option<K> {
        self.tail(key, true).first_key()
    }

    /// Get the value at or after the given key, mirroring `ceilingValue(K)`.
    fn ceiling_value(&self, key: &K) -> Option<Arc<T>> {
        self.tail(key, true).first_value()
    }

    /// Get the entry at or after the given key, mirroring `ceilingEntry(K)`.
    fn ceiling_entry(&self, key: &K) -> Option<(K, Arc<T>)> {
        self.tail(key, true).first_entry()
    }

    /// Get the key after the given key, mirroring `higherKey(K)`.
    fn higher_key(&self, key: &K) -> Option<K> {
        self.tail(key, false).first_key()
    }

    /// Get the value after the given key, mirroring `higherValue(K)`.
    fn higher_value(&self, key: &K) -> Option<Arc<T>> {
        self.tail(key, false).first_value()
    }

    /// Get the entry after the given key, mirroring `higherEntry(K)`.
    fn higher_entry(&self, key: &K) -> Option<(K, Arc<T>)> {
        self.tail(key, false).first_entry()
    }

    /// Get a sub-ranged view of this index, limited to entries whose keys occur before the given
    /// key, mirroring `head(K, boolean)`.
    fn head(&self, to: &K, to_inclusive: bool) -> Box<dyn DBCachedObjectIndex<K, T>> {
        let to_field = self.codec().encode_field(to);
        let span = field_span::head(to_field, to_inclusive, self.direction());
        let restricted = self.field_span().intersect(span.as_ref());
        self.restrict(restricted, self.direction())
    }

    /// Get a sub-ranged view of this index, limited to entries whose keys occur after the given
    /// key, mirroring `tail(K, boolean)`.
    fn tail(&self, from: &K, from_inclusive: bool) -> Box<dyn DBCachedObjectIndex<K, T>> {
        let from_field = self.codec().encode_field(from);
        let span = field_span::tail(from_field, from_inclusive, self.direction());
        let restricted = self.field_span().intersect(span.as_ref());
        self.restrict(restricted, self.direction())
    }

    /// Get a sub-ranged view of this index, mirroring `sub(K, boolean, K, boolean)`.
    fn sub(
        &self,
        from: &K,
        from_inclusive: bool,
        to: &K,
        to_inclusive: bool,
    ) -> Box<dyn DBCachedObjectIndex<K, T>> {
        let from_field = self.codec().encode_field(from);
        let to_field = self.codec().encode_field(to);
        let span = field_span::sub(from_field, from_inclusive, to_field, to_inclusive, self.direction());
        let restricted = self.field_span().intersect(span.as_ref());
        self.restrict(restricted, self.direction())
    }

    /// Get a reversed view of this index, mirroring `descending()`.
    ///
    /// This affects iteration as well as all the navigation and sub-ranging methods. Calling
    /// `descending()` on the returned view returns a view equivalent to the original.
    fn descending(&self) -> Box<dyn DBCachedObjectIndex<K, T>> {
        // `intersect(ALL)` reconstructs an equal-bounds copy of `field_span()` (or `Empty`, if
        // it already is), standing in for a `FieldSpan` clone -- there being no `clone_box`
        // method on the trait to call directly.
        let same_span = self.field_span().intersect(&field_span::all());
        self.restrict(same_span, self.direction().reverse())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::FieldType;
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::schema::Schema;
    use std::io;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct MockObject {
        key: i64,
        value: i64,
    }

    impl crate::program::database::db_object::DbObject for MockObject {
        fn state(&self) -> &crate::program::database::db_object::DbObjectState {
            unimplemented!("not exercised by this smoke test")
        }
        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl DBAnnotatedObject for MockObject {
        fn store(&self) -> &dyn crate::util::seam_stubs::DBCachedObjectStoreCore {
            unimplemented!("not exercised by this smoke test")
        }
        fn adapter(
            &self,
        ) -> &dyn crate::util::database::db_cached_domain_object_adapter::DBCachedDomainObjectAdapter
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn codecs(&self) -> &[Box<dyn crate::util::seam_stubs::DBFieldCodec>] {
            &[]
        }
        fn record(&self) -> DBRecord {
            let mut record = DBRecord::new(schema(), Field::Long(Some(self.key)));
            record.set_long(0, self.value);
            record
        }
        fn set_record(&self, _record: DBRecord) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "KEY".to_string(),
            vec![FieldType::Long],
            vec!["VALUE".to_string()],
            vec![],
        ))
    }

    /// A codec whose `K` is the object's own `value` field (column 0).
    struct ValueCodec;
    impl DBIndexFieldCodec<i64, MockObject> for ValueCodec {
        fn encode_field(&self, key: &i64) -> Field {
            Field::Long(Some(*key))
        }
        fn get_value(&self, obj: &MockObject) -> i64 {
            obj.value
        }
    }

    struct NoopErrorHandler {
        errors: Mutex<Vec<String>>,
    }
    impl ErrorHandler for NoopErrorHandler {
        fn db_error(&self, e: io::Error) {
            self.errors.lock().unwrap().push(e.to_string());
        }
    }

    /// A mock store over a `Vec<MockObject>`, proving [`DBCachedObjectIndex`] is object-safe and
    /// exercises real find/iterate/contains behavior rather than trivially-true assertions.
    struct VecStore {
        objects: Vec<MockObject>,
    }
    impl DBCachedObjectStore<MockObject> for VecStore {
        fn find_objects(&self, column_index: i32, field: &Field) -> io::Result<Vec<Arc<MockObject>>> {
            assert_eq!(column_index, 0);
            Ok(self
                .objects
                .iter()
                .filter(|o| Field::Long(Some(o.value)) == *field)
                .cloned()
                .map(Arc::new)
                .collect())
        }

        fn find_one_object(
            &self,
            column_index: i32,
            field: &Field,
        ) -> io::Result<Option<Arc<MockObject>>> {
            Ok(self.find_objects(column_index, field)?.into_iter().next())
        }

        fn iterate(
            &self,
            column_index: i32,
            field_span: &dyn FieldSpan,
            direction: Direction,
        ) -> io::Result<Vec<Arc<MockObject>>> {
            assert_eq!(column_index, 0);
            let mut objects: Vec<Arc<MockObject>> = self
                .objects
                .iter()
                .filter(|o| field_span.contains(&Field::Long(Some(o.value))))
                .cloned()
                .map(Arc::new)
                .collect();
            objects.sort_by_key(|o| o.value);
            if direction == Direction::Backward {
                objects.reverse();
            }
            Ok(objects)
        }

        fn contains(&self, value: &Arc<MockObject>) -> bool {
            self.objects.iter().any(|o| o.key == value.key)
        }

        fn has_record(&self, field: &Field, column_index: i32) -> io::Result<bool> {
            assert_eq!(column_index, 0);
            Ok(self.objects.iter().any(|o| Field::Long(Some(o.value)) == *field))
        }

        fn get_matching_record_count(&self, field: &Field, column_index: i32) -> io::Result<i32> {
            assert_eq!(column_index, 0);
            Ok(self.objects.iter().filter(|o| Field::Long(Some(o.value)) == *field).count() as i32)
        }
    }

    struct MockIndex {
        store: Arc<VecStore>,
        err_handler: Arc<NoopErrorHandler>,
        codec: Arc<ValueCodec>,
        field_span: Box<dyn FieldSpan>,
        direction: Direction,
    }

    impl DBCachedObjectIndex<i64, MockObject> for MockIndex {
        fn store(&self) -> &dyn DBCachedObjectStore<MockObject> {
            self.store.as_ref()
        }
        fn err_handler(&self) -> &dyn ErrorHandler {
            self.err_handler.as_ref()
        }
        fn codec(&self) -> &dyn DBIndexFieldCodec<i64, MockObject> {
            self.codec.as_ref()
        }
        fn column_index(&self) -> i32 {
            0
        }
        fn field_span(&self) -> &dyn FieldSpan {
            self.field_span.as_ref()
        }
        fn direction(&self) -> Direction {
            self.direction
        }
        fn restrict(
            &self,
            field_span: Box<dyn FieldSpan>,
            direction: Direction,
        ) -> Box<dyn DBCachedObjectIndex<i64, MockObject>> {
            Box::new(MockIndex {
                store: self.store.clone(),
                err_handler: self.err_handler.clone(),
                codec: self.codec.clone(),
                field_span,
                direction,
            })
        }
    }

    fn index(values: &[i64]) -> MockIndex {
        MockIndex {
            store: Arc::new(VecStore {
                objects: values
                    .iter()
                    .enumerate()
                    .map(|(i, v)| MockObject { key: i as i64, value: *v })
                    .collect(),
            }),
            err_handler: Arc::new(NoopErrorHandler { errors: Mutex::new(Vec::new()) }),
            codec: Arc::new(ValueCodec),
            field_span: Box::new(field_span::all()),
            direction: Direction::Forward,
        }
    }

    #[test]
    fn object_safe_and_gets_by_key() {
        let idx: Box<dyn DBCachedObjectIndex<i64, MockObject>> = Box::new(index(&[10, 20, 20, 30]));
        assert_eq!(idx.get(&20).len(), 2);
        assert!(idx.get(&99).is_empty());
        assert_eq!(idx.get_one(&10).map(|o| o.key), Some(0));
        assert_eq!(idx.count_key(&20), 2);
        assert!(idx.contains_key(&30));
        assert!(!idx.contains_key(&99));
    }

    #[test]
    fn values_and_keys_are_ordered_by_direction() {
        let idx = index(&[30, 10, 20]);
        assert_eq!(idx.keys(), vec![10, 20, 30]);
        assert_eq!(idx.values().iter().map(|o| o.value).collect::<Vec<_>>(), vec![10, 20, 30]);

        let descending = idx.descending();
        assert_eq!(descending.keys(), vec![30, 20, 10]);
    }

    #[test]
    fn first_and_last_reflect_direction() {
        let idx = index(&[30, 10, 20]);
        assert_eq!(idx.first_key(), Some(10));
        assert_eq!(idx.last_key(), Some(30));
        assert_eq!(idx.first_entry().map(|(k, v)| (k, v.value)), Some((10, 10)));
    }

    #[test]
    fn navigation_methods_find_neighbors() {
        let idx = index(&[10, 20, 30]);
        assert_eq!(idx.lower_key(&20), Some(10));
        assert_eq!(idx.floor_key(&20), Some(20));
        assert_eq!(idx.ceiling_key(&15), Some(20));
        assert_eq!(idx.higher_key(&20), Some(30));
        assert!(idx.lower_key(&10).is_none());
        assert!(idx.higher_key(&30).is_none());
    }

    #[test]
    fn head_tail_sub_restrict_the_view() {
        let idx = index(&[10, 20, 30, 40]);
        assert_eq!(idx.head(&30, true).keys(), vec![10, 20, 30]);
        assert_eq!(idx.head(&30, false).keys(), vec![10, 20]);
        assert_eq!(idx.tail(&20, true).keys(), vec![20, 30, 40]);
        assert_eq!(idx.tail(&20, false).keys(), vec![30, 40]);
        assert_eq!(idx.sub(&20, true, &30, true).keys(), vec![20, 30]);
    }

    #[test]
    fn descending_twice_returns_to_original_order() {
        let idx = index(&[10, 20, 30]);
        let round_trip = idx.descending().descending();
        assert_eq!(round_trip.keys(), vec![10, 20, 30]);
        assert_eq!(round_trip.direction(), Direction::Forward);
    }

    #[test]
    fn contains_value_checks_the_field_span_and_store() {
        let idx = index(&[10, 20, 30]);
        let obj = Arc::new(MockObject { key: 0, value: 10 });
        assert!(idx.contains_value(&obj));

        let restricted = idx.tail(&20, true);
        assert!(!restricted.contains_value(&obj));
        let obj20 = Arc::new(MockObject { key: 1, value: 20 });
        assert!(restricted.contains_value(&obj20));
    }

    #[test]
    fn is_empty_mirrors_the_javas_inverted_semantics() {
        let idx = index(&[10]);
        // Non-empty index -> `is_empty()` (mirroring the Java bug) returns `true`.
        assert!(idx.is_empty());
        let empty = index(&[]);
        assert!(!empty.is_empty());
    }
}
