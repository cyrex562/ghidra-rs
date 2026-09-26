use super::binary_coded_field::BinaryCodedField;
use super::binary_field::BinaryField;
use super::field::{Field, FieldType};
use super::illegal_field_access_exception::IllegalFieldAccessException;
use super::record::DBRecord;
use super::schema::Schema;
use crate::util::object_storage::ObjectStorage;

/// Provides an [`ObjectStorage`] implementation for use by `Saveable` objects, allowing them to
/// save or restore their state using a fixed set of primitives and primitive arrays. Data access
/// is also provided for storing/retrieving data via a [`DBRecord`] using a suitable [`Schema`].
///
/// Port of `db.ObjectStorageAdapterDB`. Java stores each value as a boxed `Field` subclass
/// instance (`IntField`, `BinaryCodedField`, etc) inside `fieldList`; this port instead stores
/// the plain [`Field`] enum directly, matching how this crate's [`DBRecord`]/[`Schema`] already
/// use `Field` as the primary storage currency (see e.g. `table_record.rs`), rather than the
/// separate `ByteField`/`IntField`/... object-safe trait cut-points which model a different,
/// legacy-compatibility axis of the real class hierarchy. Values with no direct `Field` variant
/// (`float`, `double`, and every array type) are encoded via [`BinaryCodedField`] and stored as
/// `Field::Binary`, exactly mirroring how Java's own `putFloat`/`putDouble`/`putXxxs` methods
/// store a `BinaryCodedField` (itself a `BinaryField` subclass) instead of a dedicated `Field`
/// type.
pub struct ObjectStorageAdapterDB {
    field_list: Vec<Field>,
    col: usize,
    read_only: bool,
}

impl ObjectStorageAdapterDB {
    /// Construct an empty writable storage adapter. Mirrors `ObjectStorageAdapterDB()`.
    pub fn new() -> Self {
        Self { field_list: Vec::new(), col: 0, read_only: false }
    }

    /// Construct a read-only storage adapter from an existing record. Mirrors
    /// `ObjectStorageAdapterDB(DBRecord)`.
    pub fn from_record(rec: &DBRecord) -> Self {
        let mut field_list = Vec::with_capacity(rec.get_field_count());
        for i in 0..rec.get_field_count() {
            field_list.push(rec.get_field(i).clone());
        }
        Self { field_list, col: 0, read_only: true }
    }

    /// Mirrors the `if (readOnly) throw new IllegalStateException();` guard present at the top of
    /// every `putXxx` method. Java's `IllegalStateException` is unchecked and every `ObjectStorage`
    /// `put_*` method in this port has no `Result` in its signature (see `util::object_storage`),
    /// so this port panics in its place -- the same unchecked-exception-to-panic convention
    /// already used throughout this crate (e.g. `AssertException`).
    fn check_writable(&self) {
        if self.read_only {
            panic!("ObjectStorageAdapterDB: illegal attempt to write to a read-only instance");
        }
    }

    /// Consume and return the next stored field, mirroring `fieldList.get(col++)`. Panics with
    /// [`IllegalFieldAccessException`] if no field remains, mirroring Java's
    /// `catch (IndexOutOfBoundsException e) { throw new IllegalFieldAccessException(); }` -- again
    /// translated to a panic rather than a `Result`, since every `ObjectStorage` `get_*` method
    /// has no `Result` in its signature.
    fn next_field(&mut self) -> Field {
        let idx = self.col;
        self.col += 1;
        match self.field_list.get(idx) {
            Some(f) => f.clone(),
            None => panic!("{}", IllegalFieldAccessException::new()),
        }
    }

    fn push_coded(&mut self, coded: &BinaryCodedField) {
        self.field_list.push(Field::Binary(coded.get_binary_data().map(|d| d.to_vec())));
    }

    fn next_coded(&mut self) -> BinaryCodedField {
        let field = self.next_field();
        BinaryCodedField::from_raw_data(field.get_binary_data().map(|d| d.to_vec()))
    }

    /// Get the [`Schema`] associated with the stored data. Mirrors
    /// `ObjectStorageAdapterDB.getSchema(int)`, which builds a `Schema(version, "key", fields,
    /// fieldNames)` -- the three-arg-plus-version `Field[]`-based constructor that always uses a
    /// `LongField` key (see `db.Schema`'s own `Schema(int, String, Field[], String[])`
    /// constructor, which delegates to `LongField.INSTANCE`). This port's [`Schema`] models column
    /// types as bare [`FieldType`] rather than boxed `Field` instances, so `fieldList.get(i).newField()`
    /// (a representative, default-valued instance of the same type) becomes `fieldList[i].get_type()`.
    pub fn get_schema(&self, version: i32) -> Schema {
        let fields: Vec<FieldType> = self.field_list.iter().map(|f| f.get_type()).collect();
        let field_names: Vec<String> = (0..fields.len()).map(|i| i.to_string()).collect();
        Schema::new(version, FieldType::Long, "key".to_string(), fields, field_names, vec![])
    }

    /// Save data into a Record. Mirrors `ObjectStorageAdapterDB.save(DBRecord)`.
    pub fn save(&self, rec: &mut DBRecord) {
        for (i, f) in self.field_list.iter().enumerate() {
            rec.set_field(i, f.clone());
        }
    }
}

impl Default for ObjectStorageAdapterDB {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStorage for ObjectStorageAdapterDB {
    fn put_int(&mut self, value: i32) {
        self.check_writable();
        self.field_list.push(Field::Int(Some(value)));
    }

    fn put_byte(&mut self, value: i8) {
        self.check_writable();
        self.field_list.push(Field::Byte(Some(value)));
    }

    fn put_short(&mut self, value: i16) {
        self.check_writable();
        self.field_list.push(Field::Short(Some(value)));
    }

    fn put_long(&mut self, value: i64) {
        self.check_writable();
        self.field_list.push(Field::Long(Some(value)));
    }

    fn put_string(&mut self, value: &str) {
        self.check_writable();
        self.field_list.push(Field::String(Some(value.to_string())));
    }

    fn put_boolean(&mut self, value: bool) {
        self.check_writable();
        self.field_list.push(Field::Boolean(Some(value)));
    }

    fn put_float(&mut self, value: f32) {
        self.check_writable();
        let coded = BinaryCodedField::from_float(value);
        self.push_coded(&coded);
    }

    fn put_double(&mut self, value: f64) {
        self.check_writable();
        let coded = BinaryCodedField::from_double(value);
        self.push_coded(&coded);
    }

    fn get_int(&mut self) -> i32 {
        self.next_field().get_int_value()
    }

    fn get_byte(&mut self) -> i8 {
        self.next_field().get_byte_value()
    }

    fn get_short(&mut self) -> i16 {
        self.next_field().get_short_value()
    }

    fn get_long(&mut self) -> i64 {
        self.next_field().get_long_value()
    }

    fn get_boolean(&mut self) -> bool {
        self.next_field().get_boolean_value()
    }

    fn get_string(&mut self) -> String {
        self.next_field().get_string_value().unwrap_or("").to_string()
    }

    fn get_float(&mut self) -> f32 {
        self.next_coded().get_float_value().unwrap_or_else(|e| panic!("{}", e))
    }

    fn get_double(&mut self) -> f64 {
        self.next_coded().get_double_value().unwrap_or_else(|e| panic!("{}", e))
    }

    fn put_ints(&mut self, value: &[i32]) {
        self.check_writable();
        let coded = BinaryCodedField::from_int_array(Some(value));
        self.push_coded(&coded);
    }

    fn put_bytes(&mut self, value: &[i8]) {
        self.check_writable();
        let bytes: Vec<u8> = value.iter().map(|&b| b as u8).collect();
        let coded = BinaryCodedField::from_byte_array(Some(&bytes));
        self.push_coded(&coded);
    }

    fn put_shorts(&mut self, value: &[i16]) {
        self.check_writable();
        let coded = BinaryCodedField::from_short_array(Some(value));
        self.push_coded(&coded);
    }

    fn put_longs(&mut self, value: &[i64]) {
        self.check_writable();
        let coded = BinaryCodedField::from_long_array(Some(value));
        self.push_coded(&coded);
    }

    fn put_floats(&mut self, value: &[f32]) {
        self.check_writable();
        let coded = BinaryCodedField::from_float_array(Some(value));
        self.push_coded(&coded);
    }

    fn put_doubles(&mut self, value: &[f64]) {
        self.check_writable();
        let coded = BinaryCodedField::from_double_array(Some(value));
        self.push_coded(&coded);
    }

    fn put_strings(&mut self, value: &[&str]) {
        self.check_writable();
        let strings: Vec<Option<String>> = value.iter().map(|s| Some(s.to_string())).collect();
        let coded = BinaryCodedField::from_string_array(Some(&strings));
        self.push_coded(&coded);
    }

    fn get_ints(&mut self) -> Vec<i32> {
        self.next_coded().get_int_array().unwrap_or_else(|e| panic!("{}", e)).unwrap_or_default()
    }

    fn get_bytes(&mut self) -> Vec<i8> {
        self.next_coded()
            .get_byte_array()
            .unwrap_or_else(|e| panic!("{}", e))
            .unwrap_or_default()
            .iter()
            .map(|&b| b as i8)
            .collect()
    }

    fn get_shorts(&mut self) -> Vec<i16> {
        self.next_coded().get_short_array().unwrap_or_else(|e| panic!("{}", e)).unwrap_or_default()
    }

    fn get_longs(&mut self) -> Vec<i64> {
        self.next_coded().get_long_array().unwrap_or_else(|e| panic!("{}", e)).unwrap_or_default()
    }

    fn get_floats(&mut self) -> Vec<f32> {
        self.next_coded().get_float_array().unwrap_or_else(|e| panic!("{}", e)).unwrap_or_default()
    }

    fn get_doubles(&mut self) -> Vec<f64> {
        self.next_coded().get_double_array().unwrap_or_else(|e| panic!("{}", e)).unwrap_or_default()
    }

    fn get_strings(&mut self) -> Vec<String> {
        self.next_coded()
            .get_string_array()
            .unwrap_or_else(|e| panic!("{}", e))
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.unwrap_or_default())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_scalar_round_trip_in_write_order() {
        let mut s = ObjectStorageAdapterDB::new();
        s.put_int(42);
        s.put_byte(-1);
        s.put_short(1000);
        s.put_long(i64::MAX);
        s.put_string("hello");
        s.put_boolean(true);
        s.put_float(1.5);
        s.put_double(3.25);

        assert_eq!(s.get_int(), 42);
        assert_eq!(s.get_byte(), -1);
        assert_eq!(s.get_short(), 1000);
        assert_eq!(s.get_long(), i64::MAX);
        assert_eq!(s.get_string(), "hello");
        assert!(s.get_boolean());
        assert_eq!(s.get_float(), 1.5_f32);
        assert_eq!(s.get_double(), 3.25_f64);
    }

    #[test]
    fn test_array_round_trip() {
        let mut s = ObjectStorageAdapterDB::new();
        s.put_ints(&[1, 2, 3]);
        s.put_bytes(&[-128, 0, 127]);
        s.put_shorts(&[100, 200]);
        s.put_longs(&[i64::MIN, i64::MAX]);
        s.put_floats(&[0.5, -0.5]);
        s.put_doubles(&[1.25, -1.25]);
        s.put_strings(&["foo", "bar"]);

        assert_eq!(s.get_ints(), vec![1, 2, 3]);
        assert_eq!(s.get_bytes(), vec![-128i8, 0, 127]);
        assert_eq!(s.get_shorts(), vec![100i16, 200]);
        assert_eq!(s.get_longs(), vec![i64::MIN, i64::MAX]);
        assert_eq!(s.get_floats(), vec![0.5f32, -0.5]);
        assert_eq!(s.get_doubles(), vec![1.25f64, -1.25]);
        assert_eq!(s.get_strings(), vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn test_get_schema_reflects_stored_field_types_and_uses_long_key() {
        let mut s = ObjectStorageAdapterDB::new();
        s.put_int(1);
        s.put_string("x");
        s.put_boolean(false);

        let schema = s.get_schema(7);
        assert_eq!(schema.get_version(), 7);
        assert_eq!(schema.get_key_type(), FieldType::Long);
        assert_eq!(schema.get_key_name(), "key");
        assert_eq!(schema.get_field_count(), 3);
        assert_eq!(schema.get_field_type(0), FieldType::Int);
        assert_eq!(schema.get_field_type(1), FieldType::String);
        assert_eq!(schema.get_field_type(2), FieldType::Boolean);
        assert_eq!(schema.get_field_name(0), "0");
        assert_eq!(schema.get_field_name(2), "2");
    }

    #[test]
    fn test_save_writes_fields_into_record_in_order() {
        let mut s = ObjectStorageAdapterDB::new();
        s.put_int(5);
        s.put_string("abc");

        let schema = Arc::new(s.get_schema(1));
        let mut rec = DBRecord::new(schema, Field::Long(Some(1)));
        s.save(&mut rec);

        assert_eq!(rec.get_field(0).get_int_value(), 5);
        assert_eq!(rec.get_field(1).get_string_value(), Some("abc"));
    }

    #[test]
    fn test_from_record_is_read_only_and_matches_stored_values() {
        let schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "key".to_string(),
            vec![FieldType::Int, FieldType::String],
            vec!["0".to_string(), "1".to_string()],
            vec![],
        ));
        let mut rec = DBRecord::new(schema, Field::Long(Some(1)));
        rec.set_field(0, Field::Int(Some(9)));
        rec.set_field(1, Field::String(Some("y".to_string())));

        let mut s = ObjectStorageAdapterDB::from_record(&rec);
        assert_eq!(s.get_int(), 9);
        assert_eq!(s.get_string(), "y");
    }

    #[test]
    #[should_panic(expected = "read-only")]
    fn test_writing_to_read_only_instance_panics() {
        let schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "key".to_string(),
            vec![FieldType::Int],
            vec!["0".to_string()],
            vec![],
        ));
        let rec = DBRecord::new(schema, Field::Long(Some(1)));
        let mut s = ObjectStorageAdapterDB::from_record(&rec);
        s.put_int(1);
    }

    #[test]
    #[should_panic(expected = "Illegal field access")]
    fn test_reading_past_end_panics_with_illegal_field_access() {
        let mut s = ObjectStorageAdapterDB::new();
        s.put_int(1);
        let _ = s.get_int();
        let _ = s.get_int(); // nothing left
    }

    #[test]
    fn test_trait_object_usage() {
        let mut s: Box<dyn ObjectStorage> = Box::new(ObjectStorageAdapterDB::new());
        s.put_boolean(true);
        assert!(s.get_boolean());
    }

    #[test]
    fn test_null_array_decodes_to_empty_vec_documented_gap() {
        // `ObjectStorage::get_ints` (the shared, already-established trait this type implements)
        // returns a bare `Vec<i32>`, not an `Option`, so a stored *null* array (Java's `int[]`
        // permits `null`) has no way to round-trip through this port's `get_ints` -- it decodes as
        // an empty vec instead. This is a pre-existing shape constraint of the shared
        // `ObjectStorage` trait (see `util/object_storage.rs`), not something introduced here.
        let coded = BinaryCodedField::from_int_array(None);
        assert_eq!(coded.get_int_array().unwrap(), None);
    }
}
