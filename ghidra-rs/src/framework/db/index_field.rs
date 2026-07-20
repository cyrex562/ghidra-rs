use super::buffer::{Buffer, DataBuffer};
use super::field::Field;
use super::illegal_field_access_exception::IllegalFieldAccessException;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Maximum length, in bytes, allowed for an indexed field value before it is truncated.
///
/// Mirrors `db.IndexField.MAX_INDEX_FIELD_LENGTH`.
pub const MAX_INDEX_FIELD_LENGTH: usize = 64;

/// An index table primary key [`Field`] wrapper which combines an indexed field value (fixed or
/// variable length) with its corresponding primary key (fixed length only).
///
/// Port of `db.IndexField`. `IndexField` was a concrete `Field` subclass in Java; it is ported
/// here as an object-safe trait (a cycle cut-point) so that dependents can hold
/// `Box<dyn IndexField>` / `&dyn IndexField` instead of a concrete type. Implementors own the
/// underlying `indexedField` / `primaryKey` [`Field`] values and are responsible for their own
/// construction (mirroring the Java constructor's validation/truncation behavior).
pub trait IndexField {
    /// Get the indexed field value. If the original value exceeded [`MAX_INDEX_FIELD_LENGTH`] in
    /// length the returned value will be truncated.
    fn get_indexed_field(&self) -> Field;

    /// Get the non-truncated index field value.
    ///
    /// Deprecated in the Java source: this method serves no real purpose since the non-truncated
    /// indexed field value is not retained within the index table.
    fn get_non_truncated_index_field(&self) -> Field;

    /// Determine if the index field value has been truncated from its original value.
    ///
    /// Deprecated in the Java source: this method serves no real purpose since the truncation
    /// status is not retained within the index table.
    fn uses_truncated_field_value(&self) -> bool;

    /// Get the primary key value.
    fn get_primary_key(&self) -> Field;

    /// Read the index field and primary key starting at `offset`, replacing this instance's
    /// values. Returns the offset immediately following the primary key.
    fn read(&mut self, buf: &dyn Buffer, offset: usize) -> usize;

    /// Construct a copy of this index field, detached from any underlying buffer.
    fn copy_field(&self) -> Box<dyn IndexField>;

    /// Construct a new, empty index field of the same indexed-value/primary-key types as this
    /// instance.
    fn new_field(&self) -> Box<dyn IndexField>;

    /// Construct a new [`IndexField`] instance for the given index value and associated primary
    /// key. `index_value` and `key` are verified against this instance's types.
    ///
    /// Returns `Err` if `index_value` or `key` is not the same type as this instance's indexed
    /// field / primary key (stands in for `IllegalArgumentException`).
    fn new_index_field(&self, index_value: Field, key: Field) -> Result<Box<dyn IndexField>, String>;

    /// Always returns `false`: not applicable to an index field.
    fn is_null(&self) -> bool {
        false
    }

    /// Always returns `Err`: an index field may not be set null.
    fn set_null(&mut self) -> Result<(), IllegalFieldAccessException> {
        Err(IllegalFieldAccessException::with_message("Index field may not be set null"))
    }

    /// Combined length, in bytes, of the indexed field value and primary key.
    fn length(&self) -> usize {
        self.get_indexed_field().length() + self.get_primary_key().length()
    }

    /// Write the indexed field value followed by the primary key into `buf` starting at
    /// `offset`. Returns the offset immediately following the primary key, or -1 if the buffer is
    /// full.
    fn write(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        let off = self.get_indexed_field().write(buf, offset);
        if off < 0 {
            return off;
        }
        self.get_primary_key().write(buf, off as usize)
    }

    /// Length, in bytes, of the encoded indexed field value plus primary key at `offset` within
    /// `buf`, without altering this instance.
    fn read_length(&self, buf: &dyn Buffer, offset: usize) -> usize {
        let idx_type = self.get_indexed_field().get_type();
        let (_decoded, idx_len) = Field::read(buf, offset, idx_type);
        idx_len + self.get_primary_key().length()
    }

    /// Whether the indexed field value is variable length.
    fn is_variable_length(&self) -> bool {
        self.get_indexed_field().get_type().is_variable_length()
    }

    /// Always `None`: mirrors `IndexField.getMinValue()`, which unconditionally throws
    /// `UnsupportedOperationException` in Java.
    fn get_min_value(&self) -> Option<Box<dyn IndexField>> {
        None
    }

    /// Always `None`: mirrors `IndexField.getMaxValue()`, which unconditionally throws
    /// `UnsupportedOperationException` in Java.
    fn get_max_value(&self) -> Option<Box<dyn IndexField>> {
        None
    }

    /// Encoded field type byte: primary key field type in the high nibble, indexed field type in
    /// the low nibble (mirrors `IndexField.getIndexFieldType`).
    fn get_field_type(&self) -> u8 {
        const INDEX_FIELD_TYPE_SHIFT: u32 = 4;
        let idx_byte = self.get_indexed_field().get_type().to_byte();
        let pk_byte = self.get_primary_key().get_type().to_byte();
        (pk_byte << INDEX_FIELD_TYPE_SHIFT) | idx_byte
    }

    /// Display form: `"<indexedField>/<primaryKey>"`, mirroring `IndexField.toString()`.
    fn to_display_string(&self) -> String {
        format!("{:?}/{:?}", self.get_indexed_field(), self.get_primary_key())
    }

    /// Human-readable value form, mirroring `IndexField.getValueAsString()`.
    fn get_value_as_string(&self) -> String {
        format!("{:?} / {:?}", self.get_indexed_field(), self.get_primary_key())
    }

    /// Whether `other` has the same indexed field value as this instance.
    fn has_same_index_value(&self, other: &dyn IndexField) -> bool {
        self.get_indexed_field() == other.get_indexed_field()
    }

    /// Whether `other` is the same indexed-value/primary-key type combination as this instance.
    fn is_same_type(&self, other: &dyn IndexField) -> bool {
        std::mem::discriminant(&self.get_indexed_field())
            == std::mem::discriminant(&other.get_indexed_field())
            && std::mem::discriminant(&self.get_primary_key())
                == std::mem::discriminant(&other.get_primary_key())
    }

    /// Whether `other` has the same indexed field value and primary key as this instance.
    fn fields_equal(&self, other: &dyn IndexField) -> bool {
        self.get_primary_key() == other.get_primary_key()
            && self.get_indexed_field() == other.get_indexed_field()
    }

    /// Deterministic hash over the indexed field value and primary key.
    fn field_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        format!("{:?}", self.get_indexed_field()).hash(&mut hasher);
        format!("{:?}", self.get_primary_key()).hash(&mut hasher);
        hasher.finish()
    }

    /// Serialize the indexed field value followed by the primary key to a flat byte array.
    fn get_binary_data(&self) -> Vec<u8> {
        let mut buf = DataBuffer::new(0, self.length());
        self.write(&mut buf, 0);
        buf.get_data().to_vec()
    }

    /// Populate this instance's indexed field value and primary key by decoding `bytes`.
    ///
    /// Returns `Err` if this instance is variable length, or if `bytes.len()` does not match
    /// [`IndexField::length`].
    fn set_binary_data(&mut self, bytes: &[u8]) -> Result<(), IllegalFieldAccessException> {
        if self.is_variable_length() {
            return Err(IllegalFieldAccessException::with_message(
                "Unsupported for variable length IndexField",
            ));
        }
        if bytes.len() != self.length() {
            return Err(IllegalFieldAccessException::new());
        }
        let buf = DataBuffer::from_data(0, bytes.to_vec());
        self.read(&buf, 0);
        Ok(())
    }

    /// Compare this instance to `other`: indexed field value first, primary key as a tiebreaker.
    fn compare_to(&self, other: &dyn IndexField) -> Ordering {
        let result = self.get_indexed_field().cmp(&other.get_indexed_field());
        if result != Ordering::Equal {
            return result;
        }
        self.get_primary_key().cmp(&other.get_primary_key())
    }

    /// Compare this instance to the indexed field value / primary key encoded in `buffer` at
    /// `offset`, without decoding a full [`IndexField`].
    fn compare_to_buffer(&self, buffer: &dyn Buffer, offset: usize) -> Ordering {
        let idx_type = self.get_indexed_field().get_type();
        let (decoded_idx, idx_len) = Field::read(buffer, offset, idx_type);
        let result = self.get_indexed_field().cmp(&decoded_idx);
        if result != Ordering::Equal {
            return result;
        }
        let pk_type = self.get_primary_key().get_type();
        let (decoded_pk, _) = Field::read(buffer, offset + idx_len, pk_type);
        self.get_primary_key().cmp(&decoded_pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same-variant null value for `field`, standing in for `Field.newField()` (not present on
    /// the ported `Field` enum).
    fn null_like(field: &Field) -> Field {
        match field {
            Field::Byte(_) => Field::Byte(None),
            Field::Short(_) => Field::Short(None),
            Field::Int(_) => Field::Int(None),
            Field::Long(_) => Field::Long(None),
            Field::String(_) => Field::String(None),
            Field::Binary(_) => Field::Binary(None),
            Field::Boolean(_) => Field::Boolean(None),
            Field::Fixed(_) => Field::Fixed(None),
        }
    }

    struct MockIndexField {
        primary_key: Field,
        non_truncated_indexed_field: Field,
        indexed_field: Field,
        is_truncated: bool,
    }

    impl MockIndexField {
        fn new(indexed_field: Field, primary_key: Field) -> Self {
            assert!(!primary_key.get_type().is_variable_length(), "variable length primaryKey not supported");
            Self {
                primary_key,
                non_truncated_indexed_field: indexed_field.clone(),
                indexed_field,
                is_truncated: false,
            }
        }
    }

    impl IndexField for MockIndexField {
        fn get_indexed_field(&self) -> Field {
            self.indexed_field.clone()
        }

        fn get_non_truncated_index_field(&self) -> Field {
            self.non_truncated_indexed_field.clone()
        }

        fn uses_truncated_field_value(&self) -> bool {
            self.is_truncated
        }

        fn get_primary_key(&self) -> Field {
            self.primary_key.clone()
        }

        fn read(&mut self, buf: &dyn Buffer, offset: usize) -> usize {
            let idx_type = self.indexed_field.get_type();
            let (decoded_idx, idx_len) = Field::read(buf, offset, idx_type);
            self.indexed_field = decoded_idx.clone();
            self.non_truncated_indexed_field = decoded_idx;
            let pk_type = self.primary_key.get_type();
            let (decoded_pk, _) = Field::read(buf, offset + idx_len, pk_type);
            self.primary_key = decoded_pk;
            offset + idx_len + self.primary_key.length()
        }

        fn copy_field(&self) -> Box<dyn IndexField> {
            Box::new(MockIndexField::new(self.indexed_field.clone(), self.primary_key.clone()))
        }

        fn new_field(&self) -> Box<dyn IndexField> {
            Box::new(MockIndexField::new(null_like(&self.indexed_field), null_like(&self.primary_key)))
        }

        fn new_index_field(
            &self,
            index_value: Field,
            key: Field,
        ) -> Result<Box<dyn IndexField>, String> {
            if std::mem::discriminant(&index_value) != std::mem::discriminant(&self.indexed_field)
                || std::mem::discriminant(&key) != std::mem::discriminant(&self.primary_key)
            {
                return Err("incorrect index value or key type".to_string());
            }
            Ok(Box::new(MockIndexField::new(index_value, key)))
        }
    }

    #[test]
    fn test_object_safety_and_write_read_round_trip() {
        let field: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(42)), Field::Long(Some(7))));
        assert_eq!(field.length(), 4 + 8);

        let mut buf = DataBuffer::new(0, field.length());
        let end = field.write(&mut buf, 0);
        assert_eq!(end, field.length() as isize);

        let mut decoded: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(None), Field::Long(None)));
        let final_offset = decoded.read(&buf, 0);
        assert_eq!(final_offset, field.length());
        assert!(field.fields_equal(decoded.as_ref()));
        assert_eq!(field.compare_to(decoded.as_ref()), Ordering::Equal);
    }

    #[test]
    fn test_compare_to_orders_by_indexed_value_then_primary_key() {
        let low: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(1)), Field::Long(Some(99))));
        let high: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(2)), Field::Long(Some(0))));
        assert_eq!(low.compare_to(high.as_ref()), Ordering::Less);
        assert_eq!(high.compare_to(low.as_ref()), Ordering::Greater);

        let same_index_low_key: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(1)), Field::Long(Some(0))));
        assert_eq!(low.compare_to(same_index_low_key.as_ref()), Ordering::Greater);
    }

    #[test]
    fn test_binary_data_round_trip() {
        let original: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(1234)), Field::Long(Some(-99))));
        let bytes = original.get_binary_data();
        assert_eq!(bytes.len(), original.length());

        let mut restored: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(None), Field::Long(None)));
        restored.set_binary_data(&bytes).unwrap();
        assert!(original.fields_equal(restored.as_ref()));
        assert_eq!(original.field_hash(), restored.field_hash());
    }

    #[test]
    fn test_null_semantics() {
        let mut field: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(1)), Field::Long(Some(2))));
        assert!(!field.is_null());
        assert!(field.set_null().is_err());
    }

    #[test]
    fn test_has_same_index_value_and_is_same_type() {
        let a: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(5)), Field::Long(Some(1))));
        let b: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(5)), Field::Long(Some(2))));
        let c: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(6)), Field::Long(Some(1))));

        assert!(a.has_same_index_value(b.as_ref()));
        assert!(!a.has_same_index_value(c.as_ref()));
        assert!(a.is_same_type(b.as_ref()));
    }

    #[test]
    fn test_new_index_field_rejects_type_mismatch() {
        let field: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(1)), Field::Long(Some(2))));
        assert!(field.new_index_field(Field::Int(Some(9)), Field::Long(Some(3))).is_ok());
        assert!(field.new_index_field(Field::String(Some("x".to_string())), Field::Long(Some(3))).is_err());
    }

    #[test]
    fn test_copy_field_and_new_field() {
        let field: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(3)), Field::Long(Some(4))));
        let copy = field.copy_field();
        assert!(field.fields_equal(copy.as_ref()));

        let fresh = field.new_field();
        assert_eq!(fresh.get_indexed_field(), Field::Int(None));
        assert_eq!(fresh.get_primary_key(), Field::Long(None));
    }

    #[test]
    fn test_field_type_and_display() {
        let field: Box<dyn IndexField> =
            Box::new(MockIndexField::new(Field::Int(Some(1)), Field::Long(Some(2))));
        assert!(!field.is_variable_length());
        assert!(!field.to_display_string().is_empty());
        assert!(!field.get_value_as_string().is_empty());
        // Long type byte (3) in high nibble, Int type byte (2) in low nibble.
        assert_eq!(field.get_field_type(), (3u8 << 4) | 2u8);
    }
}
