use super::buffer::Buffer;
use super::field::{Field, FieldType};
use super::index_field::{IndexField, MAX_INDEX_FIELD_LENGTH};

/// Legacy index tables where the indexed field was a [`LongField`](crate::framework::db::LongField)
/// and improperly employed a variable-length index storage scheme even though the primary key was
/// itself a `LongField` (and therefore fixed-length).
///
/// Port of `db.LegacyIndexField`, a concrete `class LegacyIndexField extends IndexField`. Per
/// this crate's composition-over-inheritance convention, and consistent with how [`IndexField`]
/// itself was ported (an object-safe cut-point trait with no concrete base struct to extend),
/// `LegacyIndexField` owns its `indexed_field`/`primary_key`/`non_truncated_indexed_field`/
/// `is_truncated` state directly -- mirroring `IndexField`'s own private fields -- rather than
/// wrapping some shared "generic `IndexField`" concrete type (none exists in this port).
/// `primary_key` is stored as a plain [`Field`] (always the `Field::Long` variant) exactly as
/// Java's `IndexField.primaryKey` field is itself declared `Field`, not `LongField`, even though
/// every `LegacyIndexField` constructor is guaranteed to supply a `LongField` value for it.
///
/// [`Self::with_primary_key`] replays `IndexField`'s own truncation logic
/// (`IndexField(Field, Field)`) verbatim, since that logic lives only in the Java constructor
/// rather than being reachable through the ported [`IndexField`] trait.
///
/// **Faithful bug reproduction**: [`Self::is_variable_length`] unconditionally returns `true`,
/// even when the indexed field type is itself fixed-length. This mirrors a real, acknowledged
/// Ghidra bug documented directly in `LegacyIndexField.java`'s own Javadoc: *"while fixed-length
/// IndexFields are possible this past oversight failed to override this method for fixed-length
/// cases (e.g., indexing fixed-length field with long primary key). To preserve backward
/// compatibility this can not be changed for long primary keys."* Old on-disk index tables were
/// written using variable-length storage regardless of whether the indexed value was actually
/// fixed-length, so `is_variable_length` must keep answering `true` unconditionally to remain
/// compatible with that legacy on-disk format -- this is intentionally *not* "fixed" here. See
/// `test_is_variable_length_is_unconditionally_true_even_for_fixed_length_indexed_field` below.
#[derive(Debug, Clone)]
pub struct LegacyIndexField {
    primary_key: Field,
    non_truncated_indexed_field: Field,
    indexed_field: Field,
    is_truncated: bool,
}

impl LegacyIndexField {
    /// Construct a legacy index field for the given primary table field type being indexed, with
    /// a fresh (zero) `LongField` primary key. Mirrors the public `LegacyIndexField(Field)`,
    /// which forwards to `super(indexField, new LongField())` -- i.e. `IndexField`'s own
    /// truncating constructor. `LongField.newField()`/the no-arg `LongField()` constructor both
    /// produce a zero-valued (non-null) field, mirrored here by `Field::Long(Some(0))`.
    pub fn new(indexed_field: Field) -> Self {
        Self::with_primary_key(indexed_field, Field::Long(Some(0)))
    }

    /// Construct a legacy index field for the given indexed field value and primary key.
    /// Mirrors the private `LegacyIndexField(Field, LongField)` constructor, which -- like the
    /// public one -- ultimately runs through `IndexField(Field, Field)`'s truncation logic; both
    /// Java constructors share that same superclass constructor, so there is no separate
    /// "untruncated" code path to model here.
    ///
    /// `primary_key` must be a `Field::Long`; this is an internal invariant enforced by every
    /// public entry point (`new`, `new_index_field`, `copy_field`, `new_field`), not re-validated
    /// here.
    fn with_primary_key(indexed_field: Field, primary_key: Field) -> Self {
        // Mirrors `IndexField(Field indexedField, Field primaryKey)`.
        let non_truncated_indexed_field = indexed_field.clone();
        let mut truncated = indexed_field.clone();
        let mut is_truncated = false;
        if indexed_field.get_type().is_variable_length() && indexed_field.length() >= MAX_INDEX_FIELD_LENGTH
        {
            // Ensure that we do not exceed the maximum allowed index key length and conserve
            // space when indexing very long values.
            truncate_field(&mut truncated, MAX_INDEX_FIELD_LENGTH);
            is_truncated = true;
        }
        Self { primary_key, non_truncated_indexed_field, indexed_field: truncated, is_truncated }
    }
}

impl IndexField for LegacyIndexField {
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
        let (decoded_pk, pk_len) = Field::read(buf, offset + idx_len, FieldType::Long);
        self.primary_key = decoded_pk;
        offset + idx_len + pk_len
    }

    fn copy_field(&self) -> Box<dyn IndexField> {
        // Mirrors `IndexField.copyField()`: constructs a fresh instance from copies of the
        // current (possibly already-truncated) indexed field and primary key. Null state is not
        // supported, matching the Java comment on `copyField()`.
        Box::new(LegacyIndexField::with_primary_key(self.indexed_field.clone(), self.primary_key.clone()))
    }

    fn new_field(&self) -> Box<dyn IndexField> {
        Box::new(LegacyIndexField::with_primary_key(same_type_null(&self.indexed_field), Field::Long(Some(0))))
    }

    fn new_index_field(&self, index_value: Field, key: Field) -> Result<Box<dyn IndexField>, String> {
        if std::mem::discriminant(&index_value) != std::mem::discriminant(&self.indexed_field)
            || !matches!(key, Field::Long(_))
        {
            return Err("incorrect index value or key type".to_string());
        }
        Ok(Box::new(LegacyIndexField::with_primary_key(index_value, key)))
    }

    /// Always `true`. See the struct-level doc comment for the real Ghidra bug this
    /// unconditionally faithfully preserves.
    fn is_variable_length(&self) -> bool {
        true
    }
}

impl PartialEq for LegacyIndexField {
    /// Mirrors `LegacyIndexField.equals(Object)`: `(obj instanceof LegacyIndexField) &&
    /// super.equals(obj)`. `IndexField` itself declares no `equals` override of its own, so
    /// Java's `super.equals(obj)` falls through to `Field`'s base `equals`, which real Ghidra
    /// implements value-wise per concrete `Field` subtype; [`IndexField::fields_equal`] is this
    /// port's equivalent value-wise comparison (primary key plus indexed field value). The `obj
    /// instanceof LegacyIndexField` half of the Java check is inherently satisfied here since
    /// `PartialEq<LegacyIndexField>` can only ever be compared against another `LegacyIndexField`.
    fn eq(&self, other: &Self) -> bool {
        IndexField::fields_equal(self, other)
    }
}

/// Same-variant null value for `field`, standing in for the no-arg `Field.newField()` idiom (not
/// present on the ported [`Field`] enum) -- see the same helper duplicated in `sparse_record.rs`
/// and in `index_field.rs`'s own tests.
fn same_type_null(field: &Field) -> Field {
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

/// Truncate `field`'s encoded value (in place) to at most `max_len` total encoded bytes, mirroring
/// `BinaryField.truncate(int)`/`StringField.truncate(int)` for the two variable-length [`Field`]
/// variants (`String`/`Binary` -- the only ones [`FieldType::is_variable_length`] ever reports
/// `true` for, so no other variant needs a case here).
///
/// String truncation is done on the UTF-8 byte representation (matching
/// `Field.length()`/`Field.write()`'s own byte-length accounting for `Field::String`), using a
/// lossy re-decode rather than real Ghidra's raw truncated-byte write; a hard split at an
/// arbitrary byte offset can legitimately fall inside a multi-byte UTF-8 sequence, which Rust's
/// `String` cannot represent at all (unlike Java's `String`, which is UTF-16-backed and would
/// simply produce a different kind of corruption -- a split surrogate pair -- rather than fail to
/// compile). This is a deliberate simplification of an edge case that only matters for indexed
/// string values at least [`MAX_INDEX_FIELD_LENGTH`] bytes long, not a behavior this port asserts
/// byte-for-byte equivalence with.
fn truncate_field(field: &mut Field, max_len: usize) {
    match field {
        Field::Binary(Some(data)) => {
            let max_data_len = max_len.saturating_sub(4);
            if data.len() > max_data_len {
                data.truncate(max_data_len);
            }
        }
        Field::String(Some(s)) => {
            let max_data_len = max_len.saturating_sub(4);
            if s.len() > max_data_len {
                let truncated_bytes = &s.as_bytes()[..max_data_len];
                *s = String::from_utf8_lossy(truncated_bytes).into_owned();
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::DataBuffer;
    use std::cmp::Ordering;

    #[test]
    fn test_new_defaults_primary_key_to_zero_long() {
        let field = LegacyIndexField::new(Field::Int(Some(42)));
        assert_eq!(field.get_primary_key(), Field::Long(Some(0)));
        assert_eq!(field.get_indexed_field(), Field::Int(Some(42)));
        assert!(!field.uses_truncated_field_value());
    }

    #[test]
    fn test_is_variable_length_is_unconditionally_true_even_for_fixed_length_indexed_field() {
        // The indexed field here (Int) is fixed-length, yet LegacyIndexField must still report
        // variable length -- a real, intentionally-preserved Ghidra bug (see struct docs).
        let field = LegacyIndexField::new(Field::Int(Some(1)));
        assert!(!field.get_indexed_field().get_type().is_variable_length());
        assert!(field.is_variable_length());
    }

    #[test]
    fn test_short_string_is_not_truncated() {
        let field = LegacyIndexField::new(Field::String(Some("short".to_string())));
        assert!(!field.uses_truncated_field_value());
        assert_eq!(field.get_indexed_field(), Field::String(Some("short".to_string())));
        assert_eq!(field.get_non_truncated_index_field(), Field::String(Some("short".to_string())));
    }

    #[test]
    fn test_long_string_is_truncated_to_max_index_field_length() {
        let long_value = "x".repeat(100);
        let field = LegacyIndexField::new(Field::String(Some(long_value.clone())));
        assert!(field.uses_truncated_field_value());
        // Truncated value's encoded length must not exceed MAX_INDEX_FIELD_LENGTH.
        assert!(field.get_indexed_field().length() <= MAX_INDEX_FIELD_LENGTH);
        // The non-truncated accessor still returns the original, full-length value.
        assert_eq!(field.get_non_truncated_index_field(), Field::String(Some(long_value)));
    }

    #[test]
    fn test_write_read_round_trip() {
        let seed = LegacyIndexField::new(Field::Int(Some(7)));
        let field = seed.new_index_field(Field::Int(Some(7)), Field::Long(Some(99))).unwrap();

        let mut buf = DataBuffer::new(0, field.length());
        let end = field.write(&mut buf, 0);
        assert_eq!(end, field.length() as isize);

        let mut decoded: Box<dyn IndexField> = Box::new(LegacyIndexField::new(Field::Int(None)));
        let final_offset = decoded.read(&buf, 0);
        assert_eq!(final_offset, field.length());
        assert!(field.fields_equal(decoded.as_ref()));
        assert_eq!(field.compare_to(decoded.as_ref()), Ordering::Equal);
    }

    #[test]
    fn test_new_index_field_rejects_non_long_primary_key() {
        let field = LegacyIndexField::new(Field::Int(Some(1)));
        assert!(field.new_index_field(Field::Int(Some(2)), Field::Long(Some(3))).is_ok());
        assert!(field.new_index_field(Field::Int(Some(2)), Field::Int(Some(3))).is_err());
        assert!(field.new_index_field(Field::String(Some("x".to_string())), Field::Long(Some(3))).is_err());
    }

    #[test]
    fn test_equals_is_value_based() {
        let a = LegacyIndexField::new(Field::Int(Some(1)));
        let b = LegacyIndexField::new(Field::Int(Some(1)));
        let c = LegacyIndexField::new(Field::Int(Some(2)));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_copy_field_and_new_field() {
        let field: Box<dyn IndexField> = Box::new(LegacyIndexField::new(Field::Int(Some(5))));
        let copy = field.copy_field();
        assert!(field.fields_equal(copy.as_ref()));

        let fresh = field.new_field();
        assert_eq!(fresh.get_indexed_field(), Field::Int(None));
        assert_eq!(fresh.get_primary_key(), Field::Long(Some(0)));
    }

    #[test]
    fn test_set_null_is_rejected() {
        let mut field: Box<dyn IndexField> = Box::new(LegacyIndexField::new(Field::Int(Some(1))));
        assert!(!field.is_null());
        assert!(field.set_null().is_err());
    }
}
