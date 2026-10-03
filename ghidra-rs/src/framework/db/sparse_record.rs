use std::sync::Arc;

use super::buffer::Buffer;
use super::field::Field;
use super::record::DBRecord;
use super::schema::Schema;

/// A [`DBRecord`] which supports a schema with one or more sparse columns.
///
/// Port of `db.SparseRecord`, which `extends DBRecord`. Per this crate's composition-over-
/// inheritance convention, `SparseRecord` does not try to inherit from [`DBRecord`]; it wraps one
/// (plus its own `Arc<Schema>`, since `DBRecord` does not expose its schema through a public
/// accessor) and overrides `write`/`read`/`compute_length` with sparse-aware bodies, mirroring the
/// Java overrides exactly.
///
/// A sparse column costs no storage space at all when its value is unset (`null`): non-sparse
/// fields are written densely in column order exactly as `DBRecord.write` already does, followed
/// by a single byte giving the count of *non-null* sparse fields, followed by one
/// `(column-index byte, field value)` pair per non-null sparse field. `read` mirrors this
/// layout, defaulting every sparse column back to null before selectively overwriting the ones
/// named by the trailing pairs.
///
/// One behavioral note: real Ghidra's `DBRecord.length()` is `final` and caches its result in a
/// `length` field (recomputed lazily whenever invalidated, e.g. by `SparseRecord.setXxxValue`
/// calling `invalidateLength()` after a sparse column's null/non-null state changes -- the only
/// case where a fixed-width column's encoded length can actually change). This port's
/// [`DBRecord::length`] has no such cache -- it always recomputes fully from the current field
/// values -- so there is no cache to invalidate and [`SparseRecord::compute_length`] is always
/// safe to call directly; the `setXxxValue`-triggered invalidation dance has no Rust-side
/// counterpart to port.
#[derive(Clone, Debug)]
pub struct SparseRecord {
    schema: Arc<Schema>,
    inner: DBRecord,
}

impl SparseRecord {
    /// Construct a new sparse record with the given key. Every sparse column starts out null;
    /// every non-sparse column starts out at its type's zero-ish default, exactly as
    /// [`DBRecord::new`] already initializes it.
    pub fn new(schema: Arc<Schema>, key: Field) -> Self {
        Self { inner: DBRecord::new(schema.clone(), key), schema }
    }

    pub fn get_key(&self) -> &Field {
        self.inner.get_key()
    }

    pub fn set_key(&mut self, key: Field) {
        self.inner.set_key(key);
    }

    pub fn get_field(&self, index: usize) -> &Field {
        self.inner.get_field(index)
    }

    /// Set the field at `index`.
    ///
    /// Mirrors `SparseRecord.setField(int, Field)`: a `None`/null `value` is only meaningful for
    /// a sparse column (setting a non-sparse column null is rejected, mirroring Java's
    /// `IllegalArgumentException`); passing `None` for a sparse column fills in a same-typed null
    /// field via [`Field::same_type_null`].
    pub fn set_field(&mut self, index: usize, value: Option<Field>) -> Result<(), String> {
        let value = match value {
            Some(v) => v,
            None => {
                if !self.schema.is_sparse_column(index) {
                    return Err("null value supported for sparse column only".to_string());
                }
                same_type_null(self.inner.get_field(index))
            }
        };
        self.inner.set_field(index, value);
        Ok(())
    }

    pub fn get_field_count(&self) -> usize {
        self.inner.get_field_count()
    }

    pub fn is_dirty(&self) -> bool {
        self.inner.is_dirty()
    }

    pub fn set_dirty(&mut self, dirty: bool) {
        self.inner.set_dirty(dirty)
    }

    /// Compute this record's sparse-aware stored length: densely-written non-sparse fields, plus
    /// one length-prefix byte, plus `(index byte + field length)` for every non-null sparse
    /// field. Mirrors `SparseRecord.computeLength()`.
    pub fn compute_length(&self) -> usize {
        let mut len = 1; // sparse field count is always written as a byte after non-sparse fields
        for i in 0..self.schema.get_field_count() {
            let f = self.inner.get_field(i);
            if self.schema.is_sparse_column(i) {
                if !f.is_null() {
                    // a present sparse field is prefixed by a byte naming its column index
                    len += f.length() + 1;
                }
            } else {
                len += f.length();
            }
        }
        len
    }

    /// Alias for [`Self::compute_length`]: unlike Java's cached `final DBRecord.length()`, there
    /// is no separate cached-vs-computed distinction to preserve here (see the module docs).
    pub fn length(&self) -> usize {
        self.compute_length()
    }

    /// Write this record's fields to `buf` starting at `offset`, in `SparseRecord`'s sparse-aware
    /// format. Mirrors `SparseRecord.write(Buffer, int)`.
    pub fn write(&mut self, buf: &mut dyn Buffer, offset: usize) -> usize {
        let mut sparse_field_indexes = Vec::new();
        let mut off = offset;
        for i in 0..self.schema.get_field_count() {
            if self.schema.is_sparse_column(i) {
                if !self.inner.get_field(i).is_null() {
                    sparse_field_indexes.push(i);
                }
            } else {
                let next = self.inner.get_field(i).write(buf, off);
                assert!(next >= 0, "buffer overflow writing record");
                off = next as usize;
            }
        }

        // write sparse field count
        let next = buf.put_byte(off, sparse_field_indexes.len() as u8);
        assert!(next >= 0, "buffer overflow writing record");
        off = next as usize;

        // write each non-null sparse field, prefixed by its column index
        for i in sparse_field_indexes {
            let next = buf.put_byte(off, i as u8);
            assert!(next >= 0, "buffer overflow writing record");
            off = next as usize;
            let next = self.inner.get_field(i).write(buf, off);
            assert!(next >= 0, "buffer overflow writing record");
            off = next as usize;
        }

        self.inner.set_dirty(false);
        off
    }

    /// Read this record's fields from `buf` starting at `offset`, in `SparseRecord`'s sparse-aware
    /// format, replacing this instance's current field values. Mirrors `SparseRecord.read(Buffer,
    /// int)`.
    pub fn read(&mut self, buf: &dyn Buffer, offset: usize) -> usize {
        let mut off = offset;
        for i in 0..self.schema.get_field_count() {
            if self.schema.is_sparse_column(i) {
                let null_field = same_type_null(self.inner.get_field(i));
                self.inner.set_field(i, null_field);
            } else {
                let (f, len) = Field::read(buf, off, self.schema.get_field_type(i));
                self.inner.set_field(i, f);
                off += len;
            }
        }

        let sparse_field_count = buf.get_byte(off);
        off += 1;
        for _ in 0..sparse_field_count {
            let index = buf.get_byte(off) as usize;
            off += 1;
            let (f, len) = Field::read(buf, off, self.schema.get_field_type(index));
            self.inner.set_field(index, f);
            off += len;
        }

        self.inner.set_dirty(false);
        off
    }
}

/// Same-variant null value for `field`, standing in for the no-arg `Field.newField()` /
/// `value.setNull()` idiom used throughout `SparseRecord.java` (not present on the ported
/// [`Field`] enum, which has no notion of a type-preserving "empty" constructor -- see the same
/// helper duplicated as `null_like` in `index_field.rs`'s tests).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::DataBuffer;
    use crate::framework::db::field::FieldType;

    fn make_schema_with_sparse_columns() -> Arc<Schema> {
        // Columns: 0=Int (dense), 1=String (sparse), 2=Long (sparse).
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Int, FieldType::String, FieldType::Long],
            vec!["Count".to_string(), "Name".to_string(), "Extra".to_string()],
            vec![1, 2],
        ))
    }

    #[test]
    fn test_new_record_defaults_sparse_columns_to_null() {
        let schema = make_schema_with_sparse_columns();
        let rec = SparseRecord::new(schema, Field::Long(Some(1)));
        assert!(rec.get_field(1).is_null());
        assert!(rec.get_field(2).is_null());
        assert!(!rec.get_field(0).is_null()); // dense column defaults to zero, not null
    }

    #[test]
    fn test_compute_length_only_charges_for_present_sparse_fields() {
        let schema = make_schema_with_sparse_columns();
        let mut rec = SparseRecord::new(schema, Field::Long(Some(1)));

        // No sparse fields set: dense Int (4) + sparse-count byte (1).
        assert_eq!(rec.compute_length(), 4 + 1);

        // Set the sparse String column: dense Int (4) + count byte (1) + index byte (1) +
        // string field length (4-byte length prefix + "hi" = 6).
        rec.set_field(1, Some(Field::String(Some("hi".to_string())))).unwrap();
        assert_eq!(rec.compute_length(), 4 + 1 + 1 + 6);
    }

    #[test]
    fn test_write_read_round_trip_with_mixed_sparse_fields() {
        let schema = make_schema_with_sparse_columns();
        let mut rec = SparseRecord::new(schema.clone(), Field::Long(Some(42)));
        rec.set_field(0, Some(Field::Int(Some(7)))).unwrap();
        rec.set_field(1, Some(Field::String(Some("hello".to_string())))).unwrap();
        // Column 2 (sparse Long) intentionally left null.

        let len = rec.compute_length();
        let mut buf = DataBuffer::new(0, len);
        let end = rec.write(&mut buf, 0);
        assert_eq!(end, len);
        assert!(!rec.is_dirty());

        let mut decoded = SparseRecord::new(schema, Field::Long(Some(42)));
        // Poison the decode target so the round trip actually proves something.
        decoded.set_field(2, Some(Field::Long(Some(999)))).unwrap();
        let next = decoded.read(&buf, 0);
        assert_eq!(next, len);

        assert_eq!(decoded.get_field(0), &Field::Int(Some(7)));
        assert_eq!(decoded.get_field(1), &Field::String(Some("hello".to_string())));
        assert!(decoded.get_field(2).is_null()); // read() must re-null columns absent from the buffer
        assert!(!decoded.is_dirty());
    }

    #[test]
    fn test_write_omits_null_sparse_fields_entirely() {
        let schema = make_schema_with_sparse_columns();
        let mut rec = SparseRecord::new(schema.clone(), Field::Long(Some(1)));
        rec.set_field(0, Some(Field::Int(Some(1)))).unwrap();
        // Both sparse columns left null.

        let len = rec.compute_length();
        assert_eq!(len, 4 + 1); // no sparse-field bytes at all beyond the zero count
        let mut buf = DataBuffer::new(0, len);
        rec.write(&mut buf, 0);
        // The sparse field count byte, immediately after the dense Int, must be zero.
        assert_eq!(buf.get_byte(4), 0);
    }

    #[test]
    fn test_set_field_rejects_null_for_non_sparse_column() {
        let schema = make_schema_with_sparse_columns();
        let mut rec = SparseRecord::new(schema, Field::Long(Some(1)));
        assert!(rec.set_field(0, None).is_err()); // column 0 is dense
        assert!(rec.set_field(1, None).is_ok()); // column 1 is sparse
    }

    #[test]
    fn test_set_field_none_on_sparse_column_produces_same_type_null() {
        let schema = make_schema_with_sparse_columns();
        let mut rec = SparseRecord::new(schema, Field::Long(Some(1)));
        rec.set_field(1, Some(Field::String(Some("x".to_string())))).unwrap();
        assert!(!rec.get_field(1).is_null());

        rec.set_field(1, None).unwrap();
        assert!(rec.get_field(1).is_null());
        assert_eq!(rec.get_field(1).get_type(), FieldType::String);
    }
}
