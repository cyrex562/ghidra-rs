use super::buffer::Buffer;
use super::field::FieldType;
use super::illegal_field_access_exception::IllegalFieldAccessException;
use super::primitive_field::PrimitiveField;
use std::cmp::Ordering;

/// A [`PrimitiveField`] wrapper for boolean data read from or written to a Record.
///
/// Port of `db.BooleanField`. `BooleanField` was a concrete, `final` `PrimitiveField` subclass in
/// Java; it is ported here as an object-safe trait (a cycle cut-point) so that dependents can
/// hold `Box<dyn BooleanField>` / `&dyn BooleanField` instead of a concrete type, mirroring the
/// pattern established by [`super::byte_field::ByteField`].
///
/// # The raw-byte quirk
///
/// Java's `BooleanField` is internally backed by a `byte value`, not a `boolean`:
/// `getBooleanValue()` returns `value != 0`, but `write`, `read`, `equals`, `compareTo`,
/// `hashCode`, and `getBinaryData`/`setBinaryData` all operate directly on the *raw byte*, not on
/// a normalized 0/1 value. In particular `setBinaryData`/`read` store whatever raw byte is
/// supplied verbatim (no normalization), so two fields that both report `getBooleanValue() ==
/// true` can still be unequal, differently ordered, and differently hashed if their raw bytes
/// differ (e.g. `5` vs `1`). `copyField()`, by contrast, *does* normalize (it goes through the
/// public `BooleanField(boolean)` constructor), so a round-trip through `copyField()` can silently
/// change a non-canonical raw byte to canonical `0`/`1`. This is faithfully reproduced here:
/// implementors expose the raw byte via [`Self::get_raw_byte`] / [`Self::set_raw_byte`], and all
/// of the raw-byte-sensitive default methods below are built on those, not on
/// [`Self::get_boolean_value`].
pub trait BooleanField: PrimitiveField {
    /// Returns the field's raw stored byte, mirroring Java's private `BooleanField.value` field
    /// directly (not normalized to 0/1). Not part of `BooleanField`'s public Java API, but needed
    /// here so that [`Self::write`], [`Self::compare_to`], [`Self::field_hash`], and
    /// [`Self::get_binary_data`] can faithfully reproduce Java's raw-byte semantics described in
    /// the trait-level doc comment.
    fn get_raw_byte(&self) -> i8;

    /// Sets the field's raw stored byte verbatim (no 0/1 normalization), mirroring the body of
    /// `BooleanField.read(Buffer, int)` / `BooleanField.setBinaryData(byte[])`.
    ///
    /// Implementors must invoke [`PrimitiveField::updating_primitive_value`] (or an equivalent
    /// immutable/null check) before applying the new value, returning its error if the field is
    /// immutable.
    fn set_raw_byte(&mut self, value: i8) -> Result<(), IllegalFieldAccessException>;

    /// Constructs a new, empty (zero-valued, non-null-forced) boolean field. Mirrors
    /// `BooleanField.newField()`.
    fn new_field(&self) -> Box<dyn BooleanField>;

    /// Returns the minimum representable boolean field value (`false`). Mirrors
    /// `BooleanField.getMinValue()`.
    fn get_min_value(&self) -> Box<dyn BooleanField>;

    /// Returns the maximum representable boolean field value (`true`). Mirrors
    /// `BooleanField.getMaxValue()`.
    fn get_max_value(&self) -> Box<dyn BooleanField>;

    /// Returns the field's current boolean value: `true` iff the raw byte is nonzero. Mirrors
    /// `BooleanField.getBooleanValue()`.
    fn get_boolean_value(&self) -> bool {
        self.get_raw_byte() != 0
    }

    /// Sets the field's boolean value, normalizing to a canonical raw byte of `1` or `0`. Mirrors
    /// `BooleanField.setBooleanValue(boolean)`.
    fn set_boolean_value(&mut self, value: bool) -> Result<(), IllegalFieldAccessException> {
        self.set_raw_byte(if value { 1 } else { 0 })
    }

    /// Constructs a copy of this field. If null, the copy is null; otherwise the copy's raw byte
    /// is normalized to canonical `1`/`0` via [`Self::set_boolean_value`] -- reproducing the
    /// normalize-on-copy quirk described in the trait-level doc comment, since Java's
    /// `copyField()` passes through the public `boolean`-taking constructor rather than copying
    /// the raw byte. Mirrors `BooleanField.copyField()`.
    fn copy_field(&self) -> Box<dyn BooleanField> {
        let mut copy = self.new_field();
        if self.is_null() {
            copy.set_null().unwrap();
        } else {
            copy.set_boolean_value(self.get_boolean_value()).unwrap();
        }
        copy
    }

    /// Encoded length in bytes of this field. Mirrors `BooleanField.length()`.
    fn length(&self) -> usize {
        1
    }

    /// The `Field` type tag for a boolean field. Mirrors `BooleanField.getFieldType()`.
    fn get_field_type(&self) -> FieldType {
        FieldType::Boolean
    }

    /// Writes this field's raw byte into `buf` at `offset`. Returns the next available offset, or
    /// -1 if the buffer is full. Mirrors `BooleanField.write(Buffer, int)`.
    fn write(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        buf.put_byte(offset, self.get_raw_byte() as u8)
    }

    /// Reads a raw byte from `buf` at `offset` into this field verbatim (no normalization),
    /// clearing any null state. Returns the offset immediately following the read value. Mirrors
    /// `BooleanField.read(Buffer, int)`.
    fn read(&mut self, buf: &dyn Buffer, offset: usize) -> Result<usize, IllegalFieldAccessException> {
        let v = buf.get_byte(offset) as i8;
        self.set_raw_byte(v)?;
        Ok(offset + 1)
    }

    /// Length in bytes of the encoded value at `offset` within `buf`, without altering this
    /// instance. Always 1 for a boolean field. Mirrors `BooleanField.readLength(Buffer, int)`.
    fn read_length(&self, _buf: &dyn Buffer, _offset: usize) -> usize {
        1
    }

    /// Compares this field's *raw byte* (not its boolean value) to `other`'s. Mirrors
    /// `BooleanField.compareTo(Field)` -- see the trait-level doc comment for why this can order
    /// two equally-`true` fields as unequal.
    fn compare_to(&self, other: &dyn BooleanField) -> Ordering {
        self.get_raw_byte().cmp(&other.get_raw_byte())
    }

    /// Compares this field's raw byte to the byte encoded in `buffer` at `offset`, without
    /// decoding a full field. Mirrors `BooleanField.compareTo(DataBuffer, int)`.
    fn compare_to_buffer(&self, buffer: &dyn Buffer, offset: usize) -> Ordering {
        let other_value = buffer.get_byte(offset) as i8;
        self.get_raw_byte().cmp(&other_value)
    }

    /// Returns this field's raw byte, sign-extended to `i64`. Mirrors
    /// `BooleanField.getLongValue()` (note: unlike most other `PrimitiveField`s, `BooleanField`
    /// has no public `setLongValue`).
    fn get_long_value(&self) -> i64 {
        self.get_raw_byte() as i64
    }

    /// Returns this field's raw byte as a single-byte array. Mirrors
    /// `BooleanField.getBinaryData()`.
    fn get_binary_data(&self) -> Vec<u8> {
        vec![self.get_raw_byte() as u8]
    }

    /// Sets this field's raw byte from `bytes`, verbatim (no normalization).
    ///
    /// `None` mirrors a `null` array argument (sets this field null). `Some(bytes)` with a length
    /// other than 1 mirrors `IllegalFieldAccessException`. Mirrors
    /// `BooleanField.setBinaryData(byte[])`.
    fn set_binary_data(&mut self, bytes: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
        match bytes {
            None => self.set_null(),
            Some(b) if b.len() != 1 => Err(IllegalFieldAccessException::new()),
            Some(b) => self.set_raw_byte(b[0] as i8),
        }
    }

    /// Whether `other` has the same raw byte as this instance (not merely the same boolean
    /// value). Mirrors `BooleanField.equals(Object)`.
    fn fields_equal(&self, other: &dyn BooleanField) -> bool {
        self.get_raw_byte() == other.get_raw_byte()
    }

    /// Deterministic hash over this field's raw byte, matching Java's `byte`-to-`int`
    /// sign-extending widening conversion. Mirrors `BooleanField.hashCode()`.
    fn field_hash(&self) -> i32 {
        self.get_raw_byte() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBooleanField {
        value: i8,
        is_null: bool,
        immutable: bool,
    }

    impl MockBooleanField {
        fn new(value: bool) -> Self {
            Self { value: if value { 1 } else { 0 }, is_null: false, immutable: false }
        }

        fn from_raw(value: i8) -> Self {
            Self { value, is_null: false, immutable: false }
        }

        fn immutable(value: bool) -> Self {
            Self { value: if value { 1 } else { 0 }, is_null: false, immutable: true }
        }
    }

    impl PrimitiveField for MockBooleanField {
        fn is_null(&self) -> bool {
            self.is_null
        }

        fn set_null(&mut self) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.is_null = true;
            self.value = 0;
            Ok(())
        }

        fn updating_primitive_value(&mut self) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.is_null = false;
            Ok(())
        }

        fn get_value_as_string(&self) -> String {
            (self.value != 0).to_string()
        }

        fn type_name(&self) -> &str {
            "BooleanField"
        }
    }

    impl BooleanField for MockBooleanField {
        fn get_raw_byte(&self) -> i8 {
            self.value
        }

        fn set_raw_byte(&mut self, value: i8) -> Result<(), IllegalFieldAccessException> {
            self.updating_primitive_value()?;
            self.value = value;
            Ok(())
        }

        fn new_field(&self) -> Box<dyn BooleanField> {
            Box::new(MockBooleanField::new(false))
        }

        fn get_min_value(&self) -> Box<dyn BooleanField> {
            Box::new(MockBooleanField::immutable(false))
        }

        fn get_max_value(&self) -> Box<dyn BooleanField> {
            Box::new(MockBooleanField::immutable(true))
        }
    }

    #[test]
    fn test_object_safety_and_value_roundtrip() {
        let mut field: Box<dyn BooleanField> = Box::new(MockBooleanField::new(false));
        assert!(!field.get_boolean_value());

        field.set_boolean_value(true).unwrap();
        assert!(field.get_boolean_value());
        assert_eq!(field.get_long_value(), 1);
        assert!(!field.is_null());
    }

    #[test]
    fn test_write_read_round_trip() {
        use super::super::buffer::DataBuffer;

        let original: Box<dyn BooleanField> = Box::new(MockBooleanField::new(true));
        let mut buf = DataBuffer::new(0, original.length());
        let end = original.write(&mut buf, 0);
        assert_eq!(end, original.length() as isize);

        let mut decoded: Box<dyn BooleanField> = Box::new(MockBooleanField::new(false));
        let next_offset = decoded.read(&buf, 0).unwrap();
        assert_eq!(next_offset, 1);
        assert!(original.fields_equal(decoded.as_ref()));
        assert_eq!(original.compare_to(decoded.as_ref()), Ordering::Equal);
        assert_eq!(original.compare_to_buffer(&buf, 0), Ordering::Equal);
    }

    #[test]
    fn test_binary_data_round_trip() {
        let original: Box<dyn BooleanField> = Box::new(MockBooleanField::new(true));
        let bytes = original.get_binary_data();
        assert_eq!(bytes, vec![1u8]);

        let mut restored: Box<dyn BooleanField> = Box::new(MockBooleanField::new(false));
        restored.set_binary_data(Some(&bytes)).unwrap();
        assert!(original.fields_equal(restored.as_ref()));
        assert_eq!(original.field_hash(), restored.field_hash());
    }

    #[test]
    fn test_set_binary_data_rejects_wrong_length() {
        let mut field: Box<dyn BooleanField> = Box::new(MockBooleanField::new(true));
        assert!(field.set_binary_data(Some(&[1, 2])).is_err());
    }

    #[test]
    fn test_set_binary_data_none_sets_null() {
        let mut field: Box<dyn BooleanField> = Box::new(MockBooleanField::new(true));
        field.set_binary_data(None).unwrap();
        assert!(field.is_null());
        assert!(!field.get_boolean_value());
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field: Box<dyn BooleanField> = Box::new(MockBooleanField::immutable(true));
        assert!(field.set_boolean_value(false).is_err());
        assert!(field.set_null().is_err());
    }

    #[test]
    fn test_min_max_value() {
        let field: Box<dyn BooleanField> = Box::new(MockBooleanField::new(false));
        assert!(!field.get_min_value().get_boolean_value());
        assert!(field.get_max_value().get_boolean_value());
    }

    /// Faithful port of the `BooleanField` raw-byte quirk described in the trait-level doc
    /// comment (see `BooleanField.java` `setBinaryData`/`read`/`compareTo`/`equals`, which all
    /// operate on the raw stored byte with no 0/1 normalization). A field whose raw byte is `5`
    /// (set via `setBinaryData`, exactly as a corrupt or hand-crafted buffer might do) reports
    /// `getBooleanValue() == true` just like a canonical raw-byte-`1` field, yet the two are
    /// *not* `fields_equal`, do *not* compare as `Equal`, and do *not* share a `field_hash` --
    /// because `compareTo`/`equals`/`hashCode` all compare/hash the raw byte, not the boolean.
    #[test]
    fn test_raw_byte_quirk_true_values_can_differ() {
        let canonical_true: Box<dyn BooleanField> = Box::new(MockBooleanField::new(true)); // raw = 1
        let mut noncanonical_true: Box<dyn BooleanField> = Box::new(MockBooleanField::new(false));
        noncanonical_true.set_binary_data(Some(&[5])).unwrap(); // raw = 5, still "true"

        assert!(canonical_true.get_boolean_value());
        assert!(noncanonical_true.get_boolean_value());

        assert!(!canonical_true.fields_equal(noncanonical_true.as_ref()));
        assert_eq!(canonical_true.compare_to(noncanonical_true.as_ref()), Ordering::Less);
        assert_ne!(canonical_true.field_hash(), noncanonical_true.field_hash());
        assert_eq!(noncanonical_true.get_long_value(), 5);
    }

    /// Faithful port of `BooleanField.copyField()` normalizing a non-canonical raw byte to
    /// canonical `1`/`0` (because it passes through the public `boolean`-taking constructor
    /// rather than copying the raw byte directly) -- so a field is not always `fields_equal` to
    /// its own `copy_field()` result, even though both report the same `get_boolean_value()`.
    #[test]
    fn test_copy_field_normalizes_noncanonical_raw_byte() {
        let mut original: Box<dyn BooleanField> = Box::new(MockBooleanField::new(false));
        original.set_binary_data(Some(&[5])).unwrap(); // raw = 5 ("true", non-canonical)

        let copy = original.copy_field();
        assert_eq!(copy.get_raw_byte(), 1); // normalized
        assert_eq!(original.get_raw_byte(), 5); // original untouched
        assert!(original.get_boolean_value() && copy.get_boolean_value());
        assert!(!original.fields_equal(copy.as_ref())); // yet not equal by raw byte
    }

    #[test]
    fn test_copy_field_preserves_null() {
        let mut original: Box<dyn BooleanField> = Box::new(MockBooleanField::new(true));
        original.set_null().unwrap();
        let copy = original.copy_field();
        assert!(copy.is_null());
    }

    #[test]
    fn test_display_string() {
        let field: Box<dyn BooleanField> = Box::new(MockBooleanField::new(true));
        assert_eq!(field.to_display_string(), "BooleanField: true");
    }

    // Also exercise `from_raw` directly to make sure the helper constructor itself is covered.
    #[test]
    fn test_from_raw_helper() {
        let field = MockBooleanField::from_raw(-1);
        assert_eq!(field.get_raw_byte(), -1);
        assert!(field.get_boolean_value());
    }
}
