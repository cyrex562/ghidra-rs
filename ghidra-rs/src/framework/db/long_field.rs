use super::buffer::Buffer;
use super::field::FieldType;
use super::illegal_field_access_exception::IllegalFieldAccessException;
use super::primitive_field::PrimitiveField;
use std::cmp::Ordering;

/// A [`PrimitiveField`] wrapper for an 8-byte signed long value read from or written to a Record.
///
/// Port of `db.LongField`. `LongField` was a concrete, `final` `PrimitiveField` subclass in Java;
/// it is ported here as an object-safe trait (a cycle cut-point) so that dependents can hold
/// `Box<dyn LongField>` / `&dyn LongField` instead of a concrete type, mirroring the pattern
/// established by [`super::byte_field::ByteField`]. Implementors own the underlying `value` and
/// are responsible for their own construction and null/immutable bookkeeping (mirroring the Java
/// constructors and `PrimitiveField` state machine).
///
/// The Java class also exposes `MIN_VALUE`, `MAX_VALUE`, `ZERO_VALUE`, and `INSTANCE` static
/// singleton fields (used e.g. by `Schema` to describe a long column). Those are deferred to
/// whichever concrete implementor eventually replaces the placeholder use of this trait, since a
/// trait cannot hold `Self`-typed constants while remaining object-safe.
pub trait LongField: PrimitiveField {
    /// Returns the field's current long value. Mirrors `LongField.getLongValue()`.
    fn get_long_value(&self) -> i64;

    /// Sets the field's long value.
    ///
    /// Mirrors `LongField.setLongValue(long)`: implementors must invoke
    /// [`PrimitiveField::updating_primitive_value`] (or an equivalent immutable/null check)
    /// before applying the new value, returning its error if the field is immutable.
    fn set_long_value(&mut self, value: i64) -> Result<(), IllegalFieldAccessException>;

    /// Constructs a copy of this field, detached from any underlying buffer. Mirrors
    /// `LongField.copyField()`.
    fn copy_field(&self) -> Box<dyn LongField>;

    /// Constructs a new, empty (zero-valued, non-null-forced) long field. Mirrors
    /// `LongField.newField()`.
    fn new_field(&self) -> Box<dyn LongField>;

    /// Returns the minimum representable long field value (`Long.MIN_VALUE`). Mirrors
    /// `LongField.getMinValue()`.
    fn get_min_value(&self) -> Box<dyn LongField>;

    /// Returns the maximum representable long field value (`Long.MAX_VALUE`). Mirrors
    /// `LongField.getMaxValue()`.
    fn get_max_value(&self) -> Box<dyn LongField>;

    /// Encoded length in bytes of this field. Mirrors `LongField.length()`.
    fn length(&self) -> usize {
        8
    }

    /// The `Field` type tag for a long field. Mirrors `LongField.getFieldType()`.
    fn get_field_type(&self) -> FieldType {
        FieldType::Long
    }

    /// Writes this field's value into `buf` at `offset`. Returns the next available offset, or
    /// -1 if the buffer is full. Mirrors `LongField.write(Buffer, int)`.
    fn write(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        buf.put_long(offset, self.get_long_value())
    }

    /// Reads a long value from `buf` at `offset` into this field, clearing any null state.
    /// Returns the offset immediately following the read value. Mirrors
    /// `LongField.read(Buffer, int)`.
    fn read(&mut self, buf: &dyn Buffer, offset: usize) -> Result<usize, IllegalFieldAccessException> {
        let v = buf.get_long(offset);
        self.set_long_value(v)?;
        Ok(offset + 8)
    }

    /// Length in bytes of the encoded value at `offset` within `buf`, without altering this
    /// instance. Always 8 for a long field. Mirrors `LongField.readLength(Buffer, int)`.
    fn read_length(&self, _buf: &dyn Buffer, _offset: usize) -> usize {
        8
    }

    /// Compares this field's value to `other`'s value. Mirrors `LongField.compareTo(Field)`.
    fn compare_to(&self, other: &dyn LongField) -> Ordering {
        self.get_long_value().cmp(&other.get_long_value())
    }

    /// Compares this field's value to the long value encoded in `buffer` at `offset`, without
    /// decoding a full field. Mirrors `LongField.compareTo(DataBuffer, int)`.
    fn compare_to_buffer(&self, buffer: &dyn Buffer, offset: usize) -> Ordering {
        let other_value = buffer.get_long(offset);
        self.get_long_value().cmp(&other_value)
    }

    /// Returns this field's value as an 8-byte big-endian array. Mirrors
    /// `LongField.getBinaryData()`.
    fn get_binary_data(&self) -> Vec<u8> {
        self.get_long_value().to_be_bytes().to_vec()
    }

    /// Sets this field's value from `bytes`.
    ///
    /// `None` mirrors a `null` array argument (sets this field null). `Some(bytes)` with a length
    /// other than 8 mirrors `IllegalFieldAccessException`. Mirrors
    /// `LongField.setBinaryData(byte[])`.
    fn set_binary_data(&mut self, bytes: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
        match bytes {
            None => self.set_null(),
            Some(b) if b.len() != 8 => Err(IllegalFieldAccessException::new()),
            Some(b) => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(b);
                self.set_long_value(i64::from_be_bytes(arr))
            }
        }
    }

    /// Whether `other` has the same long value as this instance. Mirrors
    /// `LongField.equals(Object)`.
    fn fields_equal(&self, other: &dyn LongField) -> bool {
        self.get_long_value() == other.get_long_value()
    }

    /// Deterministic hash over this field's value, matching Java's `(int) (value ^ (value >>>
    /// 32))` folding of the 64-bit value into 32 bits. Mirrors `LongField.hashCode()`.
    fn field_hash(&self) -> i32 {
        let v = self.get_long_value();
        (v ^ ((v as u64 >> 32) as i64)) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockLongField {
        value: i64,
        is_null: bool,
        immutable: bool,
    }

    impl MockLongField {
        fn new(value: i64) -> Self {
            Self { value, is_null: false, immutable: false }
        }

        fn immutable(value: i64) -> Self {
            Self { value, is_null: false, immutable: true }
        }
    }

    impl PrimitiveField for MockLongField {
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
            format!("0x{:x}", self.value)
        }

        fn type_name(&self) -> &str {
            "LongField"
        }
    }

    impl LongField for MockLongField {
        fn get_long_value(&self) -> i64 {
            self.value
        }

        fn set_long_value(&mut self, value: i64) -> Result<(), IllegalFieldAccessException> {
            self.updating_primitive_value()?;
            self.value = value;
            Ok(())
        }

        fn copy_field(&self) -> Box<dyn LongField> {
            if self.is_null {
                let mut copy = MockLongField::new(0);
                copy.set_null().unwrap();
                Box::new(copy)
            } else {
                Box::new(MockLongField::new(self.value))
            }
        }

        fn new_field(&self) -> Box<dyn LongField> {
            Box::new(MockLongField::new(0))
        }

        fn get_min_value(&self) -> Box<dyn LongField> {
            Box::new(MockLongField::immutable(i64::MIN))
        }

        fn get_max_value(&self) -> Box<dyn LongField> {
            Box::new(MockLongField::immutable(i64::MAX))
        }
    }

    #[test]
    fn test_object_safety_and_value_roundtrip() {
        let mut field: Box<dyn LongField> = Box::new(MockLongField::new(0));
        assert_eq!(field.get_long_value(), 0);

        field.set_long_value(-500).unwrap();
        assert_eq!(field.get_long_value(), -500);
        assert!(!field.is_null());
    }

    #[test]
    fn test_write_read_round_trip() {
        use super::super::buffer::DataBuffer;

        let original: Box<dyn LongField> = Box::new(MockLongField::new(-1_000_000_000_000));
        let mut buf = DataBuffer::new(0, original.length());
        let end = original.write(&mut buf, 0);
        assert_eq!(end, original.length() as isize);

        let mut decoded: Box<dyn LongField> = Box::new(MockLongField::new(0));
        let next_offset = decoded.read(&buf, 0).unwrap();
        assert_eq!(next_offset, 8);
        assert!(original.fields_equal(decoded.as_ref()));
        assert_eq!(original.compare_to(decoded.as_ref()), Ordering::Equal);
        assert_eq!(original.compare_to_buffer(&buf, 0), Ordering::Equal);
    }

    #[test]
    fn test_compare_to_orders_by_value() {
        let low: Box<dyn LongField> = Box::new(MockLongField::new(-10));
        let high: Box<dyn LongField> = Box::new(MockLongField::new(10));
        assert_eq!(low.compare_to(high.as_ref()), Ordering::Less);
        assert_eq!(high.compare_to(low.as_ref()), Ordering::Greater);
    }

    #[test]
    fn test_binary_data_round_trip() {
        let original: Box<dyn LongField> = Box::new(MockLongField::new(0x0102030405060708));
        let bytes = original.get_binary_data();
        assert_eq!(bytes, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let mut restored: Box<dyn LongField> = Box::new(MockLongField::new(0));
        restored.set_binary_data(Some(&bytes)).unwrap();
        assert!(original.fields_equal(restored.as_ref()));
        assert_eq!(original.field_hash(), restored.field_hash());
    }

    #[test]
    fn test_set_binary_data_rejects_wrong_length() {
        let mut field: Box<dyn LongField> = Box::new(MockLongField::new(1));
        assert!(field.set_binary_data(Some(&[1, 2, 3])).is_err());
    }

    #[test]
    fn test_set_binary_data_none_sets_null() {
        let mut field: Box<dyn LongField> = Box::new(MockLongField::new(7));
        field.set_binary_data(None).unwrap();
        assert!(field.is_null());
        assert_eq!(field.get_long_value(), 0);
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field: Box<dyn LongField> = Box::new(MockLongField::immutable(1));
        assert!(field.set_long_value(2).is_err());
        assert!(field.set_null().is_err());
    }

    #[test]
    fn test_min_max_value() {
        let field: Box<dyn LongField> = Box::new(MockLongField::new(0));
        assert_eq!(field.get_min_value().get_long_value(), i64::MIN);
        assert_eq!(field.get_max_value().get_long_value(), i64::MAX);
    }

    /// Mirrors `LongField.hashCode()`: `(int) (value ^ (value >>> 32))`. For a value whose high
    /// and low 32-bit halves happen to be equal, the XOR-fold produces a hash of 0 even though
    /// the value itself is nonzero -- a real (if obscure) consequence of the Java folding
    /// algorithm, not a Rust-specific artifact.
    #[test]
    fn test_field_hash_xor_folds_high_and_low_words() {
        let value = 0x0000000100000001i64; // high word == low word == 1
        let field: Box<dyn LongField> = Box::new(MockLongField::new(value));
        assert_eq!(field.field_hash(), 0);
    }

    #[test]
    fn test_display_string_uses_hex_value() {
        let field: Box<dyn LongField> = Box::new(MockLongField::new(-1));
        assert_eq!(field.to_display_string(), "LongField: 0xffffffffffffffff");
    }
}
