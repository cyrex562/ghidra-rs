use super::buffer::Buffer;
use super::field::FieldType;
use super::illegal_field_access_exception::IllegalFieldAccessException;
use super::primitive_field::PrimitiveField;
use std::cmp::Ordering;

/// A [`PrimitiveField`] wrapper for a single signed byte value read from or written to a Record.
///
/// Port of `db.ByteField`. `ByteField` was a concrete, `final` `PrimitiveField` subclass in Java;
/// it is ported here as an object-safe trait (a cycle cut-point) so that dependents can hold
/// `Box<dyn ByteField>` / `&dyn ByteField` instead of a concrete type. Implementors own the
/// underlying `value` and are responsible for their own construction and null/immutable
/// bookkeeping (mirroring the Java constructors and `PrimitiveField` state machine).
///
/// The Java class also exposes `MIN_VALUE`, `MAX_VALUE`, `ZERO_VALUE`, and `INSTANCE` static
/// singleton fields (used e.g. by `Schema` to describe a byte column). Those are deferred to
/// whichever concrete implementor eventually replaces the placeholder use of this trait, since a
/// trait cannot hold `Self`-typed constants while remaining object-safe.
pub trait ByteField: PrimitiveField {
    /// Returns the field's current byte value. Mirrors `ByteField.getByteValue()`.
    fn get_byte_value(&self) -> i8;

    /// Sets the field's byte value.
    ///
    /// Mirrors `ByteField.setByteValue(byte)`: implementors must invoke
    /// [`PrimitiveField::updating_primitive_value`] (or an equivalent immutable/null check)
    /// before applying the new value, returning its error if the field is immutable.
    fn set_byte_value(&mut self, value: i8) -> Result<(), IllegalFieldAccessException>;

    /// Constructs a copy of this field, detached from any underlying buffer. Mirrors
    /// `ByteField.copyField()`.
    fn copy_field(&self) -> Box<dyn ByteField>;

    /// Constructs a new, empty (zero-valued, non-null-forced) byte field. Mirrors
    /// `ByteField.newField()`.
    fn new_field(&self) -> Box<dyn ByteField>;

    /// Returns the minimum representable byte field value (`Byte.MIN_VALUE`, i.e. -128). Mirrors
    /// `ByteField.getMinValue()`.
    fn get_min_value(&self) -> Box<dyn ByteField>;

    /// Returns the maximum representable byte field value (`Byte.MAX_VALUE`, i.e. 127). Mirrors
    /// `ByteField.getMaxValue()`.
    fn get_max_value(&self) -> Box<dyn ByteField>;

    /// Encoded length in bytes of this field. Mirrors `ByteField.length()`.
    fn length(&self) -> usize {
        1
    }

    /// The `Field` type tag for a byte field. Mirrors `ByteField.getFieldType()`.
    fn get_field_type(&self) -> FieldType {
        FieldType::Byte
    }

    /// Writes this field's value into `buf` at `offset`. Returns the next available offset, or
    /// -1 if the buffer is full. Mirrors `ByteField.write(Buffer, int)`.
    fn write(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        buf.put_byte(offset, self.get_byte_value() as u8)
    }

    /// Reads a byte value from `buf` at `offset` into this field, clearing any null state.
    /// Returns the offset immediately following the read value. Mirrors
    /// `ByteField.read(Buffer, int)`.
    fn read(&mut self, buf: &dyn Buffer, offset: usize) -> Result<usize, IllegalFieldAccessException> {
        let v = buf.get_byte(offset) as i8;
        self.set_byte_value(v)?;
        Ok(offset + 1)
    }

    /// Length in bytes of the encoded value at `offset` within `buf`, without altering this
    /// instance. Always 1 for a byte field. Mirrors `ByteField.readLength(Buffer, int)`.
    fn read_length(&self, _buf: &dyn Buffer, _offset: usize) -> usize {
        1
    }

    /// Compares this field's value to `other`'s value. Mirrors `ByteField.compareTo(Field)`.
    fn compare_to(&self, other: &dyn ByteField) -> Ordering {
        self.get_byte_value().cmp(&other.get_byte_value())
    }

    /// Compares this field's value to the byte value encoded in `buffer` at `offset`, without
    /// decoding a full field. Mirrors `ByteField.compareTo(DataBuffer, int)`.
    fn compare_to_buffer(&self, buffer: &dyn Buffer, offset: usize) -> Ordering {
        let other_value = buffer.get_byte(offset) as i8;
        self.get_byte_value().cmp(&other_value)
    }

    /// Returns this field's value widened to `i64`. Mirrors `ByteField.getLongValue()`.
    fn get_long_value(&self) -> i64 {
        self.get_byte_value() as i64
    }

    /// Sets this field's value, narrowing from `i64`. Mirrors `ByteField.setLongValue(long)`.
    fn set_long_value(&mut self, value: i64) -> Result<(), IllegalFieldAccessException> {
        self.set_byte_value(value as i8)
    }

    /// Returns this field's value as a single-byte array. Mirrors `ByteField.getBinaryData()`.
    fn get_binary_data(&self) -> Vec<u8> {
        vec![self.get_byte_value() as u8]
    }

    /// Sets this field's value from `bytes`.
    ///
    /// `None` mirrors a `null` array argument (sets this field null). `Some(bytes)` with a length
    /// other than 1 mirrors `IllegalFieldAccessException`. Mirrors
    /// `ByteField.setBinaryData(byte[])`.
    fn set_binary_data(&mut self, bytes: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
        match bytes {
            None => self.set_null(),
            Some(b) if b.len() != 1 => Err(IllegalFieldAccessException::new()),
            Some(b) => self.set_byte_value(b[0] as i8),
        }
    }

    /// Whether `other` has the same byte value as this instance. Mirrors
    /// `ByteField.equals(Object)`.
    fn fields_equal(&self, other: &dyn ByteField) -> bool {
        self.get_byte_value() == other.get_byte_value()
    }

    /// Deterministic hash over this field's value, matching Java's `byte`-to-`int` sign-extending
    /// widening conversion. Mirrors `ByteField.hashCode()`.
    fn field_hash(&self) -> i32 {
        self.get_byte_value() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockByteField {
        value: i8,
        is_null: bool,
        immutable: bool,
    }

    impl MockByteField {
        fn new(value: i8) -> Self {
            Self { value, is_null: false, immutable: false }
        }

        fn immutable(value: i8) -> Self {
            Self { value, is_null: false, immutable: true }
        }
    }

    impl PrimitiveField for MockByteField {
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
            format!("0x{:x}", (self.value as u8) & 0xff)
        }

        fn type_name(&self) -> &str {
            "ByteField"
        }
    }

    impl ByteField for MockByteField {
        fn get_byte_value(&self) -> i8 {
            self.value
        }

        fn set_byte_value(&mut self, value: i8) -> Result<(), IllegalFieldAccessException> {
            self.updating_primitive_value()?;
            self.value = value;
            Ok(())
        }

        fn copy_field(&self) -> Box<dyn ByteField> {
            if self.is_null {
                let mut copy = MockByteField::new(0);
                copy.set_null().unwrap();
                Box::new(copy)
            } else {
                Box::new(MockByteField::new(self.value))
            }
        }

        fn new_field(&self) -> Box<dyn ByteField> {
            Box::new(MockByteField::new(0))
        }

        fn get_min_value(&self) -> Box<dyn ByteField> {
            Box::new(MockByteField::immutable(i8::MIN))
        }

        fn get_max_value(&self) -> Box<dyn ByteField> {
            Box::new(MockByteField::immutable(i8::MAX))
        }
    }

    #[test]
    fn test_object_safety_and_value_roundtrip() {
        let mut field: Box<dyn ByteField> = Box::new(MockByteField::new(0));
        assert_eq!(field.get_byte_value(), 0);

        field.set_byte_value(-5).unwrap();
        assert_eq!(field.get_byte_value(), -5);
        assert_eq!(field.get_long_value(), -5);
        assert!(!field.is_null());
    }

    #[test]
    fn test_write_read_round_trip() {
        use super::super::buffer::DataBuffer;

        let original: Box<dyn ByteField> = Box::new(MockByteField::new(-100));
        let mut buf = DataBuffer::new(0, original.length());
        let end = original.write(&mut buf, 0);
        assert_eq!(end, original.length() as isize);

        let mut decoded: Box<dyn ByteField> = Box::new(MockByteField::new(0));
        let next_offset = decoded.read(&buf, 0).unwrap();
        assert_eq!(next_offset, 1);
        assert!(original.fields_equal(decoded.as_ref()));
        assert_eq!(original.compare_to(decoded.as_ref()), Ordering::Equal);
        assert_eq!(original.compare_to_buffer(&buf, 0), Ordering::Equal);
    }

    #[test]
    fn test_compare_to_orders_by_value() {
        let low: Box<dyn ByteField> = Box::new(MockByteField::new(-10));
        let high: Box<dyn ByteField> = Box::new(MockByteField::new(10));
        assert_eq!(low.compare_to(high.as_ref()), Ordering::Less);
        assert_eq!(high.compare_to(low.as_ref()), Ordering::Greater);
    }

    #[test]
    fn test_binary_data_round_trip() {
        let original: Box<dyn ByteField> = Box::new(MockByteField::new(42));
        let bytes = original.get_binary_data();
        assert_eq!(bytes, vec![42u8]);

        let mut restored: Box<dyn ByteField> = Box::new(MockByteField::new(0));
        restored.set_binary_data(Some(&bytes)).unwrap();
        assert!(original.fields_equal(restored.as_ref()));
        assert_eq!(original.field_hash(), restored.field_hash());
    }

    #[test]
    fn test_set_binary_data_rejects_wrong_length() {
        let mut field: Box<dyn ByteField> = Box::new(MockByteField::new(1));
        assert!(field.set_binary_data(Some(&[1, 2])).is_err());
    }

    #[test]
    fn test_set_binary_data_none_sets_null() {
        let mut field: Box<dyn ByteField> = Box::new(MockByteField::new(7));
        field.set_binary_data(None).unwrap();
        assert!(field.is_null());
        assert_eq!(field.get_byte_value(), 0);
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field: Box<dyn ByteField> = Box::new(MockByteField::immutable(1));
        assert!(field.set_byte_value(2).is_err());
        assert!(field.set_null().is_err());
    }

    #[test]
    fn test_min_max_value() {
        let field: Box<dyn ByteField> = Box::new(MockByteField::new(0));
        assert_eq!(field.get_min_value().get_byte_value(), i8::MIN);
        assert_eq!(field.get_max_value().get_byte_value(), i8::MAX);
    }

    #[test]
    fn test_field_hash_sign_extends() {
        let field: Box<dyn ByteField> = Box::new(MockByteField::new(-1));
        assert_eq!(field.field_hash(), -1i32);
    }

    #[test]
    fn test_display_string_uses_hex_value() {
        let field: Box<dyn ByteField> = Box::new(MockByteField::new(-1));
        assert_eq!(field.to_display_string(), "ByteField: 0xff");
    }
}
