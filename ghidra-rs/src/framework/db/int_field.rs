use super::buffer::Buffer;
use super::field::FieldType;
use super::illegal_field_access_exception::IllegalFieldAccessException;
use super::primitive_field::PrimitiveField;
use std::cmp::Ordering;

/// A [`PrimitiveField`] wrapper for a 4-byte signed integer value read from or written to a
/// Record.
///
/// Port of `db.IntField`. `IntField` was a concrete, `final` `PrimitiveField` subclass in Java;
/// it is ported here as an object-safe trait (a cycle cut-point) so that dependents can hold
/// `Box<dyn IntField>` / `&dyn IntField` instead of a concrete type, mirroring the pattern
/// established by [`super::byte_field::ByteField`]. Implementors own the underlying `value` and
/// are responsible for their own construction and null/immutable bookkeeping (mirroring the Java
/// constructors and `PrimitiveField` state machine).
///
/// The Java class also exposes `MIN_VALUE`, `MAX_VALUE`, `ZERO_VALUE`, and `INSTANCE` static
/// singleton fields (used e.g. by `Schema` to describe an int column). Those are deferred to
/// whichever concrete implementor eventually replaces the placeholder use of this trait, since a
/// trait cannot hold `Self`-typed constants while remaining object-safe.
pub trait IntField: PrimitiveField {
    /// Returns the field's current int value. Mirrors `IntField.getIntValue()`.
    fn get_int_value(&self) -> i32;

    /// Sets the field's int value.
    ///
    /// Mirrors `IntField.setIntValue(int)`: implementors must invoke
    /// [`PrimitiveField::updating_primitive_value`] (or an equivalent immutable/null check)
    /// before applying the new value, returning its error if the field is immutable.
    fn set_int_value(&mut self, value: i32) -> Result<(), IllegalFieldAccessException>;

    /// Constructs a copy of this field, detached from any underlying buffer. Mirrors
    /// `IntField.copyField()`.
    fn copy_field(&self) -> Box<dyn IntField>;

    /// Constructs a new, empty (zero-valued, non-null-forced) int field. Mirrors
    /// `IntField.newField()`.
    fn new_field(&self) -> Box<dyn IntField>;

    /// Returns the minimum representable int field value (`Integer.MIN_VALUE`). Mirrors
    /// `IntField.getMinValue()`.
    fn get_min_value(&self) -> Box<dyn IntField>;

    /// Returns the maximum representable int field value (`Integer.MAX_VALUE`). Mirrors
    /// `IntField.getMaxValue()`.
    fn get_max_value(&self) -> Box<dyn IntField>;

    /// Encoded length in bytes of this field. Mirrors `IntField.length()`.
    fn length(&self) -> usize {
        4
    }

    /// The `Field` type tag for an int field. Mirrors `IntField.getFieldType()`.
    fn get_field_type(&self) -> FieldType {
        FieldType::Int
    }

    /// Writes this field's value into `buf` at `offset`. Returns the next available offset, or
    /// -1 if the buffer is full. Mirrors `IntField.write(Buffer, int)`.
    fn write(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        buf.put_int(offset, self.get_int_value())
    }

    /// Reads an int value from `buf` at `offset` into this field, clearing any null state.
    /// Returns the offset immediately following the read value. Mirrors
    /// `IntField.read(Buffer, int)`.
    fn read(&mut self, buf: &dyn Buffer, offset: usize) -> Result<usize, IllegalFieldAccessException> {
        let v = buf.get_int(offset);
        self.set_int_value(v)?;
        Ok(offset + 4)
    }

    /// Length in bytes of the encoded value at `offset` within `buf`, without altering this
    /// instance. Always 4 for an int field. Mirrors `IntField.readLength(Buffer, int)`.
    fn read_length(&self, _buf: &dyn Buffer, _offset: usize) -> usize {
        4
    }

    /// Compares this field's value to `other`'s value. Mirrors `IntField.compareTo(Field)`.
    fn compare_to(&self, other: &dyn IntField) -> Ordering {
        self.get_int_value().cmp(&other.get_int_value())
    }

    /// Compares this field's value to the int value encoded in `buffer` at `offset`, without
    /// decoding a full field. Mirrors `IntField.compareTo(DataBuffer, int)`.
    fn compare_to_buffer(&self, buffer: &dyn Buffer, offset: usize) -> Ordering {
        let other_value = buffer.get_int(offset);
        self.get_int_value().cmp(&other_value)
    }

    /// Returns this field's value widened to `i64`. Mirrors `IntField.getLongValue()`.
    fn get_long_value(&self) -> i64 {
        self.get_int_value() as i64
    }

    /// Sets this field's value, narrowing from `i64`. Mirrors `IntField.setLongValue(long)`: a
    /// plain narrowing cast with no range check, so out-of-`i32`-range input silently truncates.
    fn set_long_value(&mut self, value: i64) -> Result<(), IllegalFieldAccessException> {
        self.set_int_value(value as i32)
    }

    /// Returns this field's value as a 4-byte big-endian array. Mirrors
    /// `IntField.getBinaryData()`.
    fn get_binary_data(&self) -> Vec<u8> {
        self.get_int_value().to_be_bytes().to_vec()
    }

    /// Sets this field's value from `bytes`.
    ///
    /// `None` mirrors a `null` array argument (sets this field null). `Some(bytes)` with a length
    /// other than 4 mirrors `IllegalFieldAccessException`. Mirrors
    /// `IntField.setBinaryData(byte[])`.
    fn set_binary_data(&mut self, bytes: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
        match bytes {
            None => self.set_null(),
            Some(b) if b.len() != 4 => Err(IllegalFieldAccessException::new()),
            Some(b) => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(b);
                self.set_int_value(i32::from_be_bytes(arr))
            }
        }
    }

    /// Whether `other` has the same int value as this instance. Mirrors
    /// `IntField.equals(Object)`.
    fn fields_equal(&self, other: &dyn IntField) -> bool {
        self.get_int_value() == other.get_int_value()
    }

    /// Deterministic hash over this field's value: simply the value itself. Mirrors
    /// `IntField.hashCode()`.
    fn field_hash(&self) -> i32 {
        self.get_int_value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockIntField {
        value: i32,
        is_null: bool,
        immutable: bool,
    }

    impl MockIntField {
        fn new(value: i32) -> Self {
            Self { value, is_null: false, immutable: false }
        }

        fn immutable(value: i32) -> Self {
            Self { value, is_null: false, immutable: true }
        }
    }

    impl PrimitiveField for MockIntField {
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
            "IntField"
        }
    }

    impl IntField for MockIntField {
        fn get_int_value(&self) -> i32 {
            self.value
        }

        fn set_int_value(&mut self, value: i32) -> Result<(), IllegalFieldAccessException> {
            self.updating_primitive_value()?;
            self.value = value;
            Ok(())
        }

        fn copy_field(&self) -> Box<dyn IntField> {
            if self.is_null {
                let mut copy = MockIntField::new(0);
                copy.set_null().unwrap();
                Box::new(copy)
            } else {
                Box::new(MockIntField::new(self.value))
            }
        }

        fn new_field(&self) -> Box<dyn IntField> {
            Box::new(MockIntField::new(0))
        }

        fn get_min_value(&self) -> Box<dyn IntField> {
            Box::new(MockIntField::immutable(i32::MIN))
        }

        fn get_max_value(&self) -> Box<dyn IntField> {
            Box::new(MockIntField::immutable(i32::MAX))
        }
    }

    #[test]
    fn test_object_safety_and_value_roundtrip() {
        let mut field: Box<dyn IntField> = Box::new(MockIntField::new(0));
        assert_eq!(field.get_int_value(), 0);

        field.set_int_value(-500).unwrap();
        assert_eq!(field.get_int_value(), -500);
        assert_eq!(field.get_long_value(), -500);
        assert!(!field.is_null());
    }

    #[test]
    fn test_write_read_round_trip() {
        use super::super::buffer::DataBuffer;

        let original: Box<dyn IntField> = Box::new(MockIntField::new(-100_000));
        let mut buf = DataBuffer::new(0, original.length());
        let end = original.write(&mut buf, 0);
        assert_eq!(end, original.length() as isize);

        let mut decoded: Box<dyn IntField> = Box::new(MockIntField::new(0));
        let next_offset = decoded.read(&buf, 0).unwrap();
        assert_eq!(next_offset, 4);
        assert!(original.fields_equal(decoded.as_ref()));
        assert_eq!(original.compare_to(decoded.as_ref()), Ordering::Equal);
        assert_eq!(original.compare_to_buffer(&buf, 0), Ordering::Equal);
    }

    #[test]
    fn test_compare_to_orders_by_value() {
        let low: Box<dyn IntField> = Box::new(MockIntField::new(-10));
        let high: Box<dyn IntField> = Box::new(MockIntField::new(10));
        assert_eq!(low.compare_to(high.as_ref()), Ordering::Less);
        assert_eq!(high.compare_to(low.as_ref()), Ordering::Greater);
    }

    #[test]
    fn test_binary_data_round_trip() {
        let original: Box<dyn IntField> = Box::new(MockIntField::new(0x01020304));
        let bytes = original.get_binary_data();
        assert_eq!(bytes, vec![0x01, 0x02, 0x03, 0x04]);

        let mut restored: Box<dyn IntField> = Box::new(MockIntField::new(0));
        restored.set_binary_data(Some(&bytes)).unwrap();
        assert!(original.fields_equal(restored.as_ref()));
        assert_eq!(original.field_hash(), restored.field_hash());
    }

    #[test]
    fn test_set_binary_data_rejects_wrong_length() {
        let mut field: Box<dyn IntField> = Box::new(MockIntField::new(1));
        assert!(field.set_binary_data(Some(&[1, 2])).is_err());
    }

    #[test]
    fn test_set_binary_data_none_sets_null() {
        let mut field: Box<dyn IntField> = Box::new(MockIntField::new(7));
        field.set_binary_data(None).unwrap();
        assert!(field.is_null());
        assert_eq!(field.get_int_value(), 0);
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field: Box<dyn IntField> = Box::new(MockIntField::immutable(1));
        assert!(field.set_int_value(2).is_err());
        assert!(field.set_null().is_err());
    }

    #[test]
    fn test_min_max_value() {
        let field: Box<dyn IntField> = Box::new(MockIntField::new(0));
        assert_eq!(field.get_min_value().get_int_value(), i32::MIN);
        assert_eq!(field.get_max_value().get_int_value(), i32::MAX);
    }

    /// Mirrors `IntField.setLongValue(long)`, which is a bare `(int) value` narrowing cast with
    /// no bounds check: an out-of-range `long` silently truncates rather than erroring. We
    /// reproduce this faithfully rather than adding a range check Java doesn't have.
    #[test]
    fn test_set_long_value_silently_truncates_out_of_range() {
        let mut field: Box<dyn IntField> = Box::new(MockIntField::new(0));
        field.set_long_value(0x1_0000_0005).unwrap(); // one full i32 wrap past 5
        assert_eq!(field.get_int_value(), 5);
    }

    #[test]
    fn test_field_hash_is_raw_value() {
        let field: Box<dyn IntField> = Box::new(MockIntField::new(-1));
        assert_eq!(field.field_hash(), -1i32);
    }

    #[test]
    fn test_display_string_uses_hex_value() {
        let field: Box<dyn IntField> = Box::new(MockIntField::new(-1));
        assert_eq!(field.to_display_string(), "IntField: 0xffffffff");
    }
}
