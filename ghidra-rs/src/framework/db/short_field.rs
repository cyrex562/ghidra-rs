use super::buffer::Buffer;
use super::field::FieldType;
use super::illegal_field_access_exception::IllegalFieldAccessException;
use super::primitive_field::PrimitiveField;
use std::cmp::Ordering;

/// A [`PrimitiveField`] wrapper for a 2-byte signed short value read from or written to a Record.
///
/// Port of `db.ShortField`. `ShortField` was a concrete, `final` `PrimitiveField` subclass in
/// Java; it is ported here as an object-safe trait (a cycle cut-point) so that dependents can
/// hold `Box<dyn ShortField>` / `&dyn ShortField` instead of a concrete type, mirroring the
/// pattern established by [`super::byte_field::ByteField`]. Implementors own the underlying
/// `value` and are responsible for their own construction and null/immutable bookkeeping
/// (mirroring the Java constructors and `PrimitiveField` state machine).
///
/// The Java class also exposes `MIN_VALUE`, `MAX_VALUE`, `ZERO_VALUE`, and `INSTANCE` static
/// singleton fields (used e.g. by `Schema` to describe a short column). Those are deferred to
/// whichever concrete implementor eventually replaces the placeholder use of this trait, since a
/// trait cannot hold `Self`-typed constants while remaining object-safe.
pub trait ShortField: PrimitiveField {
    /// Returns the field's current short value. Mirrors `ShortField.getShortValue()`.
    fn get_short_value(&self) -> i16;

    /// Sets the field's short value.
    ///
    /// Mirrors `ShortField.setShortValue(short)`: implementors must invoke
    /// [`PrimitiveField::updating_primitive_value`] (or an equivalent immutable/null check)
    /// before applying the new value, returning its error if the field is immutable.
    fn set_short_value(&mut self, value: i16) -> Result<(), IllegalFieldAccessException>;

    /// Constructs a copy of this field, detached from any underlying buffer. Mirrors
    /// `ShortField.copyField()`.
    fn copy_field(&self) -> Box<dyn ShortField>;

    /// Constructs a new, empty (zero-valued, non-null-forced) short field. Mirrors
    /// `ShortField.newField()`.
    fn new_field(&self) -> Box<dyn ShortField>;

    /// Returns the minimum representable short field value (`Short.MIN_VALUE`). Mirrors
    /// `ShortField.getMinValue()`.
    fn get_min_value(&self) -> Box<dyn ShortField>;

    /// Returns the maximum representable short field value (`Short.MAX_VALUE`). Mirrors
    /// `ShortField.getMaxValue()`.
    fn get_max_value(&self) -> Box<dyn ShortField>;

    /// Encoded length in bytes of this field. Mirrors `ShortField.length()`.
    fn length(&self) -> usize {
        2
    }

    /// The `Field` type tag for a short field. Mirrors `ShortField.getFieldType()`.
    fn get_field_type(&self) -> FieldType {
        FieldType::Short
    }

    /// Writes this field's value into `buf` at `offset`. Returns the next available offset, or
    /// -1 if the buffer is full. Mirrors `ShortField.write(Buffer, int)`.
    fn write(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        buf.put_short(offset, self.get_short_value())
    }

    /// Reads a short value from `buf` at `offset` into this field, clearing any null state.
    /// Returns the offset immediately following the read value. Mirrors
    /// `ShortField.read(Buffer, int)`.
    fn read(&mut self, buf: &dyn Buffer, offset: usize) -> Result<usize, IllegalFieldAccessException> {
        let v = buf.get_short(offset);
        self.set_short_value(v)?;
        Ok(offset + 2)
    }

    /// Length in bytes of the encoded value at `offset` within `buf`, without altering this
    /// instance. Always 2 for a short field. Mirrors `ShortField.readLength(Buffer, int)`.
    fn read_length(&self, _buf: &dyn Buffer, _offset: usize) -> usize {
        2
    }

    /// Compares this field's value to `other`'s value. Mirrors `ShortField.compareTo(Field)`.
    fn compare_to(&self, other: &dyn ShortField) -> Ordering {
        self.get_short_value().cmp(&other.get_short_value())
    }

    /// Compares this field's value to the short value encoded in `buffer` at `offset`, without
    /// decoding a full field. Mirrors `ShortField.compareTo(DataBuffer, int)`.
    fn compare_to_buffer(&self, buffer: &dyn Buffer, offset: usize) -> Ordering {
        let other_value = buffer.get_short(offset);
        self.get_short_value().cmp(&other_value)
    }

    /// Returns this field's value widened to `i64`. Mirrors `ShortField.getLongValue()`.
    fn get_long_value(&self) -> i64 {
        self.get_short_value() as i64
    }

    /// Sets this field's value, narrowing from `i64`. Mirrors `ShortField.setLongValue(long)`: a
    /// plain narrowing cast with no range check, so out-of-`i16`-range input silently truncates.
    fn set_long_value(&mut self, value: i64) -> Result<(), IllegalFieldAccessException> {
        self.set_short_value(value as i16)
    }

    /// Returns this field's value as a 2-byte big-endian array. Mirrors
    /// `ShortField.getBinaryData()`.
    fn get_binary_data(&self) -> Vec<u8> {
        self.get_short_value().to_be_bytes().to_vec()
    }

    /// Sets this field's value from `bytes`.
    ///
    /// `None` mirrors a `null` array argument (sets this field null). `Some(bytes)` with a length
    /// other than 2 mirrors `IllegalFieldAccessException`. Mirrors
    /// `ShortField.setBinaryData(byte[])`.
    fn set_binary_data(&mut self, bytes: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
        match bytes {
            None => self.set_null(),
            Some(b) if b.len() != 2 => Err(IllegalFieldAccessException::new()),
            Some(b) => {
                let mut arr = [0u8; 2];
                arr.copy_from_slice(b);
                self.set_short_value(i16::from_be_bytes(arr))
            }
        }
    }

    /// Whether `other` has the same short value as this instance. Mirrors
    /// `ShortField.equals(Object)`.
    fn fields_equal(&self, other: &dyn ShortField) -> bool {
        self.get_short_value() == other.get_short_value()
    }

    /// Deterministic hash over this field's value, matching Java's `short`-to-`int` sign-extending
    /// widening conversion used by `return value;` inside `int hashCode()`. Note this differs
    /// from [`Self::get_value_as_string`]'s `value & 0xffff` masking -- the same underlying value
    /// is sign-extended for the hash but zero-extended for display, matching the Java source
    /// exactly (`ShortField.hashCode()` vs `ShortField.getValueAsString()`). Mirrors
    /// `ShortField.hashCode()`.
    fn field_hash(&self) -> i32 {
        self.get_short_value() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockShortField {
        value: i16,
        is_null: bool,
        immutable: bool,
    }

    impl MockShortField {
        fn new(value: i16) -> Self {
            Self { value, is_null: false, immutable: false }
        }

        fn immutable(value: i16) -> Self {
            Self { value, is_null: false, immutable: true }
        }
    }

    impl PrimitiveField for MockShortField {
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
            format!("0x{:x}", (self.value as u16) & 0xffff)
        }

        fn type_name(&self) -> &str {
            "ShortField"
        }
    }

    impl ShortField for MockShortField {
        fn get_short_value(&self) -> i16 {
            self.value
        }

        fn set_short_value(&mut self, value: i16) -> Result<(), IllegalFieldAccessException> {
            self.updating_primitive_value()?;
            self.value = value;
            Ok(())
        }

        fn copy_field(&self) -> Box<dyn ShortField> {
            if self.is_null {
                let mut copy = MockShortField::new(0);
                copy.set_null().unwrap();
                Box::new(copy)
            } else {
                Box::new(MockShortField::new(self.value))
            }
        }

        fn new_field(&self) -> Box<dyn ShortField> {
            Box::new(MockShortField::new(0))
        }

        fn get_min_value(&self) -> Box<dyn ShortField> {
            Box::new(MockShortField::immutable(i16::MIN))
        }

        fn get_max_value(&self) -> Box<dyn ShortField> {
            Box::new(MockShortField::immutable(i16::MAX))
        }
    }

    #[test]
    fn test_object_safety_and_value_roundtrip() {
        let mut field: Box<dyn ShortField> = Box::new(MockShortField::new(0));
        assert_eq!(field.get_short_value(), 0);

        field.set_short_value(-500).unwrap();
        assert_eq!(field.get_short_value(), -500);
        assert_eq!(field.get_long_value(), -500);
        assert!(!field.is_null());
    }

    #[test]
    fn test_write_read_round_trip() {
        use super::super::buffer::DataBuffer;

        let original: Box<dyn ShortField> = Box::new(MockShortField::new(-12345));
        let mut buf = DataBuffer::new(0, original.length());
        let end = original.write(&mut buf, 0);
        assert_eq!(end, original.length() as isize);

        let mut decoded: Box<dyn ShortField> = Box::new(MockShortField::new(0));
        let next_offset = decoded.read(&buf, 0).unwrap();
        assert_eq!(next_offset, 2);
        assert!(original.fields_equal(decoded.as_ref()));
        assert_eq!(original.compare_to(decoded.as_ref()), Ordering::Equal);
        assert_eq!(original.compare_to_buffer(&buf, 0), Ordering::Equal);
    }

    #[test]
    fn test_compare_to_orders_by_value() {
        let low: Box<dyn ShortField> = Box::new(MockShortField::new(-10));
        let high: Box<dyn ShortField> = Box::new(MockShortField::new(10));
        assert_eq!(low.compare_to(high.as_ref()), Ordering::Less);
        assert_eq!(high.compare_to(low.as_ref()), Ordering::Greater);
    }

    #[test]
    fn test_binary_data_round_trip() {
        let original: Box<dyn ShortField> = Box::new(MockShortField::new(0x0102));
        let bytes = original.get_binary_data();
        assert_eq!(bytes, vec![0x01, 0x02]);

        let mut restored: Box<dyn ShortField> = Box::new(MockShortField::new(0));
        restored.set_binary_data(Some(&bytes)).unwrap();
        assert!(original.fields_equal(restored.as_ref()));
        assert_eq!(original.field_hash(), restored.field_hash());
    }

    #[test]
    fn test_set_binary_data_rejects_wrong_length() {
        let mut field: Box<dyn ShortField> = Box::new(MockShortField::new(1));
        assert!(field.set_binary_data(Some(&[1, 2, 3])).is_err());
    }

    #[test]
    fn test_set_binary_data_none_sets_null() {
        let mut field: Box<dyn ShortField> = Box::new(MockShortField::new(7));
        field.set_binary_data(None).unwrap();
        assert!(field.is_null());
        assert_eq!(field.get_short_value(), 0);
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field: Box<dyn ShortField> = Box::new(MockShortField::immutable(1));
        assert!(field.set_short_value(2).is_err());
        assert!(field.set_null().is_err());
    }

    #[test]
    fn test_min_max_value() {
        let field: Box<dyn ShortField> = Box::new(MockShortField::new(0));
        assert_eq!(field.get_min_value().get_short_value(), i16::MIN);
        assert_eq!(field.get_max_value().get_short_value(), i16::MAX);
    }

    /// Mirrors `ShortField.setLongValue(long)`, a bare `(short) value` narrowing cast with no
    /// bounds check.
    #[test]
    fn test_set_long_value_silently_truncates_out_of_range() {
        let mut field: Box<dyn ShortField> = Box::new(MockShortField::new(0));
        field.set_long_value(0x10005).unwrap(); // one full i16 wrap past 5
        assert_eq!(field.get_short_value(), 5);
    }

    /// Demonstrates the sign-extend-vs-zero-extend asymmetry between `hashCode()` (sign-extending
    /// widening of the raw `short`) and `getValueAsString()` (`value & 0xffff` masking) called out
    /// in `field_hash`'s doc comment: the same -1 value hashes as a negative `i32` but displays as
    /// `0xffff`.
    #[test]
    fn test_field_hash_sign_extends_but_display_zero_extends() {
        let field: Box<dyn ShortField> = Box::new(MockShortField::new(-1));
        assert_eq!(field.field_hash(), -1i32);
        assert_eq!(field.to_display_string(), "ShortField: 0xffff");
    }
}
