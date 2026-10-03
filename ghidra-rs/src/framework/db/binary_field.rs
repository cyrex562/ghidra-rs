use super::buffer::Buffer;
use super::field::FieldType;
use super::illegal_field_access_exception::IllegalFieldAccessException;
use std::cmp::Ordering;

/// A wrapper for variable length binary data which is read or written to a Record.
///
/// Port of `db.BinaryField`. `BinaryField` was a concrete, `final`-ish `Field` subclass in Java
/// (a direct `Field` subclass, not a `PrimitiveField`); it is ported here as an object-safe trait
/// (a cycle cut-point) so that dependents can hold `Box<dyn BinaryField>` / `&dyn BinaryField`
/// instead of a concrete type. Implementors own the underlying `data` (`Option<Vec<u8>>`, `None`
/// standing in for a `null` byte array) and are responsible for their own construction and
/// immutability bookkeeping (mirroring the Java constructors and `Field.checkImmutable()` state
/// machine).
///
/// The Java class also exposes an `INSTANCE` static singleton field (used e.g. by `Schema` to
/// describe a binary column). That is deferred to whichever concrete implementor eventually
/// replaces the placeholder use of this trait, since a trait cannot hold `Self`-typed constants
/// while remaining object-safe.
pub trait BinaryField {
    /// Returns the field's current binary data, or `None` if null. Mirrors
    /// `BinaryField.getBinaryData()`.
    fn get_binary_data(&self) -> Option<&[u8]>;

    /// Sets the field's binary data. `None` mirrors a `null` array argument.
    ///
    /// Mirrors `BinaryField.setBinaryData(byte[])`: implementors must perform an immutable check
    /// (mirroring `Field.checkImmutable()`) before applying the new value, returning its error if
    /// the field is immutable.
    fn set_binary_data(&mut self, data: Option<&[u8]>) -> Result<(), IllegalFieldAccessException>;

    /// Constructs a copy of this field, detached from any underlying buffer. Mirrors
    /// `BinaryField.copyField()`.
    fn copy_field(&self) -> Box<dyn BinaryField>;

    /// Constructs a new, empty (null-valued) binary field. Mirrors `BinaryField.newField()`.
    fn new_field(&self) -> Box<dyn BinaryField>;

    /// The simple type name used to build [`Self::to_display_string`], mirroring
    /// `getClass().getSimpleName()` as used by `BinaryField.toString()`.
    fn type_name(&self) -> &str {
        "BinaryField"
    }

    /// Returns `true` if this field is currently null. Mirrors `BinaryField.isNull()`.
    fn is_null(&self) -> bool {
        self.get_binary_data().is_none()
    }

    /// Sets this field to a null state. Mirrors `BinaryField.setNull()`.
    fn set_null(&mut self) -> Result<(), IllegalFieldAccessException> {
        self.set_binary_data(None)
    }

    /// Encoded length in bytes of this field: 4 (length prefix only) if null, otherwise the data
    /// length plus 4. Mirrors `BinaryField.length()`.
    fn length(&self) -> usize {
        self.get_binary_data().map_or(4, |d| d.len() + 4)
    }

    /// The `Field` type tag for a binary field. Mirrors `BinaryField.getFieldType()`.
    fn get_field_type(&self) -> FieldType {
        FieldType::Binary
    }

    /// Always `true`: a binary field is variable length. Mirrors
    /// `BinaryField.isVariableLength()`.
    fn is_variable_length(&self) -> bool {
        true
    }

    /// Writes this field's length-prefixed value into `buf` at `offset`. Returns the next
    /// available offset, or -1 if the buffer is full. Mirrors `BinaryField.write(Buffer, int)`.
    fn write(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        match self.get_binary_data() {
            None => buf.put_int(offset, -1),
            Some(data) => {
                let next = buf.put_int(offset, data.len() as i32);
                if next < 0 {
                    return next;
                }
                buf.put(next as usize, data)
            }
        }
    }

    /// Reads a length-prefixed binary value from `buf` at `offset` into this field. Returns the
    /// offset immediately following the read value. Mirrors `BinaryField.read(Buffer, int)`.
    fn read(&mut self, buf: &dyn Buffer, offset: usize) -> Result<usize, IllegalFieldAccessException> {
        let len = buf.get_int(offset);
        let mut offset = offset + 4;
        if len < 0 {
            self.set_binary_data(None)?;
        } else {
            let bytes = buf.get_bytes(offset, len as usize);
            self.set_binary_data(Some(&bytes))?;
            offset += len as usize;
        }
        Ok(offset)
    }

    /// Length in bytes of the encoded value at `offset` within `buf`, without altering this
    /// instance. Mirrors `BinaryField.readLength(Buffer, int)`.
    fn read_length(&self, buf: &dyn Buffer, offset: usize) -> usize {
        let len = buf.get_int(offset);
        (if len < 0 { 0 } else { len as usize }) + 4
    }

    /// Truncates the stored data so its encoded length does not exceed `length` bytes total
    /// (i.e. at most `length - 4` bytes of raw data). No-op if already within bounds. Mirrors
    /// `BinaryField.truncate(int)`.
    fn truncate(&mut self, length: usize) -> Result<(), IllegalFieldAccessException> {
        let max_len = length.saturating_sub(4);
        let needs_truncate = matches!(self.get_binary_data(), Some(d) if d.len() > max_len);
        if needs_truncate {
            let truncated = self.get_binary_data().unwrap()[..max_len].to_vec();
            self.set_binary_data(Some(&truncated))?;
        }
        Ok(())
    }

    /// Compares this field's value to `other`'s value: null sorts before non-null, otherwise
    /// lexicographic (unsigned) byte comparison with shorter-is-less on a common prefix. Mirrors
    /// `BinaryField.compareTo(Field)`.
    fn compare_to(&self, other: &dyn BinaryField) -> Ordering {
        match (self.get_binary_data(), other.get_binary_data()) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => {
                for (x, y) in a.iter().zip(b.iter()) {
                    match x.cmp(y) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                a.len().cmp(&b.len())
            }
        }
    }

    /// Compares this field's value to the length-prefixed binary value encoded in `buffer` at
    /// `offset`, without decoding a full field. Mirrors `BinaryField.compareTo(DataBuffer, int)`.
    fn compare_to_buffer(&self, buffer: &dyn Buffer, offset: usize) -> Ordering {
        let len = buffer.get_int(offset);
        match self.get_binary_data() {
            None => {
                if len < 0 {
                    Ordering::Equal
                } else {
                    Ordering::Less
                }
            }
            Some(data) => {
                if len < 0 {
                    return Ordering::Greater;
                }
                let other = buffer.get_bytes(offset + 4, len as usize);
                for (x, y) in data.iter().zip(other.iter()) {
                    match x.cmp(y) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                data.len().cmp(&other.len())
            }
        }
    }

    /// Always `None`: mirrors `BinaryField.getMinValue()`, which unconditionally throws
    /// `UnsupportedOperationException` in Java.
    fn get_min_value(&self) -> Option<Box<dyn BinaryField>> {
        None
    }

    /// Always `None`: mirrors `BinaryField.getMaxValue()`, which unconditionally throws
    /// `UnsupportedOperationException` in Java.
    fn get_max_value(&self) -> Option<Box<dyn BinaryField>> {
        None
    }

    /// Whether `other` has the same binary data as this instance. Mirrors
    /// `BinaryField.equals(Object)`.
    fn fields_equal(&self, other: &dyn BinaryField) -> bool {
        self.get_binary_data() == other.get_binary_data()
    }

    /// Deterministic hash over this field's binary data, matching Java's `byte`-to-`int`
    /// sign-extended-widening-free (`& 0xff`) accumulation. Mirrors `BinaryField.hashCode()`.
    fn field_hash(&self) -> i32 {
        match self.get_binary_data() {
            None => 0,
            Some(data) => data.iter().fold(0i32, |h, &b| h.wrapping_mul(31).wrapping_add(b as i32)),
        }
    }

    /// Display form: `"<TypeName>(NULL): null"` when null, otherwise
    /// `"<TypeName>: [<len>] = 0x<hex preview>"`. Mirrors `BinaryField.toString()`.
    fn to_display_string(&self) -> String {
        let null_state = if self.is_null() { "(NULL)" } else { "" };
        match self.get_binary_data() {
            None => format!("{}{}: null", self.type_name(), null_state),
            Some(d) => format!("{}{}: [{}] = 0x{}", self.type_name(), null_state, d.len(), format_hex_preview(d)),
        }
    }

    /// Human-readable value form: `"null"` when null, otherwise `"{<hex preview>}"`. Mirrors
    /// `BinaryField.getValueAsString()`.
    fn get_value_as_string(&self) -> String {
        match self.get_binary_data() {
            None => "null".to_string(),
            Some(d) => format!("{{{}}}", format_hex_preview(d)),
        }
    }
}

/// Get format value string for a byte array: up to the first 24 bytes as space-separated,
/// zero-padded lowercase hex, followed by `"..."` if truncated. Mirrors the static
/// `BinaryField.getValueAsString(byte[])` helper.
pub fn format_hex_preview(data: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i < 24 && i < data.len() {
        s.push_str(&format!("{:02x} ", data[i]));
        i += 1;
    }
    if i < data.len() {
        s.push_str("...");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBinaryField {
        data: Option<Vec<u8>>,
        immutable: bool,
    }

    impl MockBinaryField {
        fn new(data: Option<Vec<u8>>) -> Self {
            Self { data, immutable: false }
        }

        fn immutable(data: Vec<u8>) -> Self {
            Self { data: Some(data), immutable: true }
        }
    }

    impl BinaryField for MockBinaryField {
        fn get_binary_data(&self) -> Option<&[u8]> {
            self.data.as_deref()
        }

        fn set_binary_data(&mut self, data: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.data = data.map(|d| d.to_vec());
            Ok(())
        }

        fn copy_field(&self) -> Box<dyn BinaryField> {
            Box::new(MockBinaryField::new(self.data.clone()))
        }

        fn new_field(&self) -> Box<dyn BinaryField> {
            Box::new(MockBinaryField::new(None))
        }
    }

    #[test]
    fn test_object_safety_and_value_roundtrip() {
        let mut field: Box<dyn BinaryField> = Box::new(MockBinaryField::new(None));
        assert!(field.is_null());

        field.set_binary_data(Some(&[1, 2, 3])).unwrap();
        assert!(!field.is_null());
        assert_eq!(field.get_binary_data(), Some(&[1u8, 2, 3][..]));
        assert_eq!(field.length(), 3 + 4);
    }

    #[test]
    fn test_write_read_round_trip() {
        use super::super::buffer::DataBuffer;

        let original: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![9, 8, 7, 6, 5])));
        let mut buf = DataBuffer::new(0, original.length());
        let end = original.write(&mut buf, 0);
        assert_eq!(end, original.length() as isize);

        let mut decoded: Box<dyn BinaryField> = Box::new(MockBinaryField::new(None));
        let next_offset = decoded.read(&buf, 0).unwrap();
        assert_eq!(next_offset, original.length());
        assert!(original.fields_equal(decoded.as_ref()));
        assert_eq!(original.compare_to(decoded.as_ref()), Ordering::Equal);
        assert_eq!(original.compare_to_buffer(&buf, 0), Ordering::Equal);
        assert_eq!(original.read_length(&buf, 0), original.length());
    }

    #[test]
    fn test_write_read_null_round_trip() {
        use super::super::buffer::DataBuffer;

        let original: Box<dyn BinaryField> = Box::new(MockBinaryField::new(None));
        let mut buf = DataBuffer::new(0, original.length());
        original.write(&mut buf, 0);

        let mut decoded: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![1])));
        let next_offset = decoded.read(&buf, 0).unwrap();
        assert_eq!(next_offset, 4);
        assert!(decoded.is_null());
    }

    #[test]
    fn test_compare_to_orders_by_prefix_then_length() {
        let null_field: Box<dyn BinaryField> = Box::new(MockBinaryField::new(None));
        let short_field: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![1, 2])));
        let long_field: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![1, 2, 3])));
        let other_field: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![1, 3])));

        assert_eq!(null_field.compare_to(short_field.as_ref()), Ordering::Less);
        assert_eq!(short_field.compare_to(null_field.as_ref()), Ordering::Greater);
        assert_eq!(short_field.compare_to(long_field.as_ref()), Ordering::Less);
        assert_eq!(short_field.compare_to(other_field.as_ref()), Ordering::Less);
    }

    #[test]
    fn test_truncate() {
        let mut field: Box<dyn BinaryField> =
            Box::new(MockBinaryField::new(Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])));
        field.truncate(8).unwrap();
        assert_eq!(field.get_binary_data(), Some(&[1u8, 2, 3, 4][..]));

        // No-op when already within bounds.
        field.truncate(100).unwrap();
        assert_eq!(field.get_binary_data(), Some(&[1u8, 2, 3, 4][..]));
    }

    #[test]
    fn test_field_hash_and_equals() {
        let a: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![1, 2, 3])));
        let b: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![1, 2, 3])));
        let c: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![1, 2, 4])));

        assert!(a.fields_equal(b.as_ref()));
        assert_eq!(a.field_hash(), b.field_hash());
        assert!(!a.fields_equal(c.as_ref()));
        assert_ne!(a.field_hash(), c.field_hash());
    }

    #[test]
    fn test_min_max_value_unsupported() {
        let field: Box<dyn BinaryField> = Box::new(MockBinaryField::new(None));
        assert!(field.get_min_value().is_none());
        assert!(field.get_max_value().is_none());
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field: Box<dyn BinaryField> = Box::new(MockBinaryField::immutable(vec![1]));
        assert!(field.set_binary_data(Some(&[2])).is_err());
        assert!(field.set_null().is_err());
    }

    #[test]
    fn test_display_and_value_string() {
        let null_field: Box<dyn BinaryField> = Box::new(MockBinaryField::new(None));
        assert_eq!(null_field.to_display_string(), "BinaryField(NULL): null");
        assert_eq!(null_field.get_value_as_string(), "null");

        let data_field: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![0xab, 0x01])));
        assert_eq!(data_field.to_display_string(), "BinaryField: [2] = 0xab 01 ");
        assert_eq!(data_field.get_value_as_string(), "{ab 01 }");
    }

    #[test]
    fn test_copy_field_and_new_field() {
        let field: Box<dyn BinaryField> = Box::new(MockBinaryField::new(Some(vec![5, 6])));
        let copy = field.copy_field();
        assert!(field.fields_equal(copy.as_ref()));

        let fresh = field.new_field();
        assert!(fresh.is_null());
    }
}
