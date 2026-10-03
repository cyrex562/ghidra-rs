use super::buffer::Buffer;
use super::field::FieldType;
use super::illegal_field_access_exception::IllegalFieldAccessException;
use std::cmp::Ordering;

/// A wrapper for variable length UTF-8 `String` data which is read or written to a Record.
///
/// Port of `db.StringField`. `StringField` was a concrete, `final` `Field` subclass in Java (a
/// direct `Field` subclass -- it does **not** extend `PrimitiveField` or `FixedField`, and its own
/// `FixedField`-adjacent naming in this crate's task description was a documentation error on the
/// Java side that does not hold up against the real source); it is ported here as an object-safe
/// trait (a cycle cut-point) so that dependents can hold `Box<dyn StringField>` / `&dyn
/// StringField` instead of a concrete type, mirroring the pattern established by
/// [`super::binary_field::BinaryField`] (also a direct, non-`PrimitiveField` `Field` subclass).
/// Implementors own the underlying `Option<String>` (`None` standing in for a `null` string) and
/// are responsible for their own construction and immutability bookkeeping (mirroring the Java
/// constructors and `Field.checkImmutable()` state machine).
///
/// The Java class also exposes `NULL_VALUE` and `INSTANCE` static singleton fields (used e.g. by
/// `Schema` to describe a string column). Those are deferred to whichever concrete implementor
/// eventually replaces the placeholder use of this trait, since a trait cannot hold `Self`-typed
/// constants while remaining object-safe.
///
/// # Known divergence: raw bytes vs. decoded `String`
///
/// Java's `StringField` caches both the decoded `String` *and* the raw encoded `byte[]` it was
/// read from, and `getBinaryData()` returns the cached raw bytes verbatim -- even if those bytes
/// were not valid UTF-8 (Java's `new String(bytes, "UTF-8")` silently replaces malformed
/// sequences with `U+FFFD` on decode, but does not alter the cached `bytes` array itself). A Rust
/// `String` is always valid UTF-8 and cannot hold onto the original malformed bytes once decoded,
/// so [`Self::get_binary_data`]'s default implementation here always re-encodes from the
/// (possibly lossily-decoded) `String`. For well-formed UTF-8 input (the overwhelming common
/// case) this is byte-for-byte identical to Java; only hand-crafted malformed-UTF-8 buffers would
/// observe a difference on a decode-then-reencode round trip.
pub trait StringField {
    /// Returns the field's current string value, or `None` if null. Mirrors
    /// `StringField.getString()`.
    fn get_string(&self) -> Option<&str>;

    /// Sets the field's string value. `None` mirrors a `null` argument.
    ///
    /// Mirrors `StringField.setString(String)`: implementors must perform an immutable check
    /// (mirroring `Field.checkImmutable()`) before applying the new value, returning its error if
    /// the field is immutable.
    fn set_string(&mut self, value: Option<&str>) -> Result<(), IllegalFieldAccessException>;

    /// Constructs a copy of this field, detached from any underlying buffer. Mirrors
    /// `StringField.copyField()`.
    fn copy_field(&self) -> Box<dyn StringField>;

    /// Constructs a new, empty (null-valued) string field. Mirrors `StringField.newField()`.
    fn new_field(&self) -> Box<dyn StringField>;

    /// Returns `true` if this field is currently null. Mirrors `StringField.isNull()`.
    fn is_null(&self) -> bool {
        self.get_string().is_none()
    }

    /// Sets this field to a null state. Mirrors `StringField.setNull()`.
    fn set_null(&mut self) -> Result<(), IllegalFieldAccessException> {
        self.set_string(None)
    }

    /// Encoded length in bytes of this field: 4 (length prefix only) if null, otherwise the UTF-8
    /// byte length plus 4. Mirrors `StringField.length()`.
    fn length(&self) -> usize {
        self.get_string().map_or(4, |s| s.len() + 4)
    }

    /// The `Field` type tag for a string field. Mirrors `StringField.getFieldType()`.
    fn get_field_type(&self) -> FieldType {
        FieldType::String
    }

    /// Always `true`: a string field is variable length. Mirrors
    /// `StringField.isVariableLength()`.
    fn is_variable_length(&self) -> bool {
        true
    }

    /// Writes this field's length-prefixed UTF-8 value into `buf` at `offset`. Returns the next
    /// available offset, or -1 if the buffer is full. Mirrors `StringField.write(Buffer, int)`.
    fn write(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        match self.get_string() {
            None => buf.put_int(offset, -1),
            Some(s) => {
                let next = buf.put_int(offset, s.len() as i32);
                if next < 0 {
                    return next;
                }
                buf.put(next as usize, s.as_bytes())
            }
        }
    }

    /// Reads a length-prefixed UTF-8 value from `buf` at `offset` into this field. Malformed UTF-8
    /// is replaced per `String::from_utf8_lossy` (Java's `new String(bytes, "UTF-8")` similarly
    /// replaces malformed sequences on decode, though see the trait-level doc comment for the
    /// re-encode-on-read divergence). Returns the offset immediately following the read value.
    /// Mirrors `StringField.read(Buffer, int)`.
    fn read(&mut self, buf: &dyn Buffer, offset: usize) -> Result<usize, IllegalFieldAccessException> {
        let len = buf.get_int(offset);
        let mut offset = offset + 4;
        if len < 0 {
            self.set_null()?;
        } else {
            let raw = buf.get_bytes(offset, len as usize);
            let decoded = String::from_utf8_lossy(&raw).into_owned();
            self.set_string(Some(&decoded))?;
            offset += len as usize;
        }
        Ok(offset)
    }

    /// Length in bytes of the encoded value at `offset` within `buf`, without altering this
    /// instance. Mirrors `StringField.readLength(Buffer, int)`.
    fn read_length(&self, buf: &dyn Buffer, offset: usize) -> usize {
        let len = buf.get_int(offset);
        (if len < 0 { 0 } else { len as usize }) + 4
    }

    /// Truncates the stored string so its encoded length does not exceed `length` bytes total.
    ///
    /// Faithful port of `StringField.truncate(int)` (Java `StringField.java`, ~line 197), which
    /// contains a genuine bug: it compares `str.length()` -- a UTF-16 *code-unit* count -- against
    /// `maxLen = length - 4`, even though `length` (and the field's actual encoded `length()`) is
    /// expressed in *UTF-8 encoded bytes*, and, when truncation does trigger, truncates via
    /// `str.substring(0, maxLen)` -- again a code-unit-count operation, not a byte-count one. For
    /// any string containing non-ASCII characters this under-truncates: the truncated field's
    /// actual encoded byte length can still exceed the requested `length`. We reproduce this
    /// exactly (using `encode_utf16().count()` as the closest Rust equivalent of Java's
    /// UTF-16-code-unit `String.length()`) rather than fixing it -- see the accompanying test
    /// `test_truncate_under_truncates_multibyte_strings`.
    fn truncate(&mut self, length: usize) -> Result<(), IllegalFieldAccessException> {
        let max_len = length.saturating_sub(4);
        if let Some(s) = self.get_string() {
            let code_unit_len = s.encode_utf16().count();
            if code_unit_len > max_len {
                let units: Vec<u16> = s.encode_utf16().take(max_len).collect();
                let truncated = String::from_utf16_lossy(&units);
                self.set_string(Some(&truncated))?;
            }
        }
        Ok(())
    }

    /// Compares this field's value to `other`'s value: null sorts before non-null, otherwise
    /// lexicographic comparison of the two strings. Mirrors `StringField.compareTo(Field)`.
    fn compare_to(&self, other: &dyn StringField) -> Ordering {
        match (self.get_string(), other.get_string()) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }

    /// Compares this field's value to the length-prefixed UTF-8 value encoded in `buffer` at
    /// `offset`, without decoding a full field. Mirrors `StringField.compareTo(DataBuffer, int)`.
    fn compare_to_buffer(&self, buffer: &dyn Buffer, offset: usize) -> Ordering {
        let len = buffer.get_int(offset);
        let other: Option<String> = if len < 0 {
            None
        } else {
            let raw = buffer.get_bytes(offset + 4, len as usize);
            Some(String::from_utf8_lossy(&raw).into_owned())
        };
        match (self.get_string(), other.as_deref()) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }

    /// Always `None`: mirrors `StringField.getMinValue()`, which unconditionally throws
    /// `UnsupportedOperationException` in Java.
    fn get_min_value(&self) -> Option<Box<dyn StringField>> {
        None
    }

    /// Always `None`: mirrors `StringField.getMaxValue()`, which unconditionally throws
    /// `UnsupportedOperationException` in Java.
    fn get_max_value(&self) -> Option<Box<dyn StringField>> {
        None
    }

    /// Returns this field's UTF-8 encoded value, or `None` if null. Mirrors
    /// `StringField.getBinaryData()` -- see the trait-level doc comment for the raw-bytes-vs-decoded-
    /// `String` divergence for malformed UTF-8 input.
    fn get_binary_data(&self) -> Option<&[u8]> {
        self.get_string().map(|s| s.as_bytes())
    }

    /// Sets this field's value by decoding `bytes` as UTF-8 (lossily, replacing malformed
    /// sequences). `None` mirrors a `null` array argument (sets this field null). Mirrors
    /// `StringField.setBinaryData(byte[])`.
    fn set_binary_data(&mut self, bytes: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
        match bytes {
            None => self.set_string(None),
            Some(b) => {
                let decoded = String::from_utf8_lossy(b).into_owned();
                self.set_string(Some(&decoded))
            }
        }
    }

    /// Whether `other` has the same string value as this instance. Mirrors
    /// `StringField.equals(Object)`.
    fn fields_equal(&self, other: &dyn StringField) -> bool {
        self.get_string() == other.get_string()
    }

    /// Deterministic hash over this field's string value, computed exactly like Java's
    /// `String.hashCode()` (`s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]` over UTF-16 code
    /// units).
    ///
    /// # Panics
    ///
    /// Faithful port of a genuine bug in `StringField.hashCode()` (Java `StringField.java`, ~line
    /// 211): it unconditionally calls `str.hashCode()` with **no null check**, so hashing a null
    /// `StringField` throws `NullPointerException` in Java. We reproduce this by panicking rather
    /// than silently returning e.g. `0`. See `test_field_hash_panics_when_null`.
    fn field_hash(&self) -> i32 {
        let s = self.get_string().expect(
            "StringField.hashCode() NPE: field is null (faithful port of a real Java bug -- \
             StringField.java calls str.hashCode() with no null check)",
        );
        let mut hash: i32 = 0;
        for unit in s.encode_utf16() {
            hash = hash.wrapping_mul(31).wrapping_add(unit as i32);
        }
        hash
    }

    /// Display form: `"StringField: <value>"`, where `<value>` is the literal text `null` when
    /// this field is null (matching Java string concatenation's `null`-to-`"null"` conversion).
    /// Note this is hardcoded to the literal name `StringField` rather than derived from a
    /// `type_name()`-style customization point, matching the real
    /// `StringField.toString()` (which is likewise hardcoded, unlike `PrimitiveField.toString()`
    /// / `BinaryField.toString()`).
    fn to_display_string(&self) -> String {
        format!("StringField: {}", self.get_string().unwrap_or("null"))
    }

    /// Human-readable value form: `"null"` when null, otherwise the string wrapped in double
    /// quotes. Mirrors `StringField.getValueAsString()`.
    fn get_value_as_string(&self) -> String {
        match self.get_string() {
            None => "null".to_string(),
            Some(s) => format!("\"{}\"", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockStringField {
        value: Option<String>,
        immutable: bool,
    }

    impl MockStringField {
        fn new(value: Option<&str>) -> Self {
            Self { value: value.map(|s| s.to_string()), immutable: false }
        }

        fn immutable(value: &str) -> Self {
            Self { value: Some(value.to_string()), immutable: true }
        }
    }

    impl StringField for MockStringField {
        fn get_string(&self) -> Option<&str> {
            self.value.as_deref()
        }

        fn set_string(&mut self, value: Option<&str>) -> Result<(), IllegalFieldAccessException> {
            if self.immutable {
                return Err(IllegalFieldAccessException::with_message("immutable field instance"));
            }
            self.value = value.map(|s| s.to_string());
            Ok(())
        }

        fn copy_field(&self) -> Box<dyn StringField> {
            Box::new(MockStringField::new(self.value.as_deref()))
        }

        fn new_field(&self) -> Box<dyn StringField> {
            Box::new(MockStringField::new(None))
        }
    }

    #[test]
    fn test_object_safety_and_value_roundtrip() {
        let mut field: Box<dyn StringField> = Box::new(MockStringField::new(None));
        assert!(field.is_null());

        field.set_string(Some("hello")).unwrap();
        assert!(!field.is_null());
        assert_eq!(field.get_string(), Some("hello"));
        assert_eq!(field.length(), 5 + 4);
    }

    #[test]
    fn test_write_read_round_trip() {
        use super::super::buffer::DataBuffer;

        let original: Box<dyn StringField> = Box::new(MockStringField::new(Some("Ghidra")));
        let mut buf = DataBuffer::new(0, original.length());
        let end = original.write(&mut buf, 0);
        assert_eq!(end, original.length() as isize);

        let mut decoded: Box<dyn StringField> = Box::new(MockStringField::new(None));
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

        let original: Box<dyn StringField> = Box::new(MockStringField::new(None));
        let mut buf = DataBuffer::new(0, original.length());
        original.write(&mut buf, 0);

        let mut decoded: Box<dyn StringField> = Box::new(MockStringField::new(Some("x")));
        let next_offset = decoded.read(&buf, 0).unwrap();
        assert_eq!(next_offset, 4);
        assert!(decoded.is_null());
    }

    #[test]
    fn test_compare_to_orders_null_first_then_lexicographic() {
        let null_field: Box<dyn StringField> = Box::new(MockStringField::new(None));
        let a_field: Box<dyn StringField> = Box::new(MockStringField::new(Some("a")));
        let b_field: Box<dyn StringField> = Box::new(MockStringField::new(Some("b")));

        assert_eq!(null_field.compare_to(a_field.as_ref()), Ordering::Less);
        assert_eq!(a_field.compare_to(null_field.as_ref()), Ordering::Greater);
        assert_eq!(a_field.compare_to(b_field.as_ref()), Ordering::Less);
    }

    #[test]
    fn test_binary_data_round_trip() {
        let original: Box<dyn StringField> = Box::new(MockStringField::new(Some("hi")));
        let bytes = original.get_binary_data().unwrap().to_vec();
        assert_eq!(bytes, b"hi".to_vec());

        let mut restored: Box<dyn StringField> = Box::new(MockStringField::new(None));
        restored.set_binary_data(Some(&bytes)).unwrap();
        assert!(original.fields_equal(restored.as_ref()));
        assert_eq!(original.field_hash(), restored.field_hash());
    }

    #[test]
    fn test_immutable_rejects_mutation() {
        let mut field: Box<dyn StringField> = Box::new(MockStringField::immutable("x"));
        assert!(field.set_string(Some("y")).is_err());
        assert!(field.set_null().is_err());
    }

    #[test]
    fn test_min_max_value_unsupported() {
        let field: Box<dyn StringField> = Box::new(MockStringField::new(None));
        assert!(field.get_min_value().is_none());
        assert!(field.get_max_value().is_none());
    }

    #[test]
    fn test_display_and_value_string() {
        let null_field: Box<dyn StringField> = Box::new(MockStringField::new(None));
        assert_eq!(null_field.to_display_string(), "StringField: null");
        assert_eq!(null_field.get_value_as_string(), "null");

        let data_field: Box<dyn StringField> = Box::new(MockStringField::new(Some("hi")));
        assert_eq!(data_field.to_display_string(), "StringField: hi");
        assert_eq!(data_field.get_value_as_string(), "\"hi\"");
    }

    #[test]
    fn test_copy_field_and_new_field() {
        let field: Box<dyn StringField> = Box::new(MockStringField::new(Some("copy me")));
        let copy = field.copy_field();
        assert!(field.fields_equal(copy.as_ref()));

        let fresh = field.new_field();
        assert!(fresh.is_null());
    }

    #[test]
    fn test_field_hash_matches_java_string_hashcode_algorithm() {
        // Java: "abc".hashCode() == 96354
        let field: Box<dyn StringField> = Box::new(MockStringField::new(Some("abc")));
        assert_eq!(field.field_hash(), 96354);
    }

    /// See the `field_hash` doc comment: `StringField.hashCode()` throws `NullPointerException`
    /// in Java when the field is null, because it unconditionally calls `str.hashCode()`. We
    /// faithfully reproduce this as a panic rather than "fixing" it to e.g. return 0.
    #[test]
    #[should_panic(expected = "StringField.hashCode() NPE")]
    fn test_field_hash_panics_when_null() {
        let field: Box<dyn StringField> = Box::new(MockStringField::new(None));
        field.field_hash();
    }

    /// Faithful port of the `StringField.truncate(int)` bug documented on the trait's `truncate`
    /// method: truncation is gated on and performed via UTF-16 *code-unit* count, not UTF-8 byte
    /// count. A 3-character, all-non-ASCII string ("日本語", each character 3 bytes in UTF-8 but 1
    /// UTF-16 code unit) has `code_unit_len == 3` but an actual encoded `length()` of `3*3 + 4 =
    /// 13` bytes. Requesting `truncate(8)` (i.e. "keep the encoded length to at most 8 bytes", so
    /// `max_len == 4` string units) does *not* trigger truncation at all, since `3 <= 4` -- yet
    /// the field's encoded length is still 13 bytes, far exceeding the requested bound of 8. This
    /// demonstrates the under-truncation bug rather than "fixing" it.
    #[test]
    fn test_truncate_under_truncates_multibyte_strings() {
        let mut field: Box<dyn StringField> = Box::new(MockStringField::new(Some("日本語")));
        assert_eq!(field.get_string().unwrap().len(), 9); // 3 chars * 3 UTF-8 bytes each
        assert_eq!(field.length(), 13); // 9 bytes + 4-byte length prefix

        field.truncate(8).unwrap(); // caller wants encoded length <= 8

        // Bug reproduced: no truncation occurred because code-unit count (3) <= max_len (4),
        // even though the actual byte length (9) is more than double the string-data budget (4).
        assert_eq!(field.get_string().unwrap(), "日本語");
        assert_eq!(field.length(), 13); // still exceeds the requested bound of 8
    }

    #[test]
    fn test_truncate_ascii_string_behaves_as_expected() {
        let mut field: Box<dyn StringField> = Box::new(MockStringField::new(Some("abcdefghij")));
        field.truncate(8).unwrap(); // max_len = 4
        assert_eq!(field.get_string().unwrap(), "abcd");
        assert_eq!(field.length(), 8);
    }

    #[test]
    fn test_truncate_noop_when_already_within_bounds() {
        let mut field: Box<dyn StringField> = Box::new(MockStringField::new(Some("ab")));
        field.truncate(100).unwrap();
        assert_eq!(field.get_string().unwrap(), "ab");
    }
}
