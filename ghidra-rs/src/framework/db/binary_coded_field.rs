use super::binary_data_buffer::BinaryDataBuffer;
use super::binary_field::BinaryField;
use super::buffer::Buffer;
use super::illegal_field_access_exception::IllegalFieldAccessException;

/// Data type tag for a `byte[]` value. Mirrors `BinaryCodedField.BYTE_ARRAY`.
pub const BYTE_ARRAY: u8 = 0;
/// Data type tag for a `double` value. Mirrors `BinaryCodedField.FLOAT`.
pub const FLOAT: u8 = 1;
/// Data type tag for a `double` value. Mirrors `BinaryCodedField.DOUBLE`.
pub const DOUBLE: u8 = 2;
/// Data type tag for a `short[]` value. Mirrors `BinaryCodedField.SHORT_ARRAY`.
pub const SHORT_ARRAY: u8 = 3;
/// Data type tag for an `int[]` value. Mirrors `BinaryCodedField.INT_ARRAY`.
pub const INT_ARRAY: u8 = 4;
/// Data type tag for a `long[]` value. Mirrors `BinaryCodedField.LONG_ARRAY`.
pub const LONG_ARRAY: u8 = 5;
/// Data type tag for a `float[]` value. Mirrors `BinaryCodedField.FLOAT_ARRAY`.
pub const FLOAT_ARRAY: u8 = 6;
/// Data type tag for a `double[]` value. Mirrors `BinaryCodedField.DOUBLE_ARRAY`.
pub const DOUBLE_ARRAY: u8 = 7;
/// Data type tag for a `String[]` value. Mirrors `BinaryCodedField.STRING_ARRAY`.
pub const STRING_ARRAY: u8 = 8;

const DATA_TYPE_OFFSET: usize = 0;
const DATA_OFFSET: usize = 1;

/// Allows various non-database-supported data types to be encoded within a [`BinaryField`], so
/// that a table column can always be declared/handled as binary while still transparently
/// carrying a richer value (a primitive array, a `double`, etc).
///
/// Port of `db.BinaryCodedField`, a concrete `class BinaryCodedField extends BinaryField`. Per
/// this crate's composition-over-inheritance convention, this struct does not try to inherit from
/// the [`BinaryField`] trait's implementors; it owns its own `data: Option<Vec<u8>>` directly
/// (exactly matching `BinaryField`'s own private state) and implements [`BinaryField`] itself,
/// picking up every encode/decode/comparison default method that trait already provides
/// (`length`, `write`, `read`, `compare_to`, `truncate`, etc, all of which operate purely off
/// `get_binary_data`/`set_binary_data` and therefore apply unchanged to the coded byte layout
/// this type produces).
///
/// The data types this class can encode are tagged by a leading byte (`getDataType()`), followed
/// by an "is-null" marker byte, followed by the type-specific payload -- see each constructor's
/// doc comment for its exact layout. A `null` array value is preserved through encode/decode
/// (distinct from the whole field itself being null, i.e. [`BinaryField::is_null`]): the marker
/// byte at [`DATA_OFFSET`] is `-1` for a null array and `0` otherwise, mirroring the Java
/// constructors exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryCodedField {
    data: Option<Vec<u8>>,
}

impl BinaryCodedField {
    /// Construct an empty (null) coded field. Mirrors the package-private no-arg
    /// `BinaryCodedField()` constructor (used by [`BinaryField::new_field`]).
    pub fn empty() -> Self {
        Self { data: None }
    }

    /// Construct a coded field from an existing binary field's raw data. Mirrors
    /// `BinaryCodedField(BinaryField)`.
    pub fn from_binary_field(bin_field: &dyn BinaryField) -> Self {
        Self { data: bin_field.get_binary_data().map(|d| d.to_vec()) }
    }

    /// Construct a coded field from raw already-coded bytes (e.g. previously read from a buffer).
    /// Not present as a distinct Java constructor, but needed since this port does not go through
    /// `BinaryField`'s buffer-backed constructors; equivalent to constructing then calling
    /// [`BinaryField::set_binary_data`].
    pub fn from_raw_data(data: Option<Vec<u8>>) -> Self {
        Self { data }
    }

    /// Construct a coded field from a `double` value. Layout: `[DOUBLE][0][8-byte long bits]`.
    /// Mirrors `BinaryCodedField(double)`.
    pub fn from_double(value: f64) -> Self {
        let mut buffer = BinaryDataBuffer::new(9);
        buffer.put_byte(DATA_TYPE_OFFSET, DOUBLE);
        buffer.put_long(DATA_OFFSET, value.to_bits() as i64);
        Self { data: Some(buffer.get_data().to_vec()) }
    }

    /// Construct a coded field from a `float` value. Layout: `[FLOAT][0][4-byte int bits]`.
    /// Mirrors `BinaryCodedField(float)`.
    pub fn from_float(value: f32) -> Self {
        let mut buffer = BinaryDataBuffer::new(5);
        buffer.put_byte(DATA_TYPE_OFFSET, FLOAT);
        buffer.put_int(DATA_OFFSET, value.to_bits() as i32);
        Self { data: Some(buffer.get_data().to_vec()) }
    }

    /// Construct a coded field from a `byte[]` value (`None` for a null array). Layout:
    /// `[BYTE_ARRAY][0 or -1][raw bytes]`. Mirrors `BinaryCodedField(byte[])`.
    pub fn from_byte_array(values: Option<&[u8]>) -> Self {
        let data = match values {
            Some(v) => {
                let mut d = vec![0u8; v.len() + 2];
                d[DATA_OFFSET] = 0;
                d[2..].copy_from_slice(v);
                d
            }
            None => vec![0u8, 0xffu8], // [_, -1 as byte]
        };
        let mut data = data;
        data[DATA_TYPE_OFFSET] = BYTE_ARRAY;
        Self { data: Some(data) }
    }

    /// Construct a coded field from a `short[]` value (`None` for a null array). Layout:
    /// `[SHORT_ARRAY][0 or -1][big-endian shorts]`. Mirrors `BinaryCodedField(short[])`.
    pub fn from_short_array(values: Option<&[i16]>) -> Self {
        let len = values.map_or(0, |v| 2 * v.len()) + 2;
        let mut buffer = BinaryDataBuffer::new(len);
        buffer.put_byte(DATA_TYPE_OFFSET, SHORT_ARRAY);
        match values {
            Some(v) => {
                let mut offset = DATA_OFFSET;
                offset = buffer.put_byte(offset, 0) as usize;
                for &value in v {
                    offset = buffer.put_short(offset, value) as usize;
                }
            }
            None => {
                buffer.put_byte(DATA_OFFSET, 0xffu8 as i8 as u8);
            }
        }
        Self { data: Some(buffer.get_data().to_vec()) }
    }

    /// Construct a coded field from an `int[]` value (`None` for a null array). Layout:
    /// `[INT_ARRAY][0 or -1][big-endian ints]`. Mirrors `BinaryCodedField(int[])`.
    pub fn from_int_array(values: Option<&[i32]>) -> Self {
        let len = values.map_or(0, |v| 4 * v.len()) + 2;
        let mut buffer = BinaryDataBuffer::new(len);
        buffer.put_byte(DATA_TYPE_OFFSET, INT_ARRAY);
        match values {
            Some(v) => {
                let mut offset = DATA_OFFSET;
                offset = buffer.put_byte(offset, 0) as usize;
                for &value in v {
                    offset = buffer.put_int(offset, value) as usize;
                }
            }
            None => {
                buffer.put_byte(DATA_OFFSET, 0xffu8 as i8 as u8);
            }
        }
        Self { data: Some(buffer.get_data().to_vec()) }
    }

    /// Construct a coded field from a `long[]` value (`None` for a null array). Layout:
    /// `[LONG_ARRAY][0 or -1][big-endian longs]`. Mirrors `BinaryCodedField(long[])`.
    pub fn from_long_array(values: Option<&[i64]>) -> Self {
        let len = values.map_or(0, |v| 8 * v.len()) + 2;
        let mut buffer = BinaryDataBuffer::new(len);
        buffer.put_byte(DATA_TYPE_OFFSET, LONG_ARRAY);
        match values {
            Some(v) => {
                let mut offset = DATA_OFFSET;
                offset = buffer.put_byte(offset, 0) as usize;
                for &value in v {
                    offset = buffer.put_long(offset, value) as usize;
                }
            }
            None => {
                buffer.put_byte(DATA_OFFSET, 0xffu8 as i8 as u8);
            }
        }
        Self { data: Some(buffer.get_data().to_vec()) }
    }

    /// Construct a coded field from a `float[]` value (`None` for a null array). Layout:
    /// `[FLOAT_ARRAY][0 or -1][big-endian float bits]`. Mirrors `BinaryCodedField(float[])`.
    pub fn from_float_array(values: Option<&[f32]>) -> Self {
        let len = values.map_or(0, |v| 4 * v.len()) + 2;
        let mut buffer = BinaryDataBuffer::new(len);
        buffer.put_byte(DATA_TYPE_OFFSET, FLOAT_ARRAY);
        match values {
            Some(v) => {
                let mut offset = DATA_OFFSET;
                offset = buffer.put_byte(offset, 0) as usize;
                for &value in v {
                    offset = buffer.put_int(offset, value.to_bits() as i32) as usize;
                }
            }
            None => {
                buffer.put_byte(DATA_OFFSET, 0xffu8 as i8 as u8);
            }
        }
        Self { data: Some(buffer.get_data().to_vec()) }
    }

    /// Construct a coded field from a `double[]` value (`None` for a null array). Layout:
    /// `[DOUBLE_ARRAY][0 or -1][big-endian double bits]`. Mirrors `BinaryCodedField(double[])`.
    pub fn from_double_array(values: Option<&[f64]>) -> Self {
        let len = values.map_or(0, |v| 8 * v.len()) + 2;
        let mut buffer = BinaryDataBuffer::new(len);
        buffer.put_byte(DATA_TYPE_OFFSET, DOUBLE_ARRAY);
        match values {
            Some(v) => {
                let mut offset = DATA_OFFSET;
                offset = buffer.put_byte(offset, 0) as usize;
                for &value in v {
                    offset = buffer.put_long(offset, value.to_bits() as i64) as usize;
                }
            }
            None => {
                buffer.put_byte(DATA_OFFSET, 0xffu8 as i8 as u8);
            }
        }
        Self { data: Some(buffer.get_data().to_vec()) }
    }

    /// Construct a coded field from a `String[]` value (`None` for a null array; individual
    /// elements may themselves be `None` for a null string). Layout: `[STRING_ARRAY][0 or
    /// -1][(4-byte UTF-8 byte length or -1, UTF-8 bytes)*]`. Mirrors `BinaryCodedField(String[])`.
    pub fn from_string_array(strings: Option<&[Option<String>]>) -> Self {
        let mut buffer = match strings {
            Some(strs) => {
                let mut len = 2;
                for s in strs {
                    len += 4;
                    if let Some(s) = s {
                        len += s.len();
                    }
                }
                let mut buffer = BinaryDataBuffer::new(len);
                let mut offset = DATA_OFFSET;
                offset = buffer.put_byte(offset, 0) as usize;
                for s in strs {
                    match s {
                        None => offset = buffer.put_int(offset, -1) as usize,
                        Some(s) => {
                            let bytes = s.as_bytes();
                            offset = buffer.put_int(offset, bytes.len() as i32) as usize;
                            offset = buffer.put(offset, bytes) as usize;
                        }
                    }
                }
                buffer
            }
            None => {
                let mut buffer = BinaryDataBuffer::new(2);
                buffer.put_byte(DATA_OFFSET, 0xffu8 as i8 as u8);
                buffer
            }
        };
        buffer.put_byte(DATA_TYPE_OFFSET, STRING_ARRAY);
        Self { data: Some(buffer.get_data().to_vec()) }
    }

    fn data(&self) -> &[u8] {
        self.data.as_ref().expect("BinaryCodedField accessed while null")
    }

    /// Get the data type associated with this field. Mirrors `BinaryCodedField.getDataType()`.
    pub fn get_data_type(&self) -> u8 {
        self.data()[DATA_TYPE_OFFSET]
    }

    /// Get the `double` value contained within this field.
    ///
    /// Returns `Err` if this field's data type is not [`DOUBLE`], mirroring
    /// `BinaryCodedField.getDoubleValue()`'s `IllegalFieldAccessException`.
    pub fn get_double_value(&self) -> Result<f64, IllegalFieldAccessException> {
        if self.get_data_type() != DOUBLE {
            return Err(IllegalFieldAccessException::new());
        }
        let buffer = BinaryDataBuffer::from_data(self.data().to_vec());
        Ok(f64::from_bits(buffer.get_long(DATA_OFFSET) as u64))
    }

    /// Get the `float` value contained within this field.
    ///
    /// Returns `Err` if this field's data type is not [`FLOAT`], mirroring
    /// `BinaryCodedField.getFloatValue()`'s `IllegalFieldAccessException`.
    pub fn get_float_value(&self) -> Result<f32, IllegalFieldAccessException> {
        if self.get_data_type() != FLOAT {
            return Err(IllegalFieldAccessException::new());
        }
        let buffer = BinaryDataBuffer::from_data(self.data().to_vec());
        Ok(f32::from_bits(buffer.get_int(DATA_OFFSET) as u32))
    }

    /// Get the `byte[]` value contained within this field (`None` for a null array).
    ///
    /// Returns `Err` if this field's data type is not [`BYTE_ARRAY`], mirroring
    /// `BinaryCodedField.getByteArray()`'s `IllegalFieldAccessException`.
    pub fn get_byte_array(&self) -> Result<Option<Vec<u8>>, IllegalFieldAccessException> {
        if self.get_data_type() != BYTE_ARRAY {
            return Err(IllegalFieldAccessException::new());
        }
        let data = self.data();
        if (data[DATA_OFFSET] as i8) < 0 {
            return Ok(None);
        }
        Ok(Some(data[2..].to_vec()))
    }

    /// Get the `short[]` value contained within this field (`None` for a null array).
    ///
    /// Returns `Err` if this field's data type is not [`SHORT_ARRAY`], mirroring
    /// `BinaryCodedField.getShortArray()`'s `IllegalFieldAccessException`.
    pub fn get_short_array(&self) -> Result<Option<Vec<i16>>, IllegalFieldAccessException> {
        if self.get_data_type() != SHORT_ARRAY {
            return Err(IllegalFieldAccessException::new());
        }
        let data = self.data();
        if (data[DATA_OFFSET] as i8) < 0 {
            return Ok(None);
        }
        let buffer = BinaryDataBuffer::from_data(data.to_vec());
        let count = (data.len() - 2) / 2;
        let mut offset = DATA_OFFSET + 1;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(buffer.get_short(offset));
            offset += 2;
        }
        Ok(Some(values))
    }

    /// Get the `int[]` value contained within this field (`None` for a null array).
    ///
    /// Returns `Err` if this field's data type is not [`INT_ARRAY`], mirroring
    /// `BinaryCodedField.getIntArray()`'s `IllegalFieldAccessException`.
    pub fn get_int_array(&self) -> Result<Option<Vec<i32>>, IllegalFieldAccessException> {
        if self.get_data_type() != INT_ARRAY {
            return Err(IllegalFieldAccessException::new());
        }
        let data = self.data();
        if (data[DATA_OFFSET] as i8) < 0 {
            return Ok(None);
        }
        let buffer = BinaryDataBuffer::from_data(data.to_vec());
        let count = (data.len() - 2) / 4;
        let mut offset = DATA_OFFSET + 1;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(buffer.get_int(offset));
            offset += 4;
        }
        Ok(Some(values))
    }

    /// Get the `long[]` value contained within this field (`None` for a null array).
    ///
    /// Returns `Err` if this field's data type is not [`LONG_ARRAY`], mirroring
    /// `BinaryCodedField.getLongArray()`'s `IllegalFieldAccessException`.
    pub fn get_long_array(&self) -> Result<Option<Vec<i64>>, IllegalFieldAccessException> {
        if self.get_data_type() != LONG_ARRAY {
            return Err(IllegalFieldAccessException::new());
        }
        let data = self.data();
        if (data[DATA_OFFSET] as i8) < 0 {
            return Ok(None);
        }
        let buffer = BinaryDataBuffer::from_data(data.to_vec());
        let count = (data.len() - 2) / 8;
        let mut offset = DATA_OFFSET + 1;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(buffer.get_long(offset));
            offset += 8;
        }
        Ok(Some(values))
    }

    /// Get the `float[]` value contained within this field (`None` for a null array).
    ///
    /// Returns `Err` if this field's data type is not [`FLOAT_ARRAY`], mirroring
    /// `BinaryCodedField.getFloatArray()`'s `IllegalFieldAccessException`.
    pub fn get_float_array(&self) -> Result<Option<Vec<f32>>, IllegalFieldAccessException> {
        if self.get_data_type() != FLOAT_ARRAY {
            return Err(IllegalFieldAccessException::new());
        }
        let data = self.data();
        if (data[DATA_OFFSET] as i8) < 0 {
            return Ok(None);
        }
        let buffer = BinaryDataBuffer::from_data(data.to_vec());
        let count = (data.len() - 2) / 4;
        let mut offset = DATA_OFFSET + 1;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(f32::from_bits(buffer.get_int(offset) as u32));
            offset += 4;
        }
        Ok(Some(values))
    }

    /// Get the `double[]` value contained within this field (`None` for a null array).
    ///
    /// Returns `Err` if this field's data type is not [`DOUBLE_ARRAY`], mirroring
    /// `BinaryCodedField.getDoubleArray()`'s `IllegalFieldAccessException`.
    pub fn get_double_array(&self) -> Result<Option<Vec<f64>>, IllegalFieldAccessException> {
        if self.get_data_type() != DOUBLE_ARRAY {
            return Err(IllegalFieldAccessException::new());
        }
        let data = self.data();
        if (data[DATA_OFFSET] as i8) < 0 {
            return Ok(None);
        }
        let buffer = BinaryDataBuffer::from_data(data.to_vec());
        let count = (data.len() - 2) / 8;
        let mut offset = DATA_OFFSET + 1;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(f64::from_bits(buffer.get_long(offset) as u64));
            offset += 8;
        }
        Ok(Some(values))
    }

    /// Get the `String[]` value contained within this field (`None` for a null array; individual
    /// elements may themselves be `None` for a null string).
    ///
    /// Returns `Err` if this field's data type is not [`STRING_ARRAY`], mirroring
    /// `BinaryCodedField.getStringArray()`'s `IllegalFieldAccessException`.
    pub fn get_string_array(&self) -> Result<Option<Vec<Option<String>>>, IllegalFieldAccessException> {
        if self.get_data_type() != STRING_ARRAY {
            return Err(IllegalFieldAccessException::new());
        }
        let data = self.data();
        if (data[DATA_OFFSET] as i8) < 0 {
            return Ok(None);
        }
        let buffer = BinaryDataBuffer::from_data(data.to_vec());
        let mut strings = Vec::new();
        let mut offset = DATA_OFFSET + 1;
        while offset < data.len() {
            let len = buffer.get_int(offset);
            offset += 4;
            if len >= 0 {
                let bytes = buffer.get_bytes(offset, len as usize);
                strings.push(Some(String::from_utf8_lossy(&bytes).into_owned()));
                offset += len as usize;
            } else {
                strings.push(None);
            }
        }
        Ok(Some(strings))
    }
}

impl BinaryField for BinaryCodedField {
    fn get_binary_data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    fn set_binary_data(&mut self, data: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
        self.data = data.map(|d| d.to_vec());
        Ok(())
    }

    fn copy_field(&self) -> Box<dyn BinaryField> {
        Box::new(self.clone())
    }

    fn new_field(&self) -> Box<dyn BinaryField> {
        Box::new(BinaryCodedField::empty())
    }

    fn type_name(&self) -> &str {
        "BinaryCodedField"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::DataBuffer;

    #[test]
    fn test_double_round_trip() {
        let field = BinaryCodedField::from_double(3.5);
        assert_eq!(field.get_data_type(), DOUBLE);
        assert_eq!(field.get_double_value().unwrap(), 3.5);
        assert!(field.get_float_value().is_err());
    }

    #[test]
    fn test_float_round_trip() {
        let field = BinaryCodedField::from_float(2.25);
        assert_eq!(field.get_data_type(), FLOAT);
        assert_eq!(field.get_float_value().unwrap(), 2.25);
        assert!(field.get_double_value().is_err());
    }

    #[test]
    fn test_byte_array_round_trip_present_and_null() {
        let present = BinaryCodedField::from_byte_array(Some(&[1, 2, 3]));
        assert_eq!(present.get_byte_array().unwrap(), Some(vec![1u8, 2, 3]));

        let null = BinaryCodedField::from_byte_array(None);
        assert_eq!(null.get_byte_array().unwrap(), None);
        // A null *array value* is not the same as the field itself being null.
        assert!(!BinaryField::is_null(&null));
    }

    #[test]
    fn test_short_array_round_trip() {
        let field = BinaryCodedField::from_short_array(Some(&[1, -2, 300]));
        assert_eq!(field.get_short_array().unwrap(), Some(vec![1i16, -2, 300]));

        let null = BinaryCodedField::from_short_array(None);
        assert_eq!(null.get_short_array().unwrap(), None);
    }

    #[test]
    fn test_int_array_round_trip() {
        let field = BinaryCodedField::from_int_array(Some(&[1, -2, 100000]));
        assert_eq!(field.get_int_array().unwrap(), Some(vec![1i32, -2, 100000]));

        let empty = BinaryCodedField::from_int_array(Some(&[]));
        assert_eq!(empty.get_int_array().unwrap(), Some(vec![]));
    }

    #[test]
    fn test_long_array_round_trip() {
        let field = BinaryCodedField::from_long_array(Some(&[1, -2, i64::MAX]));
        assert_eq!(field.get_long_array().unwrap(), Some(vec![1i64, -2, i64::MAX]));
    }

    #[test]
    fn test_float_array_round_trip() {
        let field = BinaryCodedField::from_float_array(Some(&[1.5, -2.5]));
        assert_eq!(field.get_float_array().unwrap(), Some(vec![1.5f32, -2.5]));
    }

    #[test]
    fn test_double_array_round_trip() {
        let field = BinaryCodedField::from_double_array(Some(&[1.5, -2.5]));
        assert_eq!(field.get_double_array().unwrap(), Some(vec![1.5f64, -2.5]));
    }

    #[test]
    fn test_string_array_round_trip_with_null_elements() {
        let strings = vec![Some("hello".to_string()), None, Some("".to_string())];
        let field = BinaryCodedField::from_string_array(Some(&strings));
        assert_eq!(field.get_string_array().unwrap(), Some(strings));

        let null_array = BinaryCodedField::from_string_array(None);
        assert_eq!(null_array.get_string_array().unwrap(), None);
    }

    #[test]
    fn test_wrong_data_type_access_is_rejected() {
        let field = BinaryCodedField::from_int_array(Some(&[1, 2]));
        assert!(field.get_long_array().is_err());
        assert!(field.get_string_array().is_err());
    }

    #[test]
    fn test_from_binary_field_delegates_to_underlying_bytes() {
        struct RawBinary(Option<Vec<u8>>);
        impl BinaryField for RawBinary {
            fn get_binary_data(&self) -> Option<&[u8]> {
                self.0.as_deref()
            }
            fn set_binary_data(&mut self, data: Option<&[u8]>) -> Result<(), IllegalFieldAccessException> {
                self.0 = data.map(|d| d.to_vec());
                Ok(())
            }
            fn copy_field(&self) -> Box<dyn BinaryField> {
                Box::new(RawBinary(self.0.clone()))
            }
            fn new_field(&self) -> Box<dyn BinaryField> {
                Box::new(RawBinary(None))
            }
        }

        let source = BinaryCodedField::from_int_array(Some(&[7]));
        let raw = RawBinary(source.get_binary_data().map(|d| d.to_vec()));
        let coded = BinaryCodedField::from_binary_field(&raw);
        assert_eq!(coded.get_int_array().unwrap(), Some(vec![7]));
    }

    #[test]
    fn test_object_safety_write_read_and_length_via_binary_field_trait() {
        let original: Box<dyn BinaryField> = Box::new(BinaryCodedField::from_double(9.5));
        let mut buf = DataBuffer::new(0, original.length());
        let end = original.write(&mut buf, 0);
        assert_eq!(end, original.length() as isize);

        let mut decoded: Box<dyn BinaryField> = Box::new(BinaryCodedField::empty());
        assert!(decoded.is_null());
        decoded.read(&buf, 0).unwrap();
        assert!(!decoded.is_null());
        assert!(original.fields_equal(decoded.as_ref()));
    }

    #[test]
    fn test_copy_field_and_new_field() {
        let field: Box<dyn BinaryField> = Box::new(BinaryCodedField::from_int_array(Some(&[1, 2])));
        let copy = field.copy_field();
        assert!(field.fields_equal(copy.as_ref()));

        let fresh = field.new_field();
        assert!(fresh.is_null());
    }
}
