use super::buffer::Buffer;
use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Byte,
    Short,
    Int,
    Long,
    String,
    Binary,
    Boolean,
    Fixed(u32),
}

impl FieldType {
    pub fn to_byte(self) -> u8 {
        match self {
            FieldType::Byte => 0,
            FieldType::Short => 1,
            FieldType::Int => 2,
            FieldType::Long => 3,
            FieldType::String => 4,
            FieldType::Binary => 5,
            FieldType::Boolean => 6,
            FieldType::Fixed(len) => {
                if len == 10 {
                    7
                } else {
                    15
                } // 7 is special for FIXED_10
            }
        }
    }

    /// Decode a `FieldType` from a `Field.getFieldType()`-style type-tag byte. Mirrors the
    /// relevant cases of the static `db.Field.getField(byte)` factory (which this port models at
    /// the `FieldType` level rather than constructing a representative `Field` instance, since
    /// this port's [`super::schema::Schema`] already stores column types as `FieldType` rather
    /// than boxed `Field` instances).
    ///
    /// Returns [`UnsupportedFieldException`] for any byte not produced by [`Self::to_byte`].
    /// Note that [`Self::to_byte`] collapses every non-10-byte `Fixed` length to the single value
    /// `15` (there being no other concrete fixed-length field type in the real `db` package
    /// besides `FixedField10`); decoding `15` back necessarily loses the original length and
    /// produces `Fixed(0)` as a placeholder, mirroring that same pre-existing lossiness rather
    /// than trying to invert it.
    pub fn from_byte(b: u8) -> Result<FieldType, UnsupportedFieldException> {
        match b {
            0 => Ok(FieldType::Byte),
            1 => Ok(FieldType::Short),
            2 => Ok(FieldType::Int),
            3 => Ok(FieldType::Long),
            4 => Ok(FieldType::String),
            5 => Ok(FieldType::Binary),
            6 => Ok(FieldType::Boolean),
            7 => Ok(FieldType::Fixed(10)),
            15 => Ok(FieldType::Fixed(0)),
            other => Err(UnsupportedFieldException::for_field_type(other)),
        }
    }

    pub fn is_variable_length(self) -> bool {
        matches!(self, FieldType::String | FieldType::Binary)
    }
}

/// Thrown when an unsupported/unrecognized field type is encountered while decoding.
///
/// Port of the nested `db.Field.UnsupportedFieldException` (which `extends IOException` in
/// Java). Used by [`FieldType::from_byte`] and by [`super::schema::Schema`]'s encoded-form
/// constructor, mirroring the real `Schema(int, byte, byte[], String)` package-private
/// constructor and `Field.getField(byte)` factory, both of which declare
/// `throws UnsupportedFieldException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedFieldException {
    message: String,
}

impl UnsupportedFieldException {
    /// Construct with a specific message. Mirrors
    /// `UnsupportedFieldException(String msg)`.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }

    /// Construct for an unrecognized field-type tag byte. Mirrors
    /// `UnsupportedFieldException(byte fieldType)`.
    pub fn for_field_type(field_type: u8) -> Self {
        Self { message: format!("Unsupported field type: {}", field_type) }
    }
}

impl fmt::Display for UnsupportedFieldException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for UnsupportedFieldException {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Byte(Option<i8>),
    Short(Option<i16>),
    Int(Option<i32>),
    Long(Option<i64>),
    String(Option<String>),
    Binary(Option<Vec<u8>>),
    Boolean(Option<bool>),
    Fixed(Option<Vec<u8>>),
}

impl Field {
    pub fn is_null(&self) -> bool {
        match self {
            Field::Byte(v) => v.is_none(),
            Field::Short(v) => v.is_none(),
            Field::Int(v) => v.is_none(),
            Field::Long(v) => v.is_none(),
            Field::String(v) => v.is_none(),
            Field::Binary(v) => v.is_none(),
            Field::Boolean(v) => v.is_none(),
            Field::Fixed(v) => v.is_none(),
        }
    }

    pub fn get_type(&self) -> FieldType {
        match self {
            Field::Byte(_) => FieldType::Byte,
            Field::Short(_) => FieldType::Short,
            Field::Int(_) => FieldType::Int,
            Field::Long(_) => FieldType::Long,
            Field::String(_) => FieldType::String,
            Field::Binary(_) => FieldType::Binary,
            Field::Boolean(_) => FieldType::Boolean,
            Field::Fixed(v) => FieldType::Fixed(v.as_ref().map_or(0, |x| x.len() as u32)),
        }
    }

    pub fn get_long_value(&self) -> i64 {
        match self {
            Field::Byte(v) => v.unwrap_or(0) as i64,
            Field::Short(v) => v.unwrap_or(0) as i64,
            Field::Int(v) => v.unwrap_or(0) as i64,
            Field::Long(v) => v.unwrap_or(0),
            Field::Boolean(v) => {
                if v.unwrap_or(false) {
                    1
                } else {
                    0
                }
            }
            _ => panic!("Not a long-compatible field"),
        }
    }

    pub fn get_int_value(&self) -> i32 {
        match self {
            Field::Byte(v) => v.unwrap_or(0) as i32,
            Field::Short(v) => v.unwrap_or(0) as i32,
            Field::Int(v) => v.unwrap_or(0),
            Field::Boolean(v) => {
                if v.unwrap_or(false) {
                    1
                } else {
                    0
                }
            }
            _ => panic!("Not an int-compatible field"),
        }
    }

    pub fn get_string_value(&self) -> Option<&str> {
        match self {
            Field::String(v) => v.as_deref(),
            _ => panic!("Not a string field"),
        }
    }

    /// Returns this field's value narrowed/widened to `i8`. Mirrors the pattern of
    /// [`Self::get_int_value`]/[`Self::get_long_value`] (which widen `Byte`/`Boolean` into
    /// `Int`/`Long`): `Byte` and `Boolean` are the only variants an `i8`-typed column can
    /// meaningfully hold.
    pub fn get_byte_value(&self) -> i8 {
        match self {
            Field::Byte(v) => v.unwrap_or(0),
            Field::Boolean(v) => {
                if v.unwrap_or(false) {
                    1
                } else {
                    0
                }
            }
            _ => panic!("Not a byte-compatible field"),
        }
    }

    /// Returns this field's value widened to `i16`. Mirrors [`Self::get_int_value`]'s widening of
    /// `Byte`/`Boolean` into a wider integer type.
    pub fn get_short_value(&self) -> i16 {
        match self {
            Field::Byte(v) => v.unwrap_or(0) as i16,
            Field::Short(v) => v.unwrap_or(0),
            Field::Boolean(v) => {
                if v.unwrap_or(false) {
                    1
                } else {
                    0
                }
            }
            _ => panic!("Not a short-compatible field"),
        }
    }

    /// Returns this field's `bool` value. Mirrors `BooleanField.getBooleanValue()`.
    pub fn get_boolean_value(&self) -> bool {
        match self {
            Field::Boolean(v) => v.unwrap_or(false),
            _ => panic!("Not a boolean field"),
        }
    }

    pub fn get_binary_data(&self) -> Option<&[u8]> {
        match self {
            Field::Binary(v) => v.as_deref(),
            Field::Fixed(v) => v.as_deref(),
            _ => panic!("Not a binary field"),
        }
    }

    pub fn length(&self) -> usize {
        match self {
            Field::Byte(_) => 1,
            Field::Short(_) => 2,
            Field::Int(_) => 4,
            Field::Long(_) => 8,
            Field::String(v) => v.as_ref().map_or(4, |s| 4 + s.len()),
            Field::Binary(v) => v.as_ref().map_or(4, |b| 4 + b.len()),
            Field::Boolean(_) => 1,
            Field::Fixed(v) => v.as_ref().map_or(0, |x| x.len()),
        }
    }

    pub fn write(&self, buf: &mut dyn Buffer, offset: usize) -> isize {
        match self {
            Field::Byte(v) => buf.put_byte(offset, v.unwrap_or(0) as u8),
            Field::Short(v) => buf.put_short(offset, v.unwrap_or(0)),
            Field::Int(v) => buf.put_int(offset, v.unwrap_or(0)),
            Field::Long(v) => buf.put_long(offset, v.unwrap_or(0)),
            Field::String(v) => {
                if let Some(s) = v {
                    let off = buf.put_int(offset, s.len() as i32);
                    if off == -1 {
                        return -1;
                    }
                    buf.put(off as usize, s.as_bytes())
                } else {
                    buf.put_int(offset, -1)
                }
            }
            Field::Binary(v) => {
                if let Some(b) = v {
                    let off = buf.put_int(offset, b.len() as i32);
                    if off == -1 {
                        return -1;
                    }
                    buf.put(off as usize, b)
                } else {
                    buf.put_int(offset, -1)
                }
            }
            Field::Boolean(v) => buf.put_byte(offset, if v.unwrap_or(false) { 1 } else { 0 }),
            Field::Fixed(v) => {
                if let Some(data) = v {
                    buf.put(offset, data)
                } else {
                    // This is tricky because Fixed length field MUST have data if not sparse.
                    // If it is sparse, SparseRecord handles it.
                    // For now, write zeros.
                    if let FieldType::Fixed(l) = self.get_type() {
                        buf.put(offset, &vec![0; l as usize])
                    } else {
                        -1
                    }
                }
            }
        }
    }

    pub fn read(buf: &dyn Buffer, offset: usize, field_type: FieldType) -> (Self, usize) {
        match field_type {
            FieldType::Byte => (Field::Byte(Some(buf.get_byte(offset) as i8)), 1),
            FieldType::Short => (Field::Short(Some(buf.get_short(offset))), 2),
            FieldType::Int => (Field::Int(Some(buf.get_int(offset))), 4),
            FieldType::Long => (Field::Long(Some(buf.get_long(offset))), 8),
            FieldType::String => {
                let len = buf.get_int(offset);
                if len == -1 {
                    (Field::String(None), 4)
                } else {
                    let mut bytes = vec![0; len as usize];
                    buf.get(offset + 4, &mut bytes);
                    (
                        Field::String(Some(String::from_utf8_lossy(&bytes).to_string())),
                        4 + len as usize,
                    )
                }
            }
            FieldType::Binary => {
                let len = buf.get_int(offset);
                if len == -1 {
                    (Field::Binary(None), 4)
                } else {
                    let mut bytes = vec![0; len as usize];
                    buf.get(offset + 4, &mut bytes);
                    (Field::Binary(Some(bytes)), 4 + len as usize)
                }
            }
            FieldType::Boolean => (Field::Boolean(Some(buf.get_byte(offset) != 0)), 1),
            FieldType::Fixed(len) => {
                let mut bytes = vec![0; len as usize];
                buf.get(offset, &mut bytes);
                (Field::Fixed(Some(bytes)), len as usize)
            }
        }
    }
}

impl PartialOrd for Field {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Field {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Field::Byte(a), Field::Byte(b)) => a.cmp(b),
            (Field::Short(a), Field::Short(b)) => a.cmp(b),
            (Field::Int(a), Field::Int(b)) => a.cmp(b),
            (Field::Long(a), Field::Long(b)) => a.cmp(b),
            (Field::String(a), Field::String(b)) => a.cmp(b),
            (Field::Binary(a), Field::Binary(b)) => a.cmp(b),
            (Field::Boolean(a), Field::Boolean(b)) => a.cmp(b),
            (Field::Fixed(a), Field::Fixed(b)) => a.cmp(b),
            _ => self.get_type().to_byte().cmp(&other.get_type().to_byte()),
        }
    }
}

#[cfg(test)]
mod field_type_tests {
    use super::*;

    #[test]
    fn test_from_byte_round_trips_to_byte_for_simple_types() {
        for ty in [
            FieldType::Byte,
            FieldType::Short,
            FieldType::Int,
            FieldType::Long,
            FieldType::String,
            FieldType::Binary,
            FieldType::Boolean,
            FieldType::Fixed(10),
        ] {
            assert_eq!(FieldType::from_byte(ty.to_byte()).unwrap(), ty);
        }
    }

    #[test]
    fn test_from_byte_rejects_unknown_tag() {
        let err = FieldType::from_byte(42).unwrap_err();
        assert_eq!(err.to_string(), "Unsupported field type: 42");
    }

    #[test]
    fn test_from_byte_generic_fixed_is_lossy_placeholder() {
        // `to_byte()` collapses every non-10 Fixed length to 15 (there being no other concrete
        // fixed-length Field type in the real db package); decoding necessarily loses the
        // original length rather than recovering e.g. Fixed(4).
        assert_eq!(FieldType::from_byte(15).unwrap(), FieldType::Fixed(0));
        assert_eq!(FieldType::Fixed(4).to_byte(), 15);
    }

    #[test]
    fn test_unsupported_field_exception_display() {
        let e = UnsupportedFieldException::with_message("custom");
        assert_eq!(e.to_string(), "custom");
        let e2 = UnsupportedFieldException::for_field_type(9);
        assert_eq!(e2.to_string(), "Unsupported field type: 9");
    }
}
