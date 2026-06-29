/// Encoded value format type codes for the DEX format.
///
/// Mirrors `ghidra.file.formats.android.dex.format.ValueFormats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueFormats;

impl ValueFormats {
    /// Signed one-byte integer value.
    pub const VALUE_BYTE: u8 = 0x00;
    /// Signed two-byte integer value, sign-extended.
    pub const VALUE_SHORT: u8 = 0x02;
    /// Unsigned two-byte integer value, zero-extended.
    pub const VALUE_CHAR: u8 = 0x03;
    /// Signed four-byte integer value, sign-extended.
    pub const VALUE_INT: u8 = 0x04;
    /// Signed eight-byte integer value, sign-extended.
    pub const VALUE_LONG: u8 = 0x06;
    /// Four-byte IEEE 754 32-bit float, zero-extended to the right.
    pub const VALUE_FLOAT: u8 = 0x10;
    /// Eight-byte IEEE 754 64-bit float, zero-extended to the right.
    pub const VALUE_DOUBLE: u8 = 0x11;
    /// Unsigned four-byte index into the string_ids section.
    pub const VALUE_STRING: u8 = 0x17;
    /// Unsigned four-byte index into the type_ids section.
    pub const VALUE_TYPE: u8 = 0x18;
    /// Unsigned four-byte index into the field_ids section (field reference).
    pub const VALUE_FIELD: u8 = 0x19;
    /// Unsigned four-byte index into the method_ids section.
    pub const VALUE_METHOD: u8 = 0x1a;
    /// Unsigned four-byte index into the field_ids section (enum constant).
    pub const VALUE_ENUM: u8 = 0x1b;
    /// Embedded encoded_array; size implicit in encoding.
    pub const VALUE_ARRAY: u8 = 0x1c;
    /// Embedded encoded_annotation; size implicit in encoding.
    pub const VALUE_ANNOTATION: u8 = 0x1d;
    /// Null reference value.
    pub const VALUE_NULL: u8 = 0x1e;
    /// Boolean value (0 = false, 1 = true) encoded in value_arg.
    pub const VALUE_BOOLEAN: u8 = 0x1f;

    /// Returns the field name for the given value code, or `"Value:<value>"` if unknown.
    ///
    /// Replicates the reflection-based `toString(byte)` from the Java source, preserving
    /// declaration order.
    pub fn to_string(value: u8) -> String {
        const ENTRIES: &[(&str, u8)] = &[
            ("VALUE_BYTE", ValueFormats::VALUE_BYTE),
            ("VALUE_SHORT", ValueFormats::VALUE_SHORT),
            ("VALUE_CHAR", ValueFormats::VALUE_CHAR),
            ("VALUE_INT", ValueFormats::VALUE_INT),
            ("VALUE_LONG", ValueFormats::VALUE_LONG),
            ("VALUE_FLOAT", ValueFormats::VALUE_FLOAT),
            ("VALUE_DOUBLE", ValueFormats::VALUE_DOUBLE),
            ("VALUE_STRING", ValueFormats::VALUE_STRING),
            ("VALUE_TYPE", ValueFormats::VALUE_TYPE),
            ("VALUE_FIELD", ValueFormats::VALUE_FIELD),
            ("VALUE_METHOD", ValueFormats::VALUE_METHOD),
            ("VALUE_ENUM", ValueFormats::VALUE_ENUM),
            ("VALUE_ARRAY", ValueFormats::VALUE_ARRAY),
            ("VALUE_ANNOTATION", ValueFormats::VALUE_ANNOTATION),
            ("VALUE_NULL", ValueFormats::VALUE_NULL),
            ("VALUE_BOOLEAN", ValueFormats::VALUE_BOOLEAN),
        ];
        for &(name, v) in ENTRIES {
            if v == value {
                return name.to_string();
            }
        }
        format!("Value:{}", value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(ValueFormats::VALUE_BYTE, 0x00);
        assert_eq!(ValueFormats::VALUE_SHORT, 0x02);
        assert_eq!(ValueFormats::VALUE_CHAR, 0x03);
        assert_eq!(ValueFormats::VALUE_INT, 0x04);
        assert_eq!(ValueFormats::VALUE_LONG, 0x06);
        assert_eq!(ValueFormats::VALUE_FLOAT, 0x10);
        assert_eq!(ValueFormats::VALUE_DOUBLE, 0x11);
        assert_eq!(ValueFormats::VALUE_STRING, 0x17);
        assert_eq!(ValueFormats::VALUE_TYPE, 0x18);
        assert_eq!(ValueFormats::VALUE_FIELD, 0x19);
        assert_eq!(ValueFormats::VALUE_METHOD, 0x1a);
        assert_eq!(ValueFormats::VALUE_ENUM, 0x1b);
        assert_eq!(ValueFormats::VALUE_ARRAY, 0x1c);
        assert_eq!(ValueFormats::VALUE_ANNOTATION, 0x1d);
        assert_eq!(ValueFormats::VALUE_NULL, 0x1e);
        assert_eq!(ValueFormats::VALUE_BOOLEAN, 0x1f);
    }

    #[test]
    fn to_string_known_values() {
        assert_eq!(ValueFormats::to_string(0x00), "VALUE_BYTE");
        assert_eq!(ValueFormats::to_string(0x02), "VALUE_SHORT");
        assert_eq!(ValueFormats::to_string(0x03), "VALUE_CHAR");
        assert_eq!(ValueFormats::to_string(0x04), "VALUE_INT");
        assert_eq!(ValueFormats::to_string(0x06), "VALUE_LONG");
        assert_eq!(ValueFormats::to_string(0x10), "VALUE_FLOAT");
        assert_eq!(ValueFormats::to_string(0x11), "VALUE_DOUBLE");
        assert_eq!(ValueFormats::to_string(0x17), "VALUE_STRING");
        assert_eq!(ValueFormats::to_string(0x18), "VALUE_TYPE");
        assert_eq!(ValueFormats::to_string(0x19), "VALUE_FIELD");
        assert_eq!(ValueFormats::to_string(0x1a), "VALUE_METHOD");
        assert_eq!(ValueFormats::to_string(0x1b), "VALUE_ENUM");
        assert_eq!(ValueFormats::to_string(0x1c), "VALUE_ARRAY");
        assert_eq!(ValueFormats::to_string(0x1d), "VALUE_ANNOTATION");
        assert_eq!(ValueFormats::to_string(0x1e), "VALUE_NULL");
        assert_eq!(ValueFormats::to_string(0x1f), "VALUE_BOOLEAN");
    }

    #[test]
    fn to_string_unknown_value() {
        assert_eq!(ValueFormats::to_string(0x01), "Value:1");
        assert_eq!(ValueFormats::to_string(0x05), "Value:5");
        assert_eq!(ValueFormats::to_string(0xff), "Value:255");
    }
}
