//! Java class file constants and magic numbers.
//!
//! Ported from `ghidra.javaclass.format.JavaClassConstants`.

/// Java class file magic number (0xCAFEBABE in hex).
pub const MAGIC: u32 = 0xcafebabe;

/// Java class file magic bytes.
pub const MAGIC_BYTES: &[u8] = &[0xca, 0xfe, 0xba, 0xbe];

/// Array type code for boolean.
pub const T_BOOLEAN: u8 = 4;

/// Array type code for char.
pub const T_CHAR: u8 = 5;

/// Array type code for float.
pub const T_FLOAT: u8 = 6;

/// Array type code for double.
pub const T_DOUBLE: u8 = 7;

/// Array type code for byte.
pub const T_BYTE: u8 = 8;

/// Array type code for short.
pub const T_SHORT: u8 = 9;

/// Array type code for int.
pub const T_INT: u8 = 10;

/// Array type code for long.
pub const T_LONG: u8 = 11;

/// Placeholder string for operands.
pub const OPERAND_PLACEHOLDER: &str = "&&&";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_number_is_correct() {
        assert_eq!(MAGIC, 0xcafebabe);
    }

    #[test]
    fn magic_bytes_are_correct() {
        assert_eq!(MAGIC_BYTES, &[0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn magic_number_matches_magic_bytes() {
        let magic_from_bytes = u32::from_be_bytes([
            MAGIC_BYTES[0],
            MAGIC_BYTES[1],
            MAGIC_BYTES[2],
            MAGIC_BYTES[3],
        ]);
        assert_eq!(magic_from_bytes, MAGIC);
    }

    #[test]
    fn array_type_codes_match_java_source() {
        assert_eq!(T_BOOLEAN, 4);
        assert_eq!(T_CHAR, 5);
        assert_eq!(T_FLOAT, 6);
        assert_eq!(T_DOUBLE, 7);
        assert_eq!(T_BYTE, 8);
        assert_eq!(T_SHORT, 9);
        assert_eq!(T_INT, 10);
        assert_eq!(T_LONG, 11);
    }

    #[test]
    fn array_type_codes_are_sequential() {
        let codes = [T_BOOLEAN, T_CHAR, T_FLOAT, T_DOUBLE, T_BYTE, T_SHORT, T_INT, T_LONG];
        let mut sorted = codes;
        sorted.sort();
        assert_eq!(sorted, [4, 5, 6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn operand_placeholder_is_correct() {
        assert_eq!(OPERAND_PLACEHOLDER, "&&&");
    }
}
