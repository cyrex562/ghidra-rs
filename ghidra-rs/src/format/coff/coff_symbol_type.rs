/// No type information.
pub const T_NULL: u32 = 0x0000;
/// Void function argument.
pub const T_VOID: u32 = 0x0001;
/// Character.
pub const T_CHAR: u32 = 0x0002;
/// Short integer.
pub const T_SHORT: u32 = 0x0003;
/// Integer.
pub const T_INT: u32 = 0x0004;
/// Long integer.
pub const T_LONG: u32 = 0x0005;
/// Float.
pub const T_FLOAT: u32 = 0x0006;
/// Double.
pub const T_DOUBLE: u32 = 0x0007;
/// Structure.
pub const T_STRUCT: u32 = 0x0008;
/// Union.
pub const T_UNION: u32 = 0x0009;
/// Enumeration.
pub const T_ENUM: u32 = 0x000a;
/// Member of enumeration.
pub const T_MOE: u32 = 0x000b;
/// Unsigned character.
pub const T_UCHAR: u32 = 0x000c;
/// Unsigned short.
pub const T_USHORT: u32 = 0x000d;
/// Unsigned integer.
pub const T_UINT: u32 = 0x000e;
/// Unsigned long.
pub const T_ULONG: u32 = 0x000f;
/// Long double.
pub const T_LONG_DOUBLE: u32 = 0x0010;

/// No derived type.
pub const DT_NON: u32 = 0x0000;
/// Pointer to T.
pub const DT_PTR: u32 = 0x0001;
/// Function returning T.
pub const DT_FCN: u32 = 0x0002;
/// Array of T.
pub const DT_ARY: u32 = 0x0003;

/// Returns the base type portion of a symbol type field (low nibble).
pub fn get_base_type(symbol_type: u32) -> u32 {
    symbol_type & 0xf
}

/// Returns the derived type portion of a symbol type field (second nibble).
pub fn get_derived_type(symbol_type: u32) -> u32 {
    symbol_type & 0xf0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_type_values_match_java_source() {
        assert_eq!(T_NULL,        0x0000);
        assert_eq!(T_VOID,        0x0001);
        assert_eq!(T_CHAR,        0x0002);
        assert_eq!(T_SHORT,       0x0003);
        assert_eq!(T_INT,         0x0004);
        assert_eq!(T_LONG,        0x0005);
        assert_eq!(T_FLOAT,       0x0006);
        assert_eq!(T_DOUBLE,      0x0007);
        assert_eq!(T_STRUCT,      0x0008);
        assert_eq!(T_UNION,       0x0009);
        assert_eq!(T_ENUM,        0x000a);
        assert_eq!(T_MOE,         0x000b);
        assert_eq!(T_UCHAR,       0x000c);
        assert_eq!(T_USHORT,      0x000d);
        assert_eq!(T_UINT,        0x000e);
        assert_eq!(T_ULONG,       0x000f);
        assert_eq!(T_LONG_DOUBLE, 0x0010);
    }

    #[test]
    fn derived_type_values_match_java_source() {
        assert_eq!(DT_NON, 0x0000);
        assert_eq!(DT_PTR, 0x0001);
        assert_eq!(DT_FCN, 0x0002);
        assert_eq!(DT_ARY, 0x0003);
    }

    #[test]
    fn get_base_type_masks_low_nibble() {
        assert_eq!(get_base_type(0x00), T_NULL);
        assert_eq!(get_base_type(0x04), T_INT);
        assert_eq!(get_base_type(0x24), T_INT);  // upper bits stripped
        assert_eq!(get_base_type(0xff), 0xf);
    }

    #[test]
    fn get_derived_type_masks_second_nibble() {
        assert_eq!(get_derived_type(0x00), 0x00);
        assert_eq!(get_derived_type(0x20), 0x20);
        assert_eq!(get_derived_type(0x2f), 0x20);  // low nibble stripped
        assert_eq!(get_derived_type(0xff), 0xf0);
    }
}
