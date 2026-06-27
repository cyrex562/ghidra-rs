/// Constants for the `type` field of a Mach-O section header.
///
/// Corresponds to `SectionTypes.java` in the Ghidra source.

/// Mask covering the 8 section-type bits.
pub const SECTION_TYPE_MASK: u32 = 0x0000_00ff;

/// Regular section.
pub const S_REGULAR: u32 = 0x0;
/// Zero fill on demand section.
pub const S_ZEROFILL: u32 = 0x1;
/// Section with only literal C strings.
pub const S_CSTRING_LITERALS: u32 = 0x2;
/// Section with only 4-byte literals.
pub const S_4BYTE_LITERALS: u32 = 0x3;
/// Section with only 8-byte literals.
pub const S_8BYTE_LITERALS: u32 = 0x4;
/// Section with only pointers to literals.
pub const S_LITERAL_POINTERS: u32 = 0x5;
/// Section with only non-lazy symbol pointers.
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
/// Section with only lazy symbol pointers.
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
/// Section with only symbol stubs; stub byte size is in the `reserved2` field.
pub const S_SYMBOL_STUBS: u32 = 0x8;
/// Section with only function pointers for initialization.
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
/// Section with only function pointers for termination.
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;
/// Section contains symbols that are to be coalesced.
pub const S_COALESCED: u32 = 0xb;
/// Zero fill on demand section that can be larger than 4 GiB.
pub const S_GB_ZEROFILL: u32 = 0xc;
/// Section with only pairs of function pointers for interposing.
pub const S_INTERPOSING: u32 = 0xd;
/// Section with only 16-byte literals.
pub const S_16BYTE_LITERALS: u32 = 0xe;
/// Section contains DTrace Object Format data.
pub const S_DTRACE_DOF: u32 = 0xf;
/// Section with only lazy symbol pointers to lazy-loaded dylibs.
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
/// Thread-local variable support: template of initial values.
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
/// Thread-local variable support: zero-fill template of initial values.
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
/// Thread-local variable support: TLV descriptors.
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
/// Thread-local variable support: pointers to TLV descriptors.
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
/// Thread-local variable support: functions to initialize TLV values.
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;

/// All `S_*` type constants in declaration order, paired with the short name
/// returned by [`get_type_name`] (i.e. the `S_` prefix stripped).
static TYPE_TABLE: &[(u32, &str)] = &[
    (S_REGULAR, "REGULAR"),
    (S_ZEROFILL, "ZEROFILL"),
    (S_CSTRING_LITERALS, "CSTRING_LITERALS"),
    (S_4BYTE_LITERALS, "4BYTE_LITERALS"),
    (S_8BYTE_LITERALS, "8BYTE_LITERALS"),
    (S_LITERAL_POINTERS, "LITERAL_POINTERS"),
    (S_NON_LAZY_SYMBOL_POINTERS, "NON_LAZY_SYMBOL_POINTERS"),
    (S_LAZY_SYMBOL_POINTERS, "LAZY_SYMBOL_POINTERS"),
    (S_SYMBOL_STUBS, "SYMBOL_STUBS"),
    (S_MOD_INIT_FUNC_POINTERS, "MOD_INIT_FUNC_POINTERS"),
    (S_MOD_TERM_FUNC_POINTERS, "MOD_TERM_FUNC_POINTERS"),
    (S_COALESCED, "COALESCED"),
    (S_GB_ZEROFILL, "GB_ZEROFILL"),
    (S_INTERPOSING, "INTERPOSING"),
    (S_16BYTE_LITERALS, "16BYTE_LITERALS"),
    (S_DTRACE_DOF, "DTRACE_DOF"),
    (S_LAZY_DYLIB_SYMBOL_POINTERS, "LAZY_DYLIB_SYMBOL_POINTERS"),
    (S_THREAD_LOCAL_REGULAR, "THREAD_LOCAL_REGULAR"),
    (S_THREAD_LOCAL_ZEROFILL, "THREAD_LOCAL_ZEROFILL"),
    (S_THREAD_LOCAL_VARIABLES, "THREAD_LOCAL_VARIABLES"),
    (S_THREAD_LOCAL_VARIABLE_POINTERS, "THREAD_LOCAL_VARIABLE_POINTERS"),
    (S_THREAD_LOCAL_INIT_FUNCTION_POINTERS, "THREAD_LOCAL_INIT_FUNCTION_POINTERS"),
];

/// Returns the short name (without the `S_` prefix) for the given section type,
/// or `"Unrecognized_Section_Type_0x<hex>"` if the value is unknown.
///
/// Preserves parity with `SectionTypes.getTypeName(int)`.
pub fn get_type_name(type_value: u32) -> String {
    for &(value, name) in TYPE_TABLE {
        if value == type_value {
            return name.to_string();
        }
    }
    format!("Unrecognized_Section_Type_0x{:x}", type_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values() {
        assert_eq!(SECTION_TYPE_MASK, 0x0000_00ff);
        assert_eq!(S_REGULAR, 0x0);
        assert_eq!(S_ZEROFILL, 0x1);
        assert_eq!(S_CSTRING_LITERALS, 0x2);
        assert_eq!(S_4BYTE_LITERALS, 0x3);
        assert_eq!(S_8BYTE_LITERALS, 0x4);
        assert_eq!(S_LITERAL_POINTERS, 0x5);
        assert_eq!(S_NON_LAZY_SYMBOL_POINTERS, 0x6);
        assert_eq!(S_LAZY_SYMBOL_POINTERS, 0x7);
        assert_eq!(S_SYMBOL_STUBS, 0x8);
        assert_eq!(S_MOD_INIT_FUNC_POINTERS, 0x9);
        assert_eq!(S_MOD_TERM_FUNC_POINTERS, 0xa);
        assert_eq!(S_COALESCED, 0xb);
        assert_eq!(S_GB_ZEROFILL, 0xc);
        assert_eq!(S_INTERPOSING, 0xd);
        assert_eq!(S_16BYTE_LITERALS, 0xe);
        assert_eq!(S_DTRACE_DOF, 0xf);
        assert_eq!(S_LAZY_DYLIB_SYMBOL_POINTERS, 0x10);
        assert_eq!(S_THREAD_LOCAL_REGULAR, 0x11);
        assert_eq!(S_THREAD_LOCAL_ZEROFILL, 0x12);
        assert_eq!(S_THREAD_LOCAL_VARIABLES, 0x13);
        assert_eq!(S_THREAD_LOCAL_VARIABLE_POINTERS, 0x14);
        assert_eq!(S_THREAD_LOCAL_INIT_FUNCTION_POINTERS, 0x15);
    }

    #[test]
    fn get_type_name_known_values() {
        assert_eq!(get_type_name(S_REGULAR), "REGULAR");
        assert_eq!(get_type_name(S_ZEROFILL), "ZEROFILL");
        assert_eq!(get_type_name(S_CSTRING_LITERALS), "CSTRING_LITERALS");
        assert_eq!(get_type_name(S_4BYTE_LITERALS), "4BYTE_LITERALS");
        assert_eq!(get_type_name(S_8BYTE_LITERALS), "8BYTE_LITERALS");
        assert_eq!(get_type_name(S_LITERAL_POINTERS), "LITERAL_POINTERS");
        assert_eq!(get_type_name(S_NON_LAZY_SYMBOL_POINTERS), "NON_LAZY_SYMBOL_POINTERS");
        assert_eq!(get_type_name(S_LAZY_SYMBOL_POINTERS), "LAZY_SYMBOL_POINTERS");
        assert_eq!(get_type_name(S_SYMBOL_STUBS), "SYMBOL_STUBS");
        assert_eq!(get_type_name(S_MOD_INIT_FUNC_POINTERS), "MOD_INIT_FUNC_POINTERS");
        assert_eq!(get_type_name(S_MOD_TERM_FUNC_POINTERS), "MOD_TERM_FUNC_POINTERS");
        assert_eq!(get_type_name(S_COALESCED), "COALESCED");
        assert_eq!(get_type_name(S_GB_ZEROFILL), "GB_ZEROFILL");
        assert_eq!(get_type_name(S_INTERPOSING), "INTERPOSING");
        assert_eq!(get_type_name(S_16BYTE_LITERALS), "16BYTE_LITERALS");
        assert_eq!(get_type_name(S_DTRACE_DOF), "DTRACE_DOF");
        assert_eq!(get_type_name(S_LAZY_DYLIB_SYMBOL_POINTERS), "LAZY_DYLIB_SYMBOL_POINTERS");
        assert_eq!(get_type_name(S_THREAD_LOCAL_REGULAR), "THREAD_LOCAL_REGULAR");
        assert_eq!(get_type_name(S_THREAD_LOCAL_ZEROFILL), "THREAD_LOCAL_ZEROFILL");
        assert_eq!(get_type_name(S_THREAD_LOCAL_VARIABLES), "THREAD_LOCAL_VARIABLES");
        assert_eq!(get_type_name(S_THREAD_LOCAL_VARIABLE_POINTERS), "THREAD_LOCAL_VARIABLE_POINTERS");
        assert_eq!(get_type_name(S_THREAD_LOCAL_INIT_FUNCTION_POINTERS), "THREAD_LOCAL_INIT_FUNCTION_POINTERS");
    }

    #[test]
    fn get_type_name_unknown_returns_hex_string() {
        assert_eq!(get_type_name(0x20), "Unrecognized_Section_Type_0x20");
        assert_eq!(get_type_name(0xff), "Unrecognized_Section_Type_0xff");
        assert_eq!(get_type_name(0xab), "Unrecognized_Section_Type_0xab");
    }

    #[test]
    fn type_table_covers_all_constants() {
        assert_eq!(TYPE_TABLE.len(), 22);
    }

    #[test]
    fn all_type_values_within_mask() {
        for &(value, _) in TYPE_TABLE {
            assert_eq!(value & SECTION_TYPE_MASK, value);
        }
    }
}
