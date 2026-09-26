//! MethodHandle bytecode behavior reference kinds.
//!
//! Ported from `ghidra.javaclass.analyzers.MethodHandleBytecodeBehaviors`.

/// getfield C.f:T
pub const REF_GET_FIELD: i32 = 1;

/// getstatic C.f:T
pub const REF_GET_STATIC: i32 = 2;

/// putfield C.f:T
pub const REF_PUT_FIELD: i32 = 3;

/// putstatic C.f:T
pub const REF_PUT_STATIC: i32 = 4;

/// invokevirtual C.m:(A*)T
pub const REF_INVOKE_VIRTUAL: i32 = 5;

/// invokestatic C.m:(A*)T
pub const REF_INVOKE_STATIC: i32 = 6;

/// invokespecial C.m:(A*)T
pub const REF_INVOKE_SPECIAL: i32 = 7;

/// new C; dup; invokespecial C.<init>:(A*)void
pub const REF_NEW_INVOKE_SPECIAL: i32 = 8;

/// invokeinterface C.m:(A*)T
pub const REF_INVOKE_INTERFACE: i32 = 9;

/// Returns the name of the given MethodHandle reference kind.
///
/// Given a reference kind value, returns the corresponding constant name
/// (e.g., "REF_getField", "REF_invokeStatic").
/// If the kind is not recognized, returns a hex representation.
///
/// # Arguments
/// * `kind` - The MethodHandle reference kind value
///
/// # Returns
/// A string representing the name of the reference kind
pub fn get_name(kind: i32) -> String {
    match kind {
        REF_GET_FIELD => "REF_getField",
        REF_GET_STATIC => "REF_getStatic",
        REF_PUT_FIELD => "REF_putField",
        REF_PUT_STATIC => "REF_putStatic",
        REF_INVOKE_VIRTUAL => "REF_invokeVirtual",
        REF_INVOKE_STATIC => "REF_invokeStatic",
        REF_INVOKE_SPECIAL => "REF_invokeSpecial",
        REF_NEW_INVOKE_SPECIAL => "REF_newInvokeSpecial",
        REF_INVOKE_INTERFACE => "REF_invokeInterface",
        _ => return format!("Unrecognized kind: 0x{:x}", kind),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(REF_GET_FIELD, 1);
        assert_eq!(REF_GET_STATIC, 2);
        assert_eq!(REF_PUT_FIELD, 3);
        assert_eq!(REF_PUT_STATIC, 4);
        assert_eq!(REF_INVOKE_VIRTUAL, 5);
        assert_eq!(REF_INVOKE_STATIC, 6);
        assert_eq!(REF_INVOKE_SPECIAL, 7);
        assert_eq!(REF_NEW_INVOKE_SPECIAL, 8);
        assert_eq!(REF_INVOKE_INTERFACE, 9);
    }

    #[test]
    fn get_name_returns_correct_names() {
        assert_eq!(get_name(1), "REF_getField");
        assert_eq!(get_name(2), "REF_getStatic");
        assert_eq!(get_name(3), "REF_putField");
        assert_eq!(get_name(4), "REF_putStatic");
        assert_eq!(get_name(5), "REF_invokeVirtual");
        assert_eq!(get_name(6), "REF_invokeStatic");
        assert_eq!(get_name(7), "REF_invokeSpecial");
        assert_eq!(get_name(8), "REF_newInvokeSpecial");
        assert_eq!(get_name(9), "REF_invokeInterface");
    }

    #[test]
    fn get_name_returns_unrecognized_for_invalid_kind() {
        assert_eq!(get_name(0), "Unrecognized kind: 0x0");
        assert_eq!(get_name(10), "Unrecognized kind: 0xa");
        assert_eq!(get_name(255), "Unrecognized kind: 0xff");
        assert_eq!(get_name(-1), "Unrecognized kind: 0xffffffff");
    }

    #[test]
    fn all_valid_kinds_have_names() {
        for kind in 1..=9 {
            let name = get_name(kind);
            assert!(name.starts_with("REF_"), "Expected name for kind {} to start with REF_", kind);
            assert!(!name.contains("Unrecognized"), "Kind {} should be recognized", kind);
        }
    }
}
