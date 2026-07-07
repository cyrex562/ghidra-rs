/// File name.
pub const DOT_FILE: &str = ".file";
/// Address of the `.text` section.
pub const DOT_TEXT: &str = ".text";
/// Address of the `.data` section.
pub const DOT_DATA: &str = ".data";
/// Address of the `.bss` section.
pub const DOT_BSS: &str = ".bss";
/// Address of the beginning of a block.
pub const DOT_BB: &str = ".bb";
/// Address of the end of a block.
pub const DOT_EB: &str = ".eb";
/// Address of the beginning of a function.
pub const DOT_BF: &str = ".bf";
/// Address of the end of a function.
pub const DOT_EF: &str = ".ef";
/// Pointer to a structure or union that is returned by a function.
pub const DOT_TARGET: &str = ".target";
/// Dummy tag name for a structure, union, or enumeration.
pub const DOT_NFAKE: &str = ".nfake";
/// End of a structure, union, or enumeration.
pub const DOT_EOS: &str = ".eos";
/// Next available address after the end of the `.text` output section.
pub const DOT_ETEXT: &str = "etext";
/// Next available address after the end of the `.data` output section.
pub const DOT_EDATA: &str = "edata";
/// Next available address after the end of the `.bss` output section.
pub const DOT_END: &str = "end";

/// All special symbol name constants, for iteration.
const SPECIAL_NAMES: &[&str] = &[
    DOT_FILE, DOT_TEXT, DOT_DATA, DOT_BSS, DOT_BB, DOT_EB,
    DOT_BF, DOT_EF, DOT_TARGET, DOT_NFAKE, DOT_EOS, DOT_ETEXT, DOT_EDATA, DOT_END,
];

/// Returns `true` if `name` matches any of the special COFF symbol name constants.
///
/// The Java source has a reflective implementation over `DOT_`-prefixed `static final`
/// fields; this provides the same set without reflection.
pub fn is_special(name: &str) -> bool {
    SPECIAL_NAMES.contains(&name)
}

/// Returns the expected storage class for the named special symbol, or `None` if the
/// name is not a recognised special symbol with a well-defined storage class.
///
/// Return values correspond to constants in `CoffSymbolStorageClass`:
/// `C_FILE` = 103, `C_BLOCK` = 100, `C_FCN` = 101, `C_EOS` = 102, `C_STAT` = 3.
pub fn get_storage_class(name: &str) -> Option<i32> {
    match name {
        DOT_FILE => Some(103), // C_FILE
        DOT_BB | DOT_EB => Some(100),  // C_BLOCK
        DOT_BF | DOT_EF => Some(101),  // C_FCN
        DOT_EOS => Some(102),          // C_EOS
        DOT_TEXT | DOT_DATA | DOT_BSS => Some(3), // C_STAT
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values_match_java_source() {
        assert_eq!(DOT_FILE,   ".file");
        assert_eq!(DOT_TEXT,   ".text");
        assert_eq!(DOT_DATA,   ".data");
        assert_eq!(DOT_BSS,    ".bss");
        assert_eq!(DOT_BB,     ".bb");
        assert_eq!(DOT_EB,     ".eb");
        assert_eq!(DOT_BF,     ".bf");
        assert_eq!(DOT_EF,     ".ef");
        assert_eq!(DOT_TARGET, ".target");
        assert_eq!(DOT_NFAKE,  ".nfake");
        assert_eq!(DOT_EOS,    ".eos");
        assert_eq!(DOT_ETEXT,  "etext");
        assert_eq!(DOT_EDATA,  "edata");
        assert_eq!(DOT_END,    "end");
    }

    #[test]
    fn is_special_returns_true_for_all_dot_constants() {
        for &name in SPECIAL_NAMES {
            assert!(is_special(name), "{name} should be special");
        }
    }

    #[test]
    fn is_special_returns_false_for_ordinary_names() {
        assert!(!is_special("main"));
        assert!(!is_special("foo"));
        assert!(!is_special(""));
        assert!(!is_special(".unknown"));
    }

    #[test]
    fn get_storage_class_file() {
        assert_eq!(get_storage_class(DOT_FILE), Some(103)); // C_FILE
    }

    #[test]
    fn get_storage_class_block() {
        assert_eq!(get_storage_class(DOT_BB), Some(100)); // C_BLOCK
        assert_eq!(get_storage_class(DOT_EB), Some(100));
    }

    #[test]
    fn get_storage_class_function() {
        assert_eq!(get_storage_class(DOT_BF), Some(101)); // C_FCN
        assert_eq!(get_storage_class(DOT_EF), Some(101));
    }

    #[test]
    fn get_storage_class_eos() {
        assert_eq!(get_storage_class(DOT_EOS), Some(102)); // C_EOS
    }

    #[test]
    fn get_storage_class_stat() {
        assert_eq!(get_storage_class(DOT_TEXT), Some(3)); // C_STAT
        assert_eq!(get_storage_class(DOT_DATA), Some(3));
        assert_eq!(get_storage_class(DOT_BSS),  Some(3));
    }

    #[test]
    fn get_storage_class_unknown_returns_none() {
        // DOT_TARGET, DOT_NFAKE, DOT_ETEXT, DOT_EDATA, DOT_END have no defined class.
        assert_eq!(get_storage_class(DOT_TARGET), None);
        assert_eq!(get_storage_class(DOT_NFAKE),  None);
        assert_eq!(get_storage_class(DOT_ETEXT),  None);
        assert_eq!(get_storage_class(DOT_EDATA),  None);
        assert_eq!(get_storage_class(DOT_END),    None);
        assert_eq!(get_storage_class("main"),      None);
    }
}
