/// Well-known Mach-O section name strings.
///
/// Corresponds to `SectionNames.java` in the Ghidra source.

/// The real text part of the text section (no headers, no padding).
pub const TEXT: &str = "__text";
/// Constant null-terminated C strings.
pub const TEXT_CSTRING: &str = "__cstring";
/// Position-independent indirect symbol stubs.
pub const TEXT_PICSYMBOL_STUB: &str = "__picsymbol_stub";
/// Indirect symbol stubs.
pub const TEXT_SYMBOL_STUB: &str = "__symbol_stub";
/// Initialized constant variables.
pub const TEXT_CONST: &str = "__const";
/// 4-byte literal values (single-precision floating-point constants).
pub const TEXT_LITERAL4: &str = "__literal4";
/// 8-byte literal values (double-precision floating-point constants).
pub const TEXT_LITERAL8: &str = "__literal8";
/// The fvmlib initialization section.
pub const TEXT_FVMLIB_INIT0: &str = "__fvmlib_init0";
/// The section following the fvmlib initialization section.
pub const TEXT_FVMLIB_INIT1: &str = "__fvmlib_init1";

/// The real initialized data section (no padding, no bss overlap).
pub const DATA: &str = "__data";
/// Lazy symbol pointers — indirect references to imported functions.
pub const DATA_LA_SYMBOL_PTR: &str = "__la_symbol_ptr";
/// Non-lazy symbol pointers — indirect references to imported functions.
pub const DATA_NL_SYMBOL_PTR: &str = "__nl_symbol_ptr";
/// Placeholder section used by the dynamic linker.
pub const DATA_DYLD: &str = "__dyld";
/// Initialized relocatable constant variables.
pub const DATA_CONST: &str = "__const";
/// Module initialization functions; C++ places static constructors here.
pub const DATA_MOD_INIT_FUNC: &str = "__mod_init_func";
/// Module termination functions.
pub const DATA_MOD_TERM_FUNC: &str = "__mod_term_func";
/// The real uninitialized data section (no padding).
pub const SECT_BSS: &str = "__bss";
/// The section in which the link editor allocates common symbols.
pub const SECT_COMMON: &str = "__common";
/// Global offset table section.
pub const SECT_GOT: &str = "__got";

/// Objective-C symbol table.
pub const OBJC_SYMBOLS: &str = "__symbol_table";
/// Objective-C module information.
pub const OBJC_MODULES: &str = "__module_info";
/// Objective-C selector string table.
pub const OBJC_STRINGS: &str = "__selector_strs";
/// Objective-C selector reference table.
pub const OBJC_REFS: &str = "__selector_refs";

/// Stubs for calls to functions in a dynamic library.
pub const IMPORT_JUMP_TABLE: &str = "__jump_table";
/// Non-lazy symbol pointers (import section).
pub const IMPORT_POINTERS: &str = "__pointers";
/// Section dedicated to holding global program variables.
pub const PROGRAM_VARS: &str = "__program_vars";

/// Section containing a `dyld_chained_starts_offsets` structure.
pub const CHAIN_STARTS: &str = "__chain_starts";
/// Section containing chained fixups.
pub const THREAD_STARTS: &str = "__thread_starts";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_section_names() {
        assert_eq!(TEXT, "__text");
        assert_eq!(TEXT_CSTRING, "__cstring");
        assert_eq!(TEXT_PICSYMBOL_STUB, "__picsymbol_stub");
        assert_eq!(TEXT_SYMBOL_STUB, "__symbol_stub");
        assert_eq!(TEXT_CONST, "__const");
        assert_eq!(TEXT_LITERAL4, "__literal4");
        assert_eq!(TEXT_LITERAL8, "__literal8");
        assert_eq!(TEXT_FVMLIB_INIT0, "__fvmlib_init0");
        assert_eq!(TEXT_FVMLIB_INIT1, "__fvmlib_init1");
    }

    #[test]
    fn data_section_names() {
        assert_eq!(DATA, "__data");
        assert_eq!(DATA_LA_SYMBOL_PTR, "__la_symbol_ptr");
        assert_eq!(DATA_NL_SYMBOL_PTR, "__nl_symbol_ptr");
        assert_eq!(DATA_DYLD, "__dyld");
        assert_eq!(DATA_CONST, "__const");
        assert_eq!(DATA_MOD_INIT_FUNC, "__mod_init_func");
        assert_eq!(DATA_MOD_TERM_FUNC, "__mod_term_func");
    }

    #[test]
    fn bss_and_common_section_names() {
        assert_eq!(SECT_BSS, "__bss");
        assert_eq!(SECT_COMMON, "__common");
        assert_eq!(SECT_GOT, "__got");
    }

    #[test]
    fn objc_section_names() {
        assert_eq!(OBJC_SYMBOLS, "__symbol_table");
        assert_eq!(OBJC_MODULES, "__module_info");
        assert_eq!(OBJC_STRINGS, "__selector_strs");
        assert_eq!(OBJC_REFS, "__selector_refs");
    }

    #[test]
    fn import_and_misc_section_names() {
        assert_eq!(IMPORT_JUMP_TABLE, "__jump_table");
        assert_eq!(IMPORT_POINTERS, "__pointers");
        assert_eq!(PROGRAM_VARS, "__program_vars");
        assert_eq!(CHAIN_STARTS, "__chain_starts");
        assert_eq!(THREAD_STARTS, "__thread_starts");
    }

    #[test]
    fn all_names_start_with_double_underscore() {
        let names = [
            TEXT, TEXT_CSTRING, TEXT_PICSYMBOL_STUB, TEXT_SYMBOL_STUB,
            TEXT_CONST, TEXT_LITERAL4, TEXT_LITERAL8, TEXT_FVMLIB_INIT0,
            TEXT_FVMLIB_INIT1, DATA, DATA_LA_SYMBOL_PTR, DATA_NL_SYMBOL_PTR,
            DATA_DYLD, DATA_CONST, DATA_MOD_INIT_FUNC, DATA_MOD_TERM_FUNC,
            SECT_BSS, SECT_COMMON, SECT_GOT, OBJC_SYMBOLS, OBJC_MODULES,
            OBJC_STRINGS, OBJC_REFS, IMPORT_JUMP_TABLE, IMPORT_POINTERS,
            PROGRAM_VARS, CHAIN_STARTS, THREAD_STARTS,
        ];
        for name in &names {
            assert!(name.starts_with("__"), "{name} should start with '__'");
        }
    }
}
