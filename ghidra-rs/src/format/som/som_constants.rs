/// SOM (System Object Module) constant values for PA-RISC binaries.
///
/// Mirrors `ghidra.app.util.bin.format.som.SomConstants`.
///
/// Reference: The 32-bit PA-RISC Run-time Architecture Document (rad_11_0_32.pdf)

// System IDs
pub const SYSTEM_PA_RISC_1_0: u32 = 0x20b;
pub const SYSTEM_PA_RISC_1_1: u32 = 0x210;
pub const SYSTEM_PA_RISC_2_0: u32 = 0x214;

// Magic numbers
pub const MAGIC_LIBRARY: u32 = 0x104;
pub const MAGIC_RELOCATABLE: u32 = 0x106;
pub const MAGIC_NON_SHAREABLE_EXE: u32 = 0x107;
pub const MAGIC_SHAREABLE_EXE: u32 = 0x108;
pub const MAGIC_SHARABLE_DEMAND_LOADABLE_EXE: u32 = 0x10b;
pub const MAGIC_DYNAMIC_LOAD_LIBRARY: u32 = 0x10d;
pub const MAGIC_SHARED_LIBRARY: u32 = 0x10e;
pub const MAGIC_RELOCATABLE_LIBRARY: u32 = 0x0619;

// Version IDs
pub const VERSION_OLD: u32 = 0x85082112;
pub const VERSION_NEW: u32 = 0x87102412;

// Auxiliary header types
pub const TYPE_NULL: u32 = 0;
pub const LINKER_FOOTPRINT: u32 = 1;
pub const MEP_IX_PROGRAM: u32 = 2;
pub const DEBUGGER_FOOTPRINT: u32 = 3;
pub const EXEC_AUXILIARY_HEADER: u32 = 4;
pub const IPL_AUXILIARY_HEADER: u32 = 5;
pub const VERSION_STRIING: u32 = 6;
pub const MPE_IX_PROGRAM: u32 = 7;
pub const MPE_IX_SOM: u32 = 8;
pub const COPYRIGHT: u32 = 9;
pub const SHARED_LIBARY_VERSION_INFORMATION: u32 = 10;
pub const PRODUCT_SPECIFICS: u32 = 11;
pub const NETWARE_LOADABLE_MODULE: u32 = 12;

// Symbol types
pub const SYMBOL_NULL: u32 = 0;
pub const SYMBOL_ABSOLUTE: u32 = 1;
pub const SYMBOL_DATA: u32 = 2;
pub const SYMBOL_CODE: u32 = 3;
pub const SYMBOL_PRI_PROG: u32 = 4;
pub const SYMBOL_SEC_PROG: u32 = 5;
pub const SYMBOL_ENTRY: u32 = 6;
pub const SYMBOL_STORAGE: u32 = 7;
pub const SYMBOL_STUB: u32 = 8;
pub const SYMBOL_MODULE: u32 = 9;
pub const SYMBOL_SYM_EXT: u32 = 10;
pub const SYMBOL_ARG_EXT: u32 = 11;
pub const SYMBOL_MILLICODE: u32 = 12;
pub const SYMBOL_PLABEL: u32 = 13;
pub const SYMBOL_OCT_DIS: u32 = 14;
pub const SYMBOL_MILLI_EXT: u32 = 15;
pub const SYMBOL_TSTORAGE: u32 = 16;
pub const SYMBOL_COMDAT: u32 = 17;

// Symbol scopes
pub const SYMBOL_SCOPE_UNSAT: u32 = 0;
pub const SYMBOL_SCOPE_EXTERNAL: u32 = 1;
pub const SYMBOL_SCOPE_LOCAL: u32 = 2;
pub const SYMBOL_SCOPE_UNIVERSAL: u32 = 3;

// Dynamic relocation types
pub const DR_PLABEL_EXT: u32 = 1;
pub const DR_PLABEL_INT: u32 = 2;
pub const DR_DATA_EXT: u32 = 3;
pub const DR_DATA_INT: u32 = 4;
pub const DR_PROPAGATE: u32 = 5;
pub const DR_INVOKE: u32 = 6;
pub const DR_TEXT_INT: u32 = 7;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_ids() {
        assert_eq!(SYSTEM_PA_RISC_1_0, 0x20b);
        assert_eq!(SYSTEM_PA_RISC_1_1, 0x210);
        assert_eq!(SYSTEM_PA_RISC_2_0, 0x214);
    }

    #[test]
    fn magic_numbers() {
        assert_eq!(MAGIC_LIBRARY, 0x104);
        assert_eq!(MAGIC_RELOCATABLE, 0x106);
        assert_eq!(MAGIC_NON_SHAREABLE_EXE, 0x107);
        assert_eq!(MAGIC_SHAREABLE_EXE, 0x108);
        assert_eq!(MAGIC_SHARABLE_DEMAND_LOADABLE_EXE, 0x10b);
        assert_eq!(MAGIC_DYNAMIC_LOAD_LIBRARY, 0x10d);
        assert_eq!(MAGIC_SHARED_LIBRARY, 0x10e);
        assert_eq!(MAGIC_RELOCATABLE_LIBRARY, 0x0619);
    }

    #[test]
    fn version_ids() {
        assert_eq!(VERSION_OLD, 0x85082112);
        assert_eq!(VERSION_NEW, 0x87102412);
    }

    #[test]
    fn auxiliary_header_types() {
        assert_eq!(TYPE_NULL, 0);
        assert_eq!(LINKER_FOOTPRINT, 1);
        assert_eq!(MEP_IX_PROGRAM, 2);
        assert_eq!(DEBUGGER_FOOTPRINT, 3);
        assert_eq!(EXEC_AUXILIARY_HEADER, 4);
        assert_eq!(IPL_AUXILIARY_HEADER, 5);
        assert_eq!(VERSION_STRIING, 6);
        assert_eq!(MPE_IX_PROGRAM, 7);
        assert_eq!(MPE_IX_SOM, 8);
        assert_eq!(COPYRIGHT, 9);
        assert_eq!(SHARED_LIBARY_VERSION_INFORMATION, 10);
        assert_eq!(PRODUCT_SPECIFICS, 11);
        assert_eq!(NETWARE_LOADABLE_MODULE, 12);
    }

    #[test]
    fn symbol_types() {
        assert_eq!(SYMBOL_NULL, 0);
        assert_eq!(SYMBOL_ABSOLUTE, 1);
        assert_eq!(SYMBOL_DATA, 2);
        assert_eq!(SYMBOL_CODE, 3);
        assert_eq!(SYMBOL_PRI_PROG, 4);
        assert_eq!(SYMBOL_SEC_PROG, 5);
        assert_eq!(SYMBOL_ENTRY, 6);
        assert_eq!(SYMBOL_STORAGE, 7);
        assert_eq!(SYMBOL_STUB, 8);
        assert_eq!(SYMBOL_MODULE, 9);
        assert_eq!(SYMBOL_SYM_EXT, 10);
        assert_eq!(SYMBOL_ARG_EXT, 11);
        assert_eq!(SYMBOL_MILLICODE, 12);
        assert_eq!(SYMBOL_PLABEL, 13);
        assert_eq!(SYMBOL_OCT_DIS, 14);
        assert_eq!(SYMBOL_MILLI_EXT, 15);
        assert_eq!(SYMBOL_TSTORAGE, 16);
        assert_eq!(SYMBOL_COMDAT, 17);
    }

    #[test]
    fn symbol_scopes() {
        assert_eq!(SYMBOL_SCOPE_UNSAT, 0);
        assert_eq!(SYMBOL_SCOPE_EXTERNAL, 1);
        assert_eq!(SYMBOL_SCOPE_LOCAL, 2);
        assert_eq!(SYMBOL_SCOPE_UNIVERSAL, 3);
    }

    #[test]
    fn dynamic_relocation_types() {
        assert_eq!(DR_PLABEL_EXT, 1);
        assert_eq!(DR_PLABEL_INT, 2);
        assert_eq!(DR_DATA_EXT, 3);
        assert_eq!(DR_DATA_INT, 4);
        assert_eq!(DR_PROPAGATE, 5);
        assert_eq!(DR_INVOKE, 6);
        assert_eq!(DR_TEXT_INT, 7);
    }
}
