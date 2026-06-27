/// Constants for encoding rebasing information in dyld info commands.
pub const REBASE_TYPE_POINTER: u32 = 1;
pub const REBASE_TYPE_TEXT_ABSOLUTE32: u32 = 2;
pub const REBASE_TYPE_TEXT_PCREL32: u32 = 3;

pub const REBASE_OPCODE_MASK: u32 = 0xF0;
pub const REBASE_IMMEDIATE_MASK: u32 = 0x0F;
pub const REBASE_OPCODE_DONE: u32 = 0x00;
pub const REBASE_OPCODE_SET_TYPE_IMM: u32 = 0x10;
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u32 = 0x20;
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u32 = 0x30;
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u32 = 0x40;
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u32 = 0x50;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u32 = 0x60;
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u32 = 0x70;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u32 = 0x80;

/// Constants for encoding binding information in dyld info commands.
pub const BIND_TYPE_POINTER: u32 = 1;
pub const BIND_TYPE_TEXT_ABSOLUTE32: u32 = 2;
pub const BIND_TYPE_TEXT_PCREL32: u32 = 3;

pub const BIND_SPECIAL_DYLIB_SELF: i32 = 0;
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i32 = -1;
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i32 = -2;
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: i32 = -3;

pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u32 = 0x1;
pub const BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: u32 = 0x8;

pub const BIND_OPCODE_MASK: u32 = 0xF0;
pub const BIND_IMMEDIATE_MASK: u32 = 0x0F;
pub const BIND_OPCODE_DONE: u32 = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u32 = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u32 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u32 = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u32 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u32 = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u32 = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u32 = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u32 = 0x80;
pub const BIND_OPCODE_DO_BIND: u32 = 0x90;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u32 = 0xA0;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u32 = 0xB0;
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u32 = 0xC0;
pub const BIND_OPCODE_THREADED: u32 = 0xD0;

pub const BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB: u32 = 0x00;
pub const BIND_SUBOPCODE_THREADED_APPLY: u32 = 0x01;

/// Flags on the terminal node byte in export information.
pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u32 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u32 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u32 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u32 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u32 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u32 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u32 = 0x10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebase_types() {
        assert_eq!(REBASE_TYPE_POINTER, 1);
        assert_eq!(REBASE_TYPE_TEXT_ABSOLUTE32, 2);
        assert_eq!(REBASE_TYPE_TEXT_PCREL32, 3);
    }

    #[test]
    fn rebase_opcodes_mask_and_immediate() {
        assert_eq!(REBASE_OPCODE_MASK, 0xF0);
        assert_eq!(REBASE_IMMEDIATE_MASK, 0x0F);
        assert_eq!(REBASE_OPCODE_MASK & REBASE_IMMEDIATE_MASK, 0x00);
    }

    #[test]
    fn rebase_opcodes_values() {
        assert_eq!(REBASE_OPCODE_DONE, 0x00);
        assert_eq!(REBASE_OPCODE_SET_TYPE_IMM, 0x10);
        assert_eq!(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, 0x20);
        assert_eq!(REBASE_OPCODE_ADD_ADDR_ULEB, 0x30);
        assert_eq!(REBASE_OPCODE_ADD_ADDR_IMM_SCALED, 0x40);
        assert_eq!(REBASE_OPCODE_DO_REBASE_IMM_TIMES, 0x50);
        assert_eq!(REBASE_OPCODE_DO_REBASE_ULEB_TIMES, 0x60);
        assert_eq!(REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB, 0x70);
        assert_eq!(REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB, 0x80);
    }

    #[test]
    fn bind_types() {
        assert_eq!(BIND_TYPE_POINTER, 1);
        assert_eq!(BIND_TYPE_TEXT_ABSOLUTE32, 2);
        assert_eq!(BIND_TYPE_TEXT_PCREL32, 3);
    }

    #[test]
    fn bind_special_dylib_values() {
        assert_eq!(BIND_SPECIAL_DYLIB_SELF, 0);
        assert_eq!(BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE, -1);
        assert_eq!(BIND_SPECIAL_DYLIB_FLAT_LOOKUP, -2);
        assert_eq!(BIND_SPECIAL_DYLIB_WEAK_LOOKUP, -3);
    }

    #[test]
    fn bind_symbol_flags() {
        assert_eq!(BIND_SYMBOL_FLAGS_WEAK_IMPORT, 0x1);
        assert_eq!(BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION, 0x8);
    }

    #[test]
    fn bind_opcodes_mask_and_immediate() {
        assert_eq!(BIND_OPCODE_MASK, 0xF0);
        assert_eq!(BIND_IMMEDIATE_MASK, 0x0F);
        assert_eq!(BIND_OPCODE_MASK & BIND_IMMEDIATE_MASK, 0x00);
    }

    #[test]
    fn bind_opcodes_values() {
        assert_eq!(BIND_OPCODE_DONE, 0x00);
        assert_eq!(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM, 0x10);
        assert_eq!(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB, 0x20);
        assert_eq!(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM, 0x30);
        assert_eq!(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, 0x40);
        assert_eq!(BIND_OPCODE_SET_TYPE_IMM, 0x50);
        assert_eq!(BIND_OPCODE_SET_ADDEND_SLEB, 0x60);
        assert_eq!(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, 0x70);
        assert_eq!(BIND_OPCODE_ADD_ADDR_ULEB, 0x80);
        assert_eq!(BIND_OPCODE_DO_BIND, 0x90);
        assert_eq!(BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB, 0xA0);
        assert_eq!(BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, 0xB0);
        assert_eq!(BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, 0xC0);
        assert_eq!(BIND_OPCODE_THREADED, 0xD0);
    }

    #[test]
    fn bind_subopcode_threaded_values() {
        assert_eq!(BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB, 0x00);
        assert_eq!(BIND_SUBOPCODE_THREADED_APPLY, 0x01);
    }

    #[test]
    fn export_symbol_flags() {
        assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_MASK, 0x03);
        assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_REGULAR, 0x00);
        assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL, 0x01);
        assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE, 0x02);
        assert_eq!(EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION, 0x04);
        assert_eq!(EXPORT_SYMBOL_FLAGS_REEXPORT, 0x08);
        assert_eq!(EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, 0x10);
    }

    #[test]
    fn export_kind_mask_covers_kind_values() {
        assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_REGULAR & EXPORT_SYMBOL_FLAGS_KIND_MASK, EXPORT_SYMBOL_FLAGS_KIND_REGULAR);
        assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL & EXPORT_SYMBOL_FLAGS_KIND_MASK, EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL);
        assert_eq!(EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE & EXPORT_SYMBOL_FLAGS_KIND_MASK, EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE);
    }
}
