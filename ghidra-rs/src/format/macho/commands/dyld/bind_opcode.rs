//! Port of `ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode`.
//!
//! Bind opcodes. See
//! <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/loader.h>.

use crate::format::macho::mach_constants::DATA_TYPE_CATEGORY;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Port of `ghidra.app.util.bin.format.macho.commands.dyld.BindOpcode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum BindOpcode {
    BIND_OPCODE_DONE,
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
    BIND_OPCODE_SET_TYPE_IMM,
    BIND_OPCODE_SET_ADDEND_SLEB,
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    BIND_OPCODE_ADD_ADDR_ULEB,
    BIND_OPCODE_DO_BIND,
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED,
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
    BIND_OPCODE_THREADED,
}

impl BindOpcode {
    /// Java `BindOpcode.values()`, in declaration order.
    pub const VALUES: [BindOpcode; 14] = [
        BindOpcode::BIND_OPCODE_DONE,
        BindOpcode::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
        BindOpcode::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
        BindOpcode::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
        BindOpcode::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
        BindOpcode::BIND_OPCODE_SET_TYPE_IMM,
        BindOpcode::BIND_OPCODE_SET_ADDEND_SLEB,
        BindOpcode::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
        BindOpcode::BIND_OPCODE_ADD_ADDR_ULEB,
        BindOpcode::BIND_OPCODE_DO_BIND,
        BindOpcode::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
        BindOpcode::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED,
        BindOpcode::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
        BindOpcode::BIND_OPCODE_THREADED,
    ];

    /// Java `getOpcode()`.
    pub fn get_opcode(self) -> i32 {
        match self {
            BindOpcode::BIND_OPCODE_DONE => 0x00,
            BindOpcode::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => 0x10,
            BindOpcode::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => 0x20,
            BindOpcode::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => 0x30,
            BindOpcode::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => 0x40,
            BindOpcode::BIND_OPCODE_SET_TYPE_IMM => 0x50,
            BindOpcode::BIND_OPCODE_SET_ADDEND_SLEB => 0x60,
            BindOpcode::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => 0x70,
            BindOpcode::BIND_OPCODE_ADD_ADDR_ULEB => 0x80,
            BindOpcode::BIND_OPCODE_DO_BIND => 0x90,
            BindOpcode::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => 0xA0,
            BindOpcode::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => 0xB0,
            BindOpcode::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => 0xC0,
            BindOpcode::BIND_OPCODE_THREADED => 0xD0,
        }
    }

    /// Java `toString()` (the constant name).
    pub fn name(self) -> &'static str {
        match self {
            BindOpcode::BIND_OPCODE_DONE => "BIND_OPCODE_DONE",
            BindOpcode::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => "BIND_OPCODE_SET_DYLIB_ORDINAL_IMM",
            BindOpcode::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => "BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB",
            BindOpcode::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => "BIND_OPCODE_SET_DYLIB_SPECIAL_IMM",
            BindOpcode::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => "BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM",
            BindOpcode::BIND_OPCODE_SET_TYPE_IMM => "BIND_OPCODE_SET_TYPE_IMM",
            BindOpcode::BIND_OPCODE_SET_ADDEND_SLEB => "BIND_OPCODE_SET_ADDEND_SLEB",
            BindOpcode::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => "BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB",
            BindOpcode::BIND_OPCODE_ADD_ADDR_ULEB => "BIND_OPCODE_ADD_ADDR_ULEB",
            BindOpcode::BIND_OPCODE_DO_BIND => "BIND_OPCODE_DO_BIND",
            BindOpcode::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => "BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB",
            BindOpcode::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => "BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED",
            BindOpcode::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => "BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB",
            BindOpcode::BIND_OPCODE_THREADED => "BIND_OPCODE_THREADED",
        }
    }

    /// Java `static toDataType()`: a 1-byte `bind_opcode` enum in the `/MachO` category.
    pub fn to_data_type() -> Box<dyn DataType> {
        let mut enum_dt = EnumDataType::new("bind_opcode", 1);
        if let Ok(path) = CategoryPath::parse(DATA_TYPE_CATEGORY) {
            let _ = enum_dt.set_category_path(path);
        }
        for op in Self::VALUES {
            Enum::add(&mut enum_dt, op.name(), op.get_opcode() as i64);
        }
        Box::new(enum_dt)
    }

    /// Java `static forOpcode(int)`. `None` stands in for Java's `null`.
    pub fn for_opcode(opcode: i32) -> Option<BindOpcode> {
        Self::VALUES.into_iter().find(|op| op.get_opcode() == opcode)
    }
}

impl std::fmt::Display for BindOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_opcode_round_trips_and_rejects_unknown() {
        for op in BindOpcode::VALUES {
            assert_eq!(BindOpcode::for_opcode(op.get_opcode()), Some(op));
        }
        assert_eq!(BindOpcode::for_opcode(0xD0), Some(BindOpcode::BIND_OPCODE_THREADED));
        assert_eq!(BindOpcode::for_opcode(0xE0), None);
        assert_eq!(BindOpcode::for_opcode(0xF0), None);
        assert_eq!(BindOpcode::VALUES.len(), 14);
    }

    #[test]
    fn to_data_type_is_one_byte_enum_in_macho_category() {
        let dt = BindOpcode::to_data_type();
        assert_eq!(dt.get_name(), "bind_opcode");
        assert_eq!(dt.get_length(), 1);
        assert_eq!(dt.get_category_path().to_string(), "/MachO");
    }
}
