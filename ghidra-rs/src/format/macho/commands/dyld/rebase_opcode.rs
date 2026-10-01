//! Port of `ghidra.app.util.bin.format.macho.commands.dyld.RebaseOpcode`.
//!
//! Rebase opcodes. See
//! <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/loader.h>.

use crate::format::macho::mach_constants::DATA_TYPE_CATEGORY;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Port of `ghidra.app.util.bin.format.macho.commands.dyld.RebaseOpcode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum RebaseOpcode {
    REBASE_OPCODE_DONE,
    REBASE_OPCODE_SET_TYPE_IMM,
    REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    REBASE_OPCODE_ADD_ADDR_ULEB,
    REBASE_OPCODE_ADD_ADDR_IMM_SCALED,
    REBASE_OPCODE_DO_REBASE_IMM_TIMES,
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES,
    REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
    REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
}

impl RebaseOpcode {
    /// Java `RebaseOpcode.values()`, in declaration order.
    pub const VALUES: [RebaseOpcode; 9] = [
        RebaseOpcode::REBASE_OPCODE_DONE,
        RebaseOpcode::REBASE_OPCODE_SET_TYPE_IMM,
        RebaseOpcode::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
        RebaseOpcode::REBASE_OPCODE_ADD_ADDR_ULEB,
        RebaseOpcode::REBASE_OPCODE_ADD_ADDR_IMM_SCALED,
        RebaseOpcode::REBASE_OPCODE_DO_REBASE_IMM_TIMES,
        RebaseOpcode::REBASE_OPCODE_DO_REBASE_ULEB_TIMES,
        RebaseOpcode::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB,
        RebaseOpcode::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB,
    ];

    /// Java `getOpcode()`.
    pub fn get_opcode(self) -> i32 {
        match self {
            RebaseOpcode::REBASE_OPCODE_DONE => 0x00,
            RebaseOpcode::REBASE_OPCODE_SET_TYPE_IMM => 0x10,
            RebaseOpcode::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => 0x20,
            RebaseOpcode::REBASE_OPCODE_ADD_ADDR_ULEB => 0x30,
            RebaseOpcode::REBASE_OPCODE_ADD_ADDR_IMM_SCALED => 0x40,
            RebaseOpcode::REBASE_OPCODE_DO_REBASE_IMM_TIMES => 0x50,
            RebaseOpcode::REBASE_OPCODE_DO_REBASE_ULEB_TIMES => 0x60,
            RebaseOpcode::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => 0x70,
            RebaseOpcode::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => 0x80,
        }
    }

    /// Java `toString()` (the constant name).
    pub fn name(self) -> &'static str {
        match self {
            RebaseOpcode::REBASE_OPCODE_DONE => "REBASE_OPCODE_DONE",
            RebaseOpcode::REBASE_OPCODE_SET_TYPE_IMM => "REBASE_OPCODE_SET_TYPE_IMM",
            RebaseOpcode::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB"
            }
            RebaseOpcode::REBASE_OPCODE_ADD_ADDR_ULEB => "REBASE_OPCODE_ADD_ADDR_ULEB",
            RebaseOpcode::REBASE_OPCODE_ADD_ADDR_IMM_SCALED => "REBASE_OPCODE_ADD_ADDR_IMM_SCALED",
            RebaseOpcode::REBASE_OPCODE_DO_REBASE_IMM_TIMES => "REBASE_OPCODE_DO_REBASE_IMM_TIMES",
            RebaseOpcode::REBASE_OPCODE_DO_REBASE_ULEB_TIMES => "REBASE_OPCODE_DO_REBASE_ULEB_TIMES",
            RebaseOpcode::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                "REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB"
            }
            RebaseOpcode::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                "REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB"
            }
        }
    }

    /// Java `static toDataType()`: a 1-byte `rebase_opcode` enum in the `/MachO` category.
    pub fn to_data_type() -> Box<dyn DataType> {
        let mut enum_dt = EnumDataType::new("rebase_opcode", 1);
        if let Ok(path) = CategoryPath::parse(DATA_TYPE_CATEGORY) {
            let _ = enum_dt.set_category_path(path);
        }
        for op in Self::VALUES {
            Enum::add(&mut enum_dt, op.name(), op.get_opcode() as i64);
        }
        Box::new(enum_dt)
    }

    /// Java `static forOpcode(int)`. `None` stands in for Java's `null`.
    pub fn for_opcode(opcode: i32) -> Option<RebaseOpcode> {
        Self::VALUES.into_iter().find(|op| op.get_opcode() == opcode)
    }
}

impl std::fmt::Display for RebaseOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_opcode_round_trips_and_rejects_unknown() {
        for op in RebaseOpcode::VALUES {
            assert_eq!(RebaseOpcode::for_opcode(op.get_opcode()), Some(op));
        }
        assert_eq!(
            RebaseOpcode::for_opcode(0x70),
            Some(RebaseOpcode::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB)
        );
        assert_eq!(RebaseOpcode::for_opcode(0x90), None);
        assert_eq!(RebaseOpcode::for_opcode(0x11), None);
    }

    #[test]
    fn to_data_type_is_one_byte_enum_in_macho_category() {
        let dt = RebaseOpcode::to_data_type();
        assert_eq!(dt.get_name(), "rebase_opcode");
        assert_eq!(dt.get_length(), 1);
        assert_eq!(dt.get_category_path().to_string(), "/MachO");
    }
}
