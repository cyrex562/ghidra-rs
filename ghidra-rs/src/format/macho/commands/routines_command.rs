//! Port of `ghidra.app.util.bin.format.macho.commands.RoutinesCommand`.
//!
//! Represents a `routines_command` / `routines_command_64` structure. See
//! `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

const FIELD_NAMES: [&str; 8] = [
    "init_address",
    "init_module",
    "reserved1",
    "reserved2",
    "reserved3",
    "reserved4",
    "reserved5",
    "reserved6",
];

/// A Mach-O `routines_command` (32-bit) or `routines_command_64`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.RoutinesCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutinesCommand {
    base: LoadCommandBase,
    /// `init_address`, `init_module`, `reserved1`..`reserved6`, in that order.
    values: [i64; 8],
    is32bit: bool,
}

impl RoutinesCommand {
    /// Java: `RoutinesCommand(BinaryReader, boolean)`.
    pub fn new(reader: &mut BinaryReader, is32bit: bool) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let mut values = [0i64; 8];
        for v in values.iter_mut() {
            *v = if is32bit {
                reader.read_next_unsigned_int()? as i64
            } else {
                reader.read_next_long()?
            };
        }
        Ok(RoutinesCommand { base, values, is32bit })
    }

    /// Java: `getInitializationRoutineAddress()`.
    pub fn get_initialization_routine_address(&self) -> i64 {
        self.values[0]
    }

    /// Java: `getInitializationRoutineModuleIndex()`.
    pub fn get_initialization_routine_module_index(&self) -> i64 {
        self.values[1]
    }

    /// Java: `getReserved1()`.
    pub fn get_reserved1(&self) -> i64 {
        self.values[2]
    }

    /// Java: `getReserved2()`.
    pub fn get_reserved2(&self) -> i64 {
        self.values[3]
    }

    /// Java: `getReserved3()`.
    pub fn get_reserved3(&self) -> i64 {
        self.values[4]
    }

    /// Java: `getReserved4()`.
    pub fn get_reserved4(&self) -> i64 {
        self.values[5]
    }

    /// Java: `getReserved5()`.
    pub fn get_reserved5(&self) -> i64 {
        self.values[6]
    }

    /// Java: `getReserved6()`.
    pub fn get_reserved6(&self) -> i64 {
        self.values[7]
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        for name in FIELD_NAMES {
            if self.is32bit {
                s.dword(name)?;
            } else {
                s.qword(name)?;
            }
        }
        s.finish_structure()
    }
}

impl StructConverter for RoutinesCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for RoutinesCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "routines_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;

    #[test]
    fn parses_32_and_64_bit_layouts() {
        let mut b = Bytes::new(false);
        b.u32(0x11).u32(40);
        for v in [0x8000_1000u32, 2, 3, 4, 5, 6, 7, 8] {
            b.u32(v);
        }
        let cmd = RoutinesCommand::new(&mut BinaryReader::from_bytes(b.buf, false), true).unwrap();
        assert_eq!(cmd.get_initialization_routine_address(), 0x8000_1000, "unsigned");
        assert_eq!(cmd.get_initialization_routine_module_index(), 2);
        assert_eq!(cmd.get_reserved6(), 8);
        assert_eq!(cmd.to_structure().unwrap().get_length(), 40);

        let mut b = Bytes::new(true);
        b.u32(0x1a).u32(72);
        for v in 1..=8u64 {
            b.u64(v << 32);
        }
        let cmd = RoutinesCommand::new(&mut BinaryReader::from_bytes(b.buf, true), false).unwrap();
        assert_eq!(cmd.get_initialization_routine_address(), 1 << 32);
        assert_eq!(cmd.get_reserved1(), 3 << 32);
        assert_eq!(cmd.get_reserved5(), 7 << 32);
        assert_eq!(cmd.to_structure().unwrap().get_length(), 72);
    }
}
