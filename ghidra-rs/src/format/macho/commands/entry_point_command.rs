//! Port of `ghidra.app.util.bin.format.macho.commands.EntryPointCommand`.
//!
//! Represents an `entry_point_command` structure (`LC_MAIN`). See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// An `entry_point_command` structure (`LC_MAIN`).
///
/// Port of `ghidra.app.util.bin.format.macho.commands.EntryPointCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPointCommand {
    base: LoadCommandBase,
    entry_offset: i64,
    stack_size: i64,
}

impl EntryPointCommand {
    /// Java: `EntryPointCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let entry_offset = reader.read_next_long()?;
        let stack_size = reader.read_next_long()?;
        Ok(EntryPointCommand { base, entry_offset, stack_size })
    }

    /// Java: `getEntryOffset()`.
    pub fn get_entry_offset(&self) -> i64 {
        self.entry_offset
    }

    /// Java: `getStackSize()`.
    pub fn get_stack_size(&self) -> i64 {
        self.stack_size
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.qword("entryoff")?.qword("stacksize")?;
        s.finish_structure()
    }
}

impl StructConverter for EntryPointCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for EntryPointCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "entry_point_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_entry_point() {
        for little in [true, false] {
            let mut b = Bytes::new(little);
            b.u32(0x8000_0028).u32(24).u64(0x3f40).u64(0x10_0000);
            let cmd = EntryPointCommand::new(&mut BinaryReader::from_bytes(b.buf, little)).unwrap();
            assert_eq!(cmd.get_entry_offset(), 0x3f40);
            assert_eq!(cmd.get_stack_size(), 0x10_0000);
        }
        let mut b = Bytes::new(true);
        b.u32(0x8000_0028).u32(24).u64(0).u64(0);
        let s = EntryPointCommand::new(&mut BinaryReader::from_bytes(b.buf, true)).unwrap().to_structure().unwrap();
        assert_eq!(s.get_length(), 24);
        assert_eq!(names(&s), ["cmd", "cmdsize", "entryoff", "stacksize"]);
    }
}
