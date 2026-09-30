//! Port of `ghidra.app.util.bin.format.macho.commands.UnsupportedLoadCommand`.
//!
//! A load command whose type is recognized (or not) but not parsed.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// An unsupported load command.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.UnsupportedLoadCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedLoadCommand {
    base: LoadCommandBase,
}

impl UnsupportedLoadCommand {
    /// Java: `UnsupportedLoadCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(UnsupportedLoadCommand { base: LoadCommandBase::new(reader)? })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.finish_structure()
    }
}

impl StructConverter for UnsupportedLoadCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for UnsupportedLoadCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "unsupported_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn reads_only_header() {
        let mut b = 0xau32.to_be_bytes().to_vec();
        b.extend(16u32.to_be_bytes());
        b.extend([0u8; 8]);
        let mut r = BinaryReader::from_bytes(b, false);
        let cmd = UnsupportedLoadCommand::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 8);
        assert_eq!(cmd.get_command_type(), 0xa);
        assert_eq!(cmd.get_command_size(), 16);
        assert_eq!(cmd.get_command_name(), "unsupported_command");
        assert_eq!(names(&cmd.to_structure().unwrap()), ["cmd", "cmdsize"]);
    }
}
