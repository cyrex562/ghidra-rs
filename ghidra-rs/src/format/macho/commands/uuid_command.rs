//! Port of `ghidra.app.util.bin.format.macho.commands.UuidCommand`.
//!
//! Represents a `uuid_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::format::macho::struct_builder::{array, byte};

/// A `uuid_command` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.UuidCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UuidCommand {
    base: LoadCommandBase,
    uuid: Vec<u8>,
}

impl UuidCommand {
    /// Java: `UuidCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let uuid = reader.read_next_byte_array(16)?;
        Ok(UuidCommand { base, uuid })
    }

    /// Java: `getUUID()`, the 128-bit UUID.
    pub fn get_uuid(&self) -> &[u8] {
        &self.uuid
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add(array(byte(), 16)?, "uuid", None)?;
        s.finish_structure()
    }
}

impl StructConverter for UuidCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for UuidCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "uuid_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_uuid() {
        let mut b = Bytes::new(false);
        b.u32(0x1b).u32(24).raw(&(0u8..16).collect::<Vec<_>>());
        let mut r = BinaryReader::from_bytes(b.buf, false);
        let cmd = UuidCommand::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 24);
        assert_eq!(cmd.get_uuid(), (0u8..16).collect::<Vec<_>>().as_slice());
        let s = cmd.to_structure().unwrap();
        assert_eq!(s.get_name(), "uuid_command");
        assert_eq!(s.get_length(), 24);
        assert_eq!(names(&s), ["cmd", "cmdsize", "uuid"]);
    }
}
