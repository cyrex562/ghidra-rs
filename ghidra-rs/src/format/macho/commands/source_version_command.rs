//! Port of `ghidra.app.util.bin.format.macho.commands.SourceVersionCommand`.
//!
//! Represents a `source_version_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A `source_version_command` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.SourceVersionCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceVersionCommand {
    base: LoadCommandBase,
    version: i64,
}

impl SourceVersionCommand {
    /// Java: `SourceVersionCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let version = reader.read_next_long()?;
        Ok(SourceVersionCommand { base, version })
    }

    /// Java: `getVersion()`, the packed `A.B.C.D.E` version.
    pub fn get_version(&self) -> i64 {
        self.version
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.qword("version")?;
        s.finish_structure()
    }
}

impl StructConverter for SourceVersionCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for SourceVersionCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "source_version_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_source_version() {
        let mut b = Bytes::new(true);
        b.u32(0x2a).u32(16).u64(0x0000_0507_0000_0000);
        let cmd = SourceVersionCommand::new(&mut BinaryReader::from_bytes(b.buf, true)).unwrap();
        assert_eq!(cmd.get_version(), 0x0000_0507_0000_0000);
        let s = cmd.to_structure().unwrap();
        assert_eq!(s.get_length(), 16);
        assert_eq!(names(&s), ["cmd", "cmdsize", "version"]);
    }
}
