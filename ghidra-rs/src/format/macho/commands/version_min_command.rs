//! Port of `ghidra.app.util.bin.format.macho.commands.VersionMinCommand`.
//!
//! Represents a `version_min_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A `version_min_command` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.VersionMinCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMinCommand {
    base: LoadCommandBase,
    version: i32,
    sdk: i32,
}

impl VersionMinCommand {
    /// Java: `VersionMinCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let version = reader.read_next_int()?;
        let sdk = reader.read_next_int()?;
        Ok(VersionMinCommand { base, version, sdk })
    }

    /// Java: `getVersion()`.
    pub fn get_version(&self) -> i32 {
        self.version
    }

    /// Java: `getSdk()`.
    pub fn get_sdk(&self) -> i32 {
        self.sdk
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.dword("version")?.dword("sdk")?;
        s.finish_structure()
    }
}

impl StructConverter for VersionMinCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for VersionMinCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "version_min_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_version_min() {
        let mut b = Bytes::new(false);
        b.u32(0x24).u32(16).u32(0x000a_0e00).u32(0x000a_0f00);
        let cmd = VersionMinCommand::new(&mut BinaryReader::from_bytes(b.buf, false)).unwrap();
        assert_eq!(cmd.get_version(), 0x000a_0e00);
        assert_eq!(cmd.get_sdk(), 0x000a_0f00);
        assert_eq!(names(&cmd.to_structure().unwrap()), ["cmd", "cmdsize", "version", "sdk"]);
    }
}
