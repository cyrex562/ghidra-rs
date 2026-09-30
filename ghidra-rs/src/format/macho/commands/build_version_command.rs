//! Port of `ghidra.app.util.bin.format.macho.commands.BuildVersionCommand`.
//!
//! Represents a `build_version_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::{array, MachStruct};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A Mach-O `build_version_command`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.BuildVersionCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildVersionCommand {
    base: LoadCommandBase,
    platform: i32,
    minos: i32,
    sdk: i32,
    ntools: i64,
    build_tool_versions: Vec<BuildToolVersion>,
}

impl BuildVersionCommand {
    /// Java: `BuildVersionCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let platform = reader.read_next_int()?;
        let minos = reader.read_next_int()?;
        let sdk = reader.read_next_int()?;
        let mut cmd = BuildVersionCommand {
            base,
            platform,
            minos,
            sdk,
            ntools: 0,
            build_tool_versions: Vec::new(),
        };
        cmd.ntools = cmd.check_count(reader.read_next_unsigned_int()? as i64)?;
        for _ in 0..cmd.ntools {
            let tool = reader.read_next_int()?;
            let version = reader.read_next_int()?;
            cmd.build_tool_versions.push(BuildToolVersion::new(tool, version));
        }
        Ok(cmd)
    }

    /// Java: `getPlatform()`.
    pub fn get_platform(&self) -> i32 {
        self.platform
    }

    /// Java: `getMinOS()`.
    pub fn get_min_os(&self) -> i32 {
        self.minos
    }

    /// Java: `getSdk()`.
    pub fn get_sdk(&self) -> i32 {
        self.sdk
    }

    /// Java: `getNumTools()`.
    pub fn get_num_tools(&self) -> i64 {
        self.ntools
    }

    /// The parsed `build_tool_version` entries. Java keeps them in a private array with no
    /// accessor; exposed here so they are observable.
    pub fn get_build_tool_versions(&self) -> &[BuildToolVersion] {
        &self.build_tool_versions
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let tool_dt = BuildToolVersion::new(0, 0).to_data_type()?;
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?.dword("platform")?.dword("minos")?.dword("sdk")?;
        s.dword("ntools")?;
        if self.ntools > 0 {
            s.add(array(tool_dt, self.ntools as i32)?, "build_tool_version[]", None)?;
        }
        s.finish_structure()
    }
}

impl StructConverter for BuildVersionCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for BuildVersionCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "build_version_command".to_string()
    }
}

/// A `build_tool_version` entry.
///
/// Port of the nested `BuildVersionCommand.BuildToolVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildToolVersion {
    tool: i32,
    version: i32,
}

impl BuildToolVersion {
    /// Java: `BuildToolVersion(int, int)`.
    pub fn new(tool: i32, version: i32) -> Self {
        BuildToolVersion { tool, version }
    }

    /// Java: `getTool()`.
    pub fn get_tool(&self) -> i32 {
        self.tool
    }

    /// Java: `getVersion()`.
    pub fn get_version(&self) -> i32 {
        self.version
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("build_tool_version");
        s.dword("tool")?.dword("version")?;
        s.finish_structure()
    }
}

impl StructConverter for BuildToolVersion {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::{fields, names};

    #[test]
    fn parses_tools_and_builds_array_type() {
        let mut b = Bytes::new(true);
        b.u32(0x32).u32(40).u32(1).u32(0x000b_0000).u32(0x000b_0300).u32(2);
        b.u32(3).u32(0x0305_0100).u32(4).u32(0x0400_0000);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let cmd = BuildVersionCommand::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 40);
        assert_eq!(cmd.get_platform(), 1);
        assert_eq!(cmd.get_min_os(), 0x000b_0000);
        assert_eq!(cmd.get_sdk(), 0x000b_0300);
        assert_eq!(cmd.get_num_tools(), 2);
        assert_eq!(cmd.get_build_tool_versions()[1], BuildToolVersion::new(4, 0x0400_0000));
        let s = cmd.to_structure().unwrap();
        assert_eq!(s.get_length(), 40);
        assert_eq!(fields(&s).last().unwrap(), &("build_tool_version[]".to_string(), 24, 16));
    }

    #[test]
    fn no_tools_means_no_array() {
        let mut b = Bytes::new(false);
        b.u32(0x32).u32(24).u32(2).u32(0).u32(0).u32(0);
        let cmd = BuildVersionCommand::new(&mut BinaryReader::from_bytes(b.buf, false)).unwrap();
        assert_eq!(
            names(&cmd.to_structure().unwrap()),
            ["cmd", "cmdsize", "platform", "minos", "sdk", "ntools"]
        );
    }
}
