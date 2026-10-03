//! Port of `ghidra.app.util.bin.format.macho.commands.DynamicLibrary`.
//!
//! Represents a `dylib` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::LoadCommandBase;
use crate::format::macho::commands::load_command_string::LoadCommandString;
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A Mach-O `dylib` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DynamicLibrary`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicLibrary {
    name: LoadCommandString,
    timestamp: i32,
    current_version: i32,
    compatibility_version: i32,
}

impl DynamicLibrary {
    /// Java: `DynamicLibrary(BinaryReader, LoadCommand)`. `command` is the owning load command's
    /// already-read base state, against whose start the name's `lc_str` offset is resolved.
    pub fn new(reader: &mut BinaryReader, command: &LoadCommandBase) -> io::Result<Self> {
        let name = LoadCommandString::new(reader, command)?;
        let timestamp = reader.read_next_int()?;
        let current_version = reader.read_next_int()?;
        let compatibility_version = reader.read_next_int()?;
        Ok(DynamicLibrary { name, timestamp, current_version, compatibility_version })
    }

    /// Java: `getName()`.
    pub fn get_name(&self) -> &LoadCommandString {
        &self.name
    }

    /// Java: `getTimestamp()`.
    pub fn get_timestamp(&self) -> i32 {
        self.timestamp
    }

    /// Java: `getCurrentVersion()`.
    pub fn get_current_version(&self) -> i32 {
        self.current_version
    }

    /// Java: `getCompatibilityVersion()`.
    pub fn get_compatibility_version(&self) -> i32 {
        self.compatibility_version
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dylib");
        s.add(self.name.to_data_type()?, "name", None)?;
        s.dword("timestamp")?.dword("current_version")?.dword("compatibility_version")?;
        s.finish_structure()
    }
}

impl StructConverter for DynamicLibrary {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl fmt::Display for DynamicLibrary {
    /// Java: `toString()`, the library name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.name, f)
    }
}
