//! Port of `ghidra.app.util.bin.format.macho.commands.DynamicLinkerCommand`.
//!
//! Represents a `dylinker_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::load_command::{markup_raw_binary_base, LoadCommand, LoadCommandBase};
use crate::format::macho::commands::load_command_string::{markup_raw_binary_string, LoadCommandString};
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::MachStruct;
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program_module::ProgramModule;
use crate::util::task::TaskMonitor;

/// A `dylinker_command` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DynamicLinkerCommand`.
#[derive(Debug, Clone)]
pub struct DynamicLinkerCommand {
    base: LoadCommandBase,
    name: LoadCommandString,
}

impl DynamicLinkerCommand {
    /// Java: `DynamicLinkerCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let name = LoadCommandString::new(reader, &base)?;
        Ok(DynamicLinkerCommand { base, name })
    }

    /// Java: `getLoadCommandString()`.
    pub fn get_load_command_string(&self) -> &LoadCommandString {
        &self.name
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add(self.name.to_data_type()?, "name", None)?;
        s.finish_structure()
    }
}

impl StructConverter for DynamicLinkerCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for DynamicLinkerCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "dylinker_command".to_string()
    }

    fn markup_raw_binary(
        &self,
        header: &MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) {
        markup_raw_binary_base(self, header, api, base_address, parent_module, monitor, log);
        markup_raw_binary_string(self, &self.name, api, base_address, log, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_LOAD_DYLINKER;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    fn bytes(little: bool) -> Vec<u8> {
        let mut b = Bytes::new(little);
        b.u32(LC_LOAD_DYLINKER).u32(32).u32(12).name("@rpath/Foo", 20);
        b.buf
    }

    #[test]
    fn parses_both_endiannesses() {
        for little in [true, false] {
            let mut r = BinaryReader::from_bytes(bytes(little), little);
            let cmd = DynamicLinkerCommand::new(&mut r).unwrap();
            assert_eq!(r.get_pointer_index(), 12);
            assert_eq!(cmd.get_command_type() as u32, LC_LOAD_DYLINKER);
            assert_eq!(cmd.get_command_size(), 32);
            assert_eq!(cmd.get_load_command_string().get_offset(), 12);
            assert_eq!(cmd.get_load_command_string().get_string(), "@rpath/Foo");
        }
    }

    #[test]
    fn data_type_matches_java() {
        let cmd = DynamicLinkerCommand::new(&mut BinaryReader::from_bytes(bytes(true), true)).unwrap();
        assert_eq!(cmd.get_command_name(), "dylinker_command");
        let s = cmd.to_structure().unwrap();
        assert_eq!(s.get_name(), "dylinker_command");
        assert_eq!(s.get_length(), 12);
        assert_eq!(names(&s), ["cmd", "cmdsize", "name"]);
    }
}
