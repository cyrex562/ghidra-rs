//! Port of `ghidra.app.util.bin.format.macho.commands.SubClientCommand`.
//!
//! Represents a `sub_client_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

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

/// A `sub_client_command` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.SubClientCommand`.
#[derive(Debug, Clone)]
pub struct SubClientCommand {
    base: LoadCommandBase,
    client: LoadCommandString,
}

impl SubClientCommand {
    /// Java: `SubClientCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let client = LoadCommandString::new(reader, &base)?;
        Ok(SubClientCommand { base, client })
    }

    /// Java: `getClientName()`.
    pub fn get_client_name(&self) -> &LoadCommandString {
        &self.client
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add(self.client.to_data_type()?, "client", None)?;
        s.finish_structure()
    }
}

impl StructConverter for SubClientCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for SubClientCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "sub_client_command".to_string()
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
        markup_raw_binary_string(self, &self.client, api, base_address, log, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_SUB_CLIENT;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    fn bytes(little: bool) -> Vec<u8> {
        let mut b = Bytes::new(little);
        b.u32(LC_SUB_CLIENT).u32(32).u32(12).name("@rpath/Foo", 20);
        b.buf
    }

    #[test]
    fn parses_both_endiannesses() {
        for little in [true, false] {
            let mut r = BinaryReader::from_bytes(bytes(little), little);
            let cmd = SubClientCommand::new(&mut r).unwrap();
            assert_eq!(r.get_pointer_index(), 12);
            assert_eq!(cmd.get_command_type() as u32, LC_SUB_CLIENT);
            assert_eq!(cmd.get_command_size(), 32);
            assert_eq!(cmd.get_client_name().get_offset(), 12);
            assert_eq!(cmd.get_client_name().get_string(), "@rpath/Foo");
        }
    }

    #[test]
    fn data_type_matches_java() {
        let cmd = SubClientCommand::new(&mut BinaryReader::from_bytes(bytes(true), true)).unwrap();
        assert_eq!(cmd.get_command_name(), "sub_client_command");
        let s = cmd.to_structure().unwrap();
        assert_eq!(s.get_name(), "sub_client_command");
        assert_eq!(s.get_length(), 12);
        assert_eq!(names(&s), ["cmd", "cmdsize", "client"]);
    }
}
