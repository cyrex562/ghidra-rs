//! Port of `ghidra.app.util.bin.format.macho.commands.SubFrameworkCommand`.
//!
//! Represents a `sub_framework_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

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

/// A `sub_framework_command` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.SubFrameworkCommand`.
#[derive(Debug, Clone)]
pub struct SubFrameworkCommand {
    base: LoadCommandBase,
    umbrella: LoadCommandString,
}

impl SubFrameworkCommand {
    /// Java: `SubFrameworkCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let umbrella = LoadCommandString::new(reader, &base)?;
        Ok(SubFrameworkCommand { base, umbrella })
    }

    /// Java: `getUmbrellaFrameworkName()`.
    pub fn get_umbrella_framework_name(&self) -> &LoadCommandString {
        &self.umbrella
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add(self.umbrella.to_data_type()?, "umbrella", None)?;
        s.finish_structure()
    }
}

impl StructConverter for SubFrameworkCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for SubFrameworkCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "sub_framework_command".to_string()
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
        markup_raw_binary_string(self, &self.umbrella, api, base_address, log, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_SUB_FRAMEWORK;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    fn bytes(little: bool) -> Vec<u8> {
        let mut b = Bytes::new(little);
        b.u32(LC_SUB_FRAMEWORK).u32(32).u32(12).name("@rpath/Foo", 20);
        b.buf
    }

    #[test]
    fn parses_both_endiannesses() {
        for little in [true, false] {
            let mut r = BinaryReader::from_bytes(bytes(little), little);
            let cmd = SubFrameworkCommand::new(&mut r).unwrap();
            assert_eq!(r.get_pointer_index(), 12);
            assert_eq!(cmd.get_command_type() as u32, LC_SUB_FRAMEWORK);
            assert_eq!(cmd.get_command_size(), 32);
            assert_eq!(cmd.get_umbrella_framework_name().get_offset(), 12);
            assert_eq!(cmd.get_umbrella_framework_name().get_string(), "@rpath/Foo");
        }
    }

    #[test]
    fn data_type_matches_java() {
        let cmd = SubFrameworkCommand::new(&mut BinaryReader::from_bytes(bytes(true), true)).unwrap();
        assert_eq!(cmd.get_command_name(), "sub_framework_command");
        let s = cmd.to_structure().unwrap();
        assert_eq!(s.get_name(), "sub_framework_command");
        assert_eq!(s.get_length(), 12);
        assert_eq!(names(&s), ["cmd", "cmdsize", "umbrella"]);
    }
}
