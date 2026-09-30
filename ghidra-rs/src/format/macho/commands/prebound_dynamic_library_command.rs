//! Port of `ghidra.app.util.bin.format.macho.commands.PreboundDynamicLibraryCommand`.
//!
//! Represents a `prebound_dylib_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

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

/// A Mach-O `prebound_dylib_command`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.PreboundDynamicLibraryCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreboundDynamicLibraryCommand {
    base: LoadCommandBase,
    name: LoadCommandString,
    nmodules: i64,
    linked_modules: LoadCommandString,
}

impl PreboundDynamicLibraryCommand {
    /// Java: `PreboundDynamicLibraryCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let name = LoadCommandString::new(reader, &base)?;
        let mut cmd = PreboundDynamicLibraryCommand {
            base,
            name,
            nmodules: 0,
            linked_modules: LoadCommandString::default(),
        };
        cmd.nmodules = cmd.check_count(reader.read_next_unsigned_int()? as i64)?;
        cmd.linked_modules = LoadCommandString::new(reader, &cmd.base)?;
        Ok(cmd)
    }

    /// Java: `getLibraryName()`.
    pub fn get_library_name(&self) -> &str {
        self.name.get_string()
    }

    /// Java: `getNumberOfModules()`.
    pub fn get_number_of_modules(&self) -> i64 {
        self.nmodules
    }

    /// Java: `getLinkedModules()`.
    pub fn get_linked_modules(&self) -> &str {
        self.linked_modules.get_string()
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add(self.name.to_data_type()?, "name", None)?;
        s.dword("nmodules")?;
        s.add(self.linked_modules.to_data_type()?, "linked_modules", None)?;
        s.finish_structure()
    }
}

impl StructConverter for PreboundDynamicLibraryCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for PreboundDynamicLibraryCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "prebound_dylib_command".to_string()
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
        markup_raw_binary_string(self, &self.name, api, base_address, log, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_prebound_dylib() {
        let mut b = Bytes::new(true);
        b.u32(0x10).u32(36).u32(20).u32(3).u32(28).name("libA", 8).raw(&[0x05, 0, 0, 0, 0, 0, 0, 0]);
        let cmd = PreboundDynamicLibraryCommand::new(&mut BinaryReader::from_bytes(b.buf, true)).unwrap();
        assert_eq!(cmd.get_library_name(), "libA");
        assert_eq!(cmd.get_number_of_modules(), 3);
        assert_eq!(cmd.get_linked_modules(), "\u{5}");
        assert_eq!(
            names(&cmd.to_structure().unwrap()),
            ["cmd", "cmdsize", "name", "nmodules", "linked_modules"]
        );
    }
}
