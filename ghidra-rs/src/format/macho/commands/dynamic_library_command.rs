//! Port of `ghidra.app.util.bin.format.macho.commands.DynamicLibraryCommand`.
//!
//! Represents a `dylib_command` structure (`LC_LOAD_DYLIB`, `LC_ID_DYLIB`, `LC_LOAD_WEAK_DYLIB`,
//! `LC_REEXPORT_DYLIB`, `LC_LAZY_LOAD_DYLIB`, `LC_LOAD_UPWARD_DYLIB`). See
//! `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::dynamic_library::DynamicLibrary;
use crate::format::macho::commands::load_command::{markup_raw_binary_base, LoadCommand, LoadCommandBase};
use crate::format::macho::commands::load_command_string::markup_raw_binary_string;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::MachStruct;
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program_module::ProgramModule;
use crate::util::task::TaskMonitor;

/// A Mach-O `dylib_command`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DynamicLibraryCommand`.
#[derive(Debug, Clone)]
pub struct DynamicLibraryCommand {
    base: LoadCommandBase,
    dylib: DynamicLibrary,
}

impl DynamicLibraryCommand {
    /// Java: `DynamicLibraryCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let dylib = DynamicLibrary::new(reader, &base)?;
        Ok(DynamicLibraryCommand { base, dylib })
    }

    /// Java: `getDynamicLibrary()`.
    pub fn get_dynamic_library(&self) -> &DynamicLibrary {
        &self.dylib
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add(self.dylib.to_data_type()?, "dylib", None)?;
        s.finish_structure()
    }
}

impl StructConverter for DynamicLibraryCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for DynamicLibraryCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "dylib_command".to_string()
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
        markup_raw_binary_string(self, self.dylib.get_name(), api, base_address, log, false);
    }
}

impl fmt::Display for DynamicLibraryCommand {
    /// Java: `toString()`, the library name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.dylib, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_LOAD_DYLIB;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::{fields, names};

    #[test]
    fn parses_dylib_command_both_endiannesses() {
        for little in [true, false] {
            let mut b = Bytes::new(little);
            b.u32(LC_LOAD_DYLIB).u32(56).u32(24).u32(2).u32(0x0001_0203).u32(0x0001_0000);
            b.name("/usr/lib/libSystem.B.dylib", 32);
            let mut r = BinaryReader::from_bytes(b.buf, little);
            let cmd = DynamicLibraryCommand::new(&mut r).unwrap();
            assert_eq!(r.get_pointer_index(), 24);
            let lib = cmd.get_dynamic_library();
            assert_eq!(lib.get_name().get_string(), "/usr/lib/libSystem.B.dylib");
            assert_eq!(lib.get_timestamp(), 2);
            assert_eq!(lib.get_current_version(), 0x0001_0203);
            assert_eq!(lib.get_compatibility_version(), 0x0001_0000);
            assert_eq!(cmd.to_string(), "/usr/lib/libSystem.B.dylib");
        }
    }

    #[test]
    fn data_type_nests_dylib_and_lc_str() {
        let mut b = Bytes::new(true);
        b.u32(LC_LOAD_DYLIB).u32(32).u32(24).u32(0).u32(0).u32(0).name("a", 8);
        let cmd = DynamicLibraryCommand::new(&mut BinaryReader::from_bytes(b.buf, true)).unwrap();
        let s = cmd.to_structure().unwrap();
        assert_eq!(s.get_name(), "dylib_command");
        assert_eq!(names(&s), ["cmd", "cmdsize", "dylib"]);
        assert_eq!(fields(&s)[2], ("dylib".to_string(), 8, 16));
        let d = cmd.get_dynamic_library().to_structure().unwrap();
        assert_eq!(names(&d), ["name", "timestamp", "current_version", "compatibility_version"]);
    }
}
