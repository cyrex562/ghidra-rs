//! Port of `ghidra.app.util.bin.format.macho.commands.FixedVirtualMemoryFileCommand`.
//!
//! Represents a `fvmfile_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.
//!
//! Java's constructor reads only the load command header and never initializes `name` or
//! `header_addr` (so `getPathname()`/`toDataType()` throw `NullPointerException`). This port keeps
//! that behaviour observable rather than inventing a parse: [`get_pathname`](FixedVirtualMemoryFileCommand::get_pathname)
//! returns `None` and [`to_structure`](FixedVirtualMemoryFileCommand::to_structure) fails.

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

/// A Mach-O `fvmfile_command`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.FixedVirtualMemoryFileCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedVirtualMemoryFileCommand {
    base: LoadCommandBase,
    name: Option<LoadCommandString>,
    header_addr: i64,
}

impl FixedVirtualMemoryFileCommand {
    /// Java: `FixedVirtualMemoryFileCommand(BinaryReader)`. Reads only the header (see the module
    /// docs).
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(FixedVirtualMemoryFileCommand {
            base: LoadCommandBase::new(reader)?,
            name: None,
            header_addr: 0,
        })
    }

    /// Java: `getPathname()`. `None` where Java throws `NullPointerException`.
    pub fn get_pathname(&self) -> Option<&str> {
        self.name.as_ref().map(LoadCommandString::get_string)
    }

    /// Java: `getHeaderAddress()`.
    pub fn get_header_address(&self) -> i64 {
        self.header_addr
    }

    fn null_name() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, "fvmfile_command name was never read")
    }

    /// Java: `toDataType()`, returning the concrete structure. Fails as Java's does (see the module
    /// docs).
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let name = self.name.as_ref().ok_or_else(Self::null_name)?;
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add(name.to_data_type()?, "name", None)?;
        s.dword("header_addr")?;
        s.finish_structure()
    }
}

impl StructConverter for FixedVirtualMemoryFileCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for FixedVirtualMemoryFileCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "fvmfile_command".to_string()
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
        match &self.name {
            Some(name) => markup_raw_binary_string(self, name, api, base_address, log, false),
            None => log.append_msg(&format!("Unable to create {}", self.get_command_name())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_the_header_like_java() {
        let mut b = 0x9u32.to_le_bytes().to_vec();
        b.extend(24u32.to_le_bytes());
        b.extend([0u8; 16]);
        let mut r = BinaryReader::from_bytes(b, true);
        let cmd = FixedVirtualMemoryFileCommand::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 8);
        assert_eq!(cmd.get_command_name(), "fvmfile_command");
        assert!(cmd.get_pathname().is_none());
        assert_eq!(cmd.get_header_address(), 0);
        assert!(cmd.to_structure().is_err());
    }
}
