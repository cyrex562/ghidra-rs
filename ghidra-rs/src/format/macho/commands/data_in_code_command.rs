//! Port of `ghidra.app.util.bin.format.macho.commands.DataInCodeCommand`.
//!
//! Represents an `LC_DATA_IN_CODE` `linkedit_data_command`. See
//! [`LinkEditDataCommand`] for how the inherited state is shared.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::data_in_code_entry::DataInCodeEntry;
use crate::format::macho::commands::link_edit_data_command::LinkEditDataCommand;
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::mach_header::MachHeader;
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_module::ProgramModule;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
struct Du;
impl DataUtilities for Du {}

/// An `LC_DATA_IN_CODE` command.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DataInCodeCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataInCodeCommand {
    link_edit: LinkEditDataCommand,
    entries: Vec<DataInCodeEntry>,
}

impl DataInCodeCommand {
    /// Java: `DataInCodeCommand(BinaryReader, BinaryReader)`.
    pub fn new(load_command_reader: &mut BinaryReader, data_reader: &mut BinaryReader) -> io::Result<Self> {
        let link_edit = LinkEditDataCommand::new(load_command_reader, data_reader)?;
        let mut entries = Vec::new();
        let mut i = 0i64;
        while i + DataInCodeEntry::SIZE as i64 <= link_edit.datasize() {
            entries.push(DataInCodeEntry::new(data_reader)?);
            i += DataInCodeEntry::SIZE as i64;
        }
        Ok(DataInCodeCommand { link_edit, entries })
    }

    /// The inherited `LinkEditDataCommand` state.
    pub fn link_edit(&self) -> &LinkEditDataCommand {
        &self.link_edit
    }

    /// Java: `getEntries()`.
    pub fn get_entries(&self) -> &[DataInCodeEntry] {
        &self.entries
    }

    fn markup_entries(&self, program: &dyn Program, mut addr: Address) -> Result<(), String> {
        for entry in &self.entries {
            let dt = entry.to_data_type().map_err(|e| e.to_string())?;
            Du.create_data(program, &addr, dt, -1, ClearDataMode::CheckForSpace)
                .map_err(|e| e.to_string())?;
            addr = addr.add(DataInCodeEntry::SIZE as i64).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

impl StructConverter for DataInCodeCommand {
    /// Java: the inherited `LinkEditDataCommand.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        self.link_edit.to_data_type()
    }
}

impl LoadCommand for DataInCodeCommand {
    fn base(&self) -> &LoadCommandBase {
        self.link_edit.base()
    }

    fn get_command_name(&self) -> String {
        self.link_edit.get_command_name()
    }

    fn get_linker_data_offset(&self) -> i64 {
        self.link_edit.dataoff()
    }

    fn get_linker_data_size(&self) -> i64 {
        self.link_edit.datasize()
    }

    fn markup(
        &self,
        program: &mut dyn Program,
        header: &MachHeader,
        source: Option<&str>,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        let Some(addr) =
            self.file_offset_to_address(program, header, self.link_edit.dataoff(), self.link_edit.datasize())
        else {
            return Ok(());
        };
        self.link_edit.markup(program, header, source, monitor, log)?;
        if self.markup_entries(program, addr).is_err() {
            log.append_msg_from(
                Some("DataInCodeCommand"),
                &format!("Failed to markup: {}", self.get_contextual_name(source, None)),
            );
        }
        Ok(())
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
        self.link_edit.markup_raw_binary(header, api, base_address, parent_module, monitor, log);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::link_edit_data_command::test_support::link_edit_bytes;
    use crate::format::macho::commands::load_command_types::LC_DATA_IN_CODE;

    #[test]
    fn reads_whole_entries_only() {
        let mut b = link_edit_bytes(LC_DATA_IN_CODE, 16, 20);
        b.u32(0x100).u16(4).u16(1).u32(0x200).u16(8).u16(2).u32(0xdead);
        let mut lc = BinaryReader::from_bytes(b.buf, true);
        let mut data = lc.clone_reader();
        let cmd = DataInCodeCommand::new(&mut lc, &mut data).unwrap();
        assert_eq!(cmd.get_entries().len(), 2, "20 bytes hold two 8-byte entries");
        assert_eq!(cmd.get_entries()[1].get_offset(), 0x200);
        assert_eq!(cmd.get_entries()[1].get_kind(), 2);
        assert_eq!(cmd.get_command_type() as u32, LC_DATA_IN_CODE);
        assert_eq!(cmd.get_linker_data_size(), 20);
        assert_eq!(cmd.get_command_name(), "linkedit_data_command");
    }
}
