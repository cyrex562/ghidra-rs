//! Port of `ghidra.app.util.bin.format.macho.commands.DyldExportsTrieCommand`.
//!
//! Represents an `LC_DYLD_EXPORTS_TRIE` `linkedit_data_command`. See [`LinkEditDataCommand`] for
//! how the inherited state is shared.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::export_trie::ExportTrie;
use crate::format::macho::commands::link_edit_data_command::LinkEditDataCommand;
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::{fixed_string, uleb128};
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

/// An `LC_DYLD_EXPORTS_TRIE` command.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.DyldExportsTrieCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldExportsTrieCommand {
    link_edit: LinkEditDataCommand,
    export_trie: ExportTrie,
}

impl DyldExportsTrieCommand {
    /// Java: `DyldExportsTrieCommand(BinaryReader, BinaryReader)`. An empty trie when the command
    /// points at no data.
    pub fn new(load_command_reader: &mut BinaryReader, data_reader: &mut BinaryReader) -> io::Result<Self> {
        let link_edit = LinkEditDataCommand::new(load_command_reader, data_reader)?;
        let export_trie = if link_edit.dataoff() > 0 && link_edit.datasize() > 0 {
            ExportTrie::from_reader(data_reader)?
        } else {
            ExportTrie::new()
        };
        Ok(DyldExportsTrieCommand { link_edit, export_trie })
    }

    /// The inherited `LinkEditDataCommand` state.
    pub fn link_edit(&self) -> &LinkEditDataCommand {
        &self.link_edit
    }

    /// Java: `getExportTrie()`.
    pub fn get_export_trie(&self) -> &ExportTrie {
        &self.export_trie
    }

    fn markup_trie(&self, program: &dyn Program, addr: &Address) -> Result<(), String> {
        let err = |e: &dyn std::fmt::Display| e.to_string();
        for &offset in self.export_trie.uleb_offsets() {
            let a = addr.add(offset as i64).map_err(|e| err(&e))?;
            Du.create_data(program, &a, uleb128().map_err(|e| err(&e))?, -1, ClearDataMode::CheckForSpace)
                .map_err(|e| err(&e))?;
        }
        for &offset in self.export_trie.string_offsets() {
            let a = addr.add(offset as i64).map_err(|e| err(&e))?;
            Du.create_data(program, &a, fixed_string().map_err(|e| err(&e))?, -1, ClearDataMode::CheckForSpace)
                .map_err(|e| err(&e))?;
        }
        Ok(())
    }
}

impl StructConverter for DyldExportsTrieCommand {
    /// Java: the inherited `LinkEditDataCommand.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        self.link_edit.to_data_type()
    }
}

impl LoadCommand for DyldExportsTrieCommand {
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
        if self.markup_trie(program, &addr).is_err() {
            log.append_msg_from(
                Some("DyldExportsTrieCommand"),
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
    use crate::format::macho::commands::load_command_types::LC_DYLD_EXPORTS_TRIE;

    #[test]
    fn parses_single_export() {
        // Root: terminal size 0, 1 child "_f" -> node at 6; node: terminal size 2 (flags 0,
        // address 0x10), 0 children.
        let mut b = link_edit_bytes(LC_DYLD_EXPORTS_TRIE, 16, 10);
        b.raw(&[0x00, 0x01, b'_', b'f', 0x00, 0x06, 0x02, 0x00, 0x10, 0x00]);
        let mut lc = BinaryReader::from_bytes(b.buf, true);
        let mut data = lc.clone_reader();
        let cmd = DyldExportsTrieCommand::new(&mut lc, &mut data).unwrap();
        let exports = cmd.get_export_trie().exports();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name(), "_f");
        assert_eq!(exports[0].address(), 0x10);
    }

    #[test]
    fn empty_trie_without_data() {
        let b = link_edit_bytes(LC_DYLD_EXPORTS_TRIE, 0, 0);
        let mut lc = BinaryReader::from_bytes(b.buf, true);
        let mut data = lc.clone_reader();
        let cmd = DyldExportsTrieCommand::new(&mut lc, &mut data).unwrap();
        assert!(cmd.get_export_trie().exports().is_empty());
    }
}
