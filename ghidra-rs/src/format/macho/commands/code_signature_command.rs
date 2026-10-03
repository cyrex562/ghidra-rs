//! Port of `ghidra.app.util.bin.format.macho.commands.CodeSignatureCommand`.
//!
//! Represents an `LC_CODE_SIGNATURE` `linkedit_data_command`. See [`LinkEditDataCommand`] for
//! how the inherited state is shared.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::codesignature::code_signature_blob_parser::{self, CodeSignatureBlob};
use crate::format::macho::commands::codesignature::code_signature_generic_blob::Du;
use crate::format::macho::commands::codesignature::code_signature_super_blob::set_big_endian;
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

/// An `LC_CODE_SIGNATURE` command.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.CodeSignatureCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignatureCommand {
    link_edit: LinkEditDataCommand,
    blob: CodeSignatureBlob,
}

impl CodeSignatureCommand {
    /// Java: `CodeSignatureCommand(BinaryReader, BinaryReader)`. The signature is always
    /// big-endian, so `data_reader` is switched to big-endian before parsing it.
    pub fn new(load_command_reader: &mut BinaryReader, data_reader: &mut BinaryReader) -> io::Result<Self> {
        let link_edit = LinkEditDataCommand::new(load_command_reader, data_reader)?;
        data_reader.set_little_endian(false);
        let blob = code_signature_blob_parser::parse(data_reader)?;
        Ok(CodeSignatureCommand { link_edit, blob })
    }

    /// The inherited `LinkEditDataCommand` state.
    pub fn link_edit(&self) -> &LinkEditDataCommand {
        &self.link_edit
    }

    /// The parsed signature blob (Java's private `blob`).
    pub fn get_blob(&self) -> &CodeSignatureBlob {
        &self.blob
    }

    fn markup_blob(
        &self,
        program: &dyn Program,
        addr: &Address,
        header: &MachHeader,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), String> {
        let dt = self.blob.to_data_type().map_err(|e| e.to_string())?;
        let d = Du.create_data(program, addr, dt, -1, ClearDataMode::CheckForSpace).map_err(|e| e.to_string())?;
        set_big_endian(d)?;
        self.blob.markup(program, addr, header, monitor, log);
        Ok(())
    }
}

impl StructConverter for CodeSignatureCommand {
    /// Java: the inherited `LinkEditDataCommand.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        self.link_edit.to_data_type()
    }
}

impl LoadCommand for CodeSignatureCommand {
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
        if self.markup_blob(program, &addr, header, monitor, log).is_err() {
            log.append_msg_from(
                Some("CodeSignatureCommand"),
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
    use crate::format::macho::commands::codesignature::code_signature_blob_parser::test_support::signature;
    use crate::format::macho::commands::link_edit_data_command::test_support::link_edit_bytes;
    use crate::format::macho::commands::load_command_types::LC_CODE_SIGNATURE;

    #[test]
    fn parses_big_endian_signature_from_little_endian_image() {
        let sig = signature();
        let mut b = link_edit_bytes(LC_CODE_SIGNATURE, 16, sig.len() as u32);
        b.raw(&sig);
        let mut lc = BinaryReader::from_bytes(b.buf, true);
        let mut data = lc.clone_reader();
        let cmd = CodeSignatureCommand::new(&mut lc, &mut data).unwrap();
        assert!(lc.is_little_endian(), "only the data reader switches endianness");
        assert!(matches!(cmd.get_blob(), CodeSignatureBlob::SuperBlob(_)));
        assert_eq!(cmd.get_linker_data_size(), sig.len() as i64);
        assert_eq!(cmd.get_command_type() as u32, LC_CODE_SIGNATURE);
    }
}
