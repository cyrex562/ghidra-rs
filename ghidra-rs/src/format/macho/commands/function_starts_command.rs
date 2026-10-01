//! Port of `ghidra.app.util.bin.format.macho.commands.FunctionStartsCommand`.
//!
//! Represents an `LC_FUNCTION_STARTS` `linkedit_data_command`: a ULEB128-encoded list of deltas
//! between successive function starts. See [`LinkEditDataCommand`] for how the inherited state is
//! shared.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::link_edit_data_command::LinkEditDataCommand;
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::commands::segment_names;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::uleb128;
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::address::Address;
use crate::program::model::address::address_overflow_exception::AddressOverflowException;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_module::ProgramModule;
use crate::program::model::symbol::ref_type::RefType;
use crate::program::model::symbol::SourceType;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
struct Du;
impl DataUtilities for Du {}

/// An `LC_FUNCTION_STARTS` command.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.FunctionStartsCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionStartsCommand {
    link_edit: LinkEditDataCommand,
    lebs: Vec<LEB128Info>,
}

impl FunctionStartsCommand {
    /// Java: `FunctionStartsCommand(BinaryReader, BinaryReader)`. Reads deltas until a 0 delta
    /// or until the next one would overrun `datasize`.
    pub fn new(load_command_reader: &mut BinaryReader, data_reader: &mut BinaryReader) -> io::Result<Self> {
        let link_edit = LinkEditDataCommand::new(load_command_reader, data_reader)?;
        let mut lebs = Vec::new();
        let mut i = 0i64;
        loop {
            let info = LEB128Info::unsigned(data_reader)?;
            if i + info.get_length() as i64 > link_edit.datasize() || info.as_long() == 0 {
                break;
            }
            i += info.get_length() as i64;
            lebs.push(info);
        }
        Ok(FunctionStartsCommand { link_edit, lebs })
    }

    /// The inherited `LinkEditDataCommand` state.
    pub fn link_edit(&self) -> &LinkEditDataCommand {
        &self.link_edit
    }

    /// Java: `findFunctionStartAddrs(Address)`. The function start addresses, accumulating each
    /// delta onto the `__TEXT` segment's address.
    pub fn find_function_start_addrs(
        &self,
        text_segment_addr: &Address,
    ) -> Result<Vec<Address>, AddressOverflowException> {
        let mut addrs = Vec::with_capacity(self.lebs.len());
        let mut current_func_offset = 0i64;
        for leb in &self.lebs {
            current_func_offset = current_func_offset.wrapping_add(leb.as_long());
            addrs.push(text_segment_addr.add(current_func_offset)?);
        }
        Ok(addrs)
    }

    fn markup_starts(
        &self,
        program: &dyn Program,
        mut addr: Address,
        text_segment_vm_address: i64,
    ) -> Result<(), String> {
        let err = |e: &dyn std::fmt::Display| e.to_string();
        let text_segment_addr = program
            .get_address_factory()
            .and_then(|f| f.get_default_address_space())
            .ok_or("no default address space")?
            .address(text_segment_vm_address);
        let mut current_func_offset = 0i64;
        for leb in &self.lebs {
            let d = Du
                .create_data(program, &addr, uleb128().map_err(|e| err(&e))?, -1, ClearDataMode::CheckForSpace)
                .map_err(|e| err(&e))?;
            addr = addr.add(leb.get_length() as i64).map_err(|e| err(&e))?;
            current_func_offset = current_func_offset.wrapping_add(leb.as_long());
            let target = text_segment_addr.add(current_func_offset).map_err(|e| err(&e))?;
            let mut reference_manager = program.get_reference_manager().ok_or("no reference manager")?;
            let reference = reference_manager.add_memory_reference(
                d.get_min_address(),
                target,
                RefType::Data,
                SourceType::Imported,
                0,
            );
            reference_manager.set_primary(reference, true);
        }
        Ok(())
    }
}

impl StructConverter for FunctionStartsCommand {
    /// Java: the inherited `LinkEditDataCommand.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        self.link_edit.to_data_type()
    }
}

impl LoadCommand for FunctionStartsCommand {
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
        let Some(text_segment) = header.get_segment(segment_names::TEXT) else {
            return Ok(());
        };
        if self.markup_starts(program, addr, text_segment.get_vm_address()).is_err() {
            log.append_msg_from(
                Some("FunctionStartsCommand"),
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
    use crate::format::macho::commands::load_command_types::LC_FUNCTION_STARTS;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn decodes_deltas_until_zero() {
        // deltas: 0x3f40 (c0 7e), 0x20 (20), 0x100 (80 02), then terminator 0
        let mut b = link_edit_bytes(LC_FUNCTION_STARTS, 16, 8);
        b.raw(&[0xc0, 0x7e, 0x20, 0x80, 0x02, 0x00, 0x00, 0x00]);
        let mut lc = BinaryReader::from_bytes(b.buf, true);
        let mut data = lc.clone_reader();
        let cmd = FunctionStartsCommand::new(&mut lc, &mut data).unwrap();
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addrs = cmd.find_function_start_addrs(&space.address(0x1_0000_0000)).unwrap();
        let offs: Vec<i64> = addrs.iter().map(|a| a.offset()).collect();
        assert_eq!(offs, [0x1_0000_3f40, 0x1_0000_3f60, 0x1_0000_4060]);
        assert_eq!(cmd.get_linker_data_size(), 8);
    }

    #[test]
    fn stops_before_overrunning_datasize() {
        let mut b = link_edit_bytes(LC_FUNCTION_STARTS, 16, 2);
        b.raw(&[0x10, 0x80, 0x01, 0x00]);
        let mut lc = BinaryReader::from_bytes(b.buf, true);
        let mut data = lc.clone_reader();
        let cmd = FunctionStartsCommand::new(&mut lc, &mut data).unwrap();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        assert_eq!(cmd.find_function_start_addrs(&space.address(0)).unwrap().len(), 1);
    }
}
