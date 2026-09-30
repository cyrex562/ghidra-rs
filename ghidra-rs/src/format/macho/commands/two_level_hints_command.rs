//! Port of `ghidra.app.util.bin.format.macho.commands.TwoLevelHintsCommand`.
//!
//! Represents a `twolevel_hints_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::commands::two_level_hint::TwoLevelHint;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::MachStruct;
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program_module::ProgramModule;
use crate::util::task::TaskMonitor;

/// A Mach-O `twolevel_hints_command`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.TwoLevelHintsCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoLevelHintsCommand {
    base: LoadCommandBase,
    offset: i64,
    nhints: i64,
    hints: Vec<TwoLevelHint>,
}

impl TwoLevelHintsCommand {
    /// Java: `TwoLevelHintsCommand(BinaryReader)`. The hints are read from `offset`, after which
    /// the reader is restored.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let offset = reader.read_next_unsigned_int()? as i64;
        let mut cmd = TwoLevelHintsCommand { base, offset, nhints: 0, hints: Vec::new() };
        cmd.nhints = cmd.check_count(reader.read_next_unsigned_int()? as i64)?;
        let index = reader.get_pointer_index();
        reader.set_pointer_index(offset as u64);
        let mut result = Ok(());
        for _ in 0..cmd.nhints {
            match TwoLevelHint::new(reader) {
                Ok(h) => cmd.hints.push(h),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        reader.set_pointer_index(index);
        result.map(|_| cmd)
    }

    /// Java: `getHints()`.
    pub fn get_hints(&self) -> &[TwoLevelHint] {
        &self.hints
    }

    /// Java: `getOffset()`.
    pub fn get_offset(&self) -> i64 {
        self.offset
    }

    /// Java: `getNumberOfHints()`.
    pub fn get_number_of_hints(&self) -> i64 {
        self.nhints
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?.dword("offset")?.dword("nhints")?;
        s.finish_structure()
    }

    fn markup_raw_binary_hints(
        &self,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), String> {
        let mut fragment =
            self.create_fragment(api, base_address, parent_module).map_err(|e| e.to_string())?;
        let addr = base_address.space().address(self.get_start_index() as i64);
        api.create_data(&addr, self.to_data_type().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let hint_start_address = base_address.add(self.offset).map_err(|e| e.to_string())?;
        let mut hint_address = hint_start_address.clone();
        for hint in &self.hints {
            if monitor.is_cancelled() {
                return Ok(());
            }
            let hint_dt = hint.to_data_type().map_err(|e| e.to_string())?;
            let hint_len = hint_dt.get_length();
            api.create_data(&hint_address, hint_dt).map_err(|e| e.to_string())?;
            api.set_plate_comment(
                &hint_address,
                &format!(
                    "Sub-image Index: 0x{:x}\n      TOC Index: 0x{:x}",
                    hint.get_sub_image_index(),
                    hint.get_table_of_contents_index()
                ),
            );
            hint_address = hint_address.add(hint_len as i64).map_err(|e| e.to_string())?;
        }
        let end = hint_address.subtract_no_wrap(1).map_err(|e| e.to_string())?;
        fragment.move_code_units(&hint_start_address, &end).map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl StructConverter for TwoLevelHintsCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for TwoLevelHintsCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "twolevel_hints_command".to_string()
    }

    /// Java overrides `markupRawBinary` without calling `super`.
    fn markup_raw_binary(
        &self,
        _header: &MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) {
        self.update_monitor(monitor);
        if let Err(message) = self.markup_raw_binary_hints(api, base_address, parent_module, monitor) {
            log.append_msg(&format!("Unable to create {} - {message}", self.get_command_name()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn reads_hints_from_offset_and_restores_reader() {
        let mut b = Bytes::new(true);
        b.u32(0x16).u32(16).u32(24).u32(2).pad_to(24).u32(0x0000_0101).u32(0x0000_0302);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let cmd = TwoLevelHintsCommand::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 16);
        assert_eq!(cmd.get_offset(), 24);
        assert_eq!(cmd.get_number_of_hints(), 2);
        assert_eq!(cmd.get_hints()[0].get_sub_image_index(), 1);
        assert_eq!(cmd.get_hints()[1].get_table_of_contents_index(), 3);
        assert_eq!(names(&cmd.to_structure().unwrap()), ["cmd", "cmdsize", "offset", "nhints"]);
    }

    #[test]
    fn truncated_hints_fail_but_restore_reader() {
        let mut b = Bytes::new(true);
        b.u32(0x16).u32(16).u32(16).u32(5);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        assert!(TwoLevelHintsCommand::new(&mut r).is_err());
        assert_eq!(r.get_pointer_index(), 16);
    }
}
