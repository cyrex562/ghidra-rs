//! Port of `ghidra.app.util.bin.format.macho.commands.LinkEditDataCommand`.
//!
//! Represents a `linkedit_data_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.
//!
//! The Java class is both concrete (`LC_SEGMENT_SPLIT_INFO`, `LC_OPTIMIZATION_HINT`, ...) and the
//! base of `CodeSignatureCommand`, `DataInCodeCommand`, `DyldChainedFixupsCommand`,
//! `DyldExportsTrieCommand` and `FunctionStartsCommand`. Those embed a [`LinkEditDataCommand`]
//! (its `protected dataoff`/`datasize` are [`dataoff`](LinkEditDataCommand::dataoff)/
//! [`datasize`](LinkEditDataCommand::datasize)) and delegate the inherited `LoadCommand` members
//! to it. Java also keeps the data reader in a field; every use of it is in a constructor, so the
//! reader is only borrowed there.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::load_command::{markup_raw_binary_base, LoadCommand, LoadCommandBase};
use crate::format::macho::commands::load_command_types::get_load_command_name;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::MachStruct;
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_module::ProgramModule;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A Mach-O `linkedit_data_command`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.LinkEditDataCommand`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkEditDataCommand {
    base: LoadCommandBase,
    dataoff: i64,
    datasize: i64,
}

impl LinkEditDataCommand {
    /// Java: `LinkEditDataCommand(BinaryReader, BinaryReader)`. Leaves `data_reader` positioned at
    /// `dataoff`, ready for a subclass to read the referenced data.
    pub fn new(load_command_reader: &mut BinaryReader, data_reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(load_command_reader)?;
        let dataoff = load_command_reader.read_next_unsigned_int()? as i64;
        let datasize = load_command_reader.read_next_unsigned_int()? as i64;
        data_reader.set_pointer_index(dataoff as u64);
        Ok(LinkEditDataCommand { base, dataoff, datasize })
    }

    /// Java's `protected dataoff` field: the file offset of the referenced data.
    pub fn dataoff(&self) -> i64 {
        self.dataoff
    }

    /// Java's `protected datasize` field: the size of the referenced data.
    pub fn datasize(&self) -> i64 {
        self.datasize
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?.dword("dataoff")?.dword("datasize")?;
        s.finish_structure()
    }
}

impl StructConverter for LinkEditDataCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for LinkEditDataCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "linkedit_data_command".to_string()
    }

    fn get_linker_data_offset(&self) -> i64 {
        self.dataoff
    }

    fn get_linker_data_size(&self) -> i64 {
        self.datasize
    }

    fn markup(
        &self,
        program: &mut dyn Program,
        header: &MachHeader,
        source: Option<&str>,
        _monitor: &dyn TaskMonitor,
        _log: &MessageLog,
    ) -> Result<(), CancelledException> {
        let program: &dyn Program = program;
        let addr = self.file_offset_to_address(program, header, self.dataoff, self.datasize);
        self.markup_plate_comment(program, addr.as_ref(), source, None);
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
        markup_raw_binary_base(self, header, api, base_address, parent_module, monitor, log);
        if self.datasize > 0 {
            let start = base_address.space().address(self.dataoff);
            let name = get_load_command_name(self.get_command_type() as u32);
            if api.create_fragment(parent_module, &name, &start, self.datasize).is_err() {
                log.append_msg(&format!("Unable to create {}", self.get_command_name()));
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::format::macho::mach_header::test_support::Bytes;

    /// A little-endian `linkedit_data_command` of type `cmd` pointing at `dataoff`/`datasize`.
    pub(crate) fn link_edit_bytes(cmd: u32, dataoff: u32, datasize: u32) -> Bytes {
        let mut b = Bytes::new(true);
        b.u32(cmd).u32(16).u32(dataoff).u32(datasize);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::link_edit_bytes;
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_SEGMENT_SPLIT_INFO;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_and_positions_data_reader() {
        let mut b = link_edit_bytes(LC_SEGMENT_SPLIT_INFO, 0x20, 0x8);
        b.pad_to(0x28);
        let mut lc = BinaryReader::from_bytes(b.buf, true);
        let mut data = lc.clone_reader();
        let cmd = LinkEditDataCommand::new(&mut lc, &mut data).unwrap();
        assert_eq!(lc.get_pointer_index(), 16);
        assert_eq!(data.get_pointer_index(), 0x20);
        assert_eq!(cmd.dataoff(), 0x20);
        assert_eq!(cmd.get_linker_data_offset(), 0x20);
        assert_eq!(cmd.get_linker_data_size(), 8);
        assert_eq!(cmd.get_command_name(), "linkedit_data_command");
        assert_eq!(names(&cmd.to_structure().unwrap()), ["cmd", "cmdsize", "dataoff", "datasize"]);
    }
}
