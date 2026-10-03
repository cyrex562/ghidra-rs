//! Port of `ghidra.app.util.bin.format.macho.commands.PrebindChecksumCommand`.
//!
//! Represents a `prebind_cksum_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A `prebind_cksum_command` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.PrebindChecksumCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrebindChecksumCommand {
    base: LoadCommandBase,
    cksum: i32,
}

impl PrebindChecksumCommand {
    /// Java: `PrebindChecksumCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let cksum = reader.read_next_int()?;
        Ok(PrebindChecksumCommand { base, cksum })
    }

    /// Java: `getCheckSum()`.
    pub fn get_check_sum(&self) -> i32 {
        self.cksum
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.dword("cksum")?;
        s.finish_structure()
    }
}

impl StructConverter for PrebindChecksumCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for PrebindChecksumCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "prebind_cksum_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_checksum() {
        let mut b = Bytes::new(true);
        b.u32(0x17).u32(12).u32(0xdead_beef);
        let cmd = PrebindChecksumCommand::new(&mut BinaryReader::from_bytes(b.buf, true)).unwrap();
        assert_eq!(cmd.get_check_sum(), 0xdead_beefu32 as i32);
        assert_eq!(names(&cmd.to_structure().unwrap()), ["cmd", "cmdsize", "cksum"]);
    }
}
