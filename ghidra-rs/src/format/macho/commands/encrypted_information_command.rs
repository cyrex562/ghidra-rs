//! Port of `ghidra.app.util.bin.format.macho.commands.EncryptedInformationCommand`.
//!
//! Represents an `encryption_info_command` / `encryption_info_command_64` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// An `encryption_info_command` / `encryption_info_command_64` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.EncryptedInformationCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedInformationCommand {
    base: LoadCommandBase,
    cryptoff: i64,
    cryptsize: i64,
    cryptid: i32,
    is32bit: bool,
}

impl EncryptedInformationCommand {
    /// Java: `EncryptedInformationCommand(BinaryReader, boolean)`.
    pub fn new(reader: &mut BinaryReader, is32bit: bool) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let cryptoff = reader.read_next_unsigned_int()? as i64;
        let cryptsize = reader.read_next_unsigned_int()? as i64;
        let cryptid = reader.read_next_int()?;
        Ok(EncryptedInformationCommand { base, cryptoff, cryptsize, cryptid, is32bit })
    }

    /// Java: `getCryptID()`.
    pub fn get_crypt_id(&self) -> i32 {
        self.cryptid
    }

    /// Java: `getCryptOffset()`.
    pub fn get_crypt_offset(&self) -> i64 {
        self.cryptoff
    }

    /// Java: `getCryptSize()`.
    pub fn get_crypt_size(&self) -> i64 {
        self.cryptsize
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.dword("cryptoff")?.dword("cryptsize")?.dword("cryptid")?;
        if !self.is32bit {
            s.dword("pad")?;
        }
        s.finish_structure()
    }
}

impl StructConverter for EncryptedInformationCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for EncryptedInformationCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "encryption_info_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_encryption_info_and_pads_64_bit_layout() {
        let mut b = Bytes::new(true);
        b.u32(0x2c).u32(24).u32(0xffff_c000).u32(0x4000).u32(1).u32(0);
        let cmd = EncryptedInformationCommand::new(&mut BinaryReader::from_bytes(b.buf.clone(), true), false).unwrap();
        assert_eq!(cmd.get_crypt_offset(), 0xffff_c000, "unsigned");
        assert_eq!(cmd.get_crypt_size(), 0x4000);
        assert_eq!(cmd.get_crypt_id(), 1);
        assert_eq!(names(&cmd.to_structure().unwrap()), ["cmd", "cmdsize", "cryptoff", "cryptsize", "cryptid", "pad"]);
        let cmd32 = EncryptedInformationCommand::new(&mut BinaryReader::from_bytes(b.buf, true), true).unwrap();
        assert_eq!(cmd32.to_structure().unwrap().get_length(), 20);
    }
}
