//! Port of `ghidra.app.util.bin.format.macho.commands.FileSetEntryCommand`.
//!
//! Represents a `fileset_entry_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::commands::load_command_string::LoadCommandString;
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A Mach-O `fileset_entry_command`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.FileSetEntryCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSetEntryCommand {
    base: LoadCommandBase,
    vmaddr: i64,
    fileoff: i64,
    entry_id: LoadCommandString,
    reserved: i32,
}

impl FileSetEntryCommand {
    /// Java: `FileSetEntryCommand(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let vmaddr = reader.read_next_long()?;
        let fileoff = reader.read_next_long()?;
        let entry_id = LoadCommandString::new(reader, &base)?;
        let reserved = reader.read_next_int()?;
        Ok(FileSetEntryCommand { base, vmaddr, fileoff, entry_id, reserved })
    }

    /// Java: `getVMaddress()`.
    pub fn get_vm_address(&self) -> i64 {
        self.vmaddr
    }

    /// Java: `getFileOffset()`.
    pub fn get_file_offset(&self) -> i64 {
        self.fileoff
    }

    /// Java: `getFileSetEntryId()`.
    pub fn get_file_set_entry_id(&self) -> &LoadCommandString {
        &self.entry_id
    }

    /// Java: `getReserved()`.
    pub fn get_reserved(&self) -> i32 {
        self.reserved
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?.qword("vmaddr")?.qword("fileoff")?;
        s.add(self.entry_id.to_data_type()?, "entry_id", None)?;
        s.dword("reserved")?;
        s.finish_structure()
    }
}

impl StructConverter for FileSetEntryCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for FileSetEntryCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "fileset_entry_command".to_string()
    }
}

impl fmt::Display for FileSetEntryCommand {
    /// Java: `toString()`, the entry id.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.entry_id.get_string())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::format::macho::commands::load_command_types::LC_FILESET_ENTRY;
    use crate::format::macho::mach_header::test_support::Bytes;

    /// A little-endian `fileset_entry_command` naming `id`, `8 + 24 + 4 + 36` = 72 bytes long.
    pub(crate) fn fileset_entry_bytes(vmaddr: u64, fileoff: u64, id: &str) -> Vec<u8> {
        let mut b = Bytes::new(true);
        b.u32(LC_FILESET_ENTRY).u32(72).u64(vmaddr).u64(fileoff).u32(32).u32(0).name(id, 40);
        b.buf
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::fileset_entry_bytes;
    use super::*;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn parses_fileset_entry() {
        let bytes = fileset_entry_bytes(0xffff_fe00_0700_4000, 0x4000, "com.apple.kernel");
        let mut r = BinaryReader::from_bytes(bytes, true);
        let cmd = FileSetEntryCommand::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 32);
        assert_eq!(cmd.get_vm_address() as u64, 0xffff_fe00_0700_4000);
        assert_eq!(cmd.get_file_offset(), 0x4000);
        assert_eq!(cmd.get_file_set_entry_id().get_string(), "com.apple.kernel");
        assert_eq!(cmd.get_reserved(), 0);
        assert_eq!(cmd.to_string(), "com.apple.kernel");
        let s = cmd.to_structure().unwrap();
        assert_eq!(s.get_length(), 32);
        assert_eq!(names(&s), ["cmd", "cmdsize", "vmaddr", "fileoff", "entry_id", "reserved"]);
    }
}
