//! Port of `ghidra.app.util.bin.format.macho.commands.LoadCommandString`.
//!
//! Represents an `lc_str` union: a 32-bit offset, relative to the start of the owning load
//! command, to a NUL-terminated string stored inside that load command.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A Mach-O `lc_str`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.LoadCommandString`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadCommandString {
    offset: i32,
    string: String,
}

impl LoadCommandString {
    /// Java: `LoadCommandString(BinaryReader, LoadCommand)`. Reads the offset at the reader's
    /// position and the string it points to, relative to `command`'s start index. Java passes the
    /// partially constructed command; only its already-read base state is used.
    pub fn new(reader: &mut BinaryReader, command: &LoadCommandBase) -> io::Result<Self> {
        let offset = reader.read_next_int()?;
        let index = (command.get_start_index() as i64).wrapping_add(offset as i64);
        let string = reader.read_ascii_string(index as u64)?;
        Ok(LoadCommandString { offset, string })
    }

    /// Java: `getString()`.
    pub fn get_string(&self) -> &str {
        &self.string
    }

    /// Java: `getOffset()`.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("lc_str");
        s.dword("offset")?;
        s.finish_structure()
    }
}

impl StructConverter for LoadCommandString {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl fmt::Display for LoadCommandString {
    /// Java: `toString()`, the string itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string)
    }
}

/// The string-creating tail shared by the `markupRawBinary` overrides of the load commands that
/// end in an `lc_str` (`DynamicLibraryCommand`, `RunPathCommand`, `SubClientCommand`, ...): an
/// ASCII string from the string's offset to the end of the command.
///
/// Java repeats this body in each command; `with_message` selects between its two variants of
/// the failure log line (`"Unable to create <name>"` vs `"Unable to create <name> - <msg>"`).
pub(crate) fn markup_raw_binary_string<C: LoadCommand + ?Sized>(
    cmd: &C,
    string: &LoadCommandString,
    api: &dyn FlatProgramAPI,
    base_address: &Address,
    log: &MessageLog,
    with_message: bool,
) {
    let result: Result<(), String> = (|| {
        let address = base_address.space().address(cmd.get_start_index() as i64);
        let length = cmd.get_command_size() - string.get_offset();
        let str_addr = address.add(string.get_offset() as i64).map_err(|e| e.to_string())?;
        api.create_ascii_string(&str_addr, length).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(message) = result {
        if with_message {
            log.append_msg(&format!("Unable to create {} - {message}", cmd.get_command_name()));
        } else {
            log.append_msg(&format!("Unable to create {}", cmd.get_command_name()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::struct_builder::test_support::fields;

    #[test]
    fn reads_string_relative_to_command_start() {
        // 8 bytes of padding, then a command: cmd, cmdsize, lc_str offset 12, "hello\0".
        let mut b = vec![0u8; 8];
        b.extend(0xcu32.to_le_bytes());
        b.extend(20u32.to_le_bytes());
        b.extend(12u32.to_le_bytes());
        b.extend(b"hello\0\0\0");
        let mut r = BinaryReader::from_bytes(b, true);
        r.set_pointer_index(8);
        let base = LoadCommandBase::new(&mut r).unwrap();
        let s = LoadCommandString::new(&mut r, &base).unwrap();
        assert_eq!(r.get_pointer_index(), 20, "only the offset is consumed");
        assert_eq!(s.get_offset(), 12);
        assert_eq!(s.get_string(), "hello");
        assert_eq!(s.to_string(), "hello");
        let dt = s.to_structure().unwrap();
        assert_eq!(dt.get_name(), "lc_str");
        assert_eq!(fields(&dt), vec![("offset".to_string(), 0, 4)]);
    }
}
