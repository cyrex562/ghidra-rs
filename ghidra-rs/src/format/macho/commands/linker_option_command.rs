//! Port of `ghidra.app.util.bin.format.macho.commands.LinkerOptionCommand`.
//!
//! Represents a `linker_option_command` structure. See `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A Mach-O `linker_option_command`.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.LinkerOptionCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkerOptionCommand {
    base: LoadCommandBase,
    count: i64,
    linker_options: Vec<String>,
}

impl LinkerOptionCommand {
    /// Java: `LinkerOptionCommand(BinaryReader)`. The `count` NUL-terminated option strings that
    /// follow are read through a clone of the reader, leaving it just past `count`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let mut cmd = LinkerOptionCommand { base, count: 0, linker_options: Vec::new() };
        cmd.count = cmd.check_count(reader.read_next_unsigned_int()? as i64)?;
        let mut string_reader = reader.clone_reader();
        for _ in 0..cmd.count {
            cmd.linker_options.push(string_reader.read_next_ascii_string()?);
        }
        Ok(cmd)
    }

    /// Java: `getLinkerOptions()`.
    pub fn get_linker_options(&self) -> &[String] {
        &self.linker_options
    }

    /// Java: `toDataType()`, returning the concrete structure. Java does not set the `/MachO`
    /// category path on this one; neither does this port.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?.dword("count")?;
        Ok(s.into_structure())
    }
}

impl StructConverter for LinkerOptionCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for LinkerOptionCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "linker_option_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn reads_option_strings_without_advancing_reader() {
        let mut b = Bytes::new(true);
        b.u32(0x2d).u32(32).u32(2).raw(b"-lfoo\0-framework\0\0\0\0");
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let cmd = LinkerOptionCommand::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 12);
        assert_eq!(cmd.get_linker_options(), ["-lfoo", "-framework"]);
        let s = cmd.to_structure().unwrap();
        assert_eq!(names(&s), ["cmd", "cmdsize", "count"]);
        assert_eq!(s.get_category_path().to_string(), "/");
    }
}
