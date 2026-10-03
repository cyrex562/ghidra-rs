//! Port of `ghidra.app.util.bin.format.macho.commands.FixedVirtualMemorySharedLibraryCommand`.
//!
//! Represents a `fvmlib_command` structure, an [obsolete](crate::format::macho::commands::obsolete_command) load
//! command: [`FixedVirtualMemorySharedLibraryCommand::new`] always fails with `ObsoleteException`.

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::commands::obsolete_command::{read_obsolete, ObsoleteCommand};
use crate::format::macho::mach_exception::MachException;
use crate::program::model::data::data_type::DataType;

/// Port of `ghidra.app.util.bin.format.macho.commands.FixedVirtualMemorySharedLibraryCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedVirtualMemorySharedLibraryCommand {
    base: LoadCommandBase,
}

impl FixedVirtualMemorySharedLibraryCommand {
    /// Java: `FixedVirtualMemorySharedLibraryCommand(BinaryReader)`. Always fails once the header has been read (see
    /// [`read_obsolete`]).
    pub fn new(reader: &mut BinaryReader) -> Result<Self, MachException> {
        let base = read_obsolete(reader)?;
        Ok(FixedVirtualMemorySharedLibraryCommand { base })
    }
}

impl ObsoleteCommand for FixedVirtualMemorySharedLibraryCommand {}

impl StructConverter for FixedVirtualMemorySharedLibraryCommand {
    /// Java: `ObsoleteCommand.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.obsolete_to_structure()?))
    }
}

impl LoadCommand for FixedVirtualMemorySharedLibraryCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "fvmlib_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_LOADFVMLIB;

    #[test]
    fn construction_always_fails_as_obsolete_after_reading_header() {
        let mut b = LC_LOADFVMLIB.to_le_bytes().to_vec();
        b.extend(16u32.to_le_bytes());
        b.extend([0u8; 8]);
        let mut r = BinaryReader::from_bytes(b, true);
        let err = FixedVirtualMemorySharedLibraryCommand::new(&mut r).unwrap_err();
        assert_eq!(err.message(), "Obsolete");
        assert_eq!(r.get_pointer_index(), 8);
    }
}
