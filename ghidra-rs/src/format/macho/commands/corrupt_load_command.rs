//! Port of `ghidra.app.util.bin.format.macho.commands.CorruptLoadCommand`.
//!
//! A load command that could not be parsed; it keeps the failure that caused it.

use std::error::Error;
use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// A corrupt load command.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.CorruptLoadCommand`.
#[derive(Debug, Clone)]
pub struct CorruptLoadCommand {
    base: LoadCommandBase,
    problem: Arc<dyn Error + Send + Sync>,
}

impl CorruptLoadCommand {
    /// Java: `CorruptLoadCommand(BinaryReader, Throwable)`.
    pub fn new(reader: &mut BinaryReader, problem: Arc<dyn Error + Send + Sync>) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        Ok(CorruptLoadCommand { base, problem })
    }

    /// Java: `getProblem()`, the error that caused this load command to be corrupt.
    pub fn get_problem(&self) -> &(dyn Error + Send + Sync) {
        self.problem.as_ref()
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.finish_structure()
    }
}

impl StructConverter for CorruptLoadCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for CorruptLoadCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "corrupt_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn keeps_problem_and_reads_header() {
        let mut b = 0x2u32.to_le_bytes().to_vec();
        b.extend(24u32.to_le_bytes());
        let problem = Arc::new(io::Error::new(io::ErrorKind::UnexpectedEof, "boom"));
        let cmd = CorruptLoadCommand::new(&mut BinaryReader::from_bytes(b, true), problem).unwrap();
        assert_eq!(cmd.get_command_type(), 2);
        assert_eq!(cmd.get_command_size(), 24);
        assert_eq!(cmd.get_problem().to_string(), "boom");
        assert_eq!(cmd.get_command_name(), "corrupt_command");
        assert_eq!(names(&cmd.to_structure().unwrap()), ["cmd", "cmdsize"]);
    }
}
