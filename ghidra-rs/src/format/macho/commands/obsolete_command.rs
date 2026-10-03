//! Port of `ghidra.app.util.bin.format.macho.commands.ObsoleteCommand`.
//!
//! The abstract base of the load commands Mach-O no longer supports (`LC_SYMSEG`, `LC_IDENT`,
//! `LC_LOADFVMLIB`/`LC_IDFVMLIB`). Java's constructor reads the `cmd`/`cmdsize` header and then
//! always throws `ObsoleteException`, so no such command is ever successfully built:
//! [`LoadCommandFactory`](crate::format::macho::commands::load_command_factory) turns the failure
//! into a [`CorruptLoadCommand`](crate::format::macho::commands::corrupt_load_command::CorruptLoadCommand).
//!
//! The Java class has no instance state of its own, so it is a trait here; [`read_obsolete`] is
//! its constructor body and [`ObsoleteCommand::obsolete_to_structure`] its `toDataType()`.

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::ToDataTypeError;
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::mach_exception::MachException;
use crate::format::macho::obsolete_exception::ObsoleteException;
use crate::format::macho::struct_builder::{array, byte, MachStruct};
use crate::program::model::data::structure_data_type::StructureDataType;

/// Java: `ObsoleteCommand(BinaryReader)`. Reads the load command header, then fails with
/// [`ObsoleteException`] (as a [`MachException`], its Java superclass).
pub fn read_obsolete(reader: &mut BinaryReader) -> Result<LoadCommandBase, MachException> {
    let _base = LoadCommandBase::new(reader)?;
    Err(ObsoleteException::new().into())
}

/// Port of the abstract `ghidra.app.util.bin.format.macho.commands.ObsoleteCommand`.
pub trait ObsoleteCommand: LoadCommand {
    /// Java: `ObsoleteCommand.toDataType()`: the header followed by the command's remaining
    /// `cmdsize - 8` bytes.
    fn obsolete_to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add(array(byte(), self.get_command_size() - 8)?, "obsolete", None)?;
        s.finish_structure()
    }
}
