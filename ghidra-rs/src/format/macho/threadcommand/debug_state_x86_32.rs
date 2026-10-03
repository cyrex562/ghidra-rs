//! Port of `ghidra.app.util.bin.format.macho.threadcommand.DebugStateX86_32`.
//!
//! Represents an x86 `x86_debug_state32_t` structure.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.threadcommand.DebugStateX86_32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DebugStateX86_32 {
    /// Java: the public `dr0` field.
    pub dr0: i32,
    /// Java: the public `dr1` field.
    pub dr1: i32,
    /// Java: the public `dr2` field.
    pub dr2: i32,
    /// Java: the public `dr3` field.
    pub dr3: i32,
    /// Java: the public `dr4` field.
    pub dr4: i32,
    /// Java: the public `dr5` field.
    pub dr5: i32,
    /// Java: the public `dr6` field.
    pub dr6: i32,
    /// Java: the public `dr7` field.
    pub dr7: i32,
}

impl DebugStateX86_32 {

    /// Java: `DebugStateX86_32(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(DebugStateX86_32 {
            dr0: reader.read_next_int()?,
            dr1: reader.read_next_int()?,
            dr2: reader.read_next_int()?,
            dr3: reader.read_next_int()?,
            dr4: reader.read_next_int()?,
            dr5: reader.read_next_int()?,
            dr6: reader.read_next_int()?,
            dr7: reader.read_next_int()?,
        })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("x86_debug_state32");
        s.dword("dr0")?;
        s.dword("dr1")?;
        s.dword("dr2")?;
        s.dword("dr3")?;
        s.dword("dr4")?;
        s.dword("dr5")?;
        s.dword("dr6")?;
        s.dword("dr7")?;
        s.finish_structure()
    }
}

impl StructConverter for DebugStateX86_32 {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn reads_registers_in_order() {
        let mut b = Bytes::new(true);
        b.u32(1);
        b.u32(2);
        b.u32(3);
        b.u32(4);
        b.u32(5);
        b.u32(6);
        b.u32(7);
        b.u32(8);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let s = DebugStateX86_32::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 32);
        assert_eq!(s.dr0, 1);
        assert_eq!(s.dr7, 8);
        let st = s.to_structure().unwrap();
        assert_eq!(st.get_name(), "x86_debug_state32");
        assert_eq!(st.get_length(), 32);
        assert_eq!(names(&st).len(), 8);
    }
}
