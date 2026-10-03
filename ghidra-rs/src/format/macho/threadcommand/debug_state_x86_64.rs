//! Port of `ghidra.app.util.bin.format.macho.threadcommand.DebugStateX86_64`.
//!
//! Represents an x86-64 `x86_debug_state64_t` structure.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.threadcommand.DebugStateX86_64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DebugStateX86_64 {
    /// Java: the public `dr0` field.
    pub dr0: i64,
    /// Java: the public `dr1` field.
    pub dr1: i64,
    /// Java: the public `dr2` field.
    pub dr2: i64,
    /// Java: the public `dr3` field.
    pub dr3: i64,
    /// Java: the public `dr4` field.
    pub dr4: i64,
    /// Java: the public `dr5` field.
    pub dr5: i64,
    /// Java: the public `dr6` field.
    pub dr6: i64,
    /// Java: the public `dr7` field.
    pub dr7: i64,
}

impl DebugStateX86_64 {

    /// Java: `DebugStateX86_64(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(DebugStateX86_64 {
            dr0: reader.read_next_long()?,
            dr1: reader.read_next_long()?,
            dr2: reader.read_next_long()?,
            dr3: reader.read_next_long()?,
            dr4: reader.read_next_long()?,
            dr5: reader.read_next_long()?,
            dr6: reader.read_next_long()?,
            dr7: reader.read_next_long()?,
        })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("x86_debug_state64");
        s.qword("dr0")?;
        s.qword("dr1")?;
        s.qword("dr2")?;
        s.qword("dr3")?;
        s.qword("dr4")?;
        s.qword("dr5")?;
        s.qword("dr6")?;
        s.qword("dr7")?;
        s.finish_structure()
    }
}

impl StructConverter for DebugStateX86_64 {
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
        b.u64(1);
        b.u64(2);
        b.u64(3);
        b.u64(4);
        b.u64(5);
        b.u64(6);
        b.u64(7);
        b.u64(8);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let s = DebugStateX86_64::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 64);
        assert_eq!(s.dr0, 1);
        assert_eq!(s.dr7, 8);
        let st = s.to_structure().unwrap();
        assert_eq!(st.get_name(), "x86_debug_state64");
        assert_eq!(st.get_length(), 64);
        assert_eq!(names(&st).len(), 8);
    }
}
