//! Port of `ghidra.app.util.bin.format.macho.threadcommand.ExceptionStateX86_32`.
//!
//! Represents an x86 `x86_exception_state32_t` structure.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.threadcommand.ExceptionStateX86_32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExceptionStateX86_32 {
    /// Java: the public `trapno` field.
    pub trapno: i32,
    /// Java: the public `err` field.
    pub err: i32,
    /// Java: the public `faultvaddr` field.
    pub faultvaddr: i32,
}

impl ExceptionStateX86_32 {

    /// Java: `ExceptionStateX86_32(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(ExceptionStateX86_32 {
            trapno: reader.read_next_int()?,
            err: reader.read_next_int()?,
            faultvaddr: reader.read_next_int()?,
        })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("x86_exception_state32");
        s.dword("trapno")?;
        s.dword("err")?;
        s.dword("faultvaddr")?;
        s.finish_structure()
    }
}

impl StructConverter for ExceptionStateX86_32 {
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
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let s = ExceptionStateX86_32::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 12);
        assert_eq!(s.trapno, 1);
        assert_eq!(s.faultvaddr, 3);
        let st = s.to_structure().unwrap();
        assert_eq!(st.get_name(), "x86_exception_state32");
        assert_eq!(st.get_length(), 12);
        assert_eq!(names(&st).len(), 3);
    }
}
