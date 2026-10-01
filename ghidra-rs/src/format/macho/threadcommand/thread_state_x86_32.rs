//! Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateX86_32`.
//!
//! Represents an x86 `x86_thread_state32_t` structure.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::format::macho::threadcommand::thread_state::ThreadState;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateX86_32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThreadStateX86_32 {
    /// Java: the public `eax` field.
    pub eax: i32,
    /// Java: the public `ebx` field.
    pub ebx: i32,
    /// Java: the public `ecx` field.
    pub ecx: i32,
    /// Java: the public `edx` field.
    pub edx: i32,
    /// Java: the public `edi` field.
    pub edi: i32,
    /// Java: the public `esi` field.
    pub esi: i32,
    /// Java: the public `ebp` field.
    pub ebp: i32,
    /// Java: the public `esp` field.
    pub esp: i32,
    /// Java: the public `ss` field.
    pub ss: i32,
    /// Java: the public `eflags` field.
    pub eflags: i32,
    /// Java: the public `eip` field.
    pub eip: i32,
    /// Java: the public `cs` field.
    pub cs: i32,
    /// Java: the public `ds` field.
    pub ds: i32,
    /// Java: the public `es` field.
    pub es: i32,
    /// Java: the public `fs` field.
    pub fs: i32,
    /// Java: the public `gs` field.
    pub gs: i32,
}

impl ThreadStateX86_32 {

    /// Java: `ThreadStateX86_32(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(ThreadStateX86_32 {
            eax: reader.read_next_int()?,
            ebx: reader.read_next_int()?,
            ecx: reader.read_next_int()?,
            edx: reader.read_next_int()?,
            edi: reader.read_next_int()?,
            esi: reader.read_next_int()?,
            ebp: reader.read_next_int()?,
            esp: reader.read_next_int()?,
            ss: reader.read_next_int()?,
            eflags: reader.read_next_int()?,
            eip: reader.read_next_int()?,
            cs: reader.read_next_int()?,
            ds: reader.read_next_int()?,
            es: reader.read_next_int()?,
            fs: reader.read_next_int()?,
            gs: reader.read_next_int()?,
        })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("x86_THREAD_STATE32");
        s.dword("eax")?;
        s.dword("ebx")?;
        s.dword("ecx")?;
        s.dword("edx")?;
        s.dword("edi")?;
        s.dword("esi")?;
        s.dword("ebp")?;
        s.dword("esp")?;
        s.dword("ss")?;
        s.dword("eflags")?;
        s.dword("eip")?;
        s.dword("cs")?;
        s.dword("ds")?;
        s.dword("es")?;
        s.dword("fs")?;
        s.dword("gs")?;
        s.finish_structure()
    }
}

impl StructConverter for ThreadStateX86_32 {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl ThreadState for ThreadStateX86_32 {
    /// Java: `getInstructionPointer()`.
    fn get_instruction_pointer(&self) -> i64 {
        self.eip as u32 as i64
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
        b.u32(9);
        b.u32(10);
        b.u32(11);
        b.u32(12);
        b.u32(13);
        b.u32(14);
        b.u32(15);
        b.u32(16);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let s = ThreadStateX86_32::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 64);
        assert_eq!(s.eax, 1);
        assert_eq!(s.gs, 16);
        assert_eq!(s.get_instruction_pointer(), s.eip as u32 as i64);
        let st = s.to_structure().unwrap();
        assert_eq!(st.get_name(), "x86_THREAD_STATE32");
        assert_eq!(st.get_length(), 64);
        assert_eq!(names(&st).len(), 16);
    }

    #[test]
    fn instruction_pointer_is_unsigned() {
        let mut s = ThreadStateX86_32::new(&mut BinaryReader::from_bytes(vec![0u8; 128], true)).unwrap();
        s.eip = -4;
        assert_eq!(s.get_instruction_pointer(), 0xffff_fffc);
    }
}
