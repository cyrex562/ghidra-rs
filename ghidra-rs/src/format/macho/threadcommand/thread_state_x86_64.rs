//! Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateX86_64`.
//!
//! Represents an x86-64 `x86_thread_state64_t` structure.
//!
//! The structure names its third field `cx` (not `rcx`), as Java does.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::format::macho::threadcommand::thread_state::ThreadState;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateX86_64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(non_camel_case_types)]
pub struct ThreadStateX86_64 {
    /// Java: the public `rax` field.
    pub rax: i64,
    /// Java: the public `rbx` field.
    pub rbx: i64,
    /// Java: the public `rcx` field.
    pub rcx: i64,
    /// Java: the public `rdx` field.
    pub rdx: i64,
    /// Java: the public `rdi` field.
    pub rdi: i64,
    /// Java: the public `rsi` field.
    pub rsi: i64,
    /// Java: the public `rbp` field.
    pub rbp: i64,
    /// Java: the public `rsp` field.
    pub rsp: i64,
    /// Java: the public `r8` field.
    pub r8: i64,
    /// Java: the public `r9` field.
    pub r9: i64,
    /// Java: the public `r10` field.
    pub r10: i64,
    /// Java: the public `r11` field.
    pub r11: i64,
    /// Java: the public `r12` field.
    pub r12: i64,
    /// Java: the public `r13` field.
    pub r13: i64,
    /// Java: the public `r14` field.
    pub r14: i64,
    /// Java: the public `r15` field.
    pub r15: i64,
    /// Java: the public `rip` field.
    pub rip: i64,
    /// Java: the public `rflags` field.
    pub rflags: i64,
    /// Java: the public `cs` field.
    pub cs: i64,
    /// Java: the public `fs` field.
    pub fs: i64,
    /// Java: the public `gs` field.
    pub gs: i64,
}

impl ThreadStateX86_64 {

    /// Java: `ThreadStateX86_64(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(ThreadStateX86_64 {
            rax: reader.read_next_long()?,
            rbx: reader.read_next_long()?,
            rcx: reader.read_next_long()?,
            rdx: reader.read_next_long()?,
            rdi: reader.read_next_long()?,
            rsi: reader.read_next_long()?,
            rbp: reader.read_next_long()?,
            rsp: reader.read_next_long()?,
            r8: reader.read_next_long()?,
            r9: reader.read_next_long()?,
            r10: reader.read_next_long()?,
            r11: reader.read_next_long()?,
            r12: reader.read_next_long()?,
            r13: reader.read_next_long()?,
            r14: reader.read_next_long()?,
            r15: reader.read_next_long()?,
            rip: reader.read_next_long()?,
            rflags: reader.read_next_long()?,
            cs: reader.read_next_long()?,
            fs: reader.read_next_long()?,
            gs: reader.read_next_long()?,
        })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("x86_THREAD_STATE64");
        s.qword("rax")?;
        s.qword("rbx")?;
        s.qword("cx")?;
        s.qword("rdx")?;
        s.qword("rdi")?;
        s.qword("rsi")?;
        s.qword("rbp")?;
        s.qword("rsp")?;
        s.qword("r8")?;
        s.qword("r9")?;
        s.qword("r10")?;
        s.qword("r11")?;
        s.qword("r12")?;
        s.qword("r13")?;
        s.qword("r14")?;
        s.qword("r15")?;
        s.qword("rip")?;
        s.qword("rflags")?;
        s.qword("cs")?;
        s.qword("fs")?;
        s.qword("gs")?;
        s.finish_structure()
    }
}

impl StructConverter for ThreadStateX86_64 {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl ThreadState for ThreadStateX86_64 {
    /// Java: `getInstructionPointer()`.
    fn get_instruction_pointer(&self) -> i64 {
        self.rip
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
        b.u64(9);
        b.u64(10);
        b.u64(11);
        b.u64(12);
        b.u64(13);
        b.u64(14);
        b.u64(15);
        b.u64(16);
        b.u64(17);
        b.u64(18);
        b.u64(19);
        b.u64(20);
        b.u64(21);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let s = ThreadStateX86_64::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 168);
        assert_eq!(s.rax, 1);
        assert_eq!(s.gs, 21);
        assert_eq!(s.get_instruction_pointer(), s.rip);
        let st = s.to_structure().unwrap();
        assert_eq!(st.get_name(), "x86_THREAD_STATE64");
        assert_eq!(st.get_length(), 168);
        assert_eq!(names(&st).len(), 21);
    }
}
