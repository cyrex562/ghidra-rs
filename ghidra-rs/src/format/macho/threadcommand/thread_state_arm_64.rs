//! Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateARM_64`.
//!
//! Represents an ARM64 `arm_thread_state64_t` structure.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::format::macho::threadcommand::thread_state::ThreadState;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateARM_64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(non_camel_case_types)]
pub struct ThreadStateARM_64 {
    /// Java: the public `x0` field.
    pub x0: i64,
    /// Java: the public `x1` field.
    pub x1: i64,
    /// Java: the public `x2` field.
    pub x2: i64,
    /// Java: the public `x3` field.
    pub x3: i64,
    /// Java: the public `x4` field.
    pub x4: i64,
    /// Java: the public `x5` field.
    pub x5: i64,
    /// Java: the public `x6` field.
    pub x6: i64,
    /// Java: the public `x7` field.
    pub x7: i64,
    /// Java: the public `x8` field.
    pub x8: i64,
    /// Java: the public `x9` field.
    pub x9: i64,
    /// Java: the public `x10` field.
    pub x10: i64,
    /// Java: the public `x11` field.
    pub x11: i64,
    /// Java: the public `x12` field.
    pub x12: i64,
    /// Java: the public `x13` field.
    pub x13: i64,
    /// Java: the public `x14` field.
    pub x14: i64,
    /// Java: the public `x15` field.
    pub x15: i64,
    /// Java: the public `x16` field.
    pub x16: i64,
    /// Java: the public `x17` field.
    pub x17: i64,
    /// Java: the public `x18` field.
    pub x18: i64,
    /// Java: the public `x19` field.
    pub x19: i64,
    /// Java: the public `x20` field.
    pub x20: i64,
    /// Java: the public `x21` field.
    pub x21: i64,
    /// Java: the public `x22` field.
    pub x22: i64,
    /// Java: the public `x23` field.
    pub x23: i64,
    /// Java: the public `x24` field.
    pub x24: i64,
    /// Java: the public `x25` field.
    pub x25: i64,
    /// Java: the public `x26` field.
    pub x26: i64,
    /// Java: the public `x27` field.
    pub x27: i64,
    /// Java: the public `x28` field.
    pub x28: i64,
    /// Java: the public `fp` field.
    pub fp: i64,
    /// Java: the public `lr` field.
    pub lr: i64,
    /// Java: the public `sp` field.
    pub sp: i64,
    /// Java: the public `pc` field.
    pub pc: i64,
    /// Java: the public `cpsr` field.
    pub cpsr: i32,
    /// Java: the public `pad` field.
    pub pad: i32,
}

impl ThreadStateARM_64 {
    /// Java: `ARM64_THREAD_STATE`.
    pub const ARM64_THREAD_STATE: i32 = 6;

    /// Java: `ThreadStateARM_64(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(ThreadStateARM_64 {
            x0: reader.read_next_long()?,
            x1: reader.read_next_long()?,
            x2: reader.read_next_long()?,
            x3: reader.read_next_long()?,
            x4: reader.read_next_long()?,
            x5: reader.read_next_long()?,
            x6: reader.read_next_long()?,
            x7: reader.read_next_long()?,
            x8: reader.read_next_long()?,
            x9: reader.read_next_long()?,
            x10: reader.read_next_long()?,
            x11: reader.read_next_long()?,
            x12: reader.read_next_long()?,
            x13: reader.read_next_long()?,
            x14: reader.read_next_long()?,
            x15: reader.read_next_long()?,
            x16: reader.read_next_long()?,
            x17: reader.read_next_long()?,
            x18: reader.read_next_long()?,
            x19: reader.read_next_long()?,
            x20: reader.read_next_long()?,
            x21: reader.read_next_long()?,
            x22: reader.read_next_long()?,
            x23: reader.read_next_long()?,
            x24: reader.read_next_long()?,
            x25: reader.read_next_long()?,
            x26: reader.read_next_long()?,
            x27: reader.read_next_long()?,
            x28: reader.read_next_long()?,
            fp: reader.read_next_long()?,
            lr: reader.read_next_long()?,
            sp: reader.read_next_long()?,
            pc: reader.read_next_long()?,
            cpsr: reader.read_next_int()?,
            pad: reader.read_next_int()?,
        })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("ARM64_THREAD_STATE");
        s.qword("x0")?;
        s.qword("x1")?;
        s.qword("x2")?;
        s.qword("x3")?;
        s.qword("x4")?;
        s.qword("x5")?;
        s.qword("x6")?;
        s.qword("x7")?;
        s.qword("x8")?;
        s.qword("x9")?;
        s.qword("x10")?;
        s.qword("x11")?;
        s.qword("x12")?;
        s.qword("x13")?;
        s.qword("x14")?;
        s.qword("x15")?;
        s.qword("x16")?;
        s.qword("x17")?;
        s.qword("x18")?;
        s.qword("x19")?;
        s.qword("x20")?;
        s.qword("x21")?;
        s.qword("x22")?;
        s.qword("x23")?;
        s.qword("x24")?;
        s.qword("x25")?;
        s.qword("x26")?;
        s.qword("x27")?;
        s.qword("x28")?;
        s.qword("fp")?;
        s.qword("lr")?;
        s.qword("sp")?;
        s.qword("pc")?;
        s.dword("cpsr")?;
        s.dword("pad")?;
        s.finish_structure()
    }
}

impl StructConverter for ThreadStateARM_64 {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl ThreadState for ThreadStateARM_64 {
    /// Java: `getInstructionPointer()`.
    fn get_instruction_pointer(&self) -> i64 {
        self.pc
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
        b.u64(22);
        b.u64(23);
        b.u64(24);
        b.u64(25);
        b.u64(26);
        b.u64(27);
        b.u64(28);
        b.u64(29);
        b.u64(30);
        b.u64(31);
        b.u64(32);
        b.u64(33);
        b.u32(34);
        b.u32(35);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let s = ThreadStateARM_64::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 272);
        assert_eq!(s.x0, 1);
        assert_eq!(s.pad, 35);
        assert_eq!(s.get_instruction_pointer(), s.pc);
        let st = s.to_structure().unwrap();
        assert_eq!(st.get_name(), "ARM64_THREAD_STATE");
        assert_eq!(st.get_length(), 272);
        assert_eq!(names(&st).len(), 35);
    }
}
