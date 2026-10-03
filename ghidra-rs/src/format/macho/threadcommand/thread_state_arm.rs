//! Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateARM`.
//!
//! Represents an ARM `arm_thread_state_t` structure.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::format::macho::threadcommand::thread_state::ThreadState;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStateARM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThreadStateARM {
    /// Java: the public `r0` field.
    pub r0: i32,
    /// Java: the public `r1` field.
    pub r1: i32,
    /// Java: the public `r2` field.
    pub r2: i32,
    /// Java: the public `r3` field.
    pub r3: i32,
    /// Java: the public `r4` field.
    pub r4: i32,
    /// Java: the public `r5` field.
    pub r5: i32,
    /// Java: the public `r6` field.
    pub r6: i32,
    /// Java: the public `r7` field.
    pub r7: i32,
    /// Java: the public `r8` field.
    pub r8: i32,
    /// Java: the public `r9` field.
    pub r9: i32,
    /// Java: the public `r10` field.
    pub r10: i32,
    /// Java: the public `r11` field.
    pub r11: i32,
    /// Java: the public `r12` field.
    pub r12: i32,
    /// Java: the public `sp` field.
    pub sp: i32,
    /// Java: the public `lr` field.
    pub lr: i32,
    /// Java: the public `pc` field.
    pub pc: i32,
    /// Java: the public `cpsr` field.
    pub cpsr: i32,
}

impl ThreadStateARM {
    /// Java: `ARM_THREAD_STATE`.
    pub const ARM_THREAD_STATE: i32 = 1;
    /// Java: `ARM_VFP_STATE`.
    pub const ARM_VFP_STATE: i32 = 2;
    /// Java: `ARM_EXCEPTION_STATE`.
    pub const ARM_EXCEPTION_STATE: i32 = 3;
    /// Java: `ARM_DEBUG_STATE`.
    pub const ARM_DEBUG_STATE: i32 = 4;
    /// Java: `THREAD_STATE_NONE`.
    pub const THREAD_STATE_NONE: i32 = 5;

    /// Java: `ThreadStateARM(BinaryReader)`.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(ThreadStateARM {
            r0: reader.read_next_int()?,
            r1: reader.read_next_int()?,
            r2: reader.read_next_int()?,
            r3: reader.read_next_int()?,
            r4: reader.read_next_int()?,
            r5: reader.read_next_int()?,
            r6: reader.read_next_int()?,
            r7: reader.read_next_int()?,
            r8: reader.read_next_int()?,
            r9: reader.read_next_int()?,
            r10: reader.read_next_int()?,
            r11: reader.read_next_int()?,
            r12: reader.read_next_int()?,
            sp: reader.read_next_int()?,
            lr: reader.read_next_int()?,
            pc: reader.read_next_int()?,
            cpsr: reader.read_next_int()?,
        })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("ARM_THREAD_STATE");
        s.dword("r0")?;
        s.dword("r1")?;
        s.dword("r2")?;
        s.dword("r3")?;
        s.dword("r4")?;
        s.dword("r5")?;
        s.dword("r6")?;
        s.dword("r7")?;
        s.dword("r8")?;
        s.dword("r9")?;
        s.dword("r10")?;
        s.dword("r11")?;
        s.dword("r12")?;
        s.dword("sp")?;
        s.dword("lr")?;
        s.dword("pc")?;
        s.dword("cpsr")?;
        s.finish_structure()
    }
}

impl StructConverter for ThreadStateARM {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl ThreadState for ThreadStateARM {
    /// Java: `getInstructionPointer()`.
    fn get_instruction_pointer(&self) -> i64 {
        self.pc as u32 as i64
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
        b.u32(17);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let s = ThreadStateARM::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 68);
        assert_eq!(s.r0, 1);
        assert_eq!(s.cpsr, 17);
        assert_eq!(s.get_instruction_pointer(), s.pc as u32 as i64);
        let st = s.to_structure().unwrap();
        assert_eq!(st.get_name(), "ARM_THREAD_STATE");
        assert_eq!(st.get_length(), 68);
        assert_eq!(names(&st).len(), 17);
    }

    #[test]
    fn instruction_pointer_is_unsigned() {
        let mut s = ThreadStateARM::new(&mut BinaryReader::from_bytes(vec![0u8; 128], true)).unwrap();
        s.pc = -4;
        assert_eq!(s.get_instruction_pointer(), 0xffff_fffc);
    }
}
