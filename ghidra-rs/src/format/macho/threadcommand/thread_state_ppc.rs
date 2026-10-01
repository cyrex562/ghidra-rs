//! Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStatePPC`.
//!
//! Represents a PowerPC `ppc_thread_state_t` / `ppc_thread_state64_t` structure.
//!
//! Registers are 32-bit (zero-extended) or 64-bit per `is32bit`; the structure always uses `DWORD` fields, as Java does.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::struct_builder::MachStruct;
use crate::format::macho::threadcommand::thread_state::ThreadState;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;

/// Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadStatePPC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThreadStatePPC {
    /// Java: the public `srr0` field.
    pub srr0: i64,
    /// Java: the public `srr1` field.
    pub srr1: i64,
    /// Java: the public `r0` field.
    pub r0: i64,
    /// Java: the public `r1` field.
    pub r1: i64,
    /// Java: the public `r2` field.
    pub r2: i64,
    /// Java: the public `r3` field.
    pub r3: i64,
    /// Java: the public `r4` field.
    pub r4: i64,
    /// Java: the public `r5` field.
    pub r5: i64,
    /// Java: the public `r6` field.
    pub r6: i64,
    /// Java: the public `r7` field.
    pub r7: i64,
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
    /// Java: the public `r16` field.
    pub r16: i64,
    /// Java: the public `r17` field.
    pub r17: i64,
    /// Java: the public `r18` field.
    pub r18: i64,
    /// Java: the public `r19` field.
    pub r19: i64,
    /// Java: the public `r20` field.
    pub r20: i64,
    /// Java: the public `r21` field.
    pub r21: i64,
    /// Java: the public `r22` field.
    pub r22: i64,
    /// Java: the public `r23` field.
    pub r23: i64,
    /// Java: the public `r24` field.
    pub r24: i64,
    /// Java: the public `r25` field.
    pub r25: i64,
    /// Java: the public `r26` field.
    pub r26: i64,
    /// Java: the public `r27` field.
    pub r27: i64,
    /// Java: the public `r28` field.
    pub r28: i64,
    /// Java: the public `r29` field.
    pub r29: i64,
    /// Java: the public `r30` field.
    pub r30: i64,
    /// Java: the public `r31` field.
    pub r31: i64,
    /// Java: the public `cr` field.
    pub cr: i32,
    /// Java: the public `xer` field.
    pub xer: i64,
    /// Java: the public `lr` field.
    pub lr: i64,
    /// Java: the public `ctr` field.
    pub ctr: i64,
    /// Java: the public `mq` field.
    pub mq: i64,
    /// Java: the public `vrsave` field.
    pub vrsave: i64,
}

impl ThreadStatePPC {
    /// Java: `PPC_THREAD_STATE`.
    pub const PPC_THREAD_STATE: i32 = 1;
    /// Java: `PPC_FLOAT_STATE`.
    pub const PPC_FLOAT_STATE: i32 = 2;
    /// Java: `PPC_EXCEPTION_STATE`.
    pub const PPC_EXCEPTION_STATE: i32 = 3;
    /// Java: `PPC_VECTOR_STATE`.
    pub const PPC_VECTOR_STATE: i32 = 4;
    /// Java: `PPC_THREAD_STATE64`.
    pub const PPC_THREAD_STATE64: i32 = 5;
    /// Java: `PPC_EXCEPTION_STATE64`.
    pub const PPC_EXCEPTION_STATE64: i32 = 6;
    /// Java: `THREAD_STATE_NONE`.
    pub const THREAD_STATE_NONE: i32 = 7;

    /// Java: `ThreadStatePPC(BinaryReader, boolean)`.
    pub fn new(reader: &mut BinaryReader, is32bit: bool) -> io::Result<Self> {
        Ok(ThreadStatePPC {
            srr0: read(reader, is32bit)?,
            srr1: read(reader, is32bit)?,
            r0: read(reader, is32bit)?,
            r1: read(reader, is32bit)?,
            r2: read(reader, is32bit)?,
            r3: read(reader, is32bit)?,
            r4: read(reader, is32bit)?,
            r5: read(reader, is32bit)?,
            r6: read(reader, is32bit)?,
            r7: read(reader, is32bit)?,
            r8: read(reader, is32bit)?,
            r9: read(reader, is32bit)?,
            r10: read(reader, is32bit)?,
            r11: read(reader, is32bit)?,
            r12: read(reader, is32bit)?,
            r13: read(reader, is32bit)?,
            r14: read(reader, is32bit)?,
            r15: read(reader, is32bit)?,
            r16: read(reader, is32bit)?,
            r17: read(reader, is32bit)?,
            r18: read(reader, is32bit)?,
            r19: read(reader, is32bit)?,
            r20: read(reader, is32bit)?,
            r21: read(reader, is32bit)?,
            r22: read(reader, is32bit)?,
            r23: read(reader, is32bit)?,
            r24: read(reader, is32bit)?,
            r25: read(reader, is32bit)?,
            r26: read(reader, is32bit)?,
            r27: read(reader, is32bit)?,
            r28: read(reader, is32bit)?,
            r29: read(reader, is32bit)?,
            r30: read(reader, is32bit)?,
            r31: read(reader, is32bit)?,
            cr: reader.read_next_int()?,
            xer: read(reader, is32bit)?,
            lr: read(reader, is32bit)?,
            ctr: read(reader, is32bit)?,
            mq: read(reader, is32bit)?,
            vrsave: read(reader, is32bit)?,
        })
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("PPC_THREAD_STATE");
        s.dword("srr0")?;
        s.dword("srr1")?;
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
        s.dword("r13")?;
        s.dword("r14")?;
        s.dword("r15")?;
        s.dword("r16")?;
        s.dword("r17")?;
        s.dword("r18")?;
        s.dword("r19")?;
        s.dword("r20")?;
        s.dword("r21")?;
        s.dword("r22")?;
        s.dword("r23")?;
        s.dword("r24")?;
        s.dword("r25")?;
        s.dword("r26")?;
        s.dword("r27")?;
        s.dword("r28")?;
        s.dword("r29")?;
        s.dword("r30")?;
        s.dword("r31")?;
        s.dword("cr")?;
        s.dword("xer")?;
        s.dword("lr")?;
        s.dword("ctr")?;
        s.dword("mq")?;
        s.dword("vrsave")?;
        s.finish_structure()
    }
}

/// Java: the private `read(BinaryReader, boolean)`: a zero-extended 32-bit or a 64-bit value.
fn read(reader: &mut BinaryReader, is32bit: bool) -> io::Result<i64> {
    if is32bit {
        Ok(reader.read_next_unsigned_int()? as i64)
    } else {
        reader.read_next_long()
    }
}

impl StructConverter for ThreadStatePPC {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl ThreadState for ThreadStatePPC {
    /// Java: `getInstructionPointer()`.
    fn get_instruction_pointer(&self) -> i64 {
        self.srr0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::struct_builder::test_support::names;

    #[test]
    fn reads_32_and_64_bit_layouts() {
        for is32bit in [true, false] {
            let mut b = Bytes::new(false);
            for i in 0..34u64 {
                if is32bit { b.u32(0x8000_0000 | i as u32); } else { b.u64(0x1_0000_0000 | i); }
            }
            b.u32(0xcccc);
            for i in 0..5u64 {
                if is32bit { b.u32(0x100 + i as u32); } else { b.u64(0x100 + i); }
            }
            let len = b.len();
            let mut r = BinaryReader::from_bytes(b.buf, false);
            let s = ThreadStatePPC::new(&mut r, is32bit).unwrap();
            assert_eq!(r.get_pointer_index() as usize, len);
            if is32bit {
                assert_eq!(s.srr0, 0x8000_0000, "zero-extended");
                assert_eq!(s.r31, 0x8000_0021);
            } else {
                assert_eq!(s.srr0, 0x1_0000_0000);
            }
            assert_eq!(s.get_instruction_pointer(), s.srr0);
            assert_eq!(s.cr, 0xcccc);
            assert_eq!(s.vrsave, 0x104);
        }
        let s = ThreadStatePPC::new(&mut BinaryReader::from_bytes(vec![0u8; 400], true), false).unwrap();
        let st = s.to_structure().unwrap();
        assert_eq!(st.get_name(), "PPC_THREAD_STATE");
        assert_eq!(st.get_length(), 40 * 4);
        assert_eq!(names(&st)[0], "srr0");
    }
}
