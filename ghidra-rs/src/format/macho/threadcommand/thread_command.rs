//! Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadCommand`.
//!
//! Represents a `thread_command` (`LC_THREAD` / `LC_UNIXTHREAD`). See
//! `EXTERNAL_HEADERS/mach-o/loader.h`.
//!
//! Java holds the parsed state as the abstract `ThreadState`; its five concrete subclasses are
//! chosen here by CPU type and flavor, so the state is the closed [`ThreadStateKind`] enum.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::load_command::{LoadCommand, LoadCommandBase};
use crate::format::macho::cpu_types::{
    CPU_TYPE_ARM, CPU_TYPE_ARM64_32, CPU_TYPE_ARM_64, CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64,
    CPU_TYPE_X86, CPU_TYPE_X86_64,
};
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::struct_builder::MachStruct;
use crate::format::macho::threadcommand::thread_state::ThreadState;
use crate::format::macho::threadcommand::thread_state_arm::ThreadStateARM;
use crate::format::macho::threadcommand::thread_state_arm_64::ThreadStateARM_64;
use crate::format::macho::threadcommand::thread_state_header::ThreadStateHeader;
use crate::format::macho::threadcommand::thread_state_ppc::ThreadStatePPC;
use crate::format::macho::threadcommand::thread_state_x86::ThreadStateX86;
use crate::format::macho::threadcommand::thread_state_x86_32::ThreadStateX86_32;
use crate::format::macho::threadcommand::thread_state_x86_64::ThreadStateX86_64;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::util::msg::Msg;

/// One of the concrete thread states a [`ThreadCommand`] can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadStateKind {
    /// `x86_THREAD_STATE32`.
    X86_32(ThreadStateX86_32),
    /// `x86_THREAD_STATE64`.
    X86_64(ThreadStateX86_64),
    /// `PPC_THREAD_STATE` / `PPC_THREAD_STATE64`.
    Ppc(ThreadStatePPC),
    /// `ARM_THREAD_STATE`.
    Arm(ThreadStateARM),
    /// `ARM64_THREAD_STATE`.
    Arm64(ThreadStateARM_64),
}

impl ThreadStateKind {
    /// This state as the abstract `ThreadState`.
    pub fn as_thread_state(&self) -> &dyn ThreadState {
        match self {
            ThreadStateKind::X86_32(s) => s,
            ThreadStateKind::X86_64(s) => s,
            ThreadStateKind::Ppc(s) => s,
            ThreadStateKind::Arm(s) => s,
            ThreadStateKind::Arm64(s) => s,
        }
    }
}

/// A Mach-O `thread_command`.
///
/// Port of `ghidra.app.util.bin.format.macho.threadcommand.ThreadCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadCommand {
    base: LoadCommandBase,
    thread_state_header: ThreadStateHeader,
    thread_state: Option<ThreadStateKind>,
}

impl ThreadCommand {
    /// Java: `ThreadCommand(BinaryReader, MachHeader)`. A state of an unsupported CPU type or
    /// flavor is left unparsed (`None`).
    pub fn new(reader: &mut BinaryReader, header: &MachHeader) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let thread_state_header = ThreadStateHeader::new(reader)?;
        let flavor = thread_state_header.get_flavor();
        let cpu_type = header.get_cpu_type();
        let thread_state = match cpu_type {
            CPU_TYPE_X86 if flavor as u32 == ThreadStateX86::X86_THREAD_STATE32 => {
                Some(ThreadStateKind::X86_32(ThreadStateX86_32::new(reader)?))
            }
            CPU_TYPE_X86_64 if flavor as u32 == ThreadStateX86::X86_THREAD_STATE64 => {
                Some(ThreadStateKind::X86_64(ThreadStateX86_64::new(reader)?))
            }
            CPU_TYPE_POWERPC if flavor == ThreadStatePPC::PPC_THREAD_STATE => {
                Some(ThreadStateKind::Ppc(ThreadStatePPC::new(reader, header.is32bit())?))
            }
            CPU_TYPE_POWERPC64 if flavor == ThreadStatePPC::PPC_THREAD_STATE64 => {
                Some(ThreadStateKind::Ppc(ThreadStatePPC::new(reader, header.is32bit())?))
            }
            CPU_TYPE_ARM if flavor == ThreadStateARM::ARM_THREAD_STATE => {
                Some(ThreadStateKind::Arm(ThreadStateARM::new(reader)?))
            }
            CPU_TYPE_ARM_64 | CPU_TYPE_ARM64_32 if flavor == ThreadStateARM_64::ARM64_THREAD_STATE => {
                Some(ThreadStateKind::Arm64(ThreadStateARM_64::new(reader)?))
            }
            CPU_TYPE_X86 | CPU_TYPE_X86_64 | CPU_TYPE_POWERPC | CPU_TYPE_POWERPC64 | CPU_TYPE_ARM
            | CPU_TYPE_ARM_64 | CPU_TYPE_ARM64_32 => None,
            _ => {
                Msg::info(
                    "Mach-O Thread Command",
                    &format!(
                        "Unsupported thread command flavor: 0x{:x} for CPU type 0x{:x}",
                        flavor, cpu_type
                    ),
                );
                None
            }
        };
        Ok(ThreadCommand { base, thread_state_header, thread_state })
    }

    /// Java: `getThreadStateHeader()`.
    pub fn get_thread_state_header(&self) -> &ThreadStateHeader {
        &self.thread_state_header
    }

    /// Java: `getThreadState()`. `None` stands in for Java's `null`.
    pub fn get_thread_state(&self) -> Option<&ThreadStateKind> {
        self.thread_state.as_ref()
    }

    /// Java: `getInitialInstructionPointer()`; -1 when there is no parsed state.
    pub fn get_initial_instruction_pointer(&self) -> i64 {
        self.thread_state.as_ref().map(|s| s.as_thread_state().get_instruction_pointer()).unwrap_or(-1)
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add(self.thread_state_header.to_data_type()?, "threadStateHeader", None)?;
        if let Some(state) = &self.thread_state {
            s.add(state.as_thread_state().to_data_type()?, "threadState", None)?;
        }
        s.finish_structure()
    }
}

impl StructConverter for ThreadCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for ThreadCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "thread_command".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::load_command_types::LC_UNIXTHREAD;
    use crate::format::macho::mach_constants::{MH_MAGIC, MH_MAGIC_64};
    use crate::format::macho::mach_header::test_support::{provider, Bytes};
    use crate::format::macho::struct_builder::test_support::names;

    fn header(magic: u32, cpu: i32) -> MachHeader {
        MachHeader::new(provider(MachHeader::create(magic, cpu, 0, 2, 0, 0, 0, 0).unwrap())).unwrap()
    }

    #[test]
    fn arm64_unix_thread_gives_pc() {
        let mut b = Bytes::new(true);
        b.u32(LC_UNIXTHREAD).u32(16 + 272).u32(6).u32(68);
        for i in 0..33u64 {
            b.u64(if i == 32 { 0x1_0000_4000 } else { i });
        }
        b.u32(0).u32(0);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let cmd = ThreadCommand::new(&mut r, &header(MH_MAGIC_64, CPU_TYPE_ARM_64)).unwrap();
        assert_eq!(r.get_pointer_index(), 16 + 272);
        assert_eq!(cmd.get_thread_state_header().get_count(), 68);
        assert!(matches!(cmd.get_thread_state(), Some(ThreadStateKind::Arm64(_))));
        assert_eq!(cmd.get_initial_instruction_pointer(), 0x1_0000_4000);
        let s = cmd.to_structure().unwrap();
        assert_eq!(names(&s), ["cmd", "cmdsize", "threadStateHeader", "threadState"]);
        assert_eq!(s.get_length(), 16 + 272);
    }

    #[test]
    fn x86_32_big_endian_header_and_wrong_flavor() {
        let mut b = Bytes::new(false);
        b.u32(LC_UNIXTHREAD).u32(80).u32(1).u32(16);
        for i in 0..16u32 {
            b.u32(if i == 10 { 0xffff_0000 } else { i });
        }
        let bytes = b.buf;
        let h = header(MH_MAGIC, CPU_TYPE_X86);
        let cmd = ThreadCommand::new(&mut BinaryReader::from_bytes(bytes.clone(), false), &h).unwrap();
        assert_eq!(cmd.get_initial_instruction_pointer(), 0xffff_0000);

        let mut wrong = bytes;
        wrong[11] = 4; // flavor 4 is not x86_THREAD_STATE32
        let cmd = ThreadCommand::new(&mut BinaryReader::from_bytes(wrong, false), &h).unwrap();
        assert!(cmd.get_thread_state().is_none());
        assert_eq!(cmd.get_initial_instruction_pointer(), -1);
        assert_eq!(names(&cmd.to_structure().unwrap()), ["cmd", "cmdsize", "threadStateHeader"]);
    }
}
