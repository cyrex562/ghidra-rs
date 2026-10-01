//! Port of `ghidra.app.util.bin.format.macho.dyld.LibObjcDylib`.
//!
//! A class to represent the `libobjc` DYLIB Mach-O that resides within a DYLD cache.

use std::io;
use std::sync::Arc;

use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::segment_names;
use crate::format::macho::dyld::lib_objc_optimization::LibObjcOptimization;
use crate::format::macho::mach_header::MachHeader;
use crate::program::model::address::AddressSpace;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Port of `ghidra.app.util.bin.format.macho.dyld.LibObjcDylib`.
///
/// Java keeps the `MachHeader` in a field, but only the constructor reads it, so this port
/// borrows it just for construction.
pub struct LibObjcDylib<'a> {
    program: &'a dyn Program,
    space: Arc<AddressSpace>,
    log: &'a MessageLog,
    monitor: &'a dyn TaskMonitor,
    lib_objc_optimization: Option<LibObjcOptimization>,
}

impl<'a> LibObjcDylib<'a> {
    /// Java `LibObjcDylib(MachHeader, Program, AddressSpace, MessageLog, TaskMonitor)`: parses
    /// the `objc_opt_t` in `libobjc`'s `__TEXT,__objc_opt_ro` section, if it has one.
    pub fn new(
        lib_objc_header: &MachHeader,
        program: &'a dyn Program,
        space: Arc<AddressSpace>,
        log: &'a MessageLog,
        monitor: &'a dyn TaskMonitor,
    ) -> io::Result<Self> {
        let lib_objc_optimization = match lib_objc_header.get_section(segment_names::TEXT, LibObjcOptimization::SECTION_NAME) {
            Some(section) => Some(LibObjcOptimization::new(program, &space.address(section.get_address()))?),
            None => None,
        };
        Ok(LibObjcDylib { program, space, log, monitor, lib_objc_optimization })
    }

    /// The parsed `objc_opt_t`, if the DYLIB has an `__objc_opt_ro` section.
    pub fn get_lib_objc_optimization(&self) -> Option<&LibObjcOptimization> {
        self.lib_objc_optimization.as_ref()
    }

    /// Java `markup()`: marks up the `objc_opt_t`, if present.
    pub fn markup(&self) {
        if let Some(opt) = &self.lib_objc_optimization {
            opt.markup(self.program, &self.space, self.log, self.monitor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::memory_byte_provider::test_support::BlockMemory;
    use crate::format::macho::commands::load_command_types::LC_SEGMENT_64;
    use crate::format::macho::dyld::lib_objc_optimization::test_support::{objc_opt, MemProgram};
    use crate::format::macho::mach_constants::MH_MAGIC_64;
    use crate::format::macho::mach_header::test_support::{provider, Bytes};
    use crate::util::task::DummyMonitor;

    fn header(section: &str) -> MachHeader {
        let mut b = Bytes::new(true);
        b.u32(MH_MAGIC_64).u32(0x0100_000c).u32(0).u32(6).u32(1).u32(72 + 80).u32(0).u32(0);
        b.u32(LC_SEGMENT_64).u32(72 + 80).name("__TEXT", 16);
        b.u64(0x1_8000_0000).u64(0x8000).u64(0).u64(0x8000).u32(5).u32(5).u32(1).u32(0);
        b.name(section, 16).name("__TEXT", 16).u64(0x1_8000_4000).u64(0x40);
        b.u32(0x4000).u32(3).u32(0).u32(0).u32(0).u32(0).u32(0).u32(0);
        b.pad_to(0x200);
        let mut h = MachHeader::new(provider(b.buf)).unwrap();
        h.parse().unwrap();
        h
    }

    #[test]
    fn parses_objc_opt_from_text_section() {
        let program = MemProgram {
            memory: Arc::new(BlockMemory::new(&[("__TEXT", 0x1_8000_4000, objc_opt(16))], false)),
        };
        let space = program.memory.space.clone();
        let log = MessageLog::new();
        let dylib = LibObjcDylib::new(&header("__objc_opt_ro"), &program, space, &log, &DummyMonitor).unwrap();
        let opt = dylib.get_lib_objc_optimization().unwrap();
        assert_eq!(opt.get_version(), 16);
        assert_eq!(opt.get_addr(), 0x1_8000_4000);
        // No listing in this program: the markup failure is logged, as in Java.
        dylib.markup();
        assert!(log.to_string().contains("Failed to markup objc_opt_t."));
    }

    #[test]
    fn without_section_there_is_nothing_to_markup() {
        let program = MemProgram { memory: Arc::new(BlockMemory::new(&[], false)) };
        let space = program.memory.space.clone();
        let log = MessageLog::new();
        let dylib = LibObjcDylib::new(&header("__text"), &program, space, &log, &DummyMonitor).unwrap();
        assert!(dylib.get_lib_objc_optimization().is_none());
        dylib.markup();
        assert!(!log.has_messages());
    }
}
