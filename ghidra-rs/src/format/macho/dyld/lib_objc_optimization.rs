//! Port of `ghidra.app.util.bin.format.macho.dyld.LibObjcOptimization`.
//!
//! Represents an `objc_opt_t` structure, which resides in the `__objc_opt_ro` section of
//! `libobjc`'s `__TEXT` segment in a DYLD cache. See
//! <https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc-shared-cache.h>.

use std::io;
use std::rc::Rc;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::memory_byte_provider::MemoryByteProvider;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::struct_builder::{dword, qword, MachStruct};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
struct Du;
impl DataUtilities for Du {}

/// Port of `ghidra.app.util.bin.format.macho.dyld.LibObjcOptimization`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibObjcOptimization {
    version: i32,
    flags: i32,
    selopt_offset: i32,
    headeropt_ro_offset: i32,
    clsopt_offset: i32,
    protocolopt1_offset: i32,
    headeropt_rw_offset: i32,
    protocolopt2_offset: i32,
    large_shared_caches_class_offset: i32,
    large_shared_caches_protocol_offset: i32,
    relative_method_selector_base_address_offset: i64,
    objc_opt_addr: i64,
}

impl LibObjcOptimization {
    /// The name of the section that contains the `objc_opt_t` structure. Java: `SECTION_NAME`.
    pub const SECTION_NAME: &'static str = "__objc_opt_ro";

    /// Java `LibObjcOptimization(Program, Address)`: parses the `objc_opt_t` at
    /// `objc_opt_ro_section_addr` out of the program's memory, in the language's byte order.
    pub fn new(program: &dyn Program, objc_opt_ro_section_addr: &Address) -> io::Result<Self> {
        let memory = program.get_memory().ok_or_else(|| io::Error::other("program has no memory"))?;
        let big_endian = program
            .get_language()
            .map(|l| l.is_big_endian())
            .unwrap_or_else(|| memory.is_big_endian());
        let provider = MemoryByteProvider::from_address(Arc::clone(&memory), objc_opt_ro_section_addr.clone());
        let mut reader = BinaryReader::new(Rc::new(provider), !big_endian);

        let mut opt = LibObjcOptimization {
            version: reader.read_next_int()?,
            flags: 0,
            selopt_offset: 0,
            headeropt_ro_offset: 0,
            clsopt_offset: 0,
            protocolopt1_offset: 0,
            headeropt_rw_offset: 0,
            protocolopt2_offset: 0,
            large_shared_caches_class_offset: 0,
            large_shared_caches_protocol_offset: 0,
            relative_method_selector_base_address_offset: 0,
            objc_opt_addr: objc_opt_ro_section_addr.offset(),
        };
        if opt.version <= 14 {
            opt.selopt_offset = reader.read_next_int()?;
            opt.headeropt_ro_offset = reader.read_next_int()?;
            opt.clsopt_offset = reader.read_next_int()?;
            if opt.version >= 13 {
                opt.protocolopt1_offset = reader.read_next_int()?;
            }
        } else {
            opt.flags = reader.read_next_int()?;
            opt.selopt_offset = reader.read_next_int()?;
            opt.headeropt_ro_offset = reader.read_next_int()?;
            opt.clsopt_offset = reader.read_next_int()?;
            opt.protocolopt1_offset = reader.read_next_int()?;
            opt.headeropt_rw_offset = reader.read_next_int()?;
            opt.protocolopt2_offset = reader.read_next_int()?;
            if opt.version >= 16 {
                opt.large_shared_caches_class_offset = reader.read_next_int()?;
                opt.large_shared_caches_protocol_offset = reader.read_next_int()?;
                opt.relative_method_selector_base_address_offset = reader.read_next_long()?;
            }
        }
        Ok(opt)
    }

    /// Java `getAddr()`: the address of the `objc_opt_t` structure.
    pub fn get_addr(&self) -> i64 {
        self.objc_opt_addr
    }

    /// Java `getRelativeSelectorBaseAddressOffset()`.
    pub fn get_relative_selector_base_address_offset(&self) -> i64 {
        self.relative_method_selector_base_address_offset
    }

    /// The structure's version.
    pub fn get_version(&self) -> i32 {
        self.version
    }

    /// Java `markup(Program, AddressSpace, MessageLog, TaskMonitor)`: lays down the `objc_opt_t`
    /// structure; a failure is logged.
    pub fn markup(&self, program: &dyn Program, space: &Arc<AddressSpace>, log: &MessageLog, _monitor: &dyn TaskMonitor) {
        let addr = space.address(self.get_addr());
        let result = self
            .to_data_type()
            .map_err(|e| e.to_string())
            .and_then(|dt| {
                Du.create_data(program, &addr, dt, -1, ClearDataMode::CheckForSpace).map_err(|e| e.to_string())
            });
        if result.is_err() {
            log.append_msg_from(Some("LibObjcOptimization"), "Failed to markup objc_opt_t.");
        }
    }

    /// Java `toDataType()`, returning the concrete structure (Java sets no category path).
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("objc_opt_t");
        let names: &[&str] = if self.version <= 12 {
            &["version", "selopt_offset", "headeropt_offset", "clsopt_offset"]
        } else if self.version <= 14 {
            &["version", "selopt_offset", "headeropt_offset", "clsopt_offset", "protocolopt_offset"]
        } else if self.version == 15 {
            &[
                "version",
                "flags",
                "selopt_offset",
                "headeropt_ro_offset",
                "clsopt_offset",
                "unused_protocolopt_offset",
                "headeropt_rw_offset",
                "protocolopt_offset",
            ]
        } else {
            &[
                "version",
                "flags",
                "selopt_offset",
                "headeropt_ro_offset",
                "unused_clsopt_offset",
                "unused_protocolopt_offset",
                "headeropt_rw_offset",
                "unused_protocolopt2_offset",
                "largeSharedCachesClassOffset",
                "largeSharedCachesProtocolOffset",
            ]
        };
        for name in names {
            s.add(dword(), name, Some(""))?;
        }
        if self.version >= 16 {
            s.add(qword(), "relativeMethodSelectorBaseAddressOffset", Some(""))?;
        }
        Ok(s.into_structure())
    }
}

impl StructConverter for LibObjcOptimization {
    /// Java `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use crate::app::util::bin::memory_byte_provider::test_support::BlockMemory;
    use crate::framework::model::DomainObject;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::Memory;

    /// A program whose only capability is its (block) memory.
    pub(crate) struct MemProgram {
        pub(crate) memory: Arc<BlockMemory>,
    }

    impl DomainObject for MemProgram {}

    impl Program for MemProgram {
        fn get_name(&self) -> String {
            "libobjc.A.dylib".to_string()
        }
        fn get_language_id(&self) -> String {
            "AARCH64:LE:64:AppleSilicon".to_string()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone() as Arc<dyn Memory>)
        }
    }

    /// Little-endian `objc_opt_t` bytes of the given `version` (fields numbered from 1).
    pub(crate) fn objc_opt(version: i32) -> Vec<u8> {
        let mut v = version.to_le_bytes().to_vec();
        for i in 1..=10i32 {
            v.extend_from_slice(&(i * 0x10).to_le_bytes());
        }
        v.extend_from_slice(&0x1122_3344_5566i64.to_le_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{objc_opt, MemProgram};
    use super::*;
    use crate::app::util::bin::memory_byte_provider::test_support::BlockMemory;
    use crate::format::macho::struct_builder::test_support::names;
    use crate::util::task::DummyMonitor;

    fn parse(version: i32) -> LibObjcOptimization {
        let program = MemProgram { memory: Arc::new(BlockMemory::new(&[("__objc_opt_ro", 0x4000, objc_opt(version))], false)) };
        let addr = program.memory.space.address(0x4000);
        LibObjcOptimization::new(&program, &addr).unwrap()
    }

    #[test]
    fn parses_old_and_new_layouts() {
        let v12 = parse(12);
        assert_eq!((v12.selopt_offset, v12.headeropt_ro_offset, v12.clsopt_offset, v12.protocolopt1_offset), (0x10, 0x20, 0x30, 0));
        let v13 = parse(13);
        assert_eq!(v13.protocolopt1_offset, 0x40);
        let v15 = parse(15);
        assert_eq!((v15.flags, v15.selopt_offset, v15.protocolopt2_offset), (0x10, 0x20, 0x70));
        assert_eq!(v15.get_relative_selector_base_address_offset(), 0);
        let v16 = parse(16);
        assert_eq!(v16.large_shared_caches_class_offset, 0x80);
        assert_eq!(v16.large_shared_caches_protocol_offset, 0x90);
        // The QWORD after nine DWORDs overlaps the tenth DWORD (0xa0) and the low half of 0x1122_3344_5566.
        assert_eq!(v16.get_relative_selector_base_address_offset(), 0xa0 | (0x3344_5566_i64 << 32));
        assert_eq!(v16.get_addr(), 0x4000);
    }

    #[test]
    fn data_type_layout_follows_version() {
        assert_eq!(parse(12).to_structure().unwrap().get_length(), 16);
        assert_eq!(names(&parse(14).to_structure().unwrap())[4], "protocolopt_offset");
        assert_eq!(parse(15).to_structure().unwrap().get_length(), 32);
        let s = parse(16).to_structure().unwrap();
        assert_eq!(s.get_name(), "objc_opt_t");
        assert_eq!(s.get_length(), 48);
        assert_eq!(names(&s).last().unwrap(), "relativeMethodSelectorBaseAddressOffset");
    }

    #[test]
    fn markup_failure_is_logged() {
        let program = MemProgram { memory: Arc::new(BlockMemory::new(&[("x", 0x4000, objc_opt(16))], false)) };
        let space = program.memory.space.clone();
        let opt = LibObjcOptimization::new(&program, &space.address(0x4000)).unwrap();
        let log = MessageLog::new();
        opt.markup(&program, &space, &log, &DummyMonitor);
        assert!(log.to_string().contains("Failed to markup objc_opt_t."));
    }
}
