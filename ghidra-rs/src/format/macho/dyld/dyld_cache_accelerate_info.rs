//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheAccelerateInfo`.
//!
//! Represents a `dyld_cache_accelerate_info` structure (older caches): image-info extras,
//! initializers, DOF sections and range tables. See `dyld3/shared-cache/dyld_cache_format.h`.
//!
//! As in Java, the tables are read from their (absolute) offsets through the reader the header
//! was read with; [`parse`](DyldCacheAccelerateInfo::parse) reads them and
//! [`markup`](DyldCacheAccelerateInfo::markup) lays them down in a program.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::dyld::dyld_cache_accelerator_dof::DyldCacheAcceleratorDof;
use crate::format::macho::dyld::dyld_cache_accelerator_initializer::DyldCacheAcceleratorInitializer;
use crate::format::macho::dyld::dyld_cache_image_info_extra::DyldCacheImageInfoExtra;
use crate::format::macho::dyld::dyld_cache_range_entry::DyldCacheRangeEntry;
use crate::format::macho::struct_builder::{array, dword, qword, word, MachStruct};
use crate::program::model::address::address_set::AddressSet;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::comment_type::CommentType;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::SourceType;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `DataUtilities`' static methods are default methods on a trait in this crate.
struct Du;
impl DataUtilities for Du {}

const LOG_ORIGIN: &str = "DyldCacheAccelerateInfo";

/// A `dyld_cache_accelerate_info`.
///
/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheAccelerateInfo`.
#[derive(Debug, Clone)]
pub struct DyldCacheAccelerateInfo {
    version: i32,
    image_extras_count: i32,
    images_extras_offset: i32,
    bottom_up_list_offset: i32,
    dylib_trie_offset: i32,
    dylib_trie_size: i32,
    initializers_offset: i32,
    initializers_count: i32,
    dof_sections_offset: i32,
    dof_sections_count: i32,
    re_export_list_offset: i32,
    re_export_count: i32,
    dep_list_offset: i32,
    dep_list_count: i32,
    range_table_offset: i32,
    range_table_count: i32,
    dyld_section_addr: i64,
    reader: BinaryReader,
    image_info_extra_list: Vec<DyldCacheImageInfoExtra>,
    accelerator_initializer_list: Vec<DyldCacheAcceleratorInitializer>,
    accelerator_dof_list: Vec<DyldCacheAcceleratorDof>,
    range_entry_list: Vec<DyldCacheRangeEntry>,
}

impl DyldCacheAccelerateInfo {
    /// Java: `DyldCacheAccelerateInfo(BinaryReader)`. Reads the header; the reader is kept for
    /// [`parse`](Self::parse).
    pub fn new(reader: &BinaryReader) -> io::Result<Self> {
        let mut reader = reader.clone_reader();
        let version = reader.read_next_int()?;
        let image_extras_count = reader.read_next_int()?;
        let images_extras_offset = reader.read_next_int()?;
        let bottom_up_list_offset = reader.read_next_int()?;
        let dylib_trie_offset = reader.read_next_int()?;
        let dylib_trie_size = reader.read_next_int()?;
        let initializers_offset = reader.read_next_int()?;
        let initializers_count = reader.read_next_int()?;
        let dof_sections_offset = reader.read_next_int()?;
        let dof_sections_count = reader.read_next_int()?;
        let re_export_list_offset = reader.read_next_int()?;
        let re_export_count = reader.read_next_int()?;
        let dep_list_offset = reader.read_next_int()?;
        let dep_list_count = reader.read_next_int()?;
        let range_table_offset = reader.read_next_int()?;
        let range_table_count = reader.read_next_int()?;
        let dyld_section_addr = reader.read_next_long()?;
        Ok(DyldCacheAccelerateInfo {
            version, image_extras_count, images_extras_offset, bottom_up_list_offset, dylib_trie_offset, dylib_trie_size, initializers_offset, initializers_count, dof_sections_offset, dof_sections_count, re_export_list_offset, re_export_count, dep_list_offset, dep_list_count, range_table_offset, range_table_count,
            dyld_section_addr,
            reader,
            image_info_extra_list: Vec::new(),
            accelerator_initializer_list: Vec::new(),
            accelerator_dof_list: Vec::new(),
            range_entry_list: Vec::new(),
        })
    }

    /// Java: `parse(Program, Address, MessageLog, TaskMonitor)`.
    pub fn parse(
        &mut self,
        _program: &dyn Program,
        _accelerate_info_addr: &Address,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Parsing DYLD image image info extras...");
        self.image_info_extra_list = read_table(&mut self.reader, self.images_extras_offset, self.image_extras_count,
            DyldCacheImageInfoExtra::new, "Failed to parse dyld_cache_image_info_extra.", log, monitor)?;
        monitor.set_message("Parsing DYLD accelerator initializers...");
        self.accelerator_initializer_list = read_table(&mut self.reader, self.initializers_offset, self.initializers_count,
            DyldCacheAcceleratorInitializer::new, "Failed to parse dyld_cache_accelerator_initializer.", log, monitor)?;
        monitor.set_message("Parsing DYLD DOF sections...");
        self.accelerator_dof_list = read_table(&mut self.reader, self.dof_sections_offset, self.dof_sections_count,
            DyldCacheAcceleratorDof::new, "Failed to parse dyld_cache_accelerator_dof.", log, monitor)?;
        monitor.set_message("Parsing DYLD range entries...");
        self.range_entry_list = read_table(&mut self.reader, self.range_table_offset, self.range_table_count,
            DyldCacheRangeEntry::new, "Failed to parse dyld_cache_range_entry.", log, monitor)?;
        Ok(())
    }

    /// Java: `markup(Program, Address, TaskMonitor, MessageLog)`.
    pub fn markup(
        &self,
        program: &dyn Program,
        accelerate_info_addr: &Address,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD image info extras...");
        markup_table(program, accelerate_info_addr, self.images_extras_offset, &self.image_info_extra_list,
            "Failed to markup dyld_cache_image_info_extra.", |_, _| {}, log, monitor)?;
        monitor.set_message("Marking up DYLD accelerator initializers...");
        markup_table(program, accelerate_info_addr, self.initializers_offset, &self.accelerator_initializer_list,
            "Failed to markup dyld_cache_accelerator_initializer.",
            |program, initializer| create_initializer_function(program, initializer), log, monitor)?;
        monitor.set_message("Marking up DYLD DOF sections...");
        markup_table(program, accelerate_info_addr, self.dof_sections_offset, &self.accelerator_dof_list,
            "Failed to markup dyld_cache_accelerator_dof.", |_, _| {}, log, monitor)?;
        self.markup_word_array(program, accelerate_info_addr, "Marking up DYLD re-exports...",
            self.re_export_list_offset, self.re_export_count, "re-exports", "Failed to markup reExportList.", log, monitor);
        self.markup_word_array(program, accelerate_info_addr, "Marking up DYLD dependencies...",
            self.dep_list_offset, self.dep_list_count, "dependencies", "Failed to markup dependences.", log, monitor);
        monitor.set_message("Marking up DYLD range entries...");
        markup_table(program, accelerate_info_addr, self.range_table_offset, &self.range_entry_list,
            "Failed to markup dyld_cache_range_entry.", |_, _| {}, log, monitor)?;
        Ok(())
    }

    /// The parsed `dyld_cache_image_info_extra` entries.
    pub fn get_image_info_extras(&self) -> &[DyldCacheImageInfoExtra] {
        &self.image_info_extra_list
    }

    /// The parsed `dyld_cache_accelerator_initializer` entries.
    pub fn get_accelerator_initializers(&self) -> &[DyldCacheAcceleratorInitializer] {
        &self.accelerator_initializer_list
    }

    /// The parsed `dyld_cache_accelerator_dof` entries.
    pub fn get_accelerator_dofs(&self) -> &[DyldCacheAcceleratorDof] {
        &self.accelerator_dof_list
    }

    /// The parsed `dyld_cache_range_entry` entries.
    pub fn get_range_entries(&self) -> &[DyldCacheRangeEntry] {
        &self.range_entry_list
    }

    /// The `dyldSectionAddr` field.
    pub fn get_dyld_section_addr(&self) -> i64 {
        self.dyld_section_addr
    }

    /// Java: the private `markupReExportList`/`markupDependencies`.
    #[allow(clippy::too_many_arguments)]
    fn markup_word_array(
        &self,
        program: &dyn Program,
        accelerate_info_addr: &Address,
        message: &str,
        offset: i32,
        count: i32,
        comment: &str,
        failure: &str,
        log: &MessageLog,
        monitor: &dyn TaskMonitor,
    ) {
        monitor.set_message(message);
        monitor.initialize(1);
        let result: Result<(), String> = (|| {
            let addr = accelerate_info_addr.add(offset as i64).map_err(|e| e.to_string())?;
            let dt = array(word(), count).map_err(|e| e.to_string())?;
            Du.create_data(program, &addr, dt, -1, ClearDataMode::CheckForSpace).map_err(|e| e.to_string())?;
            let mut listing = program.get_listing().ok_or("no listing")?;
            listing.set_comment(&addr, CommentType::Eol, Some(comment.to_string()));
            Ok(())
        })();
        match result {
            Ok(()) => monitor.increment_progress(1),
            Err(_) => log.append_msg_from(Some(LOG_ORIGIN), failure),
        }
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_accelerate_info");
        s.add(dword(), "version", Some("currently 1"))?;
        s.add(dword(), "imageExtrasCount", Some("does not include aliases"))?;
        s.add(dword(), "imagesExtrasOffset", Some("offset into this chunk of first dyld_cache_image_info_extra"))?;
        s.add(dword(), "bottomUpListOffset", Some("offset into this chunk to start of 16-bit array of sorted image indexes"))?;
        s.add(dword(), "dylibTrieOffset", Some("offset into this chunk to start of trie containing all dylib paths"))?;
        s.add(dword(), "dylibTrieSize", Some("size of trie containing all dylib paths"))?;
        s.add(dword(), "initializersOffset", Some("offset into this chunk to start of initializers list"))?;
        s.add(dword(), "initializersCount", Some("size of initializers list"))?;
        s.add(dword(), "dofSectionsOffset", Some("offset into this chunk to start of DOF (DTrace object format) sections list"))?;
        s.add(dword(), "dofSectionsCount", Some("size of DOF (DTrace object format sections list)"))?;
        s.add(dword(), "reExportListOffset", Some("offset into this chunk to start of 16-bit array of re-exports"))?;
        s.add(dword(), "reExportCount", Some("size of re-exports"))?;
        s.add(dword(), "depListOffset", Some("offset into this chunk to start of 16-bit array of dependencies (0x8000 bit set if upward)"))?;
        s.add(dword(), "depListCount", Some("size of dependencies"))?;
        s.add(dword(), "rangeTableOffset", Some("offset into this chunk to start of ss"))?;
        s.add(dword(), "rangeTableCount", Some("size of dependencies"))?;
        s.add(qword(), "dyldSectionAddr", Some("address of libdyld's __dyld section in unslid cache"))?;
        s.finish_structure()
    }
}

/// Java: `markupAcceleratorInitializer`'s per-entry function creation; overlapping functions and
/// invalid input are ignored, as in Java.
fn create_initializer_function(program: &dyn Program, initializer: &DyldCacheAcceleratorInitializer) {
    let Some(base) = program.get_image_base() else { return };
    let Ok(func_addr) = base.add(initializer.get_functions_offset() as i64) else { return };
    if let Some(mut fm) = program.get_function_manager() {
        let body = AddressSet::from_address(func_addr.clone());
        let _ = fm.create_function(None, func_addr, &body, SourceType::Analysis);
    }
}

/// The shared shape of the four Java `parse*` helpers: read `count` entries from `offset`,
/// logging `failure` (and keeping what was read) on an I/O error.
#[allow(clippy::too_many_arguments)]
fn read_table<T>(
    reader: &mut BinaryReader,
    offset: i32,
    count: i32,
    read: fn(&mut BinaryReader) -> io::Result<T>,
    failure: &str,
    log: &MessageLog,
    monitor: &dyn TaskMonitor,
) -> Result<Vec<T>, CancelledException> {
    monitor.initialize(count as i64);
    reader.set_pointer_index(offset as i64 as u64);
    let mut out = Vec::new();
    for _ in 0..count {
        match read(reader) {
            Ok(v) => out.push(v),
            Err(_) => {
                log.append_msg_from(Some(LOG_ORIGIN), failure);
                break;
            }
        }
        monitor.check_cancelled()?;
        monitor.increment_progress(1);
    }
    Ok(out)
}

/// The shared shape of the Java `markup*` helpers that lay entries down consecutively.
#[allow(clippy::too_many_arguments)]
fn markup_table<T: StructConverter>(
    program: &dyn Program,
    accelerate_info_addr: &Address,
    offset: i32,
    entries: &[T],
    failure: &str,
    mut per_entry: impl FnMut(&dyn Program, &T),
    log: &MessageLog,
    monitor: &dyn TaskMonitor,
) -> Result<(), CancelledException> {
    monitor.initialize(entries.len() as i64);
    let Ok(mut addr) = accelerate_info_addr.add(offset as i64) else {
        log.append_msg_from(Some(LOG_ORIGIN), failure);
        return Ok(());
    };
    for entry in entries {
        let created = entry
            .to_data_type()
            .map_err(|e| e.to_string())
            .and_then(|dt| Du.create_data(program, &addr, dt, -1, ClearDataMode::CheckForSpace).map_err(|e| e.to_string()));
        let Ok(d) = created else {
            log.append_msg_from(Some(LOG_ORIGIN), failure);
            return Ok(());
        };
        per_entry(program, entry);
        match addr.add(d.get_length() as i64) {
            Ok(next) => addr = next,
            Err(_) => {
                log.append_msg_from(Some(LOG_ORIGIN), failure);
                return Ok(());
            }
        }
        monitor.check_cancelled()?;
        monitor.increment_progress(1);
    }
    Ok(())
}

impl StructConverter for DyldCacheAccelerateInfo {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::util::task::DummyMonitor;

    #[test]
    fn parses_tables_from_absolute_offsets() {
        let mut b = Bytes::new(true);
        // header: version 1, 1 image extra @0x50, ..., 2 initializers @0x70, 1 dof @0x80, 1 range @0x90
        for v in [1u32, 1, 0x50, 0, 0, 0, 0x70, 2, 0x80, 1, 0, 0, 0, 0, 0x90, 1] {
            b.u32(v);
        }
        b.u64(0x1_8000_0000);
        b.pad_to(0x50).u64(1).u64(2).u32(3).u32(4).u32(5).u32(6);
        b.pad_to(0x70).u32(0x10).u32(0).u32(0x20).u32(1);
        b.pad_to(0x80).u64(0x1000).u32(0x40).u32(2);
        b.pad_to(0x90).u64(0x2000).u32(0x80).u32(3);
        let r = BinaryReader::from_bytes(b.buf, true);
        let mut info = DyldCacheAccelerateInfo::new(&r).unwrap();
        assert_eq!(info.get_dyld_section_addr(), 0x1_8000_0000);
        let log = MessageLog::new();
        let space = crate::program::model::address::AddressSpace::new(
            "ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        struct NoProgram;
        impl crate::framework::model::DomainObject for NoProgram {}
        impl Program for NoProgram {
            fn get_name(&self) -> String { String::new() }
            fn get_language_id(&self) -> String { String::new() }
        }
        info.parse(&NoProgram, &space.address(0), &log, &DummyMonitor).unwrap();
        assert!(!log.has_messages());
        assert_eq!(info.get_image_info_extras().len(), 1);
        assert_eq!(info.get_accelerator_initializers()[1].get_functions_offset(), 0x20);
        assert_eq!(info.get_accelerator_dofs().len(), 1);
        assert_eq!(info.get_range_entries().len(), 1);
        assert_eq!(info.to_structure().unwrap().get_length(), 72);
    }
}
