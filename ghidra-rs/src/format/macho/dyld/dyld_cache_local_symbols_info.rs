//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsInfo`.
//!
//! Represents a `dyld_cache_local_symbols_info` structure: the unmapped local-symbol nlists of a
//! DYLD cache and the per-dylib entries that index them. See
//! `dyld3/shared-cache/dyld_cache_format.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::n_list::NList;
use crate::format::macho::cpu_types::{CPU_TYPE_ARM_64, CPU_TYPE_X86_64};
use crate::format::macho::dyld::dyld_architecture::DyldArchitecture;
use crate::format::macho::dyld::dyld_cache_local_symbols_entry::DyldCacheLocalSymbolsEntry;
use crate::format::macho::struct_builder::{dword, MachStruct};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program::Program;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Java logs this class's failures under `DyldCacheAccelerateInfo`'s simple name.
const LOG_ORIGIN: &str = "DyldCacheAccelerateInfo";

/// A `dyld_cache_local_symbols_info`.
///
/// Port of `ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsInfo`.
#[derive(Debug, Clone)]
pub struct DyldCacheLocalSymbolsInfo {
    nlist_offset: i32,
    nlist_count: i32,
    strings_offset: i32,
    strings_size: i32,
    entries_offset: i32,
    entries_count: i32,
    reader: BinaryReader,
    start_index: u64,
    nlist_list: Vec<NList>,
    local_symbols_entry_list: Vec<DyldCacheLocalSymbolsEntry>,
    is32bit: bool,
    use64bit_offsets: bool,
}

impl DyldCacheLocalSymbolsInfo {
    /// Java: `DyldCacheLocalSymbolsInfo(BinaryReader, DyldArchitecture, boolean)`. Reads only the
    /// header; [`parse`](Self::parse) reads the tables.
    pub fn new(
        reader: &BinaryReader,
        architecture: &DyldArchitecture,
        use64bit_offsets: bool,
    ) -> io::Result<Self> {
        let mut reader = reader.clone_reader();
        let start_index = reader.get_pointer_index();
        let nlist_offset = reader.read_next_int()?;
        let nlist_count = reader.read_next_int()?;
        let strings_offset = reader.read_next_int()?;
        let strings_size = reader.read_next_int()?;
        let entries_offset = reader.read_next_int()?;
        let entries_count = reader.read_next_int()?;
        let cpu = architecture.cpu_type();
        let is32bit = !(cpu == CPU_TYPE_ARM_64 || cpu == CPU_TYPE_X86_64);
        Ok(DyldCacheLocalSymbolsInfo {
            nlist_offset,
            nlist_count,
            strings_offset,
            strings_size,
            entries_offset,
            entries_count,
            reader,
            start_index,
            nlist_list: Vec::new(),
            local_symbols_entry_list: Vec::new(),
            is32bit,
            use64bit_offsets,
        })
    }

    /// Java: `parse(MessageLog, TaskMonitor)`.
    pub fn parse(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        self.parse_nlist(log, monitor)?;
        self.parse_local_symbols(log, monitor)
    }

    /// Java: `markup(Program, Address, TaskMonitor, MessageLog)`.
    pub fn markup(
        &self,
        program: &dyn Program,
        local_symbols_info_addr: &Address,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        self.markup_local_symbols(program, local_symbols_info_addr, monitor, log)?;
        self.markup_nlist(program, local_symbols_info_addr, monitor, log)
    }

    /// Java: `getLocalSymbolsEntries()`.
    pub fn get_local_symbols_entries(&self) -> &[DyldCacheLocalSymbolsEntry] {
        &self.local_symbols_entry_list
    }

    /// Java: `getNList()`.
    pub fn get_nlist(&self) -> &[NList] {
        &self.nlist_list
    }

    /// Java: `getNList(long)`: the nlists of the dylib at `dylib_offset`, or empty.
    pub fn get_nlist_for(&self, dylib_offset: i64) -> &[NList] {
        for entry in &self.local_symbols_entry_list {
            if dylib_offset == entry.get_dylib_offset() {
                let index = entry.get_nlist_start_index() as usize;
                let count = entry.get_nlist_count() as usize;
                return self.nlist_list.get(index..index + count).unwrap_or(&[]);
            }
        }
        &[]
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("dyld_cache_local_symbols_info");
        s.add(dword(), "nlistOffset", Some("offset into this chunk of nlist entries"))?;
        s.add(dword(), "nlistCount", Some("count of nlist entries"))?;
        s.add(dword(), "stringsOffset", Some("offset into this chunk of string pool"))?;
        s.add(dword(), "stringsSize", Some("byte count of string pool"))?;
        s.add(dword(), "entriesOffset", Some("offset into this chunk of array of dyld_cache_local_symbols_entry "))?;
        s.add(dword(), "entriesCount", Some("number of elements in dyld_cache_local_symbols_entry array"))?;
        s.finish_structure()
    }

    fn parse_nlist(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        let mut nlist_reader = self.reader.clone_at(0);
        monitor.set_message("Parsing DYLD local symbol nlists...");
        monitor.initialize(self.nlist_count as i64 * 2);
        nlist_reader.set_pointer_index(self.start_index.wrapping_add(self.nlist_offset as i64 as u64));
        for _ in 0..self.nlist_count {
            match NList::new(&mut nlist_reader, self.is32bit) {
                Ok(n) => self.nlist_list.push(n),
                Err(_) => {
                    log.append_msg_from(Some(LOG_ORIGIN), "Failed to parse nlist.");
                    return Ok(());
                }
            }
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
        }
        let mut order: Vec<usize> = (0..self.nlist_list.len()).collect();
        order.sort_by_key(|&i| self.nlist_list[i].get_string_table_index());
        let string_table_offset = self.start_index as i64 + self.strings_offset as i64;
        for i in order {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            self.nlist_list[i].init_string(&nlist_reader, string_table_offset);
        }
        Ok(())
    }

    fn parse_local_symbols(&mut self, log: &MessageLog, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        monitor.set_message("Parsing DYLD local symbol entries...");
        monitor.initialize(self.entries_count as i64);
        self.reader.set_pointer_index(self.start_index.wrapping_add(self.entries_offset as i64 as u64));
        for _ in 0..self.entries_count {
            match DyldCacheLocalSymbolsEntry::new(&mut self.reader, self.use64bit_offsets) {
                Ok(e) => self.local_symbols_entry_list.push(e),
                Err(_) => {
                    log.append_msg_from(Some(LOG_ORIGIN), "Failed to parse dyld_cache_local_symbols_entry.");
                    return Ok(());
                }
            }
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
        }
        Ok(())
    }

    /// Lays `items` down consecutively from `start`; `Err(())` on any data-creation failure.
    fn create_sequence<'a, T: StructConverter + 'a>(
        program: &dyn Program,
        start: &Address,
        items: impl Iterator<Item = &'a T>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Result<(), ()>, CancelledException> {
        let mut addr = start.clone();
        for item in items {
            let Ok(dt) = item.to_data_type() else { return Ok(Err(())) };
            let created = program.get_listing().ok_or(()).and_then(|mut l| l.create_data(addr.clone(), dt).map_err(|_| ()));
            let Ok(d) = created else { return Ok(Err(())) };
            let Ok(next) = addr.add(d.get_length() as i64) else { return Ok(Err(())) };
            addr = next;
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
        }
        Ok(Ok(()))
    }

    fn markup_nlist(
        &self,
        program: &dyn Program,
        local_symbols_info_addr: &Address,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD local symbol nlists...");
        monitor.initialize(self.nlist_count as i64);
        let ok = match local_symbols_info_addr.add(self.nlist_offset as i64) {
            Ok(addr) => Self::create_sequence(program, &addr, self.nlist_list.iter(), monitor)?,
            Err(_) => Err(()),
        };
        if ok.is_err() {
            log.append_msg_from(Some(LOG_ORIGIN), "Failed to markup nlist.");
        }
        Ok(())
    }

    fn markup_local_symbols(
        &self,
        program: &dyn Program,
        local_symbols_info_addr: &Address,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) -> Result<(), CancelledException> {
        monitor.set_message("Marking up DYLD local symbol entries...");
        monitor.initialize(self.entries_count as i64);
        let ok = match local_symbols_info_addr.add(self.entries_offset as i64) {
            Ok(addr) => Self::create_sequence(program, &addr, self.local_symbols_entry_list.iter(), monitor)?,
            Err(_) => Err(()),
        };
        if ok.is_err() {
            log.append_msg_from(Some(LOG_ORIGIN), "Failed to markup dyld_cache_local_symbols_entry.");
        }
        Ok(())
    }
}

impl StructConverter for DyldCacheLocalSymbolsInfo {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::n_list::test_support::nlist;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::util::task::DummyMonitor;

    #[test]
    fn parses_nlists_and_entries_relative_to_start() {
        let mut b = Bytes::new(true);
        b.pad_to(0x10);
        // header at 0x10: nlist @+0x18 (2), strings @+0x38 (8 bytes), entries @+0x40 (1)
        b.u32(0x18).u32(2).u32(0x38).u32(8).u32(0x40).u32(1);
        nlist(&mut b, false, 1, 0x0e, 1, 0, 0x100);
        nlist(&mut b, false, 4, 0x0e, 1, 0, 0x200);
        b.raw(b"\0_a\0_bb\0");
        b.u64(0x5000).u32(0).u32(2);
        let mut r = BinaryReader::from_bytes(b.buf, true);
        r.set_pointer_index(0x10);
        let arch = DyldArchitecture::X86_64;
        let mut info = DyldCacheLocalSymbolsInfo::new(&r, &arch, true).unwrap();
        let log = MessageLog::new();
        info.parse(&log, &DummyMonitor).unwrap();
        assert!(!log.has_messages(), "{:?}", log.messages());
        let names: Vec<&str> = info.get_nlist().iter().map(NList::get_string).collect();
        assert_eq!(names, ["_a", "_bb"]);
        assert_eq!(info.get_local_symbols_entries()[0].get_dylib_offset(), 0x5000);
        assert_eq!(info.get_nlist_for(0x5000).len(), 2);
        assert!(info.get_nlist_for(0x6000).is_empty());
        assert_eq!(info.to_structure().unwrap().get_length(), 24);
    }
}
