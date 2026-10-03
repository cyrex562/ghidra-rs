//! Port of `ghidra.app.util.bin.format.macho.commands.dyld.AbstractClassicProcessor`.
//!
//! Shared state and helpers for the "classic" (pre-`LC_DYLD_INFO`) bind processors
//! ([`ClassicBindProcessor`](super::classic_bind_processor::ClassicBindProcessor) and
//! [`ClassicLazyBindProcessor`](super::classic_lazy_bind_processor::ClassicLazyBindProcessor)).
//!
//! The Java abstract class declares no abstract methods; it only carries the `header`/`program`
//! fields and concrete helpers. Per the shape rules it becomes a plain struct that each concrete
//! processor embeds (composition over inheritance).
//!
//! The header and program are borrowed for the processor's lifetime, matching Java, where the
//! processor is a short-lived object constructed and immediately `process`ed by the loader.

use std::error::Error;
use std::sync::Arc;

use crate::format::macho::commands::dynamic_library_command::DynamicLibraryCommand;
use crate::format::macho::commands::n_list::NList;
use crate::format::macho::commands::n_list_constants::{
    DYNAMIC_LOOKUP_ORDINAL, EXECUTABLE_ORDINAL, SELF_LIBRARY_ORDINAL,
};
use crate::format::macho::commands::segment_command::SegmentCommand;
use crate::format::macho::cpu_types::{CPU_TYPE_ARM, CPU_TYPE_POWERPC, CPU_TYPE_X86, CPU_TYPE_X86_64};
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::mach_header_file_types::{
    MH_BUNDLE, MH_DYLIB, MH_DYLINKER, MH_EXECUTE, MH_KEXT_BUNDLE, MH_OBJECT,
};
use crate::format::macho::mach_header_flags::MH_SPLIT_SEGS;
use crate::format::macho::section::Section;
use crate::program::model::listing::bookmark_type;
use crate::program::model::listing::comment_type::CommentType;
use crate::program::model::listing::program::Program;
use crate::program::model::reloc::relocation::RelocationStatus;
use crate::program::model::symbol::Symbol;
use crate::util::task::TaskMonitor;

/// Error type for the classic processors. Java declares `throws Exception`.
pub type ClassicProcessorError = Box<dyn Error + Send + Sync>;

/// Port of `ghidra.app.util.bin.format.macho.commands.dyld.AbstractClassicProcessor`.
pub struct AbstractClassicProcessor<'a> {
    pub(crate) header: &'a MachHeader,
    pub(crate) program: &'a dyn Program,
}

impl<'a> AbstractClassicProcessor<'a> {
    /// Java `AbstractClassicProcessor(MachHeader, Program)`.
    pub fn new(header: &'a MachHeader, program: &'a dyn Program) -> Self {
        AbstractClassicProcessor { header, program }
    }

    /// Java `perform(String, String, long, String, NList, boolean, TaskMonitor)`: writes the
    /// resolved address of `n_list`'s symbol into the pointer at `address_value`, labels the
    /// symbol with a plate comment naming its dylib, and records a relocation (applied or not).
    #[allow(clippy::too_many_arguments)]
    pub fn perform(
        &self,
        segment_name: &str,
        section_name: &str,
        address_value: i64,
        from_dylib: &str,
        n_list: &NList,
        is_weak: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ClassicProcessorError> {
        let _ = (segment_name, section_name, is_weak);
        monitor.set_message(&format!("Performing bind: {}", n_list.get_string()));

        let program = self.program;
        let big_endian = program
            .get_language()
            .map(|l| l.is_big_endian())
            .or_else(|| program.get_memory().map(|m| m.is_big_endian()))
            .unwrap_or(false);
        let space = program
            .get_address_factory()
            .and_then(|f| f.get_default_address_space())
            .ok_or("program has no default address space")?;
        let address = space.address(address_value);

        let Some(symbol) = self.get_symbol(n_list) else {
            return Ok(());
        };

        if let Some(mut listing) = program.get_listing() {
            listing.set_comment(&symbol.get_address(), CommentType::Plate, Some(from_dylib.to_string()));
        }

        let offset = symbol.get_address().offset();
        let file_type = self.header.get_file_type();
        let pointer_size_8 = program.get_default_pointer_size() == 8;
        let pointer_bytes = || -> Vec<u8> {
            match (pointer_size_8, big_endian) {
                (true, true) => offset.to_be_bytes().to_vec(),
                (true, false) => offset.to_le_bytes().to_vec(),
                (false, true) => (offset as i32).to_be_bytes().to_vec(),
                (false, false) => (offset as i32).to_le_bytes().to_vec(),
            }
        };

        let mut byte_length = 0usize;
        match file_type as u32 {
            MH_EXECUTE | MH_DYLIB | MH_BUNDLE | MH_DYLINKER | MH_OBJECT => {
                let bytes = pointer_bytes();
                self.set_bytes(&address, &bytes)?;
                byte_length = bytes.len();
            }
            MH_KEXT_BUNDLE => {
                let cpu = self.header.get_cpu_type();
                if cpu == CPU_TYPE_X86 || cpu == CPU_TYPE_X86_64 {
                    let memory = program.get_memory().ok_or("program has no memory")?;
                    let block = memory
                        .get_block(&address)
                        .ok_or_else(|| format!("no memory block at {address}"))?;
                    if block.is_execute() {
                        // Then we must be fixing up code...
                        let instruction_byte = memory.get_byte(&address.subtract_wrap(1))?;
                        // Relative 32-bit call / relative 32-bit jump.
                        if instruction_byte == 0xe8 || instruction_byte == 0xe9 {
                            let difference = offset.wrapping_sub(address_value).wrapping_sub(4);
                            let d = difference as i32;
                            let bytes =
                                if big_endian { d.to_be_bytes() } else { d.to_le_bytes() };
                            self.set_bytes(&address, &bytes)?;
                            byte_length = bytes.len();
                        }
                    } else {
                        let bytes = pointer_bytes();
                        self.set_bytes(&address, &bytes)?;
                        byte_length = bytes.len();
                    }
                } else if cpu == CPU_TYPE_POWERPC || cpu == CPU_TYPE_ARM {
                    // TODO in Java too: PowerPC / iOS ARM kext files are not fixed up.
                }
            }
            _ => {}
        }

        let status = if byte_length == 0 {
            if let Some(mut bookmarks) = program.get_bookmark_manager_mut() {
                bookmarks.set_bookmark(
                    address.clone(),
                    bookmark_type::ERROR,
                    "Unhandled Classic Binding",
                    "Unable to fixup classic binding. This instruction will contain an invalid destination / fixup.",
                );
            }
            RelocationStatus::Unsupported
        } else {
            RelocationStatus::Applied
        };

        // Put an entry in the relocation table, handled or not.
        if let Some(mut relocations) = program.get_relocation_table() {
            relocations.add_with_byte_length(
                address,
                status,
                file_type,
                Vec::new(),
                byte_length as i32,
                Some(symbol.get_name().to_string()),
            );
        }
        Ok(())
    }

    fn set_bytes(
        &self,
        address: &crate::program::model::address::Address,
        bytes: &[u8],
    ) -> Result<(), ClassicProcessorError> {
        let mut memory = self.program.get_memory_mut().ok_or("program has no memory")?;
        memory.set_bytes(address, bytes)?;
        Ok(())
    }

    /// Java `getSymbol(NList)`: the first symbol named like `n_list` (Java: "looks in the global
    /// namespace first" -- the symbol table's by-name lookup order).
    pub fn get_symbol(&self, n_list: &NList) -> Option<Arc<dyn Symbol>> {
        let symbol_table = self.program.get_symbol_table()?;
        symbol_table.get_symbols_by_name(n_list.get_string()).ok()?.into_iter().next()
    }

    /// Java `getSectionName(long)`: the section containing `address`, if any.
    pub fn get_section_name(&self, address: i64) -> Option<&'a Section> {
        self.header
            .get_all_sections()
            .into_iter()
            .find(|s| s.get_address() <= address && address < s.get_address() + s.get_size())
    }

    /// Java `getClassicOrdinalName(int)`.
    pub fn get_classic_ordinal_name(&self, library_ordinal: i32) -> String {
        match library_ordinal {
            o if o == SELF_LIBRARY_ORDINAL as i32 => return "this-image".to_string(),
            o if o == EXECUTABLE_ORDINAL as i32 => return "main-executable".to_string(),
            o if o == DYNAMIC_LOOKUP_ORDINAL as i32 => return "flat-namespace".to_string(),
            _ => {}
        }
        let dylib_commands = self.header.get_load_commands_of::<DynamicLibraryCommand>();
        if library_ordinal < 0 || library_ordinal as usize >= dylib_commands.len() {
            // Java only checks the upper bound (a negative ordinal would throw); report both.
            return format!("dyld info library ordinal out of range{:x}", library_ordinal);
        }
        dylib_commands[library_ordinal as usize]
            .get_dynamic_library()
            .get_name()
            .get_string()
            .to_string()
    }

    /// Java `getRelocationBase()`: for 64-bit programs with `MH_SPLIT_SEGS`, the VM address of
    /// the first writable segment; otherwise the first segment's VM address. `None` stands in for
    /// Java's `IndexOutOfBoundsException` when the header has no segments.
    pub fn get_relocation_base(&self) -> Option<i64> {
        let segments = self.header.get_load_commands_of::<SegmentCommand>();
        if self.program.get_default_pointer_size() == 8
            && (self.header.get_flags() as u32 & MH_SPLIT_SEGS) != 0
        {
            if let Some(seg) = segments.iter().find(|s| s.is_write()) {
                return Some(seg.get_vm_address());
            }
        }
        segments.first().map(|s| s.get_vm_address())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A small mock program for the classic processor tests: real-ish memory, a by-name symbol
    //! table, and a recording relocation table (no listing / bookmark manager).

    use std::collections::HashMap;
    use std::io;
    use std::sync::{Arc, RwLock};

    use crate::framework::model::DomainObject;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::{ManagerCell, ManagerGuard};
    use crate::program::model::mem::memory::Memory;
    use crate::program::model::mem::memory_access_exception::MemoryAccessException;
    use crate::program::model::reloc::relocation::{Relocation, RelocationStatus};
    use crate::program::model::reloc::relocation_table::RelocationTable;
    use crate::program::model::symbol::source_type::SourceType;
    use crate::program::model::symbol::symbol_type::SymbolType;
    use crate::program::model::symbol::{Symbol, SymbolTable};

    /// A parsed 64-bit little-endian x86-64 `MH_EXECUTE` exercising the classic bind paths:
    ///
    /// * `__DATA` segment @0x1000 with `__nl_symbol_ptr` (@0x1000, 0x10 bytes, indirect 0) and
    ///   `__la_symbol_ptr` (@0x1010, 8 bytes, indirect 2);
    /// * `LC_SYMTAB`: `_malloc` (ordinal 1), `_free` (ordinal 1, weak ref);
    /// * `LC_DYSYMTAB`: indirect symbols `[0, INDIRECT_SYMBOL_LOCAL, 1]`, one external relocation
    ///   at segment offset 8 against symbol 1;
    /// * `LC_LOAD_DYLIB` `libSystem.B`.
    pub(crate) fn classic_image() -> crate::format::macho::mach_header::MachHeader {
        use crate::format::macho::commands::load_command_types::{
            LC_DYSYMTAB, LC_LOAD_DYLIB, LC_SEGMENT_64, LC_SYMTAB,
        };
        use crate::format::macho::mach_constants::MH_MAGIC_64;
        use crate::format::macho::mach_header::test_support::{provider, Bytes};
        let mut b = Bytes::new(true);
        let seg_len = 72 + 2 * 80;
        let sizeofcmds = seg_len + 24 + 80 + 40;
        b.u32(MH_MAGIC_64).u32(0x0100_0007).u32(3).u32(2).u32(4).u32(sizeofcmds).u32(0).u32(0);
        b.u32(LC_SEGMENT_64).u32(seg_len).name("__DATA", 16);
        b.u64(0x1000).u64(0x1000).u64(0).u64(0).u32(3).u32(3).u32(2).u32(0);
        for (name, addr, size, flags, reserved1) in
            [("__nl_symbol_ptr", 0x1000u64, 0x10u64, 6u32, 0u32), ("__la_symbol_ptr", 0x1010, 8, 7, 2)]
        {
            b.name(name, 16).name("__DATA", 16).u64(addr).u64(size);
            b.u32(0).u32(3).u32(0).u32(0).u32(flags).u32(reserved1).u32(0).u32(0);
        }
        b.u32(LC_SYMTAB).u32(24).u32(0x200).u32(2).u32(0x220).u32(15);
        b.u32(LC_DYSYMTAB).u32(80);
        for v in [0u32, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0x240, 3, 0x250, 1, 0, 0] {
            b.u32(v);
        }
        b.u32(LC_LOAD_DYLIB).u32(40).u32(24).u32(0).u32(0x10000).u32(0x10000).name("libSystem.B", 16);
        b.pad_to(0x200);
        // nlist_64[0] "_malloc", nlist_64[1] "_free" (N_WEAK_REF)
        b.u32(1).u8(1).u8(0).u16(0x0100).u64(0);
        b.u32(9).u8(1).u8(0).u16(0x0140).u64(0);
        b.pad_to(0x220).raw(b"\0_malloc\0_free\0");
        b.pad_to(0x240).u32(0).u32(0x8000_0000).u32(1);
        // relocation_info: r_address 8; symbolnum 1, length 3, extern
        b.pad_to(0x250).u32(8).u32(1 | (3 << 25) | (1 << 27));
        b.pad_to(0x300);
        let mut h = crate::format::macho::mach_header::MachHeader::new(provider(b.buf)).unwrap();
        h.parse().unwrap();
        h
    }

    /// A parsed 64-bit `nlist_64` named `name` with description `desc`.
    pub(crate) fn nlist(name: &str, desc: u16) -> crate::format::macho::commands::n_list::NList {
        use crate::app::util::bin::binary_reader::BinaryReader;
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes()); // n_strx
        b.push(0x01); // n_type: N_EXT | N_UNDF
        b.push(0); // n_sect
        b.extend_from_slice(&desc.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.push(0);
        b.extend_from_slice(name.as_bytes());
        b.push(0);
        let mut reader = BinaryReader::from_bytes(b, true);
        let mut n = crate::format::macho::commands::n_list::NList::new(&mut reader, false).unwrap();
        n.init_string(&reader, 16);
        n
    }

    pub(crate) struct SharedMemory {
        pub(crate) bytes: Arc<RwLock<Vec<u8>>>,
    }

    impl Memory for SharedMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.bytes
                .read()
                .unwrap()
                .get(addr.offset() as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let off = addr.offset() as usize;
            let buf = self.bytes.read().unwrap();
            if off >= buf.len() {
                return 0;
            }
            let n = (buf.len() - off).min(dest.len());
            dest[..n].copy_from_slice(&buf[off..off + n]);
            n
        }
        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let off = addr.offset() as usize;
            let mut buf = self.bytes.write().unwrap();
            if off + source.len() > buf.len() {
                return Err(MemoryAccessException::new("out of bounds"));
            }
            buf[off..off + source.len()].copy_from_slice(source);
            Ok(())
        }
    }

    pub(crate) struct TestSymbol {
        pub(crate) name: String,
        pub(crate) addr: Address,
    }

    impl Symbol for TestSymbol {
        fn get_address(&self) -> Address {
            self.addr.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Imported
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    pub(crate) struct ByNameSymbolTable {
        pub(crate) symbols: HashMap<String, Address>,
    }

    impl SymbolTable for ByNameSymbolTable {
        fn create_label(&mut self, _a: &Address, _n: &str, _s: SourceType) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!()
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
        fn get_symbols_by_name(&self, name: &str) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self
                .symbols
                .get(name)
                .map(|a| vec![Arc::new(TestSymbol { name: name.to_string(), addr: a.clone() }) as Arc<dyn Symbol>])
                .unwrap_or_default())
        }
    }

    #[derive(Default)]
    pub(crate) struct RecordingRelocationTable {
        pub(crate) relocations: Vec<Relocation>,
    }

    impl RelocationTable for RecordingRelocationTable {
        fn add(
            &mut self,
            addr: Address,
            status: RelocationStatus,
            type_: i32,
            values: Vec<i64>,
            bytes: Option<Vec<u8>>,
            symbol_name: Option<String>,
        ) -> Relocation {
            let r = Relocation::new(addr, status, type_, values, bytes, symbol_name);
            self.relocations.push(r.clone());
            r
        }
        fn add_with_byte_length(
            &mut self,
            addr: Address,
            status: RelocationStatus,
            type_: i32,
            values: Vec<i64>,
            byte_length: i32,
            symbol_name: Option<String>,
        ) -> Relocation {
            let bytes = (byte_length > 0).then(|| vec![0u8; byte_length as usize]);
            self.add(addr, status, type_, values, bytes, symbol_name)
        }
        fn get_relocations(&self, addr: &Address) -> Vec<Relocation> {
            self.relocations.iter().filter(|r| r.address() == addr).cloned().collect()
        }
        fn has_relocation(&self, addr: &Address) -> bool {
            self.relocations.iter().any(|r| r.address() == addr)
        }
        fn relocation_iter(&self) -> Box<dyn Iterator<Item = Relocation>> {
            Box::new(self.relocations.clone().into_iter())
        }
        fn relocation_iter_in(
            &self,
            _set: &dyn crate::program::model::address::AddressSetView,
        ) -> Box<dyn Iterator<Item = Relocation>> {
            Box::new(std::iter::empty())
        }
        fn get_relocation_address_after(&self, _addr: &Address) -> Option<Address> {
            None
        }
        fn get_size(&self) -> i32 {
            self.relocations.len() as i32
        }
        fn is_relocatable(&self) -> bool {
            true
        }
    }

    pub(crate) struct MockProgram {
        pub(crate) bytes: Arc<RwLock<Vec<u8>>>,
        pub(crate) memory: ManagerCell<SharedMemory>,
        pub(crate) memory_shared: Arc<SharedMemory>,
        pub(crate) space: Arc<AddressSpace>,
        pub(crate) pointer_size: i32,
        pub(crate) symbols: ManagerCell<ByNameSymbolTable>,
        pub(crate) relocations: ManagerCell<RecordingRelocationTable>,
    }

    impl MockProgram {
        pub(crate) fn new(len: usize, pointer_size: i32, symbols: &[(&str, i64)]) -> Self {
            let bytes = Arc::new(RwLock::new(vec![0u8; len]));
            let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
            let symbols = symbols
                .iter()
                .map(|(n, a)| (n.to_string(), Address::new(space.clone(), *a)))
                .collect();
            MockProgram {
                memory: ManagerCell::new(SharedMemory { bytes: bytes.clone() }),
                memory_shared: Arc::new(SharedMemory { bytes: bytes.clone() }),
                bytes,
                space,
                pointer_size,
                symbols: ManagerCell::new(ByNameSymbolTable { symbols }),
                relocations: ManagerCell::new(RecordingRelocationTable::default()),
            }
        }

        pub(crate) fn read(&self, off: usize, len: usize) -> Vec<u8> {
            self.bytes.read().unwrap()[off..off + len].to_vec()
        }

        pub(crate) fn relocations(&self) -> Vec<(i64, RelocationStatus, Option<String>)> {
            self.relocations
                .lock()
                .relocations
                .iter()
                .map(|r| (r.address().offset(), r.status(), r.symbol_name().map(str::to_string)))
                .collect()
        }
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory_shared.clone() as Arc<dyn Memory>)
        }
        fn get_memory_mut(&self) -> Option<ManagerGuard<'_, dyn Memory>> {
            Some(ManagerGuard::lock(&self.memory))
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(Arc::new(DefaultAddressFactory::new(vec![self.space.clone()])) as Arc<dyn AddressFactory>)
        }
        fn get_default_pointer_size(&self) -> i32 {
            self.pointer_size
        }
        fn get_symbol_table(&self) -> Option<ManagerGuard<'_, dyn SymbolTable>> {
            Some(ManagerGuard::lock(&self.symbols))
        }
        fn get_relocation_table(&self) -> Option<ManagerGuard<'_, dyn RelocationTable>> {
            Some(ManagerGuard::lock(&self.relocations))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{nlist, MockProgram};
    use super::*;
    use crate::format::macho::mach_header::test_support::empty_header64;
    use crate::program::model::listing::program::Program as _;
    use crate::util::task::DummyMonitor;

    #[test]
    fn perform_writes_little_endian_pointer_and_records_applied_relocation() {
        let header = empty_header64(); // MH_EXECUTE, x86-64
        let program = MockProgram::new(0x40, 8, &[("_printf", 0x1122_3344_5566)]);
        let p = AbstractClassicProcessor::new(&header, &program);
        let n = nlist("_printf", 0);
        p.perform("__DATA", "__nl_symbol_ptr", 0x10, "libc", &n, false, &DummyMonitor).unwrap();
        assert_eq!(program.read(0x10, 8), 0x1122_3344_5566i64.to_le_bytes());
        assert_eq!(
            program.relocations(),
            vec![(0x10, RelocationStatus::Applied, Some("_printf".to_string()))]
        );
    }

    #[test]
    fn perform_32bit_writes_four_bytes() {
        let header = empty_header64();
        let program = MockProgram::new(0x40, 4, &[("_f", 0xAABBCCDD)]);
        let p = AbstractClassicProcessor::new(&header, &program);
        p.perform("", "", 0x8, "x", &nlist("_f", 0), false, &DummyMonitor).unwrap();
        assert_eq!(program.read(0x8, 4), 0xAABBCCDDu32.to_le_bytes());
        assert_eq!(program.read(0xC, 4), [0, 0, 0, 0]);
    }

    #[test]
    fn perform_without_symbol_does_nothing() {
        let header = empty_header64();
        let program = MockProgram::new(0x40, 8, &[]);
        let p = AbstractClassicProcessor::new(&header, &program);
        p.perform("", "", 0x8, "x", &nlist("_missing", 0), false, &DummyMonitor).unwrap();
        assert!(program.relocations().is_empty());
        assert_eq!(program.read(0x8, 8), [0u8; 8]);
    }

    #[test]
    fn classic_ordinal_names() {
        let header = empty_header64();
        let program = MockProgram::new(0, 8, &[]);
        let p = AbstractClassicProcessor::new(&header, &program);
        assert_eq!(p.get_classic_ordinal_name(0), "this-image");
        assert_eq!(p.get_classic_ordinal_name(0xff), "main-executable");
        assert_eq!(p.get_classic_ordinal_name(0xfe), "flat-namespace");
        assert_eq!(p.get_classic_ordinal_name(0x1a), "dyld info library ordinal out of range1a");
        assert!(p.get_relocation_base().is_none());
        assert!(p.get_section_name(0).is_none());
        let _ = program.get_default_pointer_size();
    }
}
