//! Port of `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedFixups`.
//!
//! A statics-only Java holder class (chained-fixup walking/patching helpers plus the
//! `RELOCATION_TYPE` constant); ported here as free functions and a constant rather than a
//! type, since Rust needs no class to hang statics off of.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::macho::dyld::dyld_chained_ptr::DyldChainType;
use crate::format::macho::dyld::dyld_fixup::DyldFixup;
use crate::format::seam_stubs::{
    DyldChainedImports, MachoProgramBuilder, MemoryBlockUtils, MessageLog,
};
use crate::program::model::address::Address;
use crate::program::model::listing::library;
use crate::program::model::listing::Program;
use crate::program::model::reloc::relocation::RelocationStatus;
use crate::program::model::symbol::symbol_utilities::{DefaultSymbolUtilities, SymbolUtilities};
use crate::program::model::symbol::{SourceType, SymbolTable};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// `DyldChainedFixups.RELOCATION_TYPE`: the fabricated relocation type used to record chained
/// fixups in the program's relocation table.
pub const RELOCATION_TYPE: i32 = 0x8888;

/// The error union for `getChainedFixups`/`processPointerChain`, which declare
/// `throws IOException, CancelledException` in Java.
#[derive(Debug)]
pub enum ChainedFixupError {
    Io(io::Error),
    Cancelled(CancelledException),
}

impl std::fmt::Display for ChainedFixupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainedFixupError::Io(e) => write!(f, "{e}"),
            ChainedFixupError::Cancelled(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ChainedFixupError {}

impl From<io::Error> for ChainedFixupError {
    fn from(e: io::Error) -> Self {
        ChainedFixupError::Io(e)
    }
}

impl From<CancelledException> for ChainedFixupError {
    fn from(e: CancelledException) -> Self {
        ChainedFixupError::Cancelled(e)
    }
}

/// Walks the chained fixup information and collects a list of [`DyldFixup`]s that will need to
/// be applied to the image.
///
/// Port of `DyldChainedFixups.getChainedFixups`.
///
/// * `reader` - can read the image
/// * `chained_imports` - chained imports (may be `None`)
/// * `pointer_format` - format of pointers within this chain
/// * `page` - within data pages that has pointers to be unchained
/// * `next_off` - offset within the page that is the chain start
/// * `auth_value_add` - value to be added to each chain pointer
/// * `imagebase` - the image base
/// * `symbol_table` - the symbol table, or `None` if not available
/// * `log` - the log
/// * `monitor` - a cancellable monitor
#[allow(clippy::too_many_arguments)]
pub fn get_chained_fixups(
    reader: &dyn BinaryReader,
    chained_imports: Option<&dyn DyldChainedImports>,
    pointer_format: DyldChainType,
    page: i64,
    next_off: i64,
    auth_value_add: i64,
    imagebase: i64,
    symbol_table: Option<&dyn SymbolTable>,
    log: &dyn MessageLog,
    monitor: &dyn TaskMonitor,
) -> Result<Vec<DyldFixup>, ChainedFixupError> {
    let mut fixups = Vec::new();

    let mut next: i64 = -1;
    let mut next_off = next_off;
    while next != 0 {
        monitor.check_cancelled()?;

        let chain_loc = page.wrapping_add(next_off);
        let chain_value = pointer_format.chain_value(reader, chain_loc as u64)?;
        let new_chain_value: Option<i64>;
        let is_authenticated = pointer_format.is_authenticated(chain_value);
        let is_bound = pointer_format.is_bound(chain_value);
        let mut symbol: Option<String> = None;
        let mut lib_ordinal: Option<i32> = None;

        if is_bound {
            let chained_imports = match chained_imports {
                Some(ci) => ci,
                None => {
                    log.append_msg(&format!(
                        "Error: dyld_chained_import array required to process bound chain fixup at {chain_loc}"
                    ));
                    return Ok(Vec::new());
                }
            };
            let symbol_table = match symbol_table {
                Some(st) => st,
                None => {
                    log.append_msg(&format!(
                        "Error: symbol table required to process bound chain fixup at {chain_loc}"
                    ));
                    return Ok(Vec::new());
                }
            };
            let chain_ordinal = pointer_format.ordinal(chain_value) as i32;
            let addend = pointer_format.addend(chain_value);
            let chained_import = chained_imports.get_chained_import(chain_ordinal);
            let sym_name = DefaultSymbolUtilities
                .replace_invalid_chars(Some(&chained_import.get_name()), true)
                .unwrap_or_default();
            lib_ordinal = Some(chained_import.get_lib_ordinal());
            let global_symbols = symbol_table.get_global_symbols(&sym_name)?;
            symbol = Some(sym_name);
            if let Some(first) = global_symbols.first() {
                let mut value = first.get_address().offset();
                value = value.wrapping_add(if is_authenticated { auth_value_add } else { addend });
                new_chain_value = Some(value);
            } else {
                new_chain_value = None;
            }
        } else if is_authenticated {
            new_chain_value = Some(
                imagebase
                    .wrapping_add(pointer_format.target(chain_value))
                    .wrapping_add(auth_value_add),
            );
        } else {
            let mut value = pointer_format.target(chain_value);
            if pointer_format.is_relative() {
                value = value.wrapping_add(imagebase);
            }
            new_chain_value = Some(value);
        }

        fixups.push(DyldFixup::new(
            chain_loc,
            new_chain_value,
            pointer_format.size(),
            symbol,
            lib_ordinal,
        ));

        next = pointer_format.next(chain_value);
        next_off = next_off.wrapping_add(next.wrapping_mul(pointer_format.stride()));
    }
    Ok(fixups)
}

/// Fixes up the program's chained pointers.
///
/// Port of `DyldChainedFixups.fixupChainedPointers`.
///
/// * `fixups` - the fixups
/// * `program` - the program
/// * `imagebase` - the image base
/// * `library_paths` - library paths
/// * `log` - the log
/// * `monitor` - a cancellable monitor
/// * `memory_block_utils` - seam for the not-yet-ported `MemoryBlockUtils`
/// * `macho_program_builder` - seam for the not-yet-ported `MachoProgramBuilder`
///
/// Returns the list of fixed-up addresses.
#[allow(clippy::too_many_arguments)]
pub fn fixup_chained_pointers(
    fixups: &[DyldFixup],
    program: &mut dyn Program,
    imagebase: &Address,
    library_paths: &[String],
    log: &dyn MessageLog,
    monitor: &dyn TaskMonitor,
    memory_block_utils: &dyn MemoryBlockUtils,
    macho_program_builder: &dyn MachoProgramBuilder,
) -> Result<Vec<Address>, CancelledException> {
    if fixups.is_empty() {
        return Ok(Vec::new());
    }

    // Figure out how much space in the EXTERNAL block we need, and make it.
    let external_size: i64 = fixups
        .iter()
        .filter(|f| f.value.is_none() && f.symbol.is_some() && f.lib_ordinal.is_some())
        .map(|f| f.size as i64)
        .sum();
    let mut ext_addr: Option<Address> = None;
    if external_size > 0 {
        match memory_block_utils.add_external_block(program, external_size, log) {
            Ok(addr) => ext_addr = Some(addr),
            Err(e) => log.append_msg(&format!(
                "Failed to create space in EXTERNAL block for chained fixups: {e}"
            )),
        }
    }

    let mut fixed_addrs = Vec::new();
    monitor.initialize(fixups.len() as i64);
    monitor.set_message("Fixing up chained pointers...");
    for fixup in fixups {
        monitor.check_cancelled()?;
        monitor.increment_progress(1);

        let mut status = RelocationStatus::Unsupported;
        let fixup_addr = imagebase
            .add(fixup.offset)
            .expect("fixup offset exceeds address space");
        let mut fixup_value = fixup.value;
        let fixup_symbol = fixup.symbol.clone();
        let mut value: Vec<i64> = Vec::new();

        // Mirrors the Java `try { ... } catch (Exception e) { status = FAILURE; }`: any error
        // aborts the remaining work for this fixup (the symbol/lib-ordinal fixup below is only
        // reached if everything before it succeeded).
        let result: Result<(), String> = (|| {
            if fixup_value.is_none() && fixup_symbol.is_some() && fixup.lib_ordinal.is_some() {
                if let Some(addr) = ext_addr.clone() {
                    let sym = fixup_symbol.as_deref().unwrap();
                    let step: io::Result<()> = (|| {
                        if let Some(st) = program.get_symbol_table() {
                            st.create_label(&addr, sym, SourceType::Imported)?;
                        }
                        fixup_value = Some(addr.offset());
                        if let Some(mut stub_func) =
                            macho_program_builder.create_one_byte_function(program, sym, &addr)
                        {
                            if let Some(ext_mgr) = program.get_external_manager() {
                                if let Ok(mut loc) = ext_mgr.add_ext_location_in_library(
                                    library::UNKNOWN,
                                    Some(sym),
                                    None,
                                    SourceType::Imported,
                                ) {
                                    let created = Arc::get_mut(&mut loc)
                                        .expect("freshly created external location is uniquely owned")
                                        .create_function();
                                    let _ = stub_func.set_thunked_function(Some(created));
                                }
                            }
                        }
                        Ok(())
                    })();
                    ext_addr = Some(
                        addr.add(fixup.size as i64).expect("ext addr exceeds address space"),
                    );
                    step.map_err(|e| e.to_string())?;
                }
            }

            if let Some(v) = fixup_value {
                if fixup.size == 8 || fixup.size == 4 {
                    let mem = program.get_memory_mut().ok_or_else(|| "no memory".to_string())?;
                    let bytes: Vec<u8> = if mem.is_big_endian() {
                        if fixup.size == 8 {
                            v.to_be_bytes().to_vec()
                        } else {
                            (v as i32).to_be_bytes().to_vec()
                        }
                    } else if fixup.size == 8 {
                        v.to_le_bytes().to_vec()
                    } else {
                        (v as i32).to_le_bytes().to_vec()
                    };
                    mem.set_bytes(&fixup_addr, &bytes).map_err(|e| e.to_string())?;
                    fixed_addrs.push(fixup_addr.clone());
                    status = RelocationStatus::Applied;
                }
                value = vec![v];
            }

            if let (Some(sym), Some(lib_ordinal)) = (fixup_symbol.as_deref(), fixup.lib_ordinal) {
                value = vec![lib_ordinal as i64];
                if let Err(e) = macho_program_builder.fixup_external_library(
                    program,
                    library_paths,
                    lib_ordinal,
                    sym,
                ) {
                    log.append_msg(&format!("WARNING: Problem fixing up symbol '{sym}' - {e}"));
                }
            }
            Ok(())
        })();

        if result.is_err() {
            status = RelocationStatus::Failure;
        }

        if let Some(rt) = program.get_relocation_table() {
            rt.add_with_byte_length(
                fixup_addr,
                status,
                RELOCATION_TYPE,
                value,
                fixup.size,
                fixup_symbol,
            );
        }
    }
    log.append_msg(&format!("Fixed up {} chained pointers.", fixed_addrs.len()));
    Ok(fixed_addrs)
}

//---------------------Below are used only by handled __thread_starts-------------------------

/// Fixes up any chained pointers, starting at the given address.
///
/// Port of `DyldChainedFixups.processPointerChain`.
///
/// * `reader` - can read the image
/// * `chain_start` - the starting address of the pointer chain to fix
/// * `next_off_size` - the size of the next offset
/// * `imagebase` - the image base
/// * `log` - the log
/// * `monitor` - a cancellable monitor
///
/// Returns the fixups performed.
pub fn process_pointer_chain(
    reader: &dyn BinaryReader,
    chain_start: i64,
    next_off_size: i64,
    imagebase: i64,
    _log: &dyn MessageLog,
    monitor: &dyn TaskMonitor,
) -> Result<Vec<DyldFixup>, ChainedFixupError> {
    const BIT63: i64 = 0x1i64 << 63;
    const BIT62: i64 = 0x1i64 << 62;

    let mut fixups = Vec::new();
    let mut chain_start = chain_start;

    loop {
        monitor.check_cancelled()?;

        let chain_value = reader.read_long(chain_start as u64)?;
        let fixed_pointer_value;

        // Bad chain value
        if (chain_value & BIT62) != 0 {
            // this is a pointer, but is good now
        }

        // Pointer checked value
        if (chain_value & BIT63) != 0 {
            fixed_pointer_value = imagebase.wrapping_add(chain_value & 0xffffffffi64);
        } else {
            fixed_pointer_value = ((chain_value << 13) & 0xff000_0000_0000_000u64 as i64)
                | (chain_value & 0x7ff_ffff_ffffi64);
            let fixed_pointer_value = if (chain_value & 0x0400_0000_0000i64) != 0 {
                fixed_pointer_value | 0x00ff_fc00_0000_0000u64 as i64
            } else {
                fixed_pointer_value
            };
            fixups.push(DyldFixup::new(chain_start, Some(fixed_pointer_value), 8, None, None));

            let next_value_off = ((chain_value >> 51) & 0x7ff).wrapping_mul(next_off_size);
            if next_value_off == 0 {
                break;
            }
            chain_start = chain_start.wrapping_add(next_value_off);
            continue;
        }

        fixups.push(DyldFixup::new(chain_start, Some(fixed_pointer_value), 8, None, None));

        let next_value_off = ((chain_value >> 51) & 0x7ff).wrapping_mul(next_off_size);
        if next_value_off == 0 {
            break;
        }
        chain_start = chain_start.wrapping_add(next_value_off);
    }

    Ok(fixups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::seam_stubs::DyldChainedImport;
    use crate::program::model::symbol::Symbol;
    use crate::util::task::DummyMonitor;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                provider: Rc::new(RefCell::new(VecProvider(bytes))),
                index: 0,
                little_endian: true,
            }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(TestReader {
                provider: Rc::clone(&self.provider),
                index: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    struct TestLog;

    impl MessageLog for TestLog {
        fn copy_from(&self, _log: &dyn MessageLog) {}
        fn append_msg(&self, _message: &str) {}
        fn append_exception(&self, _t: &dyn crate::format::seam_stubs::Throwable) {}
        fn error(&self, _originator: &str, _message: &str) {}
        fn has_messages(&self) -> bool {
            false
        }
        fn clear(&self) {}
        fn set_status(&self, _status: &str) {}
        fn clear_status(&self) {}
        fn get_status(&self) -> String {
            String::new()
        }
        fn to_string(&self) -> String {
            String::new()
        }
        fn write(&self, _owner: &dyn crate::format::seam_stubs::Class, _message_header: &str) {}
    }

    fn le_long(v: i64) -> [u8; 8] {
        v.to_le_bytes()
    }

    #[test]
    fn relocation_type_constant() {
        assert_eq!(RELOCATION_TYPE, 0x8888);
    }

    #[test]
    fn get_chained_fixups_unbound_ptr64_rebase() {
        // A single Ptr64 chain entry with target=0x1000, next=0 (end of chain).
        let chain_value: i64 = 0x1000;
        let reader = TestReader::new(le_long(chain_value).to_vec());
        let log = TestLog;
        let monitor = DummyMonitor;

        let fixups = get_chained_fixups(
            &reader,
            None,
            DyldChainType::Ptr64,
            0,
            0,
            0,
            0x1_0000_0000,
            None,
            &log,
            &monitor,
        )
        .expect("no error");

        assert_eq!(fixups.len(), 1);
        assert_eq!(fixups[0].offset, 0);
        assert_eq!(fixups[0].value, Some(0x1000));
        assert_eq!(fixups[0].size, 8);
        assert!(fixups[0].symbol.is_none());
    }

    #[test]
    fn get_chained_fixups_relative_target_adds_imagebase() {
        let chain_value: i64 = 0x2000;
        let reader = TestReader::new(le_long(chain_value).to_vec());
        let log = TestLog;
        let monitor = DummyMonitor;

        let fixups = get_chained_fixups(
            &reader,
            None,
            DyldChainType::Ptr64Offset,
            0,
            0,
            0,
            0x1_0000_0000,
            None,
            &log,
            &monitor,
        )
        .expect("no error");

        assert_eq!(fixups.len(), 1);
        assert_eq!(fixups[0].value, Some(0x1_0000_2000));
    }

    #[test]
    fn get_chained_fixups_bound_without_imports_logs_and_returns_empty() {
        // Ptr64 bind bit (bit 63) set.
        let chain_value: i64 = 1i64 << 63;
        let reader = TestReader::new(le_long(chain_value).to_vec());
        let log = TestLog;
        let monitor = DummyMonitor;

        let fixups = get_chained_fixups(
            &reader,
            None,
            DyldChainType::Ptr64,
            0,
            0,
            0,
            0,
            None,
            &log,
            &monitor,
        )
        .expect("no error");

        assert!(fixups.is_empty());
    }

    struct StubSymbol {
        addr: Address,
    }

    impl Symbol for StubSymbol {
        fn get_address(&self) -> Address {
            self.addr.clone()
        }
        fn get_name(&self) -> &str {
            "_stub"
        }
        fn get_symbol_type(&self) -> crate::program::model::symbol::symbol_type::SymbolType {
            crate::program::model::symbol::symbol_type::SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Imported
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
        fn is_external(&self) -> bool {
            false
        }
        fn as_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
        fn get_containing_memory_block_name(&self) -> Option<String> {
            None
        }
        fn get_parent_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn as_variable(&self) -> Option<Arc<dyn crate::program::model::listing::Variable>> {
            None
        }
        fn as_function(&self) -> Option<Arc<dyn crate::program::model::listing::Function>> {
            None
        }
        fn is_dynamic(&self) -> bool {
            false
        }
        fn set_namespace(
            &mut self,
            _namespace: Arc<dyn crate::program::model::symbol::Namespace>,
        ) -> Result<(), crate::program::model::symbol::SetParentNamespaceError> {
            Ok(())
        }
    }

    struct StubImport {
        name: String,
        lib_ordinal: i32,
    }

    impl DyldChainedImport for StubImport {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_lib_ordinal(&self) -> i32 {
            self.lib_ordinal
        }
    }

    struct StubImports;

    impl DyldChainedImports for StubImports {
        fn get_chained_import(&self, _ordinal: i32) -> Box<dyn DyldChainedImport> {
            Box::new(StubImport { name: "_bound_symbol".to_string(), lib_ordinal: 2 })
        }
    }

    struct StubSymbolTable {
        addr: Address,
    }

    impl SymbolTable for StubSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!()
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
        fn get_global_symbols(&self, name: &str) -> io::Result<Vec<Arc<dyn Symbol>>> {
            if name == "_bound_symbol" {
                Ok(vec![Arc::new(StubSymbol { addr: self.addr.clone() })])
            } else {
                Ok(Vec::new())
            }
        }
    }

    fn test_address_space() -> Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        )
    }

    #[test]
    fn get_chained_fixups_bound_resolves_via_symbol_table() {
        let chain_value: i64 = (1i64 << 63) | 5; // bound, ordinal 5
        let reader = TestReader::new(le_long(chain_value).to_vec());
        let log = TestLog;
        let monitor = DummyMonitor;
        let space = test_address_space();
        let symtab = StubSymbolTable { addr: Address::new(space, 0x4000) };
        let imports = StubImports;

        let fixups = get_chained_fixups(
            &reader,
            Some(&imports),
            DyldChainType::Ptr64,
            0,
            0,
            0x10,
            0,
            Some(&symtab),
            &log,
            &monitor,
        )
        .expect("no error");

        assert_eq!(fixups.len(), 1);
        assert_eq!(fixups[0].symbol.as_deref(), Some("_bound_symbol"));
        assert_eq!(fixups[0].lib_ordinal, Some(2));
        // Not authenticated -> addend (0, since bind field is 0 here) is added to the resolved
        // symbol address.
        assert_eq!(fixups[0].value, Some(0x4000));
    }

    #[test]
    fn process_pointer_chain_single_entry_high_bit_set() {
        // BIT63 set: fixedPointerValue = imagebase + (chainValue & 0xffffffff).
        let chain_value: i64 = (1i64 << 63) | 0x2000;
        let reader = TestReader::new(le_long(chain_value).to_vec());
        let log = TestLog;
        let monitor = DummyMonitor;

        let fixups =
            process_pointer_chain(&reader, 0, 8, 0x1_0000_0000, &log, &monitor).expect("no error");

        assert_eq!(fixups.len(), 1);
        assert_eq!(fixups[0].offset, 0);
        assert_eq!(fixups[0].value, Some(0x1_0000_2000));
        assert_eq!(fixups[0].size, 8);
    }

    #[test]
    fn process_pointer_chain_stops_when_next_offset_is_zero() {
        let chain_value: i64 = (1i64 << 63) | 0x42;
        let reader = TestReader::new(le_long(chain_value).to_vec());
        let log = TestLog;
        let monitor = DummyMonitor;

        let fixups = process_pointer_chain(&reader, 0, 8, 0, &log, &monitor).expect("no error");
        assert_eq!(fixups.len(), 1);
    }
}
