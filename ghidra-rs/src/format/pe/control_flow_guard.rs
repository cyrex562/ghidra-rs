//! Port of `ghidra.app.util.bin.format.pe.ControlFlowGuard`.
//!
//! ControlFlowGuard is a platform security feature that was created to combat memory corruption
//! vulnerabilities. ReturnFlowGuard was introduced as an addition to ControlFlowGuard in the
//! Windows 10 Creator's update.
//!
//! Per `scripts/shape_rules.py`, this Java class has no instance state and no instance methods
//! (only `public static final String` fields and `static` helper methods), so it ports as a
//! plain module of `pub const`s and free `pub fn`s rather than a zero-field struct.
//!
//! Several helpers here (`markup_cfg_function_table`, `markup_cfg_address_taken_iat_entry_table`)
//! bottom out on forward references that are not fully ported yet:
//! [`CreateArrayCmd`](crate::app::seam_stubs::CreateArrayCmd) (already stubbed for
//! `AbstractFrameSectionBase`'s use, and reused here) drops its `DataType` argument and always
//! reports success without touching the `Listing`, and
//! [`AbstractProgramLoader`](crate::app::seam_stubs::AbstractProgramLoader)'s `mark_as_function`
//! is a true no-op -- both pending `Listing`/`FunctionManager` mutation support for a bare `&mut
//! dyn Program`. The padding half of the CFG table entry type additionally needs a concrete
//! `ByteDataType` singleton, which does not exist yet (`ByteDataType` is still a trait -- see
//! `crate::program::model::data::byte_data_type`'s module docs). Everything else (address/label
//! computation, memory reads, symbol creation) is a faithful port.

use crate::app::seam_stubs::{AbstractProgramLoader, CreateArrayCmd};
use crate::format::pe::load_config_directory::{GuardFlags, LoadConfigDirectory};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::seam_stubs::{NTHeader, OptionalHeader, PeUtils};
use crate::program::model::address::Address;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::ibo32_data_type::IBO32DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::program::Program;
use crate::program::model::symbol::source_type::SourceType;

/// Port of `ControlFlowGuard.GuardCFFunctionTableName`.
pub const GUARD_CF_FUNCTION_TABLE_NAME: &str = "GuardCFFunctionTable";
/// Port of `ControlFlowGuard.GuardCFAddressTakenIatTableName`.
pub const GUARD_CF_ADDRESS_TAKEN_IAT_TABLE_NAME: &str = "GuardCFAddressTakenIatTable";
/// Port of `ControlFlowGuard.GuardCfgTableEntryName`.
pub const GUARD_CFG_TABLE_ENTRY_NAME: &str = "GuardCfgTableEntry";

/// Port of `ControlFlowGuard.markup(LoadConfigDirectory, Program, MessageLog, NTHeader)`.
///
/// Java passes each function-pointer accessor as a `Supplier<Long>` so `markupCfgFunction` can
/// re-read it lazily; since these are pure getters with no side effects, the already-read `i64`
/// value is passed directly here instead, which is behaviorally identical.
pub fn markup(
    lcd: &LoadConfigDirectory,
    program: &mut dyn Program,
    log: &MessageLog,
    nt_header: &dyn NTHeader,
) {
    // ControlFlowGuard.
    markup_cfg_function(
        "_guard_check_icall",
        "ControlFlowGuard check",
        lcd.get_cfg_check_function_pointer(),
        program,
        nt_header,
        log,
    );
    markup_cfg_function(
        "_guard_dispatch_icall",
        "ControlFlowGuard dispatch",
        lcd.get_cfg_dispatch_function_pointer(),
        program,
        nt_header,
        log,
    );
    markup_cfg_function_table(lcd, program, log);
    markup_cfg_address_taken_iat_entry_table(lcd, program, log);

    // ReturnFlowGuard.
    markup_cfg_function(
        "_guard_ss_verify_failure",
        "ReturnFlowGuard failure",
        lcd.get_rfg_failure_routine(),
        program,
        nt_header,
        log,
    );
    markup_cfg_function(
        "_guard_ss_verify_failure_default",
        "ReturnFlowGuard default failure",
        lcd.get_rfg_failure_routine_function_pointer(),
        program,
        nt_header,
        log,
    );
    markup_cfg_function(
        "_guard_ss_verify_sp_default",
        "ReturnFlowGuard verify stack pointer",
        lcd.get_rfg_verify_stack_pointer_function_pointer(),
        program,
        nt_header,
        log,
    );
}

/// Port of the private `ControlFlowGuard.markupCfgFunctionTable(LoadConfigDirectory, Program,
/// MessageLog)`.
///
/// Java looks up (and caches) a previously-registered `GuardCfgTableEntryName` structure in the
/// program's `DataTypeManager` before building a new one; that lookup returns a `Box<dyn
/// DataType>` in this port (not a concrete, further-mutable `StructureDataTypeImpl`), so instead
/// of downcasting, a fresh structure is built every call. Functionally equivalent (the two would
/// be `isEquivalent`), just without the caching.
fn markup_cfg_function_table(lcd: &LoadConfigDirectory, program: &mut dyn Program, log: &MessageLog) {
    const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: i32 = 0xf000_0000u32 as i32;
    const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: i32 = 28;

    let table_pointer = lcd.get_cfg_function_table_pointer();
    let function_count = lcd.get_cfg_function_count();
    if table_pointer == 0 || function_count <= 0 {
        return;
    }

    let Some(space) = program.get_address_factory().and_then(|f| f.get_default_address_space()) else {
        return;
    };
    let table_addr = Address::new(space, table_pointer);

    // Label the start of the table.
    if let Some(symbol_table) = program.get_symbol_table() {
        if let Err(e) = symbol_table.create_label(&table_addr, GUARD_CF_FUNCTION_TABLE_NAME, SourceType::Imported) {
            log.append_msg(&format!("Unable to label ControlFlowGuard function table: {e}"));
        }
    }

    // Each table entry is an RVA (32-bit image base offset), followed by 'n' extra bytes.
    let guard_flags: &GuardFlags = match lcd.get_cfg_guard_flags() {
        Some(gf) => gf,
        None => return,
    };
    let n = (guard_flags.get_flags() & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
        >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;

    let category_path = CategoryPath::new(ROOT.clone(), &["CFG"]).expect("static path is valid");
    let mut entry_type =
        StructureDataTypeImpl::new_in_category(category_path, GUARD_CFG_TABLE_ENTRY_NAME, 0);
    entry_type.set_packing_enabled(false);
    let _ = entry_type.add_with_name(Box::new(IBO32DataType::new()), Some("Offset".to_string()), Some(String::new()));
    if n > 0 {
        // Java pads with `n` extra bytes via `new ArrayDataType(ByteDataType.dataType, n /
        // byteType.getLength(), byteType.getLength())`. `ByteDataType` has no concrete,
        // instantiable singleton in this crate yet (still a trait -- see
        // `crate::program::model::data::byte_data_type`), so the padding cannot be added yet.
        log.append_msg(
            "ControlFlowGuard: CFG table entry padding is not yet supported (ByteDataType is \
             not ported to a concrete instantiable form)",
        );
    }

    let entry_len = entry_type.get_length();
    // `CreateArrayCmd` (see `crate::app::seam_stubs`) drops its `DataType` argument entirely, so
    // `entry_type` itself is not passed through -- only the length Java's `applyTo` would have
    // used to size each array element.
    let cmd = CreateArrayCmd::new(table_addr.clone(), function_count as i32, entry_len, 1);
    cmd.apply_to(program);

    let table_data = program.get_listing().and_then(|listing| listing.get_data_at(&table_addr));
    create_cfg_functions(program, table_data.as_deref(), log);
}

/// Port of the private `ControlFlowGuard.createCfgFunctions(Program, Data, MessageLog)`.
fn create_cfg_functions(program: &mut dyn Program, table_data: Option<&dyn Data>, log: &MessageLog) {
    let Some(table_data) = table_data else {
        log.append_msg("Couldn't find Control Flow Guard tables.");
        return;
    };

    if !table_data.is_array() || table_data.get_num_components() < 1 {
        log.append_msg("Control Flow Guard table seems to be empty.");
        return;
    }

    for target in get_function_addresses_from_table(table_data) {
        let already_defined = program
            .get_listing()
            .and_then(|listing| listing.get_defined_data_at(&target))
            .is_some();
        if !already_defined {
            AbstractProgramLoader::mark_as_function(program, &target);
        } else {
            log.append_msg(&format!(
                "Unable to mark Control Flow Guard function at {target}. Data is already defined there."
            ));
        }
    }
}

/// Port of the private `ControlFlowGuard.getFunctionAddressesFromTable(Program, Data)`.
fn get_function_addresses_from_table(table: &dyn Data) -> Vec<Address> {
    let mut list = Vec::new();
    for i in 0..table.get_num_components() {
        let Some(entry) = table.get_component(i) else { continue };
        let Some(ibo_data) = entry.get_component(0) else { continue };
        if let Some(value) = Data::get_value(ibo_data.as_ref()) {
            if let Some(addr) = value.downcast_ref::<Address>() {
                list.push(addr.clone());
            }
        }
    }
    list
}

/// Port of the private `ControlFlowGuard.markupCfgAddressTakenIatEntryTable(LoadConfigDirectory,
/// Program, MessageLog)`.
fn markup_cfg_address_taken_iat_entry_table(lcd: &LoadConfigDirectory, program: &mut dyn Program, log: &MessageLog) {
    let table_pointer = lcd.get_guard_address_iat_table_table_pointer();
    let function_count = lcd.get_guard_address_iat_table_count();
    if table_pointer == 0 || function_count <= 0 {
        return;
    }

    let Some(space) = program.get_address_factory().and_then(|f| f.get_default_address_space()) else {
        return;
    };
    let table_addr = Address::new(space, table_pointer);

    if let Some(symbol_table) = program.get_symbol_table() {
        if let Err(e) =
            symbol_table.create_label(&table_addr, GUARD_CF_ADDRESS_TAKEN_IAT_TABLE_NAME, SourceType::Imported)
        {
            log.append_msg(&format!("Unable to label ControlFlowGuard IAT table: {e}"));
            return;
        }
    }

    // Each table entry is an RVA (32-bit image base offset).
    let ibo32 = IBO32DataType::new();
    let ibo32_len = ibo32.get_length() as i64;
    for i in 0..function_count {
        let Ok(entry_addr) = table_addr.add(i * ibo32_len) else {
            break;
        };
        if PeUtils::create_data(program, &entry_addr, &ibo32, log).is_err() {
            // If we failed to create data on a table entry, just assume the rest will fail.
            break;
        }
    }
}

/// Port of the private `ControlFlowGuard.markupCfgFunction(String, String, Supplier<Long>,
/// Program, NTHeader, MessageLog)`.
fn markup_cfg_function(
    label: &str,
    description: &str,
    function_pointer: i64,
    program: &mut dyn Program,
    nt_header: &dyn NTHeader,
    log: &MessageLog,
) {
    if function_pointer == 0 {
        return;
    }

    let Some(space) = program.get_address_factory().and_then(|f| f.get_default_address_space()) else {
        return;
    };
    let is64bit: bool = nt_header.get_optional_header().is64bit();

    let function_pointer_addr = Address::new(space.clone(), function_pointer);
    // Java: `PeUtils.createData(program, functionPointerAddr, PointerDataType.dataType, log)`.
    // `PointerDataType` has no concrete singleton yet (still a trait -- see
    // `crate::program::model::data::pointer_data_type`), and `PeUtils::create_data` ignores its
    // `data_type` argument entirely (see `crate::format::seam_stubs::PeUtils`) until `Listing`
    // mutation is wired up, so any concrete stand-in has the same (currently no-op) effect.
    let _ = PeUtils::create_data(program, &function_pointer_addr, &IBO32DataType::new(), log);

    let function_addr = {
        let Some(memory) = program.get_memory() else {
            log.append_msg(&format!(
                "Failed to read {description} function pointer address at {function_pointer_addr}"
            ));
            return;
        };
        let read = if is64bit {
            read_i64(memory.as_ref(), &function_pointer_addr)
        } else {
            read_i32(memory.as_ref(), &function_pointer_addr).map(|v| v as i64)
        };
        match read {
            Some(v) => Address::new(space, v),
            None => {
                log.append_msg(&format!(
                    "Failed to read {description} function pointer address at {function_pointer_addr}"
                ));
                return;
            }
        }
    };

    if let Some(symbol_table) = program.get_symbol_table() {
        if let Err(e) = symbol_table.create_label(&function_addr, label, SourceType::Imported) {
            log.append_msg(&format!(
                "Unable to apply label '{label}' to {description} function at {function_addr}: {e}"
            ));
        }
    }

    let already_defined =
        program.get_listing().and_then(|listing| listing.get_defined_data_at(&function_addr)).is_some();
    if !already_defined {
        AbstractProgramLoader::mark_as_function(program, &function_addr);
    } else {
        log.append_msg(&format!(
            "Unable to mark {description} as function at {function_addr}. Data is already defined there."
        ));
    }
}

/// Reads a little/big-endian (per `Memory::is_big_endian`) 4-byte signed int at `addr`, standing
/// in for `Memory.getInt(Address)`.
fn read_i32(memory: &dyn crate::program::model::mem::Memory, addr: &Address) -> Option<i32> {
    let mut buf = [0u8; 4];
    if memory.get_bytes(addr, &mut buf) != 4 {
        return None;
    }
    Some(if memory.is_big_endian() { i32::from_be_bytes(buf) } else { i32::from_le_bytes(buf) })
}

/// Reads a little/big-endian (per `Memory::is_big_endian`) 8-byte signed long at `addr`, standing
/// in for `Memory.getLong(Address)`.
fn read_i64(memory: &dyn crate::program::model::mem::Memory, addr: &Address) -> Option<i64> {
    let mut buf = [0u8; 8];
    if memory.get_bytes(addr, &mut buf) != 8 {
        return None;
    }
    Some(if memory.is_big_endian() { i64::from_be_bytes(buf) } else { i64::from_le_bytes(buf) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::format::pe::file_header::FileHeader;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::listing::Listing;
    use crate::program::model::listing::program::Program as ProgramTrait;
    use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock};
    use crate::program::model::symbol::source_type::SourceType as RealSourceType;
    use crate::program::model::symbol::{Symbol, SymbolTable, SymbolType};

    struct FixtureOptionalHeader {
        is64: bool,
    }
    impl OptionalHeader for FixtureOptionalHeader {
        fn get_size_of_image(&self) -> i64 {
            0
        }
        fn get_image_base(&self) -> i64 {
            0
        }
        fn is64bit(&self) -> bool {
            self.is64
        }
    }

    /// Minimal `BinaryReader` used only to construct a fixture [`FileHeader`] below -- this
    /// module's own tests otherwise never need to read bytes through a `BinaryReader`.
    struct MinimalReader {
        bytes: Vec<u8>,
        current_index: u64,
    }
    impl BinaryReader for MinimalReader {
        fn length(&self) -> std::io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&self, index: u64) -> bool {
            index < self.bytes.len() as u64
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> std::io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + n_elements;
            if end > self.bytes.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(self.bytes[start..end].to_vec())
        }
        fn get_byte_provider(
            &self,
        ) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::GByteStore>> {
            unimplemented!("not needed by these fixtures")
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MinimalReader { bytes: self.bytes.clone(), current_index: new_index })
        }
    }

    /// Builds a real [`FileHeader`] for test fixtures (machine = `IMAGE_FILE_MACHINE_I386`,
    /// everything else zeroed), parsed via a throwaway `NTHeader` that skips symbol table
    /// parsing.
    fn build_file_header() -> FileHeader {
        struct DummyNtForConstruction;
        impl NTHeader for DummyNtForConstruction {
            fn get_name(&self) -> String {
                unimplemented!()
            }
            fn is_rva_resoltion_section_aligned(&self) -> bool {
                true
            }
            fn get_file_header(&self) -> &FileHeader {
                unimplemented!()
            }
            fn get_optional_header(&self) -> Box<dyn OptionalHeader> {
                unimplemented!()
            }
            fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
                unimplemented!()
            }
            fn rva_to_pointer(&self, _rva: i32) -> i32 {
                unimplemented!()
            }
            fn rva_to_pointer_long(&self, _rva: i64) -> i64 {
                unimplemented!()
            }
            fn check_pointer(&self, _ptr: i64) -> bool {
                unimplemented!()
            }
            fn check_rva(&self, _rva: i64) -> bool {
                unimplemented!()
            }
            fn va_to_pointer(&self, _va: i32) -> i32 {
                unimplemented!()
            }
        }

        let mut bytes = 0x014ci16.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 18]);
        let mut reader = MinimalReader { bytes, current_index: 0 };
        FileHeader::new(&mut reader, 0, &DummyNtForConstruction).unwrap()
    }

    struct FixtureNtHeader {
        is64: bool,
        file_header: FileHeader,
    }
    impl FixtureNtHeader {
        fn new(is64: bool) -> Self {
            FixtureNtHeader { is64, file_header: build_file_header() }
        }
    }
    impl NTHeader for FixtureNtHeader {
        fn get_name(&self) -> String {
            "NT".to_string()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            true
        }
        fn get_file_header(&self) -> &FileHeader {
            &self.file_header
        }
        fn get_optional_header(&self) -> Box<dyn OptionalHeader> {
            Box::new(FixtureOptionalHeader { is64: self.is64 })
        }
        fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
            unimplemented!()
        }
        fn rva_to_pointer(&self, rva: i32) -> i32 {
            rva
        }
        fn rva_to_pointer_long(&self, rva: i64) -> i64 {
            rva
        }
        fn check_pointer(&self, _ptr: i64) -> bool {
            true
        }
        fn check_rva(&self, _rva: i64) -> bool {
            true
        }
        fn va_to_pointer(&self, va: i32) -> i32 {
            va
        }
    }

    /// A single-block, read-only memory fixture over one contiguous byte range.
    struct FixtureMemory {
        start: Address,
        data: Vec<u8>,
    }
    impl Memory for FixtureMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let offset = addr.subtract(&self.start);
            if offset < 0 {
                return Err(MemoryAccessException::new("out of bounds"));
            }
            self.data.get(offset as usize).copied().ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let offset = addr.subtract(&self.start);
            if offset < 0 {
                return 0;
            }
            let offset = offset as usize;
            let available = self.data.len().saturating_sub(offset);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.data[offset..offset + n]);
            n
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not needed by these tests")
        }
    }

    struct MockSymbol {
        address: Address,
        name: String,
    }
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> RealSourceType {
            RealSourceType::Imported
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct RecordingSymbolTable {
        created_labels: Arc<Mutex<Vec<(Address, String)>>>,
    }
    impl SymbolTable for RecordingSymbolTable {
        fn create_label(
            &mut self,
            addr: &Address,
            name: &str,
            _source: RealSourceType,
        ) -> std::io::Result<Arc<dyn Symbol>> {
            self.created_labels.lock().unwrap().push((addr.clone(), name.to_string()));
            Ok(Arc::new(MockSymbol { address: addr.clone(), name: name.to_string() }))
        }
        fn get_symbol(&self, _id: i64) -> std::io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, _addr: &Address) -> std::io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
    }

    struct TestProgram {
        address_factory: Arc<dyn crate::program::model::address::AddressFactory>,
        memory: Arc<dyn Memory>,
        symbol_table: RecordingSymbolTable,
    }
    impl crate::framework::model::DomainObject for TestProgram {}
    impl ProgramTrait for TestProgram {
        fn get_name(&self) -> String {
            "control_flow_guard_test".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
            Some(self.address_factory.clone())
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            Some(&mut self.symbol_table)
        }
        fn get_listing(&mut self) -> Option<&mut dyn Listing> {
            None
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn markup_cfg_function_zero_pointer_is_a_no_op() {
        let space = ram_space();
        let factory = Arc::new(crate::program::model::address::factory::DefaultAddressFactory::new(vec![
            space.clone(),
        ]));
        let mut program = TestProgram {
            address_factory: factory,
            memory: Arc::new(FixtureMemory { start: Address::new(space, 0), data: vec![] }),
            symbol_table: RecordingSymbolTable { created_labels: Arc::new(Mutex::new(Vec::new())) },
        };
        let log = MessageLog::new();
        let nt = FixtureNtHeader::new(false);

        markup_cfg_function("label", "desc", 0, &mut program, &nt, &log);

        assert!(program.symbol_table.created_labels.lock().unwrap().is_empty());
        assert!(log.messages().is_empty());
    }

    #[test]
    fn markup_cfg_function_reads_pointer_and_labels_target_32bit() {
        let space = ram_space();
        // The function-pointer slot lives at RAM:0x2000 and holds the little-endian 4-byte
        // target address 0x3000 -- mirrors `mem.getInt(functionPointerAddr)` for a 32-bit image.
        let start = Address::new(space.clone(), 0x2000);
        let data = 0x3000u32.to_le_bytes().to_vec();
        let factory = Arc::new(crate::program::model::address::factory::DefaultAddressFactory::new(vec![
            space.clone(),
        ]));
        let created_labels = Arc::new(Mutex::new(Vec::new()));
        let mut program = TestProgram {
            address_factory: factory,
            memory: Arc::new(FixtureMemory { start, data }),
            symbol_table: RecordingSymbolTable { created_labels: created_labels.clone() },
        };
        let log = MessageLog::new();
        let nt = FixtureNtHeader::new(false);

        markup_cfg_function("_guard_check_icall", "ControlFlowGuard check", 0x2000, &mut program, &nt, &log);

        let labels = created_labels.lock().unwrap();
        assert_eq!(labels.len(), 1);
        let (addr, name) = &labels[0];
        assert_eq!(*addr, Address::new(space, 0x3000));
        assert_eq!(name, "_guard_check_icall");
        assert!(log.messages().is_empty());
    }

    #[test]
    fn markup_cfg_function_logs_when_memory_read_fails() {
        let space = ram_space();
        // No memory block covers the pointer slot, so the read fails.
        let start = Address::new(space.clone(), 0x9000);
        let factory = Arc::new(crate::program::model::address::factory::DefaultAddressFactory::new(vec![
            space.clone(),
        ]));
        let mut program = TestProgram {
            address_factory: factory,
            memory: Arc::new(FixtureMemory { start, data: vec![] }),
            symbol_table: RecordingSymbolTable { created_labels: Arc::new(Mutex::new(Vec::new())) },
        };
        let log = MessageLog::new();
        let nt = FixtureNtHeader::new(false);

        markup_cfg_function("label", "ControlFlowGuard check", 0x2000, &mut program, &nt, &log);

        assert!(program.symbol_table.created_labels.lock().unwrap().is_empty());
        assert_eq!(log.messages().len(), 1);
        assert!(log.messages()[0].contains("Failed to read"));
    }

    #[test]
    fn markup_table_functions_are_no_ops_below_threshold() {
        // A zero table pointer/count should return immediately without touching the symbol
        // table, for both the CFG function table and the address-taken IAT table.
        let lcd = LoadConfigDirectory::default();
        let space = ram_space();
        let factory = Arc::new(crate::program::model::address::factory::DefaultAddressFactory::new(vec![
            space.clone(),
        ]));
        let created_labels = Arc::new(Mutex::new(Vec::new()));
        let mut program = TestProgram {
            address_factory: factory,
            memory: Arc::new(FixtureMemory { start: Address::new(space, 0), data: vec![] }),
            symbol_table: RecordingSymbolTable { created_labels: created_labels.clone() },
        };
        let log = MessageLog::new();

        markup_cfg_function_table(&lcd, &mut program, &log);
        markup_cfg_address_taken_iat_entry_table(&lcd, &mut program, &log);

        assert!(created_labels.lock().unwrap().is_empty());
    }
}
