//! `ElfProgramBuilder` phase 2: symbol tables, the EXTERNAL block, entry points and imports.
//!
//! Ports `processSymbolTables` (and the `processSymbols`/`calculateSymbolAddress`/
//! `evaluateElfSymbol` chain under it), `allocateLinkageBlock` and the EXTERNAL block allocator,
//! `createSymbol`/`checkPrimary`, `processEntryPoints`/`createDynamicEntryPoints`/
//! `createEntryFunction`, `createOneByteFunction` and `processImports`.
//!
//! What these Java methods do that the ported `ProgramDB` has no manager for is logged once per
//! kind (see [`ElfProgramBuilder::phase2_unavailable`]) instead of being performed:
//!
//! * symbol table / string table markup and the `.gnu_debugdata` (xz-compressed) symbol tables,
//! * undefined data for sized object symbols (`allocateUndefinedSymbolData`) -- no listing,
//! * functions (`createOneByteFunction`), external thunks, the process-entry calling convention
//!   -- no function manager; entry points are still registered,
//! * equates for constant-space symbols -- no equate table,
//! * versioned-external PRE comments -- no listing; the versioned symbol still maps to its
//!   unversioned external's address, as in Java,
//! * the `DT_INIT_ARRAY`-style entry arrays -- `createData` needs a listing, and Java stops at
//!   the first element it cannot create data for,
//! * external library paths (`processImports`) -- no external manager.

use std::collections::HashMap;
use std::sync::Arc;

use super::{addr_str, truncated_word_address, ElfLoadError, ElfLoadable, ElfProgramBuilder, BLOCK_SOURCE_NAME};
use crate::app::util::opinion::elf_loader::ELF_ENTRY_FUNCTION_NAME;
use crate::app::util::opinion::elf_loader_options_factory as options_factory;
use crate::format::elf::elf_constants::GOT_SYMBOL_NAME;
use crate::format::elf::elf_dynamic_type::{self, ElfDynamicType};
use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_section_header_constants::{SHN_ABS, SHN_COMMON, SHN_LORESERVE, SHN_UNDEF, SHN_XINDEX};
use crate::format::elf::elf_symbol::{ElfSymbol, STT_FUNC, STT_OBJECT};
use crate::format::elf::elf_symbol_name_utils;
use crate::format::elf::elf_symbol_table::ElfSymbolTable;
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::{Address, AddressSet, AddressSpace};
use crate::program::model::listing::function::Function;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::memory_block::EXTERNAL_BLOCK_NAME;
use crate::program::model::symbol::{Namespace, SourceType, Symbol, SymbolType};
use crate::util::exception::InvalidInputException;
use crate::util::seam_stubs::NumericUtilities;
use crate::util::task::TaskMonitor;

/// Java's `nextExternalBlockEntryAddress`: `null` until the EXTERNAL block range is allocated,
/// `Address.NO_ADDRESS` once it is exhausted (or could not be allocated).
#[derive(Debug, Clone, Default)]
pub(super) enum NextExternalEntry {
    #[default]
    Unallocated,
    Exhausted,
    At(Address),
}

/// The EXTERNAL block allocator state (`externalBlockLimits`, `lastExternalBlockEntryAddress`,
/// `nextExternalBlockEntryAddress`).
#[derive(Debug, Default)]
pub(super) struct ExternalBlockState {
    limits: std::option::Option<AddressRange>,
    last_entry: std::option::Option<Address>,
    next_entry: NextExternalEntry,
}

/// What `calculateSymbolAddress` answers: `null`, `Address.NO_ADDRESS` or an address.
#[derive(Debug, Clone, PartialEq)]
enum SymbolAddress {
    /// Not supported / not determined: skip the symbol.
    Skip,
    /// External: allocate it in the EXTERNAL block.
    External,
    At(Address),
}

/// Java's `StringUtils.isBlank` for a nullable name.
fn is_blank(name: std::option::Option<&str>) -> bool {
    name.is_none_or(|n| n.trim().is_empty())
}

impl ElfProgramBuilder<'_> {
    /// Mirrors `processSymbolTables(TaskMonitor)`.
    pub(super) fn process_symbol_tables(&self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        monitor.set_message("Processing symbol tables...");

        // Mapped data/object symbol addresses with specific sizes
        let mut data_allocation_map: HashMap<Address, i32> = HashMap::new();

        if self.elf.get_section(".gnu_debugdata").ok().flatten().is_some() {
            self.phase2_unavailable(".gnu_debugdata symbol extraction");
        }
        let symbol_tables: Vec<Arc<ElfSymbolTable>> = self.elf.get_symbol_tables().to_vec();

        let total_count: i64 = symbol_tables.iter().map(|t| t.get_symbol_count() as i64).sum();
        monitor.initialize(total_count);

        for elf_symbol_table in &symbol_tables {
            monitor.check_cancelled()?;
            // markupSymbolTable needs a listing
            self.process_symbols(elf_symbol_table, &mut data_allocation_map, monitor)?;
        }

        // create an artificial block for the external symbols
        self.create_external_block();

        // create undefined data code units for symbols
        self.allocate_undefined_symbol_data(&data_allocation_map);
        Ok(())
    }

    /// Mirrors `allocateUndefinedSymbolData(HashMap)`.
    fn allocate_undefined_symbol_data(&self, data_allocation_map: &HashMap<Address, i32>) {
        if !options_factory::apply_undefined_symbol_data(self.options) || data_allocation_map.is_empty() {
            return;
        }
        self.phase2_unavailable("undefined symbol data");
    }

    /// Mirrors `processSymbols(ElfSymbol[], HashMap, TaskMonitor)`.
    fn process_symbols(
        &self,
        symbol_table: &ElfSymbolTable,
        data_allocation_map: &mut HashMap<Address, i32>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ElfLoadError> {
        for elf_symbol in symbol_table.get_symbols() {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);

            if let Err(msg) = self.process_symbol(symbol_table, elf_symbol, data_allocation_map) {
                self.log(&format!("Error creating symbol: {} - {msg}", elf_symbol.get_formatted_name()));
            }
        }
        Ok(())
    }

    /// The body of `processSymbols`' loop; an `Err` is the message of the exception Java catches.
    fn process_symbol(
        &self,
        symbol_table: &ElfSymbolTable,
        elf_symbol: &ElfSymbol,
        data_allocation_map: &mut HashMap<Address, i32>,
    ) -> Result<(), String> {
        let mut address = match self.calculate_symbol_address(symbol_table, elf_symbol) {
            SymbolAddress::Skip => return Ok(()),
            SymbolAddress::External => None,
            SymbolAddress::At(a) => Some(a),
        };

        let sym_name = elf_symbol.get_name_as_string();

        // NO_ADDRESS signifies external symbol to be allocated to EXTERNAL block
        let mut using_fake_external = false;
        if address.is_none() {
            if sym_name == Some(GOT_SYMBOL_NAME) {
                // Do not assign GOT symbol to the EXTERNAL block.
                // This is likely an object module which is not fully linked.
                return Ok(());
            }
            if is_blank(sym_name) {
                return Ok(());
            }
            // check for @<version> or @@<version>
            if self.process_versioned_external(elf_symbol) {
                return Ok(());
            }
            // check if external symbol previously defined and re-use it
            if self.process_duplicate_external(elf_symbol) {
                return Ok(());
            }
            address = Some(self.allocate_external_symbol(elf_symbol)?);
            using_fake_external = true;
        }
        let address = address.expect("assigned above");

        if elf_symbol.is_object() && address.is_memory_address() {
            let size = elf_symbol.get_size() as i64;
            if size > 0 && size < i32::MAX as i64 {
                data_allocation_map.insert(address.clone(), size as i32);
            }
        }

        self.evaluate_elf_symbol(elf_symbol, address, using_fake_external)
            .map_err(|e| e.to_string())
    }

    /// Mirrors `calculateSymbolAddress(ElfSymbol)`.
    fn calculate_symbol_address(&self, symbol_table: &ElfSymbolTable, elf_symbol: &ElfSymbol) -> SymbolAddress {
        if elf_symbol.get_symbol_table_index() == 0 {
            return SymbolAddress::Skip; // always skip the first symbol, it is NULL
        }
        if elf_symbol.is_file() {
            return SymbolAddress::Skip; // do not create file symbols
        }
        if elf_symbol.is_tls() {
            self.log(&format!("Unsupported Thread-Local Symbol not loaded: {}", elf_symbol.get_formatted_name()));
            return SymbolAddress::Skip;
        }

        let load_adapter = self.elf.get_load_adapter();

        // Allow extension to have first shot at calculating symbol address
        match load_adapter.calculate_symbol_address(self, elf_symbol) {
            Ok(Some(address)) => return SymbolAddress::At(address),
            Ok(None) => {}
            Err(_) => return SymbolAddress::Skip,
        }

        let section_index = elf_symbol.get_section_header_index();
        let Some(default_space) = self.get_default_address_space() else {
            return SymbolAddress::Skip;
        };
        let default_data_space = self.get_default_data_space();
        let mut symbol_space = Arc::clone(&default_space);
        let mut sym_offset = elf_symbol.get_value() as i64;
        let value_hex = format!("{:x}", elf_symbol.get_value());

        let mut is_allocated_to_section = false;
        if section_index == SHN_UNDEF {
            // Not section relative 0x0000 (e.g., no sections defined)
            if let Some(reg_addr) = self.find_memory_register(elf_symbol) {
                return SymbolAddress::At(reg_addr);
            }
            // No sections defined or refers to external symbol. The EXTERNAL block is affected by
            // the program image base.
            sym_offset = load_adapter.get_adjusted_memory_offset(sym_offset, &default_space);
            sym_offset = sym_offset.wrapping_add(self.get_image_base_word_adjustment_offset());
        } else if section_index < SHN_LORESERVE || section_index == SHN_XINDEX {
            is_allocated_to_section = true;
            let mut u_section_index = section_index as usize;

            if section_index == SHN_XINDEX {
                let extended = elf_symbol.get_extended_section_header_index(symbol_table);
                if extended == 0 {
                    self.log(&format!(
                        "Failed to read extended symbol section index: {} - value=0x{value_hex}",
                        elf_symbol.get_formatted_name()
                    ));
                    return SymbolAddress::Skip;
                }
                u_section_index = extended as u32 as usize;
            }

            let sections = self.elf.get_sections();
            if u_section_index < sections.len() {
                let sym_section = &sections[u_section_index];
                let Some(sym_section_base) = self.find_load_address_for(ElfLoadable::Section(u_section_index), 0) else {
                    self.log(&format!(
                        "Unable to place symbol due to non-loaded section: {} - value=0x{value_hex}, section={}",
                        elf_symbol.get_formatted_name(),
                        sym_section.get_name_as_string()
                    ));
                    return SymbolAddress::Skip;
                };
                symbol_space = Arc::clone(sym_section_base.space());

                if let Some(rel_offset) =
                    load_adapter.get_section_symbol_relative_offset(sym_section, &sym_section_base, elf_symbol)
                {
                    // Section relative symbol
                    let unit = sym_section_base.space().unit_size() as i64;
                    return match sym_section_base.add_no_wrap(rel_offset.wrapping_mul(unit)) {
                        Ok(a) => SymbolAddress::At(a),
                        Err(_) => {
                            self.log(&format!(
                                "Unable to place symbol within section (address overflow): {} - value=0x{value_hex}, section={}",
                                elf_symbol.get_formatted_name(),
                                sym_section.get_name_as_string()
                            ));
                            SymbolAddress::Skip
                        }
                    };
                }
            } else if self.elf.is_relocatable() {
                // Unable to place symbol within relocatable if section missing/stripped
                self.log(&format!(
                    "No Memory for symbol: {} - 0x{value_hex}",
                    elf_symbol.get_formatted_name()
                ));
                return SymbolAddress::Skip;
            }

            // overlay spaces are not created (module docs), so the space is its own physical space
            let space = Arc::clone(&symbol_space);
            sym_offset = load_adapter.get_adjusted_memory_offset(sym_offset, &space);
            if space == default_space {
                sym_offset = self
                    .elf
                    .adjust_address_for_prelink(sym_offset)
                    .wrapping_add(self.get_image_base_word_adjustment_offset());
            } else if Some(&space) == default_data_space.as_ref() {
                sym_offset = sym_offset.wrapping_add(self.get_image_data_base());
            }
        } else if section_index == SHN_ABS {
            // Absolute symbols will be pinned to associated address
            symbol_space = default_data_space.clone().unwrap_or_else(|| Arc::clone(&default_space));
            if elf_symbol.is_function() {
                symbol_space = Arc::clone(&default_space);
            } else if let Some(reg_addr) = self.find_memory_register(elf_symbol) {
                return SymbolAddress::At(reg_addr);
            }
        } else if section_index == SHN_COMMON {
            return SymbolAddress::External; // assume unallocated/external
        } else {
            self.log(&format!(
                "Unable to place symbol: {} - value=0x{value_hex}, section-index=0x{section_index:x}",
                elf_symbol.get_formatted_name()
            ));
            return SymbolAddress::Skip;
        }

        let address = truncated_word_address(&symbol_space, sym_offset);

        if is_allocated_to_section || elf_symbol.is_absolute() {
            return SymbolAddress::At(address);
        }

        // Identify special cases which should be treated as external
        if elf_symbol.is_external() {
            return SymbolAddress::External;
        } else if !elf_symbol.is_section() && elf_symbol.get_value() == 0 {
            return SymbolAddress::External;
        } else if elf_symbol.get_value() == 1 {
            // Most likely a Thumb Symbol...
            return SymbolAddress::External;
        }
        SymbolAddress::At(address)
    }

    /// Mirrors `findMemoryRegister(ElfSymbol)`: a memory register named like the symbol
    /// (ignoring leading and trailing underscores).
    fn find_memory_register(&self, elf_symbol: &ElfSymbol) -> std::option::Option<Address> {
        let name = elf_symbol.get_name_as_string();
        if is_blank(name) {
            return None;
        }
        let name = name.expect("not blank");
        self.get_memory_register(name, elf_symbol.get_value() as i64).or_else(|| {
            let stripped = name.trim_start_matches('_').trim_end_matches('_');
            self.get_memory_register(stripped, elf_symbol.get_value() as i64)
        })
    }

    /// Mirrors `getMemoryRegister(String, long)`.
    fn get_memory_register(&self, name: &str, value: i64) -> std::option::Option<Address> {
        let reg = self.program.get_register(name)?;
        let a = reg.address().clone();
        if a.is_memory_address() && (value == 0 || value == a.addressable_word_offset()) {
            return Some(a);
        }
        None
    }

    /// Mirrors `allocateExternalSymbol(ElfSymbol)`; the error is Java's
    /// `AddressOutOfBoundsException` message.
    fn allocate_external_symbol(&self, elf_symbol: &ElfSymbol) -> Result<Address, String> {
        let mut size = elf_symbol.get_size() as i64;
        let align_size = self.elf.get_load_adapter().get_default_alignment(self) as i64;
        if elf_symbol.is_object() && size > 0 && size < i32::MAX as i64 {
            // allocate sized data, maintaining alignment of externalAddress
            size = NumericUtilities::get_unsigned_aligned_value(size, align_size);
        } else {
            size = align_size;
        }
        self.get_next_external_block_entry_address(size as i32)
            .ok_or_else(|| "failed to allocate EXTERNAL block entry".to_string())
    }

    /// Mirrors `getNextExternalBlockEntryAddress(int)`.
    fn get_next_external_block_entry_address(&self, entry_size: i32) -> std::option::Option<Address> {
        if matches!(self.external_block.borrow().next_entry, NextExternalEntry::Unallocated) {
            let alignment = self.elf.get_load_adapter().get_linkage_block_alignment();
            let limits = self.allocate_linkage_block(alignment, -1, "EXTERNAL block");
            let mut state = self.external_block.borrow_mut();
            state.next_entry = match &limits {
                Some(range) => NextExternalEntry::At(range.min_address().clone()),
                None => NextExternalEntry::Exhausted,
            };
            state.limits = limits;
        }
        let mut state = self.external_block.borrow_mut();
        let NextExternalEntry::At(addr) = state.next_entry.clone() else {
            return None;
        };
        let limits = state.limits.clone().expect("an entry address implies limits");
        match addr.add_no_wrap(entry_size as i64 - 1) {
            Ok(last_addr) if limits.contains(&last_addr) => {
                state.last_entry = Some(last_addr.clone());
                state.next_entry = match last_addr.add_no_wrap(1) {
                    Ok(next) if limits.contains(&next) => NextExternalEntry::At(next),
                    _ => NextExternalEntry::Exhausted,
                };
                Some(addr)
            }
            Ok(_) => {
                // unable to allocate entry size
                state.next_entry = NextExternalEntry::Exhausted;
                None
            }
            Err(_) => {
                // Java returns the entry address after an overflow computing its end
                state.next_entry = NextExternalEntry::Exhausted;
                Some(addr)
            }
        }
    }

    /// Mirrors `createExternalBlock()`.
    fn create_external_block(&self) {
        let (limits, last) = {
            let state = self.external_block.borrow();
            (state.limits.clone(), state.last_entry.clone())
        };
        let (Some(limits), Some(last)) = (limits, last) else {
            return;
        };
        let external_block_address = limits.min_address().clone();
        let size = last.subtract(&external_block_address) + 1;
        let result = match self.program.get_memory_mut() {
            Some(mut memory) => memory
                .create_uninitialized_block(EXTERNAL_BLOCK_NAME, &external_block_address, size, false)
                .map_err(|e| e.to_string()),
            None => Err("program has no memory".to_string()),
        };
        match result {
            Ok(block) => {
                let mut block = block.write().unwrap_or_else(|p| p.into_inner());
                // assume any value in external is writable.
                block.set_write(true);
                // Mark block as an artificial fabrication
                block.set_artificial(true);
                block.set_source_name(Some(BLOCK_SOURCE_NAME));
                block.set_comment(Some("NOTE: This block is artificial and allows ELF Relocations to work correctly"));
            }
            Err(msg) => self.log(&format!("Error creating external memory block:  - {msg}")),
        }
    }

    /// Mirrors `processDuplicateExternal(ElfSymbol)`.
    fn process_duplicate_external(&self, elf_symbol: &ElfSymbol) -> bool {
        let (limits, last) = {
            let state = self.external_block.borrow();
            (state.limits.clone(), state.last_entry.clone())
        };
        let (Some(limits), Some(last)) = (limits, last) else {
            return false;
        };
        let sym_name = elf_symbol.get_name_as_string();
        if is_blank(sym_name) {
            return false;
        }
        match self.find_external_block_symbol(sym_name.expect("not blank"), limits.min_address(), &last) {
            Some(s) => {
                // re-use of other fake external address does not support data allocation
                self.set_elf_symbol_address(elf_symbol, Some(s.get_address()));
                true
            }
            None => false,
        }
    }

    /// Mirrors `processVersionedExternal(ElfSymbol)`. The PRE comment Java adds needs a listing
    /// (module docs); the versioned symbol is still mapped to the unversioned one's address.
    fn process_versioned_external(&self, elf_symbol: &ElfSymbol) -> bool {
        let sym_name = elf_symbol.get_name_as_string();
        if is_blank(sym_name) {
            return false;
        }
        let sym_name = sym_name.expect("not blank");
        let Some(mut index) = sym_name.find('@') else {
            return false;
        };
        let (limits, last) = {
            let state = self.external_block.borrow();
            (state.limits.clone(), state.last_entry.clone())
        };
        let (Some(limits), Some(last)) = (limits, last) else {
            return false;
        };
        if let Some(alt_index) = sym_name.find("@@") {
            if alt_index > 0 {
                index = alt_index;
            }
        }
        let real_name = &sym_name[..index];

        // Find real symbol (assumes real symbol is always processed first)
        let Some(s) = self.find_external_block_symbol(real_name, limits.min_address(), &last) else {
            return false;
        };
        self.phase2_unavailable("versioned symbol comments");
        self.set_elf_symbol_address(elf_symbol, Some(s.get_address()));
        true
    }

    /// Mirrors `findExternalBlockSymbol(String, Address, Address)`.
    fn find_external_block_symbol(&self, name: &str, ext_min: &Address, ext_max: &Address) -> std::option::Option<Arc<dyn Symbol>> {
        let symbol_table = self.program.get_symbol_table()?;
        let in_range = |s: &Arc<dyn Symbol>| {
            let a = s.get_address();
            a >= *ext_min && a <= *ext_max
        };
        // try direct global name lookup first
        if let Ok(symbols) = symbol_table.get_symbols_by_name(name) {
            if let Some(s) = symbols.into_iter().find(in_range) {
                return Some(s);
            }
        }
        // iterate over all symbols in the block to find a match
        let mut it = symbol_table.get_symbol_iterator_from(ext_min, true);
        while let Some(s) = it.next_symbol() {
            if !in_range(&s) {
                break;
            }
            if s.get_name() == name {
                return Some(s);
            }
        }
        None
    }

    /// Mirrors `evaluateElfSymbol(ElfSymbol, Address, boolean)`.
    fn evaluate_elf_symbol(
        &self,
        elf_symbol: &ElfSymbol,
        address: Address,
        is_fake_external: bool,
    ) -> Result<(), InvalidInputException> {
        // allow extension to either modify symbol address or fully handle it
        let address = if address.is_memory_address() {
            self.elf.get_load_adapter().evaluate_elf_symbol(self, elf_symbol, address, is_fake_external)
        } else {
            Some(address)
        };
        let Some(address) = address else {
            return Ok(());
        };

        // Remember where in memory Elf symbols have been mapped
        self.set_elf_symbol_address(elf_symbol, Some(address.clone()));

        if elf_symbol.is_section() {
            // Do not add section symbols to program symbol table
            return Ok(());
        }
        let name = elf_symbol.get_name_as_string();
        if is_blank(name) {
            return Ok(());
        }
        let mut name = name.expect("not blank").to_string();

        if address.is_constant_address() {
            // Do not add constant symbols to program symbol table; define as equate instead
            match self.program.get_equate_table() {
                Some(mut equates) => {
                    let _ = equates.create_equate(&name, address.offset());
                }
                None => self.phase2_unavailable("equate creation"),
            }
            return Ok(());
        }

        let sym_type = elf_symbol.get_type();
        let mut is_primary = sym_type == STT_FUNC || sym_type == STT_OBJECT || elf_symbol.get_size() != 0;
        // don't displace existing primary unless symbol is a function or object symbol
        if name.contains('@') {
            is_primary = false; // do not make version symbol primary
        } else if !is_primary && (elf_symbol.is_global() || elf_symbol.is_weak()) {
            is_primary = self.primary_symbol(&address).is_none();
        }

        let validated_name = elf_symbol_name_utils::replace_invalid_chars(&name);
        if validated_name != name {
            self.log(&format!("Unsupported symbol name has been escaped: \"{validated_name}\""));
            name = validated_name;
        }

        self.create_symbol(address.clone(), &name, is_primary, elf_symbol.is_absolute(), None)?;

        // NOTE: treat weak symbols as global so that other programs may link to them.
        if (elf_symbol.is_global() || elf_symbol.is_weak()) && !is_fake_external {
            self.add_external_entry_point(&address);
        }

        if sym_type == STT_FUNC && self.function_at(&address).is_none() {
            if let Some(f) = self.create_one_byte_function(None, address, false) {
                if is_fake_external && !f.is_thunk() {
                    self.phase2_unavailable("external function thunks");
                }
            }
        }
        Ok(())
    }

    /// `program.getSymbolTable().getPrimarySymbol(addr)`.
    fn primary_symbol(&self, addr: &Address) -> std::option::Option<Arc<dyn Symbol>> {
        self.program.get_symbol_table()?.get_primary_symbol(addr).ok().flatten()
    }

    /// `program.getSymbolTable().addExternalEntryPoint(addr)`.
    fn add_external_entry_point(&self, addr: &Address) {
        if let Some(mut symbol_table) = self.program.get_symbol_table() {
            if let Err(e) = symbol_table.add_external_entry_point(addr) {
                self.log(&format!("Failed to add external entry point at {}: {e}", addr_str(addr)));
            }
        }
    }

    /// `program.getFunctionManager().getFunctionAt(addr)`; no function manager has no functions.
    fn function_at(&self, addr: &Address) -> std::option::Option<Arc<dyn Function>> {
        self.program.get_function_manager()?.get_function_at(addr)
    }

    /// Mirrors `createSymbol(Address, String, boolean, boolean, Namespace)`.
    pub(super) fn create_symbol_impl(
        &self,
        addr: Address,
        name: &str,
        is_primary: bool,
        pin_absolute: bool,
        namespace: std::option::Option<Arc<dyn Namespace>>,
    ) -> Result<Arc<dyn Symbol>, InvalidInputException> {
        let io_err = |e: std::io::Error| InvalidInputException::with_message(e.to_string());
        let mut sym = {
            let mut symbol_table = self
                .program
                .get_symbol_table()
                .ok_or_else(|| InvalidInputException::with_message("program has no symbol table"))?;
            match namespace {
                Some(ns) => symbol_table.create_label_in_namespace(&addr, name, ns, SourceType::Imported),
                None => symbol_table.create_label(&addr, name, SourceType::Imported),
            }
            .map_err(io_err)?
        };
        if is_primary {
            sym = self.check_primary(sym);
        }
        if pin_absolute && !sym.is_pinned() {
            let mut symbol_table = self
                .program
                .get_symbol_table()
                .ok_or_else(|| InvalidInputException::with_message("program has no symbol table"))?;
            symbol_table.set_symbol_pinned(sym.get_id(), true).map_err(io_err)?;
            if let Some(pinned) = symbol_table.get_symbol(sym.get_id()).map_err(io_err)? {
                sym = pinned;
            }
        }
        Ok(sym)
    }

    /// Mirrors `checkPrimary(Symbol)`, with `SetLabelPrimaryCmd` applied inline for labels.
    fn check_primary(&self, sym: Arc<dyn Symbol>) -> Arc<dyn Symbol> {
        if sym.is_primary() {
            return sym;
        }
        let name = sym.get_name().to_string();
        let addr = sym.get_address();

        if name.find('@').is_some_and(|i| i > 0) {
            return sym; // do not make versioned symbols primary
        }
        // if starts with a $, probably a markup symbol, like $t,$a,$d
        if name.starts_with('$') {
            return sym;
        }
        // if sym starts with a non-letter give preference to an existing symbol which does
        let starts_alphabetic = |n: &str| n.chars().next().is_some_and(char::is_alphabetic);
        if !starts_alphabetic(&name) {
            if let Some(primary) = self.primary_symbol(&addr) {
                if primary.get_source() != SourceType::Default && starts_alphabetic(primary.get_name()) {
                    return sym;
                }
            }
        }

        // SetLabelPrimaryCmd(addr, name, sym.getParentNamespace()).applyTo(program)
        let Some(old_symbol) = self.primary_symbol(&addr) else {
            self.log(&format!("No Symbols at address: {addr}"));
            return sym;
        };
        if old_symbol.get_symbol_type() == SymbolType::Function {
            self.phase2_unavailable("function symbol renaming");
            return sym;
        }
        let Some(mut symbol_table) = self.program.get_symbol_table() else {
            return sym;
        };
        match symbol_table.set_primary_symbol(sym.get_id()) {
            Ok(true) => symbol_table.get_symbol(sym.get_id()).ok().flatten().unwrap_or(sym),
            _ => {
                drop(symbol_table);
                self.log(&format!("Set primary not permitted for {name}"));
                sym
            }
        }
    }

    /// Mirrors `createOneByteFunction(String, Address, boolean)`.
    pub(super) fn create_one_byte_function_impl(
        &self,
        name: std::option::Option<&str>,
        address: Address,
        is_entry: bool,
    ) -> std::option::Option<Arc<dyn Function>> {
        if is_entry {
            self.add_external_entry_point(&address);
        }
        let name = name.filter(|n| !n.is_empty());
        let Some(mut function_mgr) = self.program.get_function_manager() else {
            self.phase2_unavailable("function creation");
            return None;
        };
        let existing = function_mgr.get_function_at(&address);
        match existing {
            None => {
                let body = AddressSet::from_address(address.clone());
                match function_mgr.create_function(name, address.clone(), &body, SourceType::Imported) {
                    Ok(f) => Some(f),
                    Err(e) => {
                        drop(function_mgr);
                        self.log(&format!("Error while creating function at {address}: {e}"));
                        None
                    }
                }
            }
            Some(f) => {
                drop(function_mgr);
                if let Some(name) = name {
                    if let Err(e) = self.create_symbol_impl(address.clone(), name, true, false, None) {
                        self.log(&format!("Error while creating function at {address}: {e}"));
                    }
                }
                Some(f)
            }
        }
    }

    /// Mirrors `allocateLinkageBlock(int, int, String)`: the largest (or, preferably, the last
    /// big-enough) unallocated range of the default space, aligned.
    pub(super) fn allocate_linkage_block_impl(&self, alignment: i32, size: i32, purpose: &str) -> std::option::Option<AddressRange> {
        let load_adapter = self.elf.get_load_adapter();
        let space = self.get_default_address_space()?;

        // AVAILABLE_MEMORY from the alignment to the end of the space, minus ALLOCATED_MEMORY:
        // earlier allocations and the memory blocks.
        let mut allocated: Vec<(u64, u64)> = self
            .allocated_regions
            .borrow()
            .iter()
            .map(|r| (r.min_address().unsigned_offset(), r.max_address().unsigned_offset()))
            .collect();
        if let Some(memory) = self.program.get_memory() {
            for block in memory.get_blocks() {
                // only consider physical addresses
                let start = block.get_start();
                if start.space() != &space {
                    continue;
                }
                // Java computes an EXTERNAL block end extended by the external block reserve
                // size but then marks only the block itself allocated; so does this port.
                let _ = load_adapter.get_external_block_reserve_size();
                allocated.push((start.unsigned_offset(), block.get_end().unsigned_offset()));
            }
        }
        let available = available_ranges(
            truncated_word_address(&space, alignment as i64).unsigned_offset(),
            space.max_address().unsigned_offset(),
            allocated,
        );

        // Give preference to last unallocated range whose size should be big-enough
        let preferred_range_size: i128 = if size <= 0 {
            load_adapter.get_preferred_external_block_size() as i128
        } else {
            size as i128
        };
        let mut max_range: std::option::Option<(u64, u64)> = None;
        let mut max_range_length: i128 = 0;
        let mut last_big_unallocated_range: std::option::Option<(u64, u64)> = None;
        for &(min, max) in &available {
            let mut range_length = max as i128 - min as i128 + 1;
            if max_range.is_none() || max_range_length < range_length {
                max_range = Some((min, max));
                max_range_length = range_length;
            }
            let aligned = NumericUtilities::get_unsigned_aligned_value(min as i64, alignment as i64) as u64;
            range_length -= aligned.wrapping_sub(min) as i64 as i128;
            if range_length >= preferred_range_size {
                last_big_unallocated_range = Some((min, max));
            }
        }

        let max_range_len_long = max_range.map(|(min, max)| max.wrapping_sub(min).wrapping_add(1) as i64);
        if max_range.is_none()
            || (size > 0 && max_range_len_long.is_some_and(|l| l > 0 && l < size as i64))
        {
            self.log(&format!(
                "ELF unable to find unallocated memory required for {purpose}: {}",
                Program::get_name(self.program.as_ref())
            ));
            return None; // NOTE: this will likely cause other errors to follow
        }
        let mut free_range = max_range.expect("checked above");
        if let Some(big) = last_big_unallocated_range {
            if big.0 > free_range.0 {
                // prefer the last unallocated range if it is a big range (need not be the biggest)
                free_range = big;
            }
        }

        let aligned = NumericUtilities::get_unsigned_aligned_value(free_range.0 as i64, alignment as i64);
        let mut range = AddressRange::new(space.address(aligned), space.address(free_range.1 as i64));
        if size > 0 {
            let range_len = range.length() as i64;
            if range_len < 0 || range_len > size as i64 {
                // reduce size of allocation range
                let min = range.min_address().clone();
                let max = min.add(size as i64 - 1).ok()?;
                range = AddressRange::new(min, max);
            }
            // keep track if allocations other than the EXTERNAL block allocation
            self.allocated_regions.borrow_mut().push(range.clone());
        }
        Some(range)
    }

    /// Mirrors `processEntryPoints(TaskMonitor)`.
    pub(super) fn process_entry_points(&self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        monitor.check_cancelled()?;
        monitor.set_message("Creating entry points...");

        let entry = self.elf.e_entry(); // already adjusted for pre-link
        if entry != 0 && (self.elf.is_executable() || self.elf.is_shared_object()) {
            let entry_addr = self.create_entry_function_at_offset(ELF_ENTRY_FUNCTION_NAME, entry);
            // addElfHeaderReferenceMarkup needs a listing; the process-entry calling convention
            // needs a function, which needs a function manager.
            if entry_addr.is_some_and(|a| self.function_at(&a).is_some()) {
                self.phase2_unavailable("process entry calling convention");
            }
        }

        // process dynamic entry points
        self.create_dynamic_entry_points(&elf_dynamic_type::dt_init(), None, "_INIT_", monitor)?;
        self.create_dynamic_entry_points(&elf_dynamic_type::dt_fini(), None, "_FINI_", monitor)?;
        self.create_dynamic_entry_points(
            &elf_dynamic_type::dt_init_array(),
            Some(&elf_dynamic_type::dt_init_arraysz()),
            "_INIT_",
            monitor,
        )?;
        self.create_dynamic_entry_points(
            &elf_dynamic_type::dt_preinit_array(),
            Some(&elf_dynamic_type::dt_preinit_arraysz()),
            "_PREINIT_",
            monitor,
        )?;
        self.create_dynamic_entry_points(
            &elf_dynamic_type::dt_fini_array(),
            Some(&elf_dynamic_type::dt_fini_arraysz()),
            "_FINI_",
            monitor,
        )?;
        Ok(())
    }

    /// Mirrors `createDynamicEntryPoints(ElfDynamicType, ElfDynamicType, String, TaskMonitor)`.
    fn create_dynamic_entry_points(
        &self,
        dynamic_entry_type: &ElfDynamicType,
        entry_array_size_type: std::option::Option<&ElfDynamicType>,
        base_name: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ElfLoadError> {
        let Some(dynamic_table) = self.elf.get_dynamic_table() else {
            return Ok(());
        };
        let Ok(value) = dynamic_table.get_dynamic_value_of_type(dynamic_entry_type) else {
            return Ok(()); // NotFoundException: ignore
        };
        let entry_addr_offset = self.elf.adjust_address_for_prelink(value);
        let Some(size_type) = entry_array_size_type else {
            // single entry addr case
            self.create_entry_function_at_offset(&format!("_{}", dynamic_entry_type.name), entry_addr_offset);
            return Ok(());
        };
        if dynamic_table.get_dynamic_value_of_type(size_type).is_err() {
            return Ok(());
        }
        monitor.check_cancelled()?;
        // entryAddrOffset points to an array of entry addresses: each element is applied as
        // DWORD/QWORD/pointer data and read back through the listing, which ProgramDB lacks --
        // Java's loop ends at the first element createData fails for.
        monitor.set_message(&format!("Processing {base_name} array..."));
        self.phase2_unavailable("dynamic entry point arrays");
        Ok(())
    }

    /// Mirrors `createEntryFunction(String, long)`.
    fn create_entry_function_at_offset(&self, name: &str, entry_addr: i64) -> std::option::Option<Address> {
        let entry_addr = entry_addr.wrapping_add(self.get_image_base_word_adjustment_offset()); // word offset
        let entry_address = truncated_word_address(&self.get_default_address_space()?, entry_addr);
        self.create_entry_function(name, entry_address.clone());
        Some(entry_address)
    }

    /// Mirrors `createEntryFunction(String, Address)`.
    fn create_entry_function(&self, name: &str, entry_address: Address) {
        let is_execute = self
            .program
            .get_memory()
            .and_then(|m| m.get_block(&entry_address))
            .is_some_and(|block| block.is_execute());
        if !is_execute {
            return;
        }
        let entry_address = self.elf.get_load_adapter().creating_function(self, entry_address);
        if self.function_at(&entry_address).is_some() {
            self.add_external_entry_point(&entry_address);
            return; // symbol-based function already created
        }
        self.create_one_byte_function_impl(Some(name), entry_address, true);
    }

    /// Mirrors `processImports(TaskMonitor)`.
    pub(super) fn process_imports(&self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        monitor.check_cancelled()?;
        monitor.set_message("Processing imports...");
        if self.elf.get_dynamic_table().is_none() {
            return Ok(());
        }
        let needed_libs = self.elf.get_dynamic_library_names();
        if needed_libs.is_empty() {
            return Ok(());
        }
        // ProgramDB has no ExternalManager (and the trait has no setExternalPath) yet.
        self.phase2_unavailable("external library paths");
        Ok(())
    }
}

/// The parts of `[start, end]` (unsigned offsets) no `(min, max)` range in `allocated` covers,
/// ascending -- the `AVAILABLE_MEMORY` ranges of Java's `AddressRangeObjectMap`.
fn available_ranges(start: u64, end: u64, mut allocated: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    allocated.sort_unstable();
    let mut out = Vec::new();
    let mut cursor = Some(start);
    for (min, max) in allocated {
        let Some(c) = cursor else { break };
        if max < c {
            continue;
        }
        if min > end {
            break;
        }
        if min > c {
            out.push((c, min - 1));
        }
        cursor = max.checked_add(1);
    }
    if let Some(c) = cursor {
        if c <= end {
            out.push((c, end));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::available_ranges;

    #[test]
    fn available_ranges_subtract_allocations() {
        assert_eq!(available_ranges(0x1000, 0xffff, vec![]), vec![(0x1000, 0xffff)]);
        assert_eq!(
            available_ranges(0x1000, 0xffff, vec![(0x4000, 0x4fff), (0x2000, 0x2fff)]),
            vec![(0x1000, 0x1fff), (0x3000, 0x3fff), (0x5000, 0xffff)]
        );
        assert_eq!(available_ranges(0x1000, 0xffff, vec![(0, 0x1fff), (0xf000, 0xffff)]), vec![(0x2000, 0xefff)]);
        assert_eq!(available_ranges(0, u64::MAX, vec![(0, u64::MAX)]), vec![]);
    }
}
