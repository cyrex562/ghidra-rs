//! `ElfProgramBuilder` phase 3, scoped to what an x86-64 executable or shared object needs for
//! its GOT to read as Ghidra shows it: the dynamic relocations that fill GOT slots
//! (`processRelocations` with the `X86_64_ElfRelocationHandler` cases below), and the default
//! GOT markup (`ElfLoadAdapter.processGotPlt` -> `ElfDefaultGotPltMarkup.processGOTSections`),
//! which types every GOT slot as a pointer -- so a slot filled with an import's EXTERNAL block
//! address gets a DATA reference to that import's symbol.
//!
//! # What is ported
//!
//! * `processRelocations` / `processRelocationTable` / `processRelocationTableEntries` for a
//!   non-relocatable x86-64 image (`ET_EXEC` / `ET_DYN`), RELR tables included, applying
//!   `X86_64_ElfRelocationHandler.relocate`'s `R_X86_64_RELATIVE`, `RELATIVE64`, `IRELATIVE`,
//!   `64`, `GLOB_DAT` and `JUMP_SLOT` cases (symbol value: the symbol's program address, as
//!   `ElfRelocationContext.getSymbolValue`).
//! * `ElfDefaultGotPltMarkup.processGOTSections` / `processGOT` (first-entry `_DYNAMIC` fixup
//!   included) / `createPointer` / `isValidPointer` / `removeMemRefs`.
//!
//! # Not yet ported
//!
//! * Other machines' relocation handlers, the remaining x86-64 relocation types (each kind
//!   is logged once with its count), relocatable objects (`ET_REL`: section-relative bases and
//!   GOT allocation), the program relocation table (Java records every relocation's status and
//!   original bytes), relocation-table markup and relocation bookmarks.
//! * `processDynamicPLTGOT` (no section headers), `processPLTSection` (PLT disassembly and
//!   external-function conversion), marking `.got` blocks read-only, `setConstant` (a no-op for
//!   `.got` blocks anyway), and the ARM pre-link image-base heuristic.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{ElfLoadError, ElfProgramBuilder};
use crate::app::util::opinion::elf_loader_options_factory as options_factory;
use crate::format::elf::elf_constants::EM_X86_64;
use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_relocation::ElfRelocation;
use crate::format::elf::elf_relocation_table::ElfRelocationTable;
use crate::format::elf::elf_section_header_constants::DOT_GOT;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::pointer_data_type::PointerDataType;
use crate::program::model::symbol::SourceType;
use crate::util::task::TaskMonitor;

// X86_64_ElfRelocationType ids applied here.
const R_X86_64_64: i32 = 1;
const R_X86_64_GLOB_DAT: i32 = 6;
const R_X86_64_JUMP_SLOT: i32 = 7;
const R_X86_64_RELATIVE: i32 = 8;
const R_X86_64_IRELATIVE: i32 = 37;
const R_X86_64_RELATIVE64: i32 = 38;

impl ElfProgramBuilder<'_> {
    /// Port of `processRelocations` for x86-64 images; see the module docs.
    pub(super) fn process_relocations(&self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        let tables = self.elf.get_relocation_tables();
        if tables.is_empty() {
            return Ok(());
        }
        monitor.set_message("Processing relocation tables...");
        if !options_factory::perform_relocations(self.options) {
            return Ok(());
        }
        if self.elf.e_machine() as u16 != EM_X86_64 {
            self.log("ELF relocation handler extension not found!  Unable to process relocations.");
            return Ok(());
        }
        if self.elf.is_relocatable() {
            self.phase2_unavailable("relocatable object relocations");
            return Ok(());
        }
        let mut unhandled: BTreeMap<i32, usize> = BTreeMap::new();
        for table in tables {
            monitor.check_cancelled()?;
            self.process_relocation_table(table, &mut unhandled, monitor)?;
        }
        for (ty, count) in unhandled {
            self.log(&format!("ELF x86-64 relocation type {ty} is not applied by this loader yet ({count} relocations)"));
        }
        Ok(())
    }

    fn process_relocation_table(
        &self,
        table: &Arc<ElfRelocationTable>,
        unhandled: &mut BTreeMap<i32, usize>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ElfLoadError> {
        let base = self.get_default_address(self.elf.adjust_address_for_prelink(0));
        if table.is_missing_required_symbol_table() {
            self.log("Unable to apply dynamic relocations due to missing symbol table");
            return Ok(());
        }
        let symbol_table = table.get_associated_symbol_table();
        for reloc in table.get_relocations() {
            monitor.check_cancelled()?;
            let ty = if table.is_relr_table() { R_X86_64_RELATIVE } else { reloc.get_type() };
            if ty == 0 {
                continue; // R_X86_64_NONE
            }
            let reloc_addr = base.add_wrap(reloc.get_offset());
            let symbol_index = reloc.get_symbol_index();
            let symbol = symbol_table.and_then(|t| t.get_symbol(symbol_index));
            let symbol_name = symbol.and_then(|s| s.get_name_as_string()).unwrap_or_default();
            if let Err(message) = self.apply_relocation(reloc, ty, &reloc_addr, symbol_index, symbol, unhandled) {
                self.log(&format!(
                    "Unable to perform relocation: Type = {ty} (0x{ty:x}) at {reloc_addr} (Symbol = {symbol_name}) - {message}"
                ));
            }
        }
        Ok(())
    }

    /// `X86_64_ElfRelocationHandler.relocate` for the types this loader applies.
    fn apply_relocation(
        &self,
        reloc: &ElfRelocation,
        ty: i32,
        reloc_addr: &Address,
        symbol_index: i32,
        symbol: Option<&crate::format::elf::elf_symbol::ElfSymbol>,
        unhandled: &mut BTreeMap<i32, usize>,
    ) -> Result<(), String> {
        if !matches!(
            ty,
            R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_X86_64_RELATIVE | R_X86_64_RELATIVE64 | R_X86_64_IRELATIVE
        ) {
            *unhandled.entry(ty).or_default() += 1;
            return Ok(());
        }
        let memory = self.program.get_memory().ok_or("program has no memory")?;
        let block = memory.get_block(reloc_addr).ok_or("Block is non-existent")?;
        if !block.is_initialized() {
            return Err("Uninitialized memory".to_string());
        }
        let current = || -> Result<i64, String> {
            let mut bytes = [0u8; 8];
            if memory.get_bytes(reloc_addr, &mut bytes) != 8 {
                return Err(format!("Unable to read bytes at {reloc_addr}"));
            }
            Ok(if self.elf.is_big_endian() { i64::from_be_bytes(bytes) } else { i64::from_le_bytes(bytes) })
        };
        let addend = if reloc.has_addend() { reloc.get_addend() } else { current()? };
        let value = match ty {
            R_X86_64_RELATIVE | R_X86_64_RELATIVE64 => {
                let adjustment = self.get_image_base_word_adjustment_offset();
                if self.elf.is_pre_linked() {
                    current()?.wrapping_add(adjustment)
                } else {
                    addend.wrapping_add(adjustment)
                }
            }
            R_X86_64_IRELATIVE => addend.wrapping_add(self.get_image_base_word_adjustment_offset()),
            _ => {
                // handleUnresolvedSymbol: a symbol the loader did not place cannot be applied
                let symbol_value = match symbol {
                    _ if symbol_index == 0 => 0,
                    Some(symbol) => self
                        .get_elf_symbol_address(symbol)
                        .map(|a| a.addressable_word_offset())
                        .ok_or_else(|| "Unresolved symbol".to_string())?,
                    None => return Err(format!("Invalid symbol index ({symbol_index})")),
                };
                symbol_value.wrapping_add(addend)
            }
        };
        drop(block);
        drop(memory);
        let bytes = if self.elf.is_big_endian() { value.to_be_bytes() } else { value.to_le_bytes() };
        let mut memory = self.program.get_memory_mut().ok_or("program has no memory")?;
        memory.set_bytes(reloc_addr, &bytes).map_err(|e| e.to_string())
    }

    /// Port of `ElfLoadAdapter.processGotPlt`'s default (`ElfDefaultGotPltMarkup.process`) for
    /// an image with section headers: every initialized `.got*` block's slots become pointers.
    pub(super) fn process_got_plt(&self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        monitor.set_message("Processing PLT/GOT ...");
        if self.elf.get_section_header_count() == 0 {
            self.phase2_unavailable("dynamic PLT/GOT markup (no section headers)");
            return Ok(());
        }
        let Some(memory) = self.program.get_memory() else { return Ok(()) };
        let got_blocks: Vec<(Address, Address)> = memory
            .get_blocks()
            .iter()
            .filter(|b| b.get_name().starts_with(DOT_GOT) && b.is_initialized())
            .map(|b| (b.get_start(), b.get_end()))
            .collect();
        drop(memory);
        for (start, end) in got_blocks {
            monitor.check_cancelled()?;
            self.process_got(&start, &end);
        }
        self.phase2_unavailable("PLT section markup");
        Ok(())
    }

    /// Port of `ElfDefaultGotPltMarkup.processGOT(Address, Address, TaskMonitor)`.
    fn process_got(&self, got_start: &Address, got_end: &Address) {
        if self.program.has_defined_data_at(got_start) {
            return; // evidence of prior markup - skip GOT processing
        }
        // Fixup first GOT entry which frequently refers to _DYNAMIC but generally lacks
        // relocation (e.g. .got.plt)
        let image_base_adj = self.get_image_base_word_adjustment_offset();
        if let Some(dynamic) = self.elf.get_dynamic_table() {
            if image_base_adj != 0 {
                if let Err(e) = self.fix_first_got_entry(got_start, dynamic.get_address_offset(), image_base_adj) {
                    self.log(&format!("Failed to process first GOT entry at {got_start}: {e}"));
                }
            }
        }
        let pointer_size = self.program.get_default_pointer_size();
        let pointer: Arc<dyn DataType> = match PointerDataType::new_with(None::<Arc<dyn DataType>>, pointer_size, None) {
            Ok(p) => Arc::new(p),
            Err(e) => {
                self.log(&format!("Failed to process GOT at {got_start}: {e}"));
                return;
            }
        };
        let mut remaining = got_end.subtract(got_start) + 1;
        let mut offset = 0i64;
        while remaining >= i64::from(pointer_size) {
            let Ok(slot) = got_start.add_no_wrap(offset) else { break };
            match self.create_pointer(&slot, &pointer) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    self.log(&format!("Failed to process GOT at {got_start}: {e}"));
                    break;
                }
            }
            remaining -= i64::from(pointer_size);
            offset += i64::from(pointer_size);
        }
    }

    fn fix_first_got_entry(&self, got_start: &Address, dynamic_offset: i64, adjustment: i64) -> Result<(), String> {
        let value = self.get_original_value(got_start.clone(), false).map_err(|e| e.to_string())?;
        if value != dynamic_offset {
            return Ok(());
        }
        let value = value.wrapping_add(adjustment);
        let bytes: Vec<u8> = match (self.elf.is64_bit(), self.elf.is_big_endian()) {
            (true, false) => value.to_le_bytes().to_vec(),
            (true, true) => value.to_be_bytes().to_vec(),
            (false, false) => (value as i32).to_le_bytes().to_vec(),
            (false, true) => (value as i32).to_be_bytes().to_vec(),
        };
        let mut memory = self.program.get_memory_mut().ok_or("program has no memory")?;
        memory.set_bytes(got_start, &bytes).map_err(|e| e.to_string())
    }

    /// Port of `ElfDefaultGotPltMarkup.createPointer(addr, keepRefWhenValid = true)`: `false`
    /// when `addr` is not in initialized memory (Java's `null`).
    fn create_pointer(&self, addr: &Address, pointer: &Arc<dyn DataType>) -> Result<bool, String> {
        let Some(memory) = self.program.get_memory() else { return Ok(false) };
        if !memory.get_block(addr).is_some_and(|b| b.is_initialized()) {
            return Ok(false);
        }
        drop(memory);
        if !self.program.has_defined_data_at(addr) {
            self.program.create_data(addr, Arc::clone(pointer)).map_err(|e| e.message().to_string())?;
        }
        if !self.is_valid_pointer(addr, pointer.get_length()) {
            // removeMemRefs
            if let Some(mut references) = self.program.get_reference_manager() {
                references.remove_all_references_from(addr.clone());
            }
        }
        Ok(true)
    }

    /// Port of `ElfDefaultGotPltMarkup.isValidPointer`: the pointer at `addr` refers to memory
    /// or to an address with a non-default primary symbol.
    fn is_valid_pointer(&self, addr: &Address, size: i32) -> bool {
        let Some(memory) = self.program.get_memory() else { return false };
        let mut bytes = vec![0u8; size.max(0) as usize];
        if memory.get_bytes(addr, &mut bytes) != bytes.len() {
            return false;
        }
        let value = bytes
            .iter()
            .enumerate()
            .fold(0u64, |acc, (i, b)| {
                let shift = if self.elf.is_big_endian() { (bytes.len() - 1 - i) * 8 } else { i * 8 };
                acc | (u64::from(*b) << shift)
            });
        let ref_addr = addr.space().address(value as i64);
        if memory.contains(&ref_addr) {
            return true;
        }
        drop(memory);
        self.program
            .get_symbol_table()
            .and_then(|table| table.get_primary_symbol(&ref_addr).ok().flatten())
            .is_some_and(|primary| primary.get_source() != SourceType::Default)
    }
}
