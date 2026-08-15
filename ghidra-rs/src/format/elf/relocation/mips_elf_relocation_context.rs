//! Port of `ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationContext`.
//!
//! Provides extended relocation context with the ability to retain deferred relocation lists. In
//! addition, the ability to generate a section GOT table is provided to facilitate relocations
//! encountered within object modules.
//!
//! # Shape
//!
//! Java's `MIPS_ElfRelocationContext` is a concrete leaf: it extends
//! `ElfRelocationContext<MIPS_ElfRelocationHandler>` with the deferred HI16/GOT16 lists, the
//! fabricated section GOT, and the GP-value lookups the MIPS handler drives. Per the port's shape
//! rules a concrete leaf class becomes a `struct` + `impl`, never a trait; the overridable
//! behaviour it inherits is supplied by implementing
//! [`ElfRelocationContext`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext)
//! over an [`ElfRelocationContextBase`] field.
//!
//! # Departures from the Java class
//!
//! * **Interior mutability.** In Java the *handler* mutates the context it is handed: it appends to
//!   the deferred lists, sets `useSavedAddend`/`savedAddend`, and allocates section GOT entries,
//!   all through a plain reference. The ported `ElfRelocationContext::process_relocation_for_symbol`
//!   (like Java's, which is called from a `final` method that holds no write lock) takes `&self`,
//!   so every field the handler writes is held in a `Cell`/`RefCell`. The Java fields that are
//!   package-private -- read and written directly by the handler -- stay public fields here rather
//!   than becoming accessor pairs.
//! * **`Address.NO_ADDRESS`.** Java distinguishes three states for the section GOT cursor: `null`
//!   (not allocated yet), `Address.NO_ADDRESS` (allocation failed, or the block is full), and a
//!   real address. This crate has no `NO_ADDRESS` sentinel, so [`SectionGotAddress`] models the
//!   three states explicitly. Where Java returns `NO_ADDRESS` from
//!   `getNextSectionGotEntryAddress` (the "unable to allocate entry size" branch, which its own
//!   caller then mistakes for a usable address), this port returns `None`, i.e. the same answer as
//!   the other failure branch.
//! * **`iterateHi16`/`iterateGot16`.** Java hands out a `LinkedList` iterator so the handler can
//!   remove entries as it matches them. A `RefCell<Vec<..>>` cannot lend a mutating iterator
//!   across the borrow, so the lists are exposed as public fields instead; the handler drains or
//!   retains directly. [`add_hi16_relocation`](MipsElfRelocationContext::add_hi16_relocation) and
//!   [`add_got16_relocation`](MipsElfRelocationContext::add_got16_relocation) are kept as Java has
//!   them.
//! * **`createGot`.** Java calls `MemoryBlockUtils.createInitializedBlock(...)`, marks the block
//!   artificial, `putBytes` the GOT entries, and lays down a `PointerDataType` over each. Only the
//!   first and third have a ported equivalent: the block is created through
//!   [`Memory::create_initialized_block`](crate::program::model::mem::memory::Memory::create_initialized_block)
//!   and the entries written with `set_bytes`. `MemoryBlock::set_artificial` needs `&mut` access to
//!   a block this crate hands back as an `Arc`, and `PointerDataType` is a trait with no
//!   constructible default (see
//!   [`DataUtilities`](crate::program::model::data::data_utilities::DataUtilities) for the same
//!   limitation), so the artificial flag and the pointer markup are skipped. As in the
//!   [`PowerPC` context](crate::format::elf::relocation::power_pc_elf_relocation_context), program
//!   mutation is best-effort through `Arc::get_mut` and silently no-ops when the `Program` handle
//!   is not uniquely owned.
//! * **`getAdjustedGPValue`/`getGP0Value`.** `Symbol` lookup goes through
//!   [`SymbolUtilities::get_label_or_function_symbol`], which needs `&mut Program`; same
//!   best-effort `Arc::get_mut` idiom.
//! * **`getSectionGotName`.** Java dereferences `getSectionToBeRelocated()` unconditionally. The
//!   ported seam answers `None` for a dynamic relocation table (and when no table is being
//!   processed), in which case the block name is just `%got`.
//! * The `MIPS_ElfRelocationHandler` this context is generic over is not ported yet -- the forward
//!   edge of the context/handler cycle. It is stubbed as
//!   [`MipsElfRelocationHandler`](crate::format::seam_stubs::MipsElfRelocationHandler), and
//!   `MIPS_DeferredRelocation` (its nested class) as
//!   [`MipsDeferredRelocation`](crate::format::seam_stubs::MipsDeferredRelocation).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::Arc;

use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::elf::relocation::abstract_elf_relocation_handler::AbstractElfRelocationHandler;
use crate::format::elf::relocation::elf_relocation_context::{
    ElfRelocationContext, ElfRelocationContextBase, RelocationProcessingError,
};
use crate::format::elf::relocation::elf_relocation_type::ElfRelocationType;
use crate::format::elf::relocation::mips_elf_relocation_type::MipsElfRelocationType;
use crate::format::seam_stubs::{
    elf_relocation_handler, ElfRelocation, MipsDeferredRelocation, MipsElfRelocationHandler,
};
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::Address;
use crate::program::model::reloc::{RelocationResult, RelocationStatus};
use crate::program::model::symbol::symbol_utilities::{DefaultSymbolUtilities, SymbolUtilities};
use crate::util::big_endian_data_converter::BigEndianDataConverter;
use crate::util::data_converter::DataConverter;
use crate::util::little_endian_data_converter::LittleEndianDataConverter;
use crate::util::task::DummyMonitor;

/// `MIPS_ElfExtension.MIPS_GP_VALUE_SYMBOL` -- the symbol carrying the image's GP value.
///
/// Duplicated here rather than stubbed: `MIPS_ElfExtension` is unported, and this is the only
/// member of it the context needs.
const MIPS_GP_VALUE_SYMBOL: &str = "_mips_gp_value";

/// `MIPS_ElfExtension.MIPS_GP0_VALUE_SYMBOL` -- the symbol carrying the `.reginfo` GP0 value.
const MIPS_GP0_VALUE_SYMBOL: &str = "_mips_gp0_value";

/// The symbol whose value is the GP register itself rather than a placed address.
const GNU_LOCAL_GP_SYMBOL: &str = "__gnu_local_gp";

/// Size of the linkage block reserved for the fabricated section GOT.
const SECTION_GOT_SIZE: i32 = 0x10000;

/// `gp` is defined as a 0x7ff0 byte offset into the global offset table.
const GP_OFFSET_INTO_GOT: i64 = 0x7ff0;

/// One of the two section-GOT cursors, which Java models with a nullable [`Address`] plus the
/// `Address.NO_ADDRESS` sentinel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SectionGotAddress {
    /// Java `null`: the section GOT has not been allocated yet.
    #[default]
    Unallocated,
    /// Java `Address.NO_ADDRESS`: allocation failed, or the GOT block is exhausted.
    Unavailable,
    /// A usable address.
    At(Address),
}

impl SectionGotAddress {
    /// The address, if this cursor holds one.
    pub fn address(&self) -> Option<&Address> {
        match self {
            SectionGotAddress::At(addr) => Some(addr),
            _ => None,
        }
    }
}

/// Extended MIPS relocation context: retains deferred relocation lists and can generate a section
/// GOT table to facilitate relocations encountered within object modules.
pub struct MipsElfRelocationContext {
    base: ElfRelocationContextBase,
    /// Java's narrowed `handler` field. `None` when no handler was found for the image.
    handler: Option<Arc<dyn MipsElfRelocationHandler>>,

    /// HI16 relocations awaiting their matching LO16 relocation (Java's `hi16list`).
    pub hi16_list: RefCell<Vec<MipsDeferredRelocation>>,
    /// GOT16 relocations awaiting their matching LO16 relocation (Java's `got16list`).
    pub got16_list: RefCell<Vec<MipsDeferredRelocation>>,

    section_got_limits: RefCell<Option<AddressRange>>,
    section_got_address: RefCell<SectionGotAddress>,
    last_section_got_entry_address: RefCell<Option<Address>>,
    next_section_got_entry_address: RefCell<SectionGotAddress>,
    got_map: RefCell<HashMap<i64, Address>>,

    /// True if the value computed by the current relocation should be saved for the next one,
    /// which targets the same offset.
    pub save_value_for_next_reloc: Cell<bool>,
    /// True if [`saved_addend`](Self::saved_addend) should be used instead of an extracted addend.
    pub use_saved_addend: Cell<bool>,
    /// True if the computation that produced [`saved_addend`](Self::saved_addend) failed.
    pub saved_addend_has_error: Cell<bool>,
    /// The addend carried over from the previous relocation at the same offset.
    pub saved_addend: Cell<i64>,

    /// The symbol resolved by the previous relocation of a packed MIPS-64 entry.
    pub last_elf_symbol: RefCell<Option<ElfSymbol>>,
    /// The address of [`last_elf_symbol`](Self::last_elf_symbol).
    pub last_symbol_addr: RefCell<Option<Address>>,
}

impl MipsElfRelocationContext {
    /// Relocation context for a specific MIPS ELF image and relocation table.
    ///
    /// # Arguments
    /// * `handler` - MIPS relocation handler, or `None` if not available
    /// * `load_helper` - the ELF load helper
    /// * `symbol_map` - ELF symbol placement map
    pub fn new(
        handler: Option<Arc<dyn MipsElfRelocationHandler>>,
        load_helper: Arc<dyn ElfLoadHelper>,
        symbol_map: Arc<HashMap<ElfSymbol, Address>>,
    ) -> Self {
        let base = ElfRelocationContextBase::new(
            handler.clone().map(MipsElfRelocationHandler::as_elf_relocation_handler),
            load_helper,
            symbol_map,
        );
        MipsElfRelocationContext {
            base,
            handler,
            hi16_list: RefCell::new(Vec::new()),
            got16_list: RefCell::new(Vec::new()),
            section_got_limits: RefCell::new(None),
            section_got_address: RefCell::new(SectionGotAddress::Unallocated),
            last_section_got_entry_address: RefCell::new(None),
            next_section_got_entry_address: RefCell::new(SectionGotAddress::Unallocated),
            got_map: RefCell::new(HashMap::new()),
            save_value_for_next_reloc: Cell::new(false),
            use_saved_addend: Cell::new(false),
            saved_addend_has_error: Cell::new(false),
            saved_addend: Cell::new(0),
            last_elf_symbol: RefCell::new(None),
            last_symbol_addr: RefCell::new(None),
        }
    }

    /// Apply one of the (up to three) relocations packed into a single entry.
    ///
    /// Ports Java's private `doRelocate`.
    fn do_relocate(
        &self,
        relocation: &dyn ElfRelocation,
        relocation_address: &Address,
        reloc_type: i32,
        symbol_index: i32,
    ) -> Result<RelocationResult, RelocationProcessingError> {
        if reloc_type == 0 {
            return Ok(RelocationResult::SKIPPED);
        }

        let elf_symbol = self.base.get_symbol(symbol_index);
        let symbol_addr = elf_symbol.as_ref().and_then(|s| self.get_symbol_address(s));
        let symbol_value = elf_symbol.as_ref().map_or(0, |s| self.get_symbol_value(s));
        let symbol_name = elf_symbol
            .as_ref()
            .and_then(ElfSymbol::get_name_as_string)
            .map(str::to_string);

        let Some(handler) = self.handler.as_ref() else {
            // Unreachable through `process_relocation`, which rejects a missing handler first.
            return Ok(RelocationResult::FAILURE);
        };

        let Some(relocation_type) = handler.get_relocation_type(reloc_type) else {
            handler.mark_as_undefined(
                self.base.get_program().as_ref(),
                relocation_address,
                reloc_type,
                symbol_name.as_deref(),
                symbol_index,
                self.base.get_log().as_ref(),
            );
            return Ok(RelocationResult::UNSUPPORTED);
        };

        let Some(elf_symbol) = elf_symbol else {
            // Java passes the null symbol straight through to the handler, which dereferences it.
            // Reject it here instead, the way the inherited `processRelocation` rejects an
            // unresolvable symbol index.
            self.base.mark_relocation_error(
                relocation_address,
                reloc_type,
                symbol_index,
                None,
                &format!("Invalid symbol index ({symbol_index})"),
            );
            return Ok(RelocationResult::FAILURE);
        };

        Ok(AbstractElfRelocationHandler::relocate(
            handler.as_ref(),
            self,
            relocation,
            relocation_type,
            relocation_address,
            &elf_symbol,
            symbol_addr.as_ref(),
            symbol_value,
            symbol_name.as_deref(),
        )?)
    }

    /// Allocate the linkage block that backs the fabricated section GOT.
    fn allocate_section_got(&self) {
        let alignment = self
            .base
            .get_load_adapter()
            .map_or(0x1000, |adapter| adapter.get_linkage_block_alignment());
        let section_got_name = self.get_section_got_name();
        let limits = self.base.get_load_helper().allocate_linkage_block(
            alignment,
            SECTION_GOT_SIZE,
            &section_got_name,
        );

        let got_address = match &limits {
            Some(range) => SectionGotAddress::At(range.min_address().clone()),
            None => SectionGotAddress::Unavailable,
        };
        *self.section_got_limits.borrow_mut() = limits;
        *self.section_got_address.borrow_mut() = got_address.clone();
        *self.next_section_got_entry_address.borrow_mut() = got_address;

        let load_helper = self.base.get_load_helper();
        if self.section_got_limits.borrow().is_none() {
            load_helper.log(&format!(
                "Failed to allocate {section_got_name} block required for relocation processing"
            ));
        } else {
            load_helper.log(&format!(
                "Created {section_got_name} block required for relocation processing (gp=0x{:x})",
                self.get_gp_value()
            ));
        }
    }

    /// Allocate the next section GOT entry location.
    ///
    /// Returns the address of the GOT entry, or `None` if unable to allocate.
    fn get_next_section_got_entry_address(&self) -> Option<Address> {
        if *self.next_section_got_entry_address.borrow() == SectionGotAddress::Unallocated {
            self.allocate_section_got();
        }

        let addr = self.next_section_got_entry_address.borrow().address().cloned()?;

        let pointer_size = self.base.get_program().get_default_pointer_size();
        match addr.add_no_wrap(i64::from(pointer_size) - 1) {
            Ok(last_addr) => {
                if self.section_got_limits_contain(&last_addr) {
                    *self.last_section_got_entry_address.borrow_mut() = Some(last_addr.clone());
                    let next = match last_addr.add_no_wrap(1) {
                        Ok(next) if self.section_got_limits_contain(&next) => {
                            SectionGotAddress::At(next)
                        }
                        _ => SectionGotAddress::Unavailable,
                    };
                    *self.next_section_got_entry_address.borrow_mut() = next;
                } else {
                    // Unable to allocate an entry-sized slot.
                    *self.next_section_got_entry_address.borrow_mut() =
                        SectionGotAddress::Unavailable;
                    return None;
                }
            }
            Err(_) => {
                *self.next_section_got_entry_address.borrow_mut() = SectionGotAddress::Unavailable;
            }
        }
        Some(addr)
    }

    fn section_got_limits_contain(&self, addr: &Address) -> bool {
        self.section_got_limits
            .borrow()
            .as_ref()
            .is_some_and(|range| range.contains(addr))
    }

    /// Get the preferred GP.
    ///
    /// NOTE: This needs work to properly handle the use of multiple GP's.
    ///
    /// Returns the preferred GP value, or -1 if unable to determine GP.
    pub fn get_gp_value(&self) -> i64 {
        let gp = self.get_adjusted_gp_value();
        if gp != -1 {
            return gp;
        }

        // TODO: we should probably not resort to assuming use of fabricated got so easily
        // since get_adjusted_gp_value has rather limited capability at present.

        // Assume GP relative to fabricated GOT.
        if *self.section_got_address.borrow() == SectionGotAddress::Unallocated {
            self.allocate_section_got();
        }
        match self.section_got_address.borrow().address() {
            // gp is defined as 0x7ff0 byte offset into the global offset table.
            Some(addr) => addr.offset() + GP_OFFSET_INTO_GOT,
            None => -1,
        }
    }

    /// Determine if the next relocation has the same offset.
    ///
    /// If true, the computed value should be stored to [`saved_addend`](Self::saved_addend) and
    /// [`use_saved_addend`](Self::use_saved_addend) set true.
    pub fn next_relocation_has_same_offset(&self, relocation: &dyn ElfRelocation) -> bool {
        let Some(table) = self.base.relocation_table() else {
            return false;
        };
        let relocations = table.get_relocations();
        let reloc_index = relocation.get_relocation_index();
        if reloc_index < 0 || reloc_index as usize >= relocations.len().saturating_sub(1) {
            return false;
        }
        let reloc_index = reloc_index as usize;
        relocations[reloc_index].get_offset() == relocations[reloc_index + 1].get_offset()
            && relocations[reloc_index + 1].get_type()
                != MipsElfRelocationType::R_MIPS_NONE.type_id_value()
    }

    /// Get or allocate a GOT entry for the specified `symbol_value`.
    ///
    /// Returns the GOT entry address, or `None` if unable to allocate.
    pub fn get_section_got_address(&self, symbol_value: i64) -> Option<Address> {
        if let Some(addr) = self.got_map.borrow().get(&symbol_value) {
            return Some(addr.clone());
        }
        let addr = self.get_next_section_got_entry_address()?;
        self.got_map.borrow_mut().insert(symbol_value, addr.clone());
        Some(addr)
    }

    fn get_section_got_name(&self) -> String {
        let section_name = self
            .base
            .relocation_table()
            .and_then(|table| table.get_section_to_be_relocated())
            .map(|section| section.get_name_as_string())
            .unwrap_or_default();
        format!("{}{section_name}", elf_relocation_handler::GOT_BLOCK_NAME)
    }

    /// Flush the section GOT table to a new `%got` memory block.
    fn create_got(&self) {
        let Some(last_entry_addr) = self.last_section_got_entry_address.borrow().clone() else {
            return;
        };
        let Some(got_addr) = self.section_got_address.borrow().address().cloned() else {
            return;
        };
        let size = last_entry_addr.subtract(&got_addr) + 1;
        let block_name = self.get_section_got_name();

        let log = self.base.get_log();
        let pointer_size = self.base.get_program().get_default_pointer_size();
        let big_endian = self.base.is_big_endian();
        let converter: &dyn DataConverter = if big_endian {
            &BigEndianDataConverter
        } else {
            &LittleEndianDataConverter
        };

        // See the module docs: program mutation is best-effort through `Arc::get_mut`.
        let mut program = self.base.get_program().clone();
        let Some(memory) = Arc::get_mut(&mut program).and_then(|p| p.get_memory_mut()) else {
            log.append_msg(&format!("Failed to create {block_name} block"));
            return;
        };

        if let Err(e) = memory.create_initialized_block(
            &block_name,
            &got_addr,
            size as u64,
            0,
            &DummyMonitor,
            false,
        ) {
            log.append_msg(&format!("Failed to create {block_name} block: {e}"));
            return;
        }

        for (symbol_value, addr) in self.got_map.borrow().iter() {
            let bytes = if pointer_size == 4 {
                converter.int_to_bytes(*symbol_value as i32)
            } else {
                converter.long_to_bytes(*symbol_value)
            };
            if let Err(e) = memory.set_bytes(addr, &bytes) {
                log.append_msg(&format!("Failed to write {block_name} entry at {addr}: {e}"));
            }
        }
    }

    /// Get the GP value.
    ///
    /// Returns the adjusted GP value, or -1 if the `_mips_gp_value` symbol is not defined.
    pub fn get_adjusted_gp_value(&self) -> i64 {
        // TODO: this is a simplified use of GP and could be incorrect when multiple GPs exist.
        self.gp_symbol_offset(MIPS_GP_VALUE_SYMBOL)
    }

    /// Get the GP0 value (from `.reginfo` and the generated symbol).
    ///
    /// Returns the adjusted GP0 value, or -1 if the `_mips_gp0_value` symbol is not defined.
    pub fn get_gp0_value(&self) -> i64 {
        self.gp_symbol_offset(MIPS_GP0_VALUE_SYMBOL)
    }

    /// The offset of the named label-or-function symbol, or -1 if it is not defined.
    fn gp_symbol_offset(&self, symbol_name: &str) -> i64 {
        let log = self.base.get_log();
        let mut program = self.base.get_program().clone();
        let symbol = Arc::get_mut(&mut program).and_then(|program| {
            let log = log.clone();
            DefaultSymbolUtilities.get_label_or_function_symbol(program, symbol_name, &mut |err| {
                log.append_msg(&format!("MIPS_ELF> {err}"));
            })
        });
        symbol.map_or(-1, |symbol| symbol.get_address().offset())
    }

    /// Add a HI16 relocation for deferred processing.
    pub fn add_hi16_relocation(&self, hi16reloc: MipsDeferredRelocation) {
        self.hi16_list.borrow_mut().push(hi16reloc);
    }

    /// Add a GOT16 relocation for deferred processing.
    pub fn add_got16_relocation(&self, got16reloc: MipsDeferredRelocation) {
        self.got16_list.borrow_mut().push(got16reloc);
    }
}

impl ElfRelocationContext for MipsElfRelocationContext {
    fn base(&self) -> &ElfRelocationContextBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ElfRelocationContextBase {
        &mut self.base
    }

    fn as_relocation_context(&self) -> &dyn ElfRelocationContext {
        self
    }

    fn process_relocation_for_symbol(
        &self,
        relocation: &dyn ElfRelocation,
        _elf_symbol: &ElfSymbol,
        relocation_address: &Address,
    ) -> Result<RelocationResult, RelocationProcessingError> {
        *self.last_symbol_addr.borrow_mut() = None;
        *self.last_elf_symbol.borrow_mut() = None;

        let mut type_id = relocation.get_type();
        let mut symbol_index = relocation.get_symbol_index();

        let mut last_result = RelocationResult::FAILURE;
        if self.base.get_elf_header().is64_bit() {
            // Each relocation can pack up to 3 relocations for 64-bit.
            for n in 0..3 {
                if n == 1 {
                    // The symbol used by the second pack slot is encoded in the info field of the
                    // relocation. This could be any symbol and does not need to match the first
                    // packed entry.
                    symbol_index = relocation.get_special_symbol_index();
                } else if n == 2 {
                    // The third pack slot should not be referring to any symbol. Clear out the
                    // symbol index to catch any errors in relocations using symbolIndex.
                    symbol_index = 0;
                }

                let reloc_type = type_id & 0xff;
                type_id >>= 8;
                let next_reloc_type = if n < 2 { type_id & 0xff } else { 0 };
                let is_last =
                    next_reloc_type == MipsElfRelocationType::R_MIPS_NONE.type_id_value();
                self.save_value_for_next_reloc.set(if is_last {
                    self.next_relocation_has_same_offset(relocation)
                } else {
                    true
                });

                let result =
                    self.do_relocate(relocation, relocation_address, reloc_type, symbol_index)?;

                if result.status() == RelocationStatus::Failure
                    || result.status() == RelocationStatus::Unsupported
                {
                    return Ok(result);
                }
                last_result = result;

                if is_last {
                    break;
                }
            }
            return Ok(last_result);
        }

        // 32-bit ELF
        self.save_value_for_next_reloc
            .set(self.next_relocation_has_same_offset(relocation));
        self.do_relocate(relocation, relocation_address, type_id, symbol_index)
    }

    fn end_relocation_table_processing(&mut self) {
        // Mark all deferred relocations which were never processed.
        for reloc in self.hi16_list.borrow().iter() {
            reloc.mark_unprocessed(&self.base, "LO16 Relocation");
        }
        self.hi16_list.borrow_mut().clear();
        for reloc in self.got16_list.borrow().iter() {
            reloc.mark_unprocessed(&self.base, "LO16 Relocation");
        }
        self.got16_list.borrow_mut().clear();

        // Generate the section GOT table if required.
        self.create_got();

        *self.section_got_limits.borrow_mut() = None;
        *self.section_got_address.borrow_mut() = SectionGotAddress::Unallocated;
        *self.last_section_got_entry_address.borrow_mut() = None;
        *self.next_section_got_entry_address.borrow_mut() = SectionGotAddress::Unallocated;
        self.got_map.borrow_mut().clear();
        self.use_saved_addend.set(false);
        self.saved_addend_has_error.set(false);
        *self.last_symbol_addr.borrow_mut() = None;
        *self.last_elf_symbol.borrow_mut() = None;

        self.base.end_relocation_table_processing();
    }

    fn extract_addend(&self) -> bool {
        self.base
            .relocation_table()
            .is_none_or(|table| !table.has_addend_relocations())
            && !self.use_saved_addend.get()
    }

    fn get_symbol_value(&self, symbol: &ElfSymbol) -> i64 {
        if symbol.get_name_as_string() == Some(GNU_LOCAL_GP_SYMBOL) {
            return self.get_adjusted_gp_value(); // TODO: need to verify this case still
        }
        // `super.getSymbolValue(symbol)`; a trait default body cannot be called from an override,
        // so the inherited one line is repeated here.
        self.get_symbol_address(symbol)
            .map_or(0, |addr| addr.addressable_word_offset())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Mutex;

    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::format::elf::elf_section_header_constants::SHN_UNDEF;
    use crate::format::elf::elf_symbol::{STB_GLOBAL, STT_FUNC};
    use crate::format::seam_stubs::{
        ElfHeader, ElfRelocationHandler, ElfRelocationTable, ElfSectionHeader, ElfSymbolTable,
        MessageLog, Throwable,
    };
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;

    // ---------------------------------------------------------------- test doubles

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "MIPS:BE:32:default".to_string()
        }
    }

    #[derive(Default)]
    struct RecordingLog {
        messages: Mutex<Vec<String>>,
    }

    impl MessageLog for RecordingLog {
        fn copy_from(&self, _log: &dyn MessageLog) {}
        fn append_msg(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn append_exception(&self, _t: &dyn Throwable) {}
        fn error(&self, _originator: &str, _message: &str) {}
        fn has_messages(&self) -> bool {
            !self.messages.lock().unwrap().is_empty()
        }
        fn clear(&self) {
            self.messages.lock().unwrap().clear();
        }
        fn set_status(&self, _status: &str) {}
        fn clear_status(&self) {}
        fn get_status(&self) -> String {
            String::new()
        }
        fn to_string(&self) -> String {
            self.messages.lock().unwrap().join("\n")
        }
        fn write(&self, _owner: &dyn crate::format::seam_stubs::Class, _message_header: &str) {}
    }

    struct MockElfHeader {
        is32_bit: bool,
    }

    impl ElfHeader for MockElfHeader {
        fn is32_bit(&self) -> bool {
            self.is32_bit
        }
        fn is_relocatable(&self) -> bool {
            true
        }
        fn get_sections(&self) -> Vec<Box<dyn ElfSectionHeader>> {
            Vec::new()
        }
    }

    struct MockLoadHelper {
        log: Arc<RecordingLog>,
        /// Messages passed to `ElfLoadHelper.log(...)`, distinct from the import log.
        helper_log: Mutex<Vec<String>>,
        is32_bit: bool,
        /// The range `allocateLinkageBlock` should hand back, if any.
        linkage_block: Option<AddressRange>,
    }

    impl MockLoadHelper {
        fn new() -> Self {
            MockLoadHelper {
                log: Arc::new(RecordingLog::default()),
                helper_log: Mutex::new(Vec::new()),
                is32_bit: true,
                linkage_block: None,
            }
        }
    }

    impl ElfLoadHelper for MockLoadHelper {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_option_bool(&self, _option_name: &str, default_value: bool) -> bool {
            default_value
        }
        fn get_option_string(
            &self,
            _option_name: &str,
            default_value: Option<String>,
        ) -> Option<String> {
            default_value
        }
        fn get_option_i32(&self, _option_name: &str, default_value: i32) -> i32 {
            default_value
        }
        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            Arc::new(MockElfHeader { is32_bit: self.is32_bit })
        }
        fn get_log(&self) -> Arc<dyn MessageLog> {
            self.log.clone()
        }
        fn log(&self, msg: &str) {
            self.helper_log.lock().unwrap().push(msg.to_string());
        }
        fn log_exception(&self, t: &dyn std::error::Error) {
            self.helper_log.lock().unwrap().push(t.to_string());
        }
        fn mark_as_code(&self, _address: Address) {}
        fn create_one_byte_function(
            &self,
            _name: Option<&str>,
            _address: Address,
            _is_entry: bool,
        ) -> Arc<dyn crate::program::model::listing::function::Function> {
            unimplemented!("not exercised by these tests")
        }
        fn create_external_function_linkage(
            &self,
            _name: &str,
            _function_addr: Address,
            _indirect_pointer_addr: Option<Address>,
        ) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_undefined_data(
            &self,
            _address: Address,
            _length: i32,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_data(
            &self,
            _address: Address,
            _dt: Box<dyn crate::program::model::data::data_type::DataType>,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_elf_symbol_address(&self, _elf_symbol: &ElfSymbol, _address: Option<Address>) {}
        fn get_elf_symbol_address(&self, _elf_symbol: &ElfSymbol) -> Option<Address> {
            None
        }
        fn create_symbol(
            &self,
            _addr: Address,
            _name: &str,
            _is_primary: bool,
            _pin_absolute: bool,
            _namespace: Option<Arc<dyn crate::program::model::symbol::namespace::Namespace>>,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::Symbol>,
            crate::util::exception::InvalidInputException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn find_load_address(
            &self,
            _section: &dyn crate::format::memory_loadable::MemoryLoadable,
            _byte_offset_within_section: i64,
        ) -> Option<Address> {
            None
        }
        fn get_default_address(&self, _addressable_word_offset: i64) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_image_base_word_adjustment_offset(&self) -> i64 {
            0
        }
        fn get_got_value(&self) -> Option<i64> {
            None
        }
        fn allocate_linkage_block(
            &self,
            _alignment: i32,
            _size: i32,
            _purpose: &str,
        ) -> Option<AddressRange> {
            self.linkage_block.clone()
        }
        fn get_original_value(
            &self,
            _addr: Address,
            _sign_extend: bool,
        ) -> Result<i64, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn add_artificial_reloc_table_entry(&self, _address: Address, _length: i32) -> bool {
            false
        }
    }

    struct MockRelocation {
        symbol_index: i32,
        type_id: i32,
        offset: i64,
        relocation_index: i32,
    }

    impl Default for MockRelocation {
        fn default() -> Self {
            MockRelocation { symbol_index: 0, type_id: 0, offset: 0, relocation_index: -1 }
        }
    }

    impl ElfRelocation for MockRelocation {
        fn get_symbol_index(&self) -> i32 {
            self.symbol_index
        }
        fn get_type(&self) -> i32 {
            self.type_id
        }
        fn get_offset(&self) -> i64 {
            self.offset
        }
        fn get_relocation_index(&self) -> i32 {
            self.relocation_index
        }
    }

    struct MockSection;
    impl ElfSectionHeader for MockSection {
        fn get_name_as_string(&self) -> String {
            ".text".to_string()
        }
        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            Arc::new(MockElfHeader { is32_bit: true })
        }
        fn get_address(&self) -> i64 {
            0
        }
        fn get_flags(&self) -> i64 {
            0
        }
        fn get_logical_size(&self) -> i64 {
            0
        }
    }

    /// A relocation table holding a fixed list of `(offset, type)` pairs.
    struct MockRelocationTable {
        has_addend: bool,
        entries: Vec<(i64, i32)>,
        with_section: bool,
    }

    impl MockRelocationTable {
        fn empty() -> Self {
            MockRelocationTable { has_addend: false, entries: Vec::new(), with_section: false }
        }
    }

    impl ElfRelocationTable for MockRelocationTable {
        fn has_addend_relocations(&self) -> bool {
            self.has_addend
        }
        fn get_associated_symbol_table(&self) -> Option<Arc<dyn ElfSymbolTable>> {
            None
        }
        fn get_relocations(&self) -> Vec<Box<dyn ElfRelocation>> {
            self.entries
                .iter()
                .enumerate()
                .map(|(i, (offset, type_id))| {
                    Box::new(MockRelocation {
                        offset: *offset,
                        type_id: *type_id,
                        relocation_index: i as i32,
                        ..MockRelocation::default()
                    }) as Box<dyn ElfRelocation>
                })
                .collect()
        }
        fn get_section_to_be_relocated(&self) -> Option<Arc<dyn ElfSectionHeader>> {
            self.with_section.then(|| Arc::new(MockSection) as Arc<dyn ElfSectionHeader>)
        }
    }

    // ---------------------------------------------------------------- fixtures

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn address(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    fn context_with(helper: Arc<MockLoadHelper>) -> MipsElfRelocationContext {
        MipsElfRelocationContext::new(None, helper, Arc::new(HashMap::new()))
    }

    /// A string table that answers the same name for every offset.
    struct FixedStringTable(&'static str);

    impl crate::format::seam_stubs::ElfStringTable for FixedStringTable {
        fn read_string(
            &self,
            _reader: &dyn crate::app::util::bin::binary_reader::BinaryReader,
            _string_offset: i64,
        ) -> String {
            self.0.to_string()
        }
    }

    /// An `Elf32_Sym` (`st_name`, `st_value`, `st_size`, `st_info`, `st_other`, `st_shndx`,
    /// little endian) parsed and then given `name` through its string table, which is the only
    /// way an `ElfSymbol` acquires a name.
    fn named_symbol(name: &'static str) -> ElfSymbol {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // st_name
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // st_value
        bytes.extend_from_slice(&4u32.to_le_bytes()); // st_size
        bytes.push(STB_GLOBAL << 4 | STT_FUNC); // st_info
        bytes.push(0); // st_other
        bytes.extend_from_slice(&SHN_UNDEF.to_le_bytes()); // st_shndx

        let mut reader = VecReader::new(bytes);
        let mut symbol = ElfSymbol::parse(&mut reader, 1, &MockElfHeader { is32_bit: true })
            .expect("symbol entry parses");
        symbol.init_symbol_name(&reader, &FixedStringTable(name));
        symbol
    }

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            self.0
                .get(start..start + length)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            unimplemented!()
        }
    }

    /// Smallest little-endian [`BinaryReader`] over a byte vector; the crate has no concrete
    /// reader yet.
    struct VecReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        current_index: u64,
    }

    impl VecReader {
        fn new(data: Vec<u8>) -> Self {
            VecReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                current_index: 0,
            }
        }
    }

    impl BinaryReader for VecReader {
        fn length(&self) -> std::io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            std::mem::replace(&mut self.current_index, index)
        }
        fn is_little_endian(&self) -> bool {
            true
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> std::io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> std::io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(VecReader {
                provider: Rc::clone(&self.provider),
                current_index: new_index,
            })
        }
    }

    // ---------------------------------------------------------------- tests

    /// A GOT entry is allocated at the start of the linkage block, and a second request for the
    /// same symbol value returns the very same entry (Java's `gotMap` hit), while a different
    /// symbol value advances by one pointer (4 bytes in this 32-bit space).
    #[test]
    fn section_got_entries_are_allocated_once_per_symbol_value() {
        let helper = Arc::new(MockLoadHelper {
            linkage_block: Some(AddressRange::new(address(0x10_0000), address(0x10_ffff))),
            ..MockLoadHelper::new()
        });
        let context = context_with(helper.clone());

        let first = context.get_section_got_address(0x1234).expect("GOT entry allocated");
        assert_eq!(first, address(0x10_0000));
        // Same symbol value -> same entry.
        assert_eq!(context.get_section_got_address(0x1234), Some(address(0x10_0000)));
        // Different symbol value -> next pointer-sized slot.
        assert_eq!(context.get_section_got_address(0x5678), Some(address(0x10_0004)));

        // Java logs the fabricated block and the GP derived from it. (The first message is the
        // inherited "no relocation handler" notice, this context being built without one.)
        let messages = helper.helper_log.lock().unwrap();
        assert_eq!(
            messages.last().map(String::as_str),
            Some("Created %got block required for relocation processing (gp=0x107ff0)")
        );
    }

    /// With no linkage block available, Java sets `sectionGotAddress` to `NO_ADDRESS`, logs the
    /// failure, and every GOT request answers null.
    #[test]
    fn section_got_allocation_failure_is_logged_and_yields_no_entries() {
        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(helper.clone());

        assert_eq!(context.get_section_got_address(0x1234), None);
        assert_eq!(
            helper.helper_log.lock().unwrap().last().map(String::as_str),
            Some("Failed to allocate %got block required for relocation processing")
        );
    }

    /// `gp` is defined as 0x7ff0 bytes into the GOT, and is -1 when no GOT could be fabricated
    /// (the `_mips_gp_value` symbol being undefined in both cases).
    #[test]
    fn gp_value_is_the_got_base_plus_0x7ff0() {
        let helper = Arc::new(MockLoadHelper {
            linkage_block: Some(AddressRange::new(address(0x10_0000), address(0x10_ffff))),
            ..MockLoadHelper::new()
        });
        assert_eq!(context_with(helper).get_gp_value(), 0x10_7ff0);

        let helper = Arc::new(MockLoadHelper::new());
        assert_eq!(context_with(helper).get_gp_value(), -1);
        // No `_mips_gp_value`/`_mips_gp0_value` symbol is defined by the mock program.
        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(helper);
        assert_eq!(context.get_adjusted_gp_value(), -1);
        assert_eq!(context.get_gp0_value(), -1);
    }

    /// The GOT block name is `%got` + the name of the section being relocated.
    #[test]
    fn section_got_block_is_named_after_the_relocated_section() {
        let helper = Arc::new(MockLoadHelper::new());
        let mut context = context_with(helper);
        assert_eq!(context.get_section_got_name(), "%got");

        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            with_section: true,
            ..MockRelocationTable::empty()
        }));
        assert_eq!(context.get_section_got_name(), "%got.text");
    }

    /// Java's `nextRelocationHasSameOffset`: true only when the following entry targets the same
    /// offset and is not `R_MIPS_NONE`.
    #[test]
    fn next_relocation_has_same_offset_matches_java() {
        let helper = Arc::new(MockLoadHelper::new());
        let mut context = context_with(helper);

        let r_mips_hi16 = MipsElfRelocationType::R_MIPS_HI16.type_id_value();
        let r_mips_lo16 = MipsElfRelocationType::R_MIPS_LO16.type_id_value();
        let r_mips_none = MipsElfRelocationType::R_MIPS_NONE.type_id_value();

        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            entries: vec![
                (0x100, r_mips_hi16), // 0: followed by LO16 at the same offset
                (0x100, r_mips_lo16), // 1: followed by a different offset
                (0x200, r_mips_hi16), // 2: followed by NONE at the same offset
                (0x200, r_mips_none), // 3: last entry
            ],
            ..MockRelocationTable::empty()
        }));

        let at = |index: i32| MockRelocation {
            relocation_index: index,
            ..MockRelocation::default()
        };
        assert!(context.next_relocation_has_same_offset(&at(0)));
        assert!(!context.next_relocation_has_same_offset(&at(1)));
        // Same offset, but the follower is R_MIPS_NONE.
        assert!(!context.next_relocation_has_same_offset(&at(2)));
        // Last entry, and an unknown index.
        assert!(!context.next_relocation_has_same_offset(&at(3)));
        assert!(!context.next_relocation_has_same_offset(&at(-1)));
    }

    /// Java's `extractAddend`: an addend must be extracted only for a REL-style table, and never
    /// while a saved addend is being carried over from the previous relocation.
    #[test]
    fn extract_addend_also_honours_the_saved_addend() {
        let helper = Arc::new(MockLoadHelper::new());
        let mut context = context_with(helper);

        context.start_relocation_table_processing(Arc::new(MockRelocationTable::empty()));
        assert!(context.extract_addend());

        context.use_saved_addend.set(true);
        assert!(!context.extract_addend());

        context.use_saved_addend.set(false);
        context.start_relocation_table_processing(Arc::new(MockRelocationTable {
            has_addend: true,
            ..MockRelocationTable::empty()
        }));
        assert!(!context.extract_addend());
    }

    /// `__gnu_local_gp` resolves to the adjusted GP value rather than to its placement; every
    /// other symbol keeps the inherited behaviour (the addressable word offset of its placement).
    #[test]
    fn gnu_local_gp_symbol_value_is_the_adjusted_gp_value() {
        let gnu_local_gp = named_symbol(GNU_LOCAL_GP_SYMBOL);
        let ordinary = named_symbol("memcpy");

        // Both symbols are placed, so the inherited lookup would answer 0x1234 for either.
        let mut symbol_map = HashMap::new();
        symbol_map.insert(gnu_local_gp.clone(), address(0x1234));
        symbol_map.insert(ordinary.clone(), address(0x1234));

        let context = MipsElfRelocationContext::new(
            None,
            Arc::new(MockLoadHelper::new()),
            Arc::new(symbol_map),
        );

        assert_eq!(context.get_symbol_value(&ordinary), 0x1234);
        // The mock program defines no `_mips_gp_value`, so the adjusted GP value is -1 -- and the
        // placement is deliberately ignored.
        assert_eq!(context.get_adjusted_gp_value(), -1);
        assert_eq!(context.get_symbol_value(&gnu_local_gp), -1);
    }

    /// `endRelocationTableProcessing` clears the deferred lists and every piece of section GOT
    /// state, and does not leave a saved addend behind for the next table.
    #[test]
    fn end_relocation_table_processing_resets_the_context() {
        let helper = Arc::new(MockLoadHelper {
            linkage_block: Some(AddressRange::new(address(0x10_0000), address(0x10_ffff))),
            ..MockLoadHelper::new()
        });
        let mut context = context_with(helper);
        context.start_relocation_table_processing(Arc::new(MockRelocationTable::empty()));

        context.add_hi16_relocation(MipsDeferredRelocation {
            reloc_type: MipsElfRelocationType::R_MIPS_HI16,
            elf_symbol: Some(ElfSymbol::new()),
            reloc_addr: address(0x2000),
            old_value: 0,
            addend: 0,
            is_gp_disp: false,
        });
        context.add_got16_relocation(MipsDeferredRelocation {
            reloc_type: MipsElfRelocationType::R_MIPS_GOT16,
            elf_symbol: None,
            reloc_addr: address(0x2004),
            old_value: 0,
            addend: 0,
            is_gp_disp: false,
        });
        assert!(context.get_section_got_address(0x1234).is_some());
        context.use_saved_addend.set(true);
        context.saved_addend_has_error.set(true);

        context.end_relocation_table_processing();

        assert!(context.hi16_list.borrow().is_empty());
        assert!(context.got16_list.borrow().is_empty());
        assert!(!context.use_saved_addend.get());
        assert!(!context.saved_addend_has_error.get());
        assert!(context.got_map.borrow().is_empty());
        assert_eq!(
            *context.section_got_address.borrow(),
            SectionGotAddress::Unallocated
        );
        assert!(context.last_section_got_entry_address.borrow().is_none());
        // The inherited reset still ran.
        assert!(context.base().relocation_table().is_none());
    }

    /// A relocation type of 0 is skipped without consulting the handler (which is absent here).
    #[test]
    fn relocation_type_zero_is_skipped() {
        let helper = Arc::new(MockLoadHelper::new());
        let context = context_with(helper);

        let result = context
            .process_relocation_for_symbol(
                &MockRelocation::default(),
                &ElfSymbol::new(),
                &address(0x2000),
            )
            .expect("no error");
        assert_eq!(result, RelocationResult::SKIPPED);
    }

    /// The MIPS handler stub is wired into the base context, so the inherited accessors see it.
    #[test]
    fn handler_is_shared_with_the_base_context() {
        struct StubHandler;

        impl ElfRelocationHandler for StubHandler {
            fn relocate(
                &self,
                _context: &dyn ElfRelocationContext,
                _relocation: &dyn ElfRelocation,
                _relocation_address: &Address,
            ) -> Result<RelocationResult, RelocationProcessingError> {
                unimplemented!("not exercised by this test")
            }
            fn mark_as_error(
                &self,
                _program: &dyn Program,
                _relocation_address: &Address,
                _type_id: i32,
                _symbol_name: Option<&str>,
                _symbol_index: i32,
                _msg: &str,
                _log: &dyn MessageLog,
            ) {
            }
            fn mark_as_warning(
                &self,
                _program: &dyn Program,
                _relocation_address: &Address,
                _type_id: i32,
                _symbol_name: Option<&str>,
                _symbol_index: i32,
                _msg: &str,
                _log: &dyn MessageLog,
            ) {
            }
        }

        impl AbstractElfRelocationHandler<MipsElfRelocationType> for StubHandler {
            fn relocate(
                &self,
                _elf_relocation_context: &dyn ElfRelocationContext,
                _relocation: &dyn ElfRelocation,
                _relocation_type: MipsElfRelocationType,
                _relocation_address: &Address,
                _elf_symbol: &ElfSymbol,
                _symbol_addr: Option<&Address>,
                _symbol_value: i64,
                _symbol_name: Option<&str>,
            ) -> Result<RelocationResult, MemoryAccessException> {
                unimplemented!("not exercised by this test")
            }
        }

        impl MipsElfRelocationHandler for StubHandler {
            fn as_elf_relocation_handler(self: Arc<Self>) -> Arc<dyn ElfRelocationHandler> {
                self
            }
            fn get_relocation_type(&self, type_id: i32) -> Option<MipsElfRelocationType> {
                (type_id == MipsElfRelocationType::R_MIPS_HI16.type_id_value())
                    .then_some(MipsElfRelocationType::R_MIPS_HI16)
            }
            fn mark_as_undefined(
                &self,
                _program: &dyn Program,
                _relocation_address: &Address,
                _type_id: i32,
                _symbol_name: Option<&str>,
                _symbol_index: i32,
                _log: &dyn MessageLog,
            ) {
            }
        }

        let helper = Arc::new(MockLoadHelper::new());
        let context = MipsElfRelocationContext::new(
            Some(Arc::new(StubHandler)),
            helper.clone(),
            Arc::new(HashMap::new()),
        );

        assert!(context.base().has_relocation_handler());
        // No "handler not found" message was logged at construction.
        assert!(helper.helper_log.lock().unwrap().is_empty());
    }
}
