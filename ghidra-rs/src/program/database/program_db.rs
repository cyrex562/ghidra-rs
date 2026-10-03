use crate::framework::db::DBHandle;
use crate::framework::model::DomainObject;
use crate::program::database::code::listing_store::{CodeUnitSummary, DefinedData, ListingStore};
use crate::program::model::data::data_type::DataType;
use crate::program::util::CodeUnitInsertionException;
use crate::program::database::map::AddressMapDB;
use crate::program::database::mem::MemoryMapDB;
use crate::program::database::references::{ReferenceRecord, ReferenceStore};
use crate::program::database::symbol::namespace_manager::NamespaceManagerDB;
use crate::program::database::symbol::SymbolManagerDB;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::{ManagerGuard, Program};
use crate::program::model::address::factory::AddressFactory;
use crate::program::model::address::Address;
use crate::program::model::mem::Memory;
use crate::program::database::symbol::DynamicSymbolSource;
use crate::program::database::symbol::dynamic_symbol::{DataLabelPrefix, DynamicDataLabel};
use crate::program::model::listing::code_unit_format::{CodeUnitFormat, DefaultCodeUnitFormat};
use crate::program::model::listing::Instruction;
use crate::program::disassemble::DisassembledInstruction;
use crate::program::model::symbol::{ReferenceManager, SymbolTable};
use crate::program::seam_stubs::CodeUnitFormatOptions;
use std::io;
use std::sync::{Arc, RwLock};

pub struct ProgramDB {
    db_handle: Arc<RwLock<DBHandle>>,
    name: String,
    language: Arc<SleighLanguage>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    memory: Arc<RwLock<MemoryMapDB>>,
    namespace_mgr: Arc<RwLock<NamespaceManagerDB>>,
    symbol_mgr: Arc<RwLock<SymbolManagerDB>>,
    /// The program's code units (Java's `CodeManager` store).
    listing: Arc<RwLock<ListingStore>>,
    /// The program's references (Java's `ReferenceDBManager` store), shared with the listing,
    /// which maintains its instructions' default references in it.
    references: Arc<RwLock<ReferenceStore>>,
    /// The program's image base (Java keeps it in `AddressMapDB` and the program's stored
    /// options). A new program's image base is address 0 of the default space.
    image_base: RwLock<Address>,
}

impl ProgramDB {
    pub fn new(name: String, language: Arc<SleighLanguage>) -> io::Result<Self> {
        let db_handle = Arc::new(RwLock::new(DBHandle::new()?));
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(
            db_handle.clone(),
            language.get_address_factory(),
        )?));
        let memory = MemoryMapDB::new(
            db_handle.clone(),
            addr_map.clone(),
            crate::framework::data::OpenMode::Create,
            language.is_big_endian(),
            &crate::util::task::DummyMonitor,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let namespace_mgr = Arc::new(RwLock::new(NamespaceManagerDB::new(
            db_handle.clone(),
            addr_map.clone(),
        )?));

        let symbol_mgr = Arc::new(RwLock::new(SymbolManagerDB::new(
            db_handle.clone(),
            addr_map.clone(),
            namespace_mgr.clone(),
            true,
        )?));

        let image_base = language
            .get_address_factory()
            .get_default_address_space()
            .map(|space| space.address(0))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "language has no default address space"))?;

        let references = Arc::new(RwLock::new(ReferenceStore::new()));
        let listing = Arc::new(RwLock::new(ListingStore::with_references(language.clone(), references.clone())));
        symbol_mgr.write().unwrap_or_else(|p| p.into_inner()).set_dynamic_symbol_source(Arc::new(ProgramDynamicSymbols {
            listing: listing.clone(),
            references: references.clone(),
        }));
        Ok(Self {
            listing,
            references,
            image_base: RwLock::new(image_base),
            db_handle,
            name,
            language,
            addr_map,
            memory,
            namespace_mgr,
            symbol_mgr,
        })
    }

    pub fn get_memory(&self) -> Arc<RwLock<MemoryMapDB>> {
        self.memory.clone()
    }

    pub fn get_symbol_table(&self) -> Arc<RwLock<SymbolManagerDB>> {
        self.symbol_mgr.clone()
    }

    pub fn get_language(&self) -> &Arc<SleighLanguage> {
        &self.language
    }

    /// The program's code-unit store, shared: lock it for writing to create or clear
    /// instructions, for reading to query them (with [`ProgramDB::get_memory`] for their bytes).
    pub fn get_listing_store(&self) -> Arc<RwLock<ListingStore>> {
        self.listing.clone()
    }

    /// The program's reference store, shared: lock it for reading to query references, for
    /// writing to add or remove them. Lock order: never take the listing lock while holding this
    /// one (creating or clearing instructions takes the listing lock, then this one).
    pub fn get_reference_store(&self) -> Arc<RwLock<ReferenceStore>> {
        self.references.clone()
    }

    /// The references from `from`, in the order added (see
    /// [`ReferenceStore::references_from`]). Takes the reference read lock for the call.
    pub fn references_from(&self, from: &Address) -> Vec<ReferenceRecord> {
        self.references.read().unwrap_or_else(|p| p.into_inner()).references_from(from)
    }

    /// The references to `to`, in the order added (see [`ReferenceStore::references_to`]).
    /// Takes the reference read lock for the call.
    pub fn references_to(&self, to: &Address) -> Vec<ReferenceRecord> {
        self.references.read().unwrap_or_else(|p| p.into_inner()).references_to(to)
    }

    /// The code units intersecting `[start, end]`, in address order: instructions, defined data,
    /// and an undefined byte at every other memory address (see [`ListingStore::code_units`]). Takes
    /// the listing and memory read locks for the duration of the call.
    pub fn code_units(&self, start: &Address, end: &Address) -> Vec<CodeUnitSummary> {
        let listing = self.listing.read().unwrap_or_else(|p| p.into_inner());
        let memory = self.memory.read().unwrap_or_else(|p| p.into_inner());
        listing.code_units(&*memory, start, end).collect()
    }

    /// The instructions starting in `[start, end]`, in address order (see
    /// [`ListingStore::instruction_summaries`]). Takes the listing and memory read locks for the
    /// duration of the call.
    pub fn instruction_summaries(&self, start: &Address, end: &Address) -> Vec<CodeUnitSummary> {
        let listing = self.listing.read().unwrap_or_else(|p| p.into_inner());
        let memory = self.memory.read().unwrap_or_else(|p| p.into_inner());
        listing.instruction_summaries(&*memory, start, end).collect()
    }

    /// The defined data starting in `[start, end]`, in address order (see
    /// [`ListingStore::data_summaries`]): each with [`CodeUnitKind::Data`], the data type's
    /// mnemonic (`addr`, `dq`, ...) and its default value representation as the one operand.
    /// Takes the listing and memory read locks for the duration of the call.
    ///
    /// [`CodeUnitKind::Data`]: crate::program::database::code::listing_store::CodeUnitKind::Data
    pub fn data_summaries(&self, start: &Address, end: &Address) -> Vec<CodeUnitSummary> {
        let listing = self.listing.read().unwrap_or_else(|p| p.into_inner());
        let memory = self.memory.read().unwrap_or_else(|p| p.into_inner());
        listing.data_summaries(&*memory, start, end).collect()
    }

    /// Creates data of `data_type` at `address` (see [`ListingStore::create_data`]): Java's
    /// `Listing.createData(Address, DataType)`. Takes the listing write lock (and, for pointer
    /// data, the reference write lock under it) and the memory read lock.
    ///
    /// # Errors
    /// As [`ListingStore::create_data`].
    pub fn create_data(
        &self,
        address: &Address,
        data_type: Arc<dyn DataType>,
    ) -> Result<DefinedData, CodeUnitInsertionException> {
        let mut listing = self.listing.write().unwrap_or_else(|p| p.into_inner());
        let memory = self.memory.read().unwrap_or_else(|p| p.into_inner());
        listing.create_data(&*memory, address.clone(), data_type, -1)
    }

    /// The defined data starting at `address`, if any (a copy; see
    /// [`ListingStore::defined_data_at`]). Takes the listing read lock for the call.
    pub fn defined_data_at(&self, address: &Address) -> Option<DefinedData> {
        self.listing.read().unwrap_or_else(|p| p.into_inner()).defined_data_at(address).cloned()
    }
}

/// A code unit's text as the listing shows it: the mnemonic and operands through
/// `CodeUnitFormat` with the listing's default options, so operand addresses with a reference
/// read as the destination's symbol (stored or dynamic). See [`ProgramDB::operand_display`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandDisplay {
    /// `CodeUnitFormat.getMnemonicRepresentation`.
    pub mnemonic: String,
    /// `CodeUnitFormat.getOperandRepresentationString` of each operand, in order.
    pub operands: Vec<String>,
    /// The operand field: the operands laid out with the instruction's separators the way
    /// [`CodeUnitSummary::operand_text`] lays out the default representations
    /// (`qword ptr [DAT_00103fd8]`, `RAX,qword ptr [LAB_00101234]`).
    pub operand_field: String,
}

/// What [`SymbolManagerDB`] asks the program for dynamic symbols: the reference store's
/// reference levels and the listing's instructions and defined data. Each answer takes one store's read lock.
struct ProgramDynamicSymbols {
    listing: Arc<RwLock<ListingStore>>,
    references: Arc<RwLock<ReferenceStore>>,
}

impl DynamicSymbolSource for ProgramDynamicSymbols {
    fn reference_level(&self, addr: &Address) -> Option<i8> {
        self.references.read().unwrap_or_else(|p| p.into_inner()).reference_level(addr)
    }

    fn instruction_containing(&self, addr: &Address) -> Option<Address> {
        let listing = self.listing.read().unwrap_or_else(|p| p.into_inner());
        listing.instruction_containing(addr).map(|id| listing.record(id).address().clone())
    }

    /// The listing's defined data (its read lock, released), then its primary operand-0
    /// memory reference (the reference read lock).
    fn defined_data_containing(&self, addr: &Address) -> Option<DynamicDataLabel> {
        let (start, prefix) = {
            let listing = self.listing.read().unwrap_or_else(|p| p.into_inner());
            let data = listing.defined_data_containing(addr)?;
            let prefix = if data.is_pointer() {
                DataLabelPrefix::Pointer
            } else {
                DataLabelPrefix::Fixed(data.data_type().get_default_label_prefix())
            };
            (data.address().clone(), prefix)
        };
        let reference_target = self
            .references
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .primary_reference_from(&start, 0)
            .map(|r| crate::program::model::symbol::Reference::to_address(&r))
            .filter(|to| to.is_memory_address());
        Some(DynamicDataLabel { start, prefix, reference_target })
    }
}

impl ProgramDB {
    /// The instruction or defined data at `address` as the listing displays it
    /// (`CodeUnitFormat` with [`CodeUnitFormatOptions::browser_default`]): references on
    /// operands read as their destinations' symbols, a referenced address without one as its
    /// dynamic label (`LAB_`, `SUB_`, `DAT_`, ...), a READ of a pointer to a named symbol as
    /// `->` and that name. Defined data shows its data type's mnemonic (`addr`, `dq`) and one
    /// operand, `getDataValueRepresentation`: the symbol its primary reference reaches
    /// (`__libc_start_main` for a GOT pointer to that import), else its default value
    /// representation. `None` when no instruction or defined data starts at `address` (or an
    /// instruction's bytes can no longer be read).
    ///
    /// Takes the listing and memory read locks to build the instruction and releases them
    /// before formatting, which takes the reference, symbol, listing and memory locks in turn;
    /// do not call it while holding any of them.
    pub fn operand_display(self: &Arc<Self>, address: &Address) -> Option<OperandDisplay> {
        let instruction = {
            let listing = self.listing.read().unwrap_or_else(|p| p.into_inner());
            let memory = self.memory.read().unwrap_or_else(|p| p.into_inner());
            let Some(id) = listing.instruction_at(address) else {
                let summary = listing.defined_data_at(address)?.summary(&*memory, self.language.is_big_endian());
                drop(memory);
                drop(listing);
                return Some(self.data_operand_display(summary));
            };
            let program: Arc<dyn Program> = self.clone();
            listing.to_instruction(id, &*memory, Some(program), SleighLanguage::get_address_factory(&self.language))?
        };
        let format = DefaultCodeUnitFormat::with_options(CodeUnitFormatOptions::browser_default());
        Some(Self::instruction_operand_display(&format, &instruction))
    }

    /// [`operand_display`](Self::operand_display) of every instruction and defined data
    /// starting in `[start, end]`, in address order. Takes the listing and memory read locks
    /// once to build the range's code units and releases them before formatting (each operand's
    /// formatting takes the reference, symbol, listing and memory locks in turn, as
    /// `operand_display` does); do not call it while holding any of them.
    pub fn operand_displays(self: &Arc<Self>, start: &Address, end: &Address) -> Vec<(Address, OperandDisplay)> {
        let (instructions, data) = {
            let listing = self.listing.read().unwrap_or_else(|p| p.into_inner());
            let memory = self.memory.read().unwrap_or_else(|p| p.into_inner());
            let program: Arc<dyn Program> = self.clone();
            let factory = SleighLanguage::get_address_factory(&self.language);
            let instructions: Vec<(Address, DisassembledInstruction)> = listing
                .instructions_in(start, end)
                .filter_map(|id| {
                    let address = listing.record(id).address().clone();
                    let instruction = listing.to_instruction(id, &*memory, Some(program.clone()), factory.clone())?;
                    Some((address, instruction))
                })
                .collect();
            let big_endian = self.language.is_big_endian();
            let data: Vec<CodeUnitSummary> =
                listing.defined_data_in(start, end).map(|d| d.summary(&*memory, big_endian)).collect();
            (instructions, data)
        };
        let format = DefaultCodeUnitFormat::with_options(CodeUnitFormatOptions::browser_default());
        let mut shown: Vec<(Address, OperandDisplay)> = instructions
            .iter()
            .map(|(address, instruction)| (address.clone(), Self::instruction_operand_display(&format, instruction)))
            .collect();
        shown.extend(data.into_iter().map(|summary| (summary.address.clone(), self.data_operand_display(summary))));
        shown.sort_by(|a, b| a.0.cmp(&b.0));
        shown
    }

    /// An instruction's mnemonic, operands and operand field through `format`.
    fn instruction_operand_display(format: &DefaultCodeUnitFormat, instruction: &DisassembledInstruction) -> OperandDisplay {
        let mnemonic = format.get_mnemonic_representation(instruction);
        let instr: &dyn Instruction = instruction;
        let count = instr.get_num_operands();
        let operands: Vec<String> =
            (0..count).map(|i| format.get_operand_representation_string(instruction, i)).collect();
        let mut operand_field = instr.get_separator(0).unwrap_or_default();
        for (i, operand) in operands.iter().enumerate() {
            operand_field.push_str(operand);
            if let Some(separator) = instr.get_separator(i as i32 + 1) {
                operand_field.push_str(&separator);
            }
        }
        OperandDisplay { mnemonic, operands, operand_field }
    }
}

impl ProgramDB {
    /// `CodeUnitFormat.getDataValueRepresentation` for non-composite data under the browser
    /// options: a memory reference on operand 0 reads as the symbol it reaches (stored or
    /// dynamic; no namespace or offcut decoration yet), else the default value representation
    /// in `summary`. Takes the reference and symbol locks in turn.
    fn data_operand_display(&self, summary: CodeUnitSummary) -> OperandDisplay {
        let reference = self
            .references
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .primary_reference_from(&summary.address, 0);
        let label = reference.and_then(|reference| {
            let symbols = self.symbol_mgr.read().unwrap_or_else(|p| p.into_inner());
            symbols.get_symbol_for_reference(&reference).ok().flatten().map(|s| s.get_name().to_string())
        });
        let operand = label.unwrap_or(summary.operand_text);
        OperandDisplay { mnemonic: summary.mnemonic, operands: vec![operand.clone()], operand_field: operand }
    }
}

impl DomainObject for ProgramDB {
    /// A `ProgramDB` here is a local, unversioned database the caller owns outright, so -- as
    /// Java's `DomainObjectAdapterDB.hasExclusiveAccess` answers for a program with no shared
    /// checkout -- access is always exclusive.
    fn has_exclusive_access(&self) -> bool {
        true
    }
}

impl Program for ProgramDB {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_language_id(&self) -> String {
        self.language.get_id().to_string()
    }

    fn get_address_factory(&self) -> Option<std::sync::Arc<dyn crate::program::model::address::AddressFactory>> {
        Some(self.language.get_address_factory())
    }

    /// Delegates to the memory map, as Java's `ProgramDB` does.
    fn get_loaded_and_initialized_address_set(&self) -> std::boxed::Box<dyn crate::program::model::address::AddressSetView> {
        Memory::get_loaded_and_initialized_address_set(&*self.memory.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// Delegates to the memory map, as Java's `ProgramDB` does.
    fn get_all_initialized_address_set(&self) -> std::boxed::Box<dyn crate::program::model::address::AddressSetView> {
        Memory::get_all_initialized_address_set(&*self.memory.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// The program's symbol table, write-locked for the life of the returned handle.
    ///
    /// Stands in for `ProgramDB.getSymbolTable()`. The symbol manager is already shared with the
    /// other managers as an `Arc<RwLock<_>>`, so the handle locks that same lock: a symbol created
    /// through it is visible through [`ProgramDB::get_symbol_table`]'s shared handle and through
    /// every later handle.
    fn get_symbol_table(&self) -> Option<ManagerGuard<'_, dyn SymbolTable>> {
        Some(ManagerGuard::write(&*self.symbol_mgr))
    }

    /// The program's reference store as a [`ReferenceManager`], write-locked for the life of
    /// the handle. Stands in for `ProgramDB.getReferenceManager()` (memory references only, see
    /// [`ReferenceStore`]'s `ReferenceManager` impl). Lock order: never ask for it while
    /// holding the reference store's lock, nor take the listing lock while holding it.
    fn get_reference_manager(&self) -> Option<ManagerGuard<'_, dyn ReferenceManager>> {
        Some(ManagerGuard::write(&*self.references))
    }

    /// Answers from the listing store (takes its read lock for the call).
    fn has_defined_data_at(&self, addr: &Address) -> bool {
        self.listing.read().unwrap_or_else(|p| p.into_inner()).defined_data_at(addr).is_some()
    }

    /// [`ProgramDB::create_data`] through the program seam.
    fn create_data(&self, addr: &Address, data_type: Arc<dyn DataType>) -> Result<(), CodeUnitInsertionException> {
        ProgramDB::create_data(self, addr, data_type).map(|_| ())
    }

    /// The program's memory, write-locked for the life of the returned handle. Stands in for
    /// `ProgramDB.getMemory()` where the caller modifies memory.
    fn get_memory_mut(&self) -> Option<ManagerGuard<'_, dyn Memory>> {
        Some(ManagerGuard::write(&*self.memory))
    }

    /// A read handle on the program's memory that does not keep the memory map alive (see
    /// [`MemoryMapDB::as_memory`]). Stands in for `ProgramDB.getMemory()` where the caller only
    /// reads.
    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        Some(MemoryMapDB::as_memory(&self.memory))
    }

    fn get_language(&self) -> Option<Arc<dyn crate::program::model::lang::Language>> {
        Some(self.language.clone())
    }

    fn get_image_base(&self) -> Option<Address> {
        Some(self.image_base.read().unwrap_or_else(|p| p.into_inner()).clone())
    }

    /// Mirrors `ProgramDB.setImageBase(Address, boolean)` for a program whose memory is still
    /// empty -- the case a loader hits, since it sets the image base before creating blocks.
    ///
    /// # Errors
    /// `InvalidInput` if `base` is not in the default address space (Java's
    /// `IllegalArgumentException`); `Unsupported` if blocks already exist, because relocating
    /// existing blocks to a new image base (Java's `MemoryMapDB.setImageBase` / key re-encoding
    /// in `AddressMapDB`) is not ported.
    fn set_image_base(&self, base: Address, commit: bool) -> io::Result<()> {
        let _ = commit;
        let mut image_base = self.image_base.write().unwrap_or_else(|p| p.into_inner());
        if *image_base == base {
            return Ok(());
        }
        let default_space = self.language.get_address_factory().get_default_address_space();
        if default_space.as_ref() != Some(base.space()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Image base must be in the default address space",
            ));
        }
        if !self.memory.read().unwrap_or_else(|p| p.into_inner()).get_blocks().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "changing the image base of a program with memory blocks is not supported",
            ));
        }
        *image_base = base;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::AddressFactory;
    use crate::program::model::address::Address;
    use crate::program::model::pcode::PackedDecode;
    use crate::program::model::symbol::{SourceType, SymbolTable};

    #[test]
    fn test_program_db_symbols() {
        let mut data = vec![];
        // <sleigh version="4" bigendian="false">
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        // <spaces defaultspace="ram">
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        // <space_other/>
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        // </spaces>
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        // <scope id="0" parent="0"/>
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        // </symbol_table>
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        // </sleigh>
        data.extend_from_slice(&[0xA0, 0x80 | 33]);

        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(
            vec![],
        ));
        let decoder = PackedDecode::new(factory, data);
        let language = Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap());

        let program = ProgramDB::new("test_prog".to_string(), language.clone()).unwrap();

        let space = language
            .get_address_factory()
            .get_address_space_by_name("ram")
            .unwrap();
        let addr = Address::new(space.clone(), 0x1000);

        {
            let symbol_table_arc = program.get_symbol_table();
            let mut symbol_table = symbol_table_arc.write().unwrap();
            symbol_table
                .create_label(&addr, "test_label", SourceType::UserDefined)
                .unwrap();
        }

        let symbol_table_arc = program.get_symbol_table();
        let symbol_table = symbol_table_arc.read().unwrap();
        let symbols = symbol_table.get_symbols(&addr).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].get_name(), "test_label");
    }

    fn test_program() -> (ProgramDB, Address) {
        let mut data = vec![];
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        data.extend_from_slice(&[0xA0, 0x80 | 33]);
        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(
            vec![],
        ));
        let decoder = PackedDecode::new(factory, data);
        let language = Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap());
        let space = language
            .get_address_factory()
            .get_address_space_by_name("ram")
            .unwrap();
        let program = ProgramDB::new("test_prog".to_string(), language).unwrap();
        (program, Address::new(space, 0x1000))
    }

    #[test]
    fn a_new_programs_memory_is_all_undefined_code_units() {
        let (program, addr) = test_program();
        program
            .get_memory()
            .write()
            .unwrap()
            .create_initialized_block("b", &addr, Some(&mut &[0x6a, 0x00][..]), 2, None, false)
            .unwrap();
        let units = program.code_units(&addr, &addr.add_wrap(5));
        assert_eq!(units.iter().map(|u| u.operand_text.as_str()).collect::<Vec<_>>(), vec!["6Ah", "00h"]);
        assert!(units.iter().all(|u| !u.is_instruction() && u.mnemonic == "??"));
        assert_eq!(program.get_listing_store().read().unwrap().num_instructions(), 0);
    }

    #[test]
    fn data_created_through_the_program_seam_is_answered_from_the_listing_store() {
        let (program, addr) = test_program();
        program
            .get_memory()
            .write()
            .unwrap()
            .create_initialized_block("b", &addr, Some(&mut &[0x04, 0x10, 0x00, 0x00, 0x6a][..]), 5, None, false) // little-endian 0x1004
            .unwrap();
        let pointer: Arc<dyn DataType> = Arc::new(
            crate::program::model::data::pointer_data_type::PointerDataType::new_with(None::<Arc<dyn DataType>>, 4, None)
                .unwrap(),
        );
        let seam: &dyn Program = &program;
        assert!(!seam.has_defined_data_at(&addr));
        seam.create_data(&addr, pointer.clone()).unwrap();
        assert!(seam.has_defined_data_at(&addr));
        assert!(!seam.has_defined_data_at(&addr.add_wrap(1)));
        assert_eq!(
            seam.create_data(&addr.add_wrap(2), pointer).unwrap_err().message(),
            "Insufficent memory at address ram:0x1002 (length: 4 bytes)"
        );
        let units = program.code_units(&addr, &addr.add_wrap(4));
        assert_eq!(units.len(), 2);
        assert!(units[0].is_defined_data());
        assert_eq!(program.data_summaries(&addr, &addr.add_wrap(4)), units[..1].to_vec());
        assert_eq!(program.defined_data_at(&addr).map(|d| d.length()), Some(4));
        // the pointer's default reference (to 0x1004), which its operand reads as
        assert_eq!(program.references_from(&addr).len(), 1);
        let program = Arc::new(program);
        let shown = program.operand_display(&addr).unwrap();
        assert_eq!((shown.mnemonic.as_str(), shown.operand_field.as_str()), ("addr", "DAT_00001004"));
        program
            .get_symbol_table()
            .write()
            .unwrap()
            .create_label(&addr.add_wrap(4), "target", SourceType::UserDefined)
            .unwrap();
        assert_eq!(program.operand_display(&addr).unwrap().operands, vec!["target".to_string()]);
        assert!(program.operand_display(&addr.add_wrap(1)).is_none());
        assert_eq!(
            program.operand_displays(&addr, &addr.add_wrap(4)),
            vec![(addr.clone(), program.operand_display(&addr).unwrap())]
        );
    }

    #[test]
    fn referenced_data_is_named_as_javas_dynamic_data_names() {
        use crate::program::model::symbol::RefType;
        let (program, addr) = test_program();
        // 0x1000: pointer -> 0x1008 ; 0x1004: pointer -> itself ; 0x1008: dword
        let bytes = [0x08, 0x10, 0, 0, 0x04, 0x10, 0, 0, 0x2a, 0, 0, 0];
        program.get_memory().write().unwrap().create_initialized_block("b", &addr, Some(&mut &bytes[..]), 12, None, false).unwrap();
        let pointer: Arc<dyn DataType> = Arc::new(
            crate::program::model::data::pointer_data_type::PointerDataType::new_with(None::<Arc<dyn DataType>>, 4, None)
                .unwrap(),
        );
        let dword: Arc<dyn DataType> = Arc::new(crate::program::model::data::dword_data_type::DWordDataType::new(None));
        program.create_data(&addr, pointer.clone()).unwrap();
        program.create_data(&addr.add_wrap(4), pointer).unwrap();
        program.create_data(&addr.add_wrap(8), dword).unwrap();
        // something (in the dword, but not at its start) reads the first pointer, and two bytes
        // into it
        for to in [addr.clone(), addr.add_wrap(2)] {
            program
                .get_reference_store()
                .write()
                .unwrap()
                .add_memory_reference(addr.add_wrap(11), to, RefType::Read, SourceType::UserDefined, 0)
                .unwrap();
        }
        let name = |offset: i64| {
            program.get_symbol_table().read().unwrap().get_primary_symbol(&addr.add_wrap(offset)).unwrap().map(|s| s.get_name().to_string())
        };
        assert_eq!(name(8).as_deref(), Some("DWORD_00001008"), "the dword the first pointer reaches");
        assert_eq!(name(0).as_deref(), Some("PTR_DWORD_00001000"));
        assert_eq!(name(2).as_deref(), Some("PTR_DWORD_00001000+2"));
        assert_eq!(name(4).as_deref(), Some("PTR_LOOP_00001004"));
        program.get_symbol_table().write().unwrap().create_label(&addr.add_wrap(8), "answer", SourceType::UserDefined).unwrap();
        assert_eq!(name(0).as_deref(), Some("PTR_answer_00001000"));
        program.get_symbol_table().write().unwrap().create_label(&addr, "table", SourceType::UserDefined).unwrap();
        assert_eq!(name(2).as_deref(), Some("table+2"));
    }

    #[test]
    fn program_db_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProgramDB>();
    }

    #[test]
    fn two_managers_can_be_held_at_once_from_a_shared_program() {
        let (program, addr) = test_program();
        let program: &dyn Program = &program;
        let mut symbol_table = program.get_symbol_table().expect("symbol table");
        let memory = program.get_memory_mut().expect("memory");
        symbol_table
            .create_label(&addr, "both_held", SourceType::UserDefined)
            .unwrap();
        assert!(memory.get_block(&addr).is_none());
        assert_eq!(symbol_table.get_symbols(&addr).unwrap().len(), 1);
    }

    #[test]
    fn mutation_through_one_handle_is_visible_through_the_next() {
        let (program, addr) = test_program();
        let shared: Arc<dyn Program> = Arc::new(program);
        let other_owner = Arc::clone(&shared);
        shared
            .get_symbol_table()
            .unwrap()
            .create_label(&addr, "via_first", SourceType::UserDefined)
            .unwrap();
        let symbols = other_owner.get_symbol_table().unwrap().get_symbols(&addr).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].get_name(), "via_first");
    }

    #[test]
    fn trait_handle_and_inherent_shared_handle_see_the_same_symbol_table() {
        let (program, addr) = test_program();
        Program::get_symbol_table(&program)
            .unwrap()
            .create_label(&addr, "trait_side", SourceType::UserDefined)
            .unwrap();
        let shared = program.get_symbol_table();
        let symbols = shared.read().unwrap().get_symbols(&addr).unwrap();
        assert_eq!(symbols[0].get_name(), "trait_side");
    }

    #[test]
    fn handles_can_be_used_from_other_threads() {
        let (program, addr) = test_program();
        let shared: Arc<dyn Program> = Arc::new(program);
        let workers: Vec<_> = (0..4)
            .map(|i| {
                let program = Arc::clone(&shared);
                let addr = addr.clone();
                std::thread::spawn(move || {
                    program
                        .get_symbol_table()
                        .unwrap()
                        .create_label(&addr, &format!("label_{i}"), SourceType::UserDefined)
                        .unwrap();
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(shared.get_symbol_table().unwrap().get_symbols(&addr).unwrap().len(), 4);
    }
}
