//! Port of `ghidra.app.util.opinion.UnixAoutProgramLoader`.
//!
//! Drives everything that turns a parsed UNIX a.out header into a loaded `Program`: building the
//! file's four tables, sizing `.bss` for `N_UNDF` symbols, creating the memory blocks, laying down
//! symbols and functions, applying relocations, and marking up the on-disk structures.
//!
//! # Departures from the Java class
//!
//! * The a.out header and its three tables (`UnixAoutHeader`, `UnixAoutStringTable`,
//!   `UnixAoutSymbolTable`, `UnixAoutRelocationTable`) and `UnixAoutRelocation` are not ported yet
//!   -- this loader is the reason they come up at all -- so they are modeled as placeholders in
//!   [`format::seam_stubs`](crate::format::seam_stubs), along with the table constructors
//!   [`build_tables`](UnixAoutProgramLoader::build_tables) calls. `MemoryBlockUtils`' two
//!   block-creating statics are likewise placeholders in
//!   [`app::seam_stubs::memory_block_utils`](crate::app::seam_stubs::memory_block_utils). All of
//!   those placeholders are `unimplemented!()`, so the block-creating and markup phases panic if
//!   actually reached today; the loader's own logic (table construction order, `.bss` sizing,
//!   address arithmetic, relocation evaluation, symbol/alias handling) is ported in full.
//! * `UnixAoutSymbol` is already ported, so its real type is used
//!   ([`crate::format::unixaout::unix_aout_symbol`]). Its `name` is `Option<String>` there, where
//!   Java's is a nullable `String`; `createFunction` takes the same nullable name through
//!   unchanged, while `createLabel` -- whose ported signature takes `&str` -- receives `""` for an
//!   unnamed symbol, leaving the symbol table to reject it exactly as Java's does for `null`.
//! * `loadSections` inlines `byteProvider.getInputStream(0)` + `MonitoredInputStream` +
//!   `Memory.createFileBytes`; the ported [`Memory`] trait has no `createFileBytes`, so this port
//!   calls [`memory_block_utils::create_file_bytes`], which is the same three steps packaged as
//!   the `MemoryBlockUtils` static Java offers for exactly this purpose.
//! * `AddressSpace.OTHER_SPACE` is a Java static on an otherwise-ported class; it is reproduced
//!   here as the private [`other_space`] singleton (see its docs).
//! * `DataConverter.getInstance(boolean)` is likewise unported; the two ported unit structs
//!   [`BigEndianDataConverter`]/[`LittleEndianDataConverter`] stand in for its two singletons.
//! * `applyRelocations` reads and writes the relocated bytes through [`Memory`] rather than
//!   through the `MemoryBlock` Java uses: the ported `MemoryBlock` is only reachable behind an
//!   `Arc`, so its `&mut self` `set_bytes` cannot be called. Both address the same bytes.
//! * `applyRelocations(long baseAddr, MemoryBlock, UnixAoutRelocationTable)` never reads
//!   `baseAddr`, and its other two parameters are always this loader's own state, so
//!   [`apply_relocations`](UnixAoutProgramLoader::apply_relocations) takes just a
//!   [`RelocationSection`] selector and looks both up itself. That also keeps the relocation table
//!   (a field) from being borrowed across the mutations the body makes to `program` (another
//!   field).
//! * Java dereferences `bssBlock`/`externalBlock` unconditionally in `loadSymbols`' `N_UNDF` arm
//!   (an NPE if the block is missing). Here a missing block leaves the symbol unplaced and skips
//!   it, without consuming an external slot or `.bss` space.
//! * Java's `loadAout` wraps five checked exceptions in an unchecked `RuntimeException` and lets
//!   `IOException`/`CancelledException` through; this port reports every one of them as a variant
//!   of [`LoadAoutError`] instead. [`LoadAoutError::MissingProgramComponent`] additionally covers
//!   the managers Java reaches through `Program` without a null check.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, OnceLock};

use thiserror::Error;

use crate::app::seam_stubs::{memory_block_utils, MessageLog};
use crate::format::seam_stubs::{
    unix_aout_tables, UnixAoutHeader, UnixAoutRelocation, UnixAoutRelocationTable,
    UnixAoutStringTable, UnixAoutSymbolTable,
};
use crate::format::unixaout::unix_aout_symbol::{SymbolKind, SymbolType, UnixAoutSymbol};
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::model::address::{
    Address, AddressOutOfBoundsException, AddressOverflowException, AddressSet, AddressSpace,
    AddressSpaceType,
};
use crate::program::model::listing::listing::CreateFunctionError;
use crate::program::model::listing::Program;
use crate::program::model::mem::memory_block::EXTERNAL_BLOCK_NAME;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::reloc::relocation::RelocationStatus;
use crate::program::model::symbol::SourceType;
use crate::program::util::code_unit_insertion_exception::CodeUnitInsertionException;
use crate::util::big_endian_data_converter::BigEndianDataConverter;
use crate::util::data_converter::DataConverter;
use crate::util::exception::{CancelledException, DuplicateNameException, InvalidInputException};
use crate::util::little_endian_data_converter::LittleEndianDataConverter;
use crate::util::task::TaskMonitor;

/// Name of the block holding the executable's `.text` section.
pub const DOT_TEXT: &str = ".text";
/// Name of the block holding the executable's `.data` section.
pub const DOT_DATA: &str = ".data";
/// Name of the block holding the executable's `.bss` section.
pub const DOT_BSS: &str = ".bss";
/// Name of the block holding the `.text` relocation table.
pub const DOT_REL_TEXT: &str = ".rel.text";
/// Name of the block holding the `.data` relocation table.
pub const DOT_REL_DATA: &str = ".rel.data";
/// Name of the block holding the string table.
pub const DOT_STRTAB: &str = ".strtab";
/// Name of the block holding the symbol table.
pub const DOT_SYMTAB: &str = ".symtab";

/// Name of the block the a.out header itself is marked up in, when it is not part of `.text`.
const AOUT_HEADER_BLOCK_NAME: &str = "_aoutHeader";

/// Smallest `EXTERNAL` block this loader will create (64K).
const EXTERNAL_BLOCK_MIN_SIZE: i64 = 0x10000;

/// Which of the two relocation tables [`UnixAoutProgramLoader::apply_relocations`] should apply.
///
/// Stands in for the `(MemoryBlock targetBlock, UnixAoutRelocationTable relTable)` pair Java's
/// `applyRelocations` takes; each variant names one of the two calls `loadAout` makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationSection {
    /// `.rel.text`, applied to `.text`.
    Text,
    /// `.rel.data`, applied to `.data`.
    Data,
}

impl RelocationSection {
    /// Name of the block this section's relocations are applied to.
    fn target_block_name(self) -> &'static str {
        match self {
            RelocationSection::Text => DOT_TEXT,
            RelocationSection::Data => DOT_DATA,
        }
    }
}

/// Everything [`UnixAoutProgramLoader::load_aout`] can fail with.
///
/// Java throws `IOException`/`CancelledException` and wraps `AddressOverflowException`,
/// `InvalidInputException`, `CodeUnitInsertionException`, `DuplicateNameException` and
/// `MemoryAccessException` in a `RuntimeException`; all seven are reported here instead.
#[derive(Debug, Error)]
pub enum LoadAoutError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    #[error(transparent)]
    AddressOutOfBounds(#[from] AddressOutOfBoundsException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error(transparent)]
    CodeUnitInsertion(#[from] CodeUnitInsertionException),
    #[error(transparent)]
    DuplicateName(#[from] DuplicateNameException),
    #[error(transparent)]
    MemoryAccess(#[from] MemoryAccessException),
    /// A `Program` component Java reaches for without a null check was absent.
    #[error("program has no {0}")]
    MissingProgramComponent(&'static str),
}

impl From<CreateFunctionError> for LoadAoutError {
    fn from(e: CreateFunctionError) -> Self {
        match e {
            CreateFunctionError::InvalidInput(e) => LoadAoutError::InvalidInput(e),
            // Every `applyRelocations`/`markupSections` caller catches this one itself; reaching
            // here means a caller that did not, which Java would also have propagated.
            CreateFunctionError::Overlapping(e) => {
                LoadAoutError::InvalidInput(InvalidInputException::with_message(e.message()))
            }
        }
    }
}

/// The address space non-loaded file structures (the header, string/symbol/relocation tables) are
/// marked up in.
///
/// Stands in for `AddressSpace.OTHER_SPACE`, a static on the otherwise-ported
/// [`AddressSpace`]: `new GenericAddressSpace("OTHER", 64, TYPE_OTHER, 0)`. Kept a singleton, as
/// the Java static is, so every block this loader puts there lands in the same space.
fn other_space() -> &'static Arc<AddressSpace> {
    static OTHER_SPACE: OnceLock<Arc<AddressSpace>> = OnceLock::new();
    OTHER_SPACE.get_or_init(|| AddressSpace::new("OTHER", 64, 1, AddressSpaceType::Other, 0))
}

/// Loads a UNIX a.out executable, described by an already-parsed header, into a `Program`.
pub struct UnixAoutProgramLoader<'a> {
    program: &'a mut dyn Program,
    monitor: &'a dyn TaskMonitor,
    log: &'a dyn MessageLog,
    header: &'a dyn UnixAoutHeader,

    file_bytes: Option<Arc<dyn FileBytes>>,

    rel_text: Option<Box<dyn UnixAoutRelocationTable>>,
    rel_data: Option<Box<dyn UnixAoutRelocationTable>>,
    symtab: Option<Box<dyn UnixAoutSymbolTable>>,
    strtab: Option<Box<dyn UnixAoutStringTable>>,

    /// `N_UNDF` symbols with a non-zero value, keyed by name; the value is the size to reserve.
    ///
    /// A `BTreeMap` rather than Java's `HashMap` so the `.bss` padding is summed in a stable
    /// order. Unnamed symbols share the empty-string key, as Java's share the `null` key.
    possible_bss_symbols: BTreeMap<String, u64>,
    /// Extra `.bss` bytes reserved for [`possible_bss_symbols`](Self::possible_bss_symbols).
    /// Widened from Java's `int`, which silently truncates the `long` sizes it sums.
    extra_bss_size: i64,
    /// Number of `N_UNDF` symbols with a zero value, each of which gets an `EXTERNAL` slot.
    undefined_symbol_count: i64,
}

impl<'a> UnixAoutProgramLoader<'a> {
    /// Port of `UnixAoutProgramLoader(Program, UnixAoutHeader, TaskMonitor, MessageLog)`.
    pub fn new(
        program: &'a mut dyn Program,
        header: &'a dyn UnixAoutHeader,
        monitor: &'a dyn TaskMonitor,
        log: &'a dyn MessageLog,
    ) -> Self {
        UnixAoutProgramLoader {
            program,
            monitor,
            log,
            header,
            file_bytes: None,
            rel_text: None,
            rel_data: None,
            symtab: None,
            strtab: None,
            possible_bss_symbols: BTreeMap::new(),
            extra_bss_size: 0,
            undefined_symbol_count: 0,
        }
    }

    /// Port of `loadAout(long baseAddr)`.
    pub fn load_aout(&mut self, base_addr: i64) -> Result<(), LoadAoutError> {
        // `ByteProvider.getAbsolutePath()` is not part of the ported `ByteProvider` trait; its
        // Java default is the provider's file path, which is.
        let path = self
            .header
            .get_reader()
            .get_byte_provider()
            .borrow()
            .get_file()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        self.log.append_msg(&format!("----- Loading {path} -----"));
        self.log
            .append_msg(&format!("Found a.out type {}.", self.header.get_executable_type().name()));

        self.build_tables()?;
        self.preprocess_symbol_table();
        self.load_sections(base_addr)?;
        self.load_symbols()?;
        self.apply_relocations(RelocationSection::Text)?;
        self.apply_relocations(RelocationSection::Data)?;
        self.markup_sections()?;
        Ok(())
    }

    /// Port of the private `buildTables(ByteProvider)`. The provider parameter is unused in Java;
    /// every table is built from `header.getReader()` instead.
    fn build_tables(&mut self) -> io::Result<()> {
        if self.header.get_str_size() > 0 {
            self.strtab = Some(unix_aout_tables::new_string_table(
                self.header.get_reader(),
                self.header.get_str_offset(),
                self.header.get_str_size(),
            )?);
        }
        if self.header.get_sym_size() > 0 {
            self.symtab = Some(unix_aout_tables::new_symbol_table(
                self.header.get_reader(),
                self.header.get_sym_offset(),
                self.header.get_sym_size(),
                self.strtab.as_deref(),
                self.log,
            )?);
        }
        if self.header.get_text_reloc_size() > 0 {
            self.rel_text = Some(unix_aout_tables::new_relocation_table(
                self.header.get_reader(),
                self.header.get_text_reloc_offset(),
                self.header.get_text_reloc_size(),
                self.symtab.as_deref(),
            )?);
        }
        if self.header.get_data_reloc_size() > 0 {
            self.rel_data = Some(unix_aout_tables::new_relocation_table(
                self.header.get_reader(),
                self.header.get_data_reloc_offset(),
                self.header.get_data_reloc_size(),
                self.symtab.as_deref(),
            )?);
        }
        Ok(())
    }

    /// Port of the private `preprocessSymbolTable()`.
    fn preprocess_symbol_table(&mut self) {
        let Some(symbols) = self.symbols() else {
            return;
        };

        let mut found_stabs = false;
        for symbol in &symbols {
            match symbol.symbol_type {
                SymbolType::NUndf => {
                    if symbol.value > 0 {
                        // This is a special case given by the A.out spec: if the linker cannot
                        // find this symbol in any of the other binary files, then the fact that it
                        // is marked as N_UNDF but has a non-zero value means that its value should
                        // be interpreted as a size, and the linker should reserve space in .bss
                        // for it.
                        self.possible_bss_symbols
                            .insert(symbol.name.clone().unwrap_or_default(), symbol.value);
                    } else {
                        self.undefined_symbol_count += 1;
                    }
                }
                SymbolType::NStab => {
                    if !found_stabs {
                        found_stabs = true;
                        self.log.append_msg_from(DOT_SYMTAB, "File contains STABS.");
                    }
                }
                _ => {}
            }
        }

        for value in self.possible_bss_symbols.values() {
            self.extra_bss_size += *value as i64;
        }

        if self.extra_bss_size > 0 {
            self.log.append_msg_from(
                DOT_BSS,
                &format!("Added {} bytes for N_UNDF symbols.", self.extra_bss_size),
            );
        }
    }

    /// Port of the private `loadSections(long baseAddr, ByteProvider)`.
    fn load_sections(&mut self, base_addr: i64) -> Result<(), LoadAoutError> {
        self.monitor.set_message("Loading FileBytes...");

        let provider = self.header.get_reader().get_byte_provider();
        let file_bytes = memory_block_utils::create_file_bytes(self.program, &provider, self.monitor)?;
        self.file_bytes = Some(Arc::clone(&file_bytes));

        let default_address_space = self
            .program
            .get_address_factory()
            .and_then(|f| f.get_default_address_space())
            .ok_or(LoadAoutError::MissingProgramComponent("default address space"))?;
        let other_address = other_space().min_address();
        let mut next_free_address = default_address_space.checked_address(0)?;

        let header = self.header;

        if header.get_text_offset() != 0 || header.get_text_size() < 32 {
            memory_block_utils::create_initialized_block(
                self.program,
                true,
                AOUT_HEADER_BLOCK_NAME,
                &other_address,
                &file_bytes,
                0,
                32,
                None,
                None,
                false,
                false,
                false,
                self.log,
            )?;
        }
        if header.get_text_size() > 0 {
            let address =
                default_address_space.checked_address(base_addr + header.get_text_addr())?;
            next_free_address = address.add(header.get_text_size())?;
            memory_block_utils::create_initialized_block(
                self.program,
                false,
                DOT_TEXT,
                &address,
                &file_bytes,
                header.get_text_offset(),
                header.get_text_size(),
                None,
                None,
                true,
                true,
                true,
                self.log,
            )?;
        }
        if header.get_data_size() > 0 {
            let address =
                default_address_space.checked_address(base_addr + header.get_data_addr())?;
            next_free_address = address.add(header.get_data_size())?;
            memory_block_utils::create_initialized_block(
                self.program,
                false,
                DOT_DATA,
                &address,
                &file_bytes,
                header.get_data_offset(),
                header.get_data_size(),
                None,
                None,
                true,
                true,
                false,
                self.log,
            )?;
        }
        if header.get_bss_size() + self.extra_bss_size > 0 {
            let address =
                default_address_space.checked_address(base_addr + header.get_bss_addr())?;
            next_free_address = address.add(header.get_bss_size() + self.extra_bss_size)?;
            memory_block_utils::create_uninitialized_block(
                self.program,
                false,
                DOT_BSS,
                &address,
                header.get_bss_size() + self.extra_bss_size,
                None,
                None,
                true,
                true,
                false,
                self.log,
            );
        }
        if self.undefined_symbol_count > 0 {
            let mut external_section_size = self.undefined_symbol_count * 4;
            if external_section_size < EXTERNAL_BLOCK_MIN_SIZE {
                external_section_size = EXTERNAL_BLOCK_MIN_SIZE;
            }
            let external_block = memory_block_utils::create_uninitialized_block(
                self.program,
                false,
                EXTERNAL_BLOCK_NAME,
                &next_free_address,
                external_section_size,
                None,
                None,
                false,
                false,
                false,
                self.log,
            );
            if let Some(mut external_block) = external_block {
                external_block.set_artificial(true);
            }
        }
        if header.get_str_size() > 0 {
            memory_block_utils::create_initialized_block(
                self.program,
                true,
                DOT_STRTAB,
                &other_address,
                &file_bytes,
                header.get_str_offset(),
                header.get_str_size(),
                None,
                None,
                false,
                false,
                false,
                self.log,
            )?;
        }
        if header.get_sym_size() > 0 {
            memory_block_utils::create_initialized_block(
                self.program,
                true,
                DOT_SYMTAB,
                &other_address,
                &file_bytes,
                header.get_sym_offset(),
                header.get_sym_size(),
                None,
                None,
                false,
                false,
                false,
                self.log,
            )?;
        }
        if header.get_text_reloc_size() > 0 {
            memory_block_utils::create_initialized_block(
                self.program,
                true,
                DOT_REL_TEXT,
                &other_address,
                &file_bytes,
                header.get_text_reloc_offset(),
                header.get_text_reloc_size(),
                None,
                None,
                false,
                false,
                false,
                self.log,
            )?;
        }
        if header.get_data_reloc_size() > 0 {
            memory_block_utils::create_initialized_block(
                self.program,
                true,
                DOT_REL_DATA,
                &other_address,
                &file_bytes,
                header.get_data_reloc_offset(),
                header.get_data_reloc_size(),
                None,
                None,
                false,
                false,
                false,
                self.log,
            )?;
        }

        Ok(())
    }

    /// Port of the private `loadSymbols()`.
    fn load_symbols(&mut self) -> Result<(), LoadAoutError> {
        self.monitor.set_message("Loading symbols...");

        let Some(symbols) = self.symbols() else {
            return Ok(());
        };

        let memory = self
            .program
            .get_memory()
            .ok_or(LoadAoutError::MissingProgramComponent("memory"))?;
        let text_start = memory.get_block_by_name(DOT_TEXT).map(|b| b.get_start());
        let data_start = memory.get_block_by_name(DOT_DATA).map(|b| b.get_start());
        let bss_start = memory.get_block_by_name(DOT_BSS).map(|b| b.get_start());
        let bss_end = memory.get_block_by_name(DOT_BSS).map(|b| b.get_end());
        let external_start = memory.get_block_by_name(EXTERNAL_BLOCK_NAME).map(|b| b.get_start());
        drop(memory);

        let mut extra_bss_offset: i64 = 0;
        let mut undefined_symbol_idx: i64 = 0;
        let mut aliases: Vec<String> = Vec::new();

        for symbol in &symbols {
            // `address`/`block` are set together in Java; the block is only ever used for its
            // name in the log message below, so it is carried as that name here.
            let mut placement: Option<(Address, &'static str)> = None;

            match symbol.symbol_type {
                SymbolType::NText => {
                    placement = Self::place(text_start.as_ref(), symbol.value, DOT_TEXT)?;
                }
                SymbolType::NData => {
                    placement = Self::place(data_start.as_ref(), symbol.value, DOT_DATA)?;
                }
                SymbolType::NBss => {
                    placement = Self::place(bss_start.as_ref(), symbol.value, DOT_BSS)?;
                }
                SymbolType::NUndf => {
                    if symbol.value > 0 {
                        if let Some(end) = bss_end.as_ref() {
                            placement = Some((end.add(extra_bss_offset)?, DOT_BSS));
                            extra_bss_offset += symbol.value as i64;
                        }
                    } else if let Some(start) = external_start.as_ref() {
                        let address = start.add(undefined_symbol_idx * 4)?;
                        undefined_symbol_idx += 1;
                        self.symbol_table()?.add_external_entry_point(&address)?;
                        placement = Some((address, EXTERNAL_BLOCK_NAME));
                    }
                }
                SymbolType::NIndr => {
                    aliases.push(symbol.name.clone().unwrap_or_default());
                }
                SymbolType::NAbs
                | SymbolType::NFn
                | SymbolType::NStab
                | SymbolType::Unknown => {
                    aliases.clear();
                }
            }

            let Some((address, block_name)) = placement else {
                continue;
            };

            let name = symbol.name.as_deref();
            match symbol.kind {
                SymbolKind::AuxFunc => {
                    let body = AddressSet::from_address(address.clone());
                    let created = self.function_manager()?.create_function(
                        name,
                        address.clone(),
                        &body,
                        SourceType::Imported,
                    );
                    if let Err(e) = created {
                        match e {
                            CreateFunctionError::Overlapping(_) => {
                                self.log.append_msg_from(
                                    block_name,
                                    &format!(
                                        "Failed to create function {} @ {}, creating symbol instead.",
                                        name.unwrap_or_default(),
                                        address
                                    ),
                                );
                                self.symbol_table()?.create_label(
                                    &address,
                                    name.unwrap_or_default(),
                                    SourceType::Imported,
                                )?;
                            }
                            other => return Err(other.into()),
                        }
                    }
                }
                _ => {
                    let label = self.symbol_table()?.create_label(
                        &address,
                        name.unwrap_or_default(),
                        SourceType::Imported,
                    )?;
                    if symbol.is_ext {
                        let id = label.get_id();
                        self.symbol_table()?.set_primary_symbol(id)?;
                    }
                }
            }

            for alias in &aliases {
                self.symbol_table()?.create_label(&address, alias, SourceType::Imported)?;
            }

            aliases.clear();
        }

        Ok(())
    }

    /// Port of the private `applyRelocations(long, MemoryBlock, UnixAoutRelocationTable)`. See the
    /// module docs for why it selects its inputs rather than being handed them.
    fn apply_relocations(&mut self, section: RelocationSection) -> Result<(), LoadAoutError> {
        let table = match section {
            RelocationSection::Text => self.rel_text.as_deref(),
            RelocationSection::Data => self.rel_data.as_deref(),
        };
        let Some(relocations) =
            table.map(|t| t.iterator().copied().collect::<Vec<UnixAoutRelocation>>())
        else {
            return Ok(());
        };

        let target_block_name = section.target_block_name();
        let memory = self
            .program
            .get_memory()
            .ok_or(LoadAoutError::MissingProgramComponent("memory"))?;
        let Some(target_block) = memory.get_block_by_name(target_block_name) else {
            return Ok(());
        };
        let target_start = target_block.get_start();

        self.monitor
            .set_message(&format!("Applying relocations for section {target_block_name}..."));

        let big_endian = self
            .program
            .get_language()
            .ok_or(LoadAoutError::MissingProgramComponent("language"))?
            .is_big_endian();
        let big = BigEndianDataConverter;
        let little = LittleEndianDataConverter;
        let dc: &dyn DataConverter = if big_endian { &big } else { &little };

        let text_start = memory.get_block_by_name(DOT_TEXT).map(|b| b.get_start());
        let data_start = memory.get_block_by_name(DOT_DATA).map(|b| b.get_start());
        let bss_start = memory.get_block_by_name(DOT_BSS).map(|b| b.get_start());

        // Both the relocation-table row and the extern-symbol lookup below need the symbol's
        // name, and `getSymbolName`'s extern branch is guarded by the same
        // `extern && symbolNum < symtab.size()` condition the lookup uses. Resolved up front so
        // the symbol table (a field) is not borrowed while `program` (another) is mutated.
        let symtab_size = self.symtab.as_ref().map_or(0, |s| s.size());
        let symbol_names: Vec<Option<String>> = relocations
            .iter()
            .map(|r| r.get_symbol_name(self.symtab.as_deref()))
            .collect();

        for (idx, relocation) in relocations.iter().enumerate() {
            let target_address = target_start.add(relocation.address as i64)?;

            let pointer_length = relocation.pointer_length as usize;
            let mut original_bytes = vec![0u8; pointer_length];
            let read = memory.get_bytes(&target_address, &mut original_bytes);
            if read != pointer_length {
                return Err(MemoryAccessException::new(format!(
                    "Unable to read {pointer_length} bytes at {target_address}"
                ))
                .into());
            }
            let addend = dc.get_value_at(&original_bytes, 0, pointer_length) as i64;

            let mut value: Option<i64> = None;
            let mut status = RelocationStatus::Failure;

            if relocation.base_relative
                || relocation.jmp_table
                || relocation.relative
                || relocation.copy
            {
                status = RelocationStatus::Unsupported;
            } else if relocation.r#extern && u64::from(relocation.symbol_num) < symtab_size {
                if let Some(name) = symbol_names[idx].as_deref() {
                    let symbols = self.symbol_table()?.get_global_symbols(name)?;
                    value = symbols.first().map(|s| s.get_address().offset());
                }
            } else if !relocation.r#extern {
                value = match relocation.symbol_num {
                    4 => text_start.as_ref().map(Address::offset),
                    6 => data_start.as_ref().map(Address::offset),
                    8 => bss_start.as_ref().map(Address::offset),
                    _ => None,
                };
            }

            if let Some(mut value) = value {
                if relocation.pc_relative_addressing {
                    // Addend is relative to start of target section.
                    value -= target_start.offset();
                }

                // Apply relocation.
                let mut new_bytes = vec![0u8; pointer_length];
                dc.put_value_at(
                    value.wrapping_add(addend) as u64,
                    pointer_length,
                    &mut new_bytes,
                    0,
                );
                self.program
                    .get_memory_mut()
                    .ok_or(LoadAoutError::MissingProgramComponent("memory"))?
                    .set_bytes(&target_address, &new_bytes)?;

                status = RelocationStatus::Applied;
            }

            if status != RelocationStatus::Applied {
                self.log.append_msg_from(
                    target_block_name,
                    &format!(
                        "Failed to apply relocation entry {idx} with type 0x{:02x} @ {}.",
                        relocation.flags, target_address
                    ),
                );
            }

            let symbol_name = symbol_names[idx].clone();
            self.program
                .get_relocation_table()
                .ok_or(LoadAoutError::MissingProgramComponent("relocation table"))?
                .add(
                    target_address,
                    status,
                    i32::from(relocation.flags),
                    vec![i64::from(relocation.symbol_num)],
                    Some(original_bytes),
                    symbol_name,
                );
        }

        Ok(())
    }

    /// Port of the private `markupSections()`.
    fn markup_sections(&mut self) -> Result<(), LoadAoutError> {
        let default_address_space = self
            .program
            .get_address_factory()
            .and_then(|f| f.get_default_address_space())
            .ok_or(LoadAoutError::MissingProgramComponent("default address space"))?;
        let header = self.header;

        self.monitor.set_message("Marking up header...");

        // Markup header.
        let memory = self
            .program
            .get_memory()
            .ok_or(LoadAoutError::MissingProgramComponent("memory"))?;
        let aout_header_start =
            memory.get_block_by_name(AOUT_HEADER_BLOCK_NAME).map(|b| b.get_start());
        let text_block = memory.get_block_by_name(DOT_TEXT);
        let header_address = if let Some(start) = aout_header_start {
            Some(start)
        } else if text_block.is_some()
            && header.get_text_offset() == 0
            && header.get_text_size() >= 32
        {
            text_block.map(|b| b.get_start())
        } else {
            None
        };
        drop(memory);
        if let Some(header_address) = header_address {
            header.markup(self.program, &header_address)?;
        }

        // Markup entrypoint.
        if header.get_entry_point() != 0 {
            let address = default_address_space.checked_address(header.get_entry_point())?;
            let body = AddressSet::from_address(address.clone());
            let created = self.function_manager()?.create_function(
                Some("entry"),
                address.clone(),
                &body,
                SourceType::Imported,
            );
            if let Err(e) = created {
                match e {
                    CreateFunctionError::Overlapping(_) => {
                        // Java passes this format string to `appendMsg` unformatted, so the `%s`
                        // reaches the log literally; reproduced verbatim.
                        self.log.append_msg_from(
                            DOT_TEXT,
                            "Failed to create entrypoint function @ %s, creating symbol instead.",
                        );
                        self.symbol_table()?.create_label(
                            &address,
                            "entry",
                            SourceType::Imported,
                        )?;
                    }
                    other => return Err(other.into()),
                }
            }
        }

        self.monitor.set_message("Marking up relocation tables...");

        self.markup_block(DOT_REL_TEXT, RelocationSection::Text)?;
        self.markup_block(DOT_REL_DATA, RelocationSection::Data)?;

        self.monitor.set_message("Marking up symbol table...");

        if let Some(block) = self.block(DOT_SYMTAB)? {
            if let Some(symtab) = self.symtab.as_deref() {
                symtab.markup(self.program, block.as_ref())?;
            }
        }

        self.monitor.set_message("Marking up string table...");

        if let Some(block) = self.block(DOT_STRTAB)? {
            if let Some(strtab) = self.strtab.as_deref() {
                strtab.markup(self.program, block.as_ref())?;
            }
        }

        Ok(())
    }

    /// `relText.markup(program, relTextBlock)` / `relData.markup(program, relDataBlock)`.
    fn markup_block(
        &mut self,
        block_name: &str,
        section: RelocationSection,
    ) -> Result<(), LoadAoutError> {
        let Some(block) = self.block(block_name)? else {
            return Ok(());
        };
        let table = match section {
            RelocationSection::Text => self.rel_text.as_deref(),
            RelocationSection::Data => self.rel_data.as_deref(),
        };
        if let Some(table) = table {
            table.markup(self.program, block.as_ref())?;
        }
        Ok(())
    }

    /// The program's block named `name`, if it has one.
    fn block(
        &self,
        name: &str,
    ) -> Result<Option<Arc<dyn crate::program::model::mem::MemoryBlock>>, LoadAoutError> {
        let memory = self
            .program
            .get_memory()
            .ok_or(LoadAoutError::MissingProgramComponent("memory"))?;
        Ok(memory.get_block_by_name(name))
    }

    /// The symbols of the a.out symbol table, or `None` when the file has none. Java iterates the
    /// table in place; the entries are copied out here so the table (a field) is not borrowed
    /// while `program` (another) is mutated.
    fn symbols(&self) -> Option<Vec<UnixAoutSymbol>> {
        self.symtab.as_ref().map(|s| s.iterator().cloned().collect())
    }

    /// `block.getStart().add(symbol.value)`, or `None` when the block is absent.
    fn place(
        block_start: Option<&Address>,
        value: u64,
        block_name: &'static str,
    ) -> Result<Option<(Address, &'static str)>, AddressOverflowException> {
        match block_start {
            Some(start) => Ok(Some((start.add(value as i64)?, block_name))),
            None => Ok(None),
        }
    }

    fn symbol_table(
        &mut self,
    ) -> Result<&mut dyn crate::program::model::symbol::SymbolTable, LoadAoutError> {
        self.program
            .get_symbol_table()
            .ok_or(LoadAoutError::MissingProgramComponent("symbol table"))
    }

    fn function_manager(
        &mut self,
    ) -> Result<&mut dyn crate::program::model::listing::FunctionManager, LoadAoutError> {
        self.program
            .get_function_manager()
            .ok_or(LoadAoutError::MissingProgramComponent("function manager"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::util::task::DummyMonitor;
    use std::sync::Mutex;

    /// A `MessageLog` that keeps every message, so tests can assert on what the loader reported.
    #[derive(Default)]
    struct RecordingLog {
        messages: Mutex<Vec<String>>,
    }

    impl RecordingLog {
        fn messages(&self) -> Vec<String> {
            self.messages.lock().unwrap().clone()
        }
    }

    impl MessageLog for RecordingLog {
        fn append_msg(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
    }

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "a.out".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:32:default".to_string()
        }
    }

    /// A symbol table over a fixed list of symbols, standing in for the unported real one.
    struct FakeSymbolTable {
        symbols: Vec<UnixAoutSymbol>,
    }

    impl UnixAoutSymbolTable for FakeSymbolTable {
        fn iterator(&self) -> Box<dyn Iterator<Item = &UnixAoutSymbol> + '_> {
            Box::new(self.symbols.iter())
        }
        fn get(&self, symbol_num: usize) -> Option<&UnixAoutSymbol> {
            self.symbols.get(symbol_num)
        }
        fn size(&self) -> u64 {
            self.symbols.len() as u64
        }
        fn markup(
            &self,
            _program: &mut dyn Program,
            _block: &dyn crate::program::model::mem::MemoryBlock,
        ) -> io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
    }

    /// A header whose every accessor reports zero / `UNKNOWN`; individual tests do not depend on
    /// its geometry, only on the loader's own bookkeeping.
    struct ZeroHeader;

    impl UnixAoutHeader for ZeroHeader {
        fn get_reader(&self) -> crate::filesystem::ghidra::g_binary_reader::GBinaryReader {
            unimplemented!("not exercised by these tests")
        }
        fn get_executable_type(&self) -> crate::format::seam_stubs::AoutType {
            crate::format::seam_stubs::AoutType::Unknown
        }
        fn get_text_size(&self) -> i64 {
            0
        }
        fn get_data_size(&self) -> i64 {
            0
        }
        fn get_bss_size(&self) -> i64 {
            0
        }
        fn get_sym_size(&self) -> i64 {
            0
        }
        fn get_str_size(&self) -> i64 {
            0
        }
        fn get_entry_point(&self) -> i64 {
            0
        }
        fn get_text_reloc_size(&self) -> i64 {
            0
        }
        fn get_data_reloc_size(&self) -> i64 {
            0
        }
        fn get_text_offset(&self) -> i64 {
            0
        }
        fn get_data_offset(&self) -> i64 {
            0
        }
        fn get_text_reloc_offset(&self) -> i64 {
            0
        }
        fn get_data_reloc_offset(&self) -> i64 {
            0
        }
        fn get_sym_offset(&self) -> i64 {
            0
        }
        fn get_str_offset(&self) -> i64 {
            0
        }
        fn get_text_addr(&self) -> i64 {
            0
        }
        fn get_data_addr(&self) -> i64 {
            0
        }
        fn get_bss_addr(&self) -> i64 {
            0
        }
        fn markup(&self, _program: &mut dyn Program, _address: &Address) -> io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
    }

    /// Builds a symbol whose raw `n_type`/`n_other` bytes decode to the requested classification.
    fn symbol(name: &str, type_byte: u8, value: u64) -> UnixAoutSymbol {
        let mut sym = UnixAoutSymbol::new(0, type_byte, 0, 0, value);
        sym.name = Some(name.to_string());
        sym
    }

    #[test]
    fn constants_match_java_section_names() {
        assert_eq!(DOT_TEXT, ".text");
        assert_eq!(DOT_DATA, ".data");
        assert_eq!(DOT_BSS, ".bss");
        assert_eq!(DOT_REL_TEXT, ".rel.text");
        assert_eq!(DOT_REL_DATA, ".rel.data");
        assert_eq!(DOT_STRTAB, ".strtab");
        assert_eq!(DOT_SYMTAB, ".symtab");
        assert_eq!(EXTERNAL_BLOCK_MIN_SIZE, 65536);
    }

    #[test]
    fn preprocess_symbol_table_sizes_bss_and_counts_undefined_symbols() {
        // N_UNDF (type byte 0x00, ext bit set -> 0x01) entries: a non-zero value asks the linker
        // to reserve that many .bss bytes; a zero value is a truly undefined symbol needing an
        // EXTERNAL slot. A N_TEXT (0x04) entry touches neither counter.
        let symtab = FakeSymbolTable {
            symbols: vec![
                symbol("common_a", 0x01, 16),
                symbol("common_b", 0x01, 24),
                symbol("undefined_a", 0x01, 0),
                symbol("undefined_b", 0x01, 0),
                symbol("undefined_c", 0x01, 0),
                symbol("some_func", 0x04, 0x1000),
            ],
        };

        let mut program = MockProgram;
        let log = RecordingLog::default();
        let monitor = DummyMonitor;
        let header = ZeroHeader;
        let mut loader = UnixAoutProgramLoader::new(&mut program, &header, &monitor, &log);
        loader.symtab = Some(Box::new(symtab));

        loader.preprocess_symbol_table();

        assert_eq!(loader.extra_bss_size, 40);
        assert_eq!(loader.undefined_symbol_count, 3);
        assert_eq!(loader.possible_bss_symbols.get("common_a"), Some(&16));
        assert_eq!(loader.possible_bss_symbols.get("common_b"), Some(&24));
        assert!(!loader.possible_bss_symbols.contains_key("undefined_a"));
        assert_eq!(
            log.messages(),
            vec![".bss: Added 40 bytes for N_UNDF symbols.".to_string()]
        );
    }

    #[test]
    fn preprocess_symbol_table_reports_stabs_once() {
        // Type bytes >= 0x20 decode to N_STAB; only the first one is reported.
        let symtab = FakeSymbolTable {
            symbols: vec![symbol("s1", 0x20, 0), symbol("s2", 0x24, 0), symbol("s3", 0x64, 0)],
        };

        let mut program = MockProgram;
        let log = RecordingLog::default();
        let monitor = DummyMonitor;
        let header = ZeroHeader;
        let mut loader = UnixAoutProgramLoader::new(&mut program, &header, &monitor, &log);
        loader.symtab = Some(Box::new(symtab));

        loader.preprocess_symbol_table();

        assert_eq!(log.messages(), vec![".symtab: File contains STABS.".to_string()]);
        assert_eq!(loader.extra_bss_size, 0);
        assert_eq!(loader.undefined_symbol_count, 0);
    }

    #[test]
    fn preprocess_symbol_table_merges_same_named_undefined_symbols() {
        // Java keys `possibleBssSymbols` by name, so a repeated name keeps only the last size.
        let symtab = FakeSymbolTable {
            symbols: vec![symbol("common", 0x01, 8), symbol("common", 0x01, 32)],
        };

        let mut program = MockProgram;
        let log = RecordingLog::default();
        let monitor = DummyMonitor;
        let header = ZeroHeader;
        let mut loader = UnixAoutProgramLoader::new(&mut program, &header, &monitor, &log);
        loader.symtab = Some(Box::new(symtab));

        loader.preprocess_symbol_table();

        assert_eq!(loader.possible_bss_symbols.len(), 1);
        assert_eq!(loader.extra_bss_size, 32);
    }

    #[test]
    fn preprocess_symbol_table_without_a_symbol_table_is_a_no_op() {
        let mut program = MockProgram;
        let log = RecordingLog::default();
        let monitor = DummyMonitor;
        let header = ZeroHeader;
        let mut loader = UnixAoutProgramLoader::new(&mut program, &header, &monitor, &log);

        loader.preprocess_symbol_table();

        assert_eq!(loader.extra_bss_size, 0);
        assert_eq!(loader.undefined_symbol_count, 0);
        assert!(log.messages().is_empty());
    }

    #[test]
    fn build_tables_builds_nothing_when_every_section_is_empty() {
        // Each table is built only for a non-zero size; `ZeroHeader` reports none, so this must
        // not reach the (unimplemented) table constructors.
        let mut program = MockProgram;
        let log = RecordingLog::default();
        let monitor = DummyMonitor;
        let header = ZeroHeader;
        let mut loader = UnixAoutProgramLoader::new(&mut program, &header, &monitor, &log);

        loader.build_tables().unwrap();

        assert!(loader.strtab.is_none());
        assert!(loader.symtab.is_none());
        assert!(loader.rel_text.is_none());
        assert!(loader.rel_data.is_none());
    }

    #[test]
    fn relocation_symbol_name_resolves_extern_and_section_symbols() {
        let symtab = FakeSymbolTable { symbols: vec![symbol("printf", 0x01, 0)] };

        let extern_reloc = UnixAoutRelocation { r#extern: true, symbol_num: 0, ..Default::default() };
        assert_eq!(
            extern_reloc.get_symbol_name(Some(&symtab)),
            Some("printf".to_string())
        );

        // Out of range: Java's `symbolNum < symtab.size()` guard fails, yielding null.
        let out_of_range =
            UnixAoutRelocation { r#extern: true, symbol_num: 7, ..Default::default() };
        assert_eq!(out_of_range.get_symbol_name(Some(&symtab)), None);

        // Non-extern relocations name the section their symbol number selects.
        for (symbol_num, expected) in [(4u32, DOT_TEXT), (6, DOT_DATA), (8, DOT_BSS)] {
            let reloc = UnixAoutRelocation { r#extern: false, symbol_num, ..Default::default() };
            assert_eq!(reloc.get_symbol_name(Some(&symtab)), Some(expected.to_string()));
        }
        let unknown_section =
            UnixAoutRelocation { r#extern: false, symbol_num: 5, ..Default::default() };
        assert_eq!(unknown_section.get_symbol_name(Some(&symtab)), None);
    }

    #[test]
    fn apply_relocations_without_a_table_is_a_no_op() {
        let mut program = MockProgram;
        let log = RecordingLog::default();
        let monitor = DummyMonitor;
        let header = ZeroHeader;
        let mut loader = UnixAoutProgramLoader::new(&mut program, &header, &monitor, &log);

        // `MockProgram` has no memory, which would be a `MissingProgramComponent` error -- so
        // reaching `Ok` proves the null-table check short-circuits first, as Java's does.
        loader.apply_relocations(RelocationSection::Text).unwrap();
        loader.apply_relocations(RelocationSection::Data).unwrap();
    }

    #[test]
    fn other_space_is_a_singleton_named_other() {
        let space = other_space();
        assert_eq!(space.name(), "OTHER");
        assert_eq!(space.size(), 64);
        assert!(Arc::ptr_eq(space, other_space()));
    }
}
