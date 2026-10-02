//! Port of `ghidra.app.util.opinion.ElfProgramBuilder` -- phase 1: program memory.
//!
//! `ElfProgramBuilder.loadElf` turns a parsed [`ElfHeader`] into a populated `Program`. This port
//! covers the memory half of Java's `load`:
//!
//! 1. finish parsing the header (`elf.parse()`),
//! 2. set the image base (from the "Image Base" option, else keep the program's),
//! 3. store the whole file as the program's `FileBytes`,
//! 4. add `unallocated_N` OTHER sections for non-zero file regions no segment/section covers,
//! 5. turn program headers and section headers into memory "sections" exactly as Java does
//!    (segment vs section precedence, fragmentation, PT_LOAD-only unless "Import Non-Loaded
//!    Data", the `.bss`-in-segment special case, relocatable-object section packing),
//! 6. resolve them into memory blocks through [`MemorySectionResolverBase`], and
//! 7. zero-extend PT_LOAD segments when there are no section headers.
//!
//! # Not yet ported (phase 2)
//!
//! Everything Java's `load` does after the blocks exist -- ELF header/program header/section
//! header/dynamic-table markup, string tables, symbol tables (`processSymbolTables`), the
//! processor extension's `processElf`/`processGotPlt`, relocations, entry points, imports, hash
//! tables, GNU notes, read-only adjustments, info producers -- plus `addProgramProperties` and
//! `setExecutableFormat`: the ported `ProgramDB` has no listing/data/function managers, program
//! options or relocation table to write them into. The [`ElfLoadHelper`] methods that only those
//! phases call log that they are unavailable and return their "failed" value.
//!
//! # Divergences
//!
//! * Overlay blocks: `MemoryMapDB` cannot create overlay spaces yet, so every block Java would
//!   place in an overlay -- all non-loaded (OTHER-space) segments/sections, including
//!   `unallocated_N`, and loaded chunks displaced by a conflict -- is logged as not created
//!   instead of aborting the load.
//! * `joinProgramTreeFragments` is skipped: `ProgramDB` has no program tree.
//! * There is no program transaction to start/end.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use thiserror::Error;

use crate::app::seam_stubs::Option;
use crate::app::util::bin::struct_converter::StructConverter;
use crate::app::util::importer::message_log::MessageLog;
use crate::app::util::memory_block_utils;
use crate::app::util::opinion::elf_loader_options_factory as options_factory;
use crate::app::util::opinion::memory_section_resolver::{
    MemorySectionError, MemorySectionResolver, MemorySectionResolverBase, ResolverError,
};
use crate::format::elf::elf_header::ElfHeader;
use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_program_header::ElfProgramHeader;
use crate::format::elf::elf_program_header_constants::{PT_LOAD, PT_NOTE, PT_NULL};
use crate::format::elf::elf_section_header::ElfSectionHeader;
use crate::format::elf::elf_section_header_constants::{SHT_NOBITS, SHT_NULL, SHT_PROGBITS};
use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::memory_loadable::MemoryLoadable;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::database::mem::memory_map_db::{GBYTE, MAX_BINARY_SIZE, MAX_BINARY_SIZE_GB, MAX_BLOCK_SIZE, MAX_BLOCK_SIZE_GB};
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::memory::CreateBlockError;
use crate::program::model::mem::memory_access_exception::MemoryAccessException;
use crate::program::model::mem::MemoryBlockHandle;
use crate::program::model::symbol::namespace::Namespace;
use crate::program::model::symbol::Symbol;
use crate::util::exception::{CancelledException, InvalidInputException};
use crate::util::msg::Msg;
use crate::util::seam_stubs::NumericUtilities;
use crate::util::task::TaskMonitor;

/// `ElfProgramBuilder.BLOCK_SOURCE_NAME`.
pub const BLOCK_SOURCE_NAME: &str = "Elf Loader";
/// `ElfProgramBuilder.PROCESS_ENTRY_CALLING_CONVENTION_NAME`.
pub const PROCESS_ENTRY_CALLING_CONVENTION_NAME: &str = "processEntry";

const SEGMENT_NAME_PREFIX: &str = "segment_";
const UNALLOCATED_NAME_PREFIX: &str = "unallocated_";

/// Which ELF header a memory section came from: Java keys sections by the `MemoryLoadable`
/// header object itself; here by its index in the header's program/section header table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfLoadable {
    Segment(usize),
    Section(usize),
}

/// What `loadElf` throws: Java's `IOException` / `CancelledException`.
#[derive(Debug, Error)]
pub enum ElfLoadError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

impl From<ResolverError> for ElfLoadError {
    fn from(e: ResolverError) -> Self {
        match e {
            ResolverError::Cancelled(c) => ElfLoadError::Cancelled(c),
            other => ElfLoadError::Io(io::Error::other(other.to_string())),
        }
    }
}

impl From<CreateBlockError> for ElfLoadError {
    fn from(e: CreateBlockError) -> Self {
        match e {
            CreateBlockError::Cancelled(c) => ElfLoadError::Cancelled(c),
            CreateBlockError::Io(e) => ElfLoadError::Io(e),
            other => ElfLoadError::Io(io::Error::other(other.to_string())),
        }
    }
}

/// `AddressSpace.OTHER_SPACE`.
fn other_space() -> &'static Arc<AddressSpace> {
    AddressSpace::other_space()
}

/// `AddressSpace.getTruncatedAddress(offset, true)`.
fn truncated_word_address(space: &Arc<AddressSpace>, word_offset: i64) -> Address {
    let byte_offset = space
        .truncate_addressable_word_offset(word_offset)
        .wrapping_mul(space.unit_size() as i64);
    space.address(byte_offset)
}

/// `AddressSpace.isValidRange(long, long)`.
fn is_valid_range(space: &Arc<AddressSpace>, byte_offset: i64, length: i64) -> bool {
    let Ok(start) = space.checked_address(byte_offset) else {
        return false;
    };
    length != 0 && start.add_no_wrap(length - 1).is_ok()
}

/// `Address.isNonLoadedMemoryAddress()`.
fn is_non_loaded_memory_address(addr: &Address) -> bool {
    addr.space().space_type() == AddressSpaceType::Other
}

/// `Address.toString(true)`.
fn addr_str(addr: &Address) -> String {
    addr.format(true, 16)
}

/// Java's `"" + string` for a nullable `String`.
fn or_null(s: std::option::Option<&str>) -> &str {
    s.unwrap_or("null")
}

/// Loads `elf` into `program`. Port of the static `ElfProgramBuilder.loadElf(ElfHeader, Program,
/// List<Option>, MessageLog, TaskMonitor)` (phase 1 -- see the module docs).
///
/// # Errors
/// An IO error from parsing/reading the image, or a cancelled `monitor`.
pub fn load_elf(
    elf: ElfHeader,
    program: Arc<dyn Program>,
    options: &[Box<dyn Option>],
    log: &Arc<MessageLog>,
    monitor: &dyn TaskMonitor,
) -> Result<(), ElfLoadError> {
    let mut builder = ElfProgramBuilder::new(elf, program, options, Arc::clone(log))?;
    builder.load(monitor)
}

/// Builds a program's memory from an ELF image. See the module docs.
pub struct ElfProgramBuilder<'a> {
    elf: ElfHeader,
    program: Arc<dyn Program>,
    options: &'a [Box<dyn Option>],
    log: Arc<MessageLog>,
    /// Cached data image base option (Java's nullable `dataImageBase`).
    data_image_base: Cell<std::option::Option<i64>>,
    file_bytes: std::option::Option<Arc<dyn FileBytes>>,
    /// The `MemorySectionResolver` superclass state. Taken out while it resolves, so the block
    /// hooks (which may call back into this builder) never see it borrowed.
    resolver: RefCell<MemorySectionResolverBase<ElfLoadable>>,
}

impl<'a> ElfProgramBuilder<'a> {
    /// Mirrors the protected constructor.
    ///
    /// # Errors
    /// `IllegalStateException` (as an IO error) if `program` already has memory blocks.
    pub fn new(
        elf: ElfHeader,
        program: Arc<dyn Program>,
        options: &'a [Box<dyn Option>],
        log: Arc<MessageLog>,
    ) -> Result<Self, ElfLoadError> {
        let resolver = MemorySectionResolverBase::new(program.as_ref())?;
        Ok(ElfProgramBuilder {
            elf,
            program,
            options,
            log,
            data_image_base: Cell::new(None),
            file_bytes: None,
            resolver: RefCell::new(resolver),
        })
    }

    /// Mirrors the protected `load(TaskMonitor)` up to the point the program's memory is
    /// complete (see the module docs for the rest).
    ///
    /// # Errors
    /// As for [`load_elf`].
    pub fn load(&mut self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        monitor.set_message("Completing ELF header parsing...");
        monitor.set_cancel_enabled(false);
        self.elf.parse()?;
        monitor.set_cancel_enabled(true);

        monitor.check_cancelled()?;
        self.set_image_base();

        self.create_file_bytes(monitor)?;

        self.adjust_segment_and_section_file_allocations(monitor)?;

        // process headers and define "section" within memory elfProgramBuilder
        self.process_program_headers(monitor)?;
        self.process_section_headers(monitor)?;

        // resolve segment/sections and create program memory blocks
        let mut resolver = std::mem::replace(&mut *self.resolver.borrow_mut(), MemorySectionResolverBase::empty());
        let resolved = resolver.resolve(self.program.as_ref(), &*self, monitor);
        *self.resolver.borrow_mut() = resolver;
        resolved?;

        if self.elf.get_section_header_count() == 0 {
            // create/expand segments to their fullsize if no sections are defined
            self.expand_program_header_blocks(monitor)?;
        }

        Ok(())
    }

    fn create_file_bytes(&mut self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        monitor.set_message("Loading FileBytes...");
        let provider = Arc::clone(&self.program);
        let file_bytes =
            memory_block_utils::create_file_bytes(provider.as_ref(), self.elf.get_byte_provider().as_ref(), monitor)?;
        self.file_bytes = Some(file_bytes);
        Ok(())
    }

    fn file_bytes(&self) -> &Arc<dyn FileBytes> {
        self.file_bytes.as_ref().expect("file bytes are created before any block")
    }

    /// Mirrors `adjustSegmentAndSectionFileAllocations`: adds non-zero file regions no segment,
    /// section or ELF header table covers as `unallocated_N` OTHER sections.
    fn adjust_segment_and_section_file_allocations(&mut self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        let provider = std::rc::Rc::clone(self.elf.get_byte_provider());
        let length = provider.length() as i64;

        // Identify file ranges not allocated to segments or sections. Java paints a `RangeMap`
        // (-1 unallocated, -2 segment, -3 section, -4 header) and keeps the maximal -1 runs;
        // those are exactly the file range minus every other painted range.
        let mut unallocated = FileRanges::new(length);

        let segments = self.elf.get_program_headers();
        let sections = self.elf.get_sections();

        monitor.set_message("Examining file allocations...");
        monitor.initialize((segments.len() + sections.len()) as i64);

        for segment in segments {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            let size = segment.get_file_size();
            if segment.get_type() == PT_NULL as i32 || segment.is_invalid_offset() || size <= 0 {
                continue;
            }
            let offset = segment.get_offset();
            unallocated.paint(offset, offset + size - 1); // -2: used by segment
        }

        for section in sections {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            let size = section.get_size();
            if section.get_type() == SHT_NULL as i32
                || section.get_type() == SHT_NOBITS as i32
                || section.is_invalid_offset()
                || size <= 0
            {
                continue;
            }
            let offset = section.get_offset();
            unallocated.paint(offset, offset + size - 1); // -3: used by section
        }

        // Ignore header regions which will always be allocated to blocks
        let elf_header_size = self
            .elf
            .to_data_type()
            .map(|dt| dt.get_length() as i64)
            .unwrap_or(if self.elf.is64_bit() { 64 } else { 52 });
        unallocated.paint(0, elf_header_size - 1); // -4: header block
        let program_header_size = self.elf.e_phentsize() as i64 * self.elf.get_program_header_count() as i64;
        if program_header_size != 0 {
            unallocated.paint(self.elf.e_phoff(), self.elf.e_phoff() + program_header_size - 1);
        }
        let section_header_size = self.elf.e_shentsize() as i64 * self.elf.get_section_header_count() as i64;
        if section_header_size != 0 {
            unallocated.paint(self.elf.e_shoff(), self.elf.e_shoff() + section_header_size - 1);
        }

        // Add unallocated non-zero file regions as OTHER blocks
        let ranges = unallocated.ranges;
        monitor.set_message("Identify unallocated file regions...");
        monitor.initialize(ranges.len() as i64);

        let mut unallocated_index = 0;
        for (start, end) in ranges {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            let length = end - start + 1;

            if Self::is_zero_filled_file_region(provider.as_ref(), start, length)? {
                continue;
            }

            let name = format!("{UNALLOCATED_NAME_PREFIX}{unallocated_index}");
            unallocated_index += 1;
            // an AddressOverflowException is ignored, as in Java
            let _ = self.resolver.borrow_mut().add_initialized_memory_section(
                None,
                start,
                length,
                &other_space().min_address(),
                Some(&name),
                false,
                false,
                false,
                None,
                false,
                false,
            );
        }
        Ok(())
    }

    fn is_zero_filled_file_region(
        provider: &dyn crate::app::util::bin::byte_provider::ByteProvider,
        start: i64,
        length: i64,
    ) -> io::Result<bool> {
        let buf_size = length.min(16 * 1024);
        let mut remaining = length;
        // Java re-reads from `start` each pass (it never advances the offset); kept as-is.
        while remaining > 0 {
            let bytes = provider.read_bytes(start as u64, remaining.min(buf_size) as u64)?;
            if bytes.iter().any(|&b| b != 0) {
                return Ok(false);
            }
            remaining -= bytes.len() as i64;
        }
        Ok(true)
    }

    /// Mirrors `isDiscardableFillerSegment(...)`.
    fn is_discardable_filler_segment(
        &self,
        loadable: std::option::Option<&dyn MemoryLoadable>,
        block_name: &str,
        start: &Address,
        file_offset: i64,
        length: i64,
    ) -> io::Result<bool> {
        if self.elf.get_section_header_count() == 0 || self.elf.get_program_header_count() == 0 {
            return Ok(false); // only prune if both sections and program headers are present
        }

        let max_segment_discard_size = options_factory::get_max_segment_discard_size(self.options);
        if max_segment_discard_size <= 0
            || length > max_segment_discard_size as i64
            || !block_name.starts_with(SEGMENT_NAME_PREFIX)
        {
            return Ok(false);
        }

        let mut bytes = vec![0u8; length as usize];
        let bytes_read = match loadable {
            Some(loadable) if loadable.has_filtered_load_input_stream(self, start.clone()) => {
                // block is unable to map directly to file bytes - read from filtered input stream
                let mut is = loadable.get_filtered_load_input_stream(self, start.clone(), length, None)?;
                read_fully(&mut *is, &mut bytes)?
            }
            _ => self
                .file_bytes()
                .get_modified_bytes(file_offset, &mut bytes)
                .map_err(|e| io::Error::other(e.to_string()))?,
        };
        Ok(bytes_read as i64 == length && bytes.iter().all(|&b| b == 0))
    }

    /// Mirrors `setImageBase()`.
    fn set_image_base(&self) {
        if !options_factory::has_image_base_option(self.options) {
            let current = self.program.get_image_base().map_or_else(|| "null".to_string(), |a| a.to_string());
            self.log(&format!("Using existing program image base of {current}"));
            return;
        }
        let Some(default_space) = self.get_default_address_space() else {
            Msg::error("ElfProgramBuilder", &"Can't set image base.");
            return;
        };
        let image_base = match options_factory::get_image_base_option(self.options) {
            None => truncated_word_address(&default_space, self.elf.get_image_base()),
            Some(image_base_str) => match NumericUtilities::parse_hex_long(&image_base_str) {
                Ok(offset) => truncated_word_address(&default_space, offset),
                Err(_) => {
                    Msg::error("ElfProgramBuilder", &"Can't set image base.");
                    return;
                }
            },
        };
        if let Err(e) = self.program.set_image_base(image_base, true) {
            // this shouldn't happen
            Msg::error("ElfProgramBuilder", &format!("Can't set image base. {e}"));
        }
    }

    /// Mirrors `getImageDataBase()`.
    fn get_image_data_base(&self) -> i64 {
        if let Some(base) = self.data_image_base.get() {
            return base;
        }
        let base = options_factory::get_data_image_base_option(self.options)
            .and_then(|s| NumericUtilities::parse_hex_long(&s).ok())
            .unwrap_or(0);
        self.data_image_base.set(Some(base));
        base
    }

    fn get_default_address_space(&self) -> std::option::Option<Arc<AddressSpace>> {
        self.program.get_address_factory()?.get_default_address_space()
    }

    fn get_default_data_space(&self) -> std::option::Option<Arc<AddressSpace>> {
        Some(self.program.get_language()?.get_default_data_space())
    }

    /// Mirrors `getSegmentAddressSpace(ElfProgramHeader)`.
    fn get_segment_address_space(&self, header: &ElfProgramHeader) -> std::option::Option<Arc<AddressSpace>> {
        if header.get_type() != PT_LOAD as i32 && header.get_virtual_address() == 0 {
            return Some(Arc::clone(other_space()));
        }
        self.elf.get_load_adapter().get_preferred_segment_address_space(self, header)
    }

    /// Mirrors `getSegmentLoadAddress(ElfProgramHeader)`.
    fn get_segment_load_address(&self, header: &ElfProgramHeader) -> std::option::Option<Address> {
        let space = self.get_segment_address_space(header)?;
        if !space.is_loaded_memory_space() {
            // handle non-loaded sections into the OTHER space
            return Some(truncated_word_address(&space, header.get_virtual_address()));
        }
        self.elf.get_load_adapter().get_preferred_segment_address(self, header)
    }

    /// Mirrors `getSectionAddressSpace(ElfSectionHeader)`.
    fn get_section_address_space(&self, section: &ElfSectionHeader) -> std::option::Option<Arc<AddressSpace>> {
        if !section.is_alloc() {
            // The alloc bit specifies whether this block exists in memory at runtime.
            // If it doesn't throw it into an OTHER overlay block.
            // Check for overlay space (previously overlayed on OTHER space)
            let space = self
                .program
                .get_address_factory()
                .and_then(|f| f.get_address_space_by_name(&section.get_name_as_string()));
            return Some(space.unwrap_or_else(|| Arc::clone(other_space()))); // overlay not yet created
        }
        self.elf.get_load_adapter().get_preferred_section_address_space(self, section)
    }

    /// Mirrors `getSectionLoadAddress(ElfSectionHeader)`.
    fn get_section_load_address(&self, section: &ElfSectionHeader) -> std::option::Option<Address> {
        let space = self.get_section_address_space(section)?;
        if !space.is_loaded_memory_space() {
            // handle non-loaded sections into the OTHER space
            return Some(truncated_word_address(&space, section.get_address()));
        }
        self.elf.get_load_adapter().get_preferred_section_address(self, section)
    }

    /// Mirrors `expandProgramHeaderBlocks(TaskMonitor)`: grows each PT_LOAD segment to its full
    /// memory size with zero bytes, as far as free memory allows (only used when there are no
    /// section headers).
    fn expand_program_header_blocks(&self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        let headers = self.elf.get_program_headers();

        monitor.set_message("Exapanding Program Segments...");
        monitor.initialize(headers.len() as i64);
        for (i, header) in headers.iter().enumerate() {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            if header.get_type() != PT_LOAD as i32 {
                continue;
            }

            let segment_memory_size_bytes = header.get_adjusted_memory_size();
            if segment_memory_size_bytes <= 0 {
                continue;
            }

            let mut block: std::option::Option<MemoryBlockHandle> = None;
            let load_size_bytes = header.get_adjusted_load_size();
            let expand_start = if load_size_bytes == 0 {
                self.get_segment_load_address(header)
            } else {
                // Identify resolved segment block tail-end
                let resolver = self.resolver.borrow();
                let Some(resolved) = resolver.get_resolved_load_addresses(&ElfLoadable::Segment(i)) else {
                    continue;
                };
                let Some(last) = resolved.last() else { continue };
                let end_addr = last.max_address().clone();
                let Some(found) = self.memory_block_at(&end_addr) else { continue };
                if found.read().unwrap().is_overlay() {
                    continue; // tail-end was displaced by another - do not extend
                }
                if found.read().unwrap().get_end() != end_addr {
                    continue; // tail-end merged with another - do not extend
                }
                block = Some(found);
                end_addr.add(1).ok()
            };

            let full_size_bytes = segment_memory_size_bytes;
            let Some(expand_start) = expand_start else { continue };
            if full_size_bytes <= load_size_bytes {
                continue;
            }

            if let Err(e) = self.expand_segment(i, &expand_start, full_size_bytes - load_size_bytes, block.as_ref(), monitor) {
                if let ElfLoadError::Cancelled(c) = e {
                    return Err(c.into());
                }
                self.log(&format!(
                    "Failed to {} segment [{},{}] at address {}",
                    if block.is_some() { "expand" } else { "create" },
                    i,
                    or_null(header.get_description(&self.elf).as_deref()),
                    addr_str(&expand_start)
                ));
            }
        }
        Ok(())
    }

    /// The `try` body of `expandProgramHeaderBlocks`' loop.
    fn expand_segment(
        &self,
        index: usize,
        expand_start: &Address,
        expand_size: i64,
        block: std::option::Option<&MemoryBlockHandle>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ElfLoadError> {
        let mut expand_end = expand_start
            .add_no_wrap(expand_size - 1)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let memory = self.program.get_memory().ok_or_else(|| io::Error::other("no memory"))?;
        let intersect_range = memory.intersect_range(expand_start, &expand_end);
        if let Some(first) = intersect_range.first_range() {
            let first_intersect_addr = first.min_address().clone();
            if *expand_start == first_intersect_addr {
                return Ok(()); // no room for expansion
            }
            expand_end = first_intersect_addr.previous().map_err(|e| io::Error::other(e.to_string()))?;
        }
        let _ = expand_end; // Java computes it but creates the block with the full expandSize
        let mut mem = self.program.get_memory_mut().ok_or_else(|| io::Error::other("no memory"))?;
        match block {
            None => {
                // Create new zeroed segment block with no bytes from file
                let block_name = format!("{SEGMENT_NAME_PREFIX}{index}");
                let new_block = mem.create_initialized_block_from_stream(
                    &block_name,
                    expand_start,
                    None,
                    expand_size,
                    Some(monitor),
                    false,
                )?;
                let mut b = new_block.write().unwrap();
                b.set_source_name(Some(BLOCK_SOURCE_NAME));
                b.set_comment(Some("Zero-initialized segment"));
            }
            Some(block) => {
                // Expand tail end of segment which had portion loaded from file
                let name = block.read().unwrap().get_name().to_string();
                let expand_block = mem.create_initialized_block_from_stream(
                    &format!("{name}.expand"),
                    expand_start,
                    None,
                    expand_size,
                    Some(monitor),
                    false,
                )?;
                let ext_block = mem.join(block, &expand_block)?;
                let mut b = ext_block.write().unwrap();
                let comment = format!("{} (zero-extended)", or_null(b.get_comment()));
                b.set_comment(Some(&comment));
                // joinProgramTreeFragments: ProgramDB has no program tree (module docs).
            }
        }
        Ok(())
    }

    fn memory_block_at(&self, addr: &Address) -> std::option::Option<MemoryBlockHandle> {
        self.program.get_memory()?.get_block_handle(addr)
    }

    /// Mirrors `processProgramHeaders(TaskMonitor)`.
    fn process_program_headers(&self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        if self.elf.is_relocatable() && self.elf.get_program_header_count() != 0 {
            self.log(&format!(
                "Ignoring unexpected program headers for relocatable ELF (e_phnum={})",
                self.elf.get_program_header_count()
            ));
            return Ok(());
        }

        let include_other_blocks = options_factory::include_other_blocks(self.options);
        let headers = self.elf.get_program_headers();
        let file_size = self.file_bytes().get_size();

        monitor.set_message("Processing program headers...");
        monitor.initialize(headers.len() as i64);
        for (i, header) in headers.iter().enumerate() {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            if header.get_type() == PT_NULL as i32 {
                continue;
            }
            let description = header.get_description(&self.elf);
            let file_offset = header.get_offset();
            if header.get_type() != PT_LOAD as i32 {
                if !include_other_blocks {
                    continue;
                }
                if header.is_invalid_offset() || file_offset >= file_size {
                    self.log(&format!(
                        "Skipping segment[{i}, {}] with invalid file offset",
                        or_null(description.as_deref())
                    ));
                    continue;
                }
                if self.elf.get_program_load_header_containing_file_offset(file_offset).is_some() {
                    continue;
                }
                if let Some(section) =
                    self.elf.get_section_header_containing_file_range(file_offset, header.get_file_size())
                {
                    self.log(&format!(
                        "Skipping segment[{i}, {}] included by section {}",
                        or_null(description.as_deref()),
                        section.get_name_as_string()
                    ));
                    continue;
                }
            }
            if header.is_invalid_offset() || file_offset >= file_size {
                self.log(&format!(
                    "Skipping PT_LOAD segment[{i}, {}] with invalid file offset",
                    or_null(description.as_deref())
                ));
                continue;
            }
            self.process_program_header(header, i);
        }
        Ok(())
    }

    /// Mirrors `processProgramHeader(ElfProgramHeader, int)`.
    fn process_program_header(&self, header: &ElfProgramHeader, segment_number: usize) {
        let Some(address) = self.get_segment_load_address(header) else {
            self.log(&format!("Failed to load segment [{segment_number}]: no load address space"));
            return;
        };
        let space = Arc::clone(address.space());

        let addr = header.get_virtual_address();
        let load_size_bytes = header.get_adjusted_load_size();
        let mut full_size_bytes = header.get_adjusted_memory_size();

        let maintain_execute_bit = self.elf.get_section_header_count() == 0;
        let description = header.get_description(&self.elf);

        if full_size_bytes <= 0 {
            if !space.is_loaded_memory_space() && load_size_bytes > 0 {
                full_size_bytes = load_size_bytes;
            } else {
                self.log(&format!(
                    "Skipping zero-length segment [{segment_number},{}] at address {}",
                    or_null(description.as_deref()),
                    addr_str(&address)
                ));
                return;
            }
        }

        if !is_valid_range(&space, address.offset(), full_size_bytes) {
            self.log(&format!(
                "Skipping unloadable segment [{segment_number}] at address {} (size={full_size_bytes})",
                addr_str(&address)
            ));
            return;
        }

        // Only allow segment fragmentation if section headers are defined
        let is_fragmentation_ok = self.elf.get_section_header_count() != 0;

        let mut comment = get_section_comment(
            addr,
            full_size_bytes,
            space.unit_size(),
            description.as_deref(),
            address.is_loaded_memory_address(),
        );
        if !maintain_execute_bit && header.is_execute() {
            comment.push_str(" (disabled execute bit)");
        }

        let block_name = get_segment_name(header, segment_number);
        if load_size_bytes != 0 {
            let result = self.resolver.borrow_mut().add_initialized_memory_section(
                Some(ElfLoadable::Segment(segment_number)),
                header.get_offset(),
                load_size_bytes,
                &address,
                Some(&block_name),
                header.is_read(),
                header.is_write(),
                if maintain_execute_bit { header.is_execute() } else { false },
                Some(comment),
                is_fragmentation_ok,
                header.get_type() == PT_LOAD as i32,
            );
            if let Err(e) = result {
                self.log(&format!("Failed to load segment [{segment_number}]: {e}"));
            }
        }
        // NOTE: Uninitialized portions of segments will be added via expandProgramHeaderBlocks
        // when no sections are present. When sections are present, we assume sections will
        // be created which correspond to these areas.
    }

    /// Mirrors `computeRelocationStartAddress(AddressSpace, long, TaskMonitor)`.
    fn compute_relocation_start_address(
        &self,
        space: &Arc<AddressSpace>,
        base_offset: i64,
        monitor: &dyn TaskMonitor,
    ) -> Result<i64, CancelledException> {
        if !self.elf.is_relocatable() {
            return Ok(0); // not applicable
        }
        let mut reloc_start_addr: i64 = 0;
        for section in self.elf.get_sections() {
            monitor.check_cancelled()?;
            let addr = section.get_address();
            if addr < 0 {
                reloc_start_addr = 0;
                break;
            }
            if section.is_alloc() && addr != 0 {
                if self.get_section_address_space(section).as_ref() == Some(space) {
                    let section_byte_length = self.elf.get_load_adapter().get_adjusted_size(section);
                    let section_length = section_byte_length / space.unit_size() as i64;
                    reloc_start_addr = reloc_start_addr.max(addr + section_length);
                }
            }
        }

        // if more than half the address space is skipped - fall back to default relocation base
        if let Some(default_space) = self.get_default_address_space() {
            let test_offset = reloc_start_addr << 1;
            if test_offset != truncated_word_address(&default_space, test_offset).offset() {
                reloc_start_addr = 0;
            }
        }
        Ok(reloc_start_addr + base_offset)
    }

    /// Mirrors `processSectionHeaders(TaskMonitor)`.
    fn process_section_headers(&mut self, monitor: &dyn TaskMonitor) -> Result<(), ElfLoadError> {
        monitor.set_message("Processing section headers...");

        let include_other_blocks = options_factory::include_other_blocks(self.options);

        // establish section address provider for relocatable ELF binaries
        let mut reloc_provider = if self.elf.is_relocatable() {
            Some(RelocatableImageBaseProvider::new(self, monitor)?)
        } else {
            None
        };

        let file_size = self.file_bytes().get_size();
        let count = self.elf.get_sections().len();
        monitor.set_message("Processing section headers...");
        monitor.initialize(count as i64);
        for index in 0..count {
            monitor.check_cancelled()?;
            monitor.increment_progress(1);
            let section = &self.elf.get_sections()[index];
            let type_ = section.get_type();
            if type_ != SHT_NULL as i32 && (include_other_blocks || section.is_alloc()) {
                let file_offset = section.get_offset();
                if type_ != SHT_NOBITS as i32 && (section.is_invalid_offset() || file_offset >= file_size) {
                    self.log(&format!(
                        "Skipping section [{}] with invalid file offset 0x{:x}",
                        section.get_name_as_string(),
                        file_offset
                    ));
                    continue;
                }
                let size = section.get_size();
                if size <= 0 || (type_ != SHT_NOBITS as i32 && size >= file_size) {
                    self.log(&format!(
                        "Skipping section [{}] with invalid size 0x{:x}",
                        section.get_name_as_string(),
                        size
                    ));
                    continue;
                }
                self.process_section_header(index, reloc_provider.as_mut());
            }
        }
        Ok(())
    }

    /// Mirrors `processSectionHeader(ElfSectionHeader, RelocatableImageBaseProvider)`.
    fn process_section_header(&mut self, index: usize, reloc_provider: std::option::Option<&mut RelocatableImageBaseProvider>) {
        let (mut addr, is_alloc, alignment) = {
            let s = &self.elf.get_sections()[index];
            (s.get_address(), s.is_alloc(), s.get_address_alignment())
        };
        let mut section_byte_length = self.elf.get_load_adapter().get_adjusted_size(&self.elf.get_sections()[index]);
        let mut load_offset = self.elf.get_sections()[index].get_offset(); // file offset in bytes
        let mut next_reloc_offset: std::option::Option<(Arc<AddressSpace>, i64)> = None;

        // In a relocatable ELF (object module), the address of all sections is zero.
        // Therefore, we shall assign an arbitrary address that
        // will pack the sections together with proper alignment.
        if is_alloc && self.elf.is_relocatable() && addr == 0 {
            if let (Some(space), Some(provider)) =
                (self.get_section_address_space(&self.elf.get_sections()[index]), reloc_provider.as_deref())
            {
                let reloc_offset = provider.get_next_relocatable_offset(&space);
                addr = NumericUtilities::get_unsigned_aligned_value(reloc_offset, alignment);
                let _ = self.elf.get_sections_mut()[index].set_address(addr);
                next_reloc_offset = Some((Arc::clone(&space), addr + section_byte_length / space.unit_size() as i64));
            }
        }

        let section = &self.elf.get_sections()[index];
        let name = section.get_name_as_string();
        let mut address: std::option::Option<Address> = None;

        if section_byte_length == 0 && section.get_type() == SHT_PROGBITS as i32 {
            // Check for and consume uninitialized portion of PT_LOAD segment if possible
            if let Some(load_header) = self.elf.get_program_load_header_containing(addr) {
                // NOTE: should never apply to relocatable ELF
                if let Some(segment_start) = self.get_segment_load_address(load_header) {
                    let segment_space = Arc::clone(segment_start.space());
                    let load_size_bytes = load_header.get_adjusted_load_size();
                    let full_size_bytes = load_header.get_adjusted_memory_size() * segment_space.unit_size() as i64;
                    let segment_byte_offset =
                        (addr - load_header.get_virtual_address()) * segment_space.unit_size() as i64;
                    if segment_byte_offset >= load_size_bytes {
                        // create as uninitialized section block
                        load_offset = -1; // don't load bytes
                        address = segment_start.add(segment_byte_offset).ok();
                        section_byte_length = full_size_bytes - segment_byte_offset;
                    }
                }
            }
        }

        if section_byte_length == 0 {
            self.log(&format!("Skipping empty section [{name}]"));
            return;
        }

        let address = match address.or_else(|| self.get_section_load_address(section)) {
            Some(a) => a,
            None => {
                self.log(&format!("Failed to load section [{name}]: no load address space"));
                return;
            }
        };
        let space = Arc::clone(address.space());

        if !is_valid_range(&space, address.offset(), section_byte_length) {
            self.log(&format!(
                "Skipping unloadable section [{name}] at address {} (size={section_byte_length})",
                addr_str(&address)
            ));
            return;
        }

        let comment = get_section_comment(
            addr,
            section_byte_length,
            space.unit_size(),
            Some(&section.get_type_as_string(&self.elf)),
            address.is_loaded_memory_address(),
        );
        let result = if load_offset == -1 || section.get_type() == SHT_NOBITS as i32 {
            if !section.is_alloc() && section.get_type() != SHT_PROGBITS as i32 {
                return; // non-allocate at runtime
            }
            self.resolver.borrow_mut().add_uninitialized_memory_section(
                Some(ElfLoadable::Section(index)),
                section_byte_length,
                &address,
                Some(&name),
                true,
                section.is_writable(),
                section.is_executable(),
                Some(comment),
                false,
            )
        } else {
            self.resolver.borrow_mut().add_initialized_memory_section(
                Some(ElfLoadable::Section(index)),
                load_offset,
                section_byte_length,
                &address,
                Some(&name),
                section.is_alloc(),
                section.is_writable(),
                section.is_executable(),
                Some(comment),
                false,
                section.is_alloc(),
            )
        };
        if let Err(e) = result {
            self.log(&format!("Failed to load section [{name}]: {e}"));
        }

        if let (Some((space, next)), Some(provider)) = (next_reloc_offset, reloc_provider) {
            provider.set_next_relocatable_offset(&space, next);
        }
    }

    /// Mirrors `checkBlockLimit(String, long, boolean)`.
    fn check_block_limit(&self, section_name: &str, data_length: i64) -> io::Result<i64> {
        let used: i64 = self
            .program
            .get_memory()
            .map(|m| m.get_block_handles().iter().map(|b| b.read().unwrap().get_size() as i64).sum())
            .unwrap_or(0);
        let available = MAX_BINARY_SIZE - used;
        if data_length < 0 || data_length > available {
            let msg = format!(
                "Failed to create memory blocks which exceed the fixed {MAX_BINARY_SIZE_GB} GByte total memory size limit"
            );
            self.log(&format!("ERROR: {msg}"));
            return Err(io::Error::other(msg));
        }
        if data_length > MAX_BLOCK_SIZE {
            let size_gb = data_length as f32 / GBYTE as f32;
            self.log(&format!(
                "ERROR: Truncating {:.1} GByte '{section_name}' section to {MAX_BLOCK_SIZE_GB} GByte fixed size limit",
                size_gb
            ));
            return Ok(MAX_BLOCK_SIZE);
        }
        Ok(data_length)
    }

    fn loadable(&self, key: std::option::Option<&ElfLoadable>) -> std::option::Option<&dyn MemoryLoadable> {
        match key? {
            ElfLoadable::Segment(i) => self.elf.get_program_headers().get(*i).map(|h| h as &dyn MemoryLoadable),
            ElfLoadable::Section(i) => self.elf.get_sections().get(*i).map(|s| s as &dyn MemoryLoadable),
        }
    }

    fn key_of(&self, loadable: &dyn MemoryLoadable) -> std::option::Option<ElfLoadable> {
        let target = loadable as *const dyn MemoryLoadable as *const ();
        if let Some(i) = self
            .elf
            .get_program_headers()
            .iter()
            .position(|h| std::ptr::eq(h as *const ElfProgramHeader as *const (), target))
        {
            return Some(ElfLoadable::Segment(i));
        }
        self.elf
            .get_sections()
            .iter()
            .position(|s| std::ptr::eq(s as *const ElfSectionHeader as *const (), target))
            .map(ElfLoadable::Section)
    }

    /// Mirrors the `MemoryLoadable` overload of `findLoadAddress(MemoryLoadable, long)`.
    fn find_load_address_for(&self, key: ElfLoadable, byte_offset_within_section: i64) -> std::option::Option<Address> {
        let resolved: std::option::Option<Vec<AddressRange>> =
            self.resolver.borrow().get_resolved_load_addresses(&key).map(<[AddressRange]>::to_vec);
        let Some(resolved) = resolved else {
            // assume loaded segment/section superseded by PT_LOAD segment or allocated section
            match key {
                ElfLoadable::Segment(i) => {
                    let header = &self.elf.get_program_headers()[i];
                    let offset_addr = header.get_virtual_address() + byte_offset_within_section;
                    if header.get_type() != PT_LOAD as i32 {
                        // Check for PT_LOAD segment which may contain requested segment
                        if let Some(load_header) = self.elf.get_program_load_header_containing(offset_addr) {
                            let key = self.key_of(load_header)?;
                            return self
                                .find_load_address_for(key, offset_addr - load_header.get_virtual_address());
                        }
                    }
                    // PT_LOAD segment must have been superseded by section load
                    if let Some(section) = self.elf.get_section_load_header_containing(offset_addr) {
                        let key = self.key_of(section)?;
                        return self.find_load_address_for(key, offset_addr - section.get_address());
                    }
                }
                ElfLoadable::Section(i) => {
                    let s = &self.elf.get_sections()[i];
                    if s.is_alloc() {
                        return self.get_section_load_address(s);
                    }
                }
            }
            return None; // failed to locate
        };

        let mut offset = byte_offset_within_section; // track byte offset within section
        let mut containing_range = None;
        for range in &resolved {
            let range_length = range.length() as i64;
            if offset < range_length {
                containing_range = Some(range);
                break;
            }
            offset -= range_length;
        }
        match containing_range {
            Some(range) => range.min_address().add(offset).ok(),
            // Not contained within loaded bytes - compute relative to block start.
            None => resolved.first().and_then(|r| r.min_address().add(byte_offset_within_section).ok()),
        }
    }

    fn phase2_unavailable(&self, what: &str) {
        self.log(&format!("ELF {what} is not supported by this loader yet"));
    }
}

/// The file offsets still unallocated (Java's `-1` value in `adjustSegmentAndSectionFileAllocations`'s
/// `RangeMap`), as sorted, disjoint, inclusive ranges.
struct FileRanges {
    ranges: Vec<(i64, i64)>,
}

impl FileRanges {
    fn new(length: i64) -> Self {
        FileRanges { ranges: if length > 0 { vec![(0, length - 1)] } else { Vec::new() } }
    }

    /// Marks `[start, end]` allocated.
    fn paint(&mut self, start: i64, end: i64) {
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        for &(s, e) in &self.ranges {
            if e < start || s > end {
                out.push((s, e));
                continue;
            }
            if s < start {
                out.push((s, start - 1));
            }
            if e > end {
                out.push((end + 1, e));
            }
        }
        self.ranges = out;
    }
}

/// Mirrors `getSegmentName(ElfProgramHeader, int)`.
fn get_segment_name(header: &ElfProgramHeader, segment_number: usize) -> String {
    if header.get_type() == PT_NOTE as i32 {
        return "_elfNote".to_string();
    }
    format!("{SEGMENT_NAME_PREFIX}{segment_number}")
}

/// Mirrors `getSectionComment(long, long, int, String, boolean)`.
fn get_section_comment(
    addr: i64,
    byte_size: i64,
    addressable_unit_size: i32,
    description: std::option::Option<&str>,
    loaded: bool,
) -> String {
    let mut buf = String::new();
    if let Some(description) = description {
        buf.push_str(description);
        buf.push(' ');
    }
    if loaded {
        if !buf.is_empty() {
            buf.push(' ');
        }
        let max = addr as i128 + (byte_size / addressable_unit_size as i64) as i128 - 1;
        let max_str = if max < 0 { format!("-{:x}", -max) } else { format!("{max:x}") };
        buf.push_str(&format!("[0x{:x} - 0x{max_str}]", addr as u64));
    } else {
        buf.push_str("[not-loaded]");
    }
    buf
}

fn read_fully(is: &mut dyn io::Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = is.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

/// Java's inner `RelocatableImageBaseProvider`: the next free offset per address space when
/// packing a relocatable object's sections.
struct RelocatableImageBaseProvider {
    next_relocation_offset_map: HashMap<i32, i64>,
}

impl RelocatableImageBaseProvider {
    fn new(builder: &ElfProgramBuilder<'_>, monitor: &dyn TaskMonitor) -> Result<Self, CancelledException> {
        let mut map = HashMap::new();
        if let Some(default_space) = builder.get_default_address_space() {
            let base_offset =
                builder.compute_relocation_start_address(&default_space, builder.elf.get_image_base(), monitor)?;
            map.insert(default_space.unique(), base_offset);
            if let Some(default_data_space) = builder.get_default_data_space() {
                if default_data_space != default_space {
                    let base_offset = builder.compute_relocation_start_address(
                        &default_data_space,
                        builder.get_image_data_base(),
                        monitor,
                    )?;
                    map.insert(default_data_space.unique(), base_offset);
                }
            }
        }
        // In the future, an extension could introduce additional space entries
        Ok(RelocatableImageBaseProvider { next_relocation_offset_map: map })
    }

    fn set_next_relocatable_offset(&mut self, space: &Arc<AddressSpace>, next_reloc_offset: i64) {
        self.next_relocation_offset_map.insert(space.unique(), next_reloc_offset);
    }

    fn get_next_relocatable_offset(&self, space: &Arc<AddressSpace>) -> i64 {
        self.next_relocation_offset_map.get(&space.unique()).copied().unwrap_or(0)
    }
}

impl MemorySectionResolver<ElfLoadable> for ElfProgramBuilder<'_> {
    /// Mirrors the `createInitializedBlock` override.
    fn create_initialized_block(
        &self,
        key: std::option::Option<&ElfLoadable>,
        is_overlay: bool,
        name: &str,
        start: &Address,
        file_offset: i64,
        data_length: i64,
        comment: std::option::Option<&str>,
        mut r: bool,
        mut w: bool,
        mut x: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<std::option::Option<MemoryBlockHandle>, MemorySectionError> {
        let mut revised_length = self.check_block_limit(name, data_length)?;
        let loadable = self.loadable(key);

        if self.is_discardable_filler_segment(loadable, name, start, file_offset, data_length)? {
            Msg::debug(
                "ElfProgramBuilder",
                &format!("Discarding {data_length}-byte alignment/filler {name} at {start}"),
            );
            return Ok(None);
        }

        if is_non_loaded_memory_address(start) {
            r = false;
            w = false;
            x = false;
        }

        let comp_sect_orig_size = match key {
            Some(ElfLoadable::Section(i)) if self.elf.get_sections()[*i].is_compressed() => {
                self.elf.get_sections()[*i].get_size()
            }
            _ => -1,
        };

        let mut block_comment = or_null(comment).to_string();
        if comp_sect_orig_size >= 0 {
            block_comment.push_str(&format!(" (decompressed, original length: 0x{comp_sect_orig_size:x})"));
        } else if file_offset + revised_length - 1 >= self.file_bytes().get_size() {
            // ensure valid length for non-compressed items
            revised_length = self.file_bytes().get_size() - file_offset;
            self.log(&format!("Truncating block load for {name} which exceeds file length"));
        }
        if data_length != revised_length {
            // either gt MAX_BINARY_SIZE or gt fileBytes size
            block_comment.push_str(" (section truncated)");
        }

        let result = match loadable {
            Some(loadable) if loadable.has_filtered_load_input_stream(self, start.clone()) => {
                // block is unable to map directly to file bytes - load from input stream
                let log = &self.log;
                let loadable_type = if comp_sect_orig_size >= 0 { "compressed section " } else { "" };
                let consumer = |msg: &str, e: &dyn std::error::Error| {
                    log.append_msg(format!("Error when reading {loadable_type}[{name}]: {msg}"));
                    Msg::error("ElfProgramBuilder", &format!("{msg}: {e}"));
                };
                let mut is =
                    loadable.get_filtered_load_input_stream(self, start.clone(), revised_length, Some(&consumer))?;
                memory_block_utils::create_initialized_block_from_stream(
                    self.program.as_ref(),
                    is_overlay,
                    name,
                    start,
                    &mut *is,
                    revised_length,
                    Some(&block_comment),
                    Some(BLOCK_SOURCE_NAME),
                    r,
                    w,
                    x,
                    &self.log,
                    monitor,
                )
            }
            _ => {
                // create block using direct mapping to file bytes
                memory_block_utils::create_initialized_block(
                    self.program.as_ref(),
                    is_overlay,
                    name,
                    start,
                    self.file_bytes(),
                    file_offset,
                    revised_length,
                    Some(&block_comment),
                    Some(BLOCK_SOURCE_NAME),
                    r,
                    w,
                    x,
                    &self.log,
                )
            }
        };
        let block = self.map_block_result(name, result)?;
        if block.is_none() {
            let end = start.add_no_wrap(revised_length - 1)?;
            self.log(&format!(
                "Unexpected ELF memory block load conflict when creating '{name}' at {}-{}",
                addr_str(start),
                addr_str(&end)
            ));
        }
        Ok(block)
    }

    /// Mirrors the `createUninitializedBlock` override.
    fn create_uninitialized_block(
        &self,
        _key: std::option::Option<&ElfLoadable>,
        is_overlay: bool,
        name: &str,
        start: &Address,
        data_length: i64,
        comment: std::option::Option<&str>,
        mut r: bool,
        mut w: bool,
        mut x: bool,
    ) -> Result<std::option::Option<MemoryBlockHandle>, MemorySectionError> {
        let revised_length = self.check_block_limit(name, data_length)?;

        if is_non_loaded_memory_address(start) {
            r = false;
            w = false;
            x = false;
        }

        let mut comment = or_null(comment).to_string();
        if data_length != revised_length {
            comment.push_str(" (section truncated)");
        }

        Ok(memory_block_utils::create_uninitialized_block(
            self.program.as_ref(),
            is_overlay,
            name,
            start,
            revised_length,
            Some(&comment),
            Some(BLOCK_SOURCE_NAME),
            r,
            w,
            x,
            &self.log,
        ))
    }
}

impl ElfProgramBuilder<'_> {
    /// Maps `MemoryBlockUtils`' escaping failures onto the hook's checked exceptions. An overlay
    /// that cannot be created (module docs) is logged and skipped, as `MemoryBlockUtils` does for
    /// the failures it catches itself; anything else Java would let escape becomes an IO error,
    /// which the resolver logs before moving on to the next section.
    fn map_block_result(
        &self,
        name: &str,
        result: Result<std::option::Option<MemoryBlockHandle>, CreateBlockError>,
    ) -> Result<std::option::Option<MemoryBlockHandle>, MemorySectionError> {
        match result {
            Ok(block) => Ok(block),
            Err(CreateBlockError::AddressOverflow(e)) => Err(e.into()),
            Err(CreateBlockError::Cancelled(e)) => Err(e.into()),
            Err(CreateBlockError::IllegalState(msg)) => {
                self.log(&format!("Failed to create '{name}' memory block: {msg}"));
                Ok(None)
            }
            Err(e) => Err(io::Error::other(e.to_string()).into()),
        }
    }
}

impl ElfLoadHelper for ElfProgramBuilder<'_> {
    fn get_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.program)
    }

    fn get_option_bool(&self, option_name: &str, default_value: bool) -> bool {
        crate::app::seam_stubs::option_utils::get_bool_option(option_name, self.options, default_value)
    }

    fn get_option_string(
        &self,
        option_name: &str,
        default_value: std::option::Option<String>,
    ) -> std::option::Option<String> {
        crate::app::seam_stubs::option_utils::get_string_option(option_name, self.options, default_value)
    }

    fn get_option_i32(&self, option_name: &str, default_value: i32) -> i32 {
        crate::app::seam_stubs::option_utils::get_int_option(option_name, self.options, default_value)
    }

    fn get_elf_header(&self) -> &ElfHeader {
        &self.elf
    }

    fn get_log(&self) -> Arc<MessageLog> {
        Arc::clone(&self.log)
    }

    fn log(&self, msg: &str) {
        self.log.append_msg(msg);
    }

    fn log_exception(&self, t: &dyn std::error::Error) {
        self.log.append_exception(t, &[]);
    }

    fn mark_as_code(&self, _address: Address) {
        self.phase2_unavailable("code markup");
    }

    fn create_one_byte_function(
        &self,
        _name: std::option::Option<&str>,
        _address: Address,
        _is_entry: bool,
    ) -> std::option::Option<Arc<dyn Function>> {
        self.phase2_unavailable("function creation");
        None
    }

    fn create_external_function_linkage(
        &self,
        _name: &str,
        _function_addr: Address,
        _indirect_pointer_addr: std::option::Option<Address>,
    ) -> std::option::Option<Arc<dyn Function>> {
        self.phase2_unavailable("external function linkage");
        None
    }

    fn create_undefined_data(&self, _address: Address, _length: i32) -> std::option::Option<Arc<dyn Data>> {
        self.phase2_unavailable("data creation");
        None
    }

    fn create_data(&self, _address: Address, _dt: Box<dyn DataType>) -> std::option::Option<Arc<dyn Data>> {
        self.phase2_unavailable("data creation");
        None
    }

    fn set_elf_symbol_address(&self, _elf_symbol: &ElfSymbol, _address: std::option::Option<Address>) {
        self.phase2_unavailable("symbol processing");
    }

    fn get_elf_symbol_address(&self, _elf_symbol: &ElfSymbol) -> std::option::Option<Address> {
        None
    }

    fn create_symbol(
        &self,
        _addr: Address,
        name: &str,
        _is_primary: bool,
        _pin_absolute: bool,
        _namespace: std::option::Option<Arc<dyn Namespace>>,
    ) -> Result<Arc<dyn Symbol>, InvalidInputException> {
        Err(InvalidInputException::with_message(format!(
            "ELF symbol creation is not supported by this loader yet: {name}"
        )))
    }

    fn find_load_address(
        &self,
        section: &dyn MemoryLoadable,
        byte_offset_within_section: i64,
    ) -> std::option::Option<Address> {
        let key = self.key_of(section)?;
        self.find_load_address_for(key, byte_offset_within_section)
    }

    /// Mirrors `getDefaultAddress(long)`.
    fn get_default_address(&self, addressable_word_offset: i64) -> Address {
        let offset = addressable_word_offset.wrapping_add(self.get_image_base_word_adjustment_offset());
        let space = self
            .get_default_address_space()
            .expect("ELF programs have a default address space");
        truncated_word_address(&space, offset)
    }

    /// Mirrors `getImageBaseWordAdjustmentOffset()`.
    fn get_image_base_word_adjustment_offset(&self) -> i64 {
        let image_base = self
            .program
            .get_image_base()
            .map_or(0, |a| a.addressable_word_offset());
        image_base.wrapping_sub(self.elf.get_image_base())
    }

    /// Mirrors `getGOTValue()` for the `DT_PLTGOT` case; the `_GLOBAL_OFFSET_TABLE_` symbol
    /// fallback needs program symbols (phase 2).
    fn get_got_value(&self) -> std::option::Option<i64> {
        let dynamic = self.elf.get_dynamic_table()?;
        let pltgot = crate::format::elf::elf_dynamic_type::dt_pltgot();
        if !dynamic.contains_dynamic_value_of_type(&pltgot) {
            return None;
        }
        let value = dynamic.get_dynamic_value_of_type(&pltgot).ok()?;
        Some(self.elf.adjust_address_for_prelink(value) + self.get_image_base_word_adjustment_offset())
    }

    fn allocate_linkage_block(&self, _alignment: i32, _size: i32, purpose: &str) -> std::option::Option<AddressRange> {
        self.phase2_unavailable(&format!("linkage block allocation ({purpose})"));
        None
    }

    fn get_original_value(&self, addr: Address, sign_extend: bool) -> Result<i64, MemoryAccessException> {
        let _ = sign_extend;
        Err(MemoryAccessException::new(format!(
            "original file bytes lookup at {addr} is not supported by this loader yet"
        )))
    }

    fn add_artificial_reloc_table_entry(&self, _address: Address, _length: i32) -> bool {
        self.phase2_unavailable("relocation table");
        false
    }
}

#[cfg(test)]
mod tests;
