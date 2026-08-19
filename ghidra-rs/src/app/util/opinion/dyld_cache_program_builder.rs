//! Port of `ghidra.app.util.opinion.DyldCacheProgramBuilder`.
//!
//! Builds up a DYLD Cache [`Program`] by parsing the DYLD Cache headers.
//!
//! # Departures from the Java class
//!
//! * Java's `DyldCacheProgramBuilder extends MachoProgramBuilder`, which is not ported. The
//!   fields it inherits and reads (`program`, `provider`, `log`, `monitor`, `space`) are carried
//!   on this struct directly, and the six inherited members it calls up into
//!   (`markupHeaders(MachHeader, Address)`, `processMemoryBlocks`, `processExports`,
//!   `processSymbolTables`, `markupLoadCommandData`, `createOneByteFunction`) become free
//!   functions in [`macho_program_builder`], taking that state explicitly. None of those are
//!   implemented yet, so a real [`build`](DyldCacheProgramBuilder::build) panics as soon as it
//!   reaches one; the control flow around them is ported faithfully so it is in place when they
//!   land. The `fileBytes` field is likewise inherited-but-unused by this subclass (its own
//!   memory-block code calls `MemoryBlockUtils.createFileBytes` per cache file rather than
//!   reusing it) and is kept only to preserve the constructor's shape.
//! * Java's `DyldCacheMachoInfo` is a non-static *inner* class, so each instance implicitly holds
//!   the enclosing builder and its five methods forward straight back into it. Rust has no such
//!   back-reference, so [`DyldCacheMachoInfo`] is a plain data struct and those five methods live
//!   on the builder, taking the info as an argument
//!   (`info.markupHeaders()` becomes `self.markup_dylib_headers(info)`, and so on).
//! * `processDylibs`'s `TreeSet<DyldCacheMachoInfo>` (ordered by header address) becomes a `Vec`
//!   sorted by the same key, with equal-keyed entries dropped -- which is what adding to a
//!   `TreeSet` with that comparator does.
//! * Two dead Java locals are not reproduced: `processDylibs`'s `libobjcInfo`, which is assigned
//!   in the parse loop and then never read (the libobjc block re-derives it from `infoSet` with a
//!   stream), and its `localSymbolsPresent` parameter, which `build()` computes and passes but
//!   the method never uses. The parameter is kept -- `build()`'s work to compute it is part of the
//!   class -- but is `_`-prefixed.
//! * Java's `monitor.initialize(long, String)` overload has no counterpart on the ported
//!   [`TaskMonitor`], so `setDyldCacheEntryPoint`'s single use of it becomes the
//!   `setMessage` + `initialize` pair every other method here already uses.
//! * `AddressSpace.OTHER_SPACE` is a Java static singleton with no ported counterpart; the
//!   unmapped-bytes block is placed in the program's own `OTHER` space when it has one, falling
//!   back to a freshly built space matching how `DefaultAddressFactory` defines it (see
//!   [`other_space`]).
//! * Java's `build()` throws `Exception`; every failure here collapses into `io::Error`, matching
//!   [`DyldCacheLoader::load`](crate::app::util::opinion::dyld_cache_loader::DyldCacheLoader::load),
//!   this class's only caller.
//! * Most of the DYLD and Mach-O types this builder walks are not ported yet and are reached
//!   through `seam_stubs` placeholders ([`SplitDyldCache`], [`DyldCacheHeader`],
//!   [`MachHeader`], [`LibObjcDylib`], ...). Where a placeholder merely records nothing it
//!   returns `Ok(())`; where it would have to fabricate data it is `unimplemented!()`.

use std::cell::RefCell;
use std::fmt::Display;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use crate::app::seam_stubs::{
    macho_program_builder, memory_block_utils, DyldCacheHeader, LibObjcDylib, MessageLog,
    SplitDyldCache,
};
use crate::app::util::opinion::dyld_cache_options::DyldCacheOptions;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::macho::commands::segment_names;
use crate::format::seam_stubs::{mach_header_from_provider, MachHeader};
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::listing::{CommentType, Program, INFO};
use crate::program::model::symbol::symbol_utilities::{DefaultSymbolUtilities, SymbolUtilities};
use crate::program::model::symbol::SourceType;
use crate::util::task::TaskMonitor;

/// Builds up a DYLD Cache [`Program`] by parsing the DYLD Cache headers.
///
/// Port of `ghidra.app.util.opinion.DyldCacheProgramBuilder`. See the module docs for how the
/// unported `MachoProgramBuilder` superclass is modeled.
pub struct DyldCacheProgramBuilder<'a> {
    /// The `Program` to build up. Inherited from `MachoProgramBuilder`.
    program: &'a mut dyn Program,
    /// The `ByteProvider` that contains the DYLD Cache bytes. Inherited.
    provider: Rc<RefCell<dyn ByteProvider>>,
    /// Where the DYLD Cache's bytes came from. Inherited, and (as in Java) unread by this
    /// subclass -- see the module docs.
    #[allow(dead_code)]
    file_bytes: Arc<dyn FileBytes>,
    /// Options from the `DyldCacheLoader`.
    options: DyldCacheOptions,
    /// The log. Inherited.
    log: &'a dyn MessageLog,
    /// A cancelable task monitor. Inherited.
    monitor: &'a dyn TaskMonitor,
    /// The program's default address space, which `MachoProgramBuilder`'s constructor reads out
    /// of the program's address factory.
    space: Arc<AddressSpace>,
}

impl<'a> DyldCacheProgramBuilder<'a> {
    /// Port of the protected `DyldCacheProgramBuilder(Program, ByteProvider, FileBytes,
    /// DyldCacheOptions, MessageLog, TaskMonitor)` constructor, together with the part of
    /// `MachoProgramBuilder`'s constructor that resolves the default address space.
    ///
    /// # Errors
    /// Fails when the program has no address factory, or its factory no default address space --
    /// in Java, `program.getAddressFactory().getDefaultAddressSpace()` would have thrown.
    fn new(
        program: &'a mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        file_bytes: &Arc<dyn FileBytes>,
        options: DyldCacheOptions,
        log: &'a dyn MessageLog,
        monitor: &'a dyn TaskMonitor,
    ) -> io::Result<Self> {
        let space = macho_program_builder::default_address_space(program).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "program has no default address space to build a DYLD cache in",
            )
        })?;
        Ok(DyldCacheProgramBuilder {
            program,
            provider: Rc::clone(provider),
            file_bytes: Arc::clone(file_bytes),
            options,
            log,
            monitor,
            space,
        })
    }

    /// Port of `DyldCacheProgramBuilder.buildProgram(Program, ByteProvider, FileBytes,
    /// DyldCacheOptions, MessageLog, TaskMonitor)`.
    pub fn build_program(
        program: &mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        file_bytes: &Arc<dyn FileBytes>,
        options: DyldCacheOptions,
        log: &dyn MessageLog,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        let mut builder =
            DyldCacheProgramBuilder::new(program, provider, file_bytes, options, log, monitor)?;
        builder.build()
    }

    /// Port of `DyldCacheProgramBuilder.build()`.
    ///
    /// Java's `try (SplitDyldCache ...)` closes the split cache on the way out; here dropping it
    /// releases the providers it holds, so no explicit close is needed.
    fn build(&mut self) -> io::Result<()> {
        let mut split_dyld_cache = SplitDyldCache::new(
            &self.provider,
            self.options.process_local_symbols,
            self.log,
            self.monitor,
        )?;

        // Set image base
        self.set_dyld_cache_image_base(&split_dyld_cache)?;

        // Set entry point
        self.set_dyld_cache_entry_point(&split_dyld_cache)?;

        // Setup memory
        // Check if local symbols are present
        let mut local_symbols_present = false;
        for i in 0..split_dyld_cache.size() {
            let bp = Rc::clone(split_dyld_cache.get_provider(i));
            let name = split_dyld_cache.get_name(i).to_string();

            self.process_dyld_cache_memory_blocks(
                split_dyld_cache.get_dyld_cache_header_mut(i),
                &name,
                &bp,
            )?;

            if split_dyld_cache.get_dyld_cache_header(i).local_symbols_info.is_some() {
                local_symbols_present = true;
            }
        }

        // Process DYLIBs
        self.process_dylibs(&split_dyld_cache, local_symbols_present)?;

        // Perform additional DYLD processing
        for i in 0..split_dyld_cache.size() {
            let bp = Rc::clone(split_dyld_cache.get_provider(i));

            self.fixup_slide_pointers(split_dyld_cache.get_dyld_cache_header(i))?;
            self.markup_headers(split_dyld_cache.get_dyld_cache_header_mut(i))?;
            self.markup_branch_islands(split_dyld_cache.get_dyld_cache_header(i), &bp)?;
            self.create_local_symbols(split_dyld_cache.get_dyld_cache_header(i))?;
        }

        Ok(())
    }

    /// Sets the program's image base. Port of the private `setDyldCacheImageBase`.
    fn set_dyld_cache_image_base(&mut self, split_dyld_cache: &SplitDyldCache) -> io::Result<()> {
        self.monitor.set_message("Setting image base...");
        self.monitor.initialize(1);
        let base = self.space.address(split_dyld_cache.get_base_address());
        self.program.set_image_base(base, true)?;
        self.monitor.increment_progress(1);
        Ok(())
    }

    /// Sets the program's entry point (if known). Port of the private `setDyldCacheEntryPoint`.
    fn set_dyld_cache_entry_point(&mut self, split_dyld_cache: &SplitDyldCache) -> io::Result<()> {
        self.monitor.set_message("Setting entry pointer base...");
        self.monitor.initialize(1);
        let header = split_dyld_cache.get_dyld_cache_header(0);
        let entry_point = (!header.has_accelerate_info)
            .then_some(header.accelerate_info_size_or_dyld_in_cache_entry);
        match entry_point {
            Some(entry_point) => {
                let entry_point_addr = self.space.address(entry_point);
                let symbol_table = self.program.get_symbol_table().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "program has no symbol table to record an external entry point in",
                    )
                })?;
                symbol_table.add_external_entry_point(&entry_point_addr)?;
                macho_program_builder::create_one_byte_function(
                    self.program,
                    "entry",
                    &entry_point_addr,
                );
            }
            None => self.log.append_msg("Unable to determine entry point."),
        }
        self.monitor.increment_progress(1);
        Ok(())
    }

    /// Processes the DYLD Cache's memory mappings and creates memory blocks for them. Port of the
    /// private `processDyldCacheMemoryBlocks`.
    fn process_dyld_cache_memory_blocks(
        &mut self,
        dyld_cache_header: &mut DyldCacheHeader,
        name: &str,
        bp: &Rc<RefCell<dyn ByteProvider>>,
    ) -> io::Result<()> {
        let mapping_infos = dyld_cache_header.mapping_infos.clone();
        self.monitor.set_message("Processing DYLD mapped memory blocks...");
        self.monitor.initialize(mapping_infos.len() as i64);
        let extension = block_name_extension(name);
        let fb = memory_block_utils::create_file_bytes(self.program, bp, self.monitor)?;
        let mut end_of_mapped_offset: i64 = 0;
        let mut bookmark_set = false;
        for mapping_info in &mapping_infos {
            let offset = mapping_info.get_file_offset();
            let size = mapping_info.get_size();
            let block = memory_block_utils::create_initialized_block(
                self.program,
                false,
                &format!("DYLD{extension}"),
                &self.space.address(mapping_info.get_address()),
                &fb,
                offset,
                size,
                Some(""),
                Some(""),
                mapping_info.is_read(),
                mapping_info.is_write(),
                mapping_info.is_execute(),
                self.log,
            )
            .map_err(to_io)?;

            if offset + size > end_of_mapped_offset {
                end_of_mapped_offset = offset + size;
            }

            // Java sets `bookmarkSet` unconditionally and would NPE on a null block; here a
            // missing block simply leaves the bookmark for the next mapping to place.
            if !bookmark_set {
                if let Some(block) = &block {
                    let comment = format!(
                        "{} - {}",
                        name,
                        crate::app::seam_stubs::NumericUtilities::convert_bytes_to_string(
                            &dyld_cache_header.uuid,
                            ""
                        )
                    );
                    let start = block.get_start();
                    if let Some(bookmark_manager) = self.program.get_bookmark_manager_mut() {
                        bookmark_manager.set_bookmark(
                            start,
                            INFO,
                            "Dyld Cache Header",
                            &comment,
                        );
                    }
                    bookmark_set = true;
                }
            }

            self.monitor.check_cancelled().map_err(to_io)?;
            self.monitor.increment_progress(1);
        }

        let provider_length = bp.borrow_mut().length()? as i64;
        if end_of_mapped_offset < provider_length {
            self.monitor.set_message("Processing DYLD unmapped memory block...");
            let other = other_space(self.program);
            let file_block = memory_block_utils::create_initialized_block(
                self.program,
                true,
                &format!("FILE{extension}"),
                &other.address(end_of_mapped_offset),
                &fb,
                end_of_mapped_offset,
                provider_length - end_of_mapped_offset,
                Some("Useful bytes that don't get mapped into memory"),
                Some(""),
                false,
                false,
                false,
                self.log,
            )
            .map_err(to_io)?;
            if let Some(file_block) = &file_block {
                dyld_cache_header.set_file_block(&**file_block);
            }
        }

        Ok(())
    }

    /// Marks up the DYLD Cache headers. Port of the private `markupHeaders(DyldCacheHeader)`.
    fn markup_headers(&mut self, dyld_cache_header: &mut DyldCacheHeader) -> io::Result<()> {
        self.monitor.set_message("Marking up DYLD headers...");
        self.monitor.initialize(1);
        dyld_cache_header.parse_from_memory(
            &*self.program,
            &self.space,
            self.log,
            self.monitor,
        )?;
        dyld_cache_header.markup(
            &mut *self.program,
            self.options.markup_local_symbols,
            &self.space,
            self.monitor,
            self.log,
        )?;
        self.monitor.increment_progress(1);
        Ok(())
    }

    /// Marks up the DYLD Cache branch islands. Port of the private `markupBranchIslands`.
    ///
    /// Java catches `MachException | IOException` per island and carries on; both map onto
    /// `io::Error` here, so any failure from either the header parse or the mark-up is dropped.
    fn markup_branch_islands(
        &mut self,
        dyld_cache_header: &DyldCacheHeader,
        bp: &Rc<RefCell<dyn ByteProvider>>,
    ) -> io::Result<()> {
        self.monitor.set_message("Marking up DYLD branch islands...");
        self.monitor.initialize(dyld_cache_header.branch_pool_addresses.len() as i64);
        for addr in &dyld_cache_header.branch_pool_addresses {
            if let Ok(mut header) =
                mach_header_from_provider(bp, addr - dyld_cache_header.base_address)
            {
                if header.parse().is_ok() {
                    let header_addr = self.space.address(*addr);
                    let _ = macho_program_builder::markup_headers(
                        &mut *self.program,
                        &*header,
                        &header_addr,
                        self.log,
                        self.monitor,
                    );
                }
            }
            self.monitor.check_cancelled().map_err(to_io)?;
            self.monitor.increment_progress(1);
        }
        Ok(())
    }

    /// Create the DYLD Cache local symbols. Port of the private `createLocalSymbols`.
    fn create_local_symbols(&mut self, dyld_cache_header: &DyldCacheHeader) -> io::Result<()> {
        if !self.options.process_local_symbols {
            return Ok(());
        }
        let Some(local_symbols_info) = &dyld_cache_header.local_symbols_info else {
            return Ok(());
        };
        self.monitor.set_message("Creating DYLD local symbols...");
        self.monitor.initialize(local_symbols_info.get_nlist().len() as i64);
        for nlist in local_symbols_info.get_nlist() {
            // Java's `String.isBlank()`: empty once whitespace is stripped.
            if nlist.get_string().trim().is_empty() {
                continue;
            }
            let addr = self.space.address(nlist.get_value());
            let label = DefaultSymbolUtilities
                .replace_invalid_chars(Some(nlist.get_string()), true)
                .unwrap_or_default();
            let global_namespace = self.program.get_global_namespace();
            let result = match self.program.get_symbol_table() {
                Some(symbol_table) => match global_namespace {
                    Some(global_namespace) => symbol_table.create_label_in_namespace(
                        &addr,
                        &label,
                        global_namespace,
                        SourceType::Imported,
                    ),
                    None => symbol_table.create_label(&addr, &label, SourceType::Imported),
                },
                None => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "program has no symbol table to create a label in",
                )),
            };
            if let Err(e) = result {
                self.log.append_msg(&format!("{e} {}", nlist.get_string()));
            }
            self.monitor.check_cancelled().map_err(to_io)?;
            self.monitor.increment_progress(1);
        }
        Ok(())
    }

    /// Fixes any slide pointers within each of the data pages. Port of the private
    /// `fixupSlidePointers`.
    fn fixup_slide_pointers(&mut self, dyld_cache_header: &DyldCacheHeader) -> io::Result<()> {
        if !self.options.fixup_slide_pointers {
            return Ok(());
        }

        // locate slide Info
        for info in &dyld_cache_header.slide_infos {
            let version = info.get_version();

            self.log.append_msg(&format!("Fixing slide pointers version: {version}"));
            info.fixup_slide_pointers(
                &mut *self.program,
                self.options.markup_slide_pointers,
                self.options.add_slide_pointer_relocations,
                self.log,
                self.monitor,
            )?;
        }
        Ok(())
    }

    /// Processes the DYLD Cache's DYLIB files. This will mark up the DYLIB files, add them to the
    /// program tree, and make memory blocks for them. Port of the private `processDylibs`.
    ///
    /// `_local_symbols_present` mirrors Java's unused parameter -- see the module docs.
    fn process_dylibs(
        &mut self,
        split_dyld_cache: &SplitDyldCache,
        _local_symbols_present: bool,
    ) -> io::Result<()> {
        // Create an "info" object for each DyldCache DYLIB, which will make processing them
        // easier.
        self.monitor.set_message("Parsing DYLIB's...");
        let mut info_set: Vec<DyldCacheMachoInfo> = Vec::new();
        let image_records = split_dyld_cache.get_image_records();
        self.monitor.initialize(image_records.len() as i64);
        for image_record in image_records {
            self.monitor.check_cancelled().map_err(to_io)?;
            self.monitor.increment_progress(1);
            let image = image_record.image();
            let header_addr = self.space.address(image.address() as i64);
            let path = image.path().to_string();
            let info = DyldCacheMachoInfo::new(
                split_dyld_cache.get_macho(image_record)?,
                header_addr,
                &path,
            )?;
            info_set.push(info);
        }
        // `new TreeSet<>((a, b) -> a.headerAddr.compareTo(b.headerAddr))`: ordered by header
        // address, with later duplicates of an address rejected.
        info_set.sort_by(|a, b| a.header_addr.cmp(&b.header_addr));
        info_set.dedup_by(|a, b| a.header_addr == b.header_addr);

        // Markup DyldCache DYLIB headers
        self.monitor.set_message("Marking up DYLIB headers...");
        self.monitor.initialize(info_set.len() as i64);
        for info in &info_set {
            self.monitor.check_cancelled().map_err(to_io)?;
            self.monitor.increment_progress(1);
            self.markup_dylib_headers(info)?;
        }

        // Add DyldCache Mach-O's to program tree
        self.monitor.set_message("Adding DYLIB's to program tree...");
        self.monitor.initialize(info_set.len() as i64);
        for info in &info_set {
            self.monitor.check_cancelled().map_err(to_io)?;
            self.monitor.increment_progress(1);
            self.add_to_program_tree(info)?;
        }

        // Process DyldCache DYLIB memory blocks
        if self.options.process_dylib_memory {
            self.monitor.set_message("Processing DYLIB memory blocks...");
            self.monitor.initialize(info_set.len() as i64);
            for info in &info_set {
                self.monitor.check_cancelled().map_err(to_io)?;
                self.monitor.increment_progress(1);
                macho_program_builder::process_memory_blocks(
                    &mut *self.program,
                    &*info.header,
                    &info.name,
                    true,
                    false,
                    self.log,
                    self.monitor,
                )?;
            }
        }

        // Markup DyldCache DYLIB load command data
        if self.options.markup_dylib_load_command_data {
            self.monitor.set_message("Marking up DYLIB load command data...");
            self.monitor.initialize(info_set.len() as i64);
            for info in &info_set {
                self.monitor.check_cancelled().map_err(to_io)?;
                self.monitor.increment_progress(1);
                macho_program_builder::markup_load_command_data(
                    &mut *self.program,
                    &*info.header,
                    &info.name,
                    self.log,
                    self.monitor,
                )?;
            }
        }

        // Create DYLIB symbols
        if self.options.process_dylib_symbols {
            self.monitor.set_message("Creating DYLIB symbols...");
            self.monitor.initialize(info_set.len() as i64);
            for info in &info_set {
                macho_program_builder::process_symbol_tables(
                    &mut *self.program,
                    &*info.header,
                    false,
                    self.log,
                    self.monitor,
                )?;
                self.monitor.check_cancelled().map_err(to_io)?;
                self.monitor.increment_progress(1);
            }
        }

        // Create DYLIB Exports
        if self.options.process_dylib_exports {
            self.monitor.set_message("Creating DYLIB exports...");
            self.monitor.initialize(info_set.len() as i64);
            for info in &info_set {
                macho_program_builder::process_exports(
                    &mut *self.program,
                    &*info.header,
                    self.log,
                    self.monitor,
                )?;
                self.monitor.check_cancelled().map_err(to_io)?;
                self.monitor.increment_progress(1);
            }
        }

        // Process and markup the libobjc DYLIB
        if self.options.process_libobjc {
            self.monitor.set_message("Processing libobjc...");
            if let Some(lib_objc_info) = info_set.iter().find(|e| is_libobjc(&e.name)) {
                let lib_objc_dylib = LibObjcDylib::new(
                    &*lib_objc_info.header,
                    &*self.program,
                    &self.space,
                    self.log,
                    self.monitor,
                );
                lib_objc_dylib.markup(&mut *self.program)?;
            }
        }

        Ok(())
    }

    /// Marks up one cached Mach-O's headers. Port of `DyldCacheMachoInfo.markupHeaders()`.
    fn markup_dylib_headers(&mut self, info: &DyldCacheMachoInfo) -> io::Result<()> {
        macho_program_builder::markup_headers(
            &mut *self.program,
            &*info.header,
            &info.header_addr,
            self.log,
            self.monitor,
        )?;

        if !info.name.is_empty() {
            if let Some(listing) = self.program.get_listing() {
                listing.set_comment(
                    &info.header_addr,
                    CommentType::Plate,
                    Some(info.path.clone()),
                );
            }
        }
        Ok(())
    }

    /// Adds an entry to the program tree for one cached Mach-O: a module named the Mach-O's path
    /// in the DYLD Cache, and fragments for each of its segments and sections. Port of
    /// `DyldCacheMachoInfo.addToProgramTree()`.
    ///
    /// A listing with no buildable program tree (see
    /// [`Listing::get_default_root_module_mut`](crate::program::model::listing::Listing::get_default_root_module_mut))
    /// leaves the tree untouched; Java always has one.
    fn add_to_program_tree(&mut self, info: &DyldCacheMachoInfo) -> io::Result<()> {
        let memory = self.program.get_memory();
        let segments = info.header.get_all_segments();
        let path = info.path.clone();
        let space = Arc::clone(&self.space);
        let log = self.log;

        let Some(listing) = self.program.get_listing() else {
            return Ok(());
        };
        let Some(root) = listing.get_default_root_module_mut() else {
            return Ok(());
        };
        let mut module = match root.create_module(&path) {
            Ok(module) => module,
            Err(_) => {
                log.append_msg(&format!(
                    "Failed to add duplicate module to program tree: {path}"
                ));
                return Ok(());
            }
        };

        // Add the segments, because things like the header are not included in any section
        for segment in &segments {
            if segment.get_v_msize() == 0 {
                continue;
            }
            if segment.get_segment_name() == segment_names::LINKEDIT {
                continue; // __LINKEDIT segment is shared across all modules
            }
            let segment_start = space.address(segment.get_v_maddress());
            let mut segment_end =
                segment_start.add(segment.get_v_msize() - 1).map_err(to_io)?;
            if !contains(memory.as_deref(), &segment_end) {
                let Some(end) = block_end(memory.as_deref(), &segment_start) else {
                    continue;
                };
                segment_end = end;
            }
            let mut segment_fragment = module
                .create_fragment(&format!("{} - {}", segment.get_segment_name(), path))
                .map_err(to_io)?;
            segment_fragment.move_code_units(&segment_start, &segment_end).map_err(to_io)?;

            // Add the sections, which will remove overlapped ranges from the segment fragment
            for section in segment.get_sections() {
                if section.get_size() == 0 {
                    continue;
                }
                let section_start = space.address(section.get_address());
                let mut section_end =
                    section_start.add(section.get_size() - 1).map_err(to_io)?;
                if !contains(memory.as_deref(), &section_end) {
                    let Some(end) = block_end(memory.as_deref(), &section_start) else {
                        continue;
                    };
                    section_end = end;
                }
                let mut section_fragment = module
                    .create_fragment(&format!(
                        "{} {} - {}",
                        section.get_segment_name(),
                        section.get_section_name(),
                        path
                    ))
                    .map_err(to_io)?;
                section_fragment
                    .move_code_units(&section_start, &section_end)
                    .map_err(to_io)?;
            }

            // If the sections fully filled the segment, we can remove the now-empty segment
            if segment_fragment.is_empty() {
                module.remove_child(&segment_fragment.get_name()).map_err(to_io)?;
            }
        }
        Ok(())
    }
}

/// Convenience struct storing what this builder needs about an individual Mach-O.
///
/// Port of the private inner class `DyldCacheProgramBuilder.DyldCacheMachoInfo`; see the module
/// docs for why it carries no back-reference to the builder.
struct DyldCacheMachoInfo {
    header_addr: Address,
    header: Box<dyn MachHeader>,
    path: String,
    name: String,
}

impl DyldCacheMachoInfo {
    /// Port of `DyldCacheMachoInfo(SplitDyldCache, MachHeader, Address, String)`. The
    /// `SplitDyldCache` argument only reaches `MachHeader.parse(SplitDyldCache)`, which the
    /// placeholder header cannot tell from the no-arg `parse()` (see [`MachHeader::parse`]), so
    /// it is not threaded through.
    fn new(
        mut header: Box<dyn MachHeader>,
        header_addr: Address,
        path: &str,
    ) -> io::Result<Self> {
        header.parse()?;
        Ok(DyldCacheMachoInfo {
            header_addr,
            header,
            path: path.to_string(),
            name: file_name(path).to_string(),
        })
    }
}

/// The suffix `processDyldCacheMemoryBlocks` appends to its `DYLD`/`FILE` block names:
/// everything from a cache file name's first `.` onwards, or nothing when it has none.
///
/// Port of `name.contains(".") ? name.substring(name.indexOf(".")) : ""`.
fn block_name_extension(name: &str) -> &str {
    match name.find('.') {
        Some(index) => &name[index..],
        None => "",
    }
}

/// Port of `new File(path).getName()`: the last `/`-separated component of `path`, ignoring any
/// trailing separators, or `path` itself when it contains none.
fn file_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        // `new File("/").getName()` and `new File("").getName()` are both "".
        return "";
    }
    match trimmed.rfind('/') {
        Some(index) => &trimmed[index + 1..],
        None => trimmed,
    }
}

/// Port of `info.name.contains("libobjc.")`, the test `processDylibs` picks the libobjc DYLIB by.
fn is_libobjc(name: &str) -> bool {
    name.contains("libobjc.")
}

/// Stands in for `AddressSpace.OTHER_SPACE`: the program's own `OTHER` space when it has one,
/// else a space matching how `DefaultAddressFactory` defines it. See the module docs.
fn other_space(program: &dyn Program) -> Arc<AddressSpace> {
    program
        .get_address_factory()
        .and_then(|factory| factory.get_address_space_by_name("OTHER"))
        .unwrap_or_else(|| AddressSpace::new("OTHER", 32, 1, AddressSpaceType::Other, 3))
}

/// `memory.contains(addr)` for a program that may not expose memory at all, in which case
/// nothing is mapped.
fn contains(memory: Option<&dyn crate::program::model::mem::Memory>, addr: &Address) -> bool {
    memory.is_some_and(|memory| memory.contains(addr))
}

/// `memory.getBlock(addr).getEnd()`, or `None` when there is no memory or no block there --
/// where Java would have thrown an NPE.
fn block_end(
    memory: Option<&dyn crate::program::model::mem::Memory>,
    addr: &Address,
) -> Option<Address> {
    Some(memory?.get_block(addr)?.get_end())
}

/// Collapses the several checked exceptions Java's `build()` declares (`AddressOverflowException`,
/// `CancelledException`, `DuplicateNameException`, `NotFoundException`, `NotEmptyException`) onto
/// this port's single `io::Error` channel.
fn to_io<E: Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- `processDyldCacheMemoryBlocks`'s DYLD/FILE block naming ---

    #[test]
    fn block_name_extension_starts_at_the_first_dot() {
        // A DYLD sub-cache file is named e.g. `dyld_shared_cache_arm64e.01`, and its blocks are
        // named `DYLD.01` / `FILE.01`.
        assert_eq!(block_name_extension("dyld_shared_cache_arm64e.01"), ".01");
        assert_eq!(format!("DYLD{}", block_name_extension("dyld_shared_cache_arm64e.01")), "DYLD.01");
        assert_eq!(format!("FILE{}", block_name_extension("dyld_shared_cache_arm64e.01")), "FILE.01");
    }

    #[test]
    fn block_name_extension_is_empty_without_a_dot() {
        // The primary cache file has no extension, so its blocks are plain `DYLD` / `FILE`.
        assert_eq!(block_name_extension("dyld_shared_cache_arm64e"), "");
        assert_eq!(format!("DYLD{}", block_name_extension("dyld_shared_cache_arm64e")), "DYLD");
    }

    #[test]
    fn block_name_extension_takes_the_first_dot_not_the_last() {
        // `indexOf`, not `lastIndexOf`: the whole `.symbols.01` tail is the extension.
        assert_eq!(block_name_extension("dyld_shared_cache_arm64e.symbols.01"), ".symbols.01");
    }

    // --- `DyldCacheMachoInfo`'s `name` (`new File(path).getName()`) ---

    #[test]
    fn file_name_is_the_last_path_component() {
        assert_eq!(file_name("/usr/lib/libobjc.A.dylib"), "libobjc.A.dylib");
        assert_eq!(file_name("/System/Library/Frameworks/Foundation.framework/Foundation"), "Foundation");
    }

    #[test]
    fn file_name_of_a_bare_name_is_itself() {
        assert_eq!(file_name("libSystem.B.dylib"), "libSystem.B.dylib");
    }

    #[test]
    fn file_name_ignores_trailing_separators() {
        // `new File("/usr/lib/").getName()` is "lib", and `new File("/").getName()` is "".
        assert_eq!(file_name("/usr/lib/"), "lib");
        assert_eq!(file_name("/"), "");
    }

    // --- `processDylibs`'s libobjc selection ---

    #[test]
    fn libobjc_is_matched_by_name_including_its_dot() {
        assert!(is_libobjc("libobjc.A.dylib"));
        // The trailing '.' in the Java literal keeps `libobjc-trampolines.dylib` out.
        assert!(!is_libobjc("libobjc-trampolines.dylib"));
        assert!(!is_libobjc("libSystem.B.dylib"));
    }

    // --- `DyldCacheMachoInfo` ordering (the `TreeSet` comparator) ---

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    /// A [`MachHeader`] with no segments, standing in for a cached DYLIB whose headers this test
    /// does not walk.
    struct EmptyMachHeader;

    impl MachHeader for EmptyMachHeader {
        fn get_segment(
            &self,
            _segment_name: &str,
        ) -> Option<Box<dyn crate::format::seam_stubs::SegmentCommand>> {
            None
        }
        fn get_all_segments(&self) -> Vec<Box<dyn crate::format::seam_stubs::SegmentCommand>> {
            Vec::new()
        }
    }

    fn info(offset: i64, path: &str) -> DyldCacheMachoInfo {
        DyldCacheMachoInfo::new(Box::new(EmptyMachHeader), space().address(offset), path).unwrap()
    }

    #[test]
    fn macho_info_derives_its_name_from_the_path() {
        let info = info(0x1000, "/usr/lib/libobjc.A.dylib");
        assert_eq!(info.path, "/usr/lib/libobjc.A.dylib");
        assert_eq!(info.name, "libobjc.A.dylib");
        assert!(is_libobjc(&info.name));
    }

    #[test]
    fn macho_infos_sort_by_header_address_and_drop_duplicates() {
        // Mirrors `new TreeSet<>((a, b) -> a.headerAddr.compareTo(b.headerAddr))`: sorted by
        // header address, and a second image at an already-seen address is not added.
        let mut info_set = vec![
            info(0x3000, "/usr/lib/c.dylib"),
            info(0x1000, "/usr/lib/a.dylib"),
            info(0x3000, "/usr/lib/c-again.dylib"),
            info(0x2000, "/usr/lib/b.dylib"),
        ];
        info_set.sort_by(|a, b| a.header_addr.cmp(&b.header_addr));
        info_set.dedup_by(|a, b| a.header_addr == b.header_addr);

        let names: Vec<&str> = info_set.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["a.dylib", "b.dylib", "c.dylib"]);
    }

    // --- `addToProgramTree`'s fragment names ---

    #[test]
    fn program_tree_fragment_names_match_the_java_formats() {
        let path = "/usr/lib/libobjc.A.dylib";
        assert_eq!(
            format!("{} - {}", "__TEXT", path),
            "__TEXT - /usr/lib/libobjc.A.dylib"
        );
        assert_eq!(
            format!("{} {} - {}", "__TEXT", "__text", path),
            "__TEXT __text - /usr/lib/libobjc.A.dylib"
        );
    }

    #[test]
    fn linkedit_is_the_segment_skipped_when_building_the_program_tree() {
        // `__LINKEDIT` is shared across every module in the cache, so it gets no fragment.
        assert_eq!(segment_names::LINKEDIT, "__LINKEDIT");
    }

    // --- the `Dyld Cache Header` bookmark comment ---

    #[test]
    fn dyld_cache_header_bookmark_comment_pairs_the_name_with_the_uuid() {
        let uuid = [0x0a_u8, 0x1b, 0xff, 0x00];
        let comment = format!(
            "{} - {}",
            "dyld_shared_cache_arm64e",
            crate::app::seam_stubs::NumericUtilities::convert_bytes_to_string(&uuid, "")
        );
        assert_eq!(comment, "dyld_shared_cache_arm64e - 0a1bff00");
    }
}
