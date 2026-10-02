//! Port of `ghidra.app.util.opinion.MemorySectionResolver`: collects the memory "sections" a
//! loader wants (ELF segments and sections, which may overlap or share file bytes) and resolves
//! them into non-conflicting program memory blocks.
//!
//! # Shape
//!
//! Java's abstract class holds shared state plus two abstract block-creation hooks. The state and
//! the concrete algorithm live in [`MemorySectionResolverBase`]; the hooks are the
//! [`MemorySectionResolver`] trait, which the loader implements and hands to
//! [`MemorySectionResolverBase::resolve`] at call time (no back-pointer from the base to the
//! loader). Sections are keyed by a loader-chosen `K` (see
//! [`MemorySection`](super::memory_section::MemorySection)).
//!
//! # Divergences
//!
//! * Java's `fileAllocationMap` (`AddressRangeObjectMap<AllocatedFileSectionRange>`) is written
//!   during `allocateSectionMemory` but never read; it is not reproduced.
//! * This port's address model has no overlay spaces, so a block's "physical" address is the
//!   address itself and `physicalLoadedOverlaySet` only ever holds blocks a
//!   [`MemoryBlock::is_overlay`](crate::program::model::mem::MemoryBlock::is_overlay)
//!   implementation reports. Requests to create overlay blocks are passed to the hooks unchanged.
//! * `Msg.error` on a failed section is a `log::error!`-free [`Msg::error`] call, as elsewhere.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io;
use std::sync::Arc;

use thiserror::Error;

use crate::app::util::opinion::memory_section::{MemorySection, NotMemoryAddressError};
use crate::program::model::address::{
    Address, AddressOverflowException, AddressRange, AddressSet, AddressSetView, AddressSpace,
    AddressSpaceType,
};
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryBlockHandle;
use crate::util::datastruct::index_range_iterator::IndexRangeIterator;
use crate::util::datastruct::object_range_map::ObjectRangeMap;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// The checked exceptions Java's block-creation hooks declare.
#[derive(Debug, Error)]
pub enum MemorySectionError {
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Failures of [`MemorySectionResolverBase`]'s public methods (Java's `IllegalStateException` /
/// `IllegalArgumentException` / `AddressOverflowException` / `CancelledException`).
#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("{0}")]
    IllegalState(&'static str),
    #[error(transparent)]
    NotMemoryAddress(#[from] NotMemoryAddressError),
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// The two abstract methods of Java's `MemorySectionResolver`: create the memory block for (a
/// possibly fragmented chunk of) a resolved section.
pub trait MemorySectionResolver<K> {
    /// `createInitializedBlock(MemoryLoadable, boolean, String, Address, long, long, String,
    /// boolean, boolean, boolean, TaskMonitor)`. `Ok(None)` is Java's `null` (block not created
    /// -- discarded or logged conflict).
    #[allow(clippy::too_many_arguments)]
    fn create_initialized_block(
        &self,
        key: Option<&K>,
        is_overlay: bool,
        name: &str,
        start: &Address,
        file_offset: i64,
        length: i64,
        comment: Option<&str>,
        r: bool,
        w: bool,
        x: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<MemoryBlockHandle>, MemorySectionError>;

    /// `createUninitializedBlock(MemoryLoadable, boolean, String, Address, long, String,
    /// boolean, boolean, boolean)`.
    #[allow(clippy::too_many_arguments)]
    fn create_uninitialized_block(
        &self,
        key: Option<&K>,
        is_overlay: bool,
        name: &str,
        start: &Address,
        length: i64,
        comment: Option<&str>,
        r: bool,
        w: bool,
        x: bool,
    ) -> Result<Option<MemoryBlockHandle>, MemorySectionError>;
}

/// Java's inner `AllocatedFileSectionRange`: a chunk of file bytes already placed in memory.
/// `id` gives each allocation the identity Java's (non-`equals`-overriding) object has, so
/// [`ObjectRangeMap`] never coalesces two distinct allocations.
#[derive(Debug, Clone, PartialEq)]
struct AllocatedFileSectionRange {
    id: usize,
    range_start_file_offset: i64,
    /// Size in file bytes.
    range_size: i64,
    /// Start of the memory range.
    range_start_address: Address,
}

/// A memory range a section was allocated to (Java distinguishes these by `AddressRangeImpl`
/// subclass).
#[derive(Debug, Clone)]
enum AllocatedRange {
    /// A new, non-conflicting range (`AddressRangeImpl`).
    Normal(AddressRange),
    /// Supplied by another section mapping the same file region (`ProxyAddressRange`).
    Proxy(AddressRange),
    /// Must be converted to a named overlay (`OverlayAddressRange`).
    Overlay(AddressRange),
}

impl AllocatedRange {
    fn range(&self) -> &AddressRange {
        match self {
            AllocatedRange::Normal(r) | AllocatedRange::Proxy(r) | AllocatedRange::Overlay(r) => r,
        }
    }
}

/// The shared state and concrete algorithm of Java's `MemorySectionResolver`.
pub struct MemorySectionResolverBase<K> {
    used_block_names: HashSet<String>,
    physical_loaded_overlay_set: AddressSet,
    /// Built up prior to resolve.
    sections: Vec<MemorySection<K>>,
    section_index_map: HashMap<String, i32>,
    /// Created at time of resolve.
    section_memory_map: Option<HashMap<K, Vec<AddressRange>>>,
    next_non_loaded_section_insertion_index: usize,
    file_load_maps: Option<HashMap<Arc<AddressSpace>, ObjectRangeMap<AllocatedFileSectionRange>>>,
    next_allocation_id: usize,
}

fn is_non_loaded_memory_address(addr: &Address) -> bool {
    addr.space().space_type() == AddressSpaceType::Other
}

impl<K: Clone + Eq + Hash> MemorySectionResolverBase<K> {
    /// Mirrors `MemorySectionResolver(Program)`.
    ///
    /// # Errors
    /// [`ResolverError::IllegalState`] if `program` already has memory blocks.
    pub fn new(program: &dyn Program) -> Result<Self, ResolverError> {
        Self::check_memory_empty(program)?;
        Ok(Self::empty())
    }

    /// An unchecked, empty resolver (used to park the state while it is being resolved).
    pub(crate) fn empty() -> Self {
        MemorySectionResolverBase {
            used_block_names: HashSet::new(),
            physical_loaded_overlay_set: AddressSet::new(),
            sections: Vec::new(),
            section_index_map: HashMap::new(),
            section_memory_map: None,
            next_non_loaded_section_insertion_index: 0,
            file_load_maps: None,
            next_allocation_id: 0,
        }
    }

    fn check_memory_empty(program: &dyn Program) -> Result<(), ResolverError> {
        if program.get_memory().is_some_and(|m| !m.is_empty()) {
            return Err(ResolverError::IllegalState(
                "program memory blocks already exist - unsupported",
            ));
        }
        Ok(())
    }

    /// Mirrors `addInitializedMemorySection(...)`: adds an initialized memory "section" drawn from
    /// `file_offset` of the (single) data source. The last section defined takes precedence when
    /// resolving conflicts; loaded sections take precedence over non-loaded ones.
    ///
    /// # Errors
    /// `IllegalState` if already resolved; an address overflow computing the section's end.
    #[allow(clippy::too_many_arguments)]
    pub fn add_initialized_memory_section(
        &mut self,
        key: Option<K>,
        file_offset: i64,
        number_of_bytes: i64,
        start_address: &Address,
        section_name: Option<&str>,
        is_readable: bool,
        is_writable: bool,
        is_executable: bool,
        comment: Option<String>,
        is_fragmentation_ok: bool,
        is_loaded_section: bool,
    ) -> Result<(), ResolverError> {
        if self.section_memory_map.is_some() {
            return Err(ResolverError::IllegalState("already resolved"));
        }
        let section_name = self.get_unique_section_name(section_name);
        let memory_section = MemorySection::new(
            key,
            true,
            file_offset,
            number_of_bytes,
            Self::make_range(start_address, number_of_bytes)?,
            section_name,
            is_readable,
            is_writable,
            is_executable,
            comment,
            is_fragmentation_ok,
        )?;
        if is_loaded_section {
            self.sections.push(memory_section);
        } else {
            // ensure that non-loaded sections are processed after loaded sections
            // by inserting them before the loaded sections
            self.sections.insert(self.next_non_loaded_section_insertion_index, memory_section);
            self.next_non_loaded_section_insertion_index += 1;
        }
        Ok(())
    }

    /// Mirrors `addUninitializedMemorySection(...)`.
    ///
    /// # Errors
    /// As for [`add_initialized_memory_section`](Self::add_initialized_memory_section).
    #[allow(clippy::too_many_arguments)]
    pub fn add_uninitialized_memory_section(
        &mut self,
        key: Option<K>,
        number_of_bytes: i64,
        start_address: &Address,
        section_name: Option<&str>,
        is_readable: bool,
        is_writable: bool,
        is_executable: bool,
        comment: Option<String>,
        is_fragmentation_ok: bool,
    ) -> Result<(), ResolverError> {
        if self.section_memory_map.is_some() {
            return Err(ResolverError::IllegalState("already resolved"));
        }
        let section_name = self.get_unique_section_name(section_name);
        self.sections.push(MemorySection::new(
            key,
            false,
            -1,
            number_of_bytes,
            Self::make_range(start_address, number_of_bytes)?,
            section_name,
            is_readable,
            is_writable,
            is_executable,
            comment,
            is_fragmentation_ok,
        )?);
        Ok(())
    }

    fn get_unique_section_name(&self, base_name: Option<&str>) -> String {
        let base_name = match base_name.map(str::trim) {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => "NO-NAME".to_string(),
        };
        let mut name = base_name.clone();
        let mut index = 0;
        while self.used_block_names.contains(&name) {
            index += 1;
            name = format!("{base_name}-{index}");
        }
        name
    }

    fn get_unique_section_chunk_name(&self, section: &MemorySection<K>, preferred_index: i32) -> String {
        let section_name = section.get_section_name();
        let mut index = preferred_index;
        loop {
            let mut name = section_name.to_string();
            if index >= 0 {
                name.push_str(&format!(".{index}"));
            }
            if !self.used_block_names.contains(&name) {
                return name;
            }
            if index <= 0 {
                index = 1;
            } else {
                index += 1;
            }
        }
    }

    fn make_range(start_address: &Address, number_of_bytes: i64) -> Result<AddressRange, AddressOverflowException> {
        let end_address = start_address.add_no_wrap(number_of_bytes - 1)?;
        Ok(AddressRange::new(start_address.clone(), end_address))
    }

    /// Mirrors `getResolvedLoadAddresses(MemoryLoadable)`: the memory ranges the section keyed
    /// by `key` resolved to, or `None` if it was not resolved (or `resolve` has not run).
    pub fn get_resolved_load_addresses(&self, key: &K) -> Option<&[AddressRange]> {
        self.section_memory_map.as_ref()?.get(key).map(Vec::as_slice)
    }

    fn get_file_load_range_map(
        &mut self,
        space: &Arc<AddressSpace>,
        create: bool,
    ) -> Option<&mut ObjectRangeMap<AllocatedFileSectionRange>> {
        if self.file_load_maps.is_none() {
            if !create {
                return None;
            }
            self.file_load_maps = Some(HashMap::new());
        }
        let maps = self.file_load_maps.as_mut().unwrap();
        if create {
            Some(maps.entry(Arc::clone(space)).or_insert_with(ObjectRangeMap::new))
        } else {
            maps.get_mut(space)
        }
    }

    /// Mirrors `resolve(TaskMonitor)`: resolves all defined sections, creating their memory
    /// blocks through `hooks`. Sections are processed in reverse order -- the last one added
    /// takes precedence.
    ///
    /// # Errors
    /// `IllegalState` if already resolved or memory is no longer empty; `Cancelled`.
    pub fn resolve(
        &mut self,
        program: &dyn Program,
        hooks: &dyn MemorySectionResolver<K>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ResolverError> {
        monitor.set_message("Loading memory blocks...");

        if self.section_memory_map.is_some() {
            return Err(ResolverError::IllegalState("already resolved"));
        }
        Self::check_memory_empty(program)?;

        // build-up mapping of sections to a sequence of memory ranges
        self.section_memory_map = Some(HashMap::new());

        self.physical_loaded_overlay_set = AddressSet::new();
        if let Some(memory) = program.get_memory() {
            for block in memory.get_block_handles() {
                let b = block.read().unwrap();
                let min_addr = b.get_start();
                if min_addr.is_loaded_memory_address() && b.is_overlay() {
                    self.physical_loaded_overlay_set.add_range(&min_addr, &b.get_end());
                }
            }
        }

        // process sections in reverse order - last-in takes precedence
        let section_count = self.sections.len();
        monitor.initialize(section_count as i64);
        for index in (0..section_count).rev() {
            monitor.check_cancelled()?;
            let section = self.sections[index].clone();
            self.resolve_section_memory(program, hooks, &section, monitor)?;
            monitor.increment_progress(1);
        }
        Ok(())
    }

    /// Mirrors `resolveSectionMemory(...)`.
    fn resolve_section_memory(
        &mut self,
        program: &dyn Program,
        hooks: &dyn MemorySectionResolver<K>,
        section: &MemorySection<K>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let memory_allocation_list = self.allocate_section_memory(program, section, monitor)?;
        match self.process_section_ranges(program, hooks, section, &memory_allocation_list, monitor) {
            Ok(section_memory_ranges) => {
                if let Some(key) = section.get_key() {
                    self.section_memory_map
                        .as_mut()
                        .expect("resolve creates the section memory map")
                        .insert(key.clone(), section_memory_ranges);
                }
                Ok(())
            }
            Err(MemorySectionError::Cancelled(e)) => Err(e),
            Err(e) => {
                let range = section.get_physical_address_range();
                Msg::error(
                    "MemorySectionResolver",
                    &format!(
                        "Error while creating section {}[{}, {}]: {}",
                        section.get_section_name(),
                        range.min_address(),
                        range.max_address(),
                        e
                    ),
                );
                Ok(())
            }
        }
    }

    /// Mirrors `processSectionRanges(...)`: creates the section's memory block(s) for
    /// `memory_allocation_list` and returns the memory ranges the section ended up in.
    fn process_section_ranges(
        &mut self,
        program: &dyn Program,
        hooks: &dyn MemorySectionResolver<K>,
        section: &MemorySection<K>,
        memory_allocation_list: &[AllocatedRange],
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<AddressRange>, MemorySectionError> {
        let mut section_byte_offset: i64 = 0;

        let address_space = Arc::clone(section.get_physical_address_space());
        let use_file_load_map = address_space.space_type() != AddressSpaceType::Other;
        if use_file_load_map {
            self.get_file_load_range_map(&address_space, true);
        }

        let mut modified_range_list = Vec::new();

        for allocated_addr_range in memory_allocation_list {
            monitor.check_cancelled()?;

            // Generate block name rangeIndex suffix if section sliced-up
            let mut range_index = self
                .section_index_map
                .get(&section.section_name)
                .map_or(1, |i| i + 1);
            self.section_index_map.insert(section.section_name.clone(), range_index);
            if range_index == 1 && memory_allocation_list.len() == 1 {
                range_index = -1; // prefer to omit index if only a single range
            }

            let range = allocated_addr_range.range();
            let range_size = range.length() as i64;

            if let AllocatedRange::Proxy(r) = allocated_addr_range {
                modified_range_list.push(r.clone());
                section_byte_offset += range_size;
                continue; // skip range
            }

            let block_name = self.get_unique_section_chunk_name(section, range_index);

            let physical_start_addr = section.get_min_physical_address().add(section_byte_offset)?;

            if section.is_initialized {
                let file_offset = section.file_offset + section_byte_offset;
                let block = if matches!(allocated_addr_range, AllocatedRange::Overlay(_)) {
                    let mut comment = section.get_comment().map(str::to_string);
                    if section.is_loaded() {
                        // assume another section took priority
                        let priority = program
                            .get_memory()
                            .and_then(|m| m.get_block_handle(&physical_start_addr));
                        if let Some(priority_block) = priority {
                            comment = Some(format!(
                                "{} - displaced by {}",
                                comment.as_deref().unwrap_or("null"),
                                priority_block.read().unwrap().get_name()
                            ));
                        }
                    }
                    hooks.create_initialized_block(
                        section.get_key(),
                        true,
                        &block_name,
                        &physical_start_addr,
                        file_offset,
                        range_size,
                        comment.as_deref(),
                        section.is_readable(),
                        section.is_writable(),
                        section.is_execute(),
                        monitor,
                    )?
                } else {
                    hooks.create_initialized_block(
                        section.get_key(),
                        false,
                        &block_name,
                        &physical_start_addr,
                        file_offset,
                        range_size,
                        section.get_comment(),
                        section.is_readable(),
                        section.is_writable(),
                        section.is_execute(),
                        monitor,
                    )?
                };
                let (min_addr, max_addr) = match &block {
                    Some(block) => {
                        let b = block.read().unwrap();
                        let (min_addr, max_addr) = (b.get_start(), b.get_end());
                        self.used_block_names.insert(block_name.clone());
                        if b.is_overlay() && min_addr.is_loaded_memory_address() {
                            self.physical_loaded_overlay_set.add_range(&min_addr, &max_addr);
                        }
                        (min_addr, max_addr)
                    }
                    None => {
                        // block may be null due to unexpected conflict or pruning - allow to
                        // continue
                        let max_addr = physical_start_addr.add_no_wrap(range_size - 1)?;
                        (physical_start_addr.clone(), max_addr)
                    }
                };
                if use_file_load_map {
                    let chunk_file_offset = section.get_file_offset() + section_byte_offset;
                    let id = self.next_allocation_id;
                    self.next_allocation_id += 1;
                    let allocated_file_range = AllocatedFileSectionRange {
                        id,
                        range_start_file_offset: chunk_file_offset,
                        range_size,
                        range_start_address: min_addr.clone(),
                    };
                    self.get_file_load_range_map(&address_space, true)
                        .expect("created above")
                        .set_object(chunk_file_offset, chunk_file_offset + range_size - 1, allocated_file_range);
                }
                modified_range_list.push(AddressRange::new(min_addr, max_addr));
            } else {
                if !matches!(allocated_addr_range, AllocatedRange::Overlay(_)) {
                    hooks.create_uninitialized_block(
                        section.get_key(),
                        false,
                        &block_name,
                        &physical_start_addr,
                        range_size,
                        section.get_comment(),
                        section.is_readable(),
                        section.is_writable(),
                        section.is_execute(),
                    )?;
                }
                modified_range_list.push(range.clone());
            }
            section_byte_offset += range_size;
        }
        Ok(modified_range_list)
    }

    /// Mirrors `getMemoryConflictSet(Address, Address)`: the existing loaded memory (by physical
    /// address) that intersects `[range_min, range_max]`.
    fn get_memory_conflict_set(&self, program: &dyn Program, range_min: &Address, range_max: &Address) -> AddressSet {
        // dedicated non-loaded overlay - don't bother with conflict check
        if is_non_loaded_memory_address(range_min) {
            return AddressSet::new();
        }
        // Get base memory conflict set
        let mut conflict_set = program
            .get_memory()
            .map_or_else(AddressSet::new, |m| m.intersect_range(range_min, range_max));
        if !self.physical_loaded_overlay_set.is_empty() {
            // Add in loaded overlay physical address conflicts
            conflict_set.add_set(&self.physical_loaded_overlay_set.intersect_range(range_min, range_max));
        }
        conflict_set
    }

    /// Mirrors `allocateSectionMemory(...)`: splits `section` into memory ranges, identifying
    /// ranges another section already supplies (proxy) and conflicts that must become overlays.
    fn allocate_section_memory(
        &mut self,
        program: &dyn Program,
        section: &MemorySection<K>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<AllocatedRange>, CancelledException> {
        let mut range_list = Vec::new();

        let mut target_min_physical_addr = section.get_min_physical_address().clone();
        let target_max_physical_addr = section.get_max_physical_address().clone();

        if !section.is_loaded() {
            // section should be assigned to named overlay in OTHER space
            range_list.push(AllocatedRange::Overlay(AddressRange::new(
                target_min_physical_addr,
                target_max_physical_addr,
            )));
            return Ok(range_list);
        }

        let physical_conflict_addr_set =
            self.get_memory_conflict_set(program, &target_min_physical_addr, &target_max_physical_addr);
        let no_conflict = physical_conflict_addr_set.is_empty();
        if no_conflict || !section.is_fragmentation_ok {
            if no_conflict {
                // add normal non-conflicting section
                range_list.push(AllocatedRange::Normal(section.get_physical_address_range().clone()));
            } else {
                // if conflict and fragmentation not permitted bump section into overlay
                range_list.push(AllocatedRange::Overlay(section.get_physical_address_range().clone()));
            }
            return Ok(range_list);
        }

        let mut file_offset = section.get_file_offset(); // only used for initialized sections
        let result: Result<(), MemorySectionError> = (|| {
            for physical_addr_range in physical_conflict_addr_set.to_list() {
                monitor.check_cancelled()?;

                let physical_range_min_addr = physical_addr_range.min_address().clone();
                let physical_range_max_addr = physical_addr_range.max_address().clone();

                // Handle chunk before range
                if target_min_physical_addr < physical_range_min_addr {
                    // new range - no conflict
                    file_offset = Self::add_section_range(
                        section,
                        &target_min_physical_addr,
                        &physical_range_min_addr.previous()?,
                        file_offset,
                        &mut range_list,
                    );
                    target_min_physical_addr = physical_range_min_addr.clone();
                }

                // Handle overlap/conflict region
                file_offset = self.reconcile_section_range_overlap(
                    section,
                    &physical_range_min_addr,
                    &physical_range_max_addr,
                    file_offset,
                    &mut range_list,
                );
                // could bump into end of space
                target_min_physical_addr = physical_range_max_addr.add_no_wrap(1)?;
            }

            // Handle residual chunk
            if target_min_physical_addr <= target_max_physical_addr {
                // new range - no conflict
                Self::add_section_range(
                    section,
                    &target_min_physical_addr,
                    &target_max_physical_addr,
                    file_offset,
                    &mut range_list,
                );
            }
            Ok(())
        })();
        match result {
            Err(MemorySectionError::Cancelled(e)) => return Err(e),
            // ignore - end of space
            _ => {}
        }
        Ok(range_list)
    }

    /// Mirrors `addSectionRange(...)`.
    fn add_section_range(
        section: &MemorySection<K>,
        min_addr: &Address,
        max_addr: &Address,
        mut file_offset: i64,
        range_list: &mut Vec<AllocatedRange>,
    ) -> i64 {
        if section.is_initialized {
            file_offset += max_addr.subtract(min_addr) + 1;
        }
        range_list.push(AllocatedRange::Normal(AddressRange::new(min_addr.clone(), max_addr.clone())));
        file_offset
    }

    /// Mirrors `reconcileSectionRangeOverlap(...)`: adds proxy ranges where the conflicting
    /// memory already holds the same file bytes at the same address, and overlay ranges for the
    /// gaps where it does not.
    fn reconcile_section_range_overlap(
        &mut self,
        section: &MemorySection<K>,
        min_physical_addr: &Address,
        max_physical_addr: &Address,
        file_offset: i64,
        range_list: &mut Vec<AllocatedRange>,
    ) -> i64 {
        if !section.is_initialized {
            // force proxy range condition for lower priority uninitialized section (unlikely
            // condition)
            range_list.push(AllocatedRange::Proxy(AddressRange::new(
                min_physical_addr.clone(),
                max_physical_addr.clone(),
            )));
            return file_offset;
        }

        let conflict_range_size = max_physical_addr.subtract(min_physical_addr) + 1;

        let space = Arc::clone(min_physical_addr.space());
        let Some(file_load_range_map) = self.get_file_load_range_map(&space, false) else {
            // unexpected unless memory already defined
            range_list.push(AllocatedRange::Overlay(AddressRange::new(
                min_physical_addr.clone(),
                max_physical_addr.clone(),
            )));
            return file_offset + conflict_range_size;
        };

        // Snapshot the overlapping file-load ranges: Java walks them with a live iterator while
        // only reading the map.
        let mut file_ranges = Vec::new();
        {
            let mut it = file_load_range_map
                .get_index_range_iterator_in_range(file_offset, file_offset + conflict_range_size - 1);
            while it.has_next() {
                file_ranges.push(it.next());
            }
        }
        let file_ranges: Vec<_> = file_ranges
            .into_iter()
            .map(|r| {
                let object = file_load_range_map
                    .get_object(r.start())
                    .cloned()
                    .expect("iterated range has an object");
                (r, object)
            })
            .collect();

        // conflict gap accumulator addresses
        let mut conflict_gap_start: Option<Address> = None;
        let mut conflict_gap_end: Option<Address> = None;

        // NOTE: Range iterator does not fill-in the gaps, only those ranges which match-up will
        // be returned, range gaps correspond to memory conflict.
        let mut file_pos = file_offset;
        let mut expected_start: Option<Address> = Some(min_physical_addr.clone());

        for (file_offset_range, file_range) in file_ranges {
            let Some(mut expected) = expected_start.clone() else {
                // Java: AssertException("expectedRangeStart is null")
                break;
            };

            // get file load range - which may have been loaded to a different memory area
            let range_size = file_offset_range.end() - file_offset_range.start() + 1;

            if file_offset_range.start() > file_pos {
                // File load gap in memory - conflict with uninitialized or pre-existing block.
                if conflict_gap_start.is_none() {
                    conflict_gap_start = Some(expected.clone());
                }
                expected = expected.add_wrap(file_offset_range.start() - file_pos);
                conflict_gap_end = expected.previous().ok();
            }

            // Perform address computation in physical space
            let physical_addr_range_start = file_range
                .range_start_address
                .add_wrap(file_pos - file_range.range_start_file_offset);

            // Ignore use of overlay and compare physical address for match to avoid duplication
            if expected != physical_addr_range_start {
                // File load memory range does not correspond to target memory range
                if conflict_gap_start.is_none() {
                    conflict_gap_start = Some(expected.clone());
                }
                conflict_gap_end = Some(expected.add_wrap(range_size - 1));
            } else {
                // File load range matches target
                if let Some(gap_start) = conflict_gap_start.take() {
                    // add accumulated conflict gap
                    let gap_end = conflict_gap_end.take().unwrap_or_else(|| gap_start.clone());
                    range_list.push(AllocatedRange::Overlay(AddressRange::new(gap_start, gap_end)));
                }
                range_list.push(AllocatedRange::Proxy(AddressRange::new(
                    expected.clone(),
                    expected.add_wrap(range_size - 1),
                )));
            }

            file_pos = file_offset_range.end() + 1;
            // catch case where we hit the end of the address space
            expected_start = min_physical_addr.add(file_pos - file_offset).ok();
        }

        if file_pos - file_offset != conflict_range_size {
            // Trailing file load gap in memory - conflict with uninitialized or pre-existing block
            if conflict_gap_start.is_none() {
                conflict_gap_start = expected_start.clone();
            }
            conflict_gap_end = Some(max_physical_addr.clone());
        }
        if let (Some(gap_start), Some(gap_end)) = (conflict_gap_start, conflict_gap_end) {
            range_list.push(AllocatedRange::Overlay(AddressRange::new(gap_start, gap_end)));
        }
        file_offset + conflict_range_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::importer::message_log::MessageLog;
    use crate::app::util::memory_block_utils;
    use crate::app::util::memory_block_utils::tests::test_language;
    use crate::program::database::program_db::ProgramDB;
    use crate::program::model::address::factory::AddressFactory;
    use crate::util::task::DummyMonitor;
    use std::cell::RefCell;

    /// Records each hook call and creates real blocks through `MemoryBlockUtils` (stream-filled
    /// with the low byte of the file offset so tests can tell where bytes came from).
    struct Hooks<'a> {
        program: &'a ProgramDB,
        calls: RefCell<Vec<String>>,
        log: MessageLog,
    }

    impl MemorySectionResolver<u32> for Hooks<'_> {
        fn create_initialized_block(
            &self,
            key: Option<&u32>,
            is_overlay: bool,
            name: &str,
            start: &Address,
            file_offset: i64,
            length: i64,
            comment: Option<&str>,
            r: bool,
            w: bool,
            x: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<Option<MemoryBlockHandle>, MemorySectionError> {
            self.calls.borrow_mut().push(format!(
                "init {key:?} {name} {start} off={file_offset:#x} len={length:#x} ov={is_overlay}"
            ));
            if is_overlay {
                return Ok(None);
            }
            let bytes: Vec<u8> = (0..length).map(|i| (file_offset + i) as u8).collect();
            let mut input: &[u8] = &bytes;
            memory_block_utils::create_initialized_block_from_stream(
                self.program, false, name, start, &mut input, length, comment, None, r, w, x,
                &self.log, monitor,
            )
            .map_err(|e| MemorySectionError::Io(io::Error::other(e.to_string())))
        }

        fn create_uninitialized_block(
            &self,
            key: Option<&u32>,
            is_overlay: bool,
            name: &str,
            start: &Address,
            length: i64,
            comment: Option<&str>,
            r: bool,
            w: bool,
            x: bool,
        ) -> Result<Option<MemoryBlockHandle>, MemorySectionError> {
            self.calls
                .borrow_mut()
                .push(format!("uninit {key:?} {name} {start} len={length:#x} ov={is_overlay}"));
            Ok(memory_block_utils::create_uninitialized_block(
                self.program, false, name, start, length, comment, None, r, w, x, &self.log,
            ))
        }
    }

    fn setup() -> (ProgramDB, Arc<AddressSpace>) {
        let language = test_language(4, false);
        let space = language.get_address_factory().get_default_address_space().unwrap();
        (ProgramDB::new("p".into(), language).unwrap(), space)
    }

    fn blocks(program: &ProgramDB) -> Vec<(String, i64, u64)> {
        Program::get_memory(program)
            .unwrap()
            .get_block_handles()
            .iter()
            .map(|b| {
                let b = b.read().unwrap();
                (b.get_name().to_string(), b.get_start().offset(), b.get_size())
            })
            .collect()
    }

    #[test]
    fn disjoint_sections_become_one_block_each() {
        let (program, space) = setup();
        let hooks = Hooks { program: &program, calls: RefCell::new(vec![]), log: MessageLog::new() };
        let mut r = MemorySectionResolverBase::<u32>::new(&program).unwrap();
        r.add_initialized_memory_section(
            Some(1), 0x40, 0x20, &space.address(0x1000), Some(".text"), true, false, true, None,
            false, true,
        )
        .unwrap();
        r.add_uninitialized_memory_section(
            Some(2), 0x100, &space.address(0x2000), Some(".bss"), true, true, false, None, false,
        )
        .unwrap();
        r.resolve(&program, &hooks, &DummyMonitor).unwrap();
        assert_eq!(
            blocks(&program),
            vec![(".text".into(), 0x1000, 0x20), (".bss".into(), 0x2000, 0x100)]
        );
        assert_eq!(
            r.get_resolved_load_addresses(&1).unwrap(),
            &[AddressRange::new(space.address(0x1000), space.address(0x101f))]
        );
        // processed in reverse order: .bss first
        assert!(hooks.calls.borrow()[0].starts_with("uninit Some(2) .bss"));
    }

    #[test]
    fn segment_covering_sections_is_fragmented_around_them() {
        // A PT_LOAD segment (added first, fragmentation OK) and two sections inside it with
        // matching file offsets: the sections win, the segment keeps only the unclaimed gap,
        // and the section-covered parts become proxies of the section blocks.
        let (program, space) = setup();
        let hooks = Hooks { program: &program, calls: RefCell::new(vec![]), log: MessageLog::new() };
        let mut r = MemorySectionResolverBase::<u32>::new(&program).unwrap();
        r.add_initialized_memory_section(
            Some(10), 0x0, 0x300, &space.address(0x400000), Some("segment_2"), true, false, true,
            None, true, true,
        )
        .unwrap();
        r.add_initialized_memory_section(
            Some(1), 0x100, 0x80, &space.address(0x400100), Some(".text"), true, false, true,
            None, false, true,
        )
        .unwrap();
        r.add_initialized_memory_section(
            Some(2), 0x200, 0x40, &space.address(0x400200), Some(".rodata"), true, false, false,
            None, false, true,
        )
        .unwrap();
        r.resolve(&program, &hooks, &DummyMonitor).unwrap();
        assert_eq!(
            blocks(&program),
            vec![
                ("segment_2.1".into(), 0x400000, 0x100),
                (".text".into(), 0x400100, 0x80),
                ("segment_2.3".into(), 0x400180, 0x80),
                (".rodata".into(), 0x400200, 0x40),
                ("segment_2.5".into(), 0x400240, 0xc0),
            ]
        );
        // segment bytes come from the matching file offsets
        let mem = Program::get_memory(&program).unwrap();
        assert_eq!(mem.get_byte(&space.address(0x400180)).unwrap(), 0x80);
        assert_eq!(mem.get_byte(&space.address(0x400240)).unwrap(), 0x40);
        // segment's resolved ranges cover the whole segment, in order
        let ranges = r.get_resolved_load_addresses(&10).unwrap();
        assert_eq!(ranges.len(), 5);
        assert_eq!(ranges[0].min_address().offset(), 0x400000);
        assert_eq!(ranges[4].max_address().offset(), 0x4002ff);
    }

    #[test]
    fn non_loaded_and_conflicting_sections_are_overlays() {
        let (program, space) = setup();
        let other = AddressSpace::new("OTHER", 64, 1, AddressSpaceType::Other, 0);
        let hooks = Hooks { program: &program, calls: RefCell::new(vec![]), log: MessageLog::new() };
        let mut r = MemorySectionResolverBase::<u32>::new(&program).unwrap();
        r.add_initialized_memory_section(
            Some(1), 0x0, 0x10, &space.address(0x1000), Some(".a"), true, false, false, None,
            false, true,
        )
        .unwrap();
        // same addresses, different file bytes, no fragmentation -> overlay
        r.add_initialized_memory_section(
            Some(2), 0x80, 0x10, &space.address(0x1000), Some(".b"), true, false, false, None,
            false, true,
        )
        .unwrap();
        r.add_initialized_memory_section(
            Some(3), 0x90, 0x8, &other.address(0), Some(".comment"), false, false, false, None,
            false, false,
        )
        .unwrap();
        r.resolve(&program, &hooks, &DummyMonitor).unwrap();
        // .b (last) wins the address; .a and the non-loaded .comment go to overlays
        assert_eq!(blocks(&program), vec![(".b".into(), 0x1000, 0x10)]);
        let calls = hooks.calls.borrow();
        assert!(calls.iter().any(|c| c.contains(".a ") && c.ends_with("ov=true")));
        assert!(calls.iter().any(|c| c.contains(".comment") && c.ends_with("ov=true")));
    }

    #[test]
    fn duplicate_section_names_are_uniqued() {
        let (program, space) = setup();
        let mut r = MemorySectionResolverBase::<u32>::new(&program).unwrap();
        r.used_block_names.insert("x".into());
        assert_eq!(r.get_unique_section_name(Some(" x ")), "x-1");
        assert_eq!(r.get_unique_section_name(Some("  ")), "NO-NAME");
        assert_eq!(r.get_unique_section_name(None), "NO-NAME");
        let s = MemorySection::new(
            None::<u32>, true, 0, 1, AddressRange::new(space.address(0), space.address(0)),
            "x".into(), true, true, true, None, false,
        )
        .unwrap();
        assert_eq!(r.get_unique_section_chunk_name(&s, -1), "x.1");
        assert_eq!(r.get_unique_section_chunk_name(&s, 3), "x.3");
    }

    #[test]
    fn resolving_twice_or_into_nonempty_memory_fails() {
        let (program, space) = setup();
        let hooks = Hooks { program: &program, calls: RefCell::new(vec![]), log: MessageLog::new() };
        let mut r = MemorySectionResolverBase::<u32>::new(&program).unwrap();
        r.add_uninitialized_memory_section(
            Some(1), 0x10, &space.address(0x10), Some("u"), true, true, false, None, false,
        )
        .unwrap();
        r.resolve(&program, &hooks, &DummyMonitor).unwrap();
        assert!(matches!(
            r.resolve(&program, &hooks, &DummyMonitor),
            Err(ResolverError::IllegalState(_))
        ));
        assert!(MemorySectionResolverBase::<u32>::new(&program).is_err());
    }
}
