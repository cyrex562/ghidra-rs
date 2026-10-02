//! Port of `ghidra.program.database.mem.MemoryMapDB` -- block creation and byte access.
//!
//! The memory map owns the versioned [`MemoryMapDBAdapter`] (which owns the "Memory Blocks" /
//! "Sub Memory Blocks" tables and constructs the real [`MemoryBlockDB`]s with their
//! buffer / file-bytes / uninitialized sub blocks) and the [`FileBytesAdapter`] (original file
//! bytes). Block creation runs Java's precondition checks (`checkBlockName`, `checkBlockSize`,
//! `checkRange`, `checkFileBytesRange`) and then delegates to the adapter, after which the block
//! list and the all-addresses set are rebuilt (`initializeBlocks` /
//! `addToAllAddressSet`).
//!
//! # Ownership
//!
//! Java's adapter holds a back-reference to its `MemoryMapDB` (bit/byte-mapped sub blocks read
//! the bytes they map through it). Here the map is created behind an `Arc<RwLock<_>>` and the
//! adapter receives a [`Memory`] view that upgrades a `Weak` back to the map on each call, so
//! there is no ownership cycle. Java's `lock`/`refresh` scaffolding is not ported (see
//! OWNERSHIP_MIGRATION.md "Snapshot + transaction"): mutation takes `&mut self` behind the
//! caller's write lock.
//!
//! # Not (yet) ported
//!
//! * Overlay blocks: `createOverlaySpace` needs `ProgramDB.createOverlaySpace` and a program
//!   address factory; requesting `overlay` is rejected with
//!   [`MemoryMapError::IllegalState`].
//! * `checkRange`'s image-base check: `AddressMapDB` has no image base yet, so the image base is
//!   the default space's address 0, for which Java's "block may not span the image base" test can
//!   never fire.
//! * Bit/byte-mapped block creation, block move/split/join/delete, events, `program` callbacks
//!   (`checkExclusiveAccess`, `fireBlockAdded`, `dbError`) -- there is no `ProgramDB` to call.

use std::fmt;
use std::io;
use std::sync::{Arc, OnceLock, RwLock, Weak};

use thiserror::Error;

use crate::framework::data::OpenMode;
use crate::framework::db::DBHandle;
use crate::program::database::map::AddressMapDB;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::database::mem::file_bytes_adapter::{self, FileBytesAdapter, FileBytesAdapterError};
use crate::program::database::mem::memory_map_db_adapter::{
    self, MemoryMapDBAdapter, MemoryMapDBAdapterError,
};
use crate::program::model::address::address_set::AddressSetView;
use crate::program::model::address::{Address, AddressOverflowException, AddressSet};
use crate::program::model::mem::memory::CreateBlockError;
use crate::program::database::mem::byte_mapping_scheme::{ByteMappingScheme, ByteMappingSchemeError};
use crate::program::database::mem::memory_block_db::MemoryBlockDB;
use crate::program::model::mem::{
    Memory, MemoryAccessException, MemoryBlock, MemoryBlockException, MemoryBlockHandle,
    MemoryBlockType, MemoryConflictException,
};
use crate::util::exception::{CancelledException, IOCancelledException, VersionException};
use crate::util::monitored_input_stream::MonitoredInputStream;
use crate::util::task::TaskMonitor;

/// `Memory.GBYTE`.
pub const GBYTE: i64 = 1 << 30;
/// `Memory.MAX_BINARY_SIZE_GB`.
pub const MAX_BINARY_SIZE_GB: i64 = 16;
/// `Memory.MAX_BINARY_SIZE`: the maximum total number of program bytes.
pub const MAX_BINARY_SIZE: i64 = MAX_BINARY_SIZE_GB << 30;
/// `Memory.MAX_BLOCK_SIZE_GB`.
pub const MAX_BLOCK_SIZE_GB: i64 = 16;
/// `Memory.MAX_BLOCK_SIZE`: the maximum size of one memory block.
pub const MAX_BLOCK_SIZE: i64 = MAX_BLOCK_SIZE_GB << 30;

/// `MemoryBlock.READ`: the permission flag every newly created block starts with.
const READ: i32 = 0x4;

/// The exceptions Java's `MemoryMapDB` block-creation methods throw.
#[derive(Debug, Error)]
pub enum MemoryMapError {
    /// Java's `IllegalArgumentException` (invalid name, zero length, foreign address space, ...).
    #[error("{0}")]
    IllegalArgument(String),
    /// Java's `IllegalStateException` (size limits; unsupported overlay creation).
    #[error("{0}")]
    IllegalState(String),
    /// Java's `IndexOutOfBoundsException` (file-bytes range checks).
    #[error("{0}")]
    IndexOutOfBounds(String),
    /// The new block would overlap an existing one.
    #[error(transparent)]
    Conflict(#[from] MemoryConflictException),
    /// `start + length - 1` runs off the end of the address space.
    #[error(transparent)]
    AddressOverflow(#[from] AddressOverflowException),
    /// The monitor was cancelled while the block was being filled.
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    /// A database error (Java hands these to `program.dbError`).
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Blocks cannot be joined (Java's `MemoryBlockException`).
    #[error(transparent)]
    Block(#[from] MemoryBlockException),
}

impl From<MemoryMapDBAdapterError> for MemoryMapError {
    fn from(e: MemoryMapDBAdapterError) -> Self {
        match e {
            MemoryMapDBAdapterError::AddressOverflow(e) => MemoryMapError::AddressOverflow(e),
            MemoryMapDBAdapterError::Io(e) if is_io_cancelled(&e) => {
                MemoryMapError::Cancelled(CancelledException::default())
            }
            MemoryMapDBAdapterError::Io(e) => MemoryMapError::Io(e),
        }
    }
}

impl From<MemoryMapError> for CreateBlockError {
    fn from(e: MemoryMapError) -> Self {
        match e {
            MemoryMapError::IllegalArgument(m) => CreateBlockError::IllegalArgument(m),
            MemoryMapError::IllegalState(m) => CreateBlockError::IllegalState(m),
            MemoryMapError::IndexOutOfBounds(m) => CreateBlockError::IndexOutOfBounds(m),
            MemoryMapError::Conflict(e) => CreateBlockError::Conflict(e),
            MemoryMapError::AddressOverflow(e) => CreateBlockError::AddressOverflow(e),
            MemoryMapError::Cancelled(e) => CreateBlockError::Cancelled(e),
            MemoryMapError::Io(e) => CreateBlockError::Io(e),
            MemoryMapError::Block(e) => CreateBlockError::IllegalArgument(e.to_string()),
        }
    }
}

/// Java's `Address.toString()`: the offset zero-padded to the space's full width.
fn java_str(addr: &Address) -> String {
    addr.format(false, 16)
}

fn is_io_cancelled(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<IOCancelledException>())
}

/// Failure opening a memory map: Java's `IOException` / `VersionException`.
#[derive(Debug)]
pub enum MemoryMapOpenError {
    Io(io::Error),
    Version(VersionException),
}

impl fmt::Display for MemoryMapOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryMapOpenError::Io(e) => write!(f, "{e}"),
            MemoryMapOpenError::Version(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MemoryMapOpenError {}

/// The memory map of a program database.
///
/// Mirrors `ghidra.program.database.mem.MemoryMapDB` (see the module docs for its scope).
pub struct MemoryMapDB {
    addr_map: Arc<RwLock<AddressMapDB>>,
    adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>,
    file_bytes_adapter: Arc<RwLock<dyn FileBytesAdapter>>,
    is_big_endian: bool,
    /// The adapter's blocks, sorted on start address (Java's `blocks`).
    blocks: Vec<Arc<RwLock<dyn MemoryBlock>>>,
    /// Every address in every block (Java's `allAddrSet`).
    all_addr_set: AddressSet,
}

/// The [`Memory`] the adapter (and its mapped sub blocks) and `MemBuffer`s read through: a weak
/// handle back to the owning map, resolved per call.
struct MemoryMapView {
    map: Arc<OnceLock<Weak<RwLock<MemoryMapDB>>>>,
}

impl MemoryMapView {
    fn map(&self) -> Option<Arc<RwLock<MemoryMapDB>>> {
        self.map.get().and_then(Weak::upgrade)
    }
}

fn dropped() -> MemoryAccessException {
    MemoryAccessException::new("memory map is no longer available")
}

impl Memory for MemoryMapView {
    fn is_big_endian(&self) -> bool {
        self.map().is_some_and(|m| m.read().unwrap().is_big_endian)
    }

    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
        self.map().ok_or_else(dropped)?.read().unwrap().get_byte(addr)
    }

    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
        self.map().map_or(0, |m| m.read().unwrap().get_bytes(addr, dest))
    }

    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
        self.map().ok_or_else(dropped)?.write().unwrap().set_bytes(addr, source)
    }

    fn contains(&self, addr: &Address) -> bool {
        self.map().is_some_and(|m| m.read().unwrap().contains(addr))
    }

    fn get_all_file_bytes(&self) -> Vec<Arc<dyn FileBytes>> {
        self.map().map_or_else(Vec::new, |m| m.read().unwrap().get_all_file_bytes())
    }

    fn has_file_bytes(&self) -> bool {
        !Memory::get_all_file_bytes(self).is_empty()
    }

    fn get_block_handles(&self) -> Vec<MemoryBlockHandle> {
        self.map().map_or_else(Vec::new, |m| m.read().unwrap().get_blocks().to_vec())
    }

    fn get_block_handle(&self, addr: &Address) -> Option<MemoryBlockHandle> {
        self.map()?.read().unwrap().get_block(addr).cloned()
    }

    fn is_empty(&self) -> bool {
        self.map().is_none_or(|m| m.read().unwrap().get_blocks().is_empty())
    }

    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        self.map()
            .map_or_else(AddressSet::new, |m| m.read().unwrap().get_address_set().intersect_range(start, end))
    }
}

impl MemoryMapDB {
    /// Opens (or, for [`OpenMode::Create`], creates) the memory map stored in `handle`. Mirrors
    /// `MemoryMapDB(DBHandle, AddressMapDB, OpenMode, boolean, Lock, TaskMonitor)`.
    ///
    /// # Errors
    /// A [`VersionException`] if a stored schema is incompatible with `open_mode`, or an IO
    /// error reading the existing blocks.
    pub fn new(
        handle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
        open_mode: OpenMode,
        is_big_endian: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Arc<RwLock<MemoryMapDB>>, MemoryMapOpenError> {
        let slot: Arc<OnceLock<Weak<RwLock<MemoryMapDB>>>> = Arc::new(OnceLock::new());
        let view: Arc<RwLock<dyn Memory>> =
            Arc::new(RwLock::new(MemoryMapView { map: Arc::clone(&slot) }));
        let adapter = memory_map_db_adapter::get_adapter(
            Arc::clone(&handle),
            view,
            Arc::clone(&addr_map),
            open_mode,
            monitor,
        )
        .map_err(MemoryMapOpenError::Version)?;
        let file_bytes_adapter = file_bytes_adapter::get_adapter(handle, open_mode, monitor)
            .map_err(MemoryMapOpenError::Version)?;

        let mut map = MemoryMapDB {
            addr_map,
            adapter,
            file_bytes_adapter,
            is_big_endian,
            blocks: Vec::new(),
            all_addr_set: AddressSet::new(),
        };
        map.initialize_blocks();
        map.all_addr_set = map.build_full_memory_address_set();

        let map = Arc::new(RwLock::new(map));
        let _ = slot.set(Arc::downgrade(&map));
        Ok(map)
    }

    /// A [`Memory`] handle on `map` for `MemBuffer`s (`MemoryBufferImpl`, `DumbMemBufferImpl`)
    /// and other readers that take `Arc<dyn Memory>`. It does not keep the map alive.
    pub fn as_memory(map: &Arc<RwLock<MemoryMapDB>>) -> Arc<dyn Memory> {
        let slot = Arc::new(OnceLock::new());
        let _ = slot.set(Arc::downgrade(map));
        Arc::new(MemoryMapView { map: slot })
    }

    fn initialize_blocks(&mut self) {
        let mut blocks = self.adapter.read().unwrap().get_memory_blocks();
        blocks.sort_by_key(|b| b.read().unwrap().get_start());
        self.blocks = blocks;
    }

    fn build_full_memory_address_set(&self) -> AddressSet {
        let mut set = AddressSet::new();
        for block in &self.blocks {
            let b = block.read().unwrap();
            set.add_range(&b.get_start(), &b.get_end());
        }
        set
    }

    fn block_added(&mut self, block: &Arc<RwLock<dyn MemoryBlock>>) {
        {
            let b = block.read().unwrap();
            self.all_addr_set.add_range(&b.get_start(), &b.get_end());
        }
        self.initialize_blocks();
    }

    /// `checkBlockName`: `Memory.isValidMemoryBlockName`. Duplicate names are allowed, as in
    /// Java.
    fn check_block_name(name: &str) -> Result<(), MemoryMapError> {
        if !crate::program::model::mem::memory::is_valid_memory_block_name(name) {
            return Err(MemoryMapError::IllegalArgument(format!("Invalid block name: {name}")));
        }
        Ok(())
    }

    /// `checkBlockSize(long, boolean)`.
    fn check_block_size(&self, new_block_length: i64) -> Result<(), MemoryMapError> {
        if new_block_length > MAX_BLOCK_SIZE {
            return Err(MemoryMapError::IllegalState(format!(
                "New memory block NOT added: exceeds the maximum memory block byte size of {MAX_BLOCK_SIZE_GB} GByte(s)"
            )));
        }
        let new_size = (self.get_num_addresses() as i64).wrapping_add(new_block_length);
        if !(0..=MAX_BINARY_SIZE).contains(&new_size) {
            return Err(MemoryMapError::IllegalState(format!(
                "New memory block NOT added: would cause total number of initialized program bytes to exceed the maximum program size of {MAX_BINARY_SIZE_GB} GBytes"
            )));
        }
        Ok(())
    }

    /// `checkRange(Address, long)`.
    fn check_range(&self, start: &Address, size: i64) -> Result<(), MemoryMapError> {
        let space = start.space();
        if !space.is_memory_space() {
            return Err(MemoryMapError::IllegalArgument(format!(
                "Invalid memory address for block: {}",
                start.format(true, 16)
            )));
        }
        let factory = self.addr_map.read().unwrap().get_address_factory();
        match factory.get_address_space_by_name(space.name()) {
            Some(my_space) if my_space == *space => {}
            _ => {
                return Err(MemoryMapError::IllegalArgument(
                    "Block may not be created with unrecognized address space".to_string(),
                ))
            }
        }
        if size == 0 {
            return Err(MemoryMapError::IllegalArgument(
                "Block must have a non-zero length".to_string(),
            ));
        }
        let end = start.add_no_wrap(size - 1)?;
        if factory.get_default_address_space().is_some_and(|d| d == *space) {
            // AddressMapDB has no image base override yet: the image base is address 0.
            let image_base = space.address(0);
            if *start < image_base && end >= image_base {
                return Err(MemoryConflictException::new(format!(
                    "Block may not span image base address ({})",
                    java_str(&image_base)
                ))
                .into());
            }
        }
        if self.all_addr_set.intersects_range(start, &end) {
            return Err(MemoryConflictException::new(format!(
                "Part of range ({}, {}) already exists in memory.",
                java_str(start),
                java_str(&end)
            ))
            .into());
        }
        Ok(())
    }

    /// The concrete `AddressSpace` has no overlay variant yet, so `start` is never already in an
    /// overlay space and an overlay request always needs a new overlay space.
    fn reject_overlay(overlay: bool, _start: &Address) -> Result<(), MemoryMapError> {
        if overlay {
            return Err(MemoryMapError::IllegalState(
                "overlay block creation requires ProgramDB.createOverlaySpace, which is not ported"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Creates an initialized block whose every byte is `initial_value`. Mirrors
    /// `createInitializedBlock(String, Address, long, byte, TaskMonitor, boolean)`.
    pub fn create_initialized_block_filled(
        &mut self,
        name: &str,
        start: &Address,
        size: i64,
        initial_value: u8,
        monitor: Option<&dyn TaskMonitor>,
        overlay: bool,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapError> {
        if initial_value != 0 {
            let mut fill = io::repeat(initial_value);
            self.create_initialized_block(name, start, Some(&mut fill), size, monitor, overlay)
        } else {
            self.create_initialized_block(name, start, None, size, monitor, overlay)
        }
    }

    /// Creates an initialized block whose bytes are read from `is` (zero-filled once `is` is
    /// exhausted, or entirely when `is` is `None`). Mirrors
    /// `createInitializedBlock(String, Address, InputStream, long, TaskMonitor, boolean)`.
    ///
    /// # Errors
    /// See [`MemoryMapError`]; a cancelled `monitor` yields [`MemoryMapError::Cancelled`].
    pub fn create_initialized_block(
        &mut self,
        name: &str,
        start: &Address,
        is: Option<&mut dyn io::Read>,
        length: i64,
        monitor: Option<&dyn TaskMonitor>,
        overlay: bool,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapError> {
        Self::check_block_name(name)?;
        self.check_block_size(length)?;
        Self::reject_overlay(overlay, start)?;
        self.check_range(start, length)?;

        let new_block = match (is, monitor) {
            (Some(is), Some(monitor)) => {
                let mut monitored = MonitoredInputStream::new(is, monitor);
                self.adapter.write().unwrap().create_initialized_block_from_stream(
                    name,
                    start.clone(),
                    Some(&mut monitored),
                    length,
                    READ,
                )
            }
            (is, _) => self.adapter.write().unwrap().create_initialized_block_from_stream(
                name,
                start.clone(),
                is,
                length,
                READ,
            ),
        }?;
        self.block_added(&new_block);
        Ok(new_block)
    }

    /// Creates an initialized block backed by `length` bytes of `file_bytes` starting at
    /// `offset`. Mirrors `createInitializedBlock(String, Address, FileBytes, long, long,
    /// boolean)`.
    pub fn create_initialized_block_from_file_bytes(
        &mut self,
        name: &str,
        start: &Address,
        file_bytes: Arc<dyn FileBytes>,
        offset: i64,
        length: i64,
        overlay: bool,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapError> {
        Self::check_block_name(name)?;
        self.check_block_size(length)?;
        Self::check_file_bytes_range(file_bytes.as_ref(), offset, length)?;
        Self::reject_overlay(overlay, start)?;
        self.check_range(start, length)?;

        let new_block = self.adapter.write().unwrap().create_file_bytes_block(
            name,
            start.clone(),
            length,
            file_bytes,
            offset,
            READ,
        )?;
        self.block_added(&new_block);
        Ok(new_block)
    }

    /// `checkFileBytesRange(FileBytes, long, long)`.
    fn check_file_bytes_range(
        file_bytes: &dyn FileBytes,
        offset: i64,
        length: i64,
    ) -> Result<(), MemoryMapError> {
        if length <= 0 {
            return Err(MemoryMapError::IllegalArgument(format!(
                "Length must be > 0, got {length}"
            )));
        }
        if offset < 0 || offset >= file_bytes.get_size() {
            let limit = file_bytes.get_size() - 1;
            return Err(MemoryMapError::IndexOutOfBounds(format!(
                "Offset must be in range [0,{limit}], got {offset}"
            )));
        }
        if offset + length > file_bytes.get_size() {
            return Err(MemoryMapError::IndexOutOfBounds(
                "Specified length extends beyond file bytes length".to_string(),
            ));
        }
        Ok(())
    }

    /// Creates an uninitialized block (no bytes; reads fail). Mirrors
    /// `createUninitializedBlock(String, Address, long, boolean)`.
    pub fn create_uninitialized_block(
        &mut self,
        name: &str,
        start: &Address,
        size: i64,
        overlay: bool,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapError> {
        Self::check_block_name(name)?;
        self.check_block_size(size)?;
        Self::reject_overlay(overlay, start)?;
        self.check_range(start, size)?;

        let new_block = self.adapter.write().unwrap().create_block(
            MemoryBlockType::Default,
            name,
            start.clone(),
            size,
            None,
            false,
            READ,
            0,
        )?;
        self.block_added(&new_block);
        Ok(new_block)
    }

    /// Stores `size` bytes read from `is` as original file bytes. Mirrors
    /// `createFileBytes(String, long, long, InputStream, TaskMonitor)`.
    ///
    /// # Errors
    /// [`MemoryMapError::Cancelled`] if `monitor` is cancelled, or an IO error.
    pub fn create_file_bytes(
        &mut self,
        filename: &str,
        offset: i64,
        size: i64,
        is: &mut dyn io::Read,
        monitor: &dyn TaskMonitor,
    ) -> Result<Arc<dyn FileBytes>, MemoryMapError> {
        let old_progress_max = monitor.get_maximum();
        let old_progress = monitor.get_progress();
        let result =
            self.file_bytes_adapter.write().unwrap().create_file_bytes(filename, offset, size, is, monitor);
        monitor.set_maximum(old_progress_max);
        monitor.set_progress(old_progress);
        result.map_err(|e| match e {
            FileBytesAdapterError::Cancelled(_) => {
                MemoryMapError::Cancelled(CancelledException::default())
            }
            FileBytesAdapterError::Io(e) if is_io_cancelled(&e) => {
                MemoryMapError::Cancelled(CancelledException::default())
            }
            FileBytesAdapterError::Io(e) => MemoryMapError::Io(e),
        })
    }

    /// Creates a bit-mapped block: each byte is one bit of the bytes at `mapped_address`.
    /// Mirrors `createBitMappedBlock(String, Address, Address, long, boolean)`.
    pub fn create_bit_mapped_block(
        &mut self,
        name: &str,
        start: &Address,
        mapped_address: &Address,
        length: i64,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, MemoryMapError> {
        Self::check_block_name(name)?;
        self.check_block_size(length)?;
        // just to check if length fits in address space
        mapped_address.add_no_wrap((length - 1) / 8)?;
        Self::reject_overlay(overlay, start)?;
        self.check_range(start, length)?;
        let new_block = self.adapter.write().unwrap().create_block(
            MemoryBlockType::BitMapped,
            name,
            start.clone(),
            length,
            Some(mapped_address.clone()),
            false,
            READ,
            0,
        )?;
        self.block_added(&new_block);
        Ok(new_block)
    }

    /// Creates a byte-mapped block over the bytes at `mapped_address` (1:1 unless
    /// `byte_mapping_scheme` says otherwise). Mirrors `createByteMappedBlock(String, Address,
    /// Address, long, ByteMappingScheme, boolean)`.
    pub fn create_byte_mapped_block(
        &mut self,
        name: &str,
        start: &Address,
        mapped_address: &Address,
        length: i64,
        byte_mapping_scheme: Option<ByteMappingScheme>,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, MemoryMapError> {
        Self::check_block_name(name)?;
        let mut mapping_scheme = 0; // use for 1:1 mapping
        let scheme = match byte_mapping_scheme {
            None => ByteMappingScheme::from_encoded(mapping_scheme)
                .map_err(|e| MemoryMapError::IllegalArgument(e.to_string()))?,
            Some(scheme) => {
                if !scheme.is_one_to_one_mapping() {
                    mapping_scheme = scheme.get_encoded_mapping_scheme();
                }
                scheme
            }
        };
        self.check_block_size(length)?;
        // source fit check
        scheme.get_mapped_source_address(mapped_address, length - 1).map_err(|e| match e {
            ByteMappingSchemeError::AddressOverflow(e) => MemoryMapError::AddressOverflow(e),
            other => MemoryMapError::IllegalArgument(other.to_string()),
        })?;
        Self::reject_overlay(overlay, start)?;
        self.check_range(start, length)?;
        let new_block = self.adapter.write().unwrap().create_block(
            MemoryBlockType::ByteMapped,
            name,
            start.clone(),
            length,
            Some(mapped_address.clone()),
            false,
            READ,
            mapping_scheme,
        )?;
        self.block_added(&new_block);
        Ok(new_block)
    }

    /// Creates a block of the same type, initialization state and permissions as `block`.
    /// Mirrors `createBlock(MemoryBlock, String, Address, long)` for non-mapped blocks; a mapped
    /// `block` needs its source info (mapped range / scheme), which `MemoryBlockDB` does not
    /// expose yet, so it is rejected.
    pub fn create_block(
        &mut self,
        block: &MemoryBlockHandle,
        name: &str,
        start: &Address,
        length: i64,
    ) -> Result<MemoryBlockHandle, MemoryMapError> {
        Self::check_block_name(name)?;
        let (block_type, initialized, flags) = {
            let b = block.read().unwrap();
            let flags = (if b.is_read() { READ } else { 0 })
                | (if b.is_write() { 0x2 } else { 0 })
                | (if b.is_execute() { 0x1 } else { 0 })
                | (if b.is_volatile() { 0x8 } else { 0 })
                | (if b.is_artificial() { 0x10 } else { 0 });
            (b.get_type(), b.is_initialized(), flags)
        };
        self.check_block_size(length)?;
        self.check_range(start, length)?;
        if block_type != MemoryBlockType::Default {
            return Err(MemoryMapError::IllegalState(
                "creating a block like a mapped block is not supported yet".to_string(),
            ));
        }
        let new_block = self.adapter.write().unwrap().create_block(
            block_type,
            name,
            start.clone(),
            length,
            None,
            initialized,
            flags,
            0,
        )?;
        self.block_added(&new_block);
        Ok(new_block)
    }

    /// Joins two contiguous, non-mapped blocks that are both initialized or both uninitialized
    /// into one (the lower block grows; the other is deleted). Mirrors `join(MemoryBlock,
    /// MemoryBlock)`.
    ///
    /// # Errors
    /// [`MemoryMapError::Block`] if the blocks are not contiguous or differ in initialization;
    /// [`MemoryMapError::IllegalArgument`] for a mapped block or one not in this memory.
    pub fn join(
        &mut self,
        block_one: &MemoryBlockHandle,
        block_two: &MemoryBlockHandle,
    ) -> Result<MemoryBlockHandle, MemoryMapError> {
        // swap if second block is before first block
        let (one, two) = if block_one.read().unwrap().get_start() > block_two.read().unwrap().get_start() {
            (block_two, block_one)
        } else {
            (block_one, block_two)
        };
        if Arc::ptr_eq(one, two) {
            return Err(MemoryBlockException::new("Blocks are not contiguous").into());
        }
        self.check_preconditions_for_joining(one, two)?;
        let block1_addr = one.read().unwrap().get_start();
        {
            let mut b1 = one.write().unwrap();
            let mut b2 = two.write().unwrap();
            let db2 = b2
                .as_any_mut()
                .and_then(|a| a.downcast_mut::<MemoryBlockDB>())
                .ok_or_else(|| MemoryMapError::IllegalArgument("Blocks do not belong to this program".to_string()))?;
            let db1 = b1
                .as_any_mut()
                .and_then(|a| a.downcast_mut::<MemoryBlockDB>())
                .ok_or_else(|| MemoryMapError::IllegalArgument("Blocks do not belong to this program".to_string()))?;
            db1.join(db2)?;
        }
        // The adapter reads every cached block while deleting, so the block locks above must be
        // released first.
        {
            let mut adapter = self.adapter.write().unwrap();
            adapter.delete_memory_block(&*two.read().unwrap())?;
            let record = {
                let mut b1 = one.write().unwrap();
                b1.as_any_mut()
                    .and_then(|a| a.downcast_mut::<MemoryBlockDB>())
                    .map(|db| db.record().clone())
                    .expect("checked above")
            };
            adapter.update_block_record(&record)?;
        }
        self.initialize_blocks();
        Ok(self
            .get_block(&block1_addr)
            .cloned()
            .expect("the joined block starts where the first block did"))
    }

    /// `checkPreconditionsForJoining(MemoryBlock, MemoryBlock)`.
    fn check_preconditions_for_joining(
        &self,
        block1: &MemoryBlockHandle,
        block2: &MemoryBlockHandle,
    ) -> Result<(), MemoryMapError> {
        self.check_block_for_joining(block1)?;
        self.check_block_for_joining(block2)?;
        let (b1, b2) = (block1.read().unwrap(), block2.read().unwrap());
        if b1.is_initialized() != b2.is_initialized() {
            return Err(MemoryBlockException::new(
                "Both blocks must be either initialized or uninitialized",
            )
            .into());
        }
        if b1.get_end().add_no_wrap(1).ok().as_ref() != Some(&b2.get_start()) {
            return Err(MemoryBlockException::new("Blocks are not contiguous").into());
        }
        Ok(())
    }

    /// `checkBlockForJoining(MemoryBlock)` (with `checkBlock`'s ownership test).
    fn check_block_for_joining(&self, block: &MemoryBlockHandle) -> Result<(), MemoryMapError> {
        if !self.blocks.iter().any(|b| Arc::ptr_eq(b, block)) {
            return Err(MemoryMapError::IllegalArgument(
                "Blocks do not belong to this program".to_string(),
            ));
        }
        if block.read().unwrap().get_type() != MemoryBlockType::Default {
            return Err(MemoryMapError::IllegalArgument("Cannot join mapped blocks".to_string()));
        }
        Ok(())
    }

    /// All stored file bytes. Mirrors `getAllFileBytes()`.
    pub fn get_all_file_bytes(&self) -> Vec<Arc<dyn FileBytes>> {
        self.file_bytes_adapter.read().unwrap().get_all_file_bytes()
    }

    /// All blocks, sorted on start address. Mirrors `getBlocks()`.
    pub fn get_blocks(&self) -> &[Arc<RwLock<dyn MemoryBlock>>] {
        &self.blocks
    }

    /// The block containing `addr`, or `None`. Mirrors `getBlock(Address)`.
    pub fn get_block(&self, addr: &Address) -> Option<&Arc<RwLock<dyn MemoryBlock>>> {
        // blocks are sorted on start: find the last block starting at or before addr
        let idx = self.blocks.partition_point(|b| b.read().unwrap().get_start() <= *addr);
        let block = self.blocks.get(idx.checked_sub(1)?)?;
        block.read().unwrap().contains(addr).then_some(block)
    }

    /// The first block named `name`, or `None`. Mirrors `getBlock(String)`.
    pub fn get_block_by_name(&self, name: &str) -> Option<&Arc<RwLock<dyn MemoryBlock>>> {
        self.blocks.iter().find(|b| b.read().unwrap().get_name() == name)
    }

    /// The number of addresses in all blocks. Mirrors `getNumAddresses()`.
    pub fn get_num_addresses(&self) -> u64 {
        self.all_addr_set.num_addresses()
    }

    /// Every address in every block. Stands in for `MemoryMapDB`'s own `AddressSetView`
    /// implementation (it delegates to `allAddrSet`).
    pub fn get_address_set(&self) -> &AddressSet {
        &self.all_addr_set
    }

    /// Total size in bytes of all memory blocks. Mirrors `Memory.getSize()`.
    pub fn size(&self) -> u64 {
        self.get_num_addresses()
    }

    /// Whether `addr` falls within any memory block. Mirrors `Memory.contains(Address)`.
    pub fn contains(&self, addr: &Address) -> bool {
        self.all_addr_set.contains(addr)
    }
}

impl Memory for MemoryMapDB {
    fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }

    /// Mirrors `getByte(Address)`.
    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
        match self.get_block(addr) {
            Some(block) => block.read().unwrap().get_byte(addr),
            None => Err(MemoryAccessException::new(format!(
                "Address {} does not exist in memory",
                java_str(addr)
            ))),
        }
    }

    /// Mirrors `getBytes(Address, byte[])`: reads as many contiguous bytes as are available
    /// starting at `addr`, continuing across adjacent blocks, and returns the count read.
    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
        let mut total_read = 0;
        let mut cur_addr = addr.clone();
        while total_read < dest.len() {
            let Some(block) = self.get_block(&cur_addr) else {
                break;
            };
            let b = block.read().unwrap();
            let read = b.get_bytes(&cur_addr, &mut dest[total_read..]);
            if read == 0 {
                break;
            }
            total_read += read;
            match cur_addr.add_no_wrap(read as i64) {
                Ok(next) => cur_addr = next,
                Err(_) => break,
            }
        }
        total_read
    }

    /// Mirrors `setBytes(Address, byte[])` for a range within one block.
    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
        match self.get_block(addr) {
            Some(block) => block.write().unwrap().set_bytes(addr, source),
            None => Err(MemoryAccessException::new(format!(
                "Address {} does not exist in memory",
                java_str(addr)
            ))),
        }
    }

    fn contains(&self, addr: &Address) -> bool {
        MemoryMapDB::contains(self, addr)
    }

    fn create_initialized_block_from_stream(
        &mut self,
        name: &str,
        start: &Address,
        is: Option<&mut dyn io::Read>,
        length: i64,
        monitor: Option<&dyn TaskMonitor>,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        Ok(MemoryMapDB::create_initialized_block(self, name, start, is, length, monitor, overlay)?)
    }

    fn create_initialized_block_from_file_bytes(
        &mut self,
        name: &str,
        start: &Address,
        file_bytes: Arc<dyn FileBytes>,
        offset: i64,
        length: i64,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        Ok(MemoryMapDB::create_initialized_block_from_file_bytes(
            self, name, start, file_bytes, offset, length, overlay,
        )?)
    }

    fn create_uninitialized_block(
        &mut self,
        name: &str,
        start: &Address,
        length: i64,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        Ok(MemoryMapDB::create_uninitialized_block(self, name, start, length, overlay)?)
    }

    fn create_file_bytes(
        &mut self,
        filename: &str,
        offset: i64,
        size: i64,
        is: &mut dyn io::Read,
        monitor: &dyn TaskMonitor,
    ) -> Result<Arc<dyn FileBytes>, CreateBlockError> {
        Ok(MemoryMapDB::create_file_bytes(self, filename, offset, size, is, monitor)?)
    }

    fn get_all_file_bytes(&self) -> Vec<Arc<dyn FileBytes>> {
        MemoryMapDB::get_all_file_bytes(self)
    }

    fn create_bit_mapped_block(
        &mut self,
        name: &str,
        start: &Address,
        mapped_address: &Address,
        length: i64,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        Ok(MemoryMapDB::create_bit_mapped_block(self, name, start, mapped_address, length, overlay)?)
    }

    fn create_byte_mapped_block(
        &mut self,
        name: &str,
        start: &Address,
        mapped_address: &Address,
        length: i64,
        byte_mapping_scheme: Option<ByteMappingScheme>,
        overlay: bool,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        Ok(MemoryMapDB::create_byte_mapped_block(
            self,
            name,
            start,
            mapped_address,
            length,
            byte_mapping_scheme,
            overlay,
        )?)
    }

    fn create_block(
        &mut self,
        block: &MemoryBlockHandle,
        name: &str,
        start: &Address,
        length: i64,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        Ok(MemoryMapDB::create_block(self, block, name, start, length)?)
    }

    fn join(
        &mut self,
        block_one: &MemoryBlockHandle,
        block_two: &MemoryBlockHandle,
    ) -> Result<MemoryBlockHandle, CreateBlockError> {
        Ok(MemoryMapDB::join(self, block_one, block_two)?)
    }

    fn has_file_bytes(&self) -> bool {
        !MemoryMapDB::get_all_file_bytes(self).is_empty()
    }

    fn get_block_handles(&self) -> Vec<MemoryBlockHandle> {
        self.blocks.clone()
    }

    fn get_block_handle(&self, addr: &Address) -> Option<MemoryBlockHandle> {
        MemoryMapDB::get_block(self, addr).cloned()
    }

    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        self.all_addr_set.intersect_range(start, end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::map::AddressMapDB;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::mem::memory_buffer_impl::MemoryBufferImpl;
    use crate::util::exception::CancelledException;
    use crate::util::task::{CancelledListener, DummyMonitor};

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram(), offset)
    }

    fn new_map(big_endian: bool) -> Arc<RwLock<MemoryMapDB>> {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![ram()]);
        let addr_map =
            Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
        MemoryMapDB::new(handle, addr_map, OpenMode::Create, big_endian, &DummyMonitor).unwrap()
    }

    struct CancelledMonitor;
    impl TaskMonitor for CancelledMonitor {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Err(CancelledException::default())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn initialized_block_from_stream_reads_back_through_memory_and_mem_buffer() {
        let map = new_map(false);
        let mut src: &[u8] = &[0x78, 0x56, 0x34, 0x12, 0xaa, 0xbb];
        let block = map
            .write()
            .unwrap()
            .create_initialized_block(".text", &addr(0x1000), Some(&mut src), 8, None, false)
            .unwrap();
        {
            let b = block.read().unwrap();
            assert_eq!(b.get_name(), ".text");
            assert_eq!(b.get_start(), addr(0x1000));
            assert_eq!(b.get_end(), addr(0x1007));
            assert_eq!(b.get_size(), 8);
            assert!(b.is_initialized());
            assert!(b.is_read() && !b.is_write() && !b.is_execute(), "new blocks are READ only");
        }

        let m = map.read().unwrap();
        assert_eq!(m.get_byte(&addr(0x1000)).unwrap(), 0x78);
        // the stream ran out after 6 bytes: the rest is zero-filled
        let mut out = [0xffu8; 8];
        assert_eq!(m.get_bytes(&addr(0x1000), &mut out), 8);
        assert_eq!(out, [0x78, 0x56, 0x34, 0x12, 0xaa, 0xbb, 0, 0]);
        assert!(m.get_byte(&addr(0x1008)).is_err());
        assert_eq!(m.get_num_addresses(), 8);
        assert!(m.contains(&addr(0x1007)) && !m.contains(&addr(0xfff)));
        assert_eq!(m.get_blocks().len(), 1);
        drop(m);

        let buf = MemoryBufferImpl::new(MemoryMapDB::as_memory(&map), addr(0x1000));
        assert_eq!(buf.get_int(0).unwrap(), 0x1234_5678);
        assert_eq!(buf.get_byte(4).unwrap(), 0xaa);
    }

    #[test]
    fn filled_block_and_writes_round_trip() {
        let map = new_map(true);
        let mut m = map.write().unwrap();
        m.create_initialized_block_filled("fill", &addr(0x2000), 0x10, 0xcc, Some(&DummyMonitor), false)
            .unwrap();
        m.create_initialized_block_filled("zero", &addr(0x3000), 4, 0, None, false).unwrap();
        assert_eq!(m.get_byte(&addr(0x200f)).unwrap(), 0xcc);
        assert_eq!(m.get_byte(&addr(0x3003)).unwrap(), 0);

        m.set_bytes(&addr(0x2004), &[1, 2, 3]).unwrap();
        let mut out = [0u8; 5];
        assert_eq!(m.get_bytes(&addr(0x2003), &mut out), 5);
        assert_eq!(out, [0xcc, 1, 2, 3, 0xcc]);
        assert!(m.set_bytes(&addr(0x5000), &[1]).is_err());
        assert!(m.is_big_endian());
    }

    #[test]
    fn get_bytes_continues_across_adjacent_blocks_and_stops_at_a_gap() {
        let map = new_map(false);
        let mut m = map.write().unwrap();
        let mut a: &[u8] = &[1, 2];
        let mut b: &[u8] = &[3, 4];
        // created out of order: the map keeps its blocks sorted on start address
        m.create_initialized_block("b", &addr(0x102), Some(&mut b), 2, None, false).unwrap();
        m.create_initialized_block("a", &addr(0x100), Some(&mut a), 2, None, false).unwrap();
        let names: Vec<String> =
            m.get_blocks().iter().map(|b| b.read().unwrap().get_name().to_string()).collect();
        assert_eq!(names, ["a", "b"]);

        let mut out = [0u8; 6];
        assert_eq!(m.get_bytes(&addr(0x100), &mut out), 4);
        assert_eq!(&out[..4], &[1, 2, 3, 4]);
        assert_eq!(m.get_block(&addr(0x103)).unwrap().read().unwrap().get_name(), "b");
        assert!(m.get_block(&addr(0x104)).is_none());
        assert_eq!(m.get_block_by_name("a").unwrap().read().unwrap().get_start(), addr(0x100));
    }

    #[test]
    fn uninitialized_block_has_addresses_but_no_bytes() {
        let map = new_map(false);
        let mut m = map.write().unwrap();
        let block = m.create_uninitialized_block(".bss", &addr(0x8000), 0x100, false).unwrap();
        assert!(!block.read().unwrap().is_initialized());
        assert_eq!(block.read().unwrap().get_size(), 0x100);
        assert!(m.contains(&addr(0x80ff)));
        assert_eq!(m.get_num_addresses(), 0x100);
        assert!(m.get_byte(&addr(0x8000)).is_err());
        let mut out = [0u8; 4];
        assert_eq!(m.get_bytes(&addr(0x8000), &mut out), 0);
    }

    #[test]
    fn overlapping_blocks_are_rejected_with_javas_message() {
        let map = new_map(false);
        let mut m = map.write().unwrap();
        m.create_uninitialized_block("one", &addr(0x1000), 0x10, false).unwrap();

        let err = m.create_initialized_block("two", &addr(0x1008), None, 0x10, None, false).err().unwrap();
        match err {
            MemoryMapError::Conflict(e) => assert_eq!(
                e.message(),
                Some("Part of range (00001008, 00001017) already exists in memory.")
            ),
            other => panic!("expected conflict, got {other:?}"),
        }
        assert!(matches!(
            m.create_uninitialized_block("three", &addr(0xff0), 0x11, false),
            Err(MemoryMapError::Conflict(_))
        ));
        // adjacent is fine
        m.create_uninitialized_block("four", &addr(0x1010), 0x10, false).unwrap();
        assert_eq!(m.get_blocks().len(), 2);
    }

    #[test]
    fn invalid_requests_follow_java_semantics() {
        let map = new_map(false);
        let mut m = map.write().unwrap();

        let err = m.create_uninitialized_block("zero", &addr(0x1000), 0, false).err().unwrap();
        assert_eq!(err.to_string(), "Block must have a non-zero length");

        let err = m.create_uninitialized_block("", &addr(0x1000), 1, false).err().unwrap();
        assert_eq!(err.to_string(), "Invalid block name: ");
        assert!(matches!(
            m.create_uninitialized_block("tab\there", &addr(0x1000), 1, false),
            Err(MemoryMapError::IllegalArgument(_))
        ));

        // runs off the end of the 32-bit space
        assert!(matches!(
            m.create_uninitialized_block("big", &addr(0xffff_fff0), 0x20, false),
            Err(MemoryMapError::AddressOverflow(_))
        ));

        // a space the program's address factory does not know
        let other = AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 5);
        let err = m.create_uninitialized_block("x", &Address::new(other, 0), 1, false).err().unwrap();
        assert_eq!(err.to_string(), "Block may not be created with unrecognized address space");

        assert!(matches!(
            m.create_uninitialized_block("huge", &addr(0), MAX_BLOCK_SIZE + 1, false),
            Err(MemoryMapError::IllegalState(_))
        ));
        assert!(matches!(
            m.create_uninitialized_block("ov", &addr(0x1000), 1, true),
            Err(MemoryMapError::IllegalState(_))
        ));
        assert!(m.get_blocks().is_empty());

        // Java allows several blocks with the same name
        m.create_uninitialized_block("dup", &addr(0x1000), 1, false).unwrap();
        m.create_uninitialized_block("dup", &addr(0x2000), 1, false).unwrap();
        assert_eq!(m.get_blocks().len(), 2);
    }

    #[test]
    fn cancelled_monitor_cancels_the_fill() {
        let map = new_map(false);
        let mut m = map.write().unwrap();
        let mut src: &[u8] = &[1, 2, 3, 4];
        let err = m
            .create_initialized_block("c", &addr(0x1000), Some(&mut src), 4, Some(&CancelledMonitor), false)
            .err().unwrap();
        assert!(matches!(err, MemoryMapError::Cancelled(_)), "{err:?}");
    }

    #[test]
    fn file_bytes_blocks_map_a_window_of_the_original_file() {
        let map = new_map(false);
        let mut m = map.write().unwrap();
        let file: Vec<u8> = (0u8..32).collect();
        let fb = m.create_file_bytes("a.out", 0, 32, &mut &file[..], &DummyMonitor).unwrap();
        assert_eq!(fb.get_size(), 32);
        assert_eq!(m.get_all_file_bytes().len(), 1);

        let block = m
            .create_initialized_block_from_file_bytes(".data", &addr(0x4000), fb.clone(), 8, 16, false)
            .unwrap();
        assert!(block.read().unwrap().is_initialized());
        let mut out = [0u8; 16];
        assert_eq!(m.get_bytes(&addr(0x4000), &mut out), 16);
        assert_eq!(out.to_vec(), (8u8..24).collect::<Vec<_>>());

        let err = m
            .create_initialized_block_from_file_bytes("z", &addr(0x5000), fb.clone(), 0, 0, false)
            .err().unwrap();
        assert_eq!(err.to_string(), "Length must be > 0, got 0");
        let err = m
            .create_initialized_block_from_file_bytes("o", &addr(0x5000), fb.clone(), 32, 1, false)
            .err().unwrap();
        assert_eq!(err.to_string(), "Offset must be in range [0,31], got 32");
        let err = m
            .create_initialized_block_from_file_bytes("e", &addr(0x5000), fb, 30, 4, false)
            .err().unwrap();
        assert_eq!(err.to_string(), "Specified length extends beyond file bytes length");
    }

    #[test]
    fn block_permissions_are_kept_in_the_record_flags() {
        let map = new_map(false);
        let mut m = map.write().unwrap();
        let block = m.create_uninitialized_block("p", &addr(0x1000), 4, false).unwrap();
        let mut b = block.write().unwrap();
        b.set_write(true);
        b.set_execute(true);
        b.set_read(false);
        b.set_volatile(true);
        assert!(!b.is_read() && b.is_write() && b.is_execute() && b.is_volatile());
        assert!(!b.is_artificial());
    }

    #[test]
    fn join_merges_contiguous_initialized_blocks() {
        let map = new_map(false);
        let mut m = map.write().unwrap();
        let mut a: &[u8] = &[1, 2, 3, 4];
        let one = m.create_initialized_block("a", &addr(0x100), Some(&mut a), 4, None, false).unwrap();
        let mut b: &[u8] = &[5, 6];
        let two = m.create_initialized_block("b", &addr(0x104), Some(&mut b), 2, None, false).unwrap();
        one.write().unwrap().set_execute(true);
        // argument order does not matter
        let joined = m.join(&two, &one).unwrap();
        assert_eq!(m.get_blocks().len(), 1);
        let j = joined.read().unwrap();
        assert_eq!(j.get_name(), "a");
        assert_eq!(j.get_start(), addr(0x100));
        assert_eq!(j.get_size(), 6);
        assert!(j.is_execute());
        drop(j);
        let mut out = [0u8; 6];
        assert_eq!(m.get_bytes(&addr(0x100), &mut out), 6);
        assert_eq!(out, [1, 2, 3, 4, 5, 6]);
        assert_eq!(m.get_num_addresses(), 6);
    }

    #[test]
    fn join_rejects_gaps_mixed_initialization_and_mapped_blocks() {
        let map = new_map(false);
        let mut m = map.write().unwrap();
        let a = m.create_uninitialized_block("a", &addr(0x100), 4, false).unwrap();
        let gap = m.create_uninitialized_block("gap", &addr(0x200), 4, false).unwrap();
        let err = m.join(&a, &gap).err().unwrap();
        assert_eq!(err.to_string(), "Blocks are not contiguous");
        let init = m.create_initialized_block("i", &addr(0x104), None, 4, None, false).unwrap();
        let err = m.join(&a, &init).err().unwrap();
        assert_eq!(err.to_string(), "Both blocks must be either initialized or uninitialized");
        let bits = m.create_bit_mapped_block("bits", &addr(0x300), &addr(0x104), 8, false).unwrap();
        assert_eq!(bits.read().unwrap().get_type(), MemoryBlockType::BitMapped);
        let next = m.create_uninitialized_block("n", &addr(0x308), 4, false).unwrap();
        let err = m.join(&bits, &next).err().unwrap();
        assert_eq!(err.to_string(), "Cannot join mapped blocks");
        // two uninitialized neighbours do join
        let b = m.create_uninitialized_block("b", &addr(0xfc), 4, false).unwrap();
        let joined = m.join(&a, &b).unwrap();
        assert_eq!(joined.read().unwrap().get_start(), addr(0xfc));
        assert_eq!(joined.read().unwrap().get_size(), 8);
    }

    #[test]
    fn mapped_blocks_read_through_their_source() {
        let map = new_map(false);
        let mut m = map.write().unwrap();
        let mut src: &[u8] = &[0b0000_0101, 0xAB];
        m.create_initialized_block("src", &addr(0x10), Some(&mut src), 2, None, false).unwrap();
        m.create_bit_mapped_block("bits", &addr(0x100), &addr(0x10), 8, false).unwrap();
        let bytes = m.create_byte_mapped_block("bytes", &addr(0x200), &addr(0x10), 2, None, false).unwrap();
        assert_eq!(bytes.read().unwrap().get_type(), MemoryBlockType::ByteMapped);
        // mapped blocks read their source back through the map, so read without the write lock
        drop(m);
        let mem = MemoryMapDB::as_memory(&map);
        assert_eq!(mem.get_byte(&addr(0x100)).unwrap(), 1);
        assert_eq!(mem.get_byte(&addr(0x101)).unwrap(), 0);
        assert_eq!(mem.get_byte(&addr(0x102)).unwrap(), 1);
        assert_eq!(mem.get_byte(&addr(0x201)).unwrap(), 0xAB);
        let mut m = map.write().unwrap();
        // a like-typed copy of an uninitialized block keeps its permissions
        let u = m.create_uninitialized_block("u", &addr(0x400), 4, false).unwrap();
        u.write().unwrap().set_write(true);
        let copy = m.create_block(&u, "u2", &addr(0x404), 4).unwrap();
        let c = copy.read().unwrap();
        assert!(!c.is_initialized() && c.is_write() && c.is_read());
    }

}
