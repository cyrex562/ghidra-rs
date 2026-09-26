//! Trait ported from the abstract class `ghidra.program.database.mem.MemoryMapDBAdapter`.
//!
//! In Java, `MemoryMapDBAdapter` is a package-private abstract base class that reads/writes the
//! "Memory Blocks" and "Sub Memory Blocks" tables backing a `MemoryMapDB`, and is implemented by
//! four versioned adapters (`MemoryMapDBAdapterV0`..`V3`) selected at open time based on the
//! on-disk schema version. It holds mutual references with `MemoryMapDB` and `MemoryBlockDB`
//! (the adapter creates/updates blocks; blocks and the memory map call back into the adapter for
//! persistence), which is exactly the coupling this port needs to cut. All four versioned adapters
//! are now ported (`memory_map_db_adapter_v0`..`v3`), and with them, the real version-selection
//! logic itself: [`get_adapter`] (with `findReadOnlyAdapter`/`upgrade` inlined as private helpers,
//! mirroring the identical situation already handled for
//! [`bookmark_db_adapter::get_adapter`](crate::program::database::bookmark::bookmark_db_adapter::get_adapter)).
//!
//! **`MemoryMapDB` does not call this factory.** Unlike `BookmarkDBManager` (which already called
//! a `get_adapter`-shaped stub before its own versioned adapters existed),
//! [`MemoryMapDB`](crate::program::database::mem::memory_map_db::MemoryMapDB) has its own
//! self-contained `new`/`create_block` that builds the "Memory Blocks"/"Sub Memory Blocks" tables
//! directly and never references `MemoryMapDBAdapter` at all -- there was no analogous
//! already-stubbed gap to complete here. Rewiring `MemoryMapDB` to route block creation through
//! this factory (so opening an existing, older-schema database would actually work) is a larger
//! structural change than this trait's six concrete adapters alone; [`get_adapter`] is provided
//! and tested standalone so that future work can wire it in without redesigning it first.
//!
//! **`upgrade`'s fidelity limit.** Java's `upgrade` reads `block.getType()`/`isMapped()`/
//! `getComment()`/`getSourceName()`/`getFlags()` off each old block to recreate it faithfully on
//! the new adapter. This crate's [`MemoryBlock`] trait exposes none of those (see that trait's own
//! module docs for its intentionally minimal surface), so [`upgrade`] can only distinguish
//! "initialized" (migrated as a real buffer block, bytes copied verbatim) from "not initialized"
//! (migrated as a plain uninitialized block of the same size) -- bit/byte-mapped blocks are
//! downgraded to uninitialized blocks of the same size/name during upgrade, and comments/source
//! names/flags are not preserved. This is a real, precise gap (not a stub): everything else about
//! the migrated block (name, start address, size, and -- for initialized blocks -- exact byte
//! content) is faithfully carried over.
//!
//! Memory blocks and sub blocks are exposed through the existing `MemoryBlock`/`SubMemoryBlock`
//! trait objects rather than the concrete `MemoryBlockDB` struct, and the owning memory map is
//! exposed through the `Memory` trait (which `MemoryMapDB` implements), so that neither
//! `MemoryBlockDB` nor `MemoryMapDB` need to depend on this trait to remain independently
//! portable/testable.

use std::error::Error;
use std::fmt;
use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::data::OpenMode;
use crate::framework::db::{DBBuffer, DBHandle, DBRecord};
use crate::program::database::map::AddressMapDB;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::database::mem::memory_map_db_adapter_v0::MemoryMapDBAdapterV0;
use crate::program::database::mem::memory_map_db_adapter_v1;
use crate::program::database::mem::memory_map_db_adapter_v2::MemoryMapDBAdapterV2;
use crate::program::database::mem::memory_map_db_adapter_v3::MemoryMapDBAdapterV3;
use crate::program::database::mem::sub_memory_block::SubMemoryBlock;
use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::mem::{Memory, MemoryBlock, MemoryBlockType};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Error type aggregating the checked exceptions thrown by Java's `MemoryMapDBAdapter` block
/// creation methods (`IOException`, `AddressOverflowException`).
#[derive(Debug)]
pub enum MemoryMapDBAdapterError {
    /// Mirrors `IOException`: a database error occurred.
    Io(io::Error),
    /// Mirrors `AddressOverflowException`: the block length is too large for the underlying
    /// address space.
    AddressOverflow(AddressOverflowException),
}

impl fmt::Display for MemoryMapDBAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::AddressOverflow(err) => write!(f, "{err}"),
        }
    }
}

impl Error for MemoryMapDBAdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::AddressOverflow(err) => Some(err),
        }
    }
}

impl From<io::Error> for MemoryMapDBAdapterError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<AddressOverflowException> for MemoryMapDBAdapterError {
    fn from(err: AddressOverflowException) -> Self {
        Self::AddressOverflow(err)
    }
}

/// Reads/writes the memory block and sub block tables backing a `MemoryMapDB`.
pub trait MemoryMapDBAdapter: Send + Sync {
    /// Returns a `DBBuffer` for the given database buffer id. Mirrors
    /// `MemoryMapDBAdapter.getBuffer(int)`.
    fn get_buffer(&self, buffer_id: i32) -> io::Result<Box<dyn DBBuffer>>;

    /// Deletes the underlying block/sub-block tables from `handle`. Mirrors
    /// `MemoryMapDBAdapter.deleteTable(DBHandle)`.
    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()>;

    /// Reloads block state from the database. Mirrors `MemoryMapDBAdapter.refreshMemory()`.
    fn refresh_memory(&mut self) -> io::Result<()>;

    /// Returns all memory blocks, sorted on start address. Mirrors
    /// `MemoryMapDBAdapter.getMemoryBlocks()`.
    fn get_memory_blocks(&self) -> Vec<Arc<RwLock<dyn MemoryBlock>>>;

    /// Creates a new initialized block using data read from `source` (or zero-initialized if
    /// `None`); once `source` is exhausted, the remaining block bytes are zero-filled. Mirrors
    /// `MemoryMapDBAdapter.createInitializedBlock(String, Address, InputStream, long, int)`.
    fn create_initialized_block_from_stream(
        &mut self,
        name: &str,
        start_addr: Address,
        source: Option<&mut dyn io::Read>,
        length: i64,
        flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError>;

    /// Creates a new initialized block using `buf` to hold the block's bytes. Mirrors
    /// `MemoryMapDBAdapter.createInitializedBlock(String, Address, DBBuffer, int)`.
    fn create_initialized_block_from_buffer(
        &mut self,
        name: &str,
        start_addr: Address,
        buf: Box<dyn DBBuffer>,
        flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError>;

    /// Creates a new memory block that doesn't have associated bytes. `mapped_address` is the
    /// starting byte source address at which to map the block (bit/byte-mapped blocks only);
    /// `initialize_bytes`, if true, allocates a database buffer for the block's bytes
    /// (initialized default blocks only); `encoded_mapping_scheme` is used by byte-mapped blocks
    /// only. Mirrors
    /// `MemoryMapDBAdapter.createBlock(MemoryBlockType, String, Address, long, Address, boolean, int, int)`.
    #[allow(clippy::too_many_arguments)]
    fn create_block(
        &mut self,
        block_type: MemoryBlockType,
        name: &str,
        start_addr: Address,
        length: i64,
        mapped_address: Option<Address>,
        initialize_bytes: bool,
        flags: i32,
        encoded_mapping_scheme: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError>;

    /// Deletes the given memory block. Mirrors
    /// `MemoryMapDBAdapter.deleteMemoryBlock(MemoryBlockDB)`.
    fn delete_memory_block(&mut self, block: &dyn MemoryBlock) -> io::Result<()>;

    /// Updates the memory block record. Mirrors `MemoryMapDBAdapter.updateBlockRecord(DBRecord)`.
    fn update_block_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Creates a new `DBBuffer` with the given length and initial value. Mirrors
    /// `MemoryMapDBAdapter.createBuffer(int, byte)`.
    fn create_buffer(&mut self, length: usize, initial_value: u8) -> io::Result<Box<dyn DBBuffer>>;

    /// Returns the memory map that owns this adapter. Mirrors
    /// `MemoryMapDBAdapter.getMemoryMap()`.
    fn get_memory_map(&self) -> Arc<RwLock<dyn Memory>>;

    /// Deletes the sub block record for the given key. Mirrors
    /// `MemoryMapDBAdapter.deleteSubBlock(long)`.
    fn delete_sub_block(&mut self, key: i64) -> io::Result<()>;

    /// Updates the sub memory block record. Mirrors
    /// `MemoryMapDBAdapter.updateSubBlockRecord(DBRecord)`.
    fn update_sub_block_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Creates a record for a newly created sub block. `mem_block_id` is the id of the owning
    /// memory block; `starting_offset` is relative to that memory block; `data1`/`data2` are
    /// sub-block-implementation-specific payload. Mirrors
    /// `MemoryMapDBAdapter.createSubBlockRecord(long, long, long, byte, int, long)`.
    fn create_sub_block_record(
        &mut self,
        mem_block_id: i64,
        starting_offset: i64,
        length: i64,
        sub_type: u8,
        data1: i32,
        data2: i64,
    ) -> io::Result<DBRecord>;

    /// Creates a new memory block composed of the given sub blocks. Mirrors
    /// `MemoryMapDBAdapter.createBlock(String, Address, long, int, List<SubMemoryBlock>)`.
    fn create_block_from_sub_blocks(
        &mut self,
        name: &str,
        start_address: Address,
        length: i64,
        flags: i32,
        split_blocks: Vec<Box<dyn SubMemoryBlock>>,
    ) -> io::Result<Arc<RwLock<dyn MemoryBlock>>>;

    /// Creates a new memory block backed by `file_bytes` starting at `offset` within it. Mirrors
    /// `MemoryMapDBAdapter.createFileBytesBlock(String, Address, long, FileBytes, long, int)`.
    fn create_file_bytes_block(
        &mut self,
        name: &str,
        start_address: Address,
        length: i64,
        file_bytes: Arc<dyn FileBytes>,
        offset: i64,
        flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError>;
}

/// Default `max_sub_block_size` passed to [`MemoryMapDBAdapterV3::open`]. Mirrors
/// `MemoryMapDBAdapter.getAdapter`'s hardcoded `Memory.GBYTE` argument (`1L << 30`), which has not
/// been ported onto this crate's [`Memory`] trait as an associated constant -- see
/// `buffer_sub_memory_block.rs`'s identical local `GBYTE` constant for the same reason.
pub const DEFAULT_MAX_SUB_BLOCK_SIZE: i64 = 1 << 30;

/// Selects (and upgrades, if needed) the appropriate memory-block table schema for the given
/// database handle and open mode. Port of `MemoryMapDBAdapter.getAdapter(DBHandle, OpenMode,
/// MemoryMapDB, TaskMonitor)`.
///
/// # Errors
/// Returns a [`VersionException`] if the stored schema version is incompatible with `open_mode`.
pub fn get_adapter(
    handle: Arc<RwLock<DBHandle>>,
    mem_map: Arc<RwLock<dyn Memory>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    open_mode: OpenMode,
    monitor: &dyn TaskMonitor,
) -> Result<Arc<RwLock<dyn MemoryMapDBAdapter>>, VersionException> {
    if open_mode == OpenMode::Create {
        let v3 = MemoryMapDBAdapterV3::open(handle, mem_map, addr_map, DEFAULT_MAX_SUB_BLOCK_SIZE, true)?;
        return Ok(v3 as Arc<RwLock<dyn MemoryMapDBAdapter>>);
    }

    match MemoryMapDBAdapterV3::open(handle.clone(), mem_map.clone(), addr_map.clone(), DEFAULT_MAX_SUB_BLOCK_SIZE, false) {
        Ok(v3) => Ok(v3 as Arc<RwLock<dyn MemoryMapDBAdapter>>),
        Err(e) => {
            if !e.is_upgradable() || open_mode == OpenMode::Update {
                return Err(e);
            }
            let old_adapter = find_read_only_adapter(handle.clone(), mem_map.clone(), addr_map.clone())?;
            if open_mode == OpenMode::Upgrade {
                return upgrade(handle, old_adapter, mem_map, addr_map, monitor);
            }
            Ok(old_adapter)
        }
    }
}

/// Probes each historical schema version, newest first, returning the first one that opens
/// successfully. Port of the package-private `MemoryMapDBAdapter.findReadOnlyAdapter(DBHandle,
/// MemoryMapDB)`.
fn find_read_only_adapter(
    handle: Arc<RwLock<DBHandle>>,
    mem_map: Arc<RwLock<dyn Memory>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
) -> Result<Arc<RwLock<dyn MemoryMapDBAdapter>>, VersionException> {
    if let Ok(v2) = MemoryMapDBAdapterV2::open(handle.clone(), mem_map.clone(), addr_map.clone()) {
        return Ok(v2 as Arc<RwLock<dyn MemoryMapDBAdapter>>);
    }
    if let Ok(v1) = memory_map_db_adapter_v1::open(handle.clone(), mem_map.clone(), addr_map.clone()) {
        return Ok(v1 as Arc<RwLock<dyn MemoryMapDBAdapter>>);
    }
    let v0 = MemoryMapDBAdapterV0::open(handle, mem_map, addr_map, 0)?;
    Ok(v0 as Arc<RwLock<dyn MemoryMapDBAdapter>>)
}

/// Upgrades an older memory-block schema to the current ([`MemoryMapDBAdapterV3`]) one in place.
/// Port of the package-private `MemoryMapDBAdapter.upgrade(DBHandle, MemoryMapDBAdapter,
/// MemoryMapDB, TaskMonitor)`. See this module's docs for the real, precisely-scoped fidelity
/// limit versus Java's original (block type/comment/source name/flags are not preserved; only
/// name, start address, size, and -- for initialized blocks -- exact byte content are).
///
/// # Errors
/// Returns a [`VersionException`] if building the replacement `V3` tables fails.
fn upgrade(
    handle: Arc<RwLock<DBHandle>>,
    old_adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>,
    mem_map: Arc<RwLock<dyn Memory>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    monitor: &dyn TaskMonitor,
) -> Result<Arc<RwLock<dyn MemoryMapDBAdapter>>, VersionException> {
    monitor.set_message("Upgrading Memory Blocks...");
    let old_blocks = old_adapter.read().unwrap().get_memory_blocks();
    monitor.initialize(old_blocks.len() as i64 * 2);

    // Mirrors Java's `oldAdapter.deleteTable(handle)` before creating V3's tables: the old
    // schema's table(s) must be removed first, or V3's `create_table` calls below fail with
    // "already exists" (V0/V1's "Memory Block" table shares no name with V3's, but V2's "Memory
    // Blocks" table does).
    {
        let mut h = handle.write().unwrap();
        // V3 itself has no old table to delete when it's the `old_adapter` (unreachable here:
        // `get_adapter` only calls `upgrade` after a V3 open already failed), so this is always
        // V0/V1/V2's real, working `delete_table`.
        let _ = old_adapter.write().unwrap().delete_table(&mut h);
    }

    let new_adapter = MemoryMapDBAdapterV3::open(handle, mem_map, addr_map, DEFAULT_MAX_SUB_BLOCK_SIZE, true)?;

    for (i, block) in old_blocks.iter().enumerate() {
        let b = block.read().unwrap();
        let name = b.get_name().to_string();
        let start = b.get_start();
        let size = b.get_size() as i64;
        let initialized = b.is_initialized();
        if initialized {
            let mut bytes = vec![0u8; size as usize];
            b.get_bytes(&start, &mut bytes);
            drop(b);
            let mut reader: &[u8] = &bytes;
            new_adapter
                .write()
                .unwrap()
                .create_initialized_block_from_stream(&name, start, Some(&mut reader), size, 0)
                .map_err(|e| VersionException::with_message(e.to_string()))?;
        } else {
            drop(b);
            new_adapter
                .write()
                .unwrap()
                .create_block(MemoryBlockType::Default, &name, start, size, None, false, 0, 0)
                .map_err(|e| VersionException::with_message(e.to_string()))?;
        }
        monitor.set_progress(i as i64 + 1);
    }
    Ok(new_adapter as Arc<RwLock<dyn MemoryMapDBAdapter>>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::mem::MemoryAccessException;
    use std::collections::HashMap;

    /// Minimal in-memory `DBBuffer` used only to exercise `get_buffer`/`create_buffer`
    /// round-tripping.
    struct MockBuffer {
        id: i32,
        data: Vec<u8>,
    }

    impl DBBuffer for MockBuffer {
        fn split(&mut self, offset: usize) -> io::Result<Box<dyn DBBuffer>> {
            let tail = self.data.split_off(offset);
            Ok(Box::new(MockBuffer {
                id: self.id + 1,
                data: tail,
            }))
        }
        fn set_size(&mut self, size: usize, _preserve_data: bool) -> io::Result<()> {
            self.data.resize(size, 0);
            Ok(())
        }
        fn length(&self) -> usize {
            self.data.len()
        }
        fn get_id(&self) -> i32 {
            self.id
        }
        fn fill(&mut self, start_offset: usize, end_offset: usize, fill_byte: u8) -> io::Result<()> {
            for b in &mut self.data[start_offset..end_offset] {
                *b = fill_byte;
            }
            Ok(())
        }
        fn append(&mut self, mut buffer: Box<dyn DBBuffer>) -> io::Result<()> {
            let len = buffer.length();
            let mut tail = vec![0u8; len];
            buffer.get_all(0, &mut tail)?;
            self.data.extend_from_slice(&tail);
            buffer.delete()
        }
        fn get_byte(&self, offset: usize) -> io::Result<u8> {
            Ok(self.data[offset])
        }
        fn get(&self, offset: usize, data: &mut [u8], data_offset: usize, length: usize) -> io::Result<()> {
            data[data_offset..data_offset + length].copy_from_slice(&self.data[offset..offset + length]);
            Ok(())
        }
        fn fill_from_reader(&mut self, reader: &mut dyn io::Read) -> io::Result<()> {
            let mut total = 0;
            while total < self.data.len() {
                let n = reader.read(&mut self.data[total..])?;
                if n == 0 {
                    break;
                }
                total += n;
            }
            Ok(())
        }
        fn put(&mut self, offset: usize, bytes: &[u8], data_offset: usize, length: usize) -> io::Result<()> {
            self.data[offset..offset + length].copy_from_slice(&bytes[data_offset..data_offset + length]);
            Ok(())
        }
        fn put_byte(&mut self, offset: usize, b: u8) -> io::Result<()> {
            self.data[offset] = b;
            Ok(())
        }
        fn delete(&mut self) -> io::Result<()> {
            self.data.clear();
            Ok(())
        }
    }

    struct MockMemory;

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _addr: &Address, dest: &mut [u8]) -> usize {
            dest.len()
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
    }

    /// A minimal in-memory `MemoryBlock` used only by these adapter smoke tests.
    struct MockMemBlock {
        name: String,
        start: Address,
        bytes: Vec<u8>,
    }

    impl MemoryBlock for MockMemBlock {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_start(&self) -> Address {
            self.start.clone()
        }
        fn get_end(&self) -> Address {
            if self.bytes.is_empty() {
                return self.start.clone();
            }
            self.start
                .add(self.bytes.len() as i64 - 1)
                .unwrap_or_else(|_| self.start.clone())
        }
        fn get_size(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let idx = (addr.offset() - self.start.offset()) as usize;
            self.bytes
                .get(idx)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of range"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let idx = (addr.offset() - self.start.offset()) as usize;
            let available = self.bytes.len().saturating_sub(idx);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.bytes[idx..idx + n]);
            n
        }
        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let idx = (addr.offset() - self.start.offset()) as usize;
            if idx + source.len() > self.bytes.len() {
                return Err(MemoryAccessException::new("out of range"));
            }
            self.bytes[idx..idx + source.len()].copy_from_slice(source);
            Ok(())
        }
    }

    /// A minimal `MemoryMapDBAdapter` proving the trait is object-safe and that its methods
    /// behave sensibly against real (non-trivial) in-memory state, standing in for the real
    /// versioned DB-backed adapters.
    struct MockAdapter {
        next_key: i32,
        blocks: Vec<Arc<RwLock<dyn MemoryBlock>>>,
        buffers: HashMap<i32, Vec<u8>>,
        sub_block_keys: Vec<i64>,
        memory: Arc<RwLock<dyn Memory>>,
    }

    impl MockAdapter {
        fn new() -> Self {
            Self {
                next_key: 0,
                blocks: Vec::new(),
                buffers: HashMap::new(),
                sub_block_keys: Vec::new(),
                memory: Arc::new(RwLock::new(MockMemory)),
            }
        }
    }

    impl MemoryMapDBAdapter for MockAdapter {
        fn get_buffer(&self, buffer_id: i32) -> io::Result<Box<dyn DBBuffer>> {
            let data = self
                .buffers
                .get(&buffer_id)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such buffer"))?;
            Ok(Box::new(MockBuffer { id: buffer_id, data }))
        }

        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            self.blocks.clear();
            Ok(())
        }

        fn refresh_memory(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn get_memory_blocks(&self) -> Vec<Arc<RwLock<dyn MemoryBlock>>> {
            self.blocks.clone()
        }

        fn create_initialized_block_from_stream(
            &mut self,
            name: &str,
            start_addr: Address,
            source: Option<&mut dyn io::Read>,
            length: i64,
            _flags: i32,
        ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
            let mut bytes = vec![0u8; length as usize];
            if let Some(reader) = source {
                let mut total = 0usize;
                while total < bytes.len() {
                    let n = reader.read(&mut bytes[total..])?;
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
            }
            let block: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(MockMemBlock {
                name: name.to_string(),
                start: start_addr,
                bytes,
            }));
            self.blocks.push(block.clone());
            Ok(block)
        }

        fn create_initialized_block_from_buffer(
            &mut self,
            name: &str,
            start_addr: Address,
            mut buf: Box<dyn DBBuffer>,
            _flags: i32,
        ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
            let mut bytes = vec![0u8; buf.length()];
            buf.get_all(0, &mut bytes)?;
            let block: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(MockMemBlock {
                name: name.to_string(),
                start: start_addr,
                bytes,
            }));
            self.blocks.push(block.clone());
            Ok(block)
        }

        fn create_block(
            &mut self,
            _block_type: MemoryBlockType,
            name: &str,
            start_addr: Address,
            length: i64,
            _mapped_address: Option<Address>,
            _initialize_bytes: bool,
            _flags: i32,
            _encoded_mapping_scheme: i32,
        ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
            if length < 0 {
                return Err(AddressOverflowException::default().into());
            }
            let block: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(MockMemBlock {
                name: name.to_string(),
                start: start_addr,
                bytes: vec![0u8; length as usize],
            }));
            self.blocks.push(block.clone());
            Ok(block)
        }

        fn delete_memory_block(&mut self, block: &dyn MemoryBlock) -> io::Result<()> {
            self.blocks
                .retain(|b| b.read().unwrap().get_name() != block.get_name());
            Ok(())
        }

        fn update_block_record(&mut self, _record: &DBRecord) -> io::Result<()> {
            Ok(())
        }

        fn create_buffer(&mut self, length: usize, initial_value: u8) -> io::Result<Box<dyn DBBuffer>> {
            let id = self.next_key;
            self.next_key += 1;
            let data = vec![initial_value; length];
            self.buffers.insert(id, data.clone());
            Ok(Box::new(MockBuffer { id, data }))
        }

        fn get_memory_map(&self) -> Arc<RwLock<dyn Memory>> {
            self.memory.clone()
        }

        fn delete_sub_block(&mut self, key: i64) -> io::Result<()> {
            self.sub_block_keys.retain(|k| *k != key);
            Ok(())
        }

        fn update_sub_block_record(&mut self, _record: &DBRecord) -> io::Result<()> {
            Ok(())
        }

        fn create_sub_block_record(
            &mut self,
            _mem_block_id: i64,
            _starting_offset: i64,
            _length: i64,
            _sub_type: u8,
            _data1: i32,
            _data2: i64,
        ) -> io::Result<DBRecord> {
            let key = self.next_key as i64;
            self.next_key += 1;
            self.sub_block_keys.push(key);
            let schema = std::sync::Arc::new(crate::framework::db::Schema::new(
                1,
                crate::framework::db::FieldType::Long,
                "Key".to_string(),
                vec![],
                vec![],
                vec![],
            ));
            Ok(DBRecord::new(
                schema,
                crate::framework::db::Field::Long(Some(key)),
            ))
        }

        fn create_block_from_sub_blocks(
            &mut self,
            name: &str,
            start_address: Address,
            length: i64,
            _flags: i32,
            _split_blocks: Vec<Box<dyn SubMemoryBlock>>,
        ) -> io::Result<Arc<RwLock<dyn MemoryBlock>>> {
            let block: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(MockMemBlock {
                name: name.to_string(),
                start: start_address,
                bytes: vec![0u8; length as usize],
            }));
            self.blocks.push(block.clone());
            Ok(block)
        }

        fn create_file_bytes_block(
            &mut self,
            name: &str,
            start_address: Address,
            length: i64,
            _file_bytes: Arc<dyn FileBytes>,
            _offset: i64,
            _flags: i32,
        ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
            let block: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(MockMemBlock {
                name: name.to_string(),
                start: start_address,
                bytes: vec![0u8; length as usize],
            }));
            self.blocks.push(block.clone());
            Ok(block)
        }
    }

    fn test_addr(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn create_initialized_block_from_stream_reads_and_zero_fills_remainder() {
        let mut adapter = MockAdapter::new();
        let mut reader: &[u8] = &[1, 2, 3];
        let block = adapter
            .create_initialized_block_from_stream(
                "block1",
                test_addr(0x1000),
                Some(&mut reader),
                6,
                0,
            )
            .unwrap();
        let b = block.read().unwrap();
        assert_eq!(b.get_size(), 6);
        let mut out = [0u8; 6];
        assert_eq!(b.get_bytes(&test_addr(0x1000), &mut out), 6);
        assert_eq!(out, [1, 2, 3, 0, 0, 0]);
    }

    #[test]
    fn get_memory_blocks_reflects_creates_and_deletes() {
        let mut adapter = MockAdapter::new();
        adapter
            .create_block(
                MemoryBlockType::Default,
                "a",
                test_addr(0),
                4,
                None,
                true,
                0,
                0,
            )
            .unwrap();
        adapter
            .create_block(
                MemoryBlockType::Default,
                "b",
                test_addr(0x100),
                4,
                None,
                true,
                0,
                0,
            )
            .unwrap();
        assert_eq!(adapter.get_memory_blocks().len(), 2);

        let victim = adapter.get_memory_blocks()[0].clone();
        let victim_ref = victim.read().unwrap();
        adapter.delete_memory_block(&*victim_ref).unwrap();
        drop(victim_ref);

        let remaining = adapter.get_memory_blocks();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].read().unwrap().get_name(), "b");
    }

    #[test]
    fn create_block_rejects_negative_length_as_address_overflow() {
        let mut adapter = MockAdapter::new();
        let result = adapter.create_block(
            MemoryBlockType::Default,
            "bad",
            test_addr(0),
            -1,
            None,
            false,
            0,
            0,
        );
        match result {
            Err(MemoryMapDBAdapterError::AddressOverflow(_)) => {}
            other => panic!("expected AddressOverflow error, got {}", other.is_ok()),
        }
    }

    #[test]
    fn create_buffer_and_get_buffer_round_trip() {
        let mut adapter = MockAdapter::new();
        let buf = adapter.create_buffer(4, 0xAB).unwrap();
        let id = buf.get_id();
        drop(buf);

        let fetched = adapter.get_buffer(id).unwrap();
        let mut out = [0u8; 4];
        fetched.get_all(0, &mut out).unwrap();
        assert_eq!(out, [0xAB, 0xAB, 0xAB, 0xAB]);
    }

    #[test]
    fn delete_sub_block_removes_created_key() {
        let mut adapter = MockAdapter::new();
        let record = adapter.create_sub_block_record(1, 0, 10, 0, 0, 0).unwrap();
        let key = match record.get_key() {
            crate::framework::db::Field::Long(Some(k)) => *k,
            _ => panic!("expected long key"),
        };
        assert_eq!(adapter.sub_block_keys, vec![key]);
        adapter.delete_sub_block(key).unwrap();
        assert!(adapter.sub_block_keys.is_empty());
    }

    #[test]
    fn get_memory_map_returns_shared_memory() {
        let adapter = MockAdapter::new();
        let mem = adapter.get_memory_map();
        assert!(!mem.read().unwrap().is_big_endian());
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut adapter: Box<dyn MemoryMapDBAdapter> = Box::new(MockAdapter::new());
        adapter.refresh_memory().unwrap();
        assert!(adapter.get_memory_blocks().is_empty());
    }

    mod factory {
        use super::*;
        use crate::program::database::map::AddressMapDB;
        use crate::program::model::address::{AddressFactory, AddressSpaceType, DefaultAddressFactory};
        use crate::program::model::mem::MemoryAccessException;
        use crate::util::task::DummyMonitor;

        struct StubMemory;
        impl Memory for StubMemory {
            fn is_big_endian(&self) -> bool {
                false
            }
            fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
                Ok(0)
            }
            fn get_bytes(&self, _addr: &Address, dest: &mut [u8]) -> usize {
                dest.len()
            }
            fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
                Ok(())
            }
        }

        fn setup() -> (Arc<RwLock<DBHandle>>, Arc<RwLock<AddressMapDB>>, Arc<RwLock<dyn Memory>>) {
            let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
            let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
            let factory = DefaultAddressFactory::new(vec![space]);
            let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
            let mem_map: Arc<RwLock<dyn Memory>> = Arc::new(RwLock::new(StubMemory));
            (handle, addr_map, mem_map)
        }

        #[test]
        fn create_mode_builds_a_fresh_v3_adapter() {
            let (handle, addr_map, mem_map) = setup();
            let monitor = DummyMonitor;
            let adapter = get_adapter(handle, mem_map, addr_map, OpenMode::Create, &monitor).unwrap();
            assert!(adapter.read().unwrap().get_memory_blocks().is_empty());
        }

        #[test]
        fn immutable_mode_on_existing_v3_database_reopens_it() {
            let (handle, addr_map, mem_map) = setup();
            let monitor = DummyMonitor;
            {
                let created = get_adapter(handle.clone(), mem_map.clone(), addr_map.clone(), OpenMode::Create, &monitor).unwrap();
                created
                    .write()
                    .unwrap()
                    .create_block(MemoryBlockType::Default, "x", test_addr(0x1000), 4, None, false, 0, 0)
                    .unwrap();
            }
            let reopened = get_adapter(handle, mem_map, addr_map, OpenMode::Immutable, &monitor).unwrap();
            // Mirrors Java: `getAdapter` itself never populates `memoryBlocks` on reopen -- it's
            // `MemoryMapDB`'s own constructor that calls `adapter.refreshMemory()` right after
            // `getAdapter()` returns (see this module's docs on why `MemoryMapDB` doesn't route
            // through this factory yet, so nothing else calls it here).
            reopened.write().unwrap().refresh_memory().unwrap();
            assert_eq!(reopened.read().unwrap().get_memory_blocks().len(), 1);
        }

        #[test]
        fn upgrade_mode_migrates_an_old_v2_database_preserving_bytes() {
            let (handle, addr_map, mem_map) = setup();
            let monitor = DummyMonitor;

            // Build a real, standalone V2 database (not created via this factory, since V2 is a
            // read-only historical schema) with one initialized block.
            {
                use crate::program::database::mem::memory_map_db_adapter_v2::MemoryMapDBAdapterV2;
                let buf_id = {
                    let mut buf = handle.write().unwrap().create_buffer(3).unwrap();
                    buf.put_all(0, &[11, 22, 33]).unwrap();
                    buf.get_id()
                };
                let table = handle
                    .write()
                    .unwrap()
                    .create_table(
                        "Memory Blocks".to_string(),
                        crate::program::database::mem::memory_map_db_adapter_v2::v2_schema(),
                    )
                    .unwrap();
                let key = table.write().unwrap().get_next_key();
                let mut rec = DBRecord::new(table.read().unwrap().get_schema(), crate::framework::db::Field::Long(Some(key)));
                rec.set_string(0, Some("legacy".to_string()));
                rec.set_string(1, Some("c".to_string()));
                rec.set_string(2, Some("s".to_string()));
                rec.set_byte(3, 7);
                let start_addr = test_addr(0x5000);
                let start_key = addr_map.read().unwrap().get_key(&start_addr, true);
                rec.set_long(4, start_key);
                rec.set_field(5, crate::framework::db::Field::Short(Some(0))); // INITIALIZED
                rec.set_long(6, 0);
                rec.set_long(7, 3);
                rec.set_int(8, buf_id);
                rec.set_int(9, 0);
                table.write().unwrap().put_record(rec).unwrap();
                let _ = MemoryMapDBAdapterV2::open(handle.clone(), mem_map.clone(), addr_map.clone()).unwrap();
            }

            let upgraded = get_adapter(handle, mem_map, addr_map, OpenMode::Upgrade, &monitor).unwrap();
            let blocks = upgraded.read().unwrap().get_memory_blocks();
            assert_eq!(blocks.len(), 1);
            let b = blocks[0].read().unwrap();
            assert_eq!(b.get_name(), "legacy");
            let mut out = [0u8; 3];
            let start = test_addr(0x5000);
            assert_eq!(b.get_bytes(&start, &mut out), 3);
            assert_eq!(out, [11, 22, 33]);
        }

        #[test]
        fn update_mode_on_incompatible_schema_reports_version_exception() {
            let (handle, addr_map, mem_map) = setup();
            let monitor = DummyMonitor;
            // No table at all -- V3 open fails upgradeable(false), and Update mode must not try
            // to fall back to an older reader.
            assert!(get_adapter(handle, mem_map, addr_map, OpenMode::Update, &monitor).is_err());
        }
    }
}
