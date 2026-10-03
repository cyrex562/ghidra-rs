//! Port of the class `ghidra.program.database.mem.MemoryMapDBAdapterV0`.
//!
//! Oldest historical schema, read-only: every mutating trait method returns
//! `io::ErrorKind::Unsupported`, mirroring Java's `throw new UnsupportedOperationException()` on
//! every one of them. [`open`](MemoryMapDBAdapterV0::open) parses the legacy "Memory Block" table
//! (one flat record per block, with the block's single implicit sub block folded into the same
//! row) directly into the *current* (V3-shaped) block/sub-block record layout that
//! `sub_block_header.rs` already uses -- exactly like Java's constructor building `BLOCK_SCHEMA`/
//! `SUB_BLOCK_SCHEMA` (aliases of `MemoryMapDBAdapterV3`'s schema) records from the legacy columns.
//!
//! **Two-phase construction.** Java's constructor builds `List<MemoryBlockDB>` directly, handing
//! each freshly-built sub block `this` (the adapter itself) as its `MemoryMapDBAdapter`. This port
//! cannot do that inside a plain constructor -- there is no `Arc<RwLock<Self>>` to hand out until
//! *after* the struct exists. So [`open`](MemoryMapDBAdapterV0::open) instead: (1) parses the
//! table into an intermediate `ParsedBlock` list with no adapter dependency; (2) wraps the (empty)
//! adapter in `Arc::new`; (3) builds the real sub blocks/`MemoryBlockDB`s from the parsed data,
//! now that a genuine self-`Arc` exists to hand them (via the non-locking `from_parts`
//! constructors, so nothing here re-locks the adapter it's still constructing). This differs from
//! `MemoryMapDBAdapterV3`'s `Arc::new_cyclic` approach specifically because V0 needs a *live*,
//! already-upgradable self-reference *during* construction (to build its `blocks` list up front),
//! which `new_cyclic`'s `Weak::upgrade` cannot provide (it only succeeds once the `Arc` exists).
//!
//! **Address translation simplification.** Java re-resolves each legacy start address via
//! `addrFactory.oldGetAddressFromLong(...)` then `addrMap.getKey(start, false)`, translating from
//! the *old* on-disk address-key format to the *current* one. This crate's simplified
//! [`AddressMapDB`](crate::program::database::map::AddressMapDB) uses a single, stable
//! space-id/offset packing for both (see that module's docs), so `get_key`/`decode_address` are
//! exact inverses and there is no separate "old" format to translate from; the stored legacy long
//! is used directly as this crate's address-map key. The segment column is carried through
//! unconditionally (rather than Java's `expectedVersion == 1 && start instanceof SegmentedAddress`
//! guard) for the same reason `MemoryMapDBAdapterV3::get_segment` always returns 0 for
//! non-segmented spaces -- see that module's docs.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::record::DBRecord;
use crate::framework::db::{DBBuffer, DBHandle, Field, FieldType, Schema};
use crate::program::database::map::AddressMapDB;
use crate::program::database::mem::bit_mapped_sub_memory_block::BitMappedSubMemoryBlock;
use crate::program::database::mem::buffer_sub_memory_block::BufferSubMemoryBlock;
use crate::program::database::mem::byte_mapped_sub_memory_block::ByteMappedSubMemoryBlock;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::database::mem::memory_block_db::MemoryBlockDB;
use crate::program::database::mem::memory_map_db_adapter::{MemoryMapDBAdapter, MemoryMapDBAdapterError};
use crate::program::database::mem::memory_map_db_adapter_v3::{
    v3_block_schema, v3_sub_block_schema, V3_COMMENTS_COL, V3_FLAGS_COL, V3_LENGTH_COL, V3_NAME_COL, V3_SEGMENT_COL,
    V3_SOURCE_COL, V3_START_ADDR_COL,
};
use crate::program::database::mem::sub_block_header::{
    SUB_INT_DATA1_COL, SUB_LENGTH_COL, SUB_LONG_DATA2_COL, SUB_PARENT_ID_COL, SUB_START_OFFSET_COL, SUB_TYPE_BIT_MAPPED,
    SUB_TYPE_BUFFER, SUB_TYPE_BYTE_MAPPED, SUB_TYPE_COL, SUB_TYPE_UNINITIALIZED,
};
use crate::program::database::mem::sub_memory_block::SubMemoryBlock;
use crate::program::database::mem::uninitialized_sub_memory_block::UninitializedSubMemoryBlock;
use crate::program::model::address::Address;
use crate::program::model::mem::{Memory, MemoryBlock, MemoryBlockType};
use crate::util::exception::VersionException;

/// Name of the legacy "Memory Block" table. Mirrors `MemoryMapDBAdapterV0.V0_TABLE_NAME`.
pub const V0_TABLE_NAME: &str = "Memory Block";

const VERSION: i32 = 0;

pub(crate) const V0_NAME_COL: usize = 0;
pub(crate) const V0_BUFFER_ID_COL: usize = 1;
pub(crate) const V0_COMMENTS_COL: usize = 2;
pub(crate) const V0_SOURCE_NAME_COL: usize = 4;
pub(crate) const V0_IS_READ_COL: usize = 6;
pub(crate) const V0_IS_WRITE_COL: usize = 7;
pub(crate) const V0_IS_EXECUTE_COL: usize = 8;
pub(crate) const V0_START_ADDR_COL: usize = 9;
pub(crate) const V0_LENGTH_COL: usize = 10;
pub(crate) const V0_TYPE_COL: usize = 11;
pub(crate) const V0_BASE_ADDR_COL: usize = 12;
pub(crate) const V0_SEGMENT_COL: usize = 14;

const READ_FLAG: i32 = 1;
const WRITE_FLAG: i32 = 2;
const EXECUTE_FLAG: i32 = 4;

pub(crate) const BLOCK_TYPE_INITIALIZED: i16 = 0;
pub(crate) const BLOCK_TYPE_UNINITIALIZED: i16 = 1;
pub(crate) const BLOCK_TYPE_BIT_MAPPED: i16 = 2;
pub(crate) const BLOCK_TYPE_BYTE_MAPPED: i16 = 4;

/// Mirrors the commented-out `V0_TABLE_NAME` schema documented in Java's source (never actually
/// instantiated there -- V0 is read-only and only ever reads an already-existing table with this
/// shape).
/// Exposed `pub(crate)` (rather than private) so
/// [`memory_map_db_adapter_v1`](crate::program::database::mem::memory_map_db_adapter_v1)'s own
/// tests can build a realistic legacy fixture table without duplicating this 15-column layout.
pub(crate) fn v0_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::String, // 0 Name
            FieldType::Int,    // 1 Chain Buffer ID
            FieldType::String, // 2 Comments
            FieldType::String, // 3 Description (deprecated/ignored)
            FieldType::String, // 4 Source Name
            FieldType::Long,   // 5 Source Offset (deprecated/ignored)
            FieldType::Boolean,// 6 Is Read
            FieldType::Boolean,// 7 Is Write
            FieldType::Boolean,// 8 Is Execute
            FieldType::Long,   // 9 Start Address
            FieldType::Int,    // 10 Length
            FieldType::Short,  // 11 Block Type
            FieldType::Long,   // 12 Base Address
            FieldType::Long,   // 13 Source Block ID (deprecated/ignored)
            FieldType::Int,    // 14 Segment (added in V1)
        ],
        vec![
            "Name".to_string(),
            "Chain Buffer ID".to_string(),
            "Comments".to_string(),
            "Description".to_string(),
            "Source Name".to_string(),
            "Source Offset".to_string(),
            "Is Read".to_string(),
            "Is Write".to_string(),
            "Is Execute".to_string(),
            "Start Address".to_string(),
            "Length".to_string(),
            "Block Type".to_string(),
            "Base Address".to_string(),
            "Source Block ID".to_string(),
            "Segment".to_string(),
        ],
        vec![],
    ))
}

struct ParsedBlock {
    block_record: DBRecord,
    sub_record: DBRecord,
    sub_type: i16,
    buf_id: i32,
}

/// MemoryMap adapter for version 0: the oldest historical schema, read-only. Mirrors
/// `ghidra.program.database.mem.MemoryMapDBAdapterV0`.
pub struct MemoryMapDBAdapterV0 {
    handle: Arc<RwLock<DBHandle>>,
    mem_map: Arc<RwLock<dyn Memory>>,
    blocks: Vec<Arc<RwLock<dyn MemoryBlock>>>,
}

impl MemoryMapDBAdapterV0 {
    /// Opens the legacy "Memory Block" table for read-only/upgrade access. Mirrors
    /// `MemoryMapDBAdapterV0(DBHandle, MemoryMapDB)` / the `protected` 3-arg constructor V1 calls
    /// with `expectedVersion = 1`.
    ///
    /// # Errors
    /// Returns a [`VersionException`] if the table is missing or its schema version does not
    /// match `expected_version`.
    pub fn open(
        handle: Arc<RwLock<DBHandle>>,
        mem_map: Arc<RwLock<dyn Memory>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
        expected_version: i32,
    ) -> Result<Arc<RwLock<Self>>, VersionException> {
        let parsed = Self::parse(&handle, &addr_map, expected_version)?;

        let adapter = Arc::new(RwLock::new(Self {
            handle,
            mem_map,
            blocks: Vec::new(),
        }));

        let mut built: Vec<Arc<RwLock<dyn MemoryBlock>>> = Vec::with_capacity(parsed.len());
        for p in parsed {
            let trait_adapter: Arc<RwLock<dyn MemoryMapDBAdapter>> = adapter.clone();
            let sub_block: Box<dyn SubMemoryBlock> = match p.sub_type {
                t if t == BLOCK_TYPE_BIT_MAPPED => {
                    let mapped = addr_map.read().unwrap().decode_address(p.sub_record.get_long(SUB_LONG_DATA2_COL).unwrap_or(0));
                    Box::new(BitMappedSubMemoryBlock::from_parts(trait_adapter, p.sub_record, adapter.read().unwrap().mem_map.clone(), mapped))
                }
                t if t == BLOCK_TYPE_BYTE_MAPPED => {
                    let mapped = addr_map.read().unwrap().decode_address(p.sub_record.get_long(SUB_LONG_DATA2_COL).unwrap_or(0));
                    let mem_map = adapter.read().unwrap().mem_map.clone();
                    ByteMappedSubMemoryBlock::from_parts(trait_adapter, p.sub_record, mem_map, mapped)
                        .map(|b| Box::new(b) as Box<dyn SubMemoryBlock>)
                        .map_err(|e| VersionException::with_message(e.to_string()))?
                }
                t if t == BLOCK_TYPE_INITIALIZED => {
                    let h = handle_ref(&adapter);
                    let buf = h.read().unwrap().get_buffer(p.buf_id).map_err(|e| VersionException::with_message(e.to_string()))?;
                    Box::new(BufferSubMemoryBlock::from_parts(trait_adapter, p.sub_record, buf))
                }
                _ => Box::new(UninitializedSubMemoryBlock::new(trait_adapter, p.sub_record)),
            };
            let block = MemoryBlockDB::with_sub_blocks(p.block_record, addr_map.clone(), vec![sub_block]);
            built.push(Arc::new(RwLock::new(block)));
        }
        built.sort_by(|a, b| a.read().unwrap().get_start().cmp(&b.read().unwrap().get_start()));
        adapter.write().unwrap().blocks = built;

        Ok(adapter)
    }

    fn parse(
        handle: &Arc<RwLock<DBHandle>>,
        addr_map: &Arc<RwLock<AddressMapDB>>,
        expected_version: i32,
    ) -> Result<Vec<ParsedBlock>, VersionException> {
        let table = handle
            .read()
            .unwrap()
            .get_table(V0_TABLE_NAME)
            .ok_or_else(|| VersionException::with_message("Memory Block table not found"))?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != expected_version {
            return Err(VersionException::with_message(format!(
                "Memory Block table: Expected Version {expected_version}, got {version}"
            )));
        }

        let mut parsed = Vec::new();
        let table_ref = table.read().unwrap();
        let mut it = table_ref
            .get_record_iterator()
            .map_err(|e| VersionException::with_message(e.to_string()))?;
        let mut key = 0i64;
        while let Some(rec) = it.next().map_err(|e| VersionException::with_message(e.to_string()))? {
            let mut flags = 0i32;
            if rec.get_bool(V0_IS_READ_COL).unwrap_or(false) {
                flags |= READ_FLAG;
            }
            if rec.get_bool(V0_IS_WRITE_COL).unwrap_or(false) {
                flags |= WRITE_FLAG;
            }
            if rec.get_bool(V0_IS_EXECUTE_COL).unwrap_or(false) {
                flags |= EXECUTE_FLAG;
            }

            // See this module's docs: this crate's AddressMapDB uses one stable key format, so
            // the stored legacy long is used directly rather than round-tripping through a
            // separate "old address factory".
            let start_key = rec.get_long(V0_START_ADDR_COL).unwrap_or(0);
            let length = rec.get_int(V0_LENGTH_COL).unwrap_or(0) as i64;
            let buf_id = rec.get_int(V0_BUFFER_ID_COL).unwrap_or(0);
            let segment = if expected_version >= 1 {
                rec.get_int(V0_SEGMENT_COL).unwrap_or(0)
            } else {
                0
            };

            let mut block_record = DBRecord::new(v3_block_schema(), Field::Long(Some(key)));
            block_record.set_string(V3_NAME_COL, rec.get_string(V0_NAME_COL).map(|s| s.to_string()));
            block_record.set_string(V3_COMMENTS_COL, rec.get_string(V0_COMMENTS_COL).map(|s| s.to_string()));
            block_record.set_string(V3_SOURCE_COL, rec.get_string(V0_SOURCE_NAME_COL).map(|s| s.to_string()));
            block_record.set_byte(V3_FLAGS_COL, flags as i8);
            block_record.set_long(V3_START_ADDR_COL, start_key);
            block_record.set_long(V3_LENGTH_COL, length);
            block_record.set_int(V3_SEGMENT_COL, segment);

            let mut sub_record = DBRecord::new(v3_sub_block_schema(), Field::Long(Some(key)));
            sub_record.set_long(SUB_PARENT_ID_COL, key);
            sub_record.set_long(SUB_LENGTH_COL, length);
            sub_record.set_long(SUB_START_OFFSET_COL, 0);

            let block_type = match rec.get_field(V0_TYPE_COL) {
                Field::Short(Some(v)) => *v,
                _ => 0,
            };
            let base_addr = rec.get_long(V0_BASE_ADDR_COL).unwrap_or(0);
            let overlay_key = if block_type == BLOCK_TYPE_BIT_MAPPED || block_type == BLOCK_TYPE_BYTE_MAPPED {
                // Mirrors `updateOverlayAddr`: re-decode/re-encode through the (single, stable in
                // this crate) address map -- see this module's docs.
                let a = addr_map.read().unwrap().decode_address(base_addr);
                addr_map.read().unwrap().get_key(&a, false)
            } else {
                base_addr
            };

            match block_type {
                t if t == BLOCK_TYPE_BIT_MAPPED => {
                    sub_record.set_byte(SUB_TYPE_COL, SUB_TYPE_BIT_MAPPED as i8);
                    sub_record.set_long(SUB_LONG_DATA2_COL, overlay_key);
                }
                t if t == BLOCK_TYPE_BYTE_MAPPED => {
                    sub_record.set_byte(SUB_TYPE_COL, SUB_TYPE_BYTE_MAPPED as i8);
                    sub_record.set_long(SUB_LONG_DATA2_COL, overlay_key);
                }
                t if t == BLOCK_TYPE_INITIALIZED => {
                    sub_record.set_byte(SUB_TYPE_COL, SUB_TYPE_BUFFER as i8);
                    sub_record.set_int(SUB_INT_DATA1_COL, buf_id);
                }
                t if t == BLOCK_TYPE_UNINITIALIZED => {
                    sub_record.set_byte(SUB_TYPE_COL, SUB_TYPE_UNINITIALIZED as i8);
                }
                other => {
                    return Err(VersionException::with_message(format!("Unknown memory block type: {other}")));
                }
            }

            parsed.push(ParsedBlock {
                block_record,
                sub_record,
                sub_type: block_type,
                buf_id,
            });
            key += 1;
        }
        Ok(parsed)
    }
}

/// Small helper so the `open` loop above can reach `handle` through the already-Arc-wrapped
/// adapter without re-borrowing `self` mutably while `blocks` is still being assembled.
fn handle_ref(adapter: &Arc<RwLock<MemoryMapDBAdapterV0>>) -> Arc<RwLock<DBHandle>> {
    adapter.read().unwrap().handle.clone()
}

impl MemoryMapDBAdapter for MemoryMapDBAdapterV0 {
    fn get_buffer(&self, buffer_id: i32) -> io::Result<Box<dyn DBBuffer>> {
        if buffer_id < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative buffer id"));
        }
        self.handle.read().unwrap().get_buffer(buffer_id)
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(V0_TABLE_NAME);
        Ok(())
    }

    fn refresh_memory(&mut self) -> io::Result<()> {
        // Mirrors Java's `refreshMemory()` doing nothing (V0 has no live table to re-scan; its
        // block list is built once, at construction).
        Ok(())
    }

    fn get_memory_blocks(&self) -> Vec<Arc<RwLock<dyn MemoryBlock>>> {
        self.blocks.clone()
    }

    fn create_initialized_block_from_stream(
        &mut self,
        _name: &str,
        _start_addr: Address,
        _source: Option<&mut dyn io::Read>,
        _length: i64,
        _flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        Err(unsupported().into())
    }

    fn create_initialized_block_from_buffer(
        &mut self,
        _name: &str,
        _start_addr: Address,
        _buf: Box<dyn DBBuffer>,
        _flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        Err(unsupported().into())
    }

    fn create_block(
        &mut self,
        _block_type: MemoryBlockType,
        _name: &str,
        _start_addr: Address,
        _length: i64,
        _mapped_address: Option<Address>,
        _initialize_bytes: bool,
        _flags: i32,
        _encoded_mapping_scheme: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        Err(unsupported().into())
    }

    fn delete_memory_block(&mut self, _block: &dyn MemoryBlock) -> io::Result<()> {
        Err(unsupported())
    }

    fn update_block_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(unsupported())
    }

    fn create_buffer(&mut self, _length: usize, _initial_value: u8) -> io::Result<Box<dyn DBBuffer>> {
        Err(unsupported())
    }

    fn get_memory_map(&self) -> Arc<RwLock<dyn Memory>> {
        self.mem_map.clone()
    }

    fn delete_sub_block(&mut self, _key: i64) -> io::Result<()> {
        Err(unsupported())
    }

    fn update_sub_block_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(unsupported())
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
        Err(unsupported())
    }

    fn create_block_from_sub_blocks(
        &mut self,
        _name: &str,
        _start_address: Address,
        _length: i64,
        _flags: i32,
        _split_blocks: Vec<Box<dyn SubMemoryBlock>>,
    ) -> io::Result<Arc<RwLock<dyn MemoryBlock>>> {
        Err(unsupported())
    }

    fn create_file_bytes_block(
        &mut self,
        _name: &str,
        _start_address: Address,
        _length: i64,
        _file_bytes: Arc<dyn FileBytes>,
        _offset: i64,
        _flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        Err(unsupported().into())
    }
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "MemoryMapDBAdapterV0 is read-only")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::mem::MemoryAccessException;

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

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn setup() -> (Arc<RwLock<DBHandle>>, Arc<RwLock<AddressMapDB>>, Arc<RwLock<dyn Memory>>) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![test_space()]);
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
        let mem_map: Arc<RwLock<dyn Memory>> = Arc::new(RwLock::new(StubMemory));
        (handle, addr_map, mem_map)
    }

    fn write_legacy_row(
        handle: &Arc<RwLock<DBHandle>>,
        addr_map: &Arc<RwLock<AddressMapDB>>,
        name: &str,
        start: i64,
        length: i64,
        block_type: i16,
        buf_id: i32,
        base_addr: i64,
        flags: (bool, bool, bool),
    ) {
        let table = {
            let mut h = handle.write().unwrap();
            h.get_table(V0_TABLE_NAME).unwrap_or_else(|| h.create_table(V0_TABLE_NAME.to_string(), v0_schema()).unwrap())
        };
        let key = table.write().unwrap().get_next_key();
        let mut rec = DBRecord::new(v0_schema(), Field::Long(Some(key)));
        rec.set_string(V0_NAME_COL, Some(name.to_string()));
        rec.set_int(V0_BUFFER_ID_COL, buf_id);
        rec.set_string(V0_COMMENTS_COL, Some("comment".to_string()));
        rec.set_string(V0_SOURCE_NAME_COL, Some("source".to_string()));
        rec.set_bool(V0_IS_READ_COL, flags.0);
        rec.set_bool(V0_IS_WRITE_COL, flags.1);
        rec.set_bool(V0_IS_EXECUTE_COL, flags.2);
        let start_addr = Address::new(test_space(), start);
        let start_key = addr_map.read().unwrap().get_key(&start_addr, true);
        rec.set_long(V0_START_ADDR_COL, start_key);
        rec.set_int(V0_LENGTH_COL, length as i32);
        rec.set_field(V0_TYPE_COL, Field::Short(Some(block_type)));
        rec.set_long(V0_BASE_ADDR_COL, base_addr);
        table.write().unwrap().put_record(rec).unwrap();
    }

    #[test]
    fn open_with_missing_table_reports_version_exception() {
        let (handle, addr_map, mem_map) = setup();
        let err = MemoryMapDBAdapterV0::open(handle, mem_map, addr_map, 0).err().unwrap();
        assert!(!err.is_upgradable());
    }

    #[test]
    fn open_parses_initialized_block_into_real_buffer_backed_memory_block() {
        let (handle, addr_map, mem_map) = setup();
        let buf_id = {
            let mut buf = handle.write().unwrap().create_buffer(4).unwrap();
            buf.put_all(0, &[1, 2, 3, 4]).unwrap();
            buf.get_id()
        };
        write_legacy_row(&handle, &addr_map, "blk", 0x1000, 4, BLOCK_TYPE_INITIALIZED, buf_id, 0, (true, true, false));

        let adapter = MemoryMapDBAdapterV0::open(handle, mem_map, addr_map, 0).unwrap();
        let blocks = adapter.read().unwrap().get_memory_blocks();
        assert_eq!(blocks.len(), 1);
        let b = blocks[0].read().unwrap();
        assert_eq!(b.get_name(), "blk");
        assert_eq!(b.get_size(), 4);
        assert!(b.is_initialized());
        let start = Address::new(test_space(), 0x1000);
        let mut out = [0u8; 4];
        assert_eq!(b.get_bytes(&start, &mut out), 4);
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn open_parses_uninitialized_block() {
        let (handle, addr_map, mem_map) = setup();
        write_legacy_row(&handle, &addr_map, "uninit", 0x2000, 8, BLOCK_TYPE_UNINITIALIZED, 0, 0, (true, false, false));
        let adapter = MemoryMapDBAdapterV0::open(handle, mem_map, addr_map, 0).unwrap();
        let blocks = adapter.read().unwrap().get_memory_blocks();
        assert_eq!(blocks.len(), 1);
        assert!(!blocks[0].read().unwrap().is_initialized());
    }

    #[test]
    fn blocks_are_sorted_by_start_address() {
        let (handle, addr_map, mem_map) = setup();
        write_legacy_row(&handle, &addr_map, "second", 0x2000, 4, BLOCK_TYPE_UNINITIALIZED, 0, 0, (true, false, false));
        write_legacy_row(&handle, &addr_map, "first", 0x1000, 4, BLOCK_TYPE_UNINITIALIZED, 0, 0, (true, false, false));
        let adapter = MemoryMapDBAdapterV0::open(handle, mem_map, addr_map, 0).unwrap();
        let blocks = adapter.read().unwrap().get_memory_blocks();
        assert_eq!(blocks[0].read().unwrap().get_name(), "first");
        assert_eq!(blocks[1].read().unwrap().get_name(), "second");
    }

    #[test]
    fn mutating_methods_are_all_unsupported() {
        let (handle, addr_map, mem_map) = setup();
        write_legacy_row(&handle, &addr_map, "blk", 0x1000, 4, BLOCK_TYPE_UNINITIALIZED, 0, 0, (true, false, false));
        let adapter = MemoryMapDBAdapterV0::open(handle, mem_map, addr_map, 0).unwrap();
        let mut a = adapter.write().unwrap();
        assert_eq!(
            a.create_initialized_block_from_stream("x", Address::new(test_space(), 0), None, 4, 0).err().unwrap().to_string().is_empty(),
            false
        );
        assert_eq!(a.create_buffer(4, 0).err().unwrap().kind(), io::ErrorKind::Unsupported);
        assert_eq!(a.delete_sub_block(0).unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(a.create_sub_block_record(0, 0, 0, 0, 0, 0).unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn wrong_schema_version_reports_version_exception() {
        let (handle, addr_map, mem_map) = setup();
        write_legacy_row(&handle, &addr_map, "blk", 0x1000, 4, BLOCK_TYPE_UNINITIALIZED, 0, 0, (true, false, false));
        // expected_version = 1 but the table was created with VERSION = 0.
        let err = MemoryMapDBAdapterV0::open(handle, mem_map, addr_map, 1).err().unwrap();
        assert!(!err.is_upgradable());
    }
}
