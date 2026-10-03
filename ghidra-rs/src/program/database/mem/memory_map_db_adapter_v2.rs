//! Port of the class `ghidra.program.database.mem.MemoryMapDBAdapterV2`.
//!
//! Middle historical schema, read-only (same "every mutating method is unsupported" shape as
//! `MemoryMapDBAdapterV0`/`V1` -- see that module's docs for why there is no separate
//! `MemoryMapDBAdapterV1` type but there *is* a separate `V2` one here: V2's on-disk column layout
//! is genuinely different from V0/V1's, unlike V1, which is byte-for-byte the same layout as V0
//! plus one column). Reuses the same table name ("Memory Blocks") V3 uses -- the real, intentional
//! naming collision V3's own constructor comment calls out ("the table name changed going from V1
//! to V2"), disambiguated purely by the table's stored schema version.
//!
//! Uses the same two-phase (`open` parses into an adapter-independent `ParsedBlock` list, then
//! wraps in a real `Arc` and builds sub blocks against it) construction strategy as
//! `MemoryMapDBAdapterV0` -- see that module's docs for why, and why it differs from
//! `MemoryMapDBAdapterV3`'s `Arc::new_cyclic` approach.

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
    v3_block_schema, v3_sub_block_schema, TABLE_NAME, V3_COMMENTS_COL, V3_FLAGS_COL, V3_LENGTH_COL, V3_NAME_COL,
    V3_SEGMENT_COL, V3_SOURCE_COL, V3_START_ADDR_COL,
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

/// Schema version. Mirrors `MemoryMapDBAdapterV2.V2_VERSION`.
pub const V2_VERSION: i32 = 2;

const V2_NAME_COL: usize = 0;
const V2_COMMENTS_COL: usize = 1;
const V2_SOURCE_COL: usize = 2;
const V2_PERMISSIONS_COL: usize = 3;
const V2_START_ADDR_COL: usize = 4;
const V2_BLOCK_TYPE_COL: usize = 5;
const V2_OVERLAY_ADDR_COL: usize = 6;
const V2_LENGTH_COL: usize = 7;
const V2_CHAIN_BUF_COL: usize = 8;
const V2_SEGMENT_COL: usize = 9;

const BLOCK_TYPE_INITIALIZED: i16 = 0;
const BLOCK_TYPE_UNINITIALIZED: i16 = 1;
const BLOCK_TYPE_BIT_MAPPED: i16 = 2;
const BLOCK_TYPE_BYTE_MAPPED: i16 = 4;

/// Mirrors the commented-out V2 `BLOCK_SCHEMA` documented in Java's source.
pub(crate) fn v2_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        V2_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::String, // 0 Name
            FieldType::String, // 1 Comments
            FieldType::String, // 2 Source Name
            FieldType::Byte,   // 3 Permissions
            FieldType::Long,   // 4 Start Address
            FieldType::Short,  // 5 Block Type
            FieldType::Long,   // 6 Overlay Address
            FieldType::Long,   // 7 Length
            FieldType::Int,    // 8 Chain Buffer ID
            FieldType::Int,    // 9 Segment
        ],
        vec![
            "Name".to_string(),
            "Comments".to_string(),
            "Source Name".to_string(),
            "Permissions".to_string(),
            "Start Address".to_string(),
            "Block Type".to_string(),
            "Overlay Address".to_string(),
            "Length".to_string(),
            "Chain Buffer ID".to_string(),
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

/// MemoryMap adapter for version 2: a middle historical schema, read-only. Mirrors
/// `ghidra.program.database.mem.MemoryMapDBAdapterV2`.
pub struct MemoryMapDBAdapterV2 {
    handle: Arc<RwLock<DBHandle>>,
    mem_map: Arc<RwLock<dyn Memory>>,
    blocks: Vec<Arc<RwLock<dyn MemoryBlock>>>,
}

impl MemoryMapDBAdapterV2 {
    /// Opens the legacy "Memory Blocks" table as schema version 2. Mirrors
    /// `MemoryMapDBAdapterV2(DBHandle, MemoryMapDB)`.
    ///
    /// # Errors
    /// Returns a [`VersionException`] if the table is missing or its schema version does not
    /// match [`V2_VERSION`].
    pub fn open(
        handle: Arc<RwLock<DBHandle>>,
        mem_map: Arc<RwLock<dyn Memory>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
    ) -> Result<Arc<RwLock<Self>>, VersionException> {
        let parsed = Self::parse(&handle, &addr_map)?;

        let adapter = Arc::new(RwLock::new(Self {
            handle: handle.clone(),
            mem_map,
            blocks: Vec::new(),
        }));

        let mut built: Vec<Arc<RwLock<dyn MemoryBlock>>> = Vec::with_capacity(parsed.len());
        for p in parsed {
            let trait_adapter: Arc<RwLock<dyn MemoryMapDBAdapter>> = adapter.clone();
            let sub_block: Box<dyn SubMemoryBlock> = match p.sub_type {
                t if t == BLOCK_TYPE_BIT_MAPPED => {
                    let mapped = addr_map.read().unwrap().decode_address(p.sub_record.get_long(SUB_LONG_DATA2_COL).unwrap_or(0));
                    let mem_map = adapter.read().unwrap().mem_map.clone();
                    Box::new(BitMappedSubMemoryBlock::from_parts(trait_adapter, p.sub_record, mem_map, mapped))
                }
                t if t == BLOCK_TYPE_BYTE_MAPPED => {
                    let mapped = addr_map.read().unwrap().decode_address(p.sub_record.get_long(SUB_LONG_DATA2_COL).unwrap_or(0));
                    let mem_map = adapter.read().unwrap().mem_map.clone();
                    ByteMappedSubMemoryBlock::from_parts(trait_adapter, p.sub_record, mem_map, mapped)
                        .map(|b| Box::new(b) as Box<dyn SubMemoryBlock>)
                        .map_err(|e| VersionException::with_message(e.to_string()))?
                }
                t if t == BLOCK_TYPE_INITIALIZED => {
                    let h = adapter.read().unwrap().handle.clone();
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

    fn parse(handle: &Arc<RwLock<DBHandle>>, addr_map: &Arc<RwLock<AddressMapDB>>) -> Result<Vec<ParsedBlock>, VersionException> {
        let table = handle
            .read()
            .unwrap()
            .get_table(TABLE_NAME)
            .ok_or_else(|| VersionException::with_message("Memory Block table not found"))?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != V2_VERSION {
            return Err(VersionException::with_message(format!(
                "Memory Block table: Expected Version {V2_VERSION}, got {version}"
            )));
        }

        let mut parsed = Vec::new();
        let table_ref = table.read().unwrap();
        let mut it = table_ref
            .get_record_iterator()
            .map_err(|e| VersionException::with_message(e.to_string()))?;
        let mut key = 0i64;
        while let Some(rec) = it.next().map_err(|e| VersionException::with_message(e.to_string()))? {
            let flags = rec.get_byte(V2_PERMISSIONS_COL).unwrap_or(0) as i32;
            let start_addr = rec.get_long(V2_START_ADDR_COL).unwrap_or(0);
            let length = rec.get_long(V2_LENGTH_COL).unwrap_or(0);
            let buf_id = rec.get_int(V2_CHAIN_BUF_COL).unwrap_or(0);
            let segment = rec.get_int(V2_SEGMENT_COL).unwrap_or(0);

            let mut block_record = DBRecord::new(v3_block_schema(), Field::Long(Some(key)));
            block_record.set_string(V3_NAME_COL, rec.get_string(V2_NAME_COL).map(|s| s.to_string()));
            block_record.set_string(V3_COMMENTS_COL, rec.get_string(V2_COMMENTS_COL).map(|s| s.to_string()));
            block_record.set_string(V3_SOURCE_COL, rec.get_string(V2_SOURCE_COL).map(|s| s.to_string()));
            block_record.set_byte(V3_FLAGS_COL, flags as i8);
            block_record.set_long(V3_START_ADDR_COL, start_addr);
            block_record.set_long(V3_LENGTH_COL, length);
            block_record.set_int(V3_SEGMENT_COL, segment);

            let mut sub_record = DBRecord::new(v3_sub_block_schema(), Field::Long(Some(key)));
            sub_record.set_long(SUB_PARENT_ID_COL, key);
            sub_record.set_long(SUB_LENGTH_COL, length);
            sub_record.set_long(SUB_START_OFFSET_COL, 0);

            let block_type = match rec.get_field(V2_BLOCK_TYPE_COL) {
                Field::Short(Some(v)) => *v,
                _ => 0,
            };
            let overlay_addr = rec.get_long(V2_OVERLAY_ADDR_COL).unwrap_or(0);
            let _ = addr_map;

            match block_type {
                t if t == BLOCK_TYPE_BIT_MAPPED => {
                    sub_record.set_byte(SUB_TYPE_COL, SUB_TYPE_BIT_MAPPED as i8);
                    sub_record.set_long(SUB_LONG_DATA2_COL, overlay_addr);
                }
                t if t == BLOCK_TYPE_BYTE_MAPPED => {
                    sub_record.set_byte(SUB_TYPE_COL, SUB_TYPE_BYTE_MAPPED as i8);
                    sub_record.set_long(SUB_LONG_DATA2_COL, overlay_addr);
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

impl MemoryMapDBAdapter for MemoryMapDBAdapterV2 {
    fn get_buffer(&self, buffer_id: i32) -> io::Result<Box<dyn DBBuffer>> {
        if buffer_id < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative buffer id"));
        }
        self.handle.read().unwrap().get_buffer(buffer_id)
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        handle.delete_table(TABLE_NAME);
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
    io::Error::new(io::ErrorKind::Unsupported, "MemoryMapDBAdapterV2 is read-only")
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
    ) {
        let table = {
            let mut h = handle.write().unwrap();
            h.get_table(TABLE_NAME).unwrap_or_else(|| h.create_table(TABLE_NAME.to_string(), v2_schema()).unwrap())
        };
        let key = table.write().unwrap().get_next_key();
        let mut rec = DBRecord::new(v2_schema(), Field::Long(Some(key)));
        rec.set_string(V2_NAME_COL, Some(name.to_string()));
        rec.set_string(V2_COMMENTS_COL, Some("c".to_string()));
        rec.set_string(V2_SOURCE_COL, Some("s".to_string()));
        rec.set_byte(V2_PERMISSIONS_COL, 7);
        let start_addr = Address::new(test_space(), start);
        let start_key = addr_map.read().unwrap().get_key(&start_addr, true);
        rec.set_long(V2_START_ADDR_COL, start_key);
        rec.set_field(V2_BLOCK_TYPE_COL, Field::Short(Some(block_type)));
        rec.set_long(V2_OVERLAY_ADDR_COL, 0);
        rec.set_long(V2_LENGTH_COL, length);
        rec.set_int(V2_CHAIN_BUF_COL, buf_id);
        rec.set_int(V2_SEGMENT_COL, 0);
        table.write().unwrap().put_record(rec).unwrap();
    }

    #[test]
    fn open_with_missing_table_reports_version_exception() {
        let (handle, addr_map, mem_map) = setup();
        assert!(MemoryMapDBAdapterV2::open(handle, mem_map, addr_map).is_err());
    }

    #[test]
    fn open_parses_initialized_block_into_real_buffer_backed_memory_block() {
        let (handle, addr_map, mem_map) = setup();
        let buf_id = {
            let mut buf = handle.write().unwrap().create_buffer(3).unwrap();
            buf.put_all(0, &[7, 8, 9]).unwrap();
            buf.get_id()
        };
        write_legacy_row(&handle, &addr_map, "blk", 0x1000, 3, BLOCK_TYPE_INITIALIZED, buf_id);

        let adapter = MemoryMapDBAdapterV2::open(handle, mem_map, addr_map).unwrap();
        let blocks = adapter.read().unwrap().get_memory_blocks();
        assert_eq!(blocks.len(), 1);
        let b = blocks[0].read().unwrap();
        assert_eq!(b.get_name(), "blk");
        let start = Address::new(test_space(), 0x1000);
        let mut out = [0u8; 3];
        assert_eq!(b.get_bytes(&start, &mut out), 3);
        assert_eq!(out, [7, 8, 9]);
    }

    #[test]
    fn open_parses_uninitialized_block() {
        let (handle, addr_map, mem_map) = setup();
        write_legacy_row(&handle, &addr_map, "uninit", 0x2000, 8, BLOCK_TYPE_UNINITIALIZED, 0);
        let adapter = MemoryMapDBAdapterV2::open(handle, mem_map, addr_map).unwrap();
        let blocks = adapter.read().unwrap().get_memory_blocks();
        assert_eq!(blocks.len(), 1);
        assert!(!blocks[0].read().unwrap().is_initialized());
    }

    #[test]
    fn mutating_methods_are_all_unsupported() {
        let (handle, addr_map, mem_map) = setup();
        write_legacy_row(&handle, &addr_map, "blk", 0x1000, 4, BLOCK_TYPE_UNINITIALIZED, 0);
        let adapter = MemoryMapDBAdapterV2::open(handle, mem_map, addr_map).unwrap();
        let mut a = adapter.write().unwrap();
        assert_eq!(a.create_buffer(4, 0).err().unwrap().kind(), io::ErrorKind::Unsupported);
        assert_eq!(a.delete_sub_block(0).unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(a.create_sub_block_record(0, 0, 0, 0, 0, 0).unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn wrong_schema_version_reports_version_exception() {
        let (handle, addr_map, mem_map) = setup();
        // Build a table under the same name but with V3's (different) schema/version -- V2::open
        // must reject it rather than misreading V3-shaped columns as V2 ones.
        {
            let mut h = handle.write().unwrap();
            h.create_table(TABLE_NAME.to_string(), v3_block_schema()).unwrap();
        }
        assert!(MemoryMapDBAdapterV2::open(handle, mem_map, addr_map).is_err());
    }
}
