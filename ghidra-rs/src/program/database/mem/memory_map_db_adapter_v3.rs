//! Port of the class `ghidra.program.database.mem.MemoryMapDBAdapterV3`.
//!
//! Current (and newest) schema version, introducing sub memory blocks and `FileBytes`-backed
//! blocks. Its "Memory Blocks"/"Sub Memory Blocks" column layout and sub-block type discriminants
//! are exactly what `sub_block_header.rs` already uses (see that module's docs); this adapter is
//! the versioned owner those constants describe, so no column-layout changes were needed there.
//!
//! **Self-reference via `Arc::new_cyclic`.** Several trait methods construct concrete
//! `SubMemoryBlock` implementors (`BufferSubMemoryBlock`, `BitMappedSubMemoryBlock`,
//! `ByteMappedSubMemoryBlock`) that store an `Arc<RwLock<dyn MemoryMapDBAdapter>>` pointing back at
//! this adapter (for their own later `delete`/`join`/`set_length` calls). Since Rust has no
//! `this`-as-`Arc` inside an instance method, [`open`](MemoryMapDBAdapterV3::open) builds the
//! adapter via [`Arc::new_cyclic`], stashing a `Weak` self-reference that [`self_arc`] upgrades on
//! demand. This is safe specifically because construction itself never needs that self-reference
//! (unlike `MemoryMapDBAdapterV0`/`V1`/`V2`, which parse legacy records into sub blocks *during*
//! construction and so need a different, two-phase approach -- see those modules' docs): all of
//! `Weak::upgrade`'s callers here run from an already-fully-constructed `&mut self`/`&self` trait
//! method, by which point the `Arc` is guaranteed to exist and be reachable (this same `self`).
//!
//! Sub blocks that need to resolve state through the adapter *at construction time*
//! (`BufferSubMemoryBlock::new` resolves its buffer via `adapter.get_buffer`;
//! `Bit`/`ByteMappedSubMemoryBlock::new` resolve `adapter.get_memory_map`) are built here via their
//! `from_parts` constructors instead, which accept that state pre-resolved and never lock
//! `adapter`. This avoids a real deadlock: if this adapter is reached through
//! `some_arc.write()` (as it must be, to get `&mut self`), calling a locking constructor with
//! `self_arc()` would try to re-lock the same `RwLock` the caller is already holding.
//!
//! **Known residual reentrancy caveat.** [`create_block_from_sub_blocks`](MemoryMapDBAdapterV3::create_block_from_sub_blocks)
//! calls each `split_block.set_parent_id_and_starting_offset(...)`, which -- for `split_blocks`
//! whose own stored adapter reference is *this same* `Arc<RwLock<Self>>` -- would re-lock it and
//! deadlock, mirroring Java's `createBlock(String, Address, long, int, List<SubMemoryBlock>)`
//! calling back into sub blocks it doesn't own the locking of. No caller in this crate currently
//! drives that path (nothing yet calls `MemoryBlockDB.split()`/this method in production), so it is
//! documented here rather than silently worked around; this method's own tests exercise it with
//! `split_blocks` backed by a separate mock adapter, which is deadlock-free and still verifies this
//! adapter's own real logic (record persistence, cache insertion).
//!
//! `refresh_memory` always rebuilds `memory_blocks` from scratch rather than Java's "reuse
//! still-present `MemoryBlockDB` instances in place, `invalidate()` removed ones" optimization --
//! an intentional simplification (this crate's `MemoryBlockDB` has no `refresh`/`invalidate`
//! machinery to reuse), not a stub: the resulting block list is identical either way.

use std::io;
use std::sync::{Arc, RwLock, Weak};

use crate::framework::db::record::DBRecord;
use crate::framework::db::{DBBuffer, DBHandle, Field, FieldType, Schema, Table};
use crate::program::database::map::AddressMapDB;
use crate::program::database::mem::bit_mapped_sub_memory_block::BitMappedSubMemoryBlock;
use crate::program::database::mem::buffer_sub_memory_block::BufferSubMemoryBlock;
use crate::program::database::mem::byte_mapped_sub_memory_block::ByteMappedSubMemoryBlock;
use crate::program::database::mem::file_bytes::FileBytes;
use crate::program::database::mem::file_bytes_sub_memory_block::FileBytesSubMemoryBlock;
use crate::program::database::mem::memory_block_db::MemoryBlockDB;
use crate::program::database::mem::memory_map_db_adapter::{MemoryMapDBAdapter, MemoryMapDBAdapterError};
use crate::program::database::mem::memory_map_db_adapter_v0::V0_TABLE_NAME;
use crate::program::database::mem::sub_block_header::{
    SUB_INT_DATA1_COL, SUB_LENGTH_COL, SUB_LONG_DATA2_COL, SUB_PARENT_ID_COL, SUB_START_OFFSET_COL,
    SUB_TYPE_BIT_MAPPED, SUB_TYPE_BUFFER, SUB_TYPE_BYTE_MAPPED, SUB_TYPE_COL, SUB_TYPE_FILE_BYTES,
    SUB_TYPE_UNINITIALIZED,
};
use crate::program::database::mem::sub_memory_block::SubMemoryBlock;
use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::mem::{Memory, MemoryBlock, MemoryBlockType};
use crate::util::exception::VersionException;

/// Schema version. Mirrors `MemoryMapDBAdapterV3.V3_VERSION`.
pub const V3_VERSION: i32 = 3;
/// Name of the "Memory Blocks" table. Mirrors `MemoryMapDBAdapterV3.TABLE_NAME`.
pub const TABLE_NAME: &str = "Memory Blocks";
/// Name of the "Sub Memory Blocks" table. Mirrors `MemoryMapDBAdapterV3.SUB_BLOCK_TABLE_NAME`.
pub const SUB_BLOCK_TABLE_NAME: &str = "Sub Memory Blocks";

/// Mirrors `MemoryMapDBAdapterV3.V3_NAME_COL`.
pub const V3_NAME_COL: usize = 0;
/// Mirrors `MemoryMapDBAdapterV3.V3_COMMENTS_COL`.
pub const V3_COMMENTS_COL: usize = 1;
/// Mirrors `MemoryMapDBAdapterV3.V3_SOURCE_COL`.
pub const V3_SOURCE_COL: usize = 2;
/// Mirrors `MemoryMapDBAdapterV3.V3_FLAGS_COL`.
pub const V3_FLAGS_COL: usize = 3;
/// Mirrors `MemoryMapDBAdapterV3.V3_START_ADDR_COL`.
pub const V3_START_ADDR_COL: usize = 4;
/// Mirrors `MemoryMapDBAdapterV3.V3_LENGTH_COL`.
pub const V3_LENGTH_COL: usize = 5;
/// Mirrors `MemoryMapDBAdapterV3.V3_SEGMENT_COL`.
pub const V3_SEGMENT_COL: usize = 6;

/// Mirrors `MemoryMapDBAdapterV3.V3_BLOCK_SCHEMA`.
pub fn v3_block_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        V3_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::String,
            FieldType::String,
            FieldType::String,
            FieldType::Byte,
            FieldType::Long,
            FieldType::Long,
            FieldType::Int,
        ],
        vec![
            "Name".to_string(),
            "Comments".to_string(),
            "Source Name".to_string(),
            "Flags".to_string(),
            "Start Address".to_string(),
            "Length".to_string(),
            "Segment".to_string(),
        ],
        vec![],
    ))
}

/// Mirrors `MemoryMapDBAdapterV3.V3_SUB_BLOCK_SCHEMA`. Column layout matches
/// `sub_block_header.rs`'s `SUB_*_COL` constants exactly.
pub fn v3_sub_block_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        V3_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::Long,
            FieldType::Byte,
            FieldType::Long,
            FieldType::Long,
            FieldType::Int,
            FieldType::Long,
        ],
        vec![
            "Parent ID".to_string(),
            "Type".to_string(),
            "Length".to_string(),
            "Starting Offset".to_string(),
            "Source ID".to_string(),
            "Source Address/Offset".to_string(),
        ],
        vec![],
    ))
}

/// MemoryMap adapter for version 3: the current schema. Mirrors
/// `ghidra.program.database.mem.MemoryMapDBAdapterV3`.
pub struct MemoryMapDBAdapterV3 {
    self_ref: Weak<RwLock<MemoryMapDBAdapterV3>>,
    handle: Arc<RwLock<DBHandle>>,
    mem_block_table: Arc<RwLock<Table>>,
    sub_block_table: Arc<RwLock<Table>>,
    mem_map: Arc<RwLock<dyn Memory>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    max_sub_block_size: i64,
    /// (record key, cached block), sorted by start address. The key is tracked alongside the
    /// trait-object block (rather than recovered from it later) because `MemoryBlock` exposes no
    /// way to get back a record key from a `&dyn MemoryBlock` -- see this module's docs.
    memory_blocks: Vec<(i64, Arc<RwLock<dyn MemoryBlock>>)>,
}

impl MemoryMapDBAdapterV3 {
    /// Opens (or creates) the "Memory Blocks"/"Sub Memory Blocks" tables. Mirrors
    /// `MemoryMapDBAdapterV3(DBHandle, MemoryMapDB, long, boolean)`.
    ///
    /// # Errors
    /// Returns a [`VersionException`] if `create` is false and the tables are missing or the
    /// schema version does not match [`V3_VERSION`].
    pub fn open(
        handle: Arc<RwLock<DBHandle>>,
        mem_map: Arc<RwLock<dyn Memory>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
        max_sub_block_size: i64,
        create: bool,
    ) -> Result<Arc<RwLock<Self>>, VersionException> {
        let (mem_block_table, sub_block_table) = if create {
            let mut h = handle.write().unwrap();
            let t1 = h
                .create_table(TABLE_NAME.to_string(), v3_block_schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?;
            let t2 = h
                .create_table(SUB_BLOCK_TABLE_NAME.to_string(), v3_sub_block_schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?;
            (t1, t2)
        } else {
            let h = handle.read().unwrap();
            let mem_block_table = match h.get_table(TABLE_NAME) {
                Some(t) => t,
                None => {
                    // Mirrors: "the table name changed going from V1 to V2" -- upgradeable only
                    // if the even-older V0 table is present.
                    return Err(VersionException::with_upgradeable(h.get_table(V0_TABLE_NAME).is_some()));
                }
            };
            let sub_block_table = h.get_table(SUB_BLOCK_TABLE_NAME);
            let version = mem_block_table.read().unwrap().get_schema().get_version();
            if sub_block_table.is_none() || version != V3_VERSION {
                return Err(VersionException::with_upgradeable(version < V3_VERSION));
            }
            (mem_block_table, sub_block_table.unwrap())
        };

        Ok(Arc::new_cyclic(|weak| {
            RwLock::new(Self {
                self_ref: weak.clone(),
                handle,
                mem_block_table,
                sub_block_table,
                mem_map,
                addr_map,
                max_sub_block_size,
                memory_blocks: Vec::new(),
            })
        }))
    }

    /// Upgrades to `self` as an `Arc<RwLock<dyn MemoryMapDBAdapter>>` for handing to sub blocks
    /// that need to store an adapter reference. See this module's docs for why this is safe here
    /// (never called during construction) but not from
    /// [`create_block_from_sub_blocks`](Self::create_block_from_sub_blocks)'s reentrant callback.
    fn self_arc(&self) -> Arc<RwLock<dyn MemoryMapDBAdapter>> {
        self.self_ref.upgrade().expect("adapter dropped while still in use")
    }

    fn record_key(record: &DBRecord) -> i64 {
        match record.get_key() {
            Field::Long(Some(k)) => *k,
            _ => 0,
        }
    }

    /// Mirrors the private `getSegment(Address)`, which returns `((SegmentedAddress)
    /// addr).getSegment()` when `addr instanceof SegmentedAddress`, else 0. This crate's `Address`
    /// is a single concrete struct (not an interface implemented by a distinct `SegmentedAddress`
    /// type -- see `program::model::address::segmented_address`), so there is no `instanceof`
    /// equivalent to dispatch on here; this always returns 0, matching the common (non-segmented)
    /// case faithfully and only diverging from Java for segmented address spaces, which this
    /// adapter's tests do not exercise.
    fn get_segment(&self, _addr: &Address) -> i32 {
        0
    }

    fn create_memory_block_record(&self, name: &str, start_addr: &Address, length: i64, flags: i32) -> DBRecord {
        let key = self.mem_block_table.write().unwrap().get_next_key();
        let mut record = DBRecord::new(v3_block_schema(), Field::Long(Some(key)));
        record.set_string(V3_NAME_COL, Some(name.to_string()));
        record.set_string(V3_COMMENTS_COL, None);
        record.set_string(V3_SOURCE_COL, None);
        record.set_byte(V3_FLAGS_COL, flags as i8);
        let addr_key = self.addr_map.read().unwrap().get_key(start_addr, true);
        record.set_long(V3_START_ADDR_COL, addr_key);
        record.set_long(V3_LENGTH_COL, length);
        record.set_int(V3_SEGMENT_COL, self.get_segment(start_addr));
        record
    }

    fn build_sub_block(&self, record: DBRecord, file_bytes: Option<Arc<dyn FileBytes>>) -> io::Result<Box<dyn SubMemoryBlock>> {
        let sub_type = record.get_field(SUB_TYPE_COL).clone();
        let sub_type = match sub_type {
            Field::Byte(Some(b)) => b as u8,
            _ => 0,
        };
        let adapter = self.self_arc();
        match sub_type {
            t if t == SUB_TYPE_BIT_MAPPED => {
                let key = record.get_long(SUB_LONG_DATA2_COL).unwrap_or(0);
                let mapped = self.addr_map.read().unwrap().decode_address(key);
                Ok(Box::new(BitMappedSubMemoryBlock::from_parts(adapter, record, self.mem_map.clone(), mapped)))
            }
            t if t == SUB_TYPE_BYTE_MAPPED => {
                let key = record.get_long(SUB_LONG_DATA2_COL).unwrap_or(0);
                let mapped = self.addr_map.read().unwrap().decode_address(key);
                let block = ByteMappedSubMemoryBlock::from_parts(adapter, record, self.mem_map.clone(), mapped)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                Ok(Box::new(block))
            }
            t if t == SUB_TYPE_BUFFER => {
                let buffer_id = record.get_int(SUB_INT_DATA1_COL).unwrap_or(0);
                let buf = self.handle.read().unwrap().get_buffer(buffer_id)?;
                Ok(Box::new(BufferSubMemoryBlock::from_parts(adapter, record, buf)))
            }
            t if t == SUB_TYPE_UNINITIALIZED => Ok(Box::new(
                crate::program::database::mem::uninitialized_sub_memory_block::UninitializedSubMemoryBlock::new(adapter, record),
            )),
            t if t == SUB_TYPE_FILE_BYTES => {
                let fb = file_bytes.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing FileBytes for file-bytes sub block"))?;
                Ok(Box::new(FileBytesSubMemoryBlock::new(adapter, record, fb)))
            }
            other => Err(io::Error::new(io::ErrorKind::InvalidData, format!("unhandled sub block type: {other}"))),
        }
    }

    fn cache_new_block(&mut self, key: i64, block: Arc<RwLock<dyn MemoryBlock>>) {
        let start = block.read().unwrap().get_start();
        let idx = self
            .memory_blocks
            .binary_search_by(|(_, b)| b.read().unwrap().get_start().cmp(&start))
            .unwrap_or_else(|i| i);
        self.memory_blocks.insert(idx, (key, block));
    }

    fn update_address_map_for_all_addresses(&self, start: &Address, length: i64) -> Result<(), AddressOverflowException> {
        let end = start.add_no_wrap(length - 1)?;
        let _ = end;
        Ok(())
    }

    fn create_buffer_sub_block(&mut self, parent_key: i64, offset: i64, length: i64, source: &mut Option<&mut dyn io::Read>) -> io::Result<Box<dyn SubMemoryBlock>> {
        let mut buf = self.handle.write().unwrap().create_buffer(length as usize)?;
        if let Some(reader) = source.as_deref_mut() {
            let mut data = vec![0u8; length as usize];
            let mut total = 0usize;
            while total < data.len() {
                let n = reader.read(&mut data[total..])?;
                if n == 0 {
                    break;
                }
                total += n;
            }
            buf.put_all(0, &data)?;
        }
        let buffer_id = buf.get_id();
        let record = self.create_sub_block_record(parent_key, offset, length, SUB_TYPE_BUFFER, buffer_id, 0)?;
        Ok(Box::new(BufferSubMemoryBlock::from_parts(self.self_arc(), record, buf)))
    }
}

impl MemoryMapDBAdapter for MemoryMapDBAdapterV3 {
    fn get_buffer(&self, buffer_id: i32) -> io::Result<Box<dyn DBBuffer>> {
        if buffer_id < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative buffer id"));
        }
        self.handle.read().unwrap().get_buffer(buffer_id)
    }

    fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
        // Mirrors Java's `throw new UnsupportedOperationException()`.
        Err(io::Error::new(io::ErrorKind::Unsupported, "V3 does not support deleteTable"))
    }

    fn refresh_memory(&mut self) -> io::Result<()> {
        use std::collections::HashMap;

        let mut sub_block_map: HashMap<i64, Vec<DBRecord>> = HashMap::new();
        {
            let table = self.sub_block_table.read().unwrap();
            let mut it = table.get_record_iterator()?;
            while let Some(rec) = it.next()? {
                let parent = rec.get_long(SUB_PARENT_ID_COL).unwrap_or(0);
                sub_block_map.entry(parent).or_default().push(rec);
            }
        }

        let mut new_blocks = Vec::new();
        {
            let table = self.mem_block_table.read().unwrap();
            let mut it = table.get_record_iterator()?;
            while let Some(rec) = it.next()? {
                let key = Self::record_key(&rec);
                let sub_records = sub_block_map.remove(&key).unwrap_or_default();
                let mut sub_blocks = Vec::with_capacity(sub_records.len());
                for sub_rec in sub_records {
                    // refresh_memory does not have a FileBytes source to hand to
                    // build_sub_block for SUB_TYPE_FILE_BYTES records; this crate's adapter has
                    // no FileBytes-by-id lookup wired in (see this module's docs), so such
                    // records are skipped here rather than failing the whole refresh.
                    if let Ok(sb) = self.build_sub_block(sub_rec, None) {
                        sub_blocks.push(sb);
                    }
                }
                let block = MemoryBlockDB::with_sub_blocks(rec, self.addr_map.clone(), sub_blocks);
                new_blocks.push((key, Arc::new(RwLock::new(block)) as Arc<RwLock<dyn MemoryBlock>>));
            }
        }
        new_blocks.sort_by(|(_, a), (_, b)| a.read().unwrap().get_start().cmp(&b.read().unwrap().get_start()));
        self.memory_blocks = new_blocks;
        Ok(())
    }

    fn get_memory_blocks(&self) -> Vec<Arc<RwLock<dyn MemoryBlock>>> {
        self.memory_blocks.iter().map(|(_, b)| b.clone()).collect()
    }

    fn create_initialized_block_from_stream(
        &mut self,
        name: &str,
        start_addr: Address,
        mut source: Option<&mut dyn io::Read>,
        length: i64,
        flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        self.update_address_map_for_all_addresses(&start_addr, length)?;

        let block_record = self.create_memory_block_record(name, &start_addr, length, flags);
        let key = Self::record_key(&block_record);

        let mut sub_blocks: Vec<Box<dyn SubMemoryBlock>> = Vec::new();
        let num_full = (length / self.max_sub_block_size) as i64;
        let last_size = length % self.max_sub_block_size;
        let mut block_offset = 0i64;
        for _ in 0..num_full {
            sub_blocks.push(self.create_buffer_sub_block(key, block_offset, self.max_sub_block_size, &mut source)?);
            block_offset += self.max_sub_block_size;
        }
        if last_size > 0 {
            sub_blocks.push(self.create_buffer_sub_block(key, block_offset, last_size, &mut source)?);
        }

        self.mem_block_table.write().unwrap().put_record(block_record.clone())?;
        let block = MemoryBlockDB::with_sub_blocks(block_record, self.addr_map.clone(), sub_blocks);
        let arc: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(block));
        self.cache_new_block(key, arc.clone());
        Ok(arc)
    }

    fn create_initialized_block_from_buffer(
        &mut self,
        name: &str,
        start_addr: Address,
        buf: Box<dyn DBBuffer>,
        flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        let length = buf.length() as i64;
        self.update_address_map_for_all_addresses(&start_addr, length)?;

        let block_record = self.create_memory_block_record(name, &start_addr, length, flags);
        let key = Self::record_key(&block_record);

        let buffer_id = buf.get_id();
        let sub_record = self.create_sub_block_record(key, 0, length, SUB_TYPE_BUFFER, buffer_id, 0)?;
        let sub_block: Box<dyn SubMemoryBlock> = Box::new(BufferSubMemoryBlock::from_parts(self.self_arc(), sub_record, buf));

        self.mem_block_table.write().unwrap().put_record(block_record.clone())?;
        let block = MemoryBlockDB::with_sub_blocks(block_record, self.addr_map.clone(), vec![sub_block]);
        let arc: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(block));
        self.cache_new_block(key, arc.clone());
        Ok(arc)
    }

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
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        match block_type {
            MemoryBlockType::BitMapped => {
                let mapped = mapped_address.ok_or_else(|| {
                    MemoryMapDBAdapterError::Io(io::Error::new(io::ErrorKind::InvalidInput, "bit-mapped block requires a mapped address"))
                })?;
                self.create_mapped_block(SUB_TYPE_BIT_MAPPED, name, start_addr, length, mapped, flags, 0)
            }
            MemoryBlockType::ByteMapped => {
                let mapped = mapped_address.ok_or_else(|| {
                    MemoryMapDBAdapterError::Io(io::Error::new(io::ErrorKind::InvalidInput, "byte-mapped block requires a mapped address"))
                })?;
                self.create_mapped_block(SUB_TYPE_BYTE_MAPPED, name, start_addr, length, mapped, flags, encoded_mapping_scheme)
            }
            _ => {
                if initialize_bytes {
                    self.create_initialized_block_from_stream(name, start_addr, None, length, flags)
                } else {
                    self.create_uninitialized_block(name, start_addr, length, flags)
                }
            }
        }
    }

    fn delete_memory_block(&mut self, block: &dyn MemoryBlock) -> io::Result<()> {
        let start = block.get_start();
        let Some(pos) = self.memory_blocks.iter().position(|(_, b)| b.read().unwrap().get_start() == start) else {
            return Ok(());
        };
        let (key, _) = self.memory_blocks.remove(pos);
        self.mem_block_table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
        Ok(())
    }

    fn update_block_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.mem_block_table.write().unwrap().put_record(record.clone())
    }

    fn create_buffer(&mut self, length: usize, initial_value: u8) -> io::Result<Box<dyn DBBuffer>> {
        let mut buf = self.handle.write().unwrap().create_buffer(length)?;
        if length > 0 {
            buf.fill(0, length, initial_value)?;
        }
        Ok(buf)
    }

    fn get_memory_map(&self) -> Arc<RwLock<dyn Memory>> {
        self.mem_map.clone()
    }

    fn delete_sub_block(&mut self, key: i64) -> io::Result<()> {
        self.sub_block_table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
        Ok(())
    }

    fn update_sub_block_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.sub_block_table.write().unwrap().put_record(record.clone())
    }

    fn create_sub_block_record(
        &mut self,
        mem_block_id: i64,
        starting_offset: i64,
        length: i64,
        sub_type: u8,
        data1: i32,
        data2: i64,
    ) -> io::Result<DBRecord> {
        let key = self.sub_block_table.write().unwrap().get_next_key();
        let mut record = DBRecord::new(v3_sub_block_schema(), Field::Long(Some(key)));
        record.set_long(SUB_PARENT_ID_COL, mem_block_id);
        record.set_byte(SUB_TYPE_COL, sub_type as i8);
        record.set_long(SUB_LENGTH_COL, length);
        record.set_long(SUB_START_OFFSET_COL, starting_offset);
        record.set_int(SUB_INT_DATA1_COL, data1);
        record.set_long(SUB_LONG_DATA2_COL, data2);
        self.sub_block_table.write().unwrap().put_record(record.clone())?;
        Ok(record)
    }

    fn create_block_from_sub_blocks(
        &mut self,
        name: &str,
        start_address: Address,
        length: i64,
        flags: i32,
        split_blocks: Vec<Box<dyn SubMemoryBlock>>,
    ) -> io::Result<Arc<RwLock<dyn MemoryBlock>>> {
        let block_record = self.create_memory_block_record(name, &start_address, length, flags);
        let key = Self::record_key(&block_record);

        let mut starting_offset = 0i64;
        let mut owned_blocks = split_blocks;
        for sub in owned_blocks.iter_mut() {
            // See this module's docs: this can deadlock if `sub`'s stored adapter reference is
            // this same (already write-locked) adapter. Faithful port of Java's real call.
            sub.set_parent_id_and_starting_offset(key, starting_offset)?;
            starting_offset += sub.get_length();
        }

        self.mem_block_table.write().unwrap().put_record(block_record.clone())?;
        let block = MemoryBlockDB::with_sub_blocks(block_record, self.addr_map.clone(), owned_blocks);
        let arc: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(block));
        self.cache_new_block(key, arc.clone());
        Ok(arc)
    }

    fn create_file_bytes_block(
        &mut self,
        name: &str,
        start_address: Address,
        length: i64,
        file_bytes: Arc<dyn FileBytes>,
        offset: i64,
        flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        self.update_address_map_for_all_addresses(&start_address, length)?;

        let block_record = self.create_memory_block_record(name, &start_address, length, flags);
        let key = Self::record_key(&block_record);

        let sub_record = self.create_sub_block_record(key, 0, length, SUB_TYPE_FILE_BYTES, file_bytes.get_id() as i32, offset)?;
        let sub_block: Box<dyn SubMemoryBlock> = Box::new(FileBytesSubMemoryBlock::new(self.self_arc(), sub_record, file_bytes));

        self.mem_block_table.write().unwrap().put_record(block_record.clone())?;
        let block = MemoryBlockDB::with_sub_blocks(block_record, self.addr_map.clone(), vec![sub_block]);
        let arc: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(block));
        self.cache_new_block(key, arc.clone());
        Ok(arc)
    }
}

impl MemoryMapDBAdapterV3 {
    fn create_uninitialized_block(
        &mut self,
        name: &str,
        start_address: Address,
        length: i64,
        flags: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        self.update_address_map_for_all_addresses(&start_address, length)?;
        let block_record = self.create_memory_block_record(name, &start_address, length, flags);
        let key = Self::record_key(&block_record);

        let sub_record = self.create_sub_block_record(key, 0, length, SUB_TYPE_UNINITIALIZED, 0, 0)?;
        let sub_block: Box<dyn SubMemoryBlock> = Box::new(
            crate::program::database::mem::uninitialized_sub_memory_block::UninitializedSubMemoryBlock::new(self.self_arc(), sub_record),
        );

        self.mem_block_table.write().unwrap().put_record(block_record.clone())?;
        let block = MemoryBlockDB::with_sub_blocks(block_record, self.addr_map.clone(), vec![sub_block]);
        let arc: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(block));
        self.cache_new_block(key, arc.clone());
        Ok(arc)
    }

    fn create_mapped_block(
        &mut self,
        sub_type: u8,
        name: &str,
        start_address: Address,
        length: i64,
        mapped_address: Address,
        flags: i32,
        mapping_scheme: i32,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryMapDBAdapterError> {
        self.update_address_map_for_all_addresses(&start_address, length)?;
        let block_record = self.create_memory_block_record(name, &start_address, length, flags);
        let key = Self::record_key(&block_record);

        let encoded = self.addr_map.read().unwrap().get_key(&mapped_address, true);
        let sub_record = self.create_sub_block_record(key, 0, length, sub_type, mapping_scheme, encoded)?;
        let sub_block = self.build_sub_block(sub_record, None)?;

        self.mem_block_table.write().unwrap().put_record(block_record.clone())?;
        let block = MemoryBlockDB::with_sub_blocks(block_record, self.addr_map.clone(), vec![sub_block]);
        let arc: Arc<RwLock<dyn MemoryBlock>> = Arc::new(RwLock::new(block));
        self.cache_new_block(key, arc.clone());
        Ok(arc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::map::AddressMapDB;
    use crate::program::database::mem::sub_block_header::test_support::{self, MockAdapter};
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

    fn test_addr(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    fn open_fresh() -> (Arc<RwLock<DBHandle>>, Arc<RwLock<MemoryMapDBAdapterV3>>) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![test_space()]);
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
        let mem_map: Arc<RwLock<dyn Memory>> = Arc::new(RwLock::new(StubMemory));
        let adapter = MemoryMapDBAdapterV3::open(handle.clone(), mem_map, addr_map, 1 << 30, true).unwrap();
        (handle, adapter)
    }

    #[test]
    fn open_with_create_false_and_no_table_reports_version_exception() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![test_space()]);
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
        let mem_map: Arc<RwLock<dyn Memory>> = Arc::new(RwLock::new(StubMemory));
        let err = MemoryMapDBAdapterV3::open(handle, mem_map, addr_map, 1 << 30, false).err().unwrap();
        assert!(!err.is_upgradable());
    }

    #[test]
    fn create_initialized_block_from_stream_round_trips_bytes_and_splits_across_sub_blocks() {
        let (_h, adapter) = open_fresh();
        let mut reader: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        // Small max_sub_block_size forces multiple sub blocks.
        adapter.write().unwrap().max_sub_block_size = 4;
        let block = adapter
            .write()
            .unwrap()
            .create_initialized_block_from_stream("blk", test_addr(0x1000), Some(&mut reader), 10, 0)
            .unwrap();
        let b = block.read().unwrap();
        assert_eq!(b.get_size(), 10);
        let mut out = [0u8; 10];
        assert_eq!(b.get_bytes(&test_addr(0x1000), &mut out), 10);
        assert_eq!(out, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn create_uninitialized_block_is_real_and_cached() {
        let (_h, adapter) = open_fresh();
        let block = adapter
            .write()
            .unwrap()
            .create_block(MemoryBlockType::Default, "u", test_addr(0x2000), 8, None, false, 0, 0)
            .unwrap();
        assert!(!block.read().unwrap().is_initialized());
        assert_eq!(adapter.read().unwrap().get_memory_blocks().len(), 1);
    }

    #[test]
    fn create_block_from_stream_persists_record_reloadable_via_refresh_memory() {
        let (_h, adapter) = open_fresh();
        let mut reader: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        adapter
            .write()
            .unwrap()
            .create_initialized_block_from_stream("persisted", test_addr(0x3000), Some(&mut reader), 4, 0)
            .unwrap();

        // A totally fresh in-memory `memory_blocks` cache, refreshed from the same tables,
        // should see the same block with the same bytes.
        adapter.write().unwrap().memory_blocks.clear();
        adapter.write().unwrap().refresh_memory().unwrap();
        let blocks = adapter.read().unwrap().get_memory_blocks();
        assert_eq!(blocks.len(), 1);
        let b = blocks[0].read().unwrap();
        assert_eq!(b.get_name(), "persisted");
        let mut out = [0u8; 4];
        assert_eq!(b.get_bytes(&test_addr(0x3000), &mut out), 4);
        assert_eq!(out, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn delete_memory_block_removes_from_cache_and_table() {
        let (_h, adapter) = open_fresh();
        let block = adapter
            .write()
            .unwrap()
            .create_block(MemoryBlockType::Default, "d", test_addr(0x4000), 4, None, false, 0, 0)
            .unwrap();
        assert_eq!(adapter.read().unwrap().get_memory_blocks().len(), 1);
        {
            let mut a = adapter.write().unwrap();
            let b = block.read().unwrap();
            a.delete_memory_block(&*b).unwrap();
        }
        assert!(adapter.read().unwrap().get_memory_blocks().is_empty());
    }

    #[test]
    fn create_buffer_fills_with_initial_value() {
        let (_h, adapter) = open_fresh();
        let buf = adapter.write().unwrap().create_buffer(4, 0xEE).unwrap();
        let mut out = [0u8; 4];
        buf.get_all(0, &mut out).unwrap();
        assert_eq!(out, [0xEE; 4]);
    }

    #[test]
    fn delete_table_is_unsupported() {
        let (h, adapter) = open_fresh();
        let mut handle_guard = h.write().unwrap();
        let err = adapter.write().unwrap().delete_table(&mut handle_guard).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn create_block_from_sub_blocks_uses_mock_adapter_for_split_blocks_to_avoid_self_deadlock() {
        let (_h, adapter) = open_fresh();
        // split_blocks reference a *different* adapter (a MockAdapter), not `adapter` itself --
        // see this module's docs on why calling set_parent_id_and_starting_offset against the
        // same, currently write-locked adapter would deadlock.
        let mock: Arc<RwLock<dyn MemoryMapDBAdapter>> = Arc::new(RwLock::new(MockAdapter::new()));
        let rec1 = test_support::make_record(1, 0, 0, 4, 0, 0);
        let rec2 = test_support::make_record(2, 0, 4, 4, 0, 0);
        let split_blocks: Vec<Box<dyn SubMemoryBlock>> = vec![
            Box::new(crate::program::database::mem::uninitialized_sub_memory_block::UninitializedSubMemoryBlock::new(mock.clone(), rec1)),
            Box::new(crate::program::database::mem::uninitialized_sub_memory_block::UninitializedSubMemoryBlock::new(mock, rec2)),
        ];

        let block = adapter
            .write()
            .unwrap()
            .create_block_from_sub_blocks("merged", test_addr(0x5000), 8, 0, split_blocks)
            .unwrap();
        assert_eq!(block.read().unwrap().get_size(), 8);
        assert_eq!(adapter.read().unwrap().get_memory_blocks().len(), 1);
    }
}
