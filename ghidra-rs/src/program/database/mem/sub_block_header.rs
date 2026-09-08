//! Shared record-backed state factored out of the abstract Java base class
//! `ghidra.program.database.mem.SubMemoryBlock`.
//!
//! Java's `SubMemoryBlock` is an abstract class holding `protected` fields (`adapter`, `record`,
//! `subBlockOffset`, `subBlockLength`) plus several concrete (non-abstract) methods built on top
//! of them (`getParentBlockID`, `getStartingOffset`, `getLength`, `delete`, `setLength`,
//! `setParentIdAndStartingOffset`). Per this crate's "extends X is composition, not inheritance"
//! convention (see [`SubMemoryBlock`](crate::program::database::mem::sub_memory_block::SubMemoryBlock)'s
//! module docs), each concrete sub-block struct in this module holds one of these as a field
//! instead of subclassing an abstract base, and delegates the corresponding trait methods to it.
//!
//! Java reads/writes `subBlockOffset`/`subBlockLength`/the parent id via record column index
//! constants (`SUB_START_OFFSET_COL`, `SUB_LENGTH_COL`, `SUB_PARENT_ID_COL`, ...) declared on the
//! versioned `MemoryMapDBAdapterV0..V3` subclasses of
//! [`MemoryMapDBAdapter`](crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter).
//! Those constants live on `MemoryMapDBAdapterV3` specifically (Java's abstract base class and
//! `V0`/`V1`/`V2` all alias `V3`'s `SUB_*_COL`/`SUB_TYPE_*` values rather than declaring their
//! own), so this module's column layout is simply
//! [`memory_map_db_adapter_v3`](crate::program::database::mem::memory_map_db_adapter_v3)'s
//! `V3_SUB_*_COL` constants, copied here rather than imported to avoid this module depending on
//! that one: `[Parent ID: Long, Type: Byte, Length: Long, Starting Offset: Long, Source ID: Int,
//! Source Address/Offset: Long]`. This also matches the "Sub Memory Blocks" table schema
//! [`MemoryMapDB::new`](crate::program::database::mem::memory_map_db::MemoryMapDB::new) builds
//! independently (that struct still does not route block/sub-block creation through
//! `MemoryMapDBAdapter` -- see `memory_map_db_adapter.rs`'s module docs for why rewiring it is out
//! of scope), so both this module's and `MemoryMapDB::new`'s "Sub Memory Blocks" tables share one
//! column layout even though neither depends on the other for it.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::record::DBRecord;
use crate::framework::db::Field;
use crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter;

/// Column index of the owning `MemoryBlockDB`'s key. Mirrors `SUB_PARENT_ID_COL`.
pub(crate) const SUB_PARENT_ID_COL: usize = 0;
/// Column index of the sub-block type discriminant. Mirrors `SUB_TYPE_COL`.
#[allow(dead_code)]
pub(crate) const SUB_TYPE_COL: usize = 1;
/// Column index of the sub-block length. Mirrors `SUB_LENGTH_COL`.
pub(crate) const SUB_LENGTH_COL: usize = 2;
/// Column index of the sub-block's starting offset within its owning `MemoryBlockDB`. Mirrors
/// `SUB_START_OFFSET_COL`.
pub(crate) const SUB_START_OFFSET_COL: usize = 3;
/// Column index of the implementation-specific integer payload (buffer id / encoded byte mapping
/// scheme / file bytes id, depending on sub-block type). Mirrors `SUB_INT_DATA1_COL`.
pub(crate) const SUB_INT_DATA1_COL: usize = 4;
/// Column index of the implementation-specific long payload (file bytes offset / mapped address
/// key, depending on sub-block type). Mirrors `SUB_LONG_DATA2_COL`.
pub(crate) const SUB_LONG_DATA2_COL: usize = 5;

// Sub-block type discriminants, matching the real values from
// `ghidra.program.database.mem.MemoryMapDBAdapterV3` (`V3_SUB_TYPE_*`) verbatim, even though the
// versioned adapter that would actually interpret `SUB_TYPE_COL` hasn't been ported yet -- so a
// future port of that adapter can read pre-existing records without a migration.
#[allow(dead_code)]
pub(crate) const SUB_TYPE_BIT_MAPPED: u8 = 0;
pub(crate) const SUB_TYPE_BYTE_MAPPED: u8 = 1;
pub(crate) const SUB_TYPE_BUFFER: u8 = 2;
pub(crate) const SUB_TYPE_UNINITIALIZED: u8 = 3;
pub(crate) const SUB_TYPE_FILE_BYTES: u8 = 4;

/// Shared header state common to every concrete `SubMemoryBlock` implementor, mirroring
/// `SubMemoryBlock`'s protected fields and concrete methods.
pub(crate) struct SubBlockHeader {
    adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>,
    record: DBRecord,
    sub_block_offset: i64,
    sub_block_length: i64,
}

impl SubBlockHeader {
    /// Mirrors `SubMemoryBlock(MemoryMapDBAdapter, DBRecord)`: reads the starting offset and
    /// length out of `record`'s columns.
    pub(crate) fn new(adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>, record: DBRecord) -> Self {
        let sub_block_offset = record.get_long(SUB_START_OFFSET_COL).unwrap_or(0);
        let sub_block_length = record.get_long(SUB_LENGTH_COL).unwrap_or(0);
        Self {
            adapter,
            record,
            sub_block_offset,
            sub_block_length,
        }
    }

    /// Mirrors `SubMemoryBlock.getParentBlockID()`.
    pub(crate) fn get_parent_block_id(&self) -> i64 {
        self.record.get_long(SUB_PARENT_ID_COL).unwrap_or(0)
    }

    /// Mirrors `SubMemoryBlock.getStartingOffset()`.
    pub(crate) fn get_starting_offset(&self) -> i64 {
        self.sub_block_offset
    }

    /// Mirrors `SubMemoryBlock.getLength()`.
    pub(crate) fn get_length(&self) -> i64 {
        self.sub_block_length
    }

    /// The underlying record's key, used to identify this sub block to the adapter (e.g. for
    /// `deleteSubBlock`). Mirrors `record.getKey()`.
    pub(crate) fn key(&self) -> i64 {
        match self.record.get_key() {
            Field::Long(Some(key)) => *key,
            _ => 0,
        }
    }

    /// Mirrors `SubMemoryBlock.delete()`.
    pub(crate) fn delete(&mut self) -> io::Result<()> {
        let key = self.key();
        self.adapter.write().unwrap().delete_sub_block(key)
    }

    /// Mirrors `SubMemoryBlock.setLength(long)`.
    pub(crate) fn set_length(&mut self, length: i64) -> io::Result<()> {
        self.sub_block_length = length;
        self.record.set_long(SUB_LENGTH_COL, length);
        self.adapter.write().unwrap().update_sub_block_record(&self.record)
    }

    /// Mirrors `SubMemoryBlock.setParentIdAndStartingOffset(long, long)`.
    pub(crate) fn set_parent_id_and_starting_offset(&mut self, key: i64, starting_offset: i64) -> io::Result<()> {
        self.sub_block_offset = starting_offset;
        self.record.set_long(SUB_PARENT_ID_COL, key);
        self.record.set_long(SUB_START_OFFSET_COL, starting_offset);
        self.adapter.write().unwrap().update_sub_block_record(&self.record)
    }

    pub(crate) fn adapter(&self) -> &Arc<RwLock<dyn MemoryMapDBAdapter>> {
        &self.adapter
    }

    /// Kept for parity with `SubBlockHeader::adapter`/Java's `protected DBRecord record` field,
    /// available to any future concrete `SubMemoryBlock` implementor that needs direct record
    /// access (e.g. for a column this crate's shared header doesn't otherwise expose).
    #[allow(dead_code)]
    pub(crate) fn record(&self) -> &DBRecord {
        &self.record
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test scaffolding for the concrete `SubMemoryBlock` implementors' unit tests.

    use super::*;
    use crate::framework::db::{DBBuffer, DBHandle, FieldType, Schema};
    use crate::program::database::mem::sub_memory_block::SubMemoryBlock;
    use crate::program::model::address::Address;
    use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock, MemoryBlockType};
    use std::collections::HashMap;
    use std::io::Read;

    pub(crate) fn sub_block_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            3,
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

    /// Builds a sub-block `DBRecord` with the given key/offset/length/data1/data2, matching what
    /// [`MockAdapter::create_sub_block_record`] produces.
    pub(crate) fn make_record(key: i64, parent_id: i64, starting_offset: i64, length: i64, data1: i32, data2: i64) -> DBRecord {
        let mut record = DBRecord::new(sub_block_schema(), Field::Long(Some(key)));
        record.set_long(SUB_PARENT_ID_COL, parent_id);
        record.set_long(SUB_LENGTH_COL, length);
        record.set_long(SUB_START_OFFSET_COL, starting_offset);
        record.set_int(SUB_INT_DATA1_COL, data1);
        record.set_long(SUB_LONG_DATA2_COL, data2);
        let _ = data2; // silence unused warning if a future column layout drops this
        record
    }

    /// Minimal in-memory `DBBuffer`, shared by every sub-block test module that needs one.
    pub(crate) struct MockBuffer {
        pub(crate) id: i32,
        pub(crate) data: Vec<u8>,
    }

    impl DBBuffer for MockBuffer {
        fn split(&mut self, offset: usize) -> io::Result<Box<dyn DBBuffer>> {
            let tail = self.data.split_off(offset);
            Ok(Box::new(MockBuffer { id: self.id + 1, data: tail }))
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
            self.data
                .get(offset)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "out of bounds"))
        }
        fn get(&self, offset: usize, data: &mut [u8], data_offset: usize, length: usize) -> io::Result<()> {
            if offset + length > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "out of bounds"));
            }
            data[data_offset..data_offset + length].copy_from_slice(&self.data[offset..offset + length]);
            Ok(())
        }
        fn fill_from_reader(&mut self, reader: &mut dyn Read) -> io::Result<()> {
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
            if offset + length > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "out of bounds"));
            }
            self.data[offset..offset + length].copy_from_slice(&bytes[data_offset..data_offset + length]);
            Ok(())
        }
        fn put_byte(&mut self, offset: usize, b: u8) -> io::Result<()> {
            if offset >= self.data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "out of bounds"));
            }
            self.data[offset] = b;
            Ok(())
        }
        fn delete(&mut self) -> io::Result<()> {
            self.data.clear();
            Ok(())
        }
    }

    pub(crate) struct MockMemory {
        pub(crate) big_endian: bool,
        pub(crate) base: i64,
        pub(crate) data: Vec<u8>,
    }

    impl MockMemory {
        pub(crate) fn new(base: i64, data: Vec<u8>) -> Self {
            Self { big_endian: false, base, data }
        }
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let idx = (addr.offset() - self.base) as usize;
            self.data
                .get(idx)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of range"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let idx = (addr.offset() - self.base) as usize;
            let available = self.data.len().saturating_sub(idx);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.data[idx..idx + n]);
            n
        }
        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let idx = (addr.offset() - self.base) as usize;
            if idx + source.len() > self.data.len() {
                return Err(MemoryAccessException::new("out of range"));
            }
            self.data[idx..idx + source.len()].copy_from_slice(source);
            Ok(())
        }
    }

    /// A minimal `MemoryMapDBAdapter` used by the concrete `SubMemoryBlock` implementors' tests,
    /// standing in for a real DB-backed versioned adapter.
    pub(crate) struct MockAdapter {
        pub(crate) next_key: i64,
        pub(crate) next_buffer_id: i32,
        pub(crate) buffers: HashMap<i32, Vec<u8>>,
        pub(crate) deleted_sub_blocks: Vec<i64>,
        pub(crate) updated_records: Vec<DBRecord>,
        pub(crate) memory: Arc<RwLock<dyn Memory>>,
    }

    impl MockAdapter {
        pub(crate) fn new() -> Self {
            Self {
                next_key: 100,
                next_buffer_id: 0,
                buffers: HashMap::new(),
                deleted_sub_blocks: Vec::new(),
                updated_records: Vec::new(),
                memory: Arc::new(RwLock::new(MockMemory::new(0, vec![0; 64]))),
            }
        }

        pub(crate) fn with_memory(memory: Arc<RwLock<dyn Memory>>) -> Self {
            let mut adapter = Self::new();
            adapter.memory = memory;
            adapter
        }

        pub(crate) fn register_buffer(&mut self, data: Vec<u8>) -> i32 {
            let id = self.next_buffer_id;
            self.next_buffer_id += 1;
            self.buffers.insert(id, data);
            id
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
            Ok(())
        }

        fn refresh_memory(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn get_memory_blocks(&self) -> Vec<Arc<RwLock<dyn MemoryBlock>>> {
            Vec::new()
        }

        fn create_initialized_block_from_stream(
            &mut self,
            _name: &str,
            _start_addr: Address,
            _source: Option<&mut dyn Read>,
            _length: i64,
            _flags: i32,
        ) -> Result<Arc<RwLock<dyn MemoryBlock>>, crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapterError> {
            unimplemented!("not exercised by SubMemoryBlock tests")
        }

        fn create_initialized_block_from_buffer(
            &mut self,
            _name: &str,
            _start_addr: Address,
            _buf: Box<dyn DBBuffer>,
            _flags: i32,
        ) -> Result<Arc<RwLock<dyn MemoryBlock>>, crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapterError> {
            unimplemented!("not exercised by SubMemoryBlock tests")
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
        ) -> Result<Arc<RwLock<dyn MemoryBlock>>, crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapterError> {
            unimplemented!("not exercised by SubMemoryBlock tests")
        }

        fn delete_memory_block(&mut self, _block: &dyn MemoryBlock) -> io::Result<()> {
            Ok(())
        }

        fn update_block_record(&mut self, _record: &DBRecord) -> io::Result<()> {
            Ok(())
        }

        fn create_buffer(&mut self, length: usize, initial_value: u8) -> io::Result<Box<dyn DBBuffer>> {
            let id = self.next_buffer_id;
            self.next_buffer_id += 1;
            let data = vec![initial_value; length];
            self.buffers.insert(id, data.clone());
            Ok(Box::new(MockBuffer { id, data }))
        }

        fn get_memory_map(&self) -> Arc<RwLock<dyn Memory>> {
            self.memory.clone()
        }

        fn delete_sub_block(&mut self, key: i64) -> io::Result<()> {
            self.deleted_sub_blocks.push(key);
            Ok(())
        }

        fn update_sub_block_record(&mut self, record: &DBRecord) -> io::Result<()> {
            self.updated_records.push(record.clone());
            Ok(())
        }

        fn create_sub_block_record(
            &mut self,
            mem_block_id: i64,
            starting_offset: i64,
            length: i64,
            _sub_type: u8,
            data1: i32,
            data2: i64,
        ) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            Ok(make_record(key, mem_block_id, starting_offset, length, data1, data2))
        }

        fn create_block_from_sub_blocks(
            &mut self,
            _name: &str,
            _start_address: Address,
            _length: i64,
            _flags: i32,
            _split_blocks: Vec<Box<dyn SubMemoryBlock>>,
        ) -> io::Result<Arc<RwLock<dyn MemoryBlock>>> {
            unimplemented!("not exercised by SubMemoryBlock tests")
        }

        fn create_file_bytes_block(
            &mut self,
            _name: &str,
            _start_address: Address,
            _length: i64,
            _file_bytes: Arc<dyn crate::program::database::mem::file_bytes::FileBytes>,
            _offset: i64,
            _flags: i32,
        ) -> Result<Arc<RwLock<dyn MemoryBlock>>, crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapterError> {
            unimplemented!("not exercised by SubMemoryBlock tests")
        }
    }

    pub(crate) fn test_addr(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }
}
