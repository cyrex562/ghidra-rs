//! Port of the class `ghidra.program.database.mem.MemoryBlockDB`.
//!
//! This struct originally only wrapped a `DBRecord` and an `AddressMapDB`, with its byte-access
//! methods (`get_byte`/`get_bytes`/`set_bytes`) left as `TODO` stubs pending the versioned
//! `MemoryMapDBAdapter` implementations that actually own sub-block construction. Those adapters
//! (`MemoryMapDBAdapterV0`..`V3`) have now been ported, so this struct gained an optional
//! `sub_blocks` list (mirroring Java's `private List<SubMemoryBlock> subBlocks`) that the adapters
//! populate via [`with_sub_blocks`](MemoryBlockDB::with_sub_blocks); real byte access delegates to
//! them exactly as Java's `MemoryBlockDB.getByte`/`getBytes`/`putBytes` do (linear scan to find the
//! containing sub block rather than Java's binary search over a sorted list -- an intentional
//! simplification given the small sub-block counts actually exercised, not a faithfully-reproduced
//! Java behavior).
//!
//! The original two-argument [`new`](MemoryBlockDB::new) constructor is kept unchanged (and its
//! `Ok(0)`/`0`/`Ok(())` stub behavior preserved when no sub blocks are supplied) for whatever
//! callers already depend on it -- currently only
//! [`MemoryMapDB::create_block`](crate::program::database::mem::memory_map_db::MemoryMapDB::create_block),
//! which does not yet wire in real sub blocks.

use crate::framework::db::DBRecord;
use crate::program::database::map::AddressMapDB;
use crate::program::database::mem::sub_memory_block::SubMemoryBlock;
use crate::program::model::address::Address;
use crate::program::model::mem::{MemoryAccessException, MemoryBlock};
use std::sync::{Arc, RwLock};

pub struct MemoryBlockDB {
    record: DBRecord,
    addr_map: Arc<RwLock<AddressMapDB>>,
    sub_blocks: Vec<Box<dyn SubMemoryBlock>>,
}

impl MemoryBlockDB {
    pub fn new(record: DBRecord, addr_map: Arc<RwLock<AddressMapDB>>) -> Self {
        Self {
            record,
            addr_map,
            sub_blocks: Vec::new(),
        }
    }

    /// Constructs a `MemoryBlockDB` backed by real sub blocks, so `get_byte`/`get_bytes`/
    /// `set_bytes`/`is_initialized` delegate to them instead of using the legacy stub behavior.
    /// Mirrors `MemoryBlockDB(MemoryMapDBAdapter, DBRecord, List<SubMemoryBlock>)`.
    pub fn with_sub_blocks(
        record: DBRecord,
        addr_map: Arc<RwLock<AddressMapDB>>,
        sub_blocks: Vec<Box<dyn SubMemoryBlock>>,
    ) -> Self {
        Self {
            record,
            addr_map,
            sub_blocks,
        }
    }

    /// The offset of `addr` relative to this block's start address, or `None` if `addr` is not
    /// contained within `[start, end]`. Mirrors `MemoryBlockDB.getBlockOffset(Address)` (minus the
    /// address-space check, since this crate's simplified `Address` model does not need it here).
    fn block_offset(&self, addr: &Address) -> Option<i64> {
        let start = self.get_start();
        let offset = addr.offset() - start.offset();
        if offset < 0 || offset as u64 >= self.get_size() {
            return None;
        }
        Some(offset)
    }

    /// Mirrors the private `getSubBlock(long)`: finds the sub block containing the given
    /// block-relative offset via linear scan (see this module's docs for why, unlike Java's binary
    /// search over a sorted list).
    fn sub_block_at(&self, offset: i64) -> Option<&dyn SubMemoryBlock> {
        self.sub_blocks
            .iter()
            .find(|sb| sb.contains(offset))
            .map(|sb| sb.as_ref())
    }

    fn sub_block_at_mut(&mut self, offset: i64) -> Option<&mut Box<dyn SubMemoryBlock>> {
        self.sub_blocks.iter_mut().find(|sb| sb.contains(offset))
    }
}

impl MemoryBlock for MemoryBlockDB {
    fn get_name(&self) -> &str {
        self.record.get_string(0).unwrap_or("")
    }

    fn get_start(&self) -> Address {
        let key = self.record.get_long(4).unwrap_or(0);
        self.addr_map.read().unwrap().decode_address(key)
    }

    fn get_end(&self) -> Address {
        let start = self.get_start();
        let size = self.get_size();
        if size == 0 {
            return start;
        }
        start.add(size as i64 - 1).unwrap_or(start.clone())
    }

    fn get_size(&self) -> u64 {
        self.record.get_long(5).unwrap_or(0) as u64
    }

    fn is_initialized(&self) -> bool {
        self.sub_blocks
            .first()
            .map(|sb| sb.is_initialized())
            .unwrap_or(true)
    }

    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
        if self.sub_blocks.is_empty() {
            // Legacy stub behavior, preserved for callers not using with_sub_blocks (see module
            // docs).
            return Ok(0);
        }
        let offset = self
            .block_offset(addr)
            .ok_or_else(|| MemoryAccessException::new(format!("Address not contained in block: {addr}")))?;
        let sub_block = self
            .sub_block_at(offset)
            .ok_or_else(|| MemoryAccessException::new("offset not contained in any sub block"))?;
        sub_block
            .get_byte(offset)
            .map_err(|e| MemoryAccessException::new(e.to_string()))
    }

    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
        if self.sub_blocks.is_empty() {
            return 0;
        }
        let Some(mut offset) = self.block_offset(addr) else {
            return 0;
        };
        let available = self.get_size() as i64 - offset;
        let len = (dest.len() as i64).min(available.max(0)) as usize;
        let mut total = 0usize;
        while total < len {
            let Some(sub_block) = self.sub_block_at(offset) else {
                break;
            };
            let n = match sub_block.get_bytes(offset, dest, total, len - total) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            total += n;
            offset += n as i64;
        }
        total
    }

    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
        if self.sub_blocks.is_empty() {
            // Legacy stub behavior, preserved for callers not using with_sub_blocks (see module
            // docs).
            return Ok(());
        }
        let mut offset = self
            .block_offset(addr)
            .ok_or_else(|| MemoryAccessException::new(format!("Address not contained in block: {addr}")))?;
        let available = self.get_size() as i64 - offset;
        let len = (source.len() as i64).min(available.max(0)) as usize;
        let mut total = 0usize;
        while total < len {
            let Some(sub_block) = self.sub_block_at_mut(offset) else {
                break;
            };
            let n = sub_block
                .put_bytes(offset, source, total, len - total)
                .map_err(|e| MemoryAccessException::new(e.to_string()))?;
            if n == 0 {
                break;
            }
            total += n;
            offset += n as i64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::database::mem::sub_block_header::test_support::{make_record, MockAdapter};
    use crate::program::database::mem::sub_memory_block::SubMemoryBlock;
    use crate::program::database::mem::uninitialized_sub_memory_block::UninitializedSubMemoryBlock;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use std::sync::{Arc, RwLock};

    fn test_addr_map(base: i64) -> Arc<RwLock<AddressMapDB>> {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let factory = DefaultAddressFactory::new(vec![space]);
        let handle = Arc::new(RwLock::new(crate::framework::db::DBHandle::new().unwrap()));
        let map = AddressMapDB::new(handle, Arc::new(factory)).unwrap();
        let _ = base;
        Arc::new(RwLock::new(map))
    }

    fn block_record(addr_map: &Arc<RwLock<AddressMapDB>>, start: i64, size: i64) -> DBRecord {
        let schema = Arc::new(Schema::new(
            3,
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
        ));
        let mut record = DBRecord::new(schema, Field::Long(Some(1)));
        record.set_string(0, Some("block1".to_string()));
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let start_addr = Address::new(space, start);
        let key = addr_map.read().unwrap().get_key(&start_addr, true);
        record.set_long(4, key);
        record.set_long(5, size);
        record
    }

    #[test]
    fn legacy_two_arg_constructor_keeps_stub_behavior() {
        let addr_map = test_addr_map(0);
        let record = block_record(&addr_map, 0x1000, 4);
        let mut block = MemoryBlockDB::new(record, addr_map.clone());
        assert!(block.is_initialized());
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        assert_eq!(block.get_byte(&addr).unwrap(), 0);
        assert_eq!(block.get_bytes(&addr, &mut [0u8; 4]), 0);
        assert!(block.set_bytes(&addr, &[1, 2, 3, 4]).is_ok());
    }

    #[test]
    fn with_sub_blocks_delegates_real_byte_access() {
        let addr_map = test_addr_map(0);
        let record = block_record(&addr_map, 0x1000, 4);

        let mut mock_adapter = MockAdapter::new();
        let buffer_id = mock_adapter.register_buffer(vec![10, 20, 30, 40]);
        let adapter: Arc<RwLock<dyn crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter>> =
            Arc::new(RwLock::new(mock_adapter));

        let sub_record = make_record(100, 1, 0, 4, buffer_id, 0);
        let sub_block: Box<dyn SubMemoryBlock> =
            Box::new(crate::program::database::mem::buffer_sub_memory_block::BufferSubMemoryBlock::new(adapter, sub_record).unwrap());

        let mut block = MemoryBlockDB::with_sub_blocks(record, addr_map, vec![sub_block]);
        assert!(block.is_initialized());

        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let base = Address::new(space, 0x1000);
        assert_eq!(block.get_byte(&base).unwrap(), 10);
        let mut out = [0u8; 4];
        assert_eq!(block.get_bytes(&base, &mut out), 4);
        assert_eq!(out, [10, 20, 30, 40]);

        block.set_bytes(&base, &[99, 98]).unwrap();
        let mut out2 = [0u8; 4];
        block.get_bytes(&base, &mut out2);
        assert_eq!(out2, [99, 98, 30, 40]);
    }

    #[test]
    fn is_initialized_reflects_first_sub_block() {
        let addr_map = test_addr_map(0);
        let record = block_record(&addr_map, 0x2000, 4);
        let adapter: Arc<RwLock<dyn crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter>> =
            Arc::new(RwLock::new(MockAdapter::new()));
        let sub_record = make_record(101, 1, 0, 4, 0, 0);
        let sub_block: Box<dyn SubMemoryBlock> = Box::new(UninitializedSubMemoryBlock::new(adapter, sub_record));
        let block = MemoryBlockDB::with_sub_blocks(record, addr_map, vec![sub_block]);
        assert!(!block.is_initialized());
    }
}
