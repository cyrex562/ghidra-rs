//! Port of the class `ghidra.program.database.mem.UninitializedSubMemoryBlock`.
//!
//! Implementation of `SubMemoryBlock` for uninitialized blocks: it has no backing byte storage
//! at all, so every read fails with a `MemoryAccessException` and every write fails the same way.
//!
//! Per this crate's "extends X is composition, not inheritance" convention, this struct holds a
//! [`SubBlockHeader`] (the Rust stand-in for `SubMemoryBlock`'s protected `adapter`/`record`/
//! `subBlockOffset`/`subBlockLength` fields and their concrete methods) instead of subclassing an
//! abstract base. See that module's docs for the record column-index convention used here.
//!
//! `get_source_info` cannot yet be implemented: Java's `SubMemoryBlock.getSourceInfo` constructs a
//! `MemoryBlockSourceInfoDB`, which has not been ported yet (the existing `MockSubMemoryBlock` in
//! `sub_memory_block.rs`'s own tests documents the same gap). Calling it here panics with a
//! precise message rather than silently returning bogus data.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::record::DBRecord;
use crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter;
use crate::program::database::mem::sub_block_header::{SubBlockHeader, SUB_TYPE_UNINITIALIZED};
use crate::program::database::mem::sub_memory_block::{SubMemoryBlock, SubMemoryBlockError};
use crate::program::model::mem::{MemoryAccessException, MemoryBlock, MemoryBlockSourceInfo};

/// Implementation of `SubMemoryBlock` for uninitialized blocks. Mirrors
/// `ghidra.program.database.mem.UninitializedSubMemoryBlock`.
pub struct UninitializedSubMemoryBlock {
    header: SubBlockHeader,
}

impl UninitializedSubMemoryBlock {
    /// Mirrors `UninitializedSubMemoryBlock(MemoryMapDBAdapter, DBRecord)`.
    pub fn new(adapter: Arc<RwLock<dyn MemoryMapDBAdapter>>, record: DBRecord) -> Self {
        Self {
            header: SubBlockHeader::new(adapter, record),
        }
    }
}

impl SubMemoryBlock for UninitializedSubMemoryBlock {
    fn is_initialized(&self) -> bool {
        false
    }

    fn get_parent_block_id(&self) -> i64 {
        self.header.get_parent_block_id()
    }

    fn get_starting_offset(&self) -> i64 {
        self.header.get_starting_offset()
    }

    fn get_length(&self) -> i64 {
        self.header.get_length()
    }

    fn get_byte(&self, mem_block_offset: i64) -> Result<u8, SubMemoryBlockError> {
        let start = self.header.get_starting_offset();
        let length = self.header.get_length();
        if mem_block_offset < start || mem_block_offset >= start + length {
            return Err(SubMemoryBlockError::IndexOutOfBounds(format!(
                "offset {mem_block_offset} is out of bounds. Should be in [{start},{})",
                start + length
            )));
        }
        Err(MemoryAccessException::new("Attempted to read from uninitialized block").into())
    }

    fn get_bytes(
        &self,
        _mem_block_offset: i64,
        _b: &mut [u8],
        _off: usize,
        _len: usize,
    ) -> Result<usize, SubMemoryBlockError> {
        Err(MemoryAccessException::new("Attempted to read from uninitialized block").into())
    }

    fn put_byte(&mut self, _mem_block_offset: i64, _b: u8) -> Result<(), SubMemoryBlockError> {
        Err(MemoryAccessException::new("Attempted to write to an uninitialized block").into())
    }

    fn put_bytes(
        &mut self,
        _mem_block_offset: i64,
        _b: &[u8],
        _off: usize,
        _len: usize,
    ) -> Result<usize, SubMemoryBlockError> {
        Err(MemoryAccessException::new("Attempted to write to an uninitialized block").into())
    }

    fn delete(&mut self) -> io::Result<()> {
        self.header.delete()
    }

    fn set_length(&mut self, length: i64) -> io::Result<()> {
        self.header.set_length(length)
    }

    fn join(&mut self, other: &mut dyn SubMemoryBlock) -> io::Result<bool> {
        if other.as_any().downcast_ref::<UninitializedSubMemoryBlock>().is_none() {
            return Ok(false);
        }
        let new_length = self.header.get_length() + other.get_length();
        let other_key = other_record_key(other);
        self.header.set_length(new_length)?;
        self.header.adapter().write().unwrap().delete_sub_block(other_key)?;
        Ok(true)
    }

    fn get_source_info(&self, _block: Arc<dyn MemoryBlock>) -> Arc<dyn MemoryBlockSourceInfo> {
        unimplemented!("source info construction requires MemoryBlockSourceInfoDB, not yet ported")
    }

    fn split(&mut self, mem_block_offset: i64) -> Result<Box<dyn SubMemoryBlock>, SubMemoryBlockError> {
        // convert from offset in block to offset in this sub block
        let offset = mem_block_offset - self.header.get_starting_offset();
        let new_length = self.header.get_length() - offset;
        self.header.set_length(offset)?;

        let new_record = self
            .header
            .adapter()
            .write()
            .unwrap()
            .create_sub_block_record(-1, 0, new_length, SUB_TYPE_UNINITIALIZED, 0, 0)?;

        Ok(Box::new(UninitializedSubMemoryBlock::new(self.header.adapter().clone(), new_record)))
    }

    fn set_parent_id_and_starting_offset(&mut self, key: i64, starting_offset: i64) -> io::Result<()> {
        self.header.set_parent_id_and_starting_offset(key, starting_offset)
    }

    fn get_description(&self) -> String {
        format!("uninit[{:#x}]", self.header.get_length())
    }

}

/// `SubMemoryBlock::join`'s `other` parameter only exposes the trait, which has no `record`
/// accessor -- Java reaches straight into `block.record.getKey()` since `join` is itself a method
/// on the abstract base class. This crate's port keeps `SubBlockHeader`/`record` private to each
/// concrete implementor, so we recover the key the same way `delete`/`uses` already do: via
/// `as_any` downcasting to the known sibling concrete type.
fn other_record_key(other: &dyn SubMemoryBlock) -> i64 {
    other
        .as_any()
        .downcast_ref::<UninitializedSubMemoryBlock>()
        .expect("join already checked the concrete type")
        .header
        .key()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::mem::sub_block_header::test_support::{make_record, MockAdapter};
    use crate::program::model::mem::MemoryBlockType;
    use std::sync::{Arc, RwLock};

    fn block(adapter: &Arc<RwLock<MockAdapter>>, key: i64, offset: i64, length: i64) -> UninitializedSubMemoryBlock {
        let record = make_record(key, 1, offset, length, 0, 0);
        UninitializedSubMemoryBlock::new(adapter.clone() as Arc<RwLock<dyn MemoryMapDBAdapter>>, record)
    }

    #[test]
    fn is_never_initialized() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let b = block(&adapter, 1, 0, 16);
        assert!(!b.is_initialized());
        assert_eq!(b.get_type(), MemoryBlockType::Default);
        assert!(!b.is_mapped());
    }

    #[test]
    fn get_byte_out_of_bounds_reports_index_error() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let b = block(&adapter, 1, 10, 4);
        let err = b.get_byte(9).unwrap_err();
        assert!(matches!(err, SubMemoryBlockError::IndexOutOfBounds(_)));
        let err = b.get_byte(14).unwrap_err();
        assert!(matches!(err, SubMemoryBlockError::IndexOutOfBounds(_)));
    }

    #[test]
    fn get_byte_in_bounds_still_reports_memory_access_error() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let b = block(&adapter, 1, 10, 4);
        for offset in 10..14 {
            let err = b.get_byte(offset).unwrap_err();
            assert!(matches!(err, SubMemoryBlockError::MemoryAccess(_)));
        }
    }

    #[test]
    fn reads_and_writes_always_fail() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let mut b = block(&adapter, 1, 0, 4);
        let mut dest = [0u8; 4];
        assert!(matches!(
            b.get_bytes(0, &mut dest, 0, 4),
            Err(SubMemoryBlockError::MemoryAccess(_))
        ));
        assert!(matches!(b.put_byte(0, 1), Err(SubMemoryBlockError::MemoryAccess(_))));
        assert!(matches!(
            b.put_bytes(0, &[1, 2], 0, 2),
            Err(SubMemoryBlockError::MemoryAccess(_))
        ));
    }

    #[test]
    fn join_merges_two_uninitialized_blocks_and_deletes_the_other() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let mut a = block(&adapter, 1, 0, 4);
        let mut other = block(&adapter, 2, 4, 6);

        let joined = a.join(&mut other).unwrap();
        assert!(joined);
        assert_eq!(a.get_length(), 10);
        assert_eq!(adapter.read().unwrap().deleted_sub_blocks, vec![2]);
    }

    /// A struct implementing `SubMemoryBlock` but not `UninitializedSubMemoryBlock` should be
    /// rejected by `join`, mirroring Java's `!(block instanceof UninitializedSubMemoryBlock)`
    /// guard.
    #[test]
    fn join_rejects_non_uninitialized_sibling() {
        struct OtherBlock;
        impl SubMemoryBlock for OtherBlock {
            fn is_initialized(&self) -> bool {
                true
            }
            fn get_parent_block_id(&self) -> i64 {
                0
            }
            fn get_starting_offset(&self) -> i64 {
                0
            }
            fn get_length(&self) -> i64 {
                0
            }
            fn get_byte(&self, _mem_block_offset: i64) -> Result<u8, SubMemoryBlockError> {
                Ok(0)
            }
            fn get_bytes(&self, _o: i64, _b: &mut [u8], _off: usize, _len: usize) -> Result<usize, SubMemoryBlockError> {
                Ok(0)
            }
            fn put_byte(&mut self, _o: i64, _b: u8) -> Result<(), SubMemoryBlockError> {
                Ok(())
            }
            fn put_bytes(&mut self, _o: i64, _b: &[u8], _off: usize, _len: usize) -> Result<usize, SubMemoryBlockError> {
                Ok(0)
            }
            fn delete(&mut self) -> io::Result<()> {
                Ok(())
            }
            fn set_length(&mut self, _length: i64) -> io::Result<()> {
                Ok(())
            }
            fn join(&mut self, _other: &mut dyn SubMemoryBlock) -> io::Result<bool> {
                Ok(false)
            }
            fn get_source_info(&self, _block: Arc<dyn MemoryBlock>) -> Arc<dyn MemoryBlockSourceInfo> {
                unimplemented!()
            }
            fn split(&mut self, _mem_block_offset: i64) -> Result<Box<dyn SubMemoryBlock>, SubMemoryBlockError> {
                unimplemented!()
            }
            fn set_parent_id_and_starting_offset(&mut self, _key: i64, _starting_offset: i64) -> io::Result<()> {
                Ok(())
            }
            fn get_description(&self) -> String {
                "other".to_string()
            }
        }

        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let mut a = block(&adapter, 1, 0, 4);
        let mut other = OtherBlock;
        assert!(!a.join(&mut other).unwrap());
        assert_eq!(a.get_length(), 4);
    }

    #[test]
    fn split_moves_back_half_into_a_new_uninitialized_block() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let mut a = block(&adapter, 1, 100, 10);

        let back = a.split(105).unwrap();
        assert_eq!(a.get_length(), 5);
        assert_eq!(back.get_length(), 5);
        assert!(!back.is_initialized());
        assert!(back.as_any().downcast_ref::<UninitializedSubMemoryBlock>().is_some());
    }

    #[test]
    fn description_reports_length_in_hex() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let b = block(&adapter, 1, 0, 0x20);
        assert_eq!(b.get_description(), "uninit[0x20]");
    }

    #[test]
    fn set_parent_id_and_starting_offset_updates_header() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let mut b = block(&adapter, 1, 0, 4);
        b.set_parent_id_and_starting_offset(42, 100).unwrap();
        assert_eq!(b.get_starting_offset(), 100);
        assert_eq!(adapter.read().unwrap().updated_records.len(), 1);
    }

    #[test]
    fn delete_calls_through_to_adapter() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let mut b = block(&adapter, 7, 0, 4);
        b.delete().unwrap();
        assert_eq!(adapter.read().unwrap().deleted_sub_blocks, vec![7]);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let adapter = Arc::new(RwLock::new(MockAdapter::new()));
        let boxed: Box<dyn SubMemoryBlock> = Box::new(block(&adapter, 1, 0, 4));
        assert!(!boxed.is_initialized());
        assert_eq!(boxed.get_description(), "uninit[0x4]");
    }
}
