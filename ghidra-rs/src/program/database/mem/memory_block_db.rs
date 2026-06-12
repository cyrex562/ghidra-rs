use crate::framework::db::DBRecord;
use crate::program::database::map::AddressMapDB;
use crate::program::model::address::Address;
use crate::program::model::mem::{MemoryAccessException, MemoryBlock};
use std::sync::{Arc, RwLock};

pub struct MemoryBlockDB {
    record: DBRecord,
    addr_map: Arc<RwLock<AddressMapDB>>,
    // sub_blocks: Vec<SubMemoryBlock>,
}

impl MemoryBlockDB {
    pub fn new(record: DBRecord, addr_map: Arc<RwLock<AddressMapDB>>) -> Self {
        Self { record, addr_map }
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
        true
    }

    fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
        // TODO: Read from sub-blocks/buffers
        Ok(0)
    }

    fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
        // TODO: Read from sub-blocks/buffers
        0
    }

    fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
        // TODO: Write to sub-blocks/buffers
        Ok(())
    }
}
