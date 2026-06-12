use crate::program::model::address::Address;
use crate::program::model::mem::{MemoryAccessException, MemoryBlock};
use std::sync::RwLock;

pub struct MemoryBlockImpl {
    name: String,
    start: Address,
    data: RwLock<Vec<u8>>,
}

impl MemoryBlockImpl {
    pub fn new(name: String, start: Address, size: u64, initialized: bool) -> Self {
        Self {
            name,
            start,
            data: RwLock::new(if initialized {
                vec![0; size as usize]
            } else {
                Vec::new()
            }),
        }
    }
}

impl MemoryBlock for MemoryBlockImpl {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_start(&self) -> Address {
        self.start.clone()
    }

    fn get_end(&self) -> Address {
        self.start
            .add(self.get_size() as i64 - 1)
            .unwrap_or(self.start.clone())
    }

    fn get_size(&self) -> u64 {
        self.data.read().unwrap().len() as u64
    }

    fn is_initialized(&self) -> bool {
        !self.data.read().unwrap().is_empty()
    }

    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
        if !self.is_initialized() {
            return Err(MemoryAccessException("Block is uninitialized".to_string()));
        }
        let diff = (addr.offset() - self.start.offset()) as usize;
        let data = self.data.read().unwrap();
        if diff < data.len() {
            Ok(data[diff])
        } else {
            Err(MemoryAccessException(
                "Address out of bounds for block".to_string(),
            ))
        }
    }

    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
        if !self.is_initialized() {
            return 0;
        }
        let diff = (addr.offset() - self.start.offset()) as usize;
        let data = self.data.read().unwrap();
        if diff < data.len() {
            let len = std::cmp::min(dest.len(), data.len() - diff);
            dest[..len].copy_from_slice(&data[diff..diff + len]);
            len
        } else {
            0
        }
    }

    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
        if !self.is_initialized() {
            return Err(MemoryAccessException("Block is uninitialized".to_string()));
        }
        let diff = (addr.offset() - self.start.offset()) as usize;
        let mut data = self.data.write().unwrap();
        if diff < data.len() {
            let len = std::cmp::min(source.len(), data.len() - diff);
            data[diff..diff + len].copy_from_slice(&source[..len]);
            Ok(())
        } else {
            Err(MemoryAccessException(
                "Address out of bounds for block".to_string(),
            ))
        }
    }
}
