use crate::program::model::address::Address;
use crate::program::model::mem::MemoryAccessException;

pub trait Memory: Send + Sync {
    fn is_big_endian(&self) -> bool;
    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException>;
    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize;
    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException>;
}
