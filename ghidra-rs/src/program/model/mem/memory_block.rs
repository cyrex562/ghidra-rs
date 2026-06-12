use crate::program::model::address::Address;
use crate::program::model::mem::MemoryAccessException;

pub trait MemoryBlock: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_start(&self) -> Address;
    fn get_end(&self) -> Address;
    fn get_size(&self) -> u64;
    fn is_initialized(&self) -> bool;

    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException>;
    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize;
    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException>;
}
