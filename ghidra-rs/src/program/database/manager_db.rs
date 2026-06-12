use crate::program::model::address::Address;
use std::io;

pub trait ManagerDB: Send + Sync {
    fn invalidate_cache(&mut self, all: bool) -> io::Result<()>;
    fn delete_address_range(&mut self, start_addr: &Address, end_addr: &Address) -> io::Result<()>;
    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
    ) -> io::Result<()>;
}
