use crate::framework::db::{DBHandle, Field, FieldType};
use crate::program::database::map::AddressMapDB;
use crate::program::database::util::AddressRangeMapDB;
use crate::program::database::ManagerDB;
use crate::program::model::address::{Address, AddressRange};
use std::io;
use std::sync::{Arc, RwLock};

pub struct NamespaceManagerDB {
    namespace_map: AddressRangeMapDB,
}

impl NamespaceManagerDB {
    pub const NAMESPACE_MAP_NAME: &'static str = "SCOPE ADDRESSES";

    pub fn new(
        db_handle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
    ) -> io::Result<Self> {
        let namespace_map = AddressRangeMapDB::new(
            db_handle,
            addr_map,
            Self::NAMESPACE_MAP_NAME.to_string(),
            FieldType::Long, // Stores Namespace ID
            true,
        )?;

        Ok(Self { namespace_map })
    }

    pub fn get_namespace_id(&self, addr: &Address) -> io::Result<i64> {
        if let Some(field) = self.namespace_map.get_value(addr)? {
            Ok(field.get_long_value())
        } else {
            Ok(0) // Global namespace ID
        }
    }

    pub fn set_namespace_id(&mut self, range: &AddressRange, id: i64) -> io::Result<()> {
        self.namespace_map.paint(range, Field::Long(Some(id)))
    }
}

impl ManagerDB for NamespaceManagerDB {
    fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
        Ok(())
    }

    fn delete_address_range(
        &mut self,
        _start_addr: &Address,
        _end_addr: &Address,
    ) -> io::Result<()> {
        Ok(())
    }

    fn move_address_range(
        &mut self,
        _from_addr: &Address,
        _to_addr: &Address,
        _length: u64,
    ) -> io::Result<()> {
        Ok(())
    }
}
