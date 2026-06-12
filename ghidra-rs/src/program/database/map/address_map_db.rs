use crate::framework::db::{DBHandle, FieldType, Schema, Table};
use crate::program::model::address::{Address, AddressFactory};
use std::io;
use std::sync::{Arc, RwLock};

pub const ADDR_MAP_TABLE_NAME: &str = "Address Map";

pub struct AddressMapDB {
    db_handle: Arc<RwLock<DBHandle>>,
    addr_factory: Arc<dyn AddressFactory>,
    table: Arc<RwLock<Table>>,
}

impl AddressMapDB {
    pub fn new(
        db_handle: Arc<RwLock<DBHandle>>,
        addr_factory: Arc<dyn AddressFactory>,
    ) -> io::Result<Self> {
        let schema = Schema::new(
            0,
            FieldType::Long,
            "ID".to_string(),
            vec![
                FieldType::Int,  // Space ID
                FieldType::Long, // Offset
            ],
            vec!["Space ID".to_string(), "Offset".to_string()],
            vec![],
        );

        let table = {
            let mut handle = db_handle.write().unwrap();
            handle.create_table(ADDR_MAP_TABLE_NAME.to_string(), Arc::new(schema))?
        };

        Ok(Self {
            db_handle,
            addr_factory,
            table,
        })
    }

    pub fn get_key(&self, addr: &Address, _create: bool) -> i64 {
        let space_id = addr.space().space_id() as i64;
        let offset = addr.offset() as i64;
        (space_id << 48) | (offset & 0x0000FFFFFFFFFFFF)
    }

    pub fn decode_address(&self, key: i64) -> Address {
        let space_id = (key >> 48) as i32;
        let offset = key & 0x0000FFFFFFFFFFFF;
        let space = self
            .addr_factory
            .get_address_space_by_id(space_id)
            .expect("Invalid space ID in key");
        Address::new(space, offset)
    }
}
