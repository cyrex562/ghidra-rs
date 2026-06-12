use crate::framework::db::record::DBRecord;
use crate::framework::db::{DBHandle, Field, FieldType, Schema, Table};
use crate::program::database::map::AddressMapDB;
use crate::program::model::address::{Address, AddressRange};
use std::io;
use std::sync::{Arc, RwLock};

pub struct AddressRangeMapDB {
    _db_handle: Arc<RwLock<DBHandle>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    table: Arc<RwLock<Table>>,
}

impl AddressRangeMapDB {
    pub const TO_COL: usize = 0;
    pub const VALUE_COL: usize = 1;

    pub fn new(
        db_handle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
        table_name: String,
        value_type: FieldType,
        indexed: bool,
    ) -> io::Result<Self> {
        let schema = Schema::new(
            0,
            FieldType::Long, // Key is start address key
            "Start".to_string(),
            vec![
                FieldType::Long, // End address key
                value_type,      // Value
            ],
            vec!["End".to_string(), "Value".to_string()],
            if indexed { vec![1] } else { vec![] },
        );

        let table = {
            let mut handle = db_handle.write().unwrap();
            handle.create_table(table_name, Arc::new(schema))?
        };

        Ok(Self {
            _db_handle: db_handle,
            addr_map,
            table,
        })
    }

    pub fn paint(&mut self, range: &AddressRange, value: Field) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let start_key = addr_map.get_key(range.min_address(), true);
        let end_key = addr_map.get_key(range.max_address(), true);

        let mut rec = DBRecord::new(table.get_schema(), Field::Long(Some(start_key)));
        rec.set_long(Self::TO_COL, end_key);
        rec.set_field(Self::VALUE_COL, value);

        table.put_record(rec)?;
        Ok(())
    }

    pub fn get_value(&self, addr: &Address) -> io::Result<Option<Field>> {
        let table = self.table.read().unwrap();
        let addr_map = self.addr_map.read().unwrap();
        let key = addr_map.get_key(addr, false);

        let mut it = table.get_record_iterator()?;
        while let Some(rec) = it.next()? {
            let start = rec.get_key().get_long_value();
            let end = rec.get_long(Self::TO_COL).unwrap();
            if key >= start && key <= end {
                return Ok(Some(rec.get_field(Self::VALUE_COL).clone()));
            }
        }

        Ok(None)
    }
}
