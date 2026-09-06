use crate::framework::db::record::DBRecord;
use crate::framework::db::{DBHandle, Field, FieldType, Schema, Table};
use crate::program::database::map::AddressMapDB;
use crate::program::model::address::{Address, AddressRange, AddressSet};
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

    /// Associates `value` with every address in `range`, overwriting whatever value (if any) was
    /// previously associated with any address in that range.
    ///
    /// Stands in for `AddressRangeMapDB.paintRange(Address, Address, Field)`.
    pub fn paint(&mut self, range: &AddressRange, value: Field) -> io::Result<()> {
        self.clear_range(range.min_address(), range.max_address())?;

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

    /// Removes any value associations for every address in `[start, end]`. Stored ranges that
    /// only partially overlap `[start, end]` are trimmed rather than dropped entirely, keeping
    /// their surviving fragment(s) mapped to the original value.
    ///
    /// Stands in for `AddressRangeMapDB.clearRange(Address, Address)`.
    pub fn clear_range(&mut self, start: &Address, end: &Address) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let qs = addr_map.get_key(start, true);
        let qe = addr_map.get_key(end, true);

        let mut to_delete: Vec<Field> = Vec::new();
        let mut to_insert: Vec<(i64, i64, Field)> = Vec::new();

        {
            let mut it = table.get_record_iterator()?;
            while let Some(rec) = it.next()? {
                let rec_start = rec.get_key().get_long_value();
                let rec_end = rec.get_long(Self::TO_COL).unwrap();
                if rec_end < qs || rec_start > qe {
                    continue; // no overlap
                }
                to_delete.push(rec.get_key().clone());
                let value = rec.get_field(Self::VALUE_COL).clone();
                if rec_start < qs {
                    to_insert.push((rec_start, qs - 1, value.clone()));
                }
                if rec_end > qe {
                    to_insert.push((qe + 1, rec_end, value));
                }
            }
        }

        for key in to_delete {
            table.delete_record(&key)?;
        }
        for (start_key, end_key, value) in to_insert {
            let mut rec = DBRecord::new(table.get_schema(), Field::Long(Some(start_key)));
            rec.set_long(Self::TO_COL, end_key);
            rec.set_field(Self::VALUE_COL, value);
            table.put_record(rec)?;
        }

        Ok(())
    }

    /// Returns the stored `(range, value)` pairs whose ranges overlap `[start, end]`, clipped to
    /// that window, in ascending address order.
    ///
    /// Stands in for `AddressRangeMapDB.getAddressRanges(Address, Address)`.
    pub fn get_address_ranges(
        &self,
        start: &Address,
        end: &Address,
    ) -> io::Result<Vec<(AddressRange, Field)>> {
        let table = self.table.read().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let qs = addr_map.get_key(start, true);
        let qe = addr_map.get_key(end, true);

        let mut results = Vec::new();
        let mut it = table.get_record_iterator()?;
        while let Some(rec) = it.next()? {
            let rec_start = rec.get_key().get_long_value();
            let rec_end = rec.get_long(Self::TO_COL).unwrap();
            if rec_end < qs || rec_start > qe {
                continue;
            }
            let clipped_start = rec_start.max(qs);
            let clipped_end = rec_end.min(qe);
            let value = rec.get_field(Self::VALUE_COL).clone();
            let range = AddressRange::new(
                addr_map.decode_address(clipped_start),
                addr_map.decode_address(clipped_end),
            );
            results.push((range, value));
        }
        results.sort_by_key(|(range, _)| range.min_address().clone());
        Ok(results)
    }

    /// Returns the set of every address mapped to `value`.
    ///
    /// Stands in for `AddressRangeMapDB.getAddressSet(Field)`.
    pub fn get_address_set(&self, value: &Field) -> io::Result<AddressSet> {
        let table = self.table.read().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let mut set = AddressSet::new();
        let mut it = table.get_record_iterator()?;
        while let Some(rec) = it.next()? {
            if rec.get_field(Self::VALUE_COL) != value {
                continue;
            }
            let rec_start = rec.get_key().get_long_value();
            let rec_end = rec.get_long(Self::TO_COL).unwrap();
            set.add_range(
                &addr_map.decode_address(rec_start),
                &addr_map.decode_address(rec_end),
            );
        }
        Ok(set)
    }
}
