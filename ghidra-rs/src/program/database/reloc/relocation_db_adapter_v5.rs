//! Port of `ghidra.program.database.reloc.RelocationDBAdapterV5`.
//!
//! Read-only legacy adapter. `V5`'s schema was the first to move the address out of the primary
//! key and into its own indexed `Address` column (key name `"Index"`, a plain one-up ID) --
//! everything from `V6` onward keeps that shape. Every record this adapter hands back through
//! [`RelocationDBAdapter::iterator`]/[`iterator_in_set`](RelocationDBAdapter::iterator_in_set)/
//! [`iterator_from`](RelocationDBAdapter::iterator_from) is translated on the fly into the current
//! schema via [`RelocationDbAdapterV5::adapt_record`], matching Java's `RecordIteratorAdapter`
//! wrapper (see `relocation_db_adapter.rs`'s module docs for why that wrapper itself isn't
//! separately ported). [`RelocationDBAdapter::add`] returns an `io::ErrorKind::Unsupported`
//! error, mirroring Java's `throw new UnsupportedOperationException()`.
//!
//! Like `RelocationDbAdapterV6`, this port has no secondary-index support, so record collection is
//! an eager linear scan (via [`AddressIndexPrimaryKeyIterator`]) rather than a live cursor crawl.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBFieldIterator, DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::map::{AddressIndexPrimaryKeyIterator, AddressMap};
use crate::program::database::reloc::relocation_db_adapter::{
    get_flags, RelocationDBAdapter, VecRelocationRecordIterator, ADDR_COL, BYTES_COL, FLAGS_COL,
    SYMBOL_NAME_COL, TABLE_NAME, TYPE_COL, VALUE_COL,
};
use crate::program::database::reloc::relocation_db_adapter_v6::schema;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::reloc::relocation::RelocationStatus;
use crate::util::exception::VersionException;

/// Schema version implemented by this adapter. Port of `RelocationDBAdapterV5.VERSION`.
pub const VERSION: i32 = 5;

/// Column index of a V5 relocation's address (indexed). Port of `RelocationDBAdapterV5.V5_ADDR_COL`.
pub const V5_ADDR_COL: usize = 0;
/// Column index of a V5 relocation's type. Port of `RelocationDBAdapterV5.V5_TYPE_COL`.
pub const V5_TYPE_COL: usize = 1;
/// Column index of a V5 relocation's binary-coded `long[]` value. Port of
/// `RelocationDBAdapterV5.V5_VALUE_COL`.
pub const V5_VALUE_COL: usize = 2;
/// Column index of a V5 relocation's original bytes. Port of `RelocationDBAdapterV5.V5_BYTES_COL`.
pub const V5_BYTES_COL: usize = 3;
/// Column index of a V5 relocation's symbol name. Port of
/// `RelocationDBAdapterV5.V5_SYMBOL_NAME_COL`.
pub const V5_SYMBOL_NAME_COL: usize = 4;

/// The read-only, `V5`-schema implementation of the relocations database adapter.
///
/// Port of `ghidra.program.database.reloc.RelocationDBAdapterV5`.
pub struct RelocationDbAdapterV5 {
    reloc_table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl RelocationDbAdapterV5 {
    /// Opens an existing `V5` relocations table.
    ///
    /// Port of `RelocationDBAdapterV5(DBHandle, AddressMap)`.
    ///
    /// # Errors
    /// Returns a non-upgradeable [`VersionException`] if no relocations table exists, or it
    /// exists at a schema version other than [`VERSION`].
    pub fn new(handle: &DBHandle, addr_map: Arc<dyn AddressMap>) -> Result<Self, VersionException> {
        let table = handle.get_table(TABLE_NAME).ok_or_else(VersionException::new)?;
        if table.read().unwrap().get_schema().get_version() != VERSION {
            return Err(VersionException::new());
        }
        Ok(RelocationDbAdapterV5 { reloc_table: table, addr_map })
    }

    fn collect_records(
        &self,
        set: Option<&dyn AddressSetView>,
        start: Option<&Address>,
    ) -> io::Result<Vec<DBRecord>> {
        let mut it = match start {
            Some(start) => AddressIndexPrimaryKeyIterator::new_at(
                &self.reloc_table,
                V5_ADDR_COL,
                self.addr_map.as_ref(),
                start,
                true,
            )?,
            None => AddressIndexPrimaryKeyIterator::new_over_set(
                &self.reloc_table,
                V5_ADDR_COL,
                self.addr_map.as_ref(),
                set,
                true,
            )?,
        };
        let mut records = Vec::new();
        while it.has_next()? {
            if let Some(key) = it.next()? {
                let table = self.reloc_table.read().unwrap();
                if let Some(rec) = table.get_record(&key)? {
                    records.push(self.adapt_record(rec));
                }
            }
        }
        Ok(records)
    }
}

impl RelocationDBAdapter for RelocationDbAdapterV5 {
    fn add(
        &mut self,
        _addr: &Address,
        _flags: u8,
        _type_: i32,
        _values: &[i64],
        _bytes: Option<&[u8]>,
        _symbol_name: Option<&str>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "RelocationDBAdapterV5 is read-only",
        ))
    }

    fn iterator(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(VecRelocationRecordIterator::new(self.collect_records(None, None)?)))
    }

    fn iterator_in_set(&self, set: &dyn AddressSetView) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(VecRelocationRecordIterator::new(
            self.collect_records(Some(set), None)?,
        )))
    }

    fn iterator_from(&self, start: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
        Ok(Box::new(VecRelocationRecordIterator::new(
            self.collect_records(None, Some(start))?,
        )))
    }

    fn get_record_count(&self) -> i32 {
        self.reloc_table.read().unwrap().get_record_count() as i32
    }

    fn adapt_record(&self, rec: DBRecord) -> DBRecord {
        let mut new_rec = DBRecord::new(schema(), rec.get_key().clone());
        new_rec.set_field(ADDR_COL, Field::Long(Some(rec.get_field(V5_ADDR_COL).get_long_value())));
        new_rec.set_field(FLAGS_COL, Field::Byte(Some(get_flags(RelocationStatus::Unknown, 0) as i8)));
        new_rec.set_field(TYPE_COL, Field::Int(Some(rec.get_field(V5_TYPE_COL).get_int_value())));
        new_rec.set_field(
            VALUE_COL,
            Field::Binary(rec.get_field(V5_VALUE_COL).get_binary_data().map(|b| b.to_vec())),
        );
        new_rec.set_field(
            BYTES_COL,
            Field::Binary(rec.get_field(V5_BYTES_COL).get_binary_data().map(|b| b.to_vec())),
        );
        new_rec.set_field(
            SYMBOL_NAME_COL,
            Field::String(rec.get_string(V5_SYMBOL_NAME_COL).map(|s| s.to_string())),
        );
        new_rec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use crate::program::database::reloc::relocation_db_adapter::get_status;
    use crate::program::database::reloc::test_support::IdentityAddressMap;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(IdentityAddressMap::new(space()))
    }

    fn v5_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            VERSION,
            FieldType::Long,
            "Index".to_string(),
            vec![
                FieldType::Long,
                FieldType::Int,
                FieldType::Binary,
                FieldType::Binary,
                FieldType::String,
            ],
            vec![
                "Address".to_string(),
                "Type".to_string(),
                "Values".to_string(),
                "Bytes".to_string(),
                "Symbol Name".to_string(),
            ],
            vec![],
        ))
    }

    fn make_v5_table(handle: &mut DBHandle) -> Arc<RwLock<Table>> {
        handle.create_table(TABLE_NAME.to_string(), v5_schema()).unwrap()
    }

    #[test]
    fn open_rejects_missing_table() {
        let handle = DBHandle::new().unwrap();
        assert!(RelocationDbAdapterV5::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn open_rejects_wrong_version() {
        let mut handle = DBHandle::new().unwrap();
        handle
            .create_table(
                TABLE_NAME.to_string(),
                Arc::new(Schema::new(99, FieldType::Long, "Index".to_string(), vec![], vec![], vec![])),
            )
            .unwrap();
        match RelocationDbAdapterV5::new(&handle, addr_map()) {
            Err(e) => assert!(!e.is_upgradable()),
            Ok(_) => panic!("expected VersionException"),
        }
    }

    #[test]
    fn add_is_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        make_v5_table(&mut handle);
        let mut adapter = RelocationDbAdapterV5::new(&handle, addr_map()).unwrap();
        let err = adapter.add(&space().address(0), 0, 0, &[], None, None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn adapt_record_translates_every_column_and_defaults_status_to_unknown() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_v5_table(&mut handle);
        {
            let mut t = table.write().unwrap();
            let mut rec = DBRecord::new(v5_schema(), Field::Long(Some(0)));
            rec.set_field(V5_ADDR_COL, Field::Long(Some(0x4000)));
            rec.set_field(V5_TYPE_COL, Field::Int(Some(7)));
            rec.set_field(V5_VALUE_COL, Field::Binary(Some(vec![1, 2, 3])));
            rec.set_field(V5_BYTES_COL, Field::Binary(Some(vec![0xAA])));
            rec.set_field(V5_SYMBOL_NAME_COL, Field::String(Some("sym".to_string())));
            t.put_record(rec).unwrap();
        }
        let adapter = RelocationDbAdapterV5::new(&handle, addr_map()).unwrap();

        let mut it = adapter.iterator().unwrap();
        let translated = it.next().unwrap().unwrap();
        assert_eq!(translated.get_field(ADDR_COL), &Field::Long(Some(0x4000)));
        assert_eq!(translated.get_field(TYPE_COL), &Field::Int(Some(7)));
        assert_eq!(translated.get_field(VALUE_COL), &Field::Binary(Some(vec![1, 2, 3])));
        assert_eq!(translated.get_field(BYTES_COL), &Field::Binary(Some(vec![0xAA])));
        assert_eq!(translated.get_string(SYMBOL_NAME_COL), Some("sym"));
        let flags = match translated.get_field(FLAGS_COL) {
            Field::Byte(Some(b)) => *b as u8,
            _ => panic!("expected byte field"),
        };
        assert_eq!(get_status(flags), RelocationStatus::Unknown);
    }

    #[test]
    fn record_count_and_iteration_order_by_address() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_v5_table(&mut handle);
        {
            let mut t = table.write().unwrap();
            for (key, addr_val) in [(0i64, 0x300i64), (1, 0x100), (2, 0x200)] {
                let mut rec = DBRecord::new(v5_schema(), Field::Long(Some(key)));
                rec.set_field(V5_ADDR_COL, Field::Long(Some(addr_val)));
                t.put_record(rec).unwrap();
            }
        }
        let adapter = RelocationDbAdapterV5::new(&handle, addr_map()).unwrap();
        assert_eq!(adapter.get_record_count(), 3);

        let mut it = adapter.iterator().unwrap();
        let mut addrs = Vec::new();
        while let Some(rec) = it.next().unwrap() {
            addrs.push(rec.get_field(ADDR_COL).get_long_value());
        }
        assert_eq!(addrs, vec![0x100, 0x200, 0x300]);
    }
}
