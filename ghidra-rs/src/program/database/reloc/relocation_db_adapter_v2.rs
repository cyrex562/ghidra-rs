//! Port of `ghidra.program.database.reloc.RelocationDBAdapterV2`.
//!
//! Read-only legacy adapter. Like `V1`/`V3`/`V4`, `V2`'s primary key *is* the address-encoded
//! value (see `RelocationDbAdapterV4`'s module docs for why). `V2` added a single `Values` column
//! -- a plain `Long`, not yet the binary-coded `long[]` used from `V3` onward -- so
//! [`RelocationDbAdapterV2::adapt_record`] wraps that lone value into a one-element array via
//! [`encode_binary_coded_longs`], matching Java's `new BinaryCodedField(new long[] {
//! rec.getLongValue(V2_VALUE_COL) })`. There is no `Bytes`/`Symbol Name` column yet (added in
//! `V3`/`V4` respectively). [`RelocationDBAdapter::add`] returns an `io::ErrorKind::Unsupported`
//! error, mirroring Java's `throw new UnsupportedOperationException()`.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, Table};
use crate::program::database::map::{AddressKeyRecordIterator, AddressMap};
use crate::program::database::reloc::relocation_db_adapter::{
    encode_binary_coded_longs, get_flags, RelocationDBAdapter, VecRelocationRecordIterator,
    ADDR_COL, FLAGS_COL, TABLE_NAME, TYPE_COL, VALUE_COL,
};
use crate::program::database::reloc::relocation_db_adapter_v6::schema;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::reloc::relocation::RelocationStatus;
use crate::util::exception::VersionException;

/// Schema version implemented by this adapter. Port of `RelocationDBAdapterV2.VERSION`.
pub const VERSION: i32 = 2;

/// Column index of a V2 relocation's type. Port of `RelocationDBAdapterV2.V2_TYPE_COL`.
pub const V2_TYPE_COL: usize = 0;
/// Column index of a V2 relocation's (single, non-array) value. Port of
/// `RelocationDBAdapterV2.V2_VALUE_COL`.
pub const V2_VALUE_COL: usize = 1;

/// The read-only, `V2`-schema implementation of the relocations database adapter.
///
/// Port of `ghidra.program.database.reloc.RelocationDBAdapterV2`.
pub struct RelocationDbAdapterV2 {
    reloc_table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl RelocationDbAdapterV2 {
    /// Opens an existing `V2` relocations table.
    ///
    /// Port of `RelocationDBAdapterV2(DBHandle, AddressMap)`.
    ///
    /// # Errors
    /// Returns a non-upgradeable [`VersionException`] if no relocations table exists, or it
    /// exists at a schema version other than [`VERSION`].
    pub fn new(handle: &DBHandle, addr_map: Arc<dyn AddressMap>) -> Result<Self, VersionException> {
        let table = handle.get_table(TABLE_NAME).ok_or_else(VersionException::new)?;
        if table.read().unwrap().get_schema().get_version() != VERSION {
            return Err(VersionException::new());
        }
        Ok(RelocationDbAdapterV2 { reloc_table: table, addr_map })
    }

    fn collect_records(
        &self,
        set: Option<&dyn AddressSetView>,
        start: Option<&Address>,
    ) -> io::Result<Vec<DBRecord>> {
        let mut it = match start {
            Some(start) => {
                AddressKeyRecordIterator::new_at(&self.reloc_table, self.addr_map.as_ref(), start, true)?
            }
            None => AddressKeyRecordIterator::new_over_set(
                &self.reloc_table,
                self.addr_map.as_ref(),
                set,
                None,
                true,
            )?,
        };
        let mut records = Vec::new();
        while it.has_next() {
            if let Some(rec) = it.next()? {
                records.push(self.adapt_record(rec));
            }
        }
        Ok(records)
    }
}

impl RelocationDBAdapter for RelocationDbAdapterV2 {
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
            "RelocationDBAdapterV2 is read-only",
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
        // Key was encoded address (V1..V4 have no separate address column).
        new_rec.set_field(ADDR_COL, Field::Long(Some(rec.get_key().get_long_value())));
        new_rec.set_field(FLAGS_COL, Field::Byte(Some(get_flags(RelocationStatus::Unknown, 0) as i8)));
        new_rec.set_field(TYPE_COL, Field::Int(Some(rec.get_field(V2_TYPE_COL).get_int_value())));
        let single_value = rec.get_field(V2_VALUE_COL).get_long_value();
        new_rec.set_field(
            VALUE_COL,
            Field::Binary(Some(encode_binary_coded_longs(&[single_value]))),
        );
        // No Bytes/Symbol Name columns at V2 -- left unset (None), matching Java's untouched
        // defaults.
        new_rec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use crate::program::database::reloc::relocation_db_adapter::{
        decode_binary_coded_longs, get_status, BYTES_COL, SYMBOL_NAME_COL,
    };
    use crate::program::database::reloc::test_support::IdentityAddressMap;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(IdentityAddressMap::new(space()))
    }

    fn v2_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            VERSION,
            FieldType::Long,
            "Address".to_string(),
            vec![FieldType::Int, FieldType::Long],
            vec!["Type".to_string(), "Values".to_string()],
            vec![],
        ))
    }

    fn make_v2_table(handle: &mut DBHandle) -> Arc<RwLock<Table>> {
        handle.create_table(TABLE_NAME.to_string(), v2_schema()).unwrap()
    }

    #[test]
    fn open_rejects_missing_table() {
        let handle = DBHandle::new().unwrap();
        assert!(RelocationDbAdapterV2::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn add_is_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        make_v2_table(&mut handle);
        let mut adapter = RelocationDbAdapterV2::new(&handle, addr_map()).unwrap();
        let err = adapter.add(&space().address(0), 0, 0, &[], None, None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn adapt_record_wraps_single_value_into_a_one_element_array() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_v2_table(&mut handle);
        {
            let mut t = table.write().unwrap();
            let mut rec = DBRecord::new(v2_schema(), Field::Long(Some(0x7000)));
            rec.set_field(V2_TYPE_COL, Field::Int(Some(1)));
            rec.set_field(V2_VALUE_COL, Field::Long(Some(0x1234_5678)));
            t.put_record(rec).unwrap();
        }
        let adapter = RelocationDbAdapterV2::new(&handle, addr_map()).unwrap();

        let mut it = adapter.iterator().unwrap();
        let translated = it.next().unwrap().unwrap();
        assert_eq!(translated.get_field(ADDR_COL), &Field::Long(Some(0x7000)));
        assert_eq!(translated.get_field(TYPE_COL), &Field::Int(Some(1)));
        let decoded = decode_binary_coded_longs(translated.get_field(VALUE_COL).get_binary_data().unwrap());
        assert_eq!(decoded, vec![0x1234_5678]);
        assert_eq!(translated.get_field(BYTES_COL), &Field::Binary(None));
        assert_eq!(translated.get_string(SYMBOL_NAME_COL), None);
        let flags = match translated.get_field(FLAGS_COL) {
            Field::Byte(Some(b)) => *b as u8,
            _ => panic!("expected byte field"),
        };
        assert_eq!(get_status(flags), RelocationStatus::Unknown);
    }

    #[test]
    fn record_count_matches_table() {
        let mut handle = DBHandle::new().unwrap();
        let table = make_v2_table(&mut handle);
        {
            let mut t = table.write().unwrap();
            for addr_val in [0x100i64, 0x200, 0x300] {
                let rec = DBRecord::new(v2_schema(), Field::Long(Some(addr_val)));
                t.put_record(rec).unwrap();
            }
        }
        let adapter = RelocationDbAdapterV2::new(&handle, addr_map()).unwrap();
        assert_eq!(adapter.get_record_count(), 3);
    }
}
