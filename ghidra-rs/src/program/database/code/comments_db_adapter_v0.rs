//! Port of `ghidra.program.database.code.CommentsDBAdapterV0`.
//!
//! Version 0's on-disk schema only has the `EOL`/`Pre`/`Post`/`Plate` columns (no `Repeatable`);
//! this adapter reads through that legacy table and converts each record into the current
//! (version 1) record shape on the fly, leaving the repeatable-comment column unset, exactly as
//! Java's `v0ConvertRecord` does. Records are read-only: every mutating method is rejected with
//! an `Unsupported` error, matching Java's `UnsupportedOperationException`s.
//!
//! Java decodes addresses through `addrMap.getOldAddressMap()` (the pre-upgrade address
//! encoding), not the current map -- this port does the same.
//!
//! Where Java uses `AddressKeyIterator`/`AddressKeyRecordIterator` (backed by `Table`'s secondary
//! indexes), this port's [`Table`] has no secondary-index support, so both scan linearly instead,
//! matching the convention already established by `CommentsDBAdapterV1` and others in this
//! DB-adapter family.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::database::code::comments_db_adapter::{
    self, CommentsDBAdapter, MoveAddressRangeError, COMMENTS_TABLE_NAME, EOL_COMMENT_COL,
    PLATE_COMMENT_COL, POST_COMMENT_COL, PRE_COMMENT_COL,
};
use crate::program::database::map::AddressMap;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::seam_stubs::AddressKeyIteratorLike;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Legacy (version 0) column index for EOL comments.
const V0_EOL_COMMENT_COLUMN: usize = 0;
/// Legacy (version 0) column index for pre comments.
const V0_PRE_COMMENT_COLUMN: usize = 1;
/// Legacy (version 0) column index for post comments.
const V0_POST_COMMENT_COLUMN: usize = 2;
/// Legacy (version 0) column index for plate comments.
const V0_PLATE_COMMENT_COLUMN: usize = 3;

/// Converts a legacy (version 0) record into the current (version 1) record shape, leaving the
/// repeatable-comment column unset. Stands in for `CommentsDBAdapterV0.v0ConvertRecord`.
fn v0_convert_record(rec_v0: &DBRecord) -> DBRecord {
    let mut record = DBRecord::new(comments_db_adapter::schema(), rec_v0.get_key().clone());
    for (v0_col, current_col) in [
        (V0_EOL_COMMENT_COLUMN, EOL_COMMENT_COL),
        (V0_PRE_COMMENT_COLUMN, PRE_COMMENT_COL),
        (V0_POST_COMMENT_COLUMN, POST_COMMENT_COL),
        (V0_PLATE_COMMENT_COLUMN, PLATE_COMMENT_COL),
    ] {
        if let Field::String(Some(comment)) = rec_v0.get_field(v0_col) {
            record.set_field(current_col, Field::String(Some(comment.clone())));
        }
    }
    record
}

/// A `RecordIterator` over an eagerly-collected, already-converted set of records.
struct VecRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl RecordIterator for VecRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }

    fn has_next(&self) -> bool {
        self.records.len() > 0
    }
}

/// A bidirectional cursor over a sorted set of (legacy) address keys. See
/// [`CommentsDBAdapterV1`](crate::program::database::code::comments_db_adapter_v1::CommentsDBAdapterV1)'s
/// module docs for why this models both directions while [`RecordIterator`] does not.
struct VecAddressKeyIterator {
    keys: Vec<i64>,
    pos: usize,
}

impl VecAddressKeyIterator {
    fn new(keys: Vec<i64>, forward: bool) -> Self {
        let pos = if forward { 0 } else { keys.len() };
        VecAddressKeyIterator { keys, pos }
    }
}

impl AddressKeyIteratorLike for VecAddressKeyIterator {
    fn has_next(&mut self) -> bool {
        self.pos < self.keys.len()
    }

    fn has_previous(&mut self) -> bool {
        self.pos > 0
    }

    fn next(&mut self) -> Option<i64> {
        if self.pos < self.keys.len() {
            let v = self.keys[self.pos];
            self.pos += 1;
            Some(v)
        } else {
            None
        }
    }

    fn previous(&mut self) -> Option<i64> {
        if self.pos > 0 {
            self.pos -= 1;
            Some(self.keys[self.pos])
        } else {
            None
        }
    }
}

/// Version 0 adapter for the comments table.
///
/// Port of `ghidra.program.database.code.CommentsDBAdapterV0`. See the module docs for the
/// record-conversion and read-only deviations.
pub struct CommentsDBAdapterV0 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl CommentsDBAdapterV0 {
    /// Constructs a new Version 0 comments adapter, opening the existing comments table from
    /// `handle`. `addr_map` is Java's post-upgrade map; this constructor takes its
    /// [`AddressMap::get_old_address_map`] internally, mirroring
    /// `addrMap.getOldAddressMap()`.
    ///
    /// # Errors
    ///
    /// Returns [`VersionException`] if the table does not exist or is not schema version 0.
    pub fn new(
        handle: &crate::framework::db::DBHandle,
        addr_map: &dyn AddressMap,
    ) -> Result<Self, VersionException> {
        let table = handle.get_table(COMMENTS_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {COMMENTS_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(VersionException::with_version_indicator(
                VersionException::NEWER_VERSION,
                false,
            ));
        }
        Ok(CommentsDBAdapterV0 {
            table,
            addr_map: Arc::from(addr_map.get_old_address_map()),
        })
    }

    fn collect_sorted_by_address(
        &self,
        filter: impl Fn(&Address) -> bool,
    ) -> io::Result<Vec<(Address, DBRecord)>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(key)) = rec.get_key() {
                let addr = self.addr_map.decode_address(*key);
                if filter(&addr) {
                    entries.push((addr, v0_convert_record(&rec)));
                }
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "Cannot modify records with old schema")
}

impl CommentsDBAdapter for CommentsDBAdapterV0 {
    fn get_record_count(&self) -> io::Result<i32> {
        Ok(self.table.read().unwrap().get_record_count() as i32)
    }

    fn get_record(&self, addr: i64) -> io::Result<Option<DBRecord>> {
        Ok(self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(addr)))?
            .map(|rec| v0_convert_record(&rec)))
    }

    fn create_record(
        &mut self,
        _addr: i64,
        _comment_col: usize,
        _comment: &str,
    ) -> io::Result<DBRecord> {
        Err(unsupported())
    }

    fn delete_record(&mut self, _addr: i64) -> io::Result<bool> {
        Err(unsupported())
    }

    fn delete_records(&mut self, _start: &Address, _end: &Address) -> io::Result<bool> {
        Err(unsupported())
    }

    fn update_record(&mut self, _comment_rec: &DBRecord) -> io::Result<()> {
        Err(unsupported())
    }

    fn get_records_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let mut entries = self.collect_sorted_by_address(|addr| addr >= start && addr <= end)?;
        if !at_start {
            entries.reverse();
        }
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let entries = self.collect_sorted_by_address(|_| true)?;
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
    }

    fn get_keys_in_range(
        &self,
        start: &Address,
        end: &Address,
        at_start: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let entries = self.collect_sorted_by_address(|addr| addr >= start && addr <= end)?;
        let keys: Vec<i64> = entries
            .into_iter()
            .filter_map(|(_, rec)| match rec.get_key() {
                Field::Long(Some(v)) => Some(*v),
                _ => None,
            })
            .collect();
        Ok(Box::new(VecAddressKeyIterator::new(keys, at_start)))
    }

    fn put_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        Err(unsupported())
    }

    fn get_records_from(&self, addr: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
        let entries = self.collect_sorted_by_address(|a| a >= addr)?;
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
    }

    fn get_keys(
        &self,
        set: Option<&dyn AddressSetView>,
        forward: bool,
    ) -> io::Result<Box<dyn AddressKeyIteratorLike>> {
        let entries = self.collect_sorted_by_address(|addr| match set {
            Some(set) => set.contains(addr),
            None => true,
        })?;
        let keys: Vec<i64> = entries
            .into_iter()
            .filter_map(|(_, rec)| match rec.get_key() {
                Field::Long(Some(v)) => Some(*v),
                _ => None,
            })
            .collect();
        Ok(Box::new(VecAddressKeyIterator::new(keys, forward)))
    }

    fn move_address_range(
        &mut self,
        _from_addr: &Address,
        _to_addr: &Address,
        _length: i64,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), MoveAddressRangeError> {
        Err(MoveAddressRangeError::Io(unsupported()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, FieldType, Schema};
    use crate::program::model::address::{AddressSpace, AddressSpaceType, KeyRange};

    fn v0_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Address".to_string(),
            vec![
                FieldType::String,
                FieldType::String,
                FieldType::String,
                FieldType::String,
            ],
            vec![
                "EOL".to_string(),
                "Pre".to_string(),
                "Post".to_string(),
                "Plate".to_string(),
            ],
            vec![],
        ))
    }

    struct IdentityAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for IdentityAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }
        fn decode_address(&self, value: i64) -> Address {
            self.space.address(value)
        }
        fn get_address_factory(
            &self,
        ) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
            None
        }
        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }
        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(IdentityAddressMap {
                space: self.space.clone(),
            })
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            self.space.address(0)
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn setup_table(handle: &mut DBHandle, key: i64, eol: &str, pre: &str) {
        let table = handle
            .create_table(COMMENTS_TABLE_NAME.to_string(), v0_schema())
            .unwrap();
        let mut record = DBRecord::new(v0_schema(), Field::Long(Some(key)));
        record.set_field(V0_EOL_COMMENT_COLUMN, Field::String(Some(eol.to_string())));
        record.set_field(V0_PRE_COMMENT_COLUMN, Field::String(Some(pre.to_string())));
        table.write().unwrap().put_record(record).unwrap();
    }

    #[test]
    fn get_record_converts_legacy_columns() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, 0x1000, "eol text", "pre text");
        let addr_map = IdentityAddressMap { space: space() };
        let adapter = CommentsDBAdapterV0::new(&handle, &addr_map).unwrap();

        let rec = adapter.get_record(0x1000).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(EOL_COMMENT_COL),
            &Field::String(Some("eol text".to_string()))
        );
        assert_eq!(
            rec.get_field(PRE_COMMENT_COL),
            &Field::String(Some("pre text".to_string()))
        );
        assert_eq!(rec.get_field(comments_db_adapter::REPEATABLE_COMMENT_COL), &Field::String(None));
    }

    #[test]
    fn mutations_are_unsupported() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, 0x1000, "a", "b");
        let addr_map = IdentityAddressMap { space: space() };
        let mut adapter = CommentsDBAdapterV0::new(&handle, &addr_map).unwrap();

        assert_eq!(
            adapter.create_record(0x2000, EOL_COMMENT_COL, "x").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(adapter.delete_record(0x1000).unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn get_records_converts_every_record() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, 0x2000, "b", "");
        {
            let table = handle.get_table(COMMENTS_TABLE_NAME).unwrap();
            let mut record = DBRecord::new(v0_schema(), Field::Long(Some(0x1000)));
            record.set_field(V0_EOL_COMMENT_COLUMN, Field::String(Some("a".to_string())));
            table.write().unwrap().put_record(record).unwrap();
        }
        let addr_map = IdentityAddressMap { space: space() };
        let adapter = CommentsDBAdapterV0::new(&handle, &addr_map).unwrap();

        let mut iter = adapter.get_records().unwrap();
        let mut vals = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            if let Field::String(Some(s)) = rec.get_field(EOL_COMMENT_COL) {
                vals.push(s.clone());
            }
        }
        assert_eq!(vals, vec!["a", "b"]);
    }

    #[test]
    fn opening_wrong_version_table_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        {
            use crate::program::database::code::comments_db_adapter;
            handle
                .create_table(COMMENTS_TABLE_NAME.to_string(), comments_db_adapter::schema())
                .unwrap();
        }
        let addr_map = IdentityAddressMap { space: space() };
        assert!(CommentsDBAdapterV0::new(&handle, &addr_map).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        setup_table(&mut handle, 0x1000, "a", "b");
        let addr_map = IdentityAddressMap { space: space() };
        let adapter: Box<dyn CommentsDBAdapter> =
            Box::new(CommentsDBAdapterV0::new(&handle, &addr_map).unwrap());
        assert_eq!(adapter.get_record_count().unwrap(), 1);
    }
}
