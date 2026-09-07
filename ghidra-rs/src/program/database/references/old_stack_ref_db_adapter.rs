//! Port of `ghidra.program.database.references.OldStackRefDBAdpater`.
//!
//! (Java's class name itself has a typo -- "Adpater", not "Adapter" -- preserved here in the
//! module's doc references to the Java type, though the Rust type itself is spelled correctly.)
//!
//! Adapter for the legacy ("old format") stack references table, encountered only while opening
//! databases saved by older Ghidra versions and needing an upgrade to the current reference
//! storage scheme.
//!
//! Not ported here: the static factory `getAdapter(DBHandle, OpenMode, TaskMonitor)` and its
//! private `moveTable` upgrade helper, which copies every record into a fresh table on the
//! `DBHandle`'s scratch pad when opened with `OpenMode.UPGRADE`. This port's [`DBHandle`] has no
//! scratch-pad equivalent (`DBHandle.getScratchPad()` is not yet ported), so
//! [`OldStackRefDbAdapter::new`] only covers the private constructor's non-upgrade path (get the
//! existing table, verify its version); a caller performing the upgrade itself still has direct
//! access to [`get_records`](OldStackRefDbAdapter::get_records) to drive that copy manually until
//! the scratch-pad dependency lands.

use std::io;
use std::sync::Arc;

use crate::framework::db::{DBHandle, DBRecord, FieldType, RecordIterator, Schema, Table};
use crate::util::exception::VersionException;

/// A `RecordIterator` over an eagerly-collected set of records, used so
/// [`OldStackRefDbAdapter::get_records`] does not need to return a value borrowing from a
/// temporary read-lock guard.
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

/// Name of the legacy stack-references table.
pub const STACK_REF_TABLE_NAME: &str = "Stack References";

/// Column index of the reference's source ("from") address. Mirrors
/// `OldStackRefDBAdpater.FROM_ADDR_COL`.
pub const FROM_ADDR_COL: usize = 0;
/// Column index of the reference's operand index. Mirrors `OldStackRefDBAdpater.OP_INDEX_COL`.
pub const OP_INDEX_COL: usize = 1;
/// Column index of the user-defined flag. Mirrors `OldStackRefDBAdpater.USER_DEFINED_COL`.
pub const USER_DEFINED_COL: usize = 2;
/// Column index of the stack offset. Mirrors `OldStackRefDBAdpater.STACK_OFFSET_COL`.
pub const STACK_OFFSET_COL: usize = 3;

/// Builds the legacy stack-references table schema. Mirrors
/// `OldStackRefDBAdpater.STACK_REF_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::Long, FieldType::Short, FieldType::Boolean, FieldType::Short],
        vec![
            "From Address".to_string(),
            "Op Index".to_string(),
            "User Defined".to_string(),
            "Stack Offset".to_string(),
        ],
        vec![],
    ))
}

/// Adapter for the legacy stack references table in the database.
///
/// Port of `ghidra.program.database.references.OldStackRefDBAdpater`. See the module docs for
/// what was intentionally left out (the `getAdapter` static factory and its scratch-pad-based
/// upgrade path).
pub struct OldStackRefDbAdapter {
    table: Arc<std::sync::RwLock<Table>>,
}

impl OldStackRefDbAdapter {
    /// Stands in for `OldStackRefDBAdpater`'s private constructor.
    ///
    /// # Errors
    ///
    /// Returns [`VersionException`] if the table is missing, or exists at a schema version other
    /// than `0`.
    pub fn new(handle: &DBHandle) -> Result<Self, VersionException> {
        let table = handle.get_table(STACK_REF_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {STACK_REF_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(VersionException::with_upgradeable(false));
        }
        Ok(OldStackRefDbAdapter { table })
    }

    /// Stands in for `OldStackRefDBAdpater.getRecords()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    pub fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    /// Stands in for `OldStackRefDBAdpater.getRecordCount()`.
    pub fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBRecord, Field};

    fn create_table(handle: &mut DBHandle) {
        handle
            .create_table(STACK_REF_TABLE_NAME.to_string(), schema())
            .unwrap();
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(OldStackRefDbAdapter::new(&handle).is_err());
    }

    #[test]
    fn wrong_version_table_is_a_version_exception() {
        let mut handle = DBHandle::new().unwrap();
        let bad_schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Long],
            vec!["From Address".to_string()],
            vec![],
        ));
        handle
            .create_table(STACK_REF_TABLE_NAME.to_string(), bad_schema)
            .unwrap();
        assert!(OldStackRefDbAdapter::new(&handle).is_err());
    }

    #[test]
    fn get_record_count_and_iteration_round_trip() {
        let mut handle = DBHandle::new().unwrap();
        create_table(&mut handle);

        {
            let table = handle.get_table(STACK_REF_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            for (i, (from, op_index, user_defined, stack_offset)) in
                [(0x1000i64, 0i16, true, -8i16), (0x2000, 1, false, 4)]
                    .into_iter()
                    .enumerate()
            {
                let mut record = DBRecord::new(schema(), Field::Long(Some(i as i64)));
                record.set_long(FROM_ADDR_COL, from);
                record.set_field(OP_INDEX_COL, Field::Short(Some(op_index)));
                record.set_field(USER_DEFINED_COL, Field::Boolean(Some(user_defined)));
                record.set_field(STACK_OFFSET_COL, Field::Short(Some(stack_offset)));
                table.put_record(record).unwrap();
            }
        }

        let adapter = OldStackRefDbAdapter::new(&handle).unwrap();
        assert_eq!(adapter.get_record_count(), 2);

        let mut iter = adapter.get_records().unwrap();
        let mut seen = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            seen.push((
                rec.get_long(FROM_ADDR_COL).unwrap(),
                rec.get_field(STACK_OFFSET_COL).clone(),
            ));
        }
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], (0x1000, Field::Short(Some(-8))));
        assert_eq!(seen[1], (0x2000, Field::Short(Some(4))));
    }
}
