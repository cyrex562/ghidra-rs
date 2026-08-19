//! Port of `ghidra.program.database.sourcemap.SourceFileAdapter`.
//!
//! The Java type is an abstract class whose static factory method `getAdapter` selects and
//! constructs a concrete version-specific implementation (`SourceFileAdapterV0`). That concrete
//! adapter has not been ported yet, so this port only models the abstract instance API each
//! version implements, as an object-safe trait; the version-selection/construction logic (which
//! depends on the unported `SourceFileAdapterV0`) belongs with whichever type ends up owning the
//! concrete adapters. This trait was itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};

use super::SourceFile;

/// DB table name for the source file table. Stands in for `SourceFileAdapter.TABLE_NAME`.
pub const TABLE_NAME: &str = "SourceFiles";

/// Source file record column index for the path (indexed). Stands in for
/// `SourceFileAdapter.PATH_COL` (`SourceFileAdapterV0.V0_PATH_COL`).
pub const PATH_COL: usize = 0;
/// Source file record column index for the id type. Stands in for
/// `SourceFileAdapter.ID_TYPE_COL` (`SourceFileAdapterV0.V0_ID_TYPE_COL`).
pub const ID_TYPE_COL: usize = 1;
/// Source file record column index for the identifier bytes. Stands in for
/// `SourceFileAdapter.ID_COL` (`SourceFileAdapterV0.V0_ID_COL`).
pub const ID_COL: usize = 2;

/// Adapter to access the Source File table. The table stores, per source file, its path along
/// with an id type and identifier byte payload (see [`PATH_COL`], [`ID_TYPE_COL`], [`ID_COL`]).
///
/// Port of `ghidra.program.database.sourcemap.SourceFileAdapter`.
pub trait SourceFileAdapter {
    /// Returns a record iterator for this table. Stands in for `SourceFileAdapter.getRecords()`.
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns the record corresponding to `source_file`, or `None` if no such record exists.
    /// Stands in for `SourceFileAdapter.getRecord(SourceFile)`.
    fn get_record(&self, source_file: &SourceFile) -> io::Result<Option<DBRecord>>;

    /// Returns the record with key `id`, or `None` if no such record exists. Stands in for
    /// `SourceFileAdapter.getRecord(long)`.
    fn get_record_by_id(&self, id: i64) -> io::Result<Option<DBRecord>>;

    /// Creates a record for `source_file`. If a record for that source file already exists, the
    /// existing record is returned. Stands in for
    /// `SourceFileAdapter.createSourceFileRecord(SourceFile)`.
    fn create_source_file_record(&mut self, source_file: &SourceFile) -> io::Result<DBRecord>;

    /// Deletes the record with id `id` from the database, returning `true` if it was deleted.
    /// Stands in for `SourceFileAdapter.removeSourceFileRecord(long)`.
    fn remove_source_file_record(&mut self, id: i64) -> io::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::database::sourcemap::SourceFileIdType;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::String, FieldType::Byte, FieldType::Binary],
            vec!["Path".to_string(), "IdType".to_string(), "Identifier".to_string()],
            vec![PATH_COL],
        ))
    }

    struct MockRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.len() > 0
        }
    }

    /// Mirrors `SourceFileAdapterV0`'s in-memory semantics closely enough to exercise the trait's
    /// contract: `create_source_file_record` dedupes on (path, id type, identifier), and removal
    /// is by key.
    struct MockSourceFileAdapter {
        schema: Arc<Schema>,
        records: BTreeMap<i64, DBRecord>,
        next_key: i64,
    }

    impl MockSourceFileAdapter {
        fn new() -> Self {
            MockSourceFileAdapter {
                schema: schema(),
                records: BTreeMap::new(),
                next_key: 0,
            }
        }
    }

    impl SourceFileAdapter for MockSourceFileAdapter {
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self.records.values().cloned().collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_record(&self, source_file: &SourceFile) -> io::Result<Option<DBRecord>> {
            for rec in self.records.values() {
                let Field::String(Some(path)) = rec.get_field(PATH_COL) else {
                    continue;
                };
                if path != source_file.path() {
                    continue;
                }
                let Field::Byte(Some(id_type)) = rec.get_field(ID_TYPE_COL) else {
                    continue;
                };
                if *id_type as u8 != source_file.id_type().index() {
                    continue;
                }
                let Field::Binary(identifier) = rec.get_field(ID_COL) else {
                    continue;
                };
                let identifier = identifier.clone().unwrap_or_default();
                if identifier == source_file.identifier() {
                    return Ok(Some(rec.clone()));
                }
            }
            Ok(None)
        }

        fn get_record_by_id(&self, id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&id).cloned())
        }

        fn create_source_file_record(&mut self, source_file: &SourceFile) -> io::Result<DBRecord> {
            if let Some(rec) = self.get_record(source_file)? {
                return Ok(rec);
            }
            let key = self.next_key;
            self.next_key += 1;
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            rec.set_field(
                PATH_COL,
                Field::String(Some(source_file.path().to_string())),
            );
            rec.set_field(
                ID_TYPE_COL,
                Field::Byte(Some(source_file.id_type().index() as i8)),
            );
            rec.set_field(ID_COL, Field::Binary(Some(source_file.identifier())));
            self.records.insert(key, rec.clone());
            Ok(rec)
        }

        fn remove_source_file_record(&mut self, id: i64) -> io::Result<bool> {
            Ok(self.records.remove(&id).is_some())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_dedupes_records() {
        let mut adapter: Box<dyn SourceFileAdapter> = Box::new(MockSourceFileAdapter::new());

        let source_file = SourceFile::with_identifier(
            "/a/b/c.c",
            SourceFileIdType::Md5,
            Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        )
        .unwrap();

        let rec1 = adapter.create_source_file_record(&source_file).unwrap();
        let rec2 = adapter.create_source_file_record(&source_file).unwrap();
        assert_eq!(rec1.get_key(), rec2.get_key(), "duplicate insert should reuse the record");

        let key = match rec1.get_key() {
            Field::Long(Some(k)) => *k,
            other => panic!("unexpected key field: {other:?}"),
        };

        let fetched = adapter.get_record_by_id(key).unwrap().expect("record should exist");
        assert_eq!(fetched.get_string(PATH_COL), Some("/a/b/c.c"));

        let fetched_by_source_file = adapter
            .get_record(&source_file)
            .unwrap()
            .expect("record should be found by source file");
        assert_eq!(fetched_by_source_file.get_key(), rec1.get_key());

        let mut count = 0;
        {
            let mut iter = adapter.get_records().unwrap();
            while let Some(_rec) = iter.next().unwrap() {
                count += 1;
            }
        }
        assert_eq!(count, 1);

        assert!(adapter.remove_source_file_record(key).unwrap());
        assert!(!adapter.remove_source_file_record(key).unwrap());
        assert!(adapter.get_record_by_id(key).unwrap().is_none());
    }
}
