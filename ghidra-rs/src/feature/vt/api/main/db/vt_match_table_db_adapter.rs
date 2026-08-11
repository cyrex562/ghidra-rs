//! Port of `ghidra.feature.vt.api.db.VTMatchTableDBAdapter`.
//!
//! Abstract adapter for the database table that holds version-tracking matches. As with
//! [`super::vt_match_tag_db_adapter`], the Java class carries only class-level (static) state --
//! the table name prefix and schema -- plus a pair of static factory methods; per-instance state
//! (the backing [`Table`]) belongs to the concrete subclass. That split is mirrored here:
//! [`VTMatchTableDBAdapterBase`] is a namespace for the shared schema and the factory methods,
//! while [`VTMatchTableDBAdapter`] declares the abstract per-instance operations that a concrete
//! adapter (currently only `VTMatchTableDBAdapterV0`) must implement.

use std::io;
use std::sync::Arc;

use crate::feature::seam_stubs::{
    VTMatchInfo, VTMatchSetDB, VTMatchTableDBAdapterV0, VTMatchTagDB,
};
use crate::feature::vt::api::db::vt_association_db::VTAssociationDB;
use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, FieldType, RecordIterator, Schema};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Prefix of the database table backing this adapter; the full table name appends the owning
/// match set's table ID (Java: `TABLE_NAME + tableID`).
pub const TABLE_NAME: &str = "MatchTable";

/// Columns of the `MatchTable`.
///
/// Corresponds to the Java nested enum `VTMatchTableDBAdapter.ColumnDescription`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnDescription {
    TagKeyCol,
    MatchSetCol,
    SimilarityScoreCol,
    ConfidenceScoreCol,
    LengthType,
    SourceLengthCol,
    DestinationLengthCol,
    AssociationCol,
}

impl ColumnDescription {
    const VARIANTS: [ColumnDescription; 8] = [
        ColumnDescription::TagKeyCol,
        ColumnDescription::MatchSetCol,
        ColumnDescription::SimilarityScoreCol,
        ColumnDescription::ConfidenceScoreCol,
        ColumnDescription::LengthType,
        ColumnDescription::SourceLengthCol,
        ColumnDescription::DestinationLengthCol,
        ColumnDescription::AssociationCol,
    ];

    /// The Java enum constant name, e.g. `"TAG_KEY_COL"`.
    fn name(&self) -> &'static str {
        match self {
            ColumnDescription::TagKeyCol => "TAG_KEY_COL",
            ColumnDescription::MatchSetCol => "MATCH_SET_COL",
            ColumnDescription::SimilarityScoreCol => "SIMILARITY_SCORE_COL",
            ColumnDescription::ConfidenceScoreCol => "CONFIDENCE_SCORE_COL",
            ColumnDescription::LengthType => "LENGTH_TYPE",
            ColumnDescription::SourceLengthCol => "SOURCE_LENGTH_COL",
            ColumnDescription::DestinationLengthCol => "DESTINATION_LENGTH_COL",
            ColumnDescription::AssociationCol => "ASSOCIATION_COL",
        }
    }

    /// The field type backing this column (Java: `getColumnField()`).
    pub fn column_field(&self) -> FieldType {
        match self {
            ColumnDescription::TagKeyCol => FieldType::Long,
            ColumnDescription::MatchSetCol => FieldType::Long,
            ColumnDescription::SimilarityScoreCol => FieldType::String,
            ColumnDescription::ConfidenceScoreCol => FieldType::String,
            ColumnDescription::LengthType => FieldType::String,
            ColumnDescription::SourceLengthCol => FieldType::Int,
            ColumnDescription::DestinationLengthCol => FieldType::Int,
            ColumnDescription::AssociationCol => FieldType::Long,
        }
    }

    /// The column index (Java: `column()`, i.e. the enum ordinal).
    pub fn column(&self) -> usize {
        match self {
            ColumnDescription::TagKeyCol => 0,
            ColumnDescription::MatchSetCol => 1,
            ColumnDescription::SimilarityScoreCol => 2,
            ColumnDescription::ConfidenceScoreCol => 3,
            ColumnDescription::LengthType => 4,
            ColumnDescription::SourceLengthCol => 5,
            ColumnDescription::DestinationLengthCol => 6,
            ColumnDescription::AssociationCol => 7,
        }
    }

    fn column_names() -> Vec<String> {
        Self::VARIANTS.iter().map(|c| c.name().to_string()).collect()
    }

    fn column_fields() -> Vec<FieldType> {
        Self::VARIANTS.iter().map(|c| c.column_field()).collect()
    }
}

/// Abstract per-instance operations a concrete match-table adapter must implement.
///
/// Corresponds to the abstract instance methods of the Java `VTMatchTableDBAdapter` class.
pub trait VTMatchTableDBAdapter {
    fn insert_match_record(
        &self,
        info: &dyn VTMatchInfo,
        match_set: &dyn VTMatchSetDB,
        association: &VTAssociationDB,
        tag: Option<&dyn VTMatchTagDB>,
    ) -> io::Result<DBRecord>;

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator>>;

    fn get_match_record(&self, match_record_key: i64) -> io::Result<Option<DBRecord>>;

    fn get_record_count(&self) -> usize;

    fn update_record(&self, record: &DBRecord) -> io::Result<()>;

    fn delete_record(&self, match_record_key: i64) -> io::Result<bool>;

    /// Java: overload `getRecords(long associationID)`, renamed since Rust has no overloading.
    fn get_records_for_association(&self, association_id: i64) -> io::Result<Box<dyn RecordIterator>>;
}

/// Shared (class-level) state and factory methods for match-table adapters.
///
/// Corresponds to the static members of the Java `VTMatchTableDBAdapter` class.
pub struct VTMatchTableDBAdapterBase;

impl VTMatchTableDBAdapterBase {
    /// The full table name for the match table owned by the match set with the given table ID
    /// (Java: `TABLE_NAME + tableID`).
    pub fn table_name(table_id: i64) -> String {
        format!("{TABLE_NAME}{table_id}")
    }

    /// Builds the schema for the `MatchTable` (Java: static field `TABLE_SCHEMA`).
    pub fn table_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            ColumnDescription::column_fields(),
            ColumnDescription::column_names(),
            vec![],
        ))
    }

    /// Creates a new match-table adapter, creating the backing table.
    ///
    /// Corresponds to the Java static method `createAdapter(DBHandle, long)`.
    pub fn create_adapter(
        db_handle: &mut DBHandle,
        table_id: i64,
    ) -> io::Result<Box<dyn VTMatchTableDBAdapter>> {
        let adapter = VTMatchTableDBAdapterV0::create(
            db_handle,
            &Self::table_name(table_id),
            Self::table_schema(),
        )?;
        Ok(Box::new(adapter))
    }

    /// Opens an existing match-table adapter.
    ///
    /// Corresponds to the Java static method `getAdapter(DBHandle, long, OpenMode, TaskMonitor)`.
    pub fn get_adapter(
        db_handle: &DBHandle,
        table_id: i64,
        _open_mode: OpenMode,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn VTMatchTableDBAdapter>, VersionException> {
        let adapter = VTMatchTableDBAdapterV0::open(db_handle, &Self::table_name(table_id))?;
        Ok(Box::new(adapter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::vt::api::main::vt_score::VtScore;

    #[test]
    fn column_description_matches_java_shape() {
        assert_eq!(ColumnDescription::TagKeyCol.column(), 0);
        assert_eq!(ColumnDescription::MatchSetCol.column(), 1);
        assert_eq!(ColumnDescription::SimilarityScoreCol.column(), 2);
        assert_eq!(ColumnDescription::ConfidenceScoreCol.column(), 3);
        assert_eq!(ColumnDescription::LengthType.column(), 4);
        assert_eq!(ColumnDescription::SourceLengthCol.column(), 5);
        assert_eq!(ColumnDescription::DestinationLengthCol.column(), 6);
        assert_eq!(ColumnDescription::AssociationCol.column(), 7);

        assert_eq!(ColumnDescription::TagKeyCol.column_field(), FieldType::Long);
        assert_eq!(ColumnDescription::SimilarityScoreCol.column_field(), FieldType::String);
        assert_eq!(ColumnDescription::SourceLengthCol.column_field(), FieldType::Int);

        assert_eq!(
            ColumnDescription::column_names(),
            vec![
                "TAG_KEY_COL",
                "MATCH_SET_COL",
                "SIMILARITY_SCORE_COL",
                "CONFIDENCE_SCORE_COL",
                "LENGTH_TYPE",
                "SOURCE_LENGTH_COL",
                "DESTINATION_LENGTH_COL",
                "ASSOCIATION_COL",
            ]
        );
    }

    #[test]
    fn table_schema_has_eight_columns_and_long_key() {
        let schema = VTMatchTableDBAdapterBase::table_schema();
        assert_eq!(schema.get_version(), 0);
        assert_eq!(schema.get_key_type(), FieldType::Long);
        assert_eq!(schema.get_key_name(), "Key");
        assert_eq!(schema.get_field_count(), 8);
        assert_eq!(schema.get_field_name(7), "ASSOCIATION_COL");
    }

    #[test]
    fn table_name_appends_table_id() {
        assert_eq!(VTMatchTableDBAdapterBase::table_name(42), "MatchTable42");
    }

    struct FakeMatchInfo {
        similarity: VtScore,
        confidence: VtScore,
        source_len: i32,
        dest_len: i32,
    }
    impl VTMatchInfo for FakeMatchInfo {
        fn get_similarity_score(&self) -> VtScore {
            self.similarity.clone()
        }
        fn get_confidence_score(&self) -> VtScore {
            self.confidence.clone()
        }
        fn get_source_length(&self) -> i32 {
            self.source_len
        }
        fn get_destination_length(&self) -> i32 {
            self.dest_len
        }
    }

    struct FakeMatchSet;
    impl VTMatchSetDB for FakeMatchSet {}

    /// Builds a session-less `VTAssociationDB` whose only interesting property is its key, which
    /// is all `insertMatchRecord` reads off the association.
    fn fake_association(key: i64) -> VTAssociationDB {
        VTAssociationDB::from_record(DBRecord::new(
            crate::feature::vt::api::main::db::vt_association_table_db_adapter::VTAssociationTableDBAdapterBase::table_schema(),
            crate::framework::db::Field::Long(Some(key)),
        ))
    }

    struct FakeTag(i64);
    impl VTMatchTagDB for FakeTag {
        fn get_key(&self) -> i64 {
            self.0
        }
    }

    #[test]
    fn create_adapter_then_insert_and_read_back_match() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchTableDBAdapterBase::create_adapter(&mut db_handle, 1).unwrap();

        let info = FakeMatchInfo {
            similarity: VtScore::new(0.75),
            confidence: VtScore::new(0.5),
            source_len: 10,
            dest_len: 20,
        };
        let match_set = FakeMatchSet;
        let association = fake_association(7);
        let tag = FakeTag(3);

        let record = adapter
            .insert_match_record(&info, &match_set, &association, Some(&tag))
            .unwrap();

        assert_eq!(record.get_long(ColumnDescription::TagKeyCol.column()), Some(3));
        assert_eq!(
            record.get_string(ColumnDescription::SimilarityScoreCol.column()),
            Some(VtScore::new(0.75).to_storage_string().as_str())
        );
        assert_eq!(
            record.get_string(ColumnDescription::ConfidenceScoreCol.column()),
            Some(VtScore::new(0.5).to_storage_string().as_str())
        );
        assert_eq!(record.get_long(ColumnDescription::AssociationCol.column()), Some(7));
        assert_eq!(record.get_int(ColumnDescription::SourceLengthCol.column()), Some(10));
        assert_eq!(record.get_int(ColumnDescription::DestinationLengthCol.column()), Some(20));
        // MATCH_SET_COL and LENGTH_TYPE are never populated by insertMatchRecord in the Java
        // source (the matchSet parameter is unused), so they stay at their default field value.
        assert_eq!(adapter.get_record_count(), 1);
    }

    #[test]
    fn insert_match_record_with_no_tag_stores_negative_one() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchTableDBAdapterBase::create_adapter(&mut db_handle, 1).unwrap();

        let info = FakeMatchInfo {
            similarity: VtScore::new(0.1),
            confidence: VtScore::new(0.2),
            source_len: 1,
            dest_len: 2,
        };
        let record = adapter
            .insert_match_record(&info, &FakeMatchSet, &fake_association(1), None)
            .unwrap();

        assert_eq!(record.get_long(ColumnDescription::TagKeyCol.column()), Some(-1));
    }

    #[test]
    fn delete_record_removes_it() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchTableDBAdapterBase::create_adapter(&mut db_handle, 1).unwrap();

        let info = FakeMatchInfo {
            similarity: VtScore::new(0.1),
            confidence: VtScore::new(0.2),
            source_len: 1,
            dest_len: 2,
        };
        let record = adapter
            .insert_match_record(&info, &FakeMatchSet, &fake_association(1), None)
            .unwrap();
        let key = record.get_key().get_long_value();

        assert!(adapter.delete_record(key).unwrap());
        assert_eq!(adapter.get_record_count(), 0);
        assert!(!adapter.delete_record(key).unwrap());
    }

    #[test]
    fn get_records_for_association_filters_by_association_key() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchTableDBAdapterBase::create_adapter(&mut db_handle, 1).unwrap();

        let info = FakeMatchInfo {
            similarity: VtScore::new(0.1),
            confidence: VtScore::new(0.2),
            source_len: 1,
            dest_len: 2,
        };
        adapter
            .insert_match_record(&info, &FakeMatchSet, &fake_association(1), None)
            .unwrap();
        adapter
            .insert_match_record(&info, &FakeMatchSet, &fake_association(2), None)
            .unwrap();
        adapter
            .insert_match_record(&info, &FakeMatchSet, &fake_association(1), None)
            .unwrap();

        let mut iter = adapter.get_records_for_association(1).unwrap();
        let mut count = 0;
        while let Some(record) = iter.next().unwrap() {
            assert_eq!(record.get_long(ColumnDescription::AssociationCol.column()), Some(1));
            count += 1;
        }
        assert_eq!(count, 2);
    }

    struct NoOpMonitor;
    impl TaskMonitor for NoOpMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn get_adapter_on_missing_table_returns_version_exception() {
        let db_handle = DBHandle::new().unwrap();
        let monitor = NoOpMonitor;
        let result =
            VTMatchTableDBAdapterBase::get_adapter(&db_handle, 1, OpenMode::Update, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn get_adapter_reopens_created_table() {
        let mut db_handle = DBHandle::new().unwrap();
        VTMatchTableDBAdapterBase::create_adapter(&mut db_handle, 1).unwrap();

        let monitor = NoOpMonitor;
        let adapter =
            VTMatchTableDBAdapterBase::get_adapter(&db_handle, 1, OpenMode::Update, &monitor)
                .unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }
}
