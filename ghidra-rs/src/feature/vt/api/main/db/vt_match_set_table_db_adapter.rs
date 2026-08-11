//! Port of `ghidra.feature.vt.api.db.VTMatchSetTableDBAdapter`.
//!
//! Abstract adapter for the database table that holds version-tracking match sets. As with
//! [`super::vt_match_table_db_adapter`], the Java class carries only class-level (static) state --
//! the table name and schema -- plus a pair of static factory methods; per-instance state (the
//! backing [`Table`] and, for this adapter, the owning [`DBHandle`] used to create the per-match-set
//! address-range tables) belongs to the concrete subclass. That split is mirrored here:
//! [`VTMatchSetTableDBAdapterBase`] is a namespace for the shared schema and the factory methods,
//! while [`VTMatchSetTableDBAdapter`] declares the abstract per-instance operations that a concrete
//! adapter (currently only `VTMatchSetTableDBAdapterV0`) must implement.

use std::io;
use std::sync::{Arc, RwLock};

use crate::feature::seam_stubs::VTMatchSetTableDBAdapterV0;
use crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator;
use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, FieldType, RecordIterator, Schema};
use crate::program::database::map::address_map::AddressMap;
use crate::program::model::address::AddressSet;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Name of the database table backing this adapter (Java: `TABLE_NAME`).
pub const TABLE_NAME: &str = "MatchSetTable";

/// Columns of the `MatchSetTable`.
///
/// Corresponds to the Java nested enum `VTMatchSetTableDBAdapter.ColumnDescription`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnDescription {
    CorrelatorClassCol,
    CorrelatorNameCol,
    OptionsCol,
}

impl ColumnDescription {
    const VARIANTS: [ColumnDescription; 3] = [
        ColumnDescription::CorrelatorClassCol,
        ColumnDescription::CorrelatorNameCol,
        ColumnDescription::OptionsCol,
    ];

    /// The Java enum constant name, e.g. `"CORRELATOR_CLASS_COL"`.
    fn name(&self) -> &'static str {
        match self {
            ColumnDescription::CorrelatorClassCol => "CORRELATOR_CLASS_COL",
            ColumnDescription::CorrelatorNameCol => "CORRELATOR_NAME_COL",
            ColumnDescription::OptionsCol => "OPTIONS_COL",
        }
    }

    /// The field type backing this column (Java: `getColumnField()`). All three columns are
    /// `StringField.INSTANCE` in the Java source.
    pub fn column_field(&self) -> FieldType {
        FieldType::String
    }

    /// The column index (Java: `column()`, i.e. the enum ordinal).
    pub fn column(&self) -> usize {
        match self {
            ColumnDescription::CorrelatorClassCol => 0,
            ColumnDescription::CorrelatorNameCol => 1,
            ColumnDescription::OptionsCol => 2,
        }
    }

    fn column_names() -> Vec<String> {
        Self::VARIANTS.iter().map(|c| c.name().to_string()).collect()
    }

    fn column_fields() -> Vec<FieldType> {
        Self::VARIANTS.iter().map(|c| c.column_field()).collect()
    }
}

/// Abstract per-instance operations a concrete match-set-table adapter must implement.
///
/// Corresponds to the abstract instance methods of the Java `VTMatchSetTableDBAdapter` class.
pub trait VTMatchSetTableDBAdapter {
    fn create_match_set_record(
        &self,
        key: i64,
        correlator: &dyn VTProgramCorrelator,
    ) -> io::Result<DBRecord>;

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator>>;

    fn get_source_address_set(
        &self,
        record: &DBRecord,
        address_map: &dyn AddressMap,
    ) -> io::Result<Option<AddressSet>>;

    fn get_destination_address_set(
        &self,
        record: &DBRecord,
        address_map: &dyn AddressMap,
    ) -> io::Result<Option<AddressSet>>;

    fn get_next_match_set_id(&self) -> i64;

    fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>>;
}

/// Shared (class-level) state and factory methods for match-set-table adapters.
///
/// Corresponds to the static members of the Java `VTMatchSetTableDBAdapter` class.
pub struct VTMatchSetTableDBAdapterBase;

impl VTMatchSetTableDBAdapterBase {
    /// Builds the schema for the `MatchSetTable` (Java: static field `TABLE_SCHEMA`).
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

    /// Creates a new match-set-table adapter, creating the backing table.
    ///
    /// Corresponds to the Java static method `createAdapter(DBHandle)`.
    ///
    /// Unlike [`super::vt_match_table_db_adapter::VTMatchTableDBAdapterBase`], this takes the
    /// database handle by shared reference: the Java `VTMatchSetTableDBAdapterV0` keeps a
    /// reference to `dbHandle` around after construction to create per-match-set address-range
    /// tables on demand, which the `Arc<RwLock<_>>` mirrors.
    pub fn create_adapter(
        db_handle: Arc<RwLock<DBHandle>>,
    ) -> io::Result<Box<dyn VTMatchSetTableDBAdapter>> {
        let adapter =
            VTMatchSetTableDBAdapterV0::create(db_handle, TABLE_NAME, Self::table_schema())?;
        Ok(Box::new(adapter))
    }

    /// Opens an existing match-set-table adapter.
    ///
    /// Corresponds to the Java static method `getAdapter(DBHandle, OpenMode, TaskMonitor)`.
    pub fn get_adapter(
        db_handle: Arc<RwLock<DBHandle>>,
        _open_mode: OpenMode,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn VTMatchSetTableDBAdapter>, VersionException> {
        let adapter = VTMatchSetTableDBAdapterV0::open(db_handle, TABLE_NAME)?;
        Ok(Box::new(adapter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::ToolOptions;
    use crate::program::model::address::AddressSetView;

    #[test]
    fn column_description_matches_java_shape() {
        assert_eq!(ColumnDescription::CorrelatorClassCol.column(), 0);
        assert_eq!(ColumnDescription::CorrelatorNameCol.column(), 1);
        assert_eq!(ColumnDescription::OptionsCol.column(), 2);

        assert_eq!(ColumnDescription::CorrelatorClassCol.column_field(), FieldType::String);
        assert_eq!(ColumnDescription::CorrelatorNameCol.column_field(), FieldType::String);
        assert_eq!(ColumnDescription::OptionsCol.column_field(), FieldType::String);

        assert_eq!(
            ColumnDescription::column_names(),
            vec!["CORRELATOR_CLASS_COL", "CORRELATOR_NAME_COL", "OPTIONS_COL"]
        );
    }

    #[test]
    fn table_schema_has_three_columns_and_long_key() {
        let schema = VTMatchSetTableDBAdapterBase::table_schema();
        assert_eq!(schema.get_version(), 0);
        assert_eq!(schema.get_key_type(), FieldType::Long);
        assert_eq!(schema.get_key_name(), "Key");
        assert_eq!(schema.get_field_count(), 3);
        assert_eq!(schema.get_field_name(2), "OPTIONS_COL");
    }

    struct MockCorrelator;
    impl VTProgramCorrelator for MockCorrelator {
        fn correlate(
            &self,
            _session: &dyn crate::feature::vt::api::main::vt_session::VTSession,
            _monitor: &dyn TaskMonitor,
        ) -> io::Result<Box<dyn crate::feature::vt::api::main::vt_match_set::VTMatchSet>> {
            Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
        }
        fn get_name(&self) -> String {
            "Exact Match Correlator".to_string()
        }
        fn get_options(&self) -> Box<dyn ToolOptions> {
            struct NoOptions;
            impl ToolOptions for NoOptions {
                fn get_option(&self, _key: &str) -> Option<String> {
                    None
                }
            }
            Box::new(NoOptions)
        }
        fn get_source_address_set(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_source_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            panic!("not needed by these tests")
        }
        fn get_destination_program(
            &self,
        ) -> Arc<dyn crate::program::model::listing::program::Program> {
            panic!("not needed by these tests")
        }
        fn get_destination_address_set(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
    }

    #[test]
    fn create_adapter_then_create_and_read_back_match_set_record() {
        let db_handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = VTMatchSetTableDBAdapterBase::create_adapter(db_handle).unwrap();

        let key = adapter.get_next_match_set_id();
        assert_eq!(key, 0);

        let correlator = MockCorrelator;
        let record = adapter.create_match_set_record(key, &correlator).unwrap();
        assert_eq!(record.get_key().get_long_value(), 0);
        assert_eq!(
            record.get_string(ColumnDescription::CorrelatorNameCol.column()),
            Some("Exact Match Correlator")
        );

        let fetched = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(
            fetched.get_string(ColumnDescription::CorrelatorNameCol.column()),
            Some("Exact Match Correlator")
        );

        let mut iter = adapter.get_records().unwrap();
        let mut count = 0;
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn get_next_match_set_id_increments_across_calls() {
        let db_handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = VTMatchSetTableDBAdapterBase::create_adapter(db_handle).unwrap();

        assert_eq!(adapter.get_next_match_set_id(), 0);
        assert_eq!(adapter.get_next_match_set_id(), 1);
        assert_eq!(adapter.get_next_match_set_id(), 2);
    }

    #[test]
    fn get_record_for_missing_key_returns_none() {
        let db_handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = VTMatchSetTableDBAdapterBase::create_adapter(db_handle).unwrap();

        assert!(adapter.get_record(42).unwrap().is_none());
    }

    #[test]
    fn address_set_lookup_for_missing_table_returns_none() {
        let db_handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let adapter = VTMatchSetTableDBAdapterBase::create_adapter(db_handle).unwrap();

        let key = adapter.get_next_match_set_id();
        let record = adapter
            .create_match_set_record(key, &MockCorrelator)
            .unwrap();

        struct StubAddressMap;
        impl AddressMap for StubAddressMap {
            fn get_key(&self, _addr: &crate::program::model::address::Address, _create: bool) -> i64 {
                0
            }
            fn get_absolute_encoding(
                &self,
                _addr: &crate::program::model::address::Address,
                _create: bool,
            ) -> i64 {
                0
            }
            fn find_key_range(
                &self,
                _key_range_list: &[crate::program::model::address::KeyRange],
                _addr: Option<&crate::program::model::address::Address>,
            ) -> i32 {
                -1
            }
            fn decode_address(&self, _value: i64) -> crate::program::model::address::Address {
                panic!("not needed by this test")
            }
            fn get_address_factory(
                &self,
            ) -> Option<Arc<dyn crate::program::model::address::AddressFactory>> {
                None
            }
            fn get_key_ranges_absolute(
                &self,
                _start: &crate::program::model::address::Address,
                _end: &crate::program::model::address::Address,
                _absolute: bool,
                _create: bool,
            ) -> Vec<crate::program::model::address::KeyRange> {
                Vec::new()
            }
            fn get_key_ranges_for_set_absolute(
                &self,
                _set: Option<&dyn AddressSetView>,
                _absolute: bool,
                _create: bool,
            ) -> Vec<crate::program::model::address::KeyRange> {
                Vec::new()
            }
            fn get_old_address_map(&self) -> Box<dyn AddressMap> {
                panic!("not needed by this test")
            }
            fn is_upgraded(&self) -> bool {
                false
            }
            fn get_image_base(&self) -> crate::program::model::address::Address {
                panic!("not needed by this test")
            }
        }

        let address_map = StubAddressMap;
        assert!(adapter
            .get_source_address_set(&record, &address_map)
            .unwrap()
            .is_none());
        assert!(adapter
            .get_destination_address_set(&record, &address_map)
            .unwrap()
            .is_none());
    }
}
