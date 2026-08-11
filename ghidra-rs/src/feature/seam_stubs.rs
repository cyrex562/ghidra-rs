//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

pub use crate::program::model::address::Address as AddressType;

use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
use crate::feature::vt::api::main::vt_score::VtScore;

/// Placeholder for the unported Java type `VTAssociation`, referenced by `VTAssociationManager` and `AssociationHook`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait VtAssociation: Send + Sync {
    fn get_type(&self) -> Box<dyn VtAssociationType>;
    fn get_session(&self) -> Box<dyn VtSession>;
    fn get_markup_items(&self, monitor: &dyn TaskMonitor) -> std::io::Result<Vec<Box<dyn VtMarkupItem>>>;
    fn has_applied_markup_items(&self) -> bool;
    fn get_source_address(&self) -> AddressType;
    fn get_destination_address(&self) -> AddressType;
    fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>>;
    fn set_markup_status(&self, markup_items_status: &dyn VtAssociationMarkupStatus);
    fn get_markup_status(&self) -> Box<dyn VtAssociationMarkupStatus>;
    fn get_status(&self) -> Box<dyn VtAssociationStatus>;
    fn set_accepted(&self) -> std::io::Result<()>;
    fn clear_status(&self) -> std::io::Result<()>;
    fn set_rejected(&self) -> std::io::Result<()>;
    fn get_vote_count(&self) -> i32;
    fn set_vote_count(&self, vote_count: i32);
}

/// Placeholder for the unported Java type `VTMarkupItem`, referenced by `AssociationHook`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait VtMarkupItem: Send + Sync {
    fn can_apply(&self) -> bool;
    fn can_unapply(&self) -> bool;
    fn apply(&self, apply_action: &dyn VtMarkupItemApplyActionType, options: &dyn ToolOptions) -> std::io::Result<()>;
    fn unapply(&self) -> std::io::Result<()>;
    fn set_default_destination_address(&self, address: &AddressType, address_source: &str);
    fn set_destination_address(&self, address: &AddressType);
    fn get_destination_address_edit_status(&self) -> Box<dyn VtMarkupItemDestinationAddressEditStatus>;
    fn set_considered(&self, status: &dyn VtMarkupItemConsideredStatus);
    fn get_status(&self) -> Box<dyn VtMarkupItemStatus>;
    fn get_status_description(&self) -> String;
    fn get_association(&self) -> Box<dyn VtAssociation>;
    fn get_source_address(&self) -> AddressType;
    fn get_source_location(&self) -> Box<dyn ProgramLocation>;
    fn get_source_value(&self) -> Box<dyn Stringable>;
    fn get_destination_address(&self) -> AddressType;
    fn get_destination_location(&self) -> Box<dyn ProgramLocation>;
    fn get_destination_address_source(&self) -> String;
    fn get_current_destination_value(&self) -> Box<dyn Stringable>;
    fn get_original_destination_value(&self) -> Box<dyn Stringable>;
    fn supports_apply_action(&self, action_type: &dyn VtMarkupItemApplyActionType) -> bool;
    fn get_markup_type(&self) -> Box<dyn VtMarkupType>;
}

/// Placeholder for `VTAssociationType`.
pub trait VtAssociationType: Send + Sync {
    fn display_name(&self) -> &str;
}

/// Placeholder for `VTSession`.
pub trait VtSession: Send + Sync {
    fn get_name(&self) -> &str;
}

/// Placeholder for `TaskMonitor`.
pub trait TaskMonitor: Send + Sync {
    fn check_cancelled(&self) -> std::io::Result<()>;
}

/// Placeholder for `VTMarkupItemStatus`.
pub trait VtMarkupItemStatus: Send + Sync {
    fn is_applied(&self) -> bool;
}

/// Placeholder for `VTAssociationMarkupStatus`.
pub trait VtAssociationMarkupStatus: Send + Sync {
    fn get_status(&self) -> &str;
}

/// Placeholder for `VTAssociationStatus`.
pub trait VtAssociationStatus: Send + Sync {
    fn get_status(&self) -> &str;
}

/// Placeholder for `VTMarkupItemApplyActionType`.
pub trait VtMarkupItemApplyActionType: Send + Sync {
    fn get_name(&self) -> &str;
}

/// Placeholder for `ToolOptions`.
pub trait ToolOptions: Send + Sync {
    fn get_option(&self, key: &str) -> Option<String>;
}

/// Placeholder for `VTMarkupItemDestinationAddressEditStatus`.
pub trait VtMarkupItemDestinationAddressEditStatus: Send + Sync {
    fn is_editable(&self) -> bool;
}

/// Placeholder for `VTMarkupItemConsideredStatus`.
pub trait VtMarkupItemConsideredStatus: Send + Sync {
    fn is_considered(&self) -> bool;
}

/// Placeholder for `ProgramLocation`.
pub trait ProgramLocation: Send + Sync {
    fn get_address(&self) -> AddressType;
}

/// Placeholder for `Stringable`.
pub trait Stringable: Send + Sync {
    fn to_string(&self) -> String;
}

/// Placeholder for `VTMarkupType`.
pub trait VtMarkupType: Send + Sync {
    fn get_name(&self) -> &str;
}

/// Placeholder for the unported Java type `VTMatch`, referenced by `VTSession`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait VtMatch: Send + Sync {
    fn get_match_set(&self) -> Box<dyn VtMatchSet>;
    fn get_association(&self) -> Box<dyn VtAssociation>;
    fn get_tag(&self) -> VtMatchTag;
    fn set_tag(&self, tag: VtMatchTag);
    fn get_similarity_score(&self) -> VtScore;
    fn get_confidence_score(&self) -> VtScore;
    fn get_source_address(&self) -> AddressType;
    fn get_destination_address(&self) -> AddressType;
    fn get_source_length(&self) -> i32;
    fn get_destination_length(&self) -> i32;
}

/// Placeholder for the unported Java type `VTMatchInfo`, referenced by `VTMatchSet::add_match`.
/// `VTMatchInfo` is a concrete Java class (not an interface), so this stub is a struct rather
/// than a trait. Generated stub: shape hint only, no fields yet since nothing in the crate reads
/// them. Replace with the real port when available.
#[derive(Debug, Default, Clone)]
pub struct VtMatchInfo;

/// Placeholder for the unported Java type `VTMatchSet`, referenced by `VTSession`.
/// Generated stub: only a shape hint. `add_match`/`get_program_correlator_info` are omitted
/// pending ports of `VTMatchInfo`/`VTProgramCorrelatorInfo`, which have no known shape yet.
/// Replace with the real port when available.
pub trait VtMatchSet: Send + Sync {
    fn get_session(&self) -> Box<dyn VtSession>;
    fn get_matches(&self) -> Vec<Box<dyn VtMatch>>;
    fn get_match_count(&self) -> i32;
    fn get_id(&self) -> i32;
    fn delete_match(&self, match_item: &dyn VtMatch);
    fn remove_match(&self, match_item: &dyn VtMatch) -> bool;
    fn has_removable_matches(&self) -> bool;
}

/// Placeholder for the unported Java type `VTOptions`, referenced by `VTProgramCorrelatorFactory`.
/// `VTOptions` is a concrete Java class (not an interface), so this stub is a struct rather than a
/// trait. Generated stub: shape hint only, no fields yet since nothing in the crate reads them.
/// Replace with the real port when available.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct VtOptions;

/// Placeholder for the unported Java type `VTMatchTagDBAdapterV0`, referenced by
/// `VTMatchTagDBAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_match_tag_db_adapter`. `VTMatchTagDBAdapterV0` is a
/// concrete Java class (not an interface), so this stub is a struct that implements the real
/// `VTMatchTagDBAdapter` trait using already-ported `Table`/`DBHandle` machinery. Replace with the
/// real port when `VTMatchTagDBAdapterV0.java` is ported.
pub struct VTMatchTagDBAdapterV0 {
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTMatchTagDBAdapterV0 {
    pub fn create(
        db_handle: &mut crate::framework::db::DBHandle,
        table_name: &str,
        schema: std::sync::Arc<crate::framework::db::Schema>,
    ) -> std::io::Result<Self> {
        let table = db_handle.create_table(table_name.to_string(), schema)?;
        Ok(Self { table })
    }

    pub fn open(
        db_handle: &crate::framework::db::DBHandle,
        table_name: &str,
    ) -> Result<Self, crate::util::exception::VersionException> {
        let table = db_handle.get_table(table_name).ok_or_else(|| {
            crate::util::exception::VersionException::with_message(format!(
                "Missing Table: {table_name}"
            ))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(crate::util::exception::VersionException::with_message(format!(
                "Expected version 0 for table {table_name} but got {version}"
            )));
        }
        Ok(Self { table })
    }
}

/// Placeholder for the unported Java type `VTMatchInfo`, referenced by
/// `VTMatchTableDBAdapter::insert_match_record`. Trimmed to the accessors that
/// `VTMatchTableDBAdapterV0.insertMatchRecord` actually reads (similarity/confidence score,
/// source/destination length); see `VTMatchInfo.java` for the type's full public surface.
/// Replace with the real port when available.
pub trait VTMatchInfo: Send + Sync {
    fn get_similarity_score(&self) -> crate::feature::vt::api::main::vt_score::VtScore;
    fn get_confidence_score(&self) -> crate::feature::vt::api::main::vt_score::VtScore;
    fn get_source_length(&self) -> i32;
    fn get_destination_length(&self) -> i32;
}

/// Placeholder for the unported Java type `VTMatchSetDB`, referenced by
/// `VTMatchTableDBAdapter::insert_match_record`. The parameter is unused by
/// `VTMatchTableDBAdapterV0.insertMatchRecord` in the real Java implementation, so this stub
/// carries no members. Replace with the real port when available.
pub trait VTMatchSetDB: Send + Sync {}

/// Placeholder for the unported Java type `VTAssociationDB`, referenced by
/// `VTMatchTableDBAdapter::insert_match_record`. Trimmed to `get_key`, the (inherited
/// `DBAnnotatedObject`) accessor that `VTMatchTableDBAdapterV0.insertMatchRecord` actually reads;
/// see `VTAssociationDB.java` for the type's full public surface. Replace with the real port when
/// available.
pub trait VTAssociationDB: Send + Sync {
    fn get_key(&self) -> i64;
}

/// Placeholder for the unported Java type `VTMatchTagDB`, referenced by
/// `VTMatchTableDBAdapter::insert_match_record`. Trimmed to `get_key`, the (inherited
/// `DBAnnotatedObject`) accessor that `VTMatchTableDBAdapterV0.insertMatchRecord` actually reads;
/// see `VTMatchTagDB.java` for the type's full public surface. Replace with the real port when
/// available.
pub trait VTMatchTagDB: Send + Sync {
    fn get_key(&self) -> i64;
}

/// Placeholder for the unported Java type `VTMatchTableDBAdapterV0`, referenced by
/// `VTMatchTableDBAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_match_table_db_adapter`. `VTMatchTableDBAdapterV0` is a
/// concrete Java class (not an interface), so this stub is a struct that implements the real
/// `VTMatchTableDBAdapter` trait using already-ported `Table`/`DBHandle` machinery. Replace with
/// the real port when `VTMatchTableDBAdapterV0.java` is ported.
pub struct VTMatchTableDBAdapterV0 {
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTMatchTableDBAdapterV0 {
    pub fn create(
        db_handle: &mut crate::framework::db::DBHandle,
        table_name: &str,
        schema: std::sync::Arc<crate::framework::db::Schema>,
    ) -> std::io::Result<Self> {
        let table = db_handle.create_table(table_name.to_string(), schema)?;
        Ok(Self { table })
    }

    pub fn open(
        db_handle: &crate::framework::db::DBHandle,
        table_name: &str,
    ) -> Result<Self, crate::util::exception::VersionException> {
        let table = db_handle.get_table(table_name).ok_or_else(|| {
            crate::util::exception::VersionException::with_message(format!(
                "Missing Table: {table_name}"
            ))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(crate::util::exception::VersionException::with_message(format!(
                "Expected version 0 for table {table_name} but got {version}"
            )));
        }
        Ok(Self { table })
    }
}

impl crate::feature::vt::api::main::db::vt_match_table_db_adapter::VTMatchTableDBAdapter
    for VTMatchTableDBAdapterV0
{
    fn insert_match_record(
        &self,
        info: &dyn VTMatchInfo,
        _match_set: &dyn VTMatchSetDB,
        association: &dyn VTAssociationDB,
        tag: Option<&dyn VTMatchTagDB>,
    ) -> std::io::Result<crate::framework::db::DBRecord> {
        use crate::feature::vt::api::main::db::vt_match_table_db_adapter::ColumnDescription;

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        record.set_long(ColumnDescription::TagKeyCol.column(), tag.map_or(-1, |t| t.get_key()));
        record.set_string(
            ColumnDescription::SimilarityScoreCol.column(),
            Some(info.get_similarity_score().to_storage_string()),
        );
        record.set_string(
            ColumnDescription::ConfidenceScoreCol.column(),
            Some(info.get_confidence_score().to_storage_string()),
        );
        record.set_long(ColumnDescription::AssociationCol.column(), association.get_key());
        record.set_int(ColumnDescription::SourceLengthCol.column(), info.get_source_length());
        record.set_int(
            ColumnDescription::DestinationLengthCol.column(),
            info.get_destination_length(),
        );

        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_records(&self) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            records.push(record);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_match_record(
        &self,
        match_record_key: i64,
    ) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&crate::framework::db::Field::Long(Some(match_record_key)))
    }

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }

    fn update_record(&self, record: &crate::framework::db::DBRecord) -> std::io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn delete_record(&self, match_record_key: i64) -> std::io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&crate::framework::db::Field::Long(Some(match_record_key)))
    }

    fn get_records_for_association(
        &self,
        association_id: i64,
    ) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        use crate::feature::vt::api::main::db::vt_match_table_db_adapter::ColumnDescription;

        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            if record.get_long(ColumnDescription::AssociationCol.column()) == Some(association_id)
            {
                records.push(record);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }
}

/// Owned (non-borrowing) record iterator used by [`VTMatchTagDBAdapterV0::get_records`], since
/// `Table::get_record_iterator` borrows the `RwLockReadGuard` it is called on.
struct VecRecordIterator {
    records: std::vec::IntoIter<crate::framework::db::DBRecord>,
}

impl crate::framework::db::RecordIterator for VecRecordIterator {
    fn next(&mut self) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        Ok(self.records.next())
    }
    fn has_next(&self) -> bool {
        self.records.len() > 0
    }
}

impl crate::feature::vt::api::main::db::vt_match_tag_db_adapter::VTMatchTagDBAdapter
    for VTMatchTagDBAdapterV0
{
    fn insert_record(&self, tag_name: &str) -> std::io::Result<crate::framework::db::DBRecord> {
        if tag_name.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot create an empty string tag",
            ));
        }

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        record.set_string(
            crate::feature::vt::api::main::db::vt_match_tag_db_adapter::ColumnDescription::TagNameCol
                .column(),
            Some(tag_name.to_string()),
        );
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_records(
        &self,
    ) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            records.push(record);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_record(
        &self,
        tag_record_key: i64,
    ) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&crate::framework::db::Field::Long(Some(tag_record_key)))
    }

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }

    fn update_record(&self, record: &crate::framework::db::DBRecord) -> std::io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn delete_record(&self, tag_record_key: i64) -> std::io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&crate::framework::db::Field::Long(Some(tag_record_key)))
    }
}

