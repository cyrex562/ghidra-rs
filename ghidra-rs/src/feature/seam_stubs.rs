//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

pub use crate::program::model::address::Address as AddressType;

use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
use crate::feature::vt::api::main::vt_score::VtScore;
use crate::framework::remote::User;

/// Placeholder for the unported Java type `VTAssociation`, referenced by `VTAssociationManager` and `AssociationHook`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait VtAssociation: Send + Sync {
    fn get_type(&self) -> Box<dyn VtAssociationType>;

    /// Java: `VTAssociationDB.getSession()`. Returns the real, already-ported `VTSession`
    /// (`crate::feature::vt::api::main::vt_session::VTSession`) rather than the minimal local
    /// [`VtSession`] stub below, which predates that port and is now stale for this purpose.
    fn get_session(&self) -> Box<dyn crate::feature::vt::api::main::vt_session::VTSession>;

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

    /// Java: `DBObject.getKey()`, inherited by the concrete `VTAssociationDB`. Defaulted (so
    /// existing/mock implementors keep compiling) since not every `VtAssociation` implementor
    /// backs a database row.
    ///
    /// Grown for
    /// [`VTMatchMarkupItemTableDBAdapterV0`](crate::feature::vt::api::main::db::vt_match_markup_item_table_db_adapter_v0::VTMatchMarkupItemTableDBAdapterV0)'s
    /// port of `VTMatchMarkupItemTableDBAdapterV0.createMarkupItemRecord`.
    fn get_key(&self) -> i64 {
        unimplemented!("VtAssociation::get_key not available on this implementor")
    }
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

/// Placeholder for the unported Java type `VTMatchSetTableDBAdapterV0`, referenced by
/// `VTMatchSetTableDBAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_match_set_table_db_adapter`. `VTMatchSetTableDBAdapterV0`
/// is a concrete Java class (not an interface), so this stub is a struct that implements the real
/// `VTMatchSetTableDBAdapter` trait using already-ported `Table`/`DBHandle` machinery.
///
/// Two simplifications versus the real Java `VTMatchSetTableDBAdapterV0`:
///   - `CORRELATOR_CLASS_COL` stores the correlator's display name (`get_name()`) rather than a
///     reflected Java class name, since `VTProgramCorrelator` (the already-ported trait) has no
///     class-name accessor.
///   - `create_match_set_record` does not persist the source/destination address-range sub-tables
///     that the Java version writes via `program.getAddressMap()`, since the ported `Program`
///     trait does not yet expose an address map accessor; `get_source_address_set` /
///     `get_destination_address_set` still read those tables back correctly if/when something
///     populates them.
/// Replace with the real port when `VTMatchSetTableDBAdapterV0.java` is ported.
pub struct VTMatchSetTableDBAdapterV0 {
    db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTMatchSetTableDBAdapterV0 {
    pub fn create(
        db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
        table_name: &str,
        schema: std::sync::Arc<crate::framework::db::Schema>,
    ) -> std::io::Result<Self> {
        let table = db_handle
            .write()
            .unwrap()
            .create_table(table_name.to_string(), schema)?;
        Ok(Self { db_handle, table })
    }

    pub fn open(
        db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
        table_name: &str,
    ) -> Result<Self, crate::util::exception::VersionException> {
        let table = {
            let dbh = db_handle.read().unwrap();
            dbh.get_table(table_name).ok_or_else(|| {
                crate::util::exception::VersionException::with_message(format!(
                    "Missing Table: {table_name}"
                ))
            })?
        };
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(crate::util::exception::VersionException::with_message(format!(
                "Expected version 0 for table {table_name} but got {version}"
            )));
        }
        Ok(Self { db_handle, table })
    }

    fn source_table_name(record: &crate::framework::db::DBRecord) -> String {
        format!("Source Address Set {}", record.get_key().get_long_value())
    }

    fn destination_table_name(record: &crate::framework::db::DBRecord) -> String {
        format!("Destination Address Set {}", record.get_key().get_long_value())
    }

    fn read_address_set(
        &self,
        table_name: &str,
        address_map: &dyn crate::program::database::map::address_map::AddressMap,
    ) -> std::io::Result<Option<crate::program::model::address::AddressSet>> {
        let addr_table = {
            let dbh = self.db_handle.read().unwrap();
            match dbh.get_table(table_name) {
                Some(t) => t,
                None => return Ok(None),
            }
        };

        let mut address_set = crate::program::model::address::AddressSet::new();
        let table = addr_table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            let addr1 = address_map.decode_address(rec.get_long(0).unwrap_or(0));
            let addr2 = address_map.decode_address(rec.get_long(1).unwrap_or(0));
            address_set.add_range(&addr1, &addr2);
        }
        Ok(Some(address_set))
    }
}

impl crate::feature::vt::api::main::db::vt_match_set_table_db_adapter::VTMatchSetTableDBAdapter
    for VTMatchSetTableDBAdapterV0
{
    fn create_match_set_record(
        &self,
        key: i64,
        correlator: &dyn crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator,
    ) -> std::io::Result<crate::framework::db::DBRecord> {
        use crate::feature::vt::api::main::db::vt_match_set_table_db_adapter::ColumnDescription;

        let mut table = self.table.write().unwrap();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        record.set_string(
            ColumnDescription::CorrelatorClassCol.column(),
            Some(correlator.get_name()),
        );
        record.set_string(
            ColumnDescription::CorrelatorNameCol.column(),
            Some(correlator.get_name()),
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

    fn get_source_address_set(
        &self,
        record: &crate::framework::db::DBRecord,
        address_map: &dyn crate::program::database::map::address_map::AddressMap,
    ) -> std::io::Result<Option<crate::program::model::address::AddressSet>> {
        self.read_address_set(&Self::source_table_name(record), address_map)
    }

    fn get_destination_address_set(
        &self,
        record: &crate::framework::db::DBRecord,
        address_map: &dyn crate::program::database::map::address_map::AddressMap,
    ) -> std::io::Result<Option<crate::program::model::address::AddressSet>> {
        self.read_address_set(&Self::destination_table_name(record), address_map)
    }

    fn get_next_match_set_id(&self) -> i64 {
        self.table.write().unwrap().get_next_key()
    }

    fn get_record(&self, key: i64) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&crate::framework::db::Field::Long(Some(key)))
    }
}

/// Placeholder for the unported Java type `VTAssociationTableDBAdapterV0`, referenced by
/// `VTAssociationTableDBAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_association_table_db_adapter`.
/// `VTAssociationTableDBAdapterV0` is a concrete Java class (not an interface), so this stub is a
/// struct that implements the real `VTAssociationTableDBAdapter` trait using already-ported
/// `Table`/`DBHandle` machinery. `getRecordsForSourceAddress`/`getRecordsForDestinationAddress`
/// use `Table.indexIterator` in the real Java implementation; since the ported `Table` has no
/// field-index support yet, these scan and filter instead (same simplification already used by
/// `VTMatchTableDBAdapterV0::get_records_for_association` above). Replace with the real port when
/// `VTAssociationTableDBAdapterV0.java` is ported.
pub struct VTAssociationTableDBAdapterV0 {
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTAssociationTableDBAdapterV0 {
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

    fn scan_by_long_column(
        &self,
        column: usize,
        value: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            if record.get_long(column) == Some(value) {
                records.push(record);
            }
        }
        Ok(records)
    }
}

impl crate::feature::vt::api::main::db::vt_association_table_db_adapter::VTAssociationTableDBAdapter
    for VTAssociationTableDBAdapterV0
{
    fn insert_record(
        &self,
        source_address_id: i64,
        destination_address_id: i64,
        association_type: crate::feature::vt::api::main::vt_association_type::VtAssociationType,
        status: crate::feature::vt::api::main::vt_association_status::VtAssociationStatus,
        vote_count: i32,
    ) -> std::io::Result<crate::framework::db::DBRecord> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;
        use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
        use crate::feature::vt::api::main::vt_association_type::VtAssociationType;

        // Java: `type.ordinal()` / `lockedStatus.ordinal()`. Neither ported enum exposes an
        // `ordinal()` accessor, so the enum-declaration order is mirrored here by hand.
        let type_ordinal: i8 = match association_type {
            VtAssociationType::Function => 0,
            VtAssociationType::Data => 1,
        };
        let status_ordinal: i8 = match status {
            VtAssociationStatus::Available => 0,
            VtAssociationStatus::Accepted => 1,
            VtAssociationStatus::Blocked => 2,
            VtAssociationStatus::Rejected => 3,
        };

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        record.set_long(ColumnDescription::SourceAddressCol.column(), source_address_id);
        record.set_long(ColumnDescription::DestinationAddressCol.column(), destination_address_id);
        record.set_byte(ColumnDescription::TypeCol.column(), type_ordinal);
        record.set_byte(ColumnDescription::StatusCol.column(), status_ordinal);
        record.set_int(ColumnDescription::VoteCountCol.column(), vote_count);

        table.put_record(record.clone())?;
        Ok(record)
    }

    fn delete_record(&self, key: i64) -> std::io::Result<()> {
        self.table
            .write()
            .unwrap()
            .delete_record(&crate::framework::db::Field::Long(Some(key)))?;
        Ok(())
    }

    fn get_records_for_source_address(
        &self,
        address_id: i64,
    ) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let records =
            self.scan_by_long_column(ColumnDescription::SourceAddressCol.column(), address_id)?;
        Ok(Box::new(VecRecordIterator { records: records.into_iter() }))
    }

    fn get_records_for_destination_address(
        &self,
        address_id: i64,
    ) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let records = self
            .scan_by_long_column(ColumnDescription::DestinationAddressCol.column(), address_id)?;
        Ok(Box::new(VecRecordIterator { records: records.into_iter() }))
    }

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }

    fn get_records(&self) -> std::io::Result<Box<dyn crate::framework::db::RecordIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            records.push(record);
        }
        Ok(Box::new(VecRecordIterator { records: records.into_iter() }))
    }

    fn get_record(&self, key: i64) -> std::io::Result<Option<crate::framework::db::DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&crate::framework::db::Field::Long(Some(key)))
    }

    fn get_related_association_records_by_source_and_destination_address(
        &self,
        source_address_id: i64,
        destination_address_id: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let mut records =
            self.scan_by_long_column(ColumnDescription::SourceAddressCol.column(), source_address_id)?;
        records.extend(self.scan_by_long_column(
            ColumnDescription::DestinationAddressCol.column(),
            destination_address_id,
        )?);
        dedupe_records_by_key(&mut records);
        Ok(records)
    }

    fn get_related_association_records_by_source_address(
        &self,
        source_address_id: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let mut records =
            self.scan_by_long_column(ColumnDescription::SourceAddressCol.column(), source_address_id)?;
        dedupe_records_by_key(&mut records);
        Ok(records)
    }

    fn get_related_association_records_by_destination_address(
        &self,
        destination_address_id: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        use crate::feature::vt::api::main::db::vt_association_table_db_adapter::ColumnDescription;

        let mut records = self.scan_by_long_column(
            ColumnDescription::DestinationAddressCol.column(),
            destination_address_id,
        )?;
        dedupe_records_by_key(&mut records);
        Ok(records)
    }

    fn update_record(&self, record: &crate::framework::db::DBRecord) -> std::io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_association(&self, id: i64) -> std::io::Result<()> {
        self.table
            .write()
            .unwrap()
            .delete_record(&crate::framework::db::Field::Long(Some(id)))?;
        Ok(())
    }
}

/// Java: `HashSet<DBRecord>` construction, where `DBRecord.equals()`/`hashCode()` compare by key
/// (see `db.DBRecord`). Deduplicates by primary key, which is equivalent here since two records
/// sharing a key are necessarily the same row.
fn dedupe_records_by_key(records: &mut Vec<crate::framework::db::DBRecord>) {
    let mut seen = std::collections::HashSet::new();
    records.retain(|r| seen.insert(r.get_key().get_long_value()));
}

/// Placeholder for the unported Java type `VTAddressCorrelationAdapterV0`, referenced by
/// `VTAddressCorrelatorAdapterBase::create_adapter`/`get_adapter` in
/// `crate::feature::vt::api::main::db::vt_address_correlator_adapter`.
/// `VTAddressCorrelationAdapterV0` is a concrete Java class (not an interface), so this stub is a
/// struct that implements the real `VTAddressCorrelatorAdapter` trait using already-ported
/// `Table`/`DBHandle` machinery. Replace with the real port when
/// `VTAddressCorrelationAdapterV0.java` is ported.
pub struct VTAddressCorrelationAdapterV0 {
    base: crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapterBase,
    table: std::sync::Arc<std::sync::RwLock<crate::framework::db::Table>>,
}

impl VTAddressCorrelationAdapterV0 {
    pub fn create(
        db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
        table_name: &str,
        schema: std::sync::Arc<crate::framework::db::Schema>,
    ) -> std::io::Result<Self> {
        let table = db_handle
            .write()
            .unwrap()
            .create_table(table_name.to_string(), schema)?;
        Ok(Self {
            base: crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapterBase::new(db_handle),
            table,
        })
    }

    pub fn open(
        db_handle: std::sync::Arc<std::sync::RwLock<crate::framework::db::DBHandle>>,
        table_name: &str,
    ) -> Result<Self, crate::util::exception::VersionException> {
        let table = {
            let dbh = db_handle.read().unwrap();
            dbh.get_table(table_name).ok_or_else(|| {
                crate::util::exception::VersionException::with_message(format!(
                    "Missing Table: {table_name}"
                ))
            })?
        };
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(crate::util::exception::VersionException::with_message(format!(
                "Expected version 0 for table {table_name} but got {version}"
            )));
        }
        Ok(Self {
            base: crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapterBase::new(db_handle),
            table,
        })
    }
}

impl crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapter
    for VTAddressCorrelationAdapterV0
{
    fn base(
        &self,
    ) -> &crate::feature::vt::api::main::db::vt_address_correlator_adapter::VTAddressCorrelatorAdapterBase
    {
        &self.base
    }

    fn create_address_record(
        &self,
        _source_entry_long: i64,
        source_long: i64,
        destination_long: i64,
    ) -> std::io::Result<()> {
        use crate::feature::vt::api::main::db::vt_address_correlator_adapter::ColumnDescription;

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let schema = table.get_schema();
        let mut record = crate::framework::db::DBRecord::new(
            schema,
            crate::framework::db::Field::Long(Some(key)),
        );
        // Faithful port of the Java source: SOURCE_ENTRY_COL is populated with `source_long`,
        // not `source_entry_long` -- see `VTAddressCorrelationAdapterV0.createAddressRecord`.
        record.set_long(ColumnDescription::SourceEntryCol.column(), source_long);
        record.set_long(ColumnDescription::SourceAddressCol.column(), source_long);
        record.set_long(ColumnDescription::DestinationAddressCol.column(), destination_long);

        table.put_record(record)
    }

    fn get_address_records(
        &self,
        source_entry_long: i64,
    ) -> std::io::Result<Vec<crate::framework::db::DBRecord>> {
        use crate::feature::vt::api::main::db::vt_address_correlator_adapter::ColumnDescription;

        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            if record.get_long(ColumnDescription::SourceEntryCol.column()) == Some(source_entry_long)
            {
                records.push(record);
            }
        }
        Ok(records)
    }
}


/// Placeholder for the unported Java type `EolCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). `EolCommentMarkupType`
/// is a concrete Java class (not an interface), so this is a unit struct rather than a trait.
/// Trimmed to implementing the already-ported [`VtMarkupType`] trait with the display name read
/// off the Java constructor (`super("EOL Comment")`), since that is all the factory needs.
/// Replace with the real port when `EolCommentMarkupType.java` is ported.
pub struct EolCommentMarkupType;

impl VtMarkupType for EolCommentMarkupType {
    fn get_name(&self) -> &str {
        "EOL Comment"
    }
}

/// Placeholder for the unported Java type `FunctionNameMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `FunctionNameMarkupType.java` is ported.
pub struct FunctionNameMarkupType;

impl VtMarkupType for FunctionNameMarkupType {
    fn get_name(&self) -> &str {
        "Function Name"
    }
}

/// Placeholder for the unported Java type `FunctionSignatureMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `FunctionSignatureMarkupType.java` is ported.
pub struct FunctionSignatureMarkupType;

impl VtMarkupType for FunctionSignatureMarkupType {
    fn get_name(&self) -> &str {
        "Function Signature"
    }
}

/// Placeholder for the unported Java type `LabelMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `LabelMarkupType.java` is ported.
pub struct LabelMarkupType;

impl VtMarkupType for LabelMarkupType {
    fn get_name(&self) -> &str {
        "Label"
    }
}

/// Placeholder for the unported Java type `PlateCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `PlateCommentMarkupType.java` is ported.
pub struct PlateCommentMarkupType;

impl VtMarkupType for PlateCommentMarkupType {
    fn get_name(&self) -> &str {
        "Plate Comment"
    }
}

/// Placeholder for the unported Java type `PostCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `PostCommentMarkupType.java` is ported.
pub struct PostCommentMarkupType;

impl VtMarkupType for PostCommentMarkupType {
    fn get_name(&self) -> &str {
        "Post Comment"
    }
}

/// Placeholder for the unported Java type `PreCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `PreCommentMarkupType.java` is ported.
pub struct PreCommentMarkupType;

impl VtMarkupType for PreCommentMarkupType {
    fn get_name(&self) -> &str {
        "Pre Comment"
    }
}

/// Placeholder for the unported Java type `RepeatableCommentMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `RepeatableCommentMarkupType.java` is ported.
pub struct RepeatableCommentMarkupType;

impl VtMarkupType for RepeatableCommentMarkupType {
    fn get_name(&self) -> &str {
        "Repeatable Comment"
    }
}

/// Placeholder for the unported Java type `DataTypeMarkupType`, referenced by
/// [`VTMarkupTypeFactory`](crate::feature::vt::api::markuptype::vt_markup_type_factory). See
/// [`EolCommentMarkupType`] for the trimming rationale. Replace with the real port when
/// `DataTypeMarkupType.java` is ported.
pub struct DataTypeMarkupType;

impl VtMarkupType for DataTypeMarkupType {
    fn get_name(&self) -> &str {
        "Data Type"
    }
}

/// Placeholder for the unported Java type `ghidra.app.util.dialog.CheckoutDialog`, referenced by
/// `do_optional_destination_program_checkout` in
/// [`vt_session_file_util`](crate::feature::vt::api::util::vt_session_file_util). Minimal
/// placeholder: only the members that call site needs. The real `CheckoutDialog` blocks on a
/// Swing modal dialog asking the user whether to check out a file; this port has no GUI to show
/// one, so [`show_dialog`](Self::show_dialog) always reports [`CANCEL`](Self::CANCEL) and no
/// checkout is ever attempted. Replace with the real port once a GUI layer exists.
pub struct CheckoutDialog {
    pub path_name: String,
    pub user: Option<User>,
}

impl CheckoutDialog {
    pub const CHECKOUT: i32 = 0;
    pub const CANCEL: i32 = 1;

    pub fn new(path_name: String, user: Option<User>) -> Self {
        Self { path_name, user }
    }

    pub fn show_dialog(&self) -> i32 {
        Self::CANCEL
    }

    pub fn exclusive_checkout(&self) -> bool {
        false
    }
}
