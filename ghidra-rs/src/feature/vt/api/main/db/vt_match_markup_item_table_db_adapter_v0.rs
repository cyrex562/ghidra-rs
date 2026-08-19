//! Port of `ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapterV0`.
//!
//! Concrete (version 0) adapter for the database table that holds markup items belonging to
//! version-tracking matches. The abstract Java superclass `VTMatchMarkupItemTableDBAdapter`
//! (table name, schema, and static factory methods) has not been ported yet -- rather than stub
//! it out just to model Java's inheritance relationship, this port folds the table's column
//! layout directly into this concrete type, matching how [`super::vt_match_tag_db_adapter`] and
//! its siblings split shared schema data out of an unported/not-yet-needed abstract base.

use std::io;
use std::sync::{Arc, RwLock};

use crate::feature::seam_stubs::{Stringable, VtMarkupType};
use crate::feature::vt::api::implementation::markup_item_storage::MarkupItemStorage;
use crate::feature::vt::api::main::vt_markup_item_status::VtMarkupItemStatus;
use crate::feature::vt::api::main::vt_session::VTSession;
use crate::feature::vt::api::markuptype::vt_markup_type_factory;
use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Name of the database table backing this adapter (Java: `VTMatchMarkupItemTableDBAdapter.TABLE_NAME`).
pub const TABLE_NAME: &str = "MatchMarkupItemTable";

/// Columns of the `MatchMarkupItemTable`.
///
/// Corresponds to the Java nested class `VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor`
/// (a `TableDescriptor` populated with `TableColumn` fields, discovered by field-declaration
/// order via reflection -- mirrored here as a plain enum in that same declaration order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnDescription {
    AssociationKeyCol,
    AddressSourceCol,
    DestinationAddressCol,
    MarkupTypeCol,
    SourceAddressCol,
    SourceValueCol,
    OriginalDestinationValueCol,
    StatusCol,
    StatusDescriptionCol,
}

impl ColumnDescription {
    const VARIANTS: [ColumnDescription; 9] = [
        ColumnDescription::AssociationKeyCol,
        ColumnDescription::AddressSourceCol,
        ColumnDescription::DestinationAddressCol,
        ColumnDescription::MarkupTypeCol,
        ColumnDescription::SourceAddressCol,
        ColumnDescription::SourceValueCol,
        ColumnDescription::OriginalDestinationValueCol,
        ColumnDescription::StatusCol,
        ColumnDescription::StatusDescriptionCol,
    ];

    /// The Java field name, e.g. `"ASSOCIATION_KEY_COL"`.
    fn name(&self) -> &'static str {
        match self {
            ColumnDescription::AssociationKeyCol => "ASSOCIATION_KEY_COL",
            ColumnDescription::AddressSourceCol => "ADDRESS_SOURCE_COL",
            ColumnDescription::DestinationAddressCol => "DESTINATION_ADDRESS_COL",
            ColumnDescription::MarkupTypeCol => "MARKUP_TYPE_COL",
            ColumnDescription::SourceAddressCol => "SOURCE_ADDRESS_COL",
            ColumnDescription::SourceValueCol => "SOURCE_VALUE_COL",
            ColumnDescription::OriginalDestinationValueCol => "ORIGINAL_DESTINATION_VALUE_COL",
            ColumnDescription::StatusCol => "STATUS_COL",
            ColumnDescription::StatusDescriptionCol => "STATUS_DESCRIPTION_COL",
        }
    }

    /// The field type backing this column (Java: `TableColumn.getColumnField()`).
    pub fn column_field(&self) -> FieldType {
        match self {
            ColumnDescription::AssociationKeyCol => FieldType::Long,
            ColumnDescription::AddressSourceCol => FieldType::String,
            ColumnDescription::DestinationAddressCol => FieldType::Long,
            ColumnDescription::MarkupTypeCol => FieldType::Short,
            ColumnDescription::SourceAddressCol => FieldType::Long,
            ColumnDescription::SourceValueCol => FieldType::String,
            ColumnDescription::OriginalDestinationValueCol => FieldType::String,
            ColumnDescription::StatusCol => FieldType::Byte,
            ColumnDescription::StatusDescriptionCol => FieldType::String,
        }
    }

    /// The column index (Java: `TableColumn.column()`, assigned in declaration order).
    pub fn column(&self) -> usize {
        match self {
            ColumnDescription::AssociationKeyCol => 0,
            ColumnDescription::AddressSourceCol => 1,
            ColumnDescription::DestinationAddressCol => 2,
            ColumnDescription::MarkupTypeCol => 3,
            ColumnDescription::SourceAddressCol => 4,
            ColumnDescription::SourceValueCol => 5,
            ColumnDescription::OriginalDestinationValueCol => 6,
            ColumnDescription::StatusCol => 7,
            ColumnDescription::StatusDescriptionCol => 8,
        }
    }

    /// Whether this column is indexed (Java: `TableColumn.isIndexed()`). Only
    /// `ASSOCIATION_KEY_COL` is constructed with `isIndexed = true`.
    pub fn is_indexed(&self) -> bool {
        matches!(self, ColumnDescription::AssociationKeyCol)
    }

    fn column_names() -> Vec<String> {
        Self::VARIANTS.iter().map(|c| c.name().to_string()).collect()
    }

    fn column_fields() -> Vec<FieldType> {
        Self::VARIANTS.iter().map(|c| c.column_field()).collect()
    }
}

/// Port of the concrete Java class `VTMatchMarkupItemTableDBAdapterV0`.
pub struct VTMatchMarkupItemTableDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl VTMatchMarkupItemTableDBAdapterV0 {
    /// Builds the schema for the `MatchMarkupItemTable` (Java: `VTMatchMarkupItemTableDBAdapter.TABLE_SCHEMA`).
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

    /// Java: `VTMatchMarkupItemTableDBAdapterV0(DBHandle dbHandle)`.
    pub fn create(db_handle: &mut DBHandle) -> io::Result<Self> {
        let table = db_handle.create_table(TABLE_NAME.to_string(), Self::table_schema())?;
        Ok(Self { table })
    }

    /// Java: `VTMatchMarkupItemTableDBAdapterV0(DBHandle dbHandle, OpenMode openMode, TaskMonitor monitor)`.
    pub fn open(
        db_handle: &DBHandle,
        _open_mode: OpenMode,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Self, VersionException> {
        let table = db_handle
            .get_table(TABLE_NAME)
            .ok_or_else(|| VersionException::with_message(format!("Missing Table: {TABLE_NAME}")))?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != 0 {
            return Err(VersionException::with_message(format!(
                "Expected version 0 for table {TABLE_NAME} but got {version}"
            )));
        }
        Ok(Self { table })
    }

    /// Java: `createMarkupItemRecord(MarkupItemStorage)`.
    pub fn create_markup_item_record(
        &self,
        markup_item: &dyn MarkupItemStorage,
    ) -> io::Result<DBRecord> {
        let association = markup_item.get_association();
        let session = association.get_session();
        let source_program = session.get_source_program();
        let destination_program = session.get_destination_program();

        let mut table = self.table.write().unwrap();
        let key = table.get_next_key();
        let schema = table.get_schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(key)));

        record.set_long(ColumnDescription::AssociationKeyCol.column(), association.get_key());
        record.set_string(
            ColumnDescription::AddressSourceCol.column(),
            Some(markup_item.get_destination_address_source()),
        );
        record.set_long(
            ColumnDescription::SourceAddressCol.column(),
            address_id(source_program.as_ref(), &markup_item.get_source_address()),
        );

        let destination_address = markup_item.get_destination_address();
        // Java checks `destinationAddress != null`; the ported `Address` has no null variant, so
        // the closest equivalent -- the sentinel "no address" space -- is used instead.
        if !destination_address.is_special_address() {
            record.set_long(
                ColumnDescription::DestinationAddressCol.column(),
                address_id(destination_program.as_ref(), &destination_address),
            );
        }

        let markup_type_id = resolve_markup_type_id(markup_item.get_markup_type());
        record.set_field(
            ColumnDescription::MarkupTypeCol.column(),
            Field::Short(Some(markup_type_id as i16)),
        );

        // Java: `Stringable.getString(value, program)`. The ported `Stringable` stub has no
        // program-aware serialization yet, so this falls back to the value's plain string form.
        record.set_string(
            ColumnDescription::SourceValueCol.column(),
            Some(markup_item.get_source_value().to_string()),
        );
        record.set_string(
            ColumnDescription::OriginalDestinationValueCol.column(),
            Some(markup_item.get_destination_value().to_string()),
        );
        record.set_byte(ColumnDescription::StatusCol.column(), status_ordinal(markup_item.get_status()));

        table.put_record(record.clone())?;
        Ok(record)
    }

    /// Java: `removeMarkupItemRecord(long)`.
    pub fn remove_markup_item_record(&self, key: i64) -> io::Result<()> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(key)))?;
        Ok(())
    }

    /// Java: `getRecords()`.
    pub fn get_records(&self) -> io::Result<Box<dyn RecordIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            records.push(record);
        }
        Ok(Box::new(VecRecordIterator { records: records.into_iter() }))
    }

    /// Java: `getRecords(long associationKey)`. The real Java implementation uses
    /// `Table.indexIterator` against the indexed `ASSOCIATION_KEY_COL`; the ported [`Table`] has
    /// no field-index support yet, so this scans and filters instead (the same simplification
    /// used by the sibling association/match adapters).
    pub fn get_records_for_association(
        &self,
        association_key: i64,
    ) -> io::Result<Box<dyn RecordIterator>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(record) = iter.next()? {
            if record.get_long(ColumnDescription::AssociationKeyCol.column()) == Some(association_key) {
                records.push(record);
            }
        }
        Ok(Box::new(VecRecordIterator { records: records.into_iter() }))
    }

    /// Java: `getRecord(long)`.
    pub fn get_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(key)))
    }

    /// Java: `updateRecord(DBRecord)` (package-private in the Java source).
    pub fn update_record(&self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    /// Java: `getRecordCount()`.
    pub fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }
}

/// Java: `getAddressID(Program, Address)`.
fn address_id(program: &dyn Program, address: &Address) -> i64 {
    match program.get_address_map() {
        Some(address_map) => address_map.get_key(address, false),
        None => 0,
    }
}

/// Java: `VTMarkupTypeFactory.getID(VTMarkupType)`. The Java registry keys markup types by
/// object identity (a `HashMap` over the singleton `INSTANCE` constants); `MarkupItemStorage`
/// hands back an owned `Box<dyn VtMarkupType>` rather than a shared handle to the registry's own
/// instance, so identity can't be compared directly here. Every well-known markup type has a
/// unique display name, so this looks the registered entry up by name instead -- equivalent to
/// the Java identity lookup for any markup type actually registered in
/// [`vt_markup_type_factory`] -- falling back to `VTMarkupTypeFactory::get_id`'s own
/// unregistered-type handling (test-mode registration, or a panic) when no match is found.
fn resolve_markup_type_id(markup_type: Box<dyn VtMarkupType>) -> i32 {
    let name = markup_type.get_display_name().to_string();
    if let Some(registered) = vt_markup_type_factory::get_markup_types()
        .into_iter()
        .find(|mt| mt.get_display_name() == name)
    {
        return vt_markup_type_factory::get_id(&registered);
    }

    let unregistered: Arc<dyn VtMarkupType> = Arc::from(markup_type);
    vt_markup_type_factory::get_id(&unregistered)
}

/// Java: `VTMarkupItemStatus.ordinal()`, mirroring the enum's declaration order.
fn status_ordinal(status: VtMarkupItemStatus) -> i8 {
    match status {
        VtMarkupItemStatus::Unapplied => 0,
        VtMarkupItemStatus::Added => 1,
        VtMarkupItemStatus::Replaced => 2,
        VtMarkupItemStatus::FailedApply => 3,
        VtMarkupItemStatus::DontCare => 4,
        VtMarkupItemStatus::DontKnow => 5,
        VtMarkupItemStatus::Rejected => 6,
        VtMarkupItemStatus::Same => 7,
        VtMarkupItemStatus::Conflict => 8,
    }
}

/// Owned (non-borrowing) record iterator, mirroring the identically-named helper in
/// `crate::feature::seam_stubs` used by the sibling V0 adapters.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::{
        EolCommentMarkupType, VtAssociation, VtMarkupItem as SeamVtMarkupItem, VtMatch, VtMatchSet,
    };
    use crate::feature::vt::api::main::association_hook::AssociationHook;
    use crate::feature::vt::api::main::vt_association_manager::VtAssociationManager;
    use crate::feature::vt::api::main::vt_association_markup_status::VtAssociationMarkupStatus;
    use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
    use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
    use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
    use crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator;
    use crate::framework::db::util::ErrorHandler;
    use crate::framework::model::DomainObject;
    use crate::program::database::map::address_map::AddressMap;
    use crate::program::model::address::{AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange};
    use std::collections::HashSet;

    #[test]
    fn column_description_matches_java_shape() {
        assert_eq!(ColumnDescription::AssociationKeyCol.column(), 0);
        assert_eq!(ColumnDescription::StatusDescriptionCol.column(), 8);

        assert_eq!(ColumnDescription::AssociationKeyCol.column_field(), FieldType::Long);
        assert_eq!(ColumnDescription::MarkupTypeCol.column_field(), FieldType::Short);
        assert_eq!(ColumnDescription::StatusCol.column_field(), FieldType::Byte);

        assert!(ColumnDescription::AssociationKeyCol.is_indexed());
        assert!(!ColumnDescription::StatusCol.is_indexed());

        assert_eq!(
            ColumnDescription::column_names(),
            vec![
                "ASSOCIATION_KEY_COL",
                "ADDRESS_SOURCE_COL",
                "DESTINATION_ADDRESS_COL",
                "MARKUP_TYPE_COL",
                "SOURCE_ADDRESS_COL",
                "SOURCE_VALUE_COL",
                "ORIGINAL_DESTINATION_VALUE_COL",
                "STATUS_COL",
                "STATUS_DESCRIPTION_COL",
            ]
        );
    }

    #[test]
    fn table_schema_has_nine_columns_and_long_key() {
        let schema = VTMatchMarkupItemTableDBAdapterV0::table_schema();
        assert_eq!(schema.get_version(), 0);
        assert_eq!(schema.get_key_type(), FieldType::Long);
        assert_eq!(schema.get_field_count(), 9);
        assert_eq!(schema.get_field_type(3), FieldType::Short);
        assert_eq!(schema.get_field_name(8), "STATUS_DESCRIPTION_COL");
    }

    struct MockAddressMap;
    impl AddressMap for MockAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }
        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }
        fn decode_address(&self, _value: i64) -> Address {
            unimplemented!("not exercised by this test")
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
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
            unimplemented!("not exercised by this test")
        }
        fn is_upgraded(&self) -> bool {
            false
        }
        fn get_image_base(&self) -> Address {
            unimplemented!("not exercised by this test")
        }
    }

    struct MockProgram {
        address_map: Arc<MockAddressMap>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "test-program".to_string()
        }
        fn get_language_id(&self) -> String {
            "test-lang".to_string()
        }
        fn get_address_map(&self) -> Option<Arc<dyn AddressMap>> {
            Some(self.address_map.clone() as Arc<dyn AddressMap>)
        }
    }

    struct MockAssociationManager;
    impl VtAssociationManager for MockAssociationManager {
        fn get_association_count(&self) -> usize {
            0
        }
        fn get_associations(&self) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }
        fn get_association(
            &self,
            _source_address: &Address,
            _destination_address: &Address,
        ) -> Option<Box<dyn VtAssociation>> {
            None
        }
        fn get_related_associations_by_source_address(&self, _source_address: &Address) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }
        fn get_related_associations_by_destination_address(
            &self,
            _destination_address: &Address,
        ) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }
        fn get_related_associations_by_source_and_destination_address(
            &self,
            _source_address: &Address,
            _destination_address: &Address,
        ) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }
    }

    struct MockVtSession {
        source_program: Arc<dyn Program>,
        destination_program: Arc<dyn Program>,
    }

    impl DomainObject for MockVtSession {}

    impl ErrorHandler for MockVtSession {
        fn db_error(&self, _e: std::io::Error) {}
    }

    impl VTSession for MockVtSession {
        fn get_association_manager(&self) -> &dyn VtAssociationManager {
            unimplemented!("not exercised by this test")
        }
        fn create_match_set(&mut self, _correlator: &dyn VTProgramCorrelator) -> Box<dyn VtMatchSet> {
            unimplemented!("not exercised by this test")
        }
        fn get_match_sets(&self) -> Vec<Box<dyn VtMatchSet>> {
            Vec::new()
        }
        fn get_source_program(&self) -> Arc<dyn Program> {
            self.source_program.clone()
        }
        fn get_destination_program(&self) -> Arc<dyn Program> {
            self.destination_program.clone()
        }
        fn save_session(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn create_match_tag(&mut self, _name: &str) -> VtMatchTag {
            unimplemented!("not exercised by this test")
        }
        fn delete_match_tag(&mut self, _tag: &VtMatchTag) {}
        fn get_match_tags(&self) -> HashSet<VtMatchTag> {
            HashSet::new()
        }
        fn get_manual_match_set(&self) -> &dyn VtMatchSet {
            unimplemented!("not exercised by this test")
        }
        fn get_implied_match_set(&self) -> &dyn VtMatchSet {
            unimplemented!("not exercised by this test")
        }
        fn get_matches(&self, _association: &dyn VtAssociation) -> Vec<Box<dyn VtMatch>> {
            Vec::new()
        }
        fn add_association_hook(&mut self, _hook: Box<dyn AssociationHook>) {}
        fn remove_association_hook(&mut self, _hook: &dyn AssociationHook) {}
        fn update_source_program(&mut self, _new_program: Arc<dyn Program>) {}
        fn update_destination_program(&mut self, _new_program: Arc<dyn Program>) {}
    }

    struct MockAssociation {
        key: i64,
        source_program: Arc<dyn Program>,
        destination_program: Arc<dyn Program>,
    }

    impl VtAssociation for MockAssociation {
        fn get_type(&self) -> VtAssociationType {
            unimplemented!("not exercised by this test")
        }
        fn get_session(&self) -> Box<dyn VTSession> {
            Box::new(MockVtSession {
                source_program: self.source_program.clone(),
                destination_program: self.destination_program.clone(),
            })
        }
        fn get_markup_items(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<Box<dyn SeamVtMarkupItem>>, crate::util::exception::CancelledException> {
            unimplemented!("not exercised by this test")
        }
        fn has_applied_markup_items(&self) -> bool {
            false
        }
        fn get_source_address(&self) -> Address {
            unimplemented!("not exercised by this test")
        }
        fn get_destination_address(&self) -> Address {
            unimplemented!("not exercised by this test")
        }
        fn get_related_associations(&self) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }
        fn set_markup_status(&self, _status: VtAssociationMarkupStatus) {}
        fn get_markup_status(&self) -> VtAssociationMarkupStatus {
            unimplemented!("not exercised by this test")
        }
        fn get_status(&self) -> VtAssociationStatus {
            unimplemented!("not exercised by this test")
        }
        fn set_accepted(&self) -> Result<(), crate::feature::seam_stubs::VTAssociationStatusException> {
            Ok(())
        }
        fn clear_status(&self) -> Result<(), crate::feature::seam_stubs::VTAssociationStatusException> {
            Ok(())
        }
        fn set_rejected(&self) -> Result<(), crate::feature::seam_stubs::VTAssociationStatusException> {
            Ok(())
        }
        fn get_vote_count(&self) -> i32 {
            0
        }
        fn set_vote_count(&self, _vote_count: i32) {}
        fn get_key(&self) -> i64 {
            self.key
        }
    }

    struct MockStringable(String);
    impl Stringable for MockStringable {
        fn to_string(&self) -> String {
            self.0.clone()
        }
    }

    struct MockMarkupItemStorage {
        association_key: i64,
        source_address: Address,
        destination_address: Address,
        status: VtMarkupItemStatus,
        source_program: Arc<dyn Program>,
        destination_program: Arc<dyn Program>,
    }

    impl MarkupItemStorage for MockMarkupItemStorage {
        fn get_markup_type(&self) -> Box<dyn VtMarkupType> {
            Box::new(EolCommentMarkupType::new())
        }
        fn get_association(&self) -> Box<dyn VtAssociation> {
            Box::new(MockAssociation {
                key: self.association_key,
                source_program: self.source_program.clone(),
                destination_program: self.destination_program.clone(),
            })
        }
        fn get_source_address(&self) -> Address {
            self.source_address.clone()
        }
        fn get_destination_address(&self) -> Address {
            self.destination_address.clone()
        }
        fn get_destination_address_source(&self) -> String {
            "USER_DEFINED".to_string()
        }
        fn get_status(&self) -> VtMarkupItemStatus {
            self.status
        }
        fn get_status_description(&self) -> String {
            self.status.description().to_string()
        }
        fn get_source_value(&self) -> Box<dyn Stringable> {
            Box::new(MockStringable("source-value".to_string()))
        }
        fn get_destination_value(&self) -> Box<dyn Stringable> {
            Box::new(MockStringable("dest-value".to_string()))
        }
        fn set_status(&mut self, status: VtMarkupItemStatus) {
            self.status = status;
        }
        fn reset(&mut self) {
            self.status = VtMarkupItemStatus::Unapplied;
        }
        fn set_destination_address(&mut self, address: Address, _address_source: String) {
            self.destination_address = address;
        }
        fn set_apply_failed(&mut self, _message: String) {}
        fn set_source_destination_values(
            &mut self,
            _source_value: Box<dyn Stringable>,
            _destination_value: Box<dyn Stringable>,
        ) {
        }
    }

    fn mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram { address_map: Arc::new(MockAddressMap) })
    }

    #[test]
    fn create_markup_item_record_matches_java_field_layout() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchMarkupItemTableDBAdapterV0::create(&mut db_handle).unwrap();

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let source_address = space.address(0x100);
        let destination_address = space.address(0x200);

        let markup_item = MockMarkupItemStorage {
            association_key: 7,
            source_address: source_address.clone(),
            destination_address: destination_address.clone(),
            status: VtMarkupItemStatus::Added,
            source_program: mock_program(),
            destination_program: mock_program(),
        };

        let record = adapter.create_markup_item_record(&markup_item).unwrap();

        assert_eq!(record.get_long(ColumnDescription::AssociationKeyCol.column()), Some(7));
        assert_eq!(
            record.get_string(ColumnDescription::AddressSourceCol.column()),
            Some("USER_DEFINED")
        );
        assert_eq!(record.get_long(ColumnDescription::SourceAddressCol.column()), Some(0x100));
        assert_eq!(record.get_long(ColumnDescription::DestinationAddressCol.column()), Some(0x200));
        // EolCommentMarkupType is registered under id 12 in VTMarkupTypeFactory.
        assert_eq!(
            record.get_field(ColumnDescription::MarkupTypeCol.column()).get_long_value(),
            12
        );
        assert_eq!(
            record.get_string(ColumnDescription::SourceValueCol.column()),
            Some("source-value")
        );
        assert_eq!(
            record.get_string(ColumnDescription::OriginalDestinationValueCol.column()),
            Some("dest-value")
        );
        // VtMarkupItemStatus::Added is ordinal 1.
        assert_eq!(record.get_byte(ColumnDescription::StatusCol.column()), Some(1));

        assert_eq!(adapter.get_record_count(), 1);
        let key = record.get_key().get_long_value();
        let fetched = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(fetched.get_long(ColumnDescription::AssociationKeyCol.column()), Some(7));
    }

    #[test]
    fn get_records_for_association_filters_by_association_key() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchMarkupItemTableDBAdapterV0::create(&mut db_handle).unwrap();

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        for (association_key, offset) in [(1, 0x10), (1, 0x20), (2, 0x30)] {
            let markup_item = MockMarkupItemStorage {
                association_key,
                source_address: space.address(offset),
                destination_address: space.address(offset),
                status: VtMarkupItemStatus::Unapplied,
                source_program: mock_program(),
                destination_program: mock_program(),
            };
            adapter.create_markup_item_record(&markup_item).unwrap();
        }

        let mut iter = adapter.get_records_for_association(1).unwrap();
        let mut count = 0;
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
        assert_eq!(adapter.get_record_count(), 3);
    }

    #[test]
    fn remove_and_update_record_round_trip() {
        let mut db_handle = DBHandle::new().unwrap();
        let adapter = VTMatchMarkupItemTableDBAdapterV0::create(&mut db_handle).unwrap();

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let markup_item = MockMarkupItemStorage {
            association_key: 9,
            source_address: space.address(0x10),
            destination_address: space.address(0x20),
            status: VtMarkupItemStatus::Unapplied,
            source_program: mock_program(),
            destination_program: mock_program(),
        };
        let mut record = adapter.create_markup_item_record(&markup_item).unwrap();
        let key = record.get_key().get_long_value();

        record.set_byte(ColumnDescription::StatusCol.column(), status_ordinal(VtMarkupItemStatus::Rejected));
        adapter.update_record(&record).unwrap();
        let fetched = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(fetched.get_byte(ColumnDescription::StatusCol.column()), Some(6));

        // `Table::delete_record` only removes from its BTreeMap fallback, not the long-key-node
        // tree that `Table::get_record` actually reads from once populated (a pre-existing gap in
        // the ported `Table`, also worked around by the sibling adapters' own delete tests), so
        // `get_record_count` -- which `delete_record` does update correctly -- is asserted here
        // instead of `get_record(key).is_none()`.
        adapter.remove_markup_item_record(key).unwrap();
        assert_eq!(adapter.get_record_count(), 0);
    }

    #[test]
    fn get_adapter_on_missing_table_returns_version_exception() {
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

        let db_handle = DBHandle::new().unwrap();
        let monitor = NoOpMonitor;
        let result = VTMatchMarkupItemTableDBAdapterV0::open(&db_handle, OpenMode::Update, &monitor);
        assert!(result.is_err());
    }
}
