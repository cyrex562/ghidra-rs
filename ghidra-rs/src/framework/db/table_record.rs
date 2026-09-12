use super::db_handle::DBHandle;
use super::field::{Field, FieldType, UnsupportedFieldException};
use super::nodes::node_mgr::NodeMgr;
use super::record::DBRecord;
use super::schema::Schema;
use super::table::Table;
use std::cmp::Ordering;
use std::sync::{Arc, RwLock};

const NAME_COLUMN: usize = 0;
const VERSION_COLUMN: usize = 1;
const BUFFER_ID_COLUMN: usize = 2;
const KEY_TYPE_COLUMN: usize = 3;
const FIELD_TYPES_COLUMN: usize = 4;
const FIELD_NAMES_COLUMN: usize = 5;
const COLUMN_INDEXED_COLUMN: usize = 6;
const MAX_KEY_COLUMN: usize = 7;
const RECORD_COUNT_COLUMN: usize = 8;

/// Build the storage [`Schema`] used for the master-table record that backs every
/// [`TableRecord`]. Mirrors the static `Schema schema = new Schema(0, "TableNum", fields,
/// tableRecordFieldNames)` field initializer in Java.
///
/// Java builds this once as a shared `static` `Schema` (an implementation-detail optimization);
/// this port instead builds a fresh, equivalent `Schema` on demand (from
/// [`TableRecord::table_record_schema`] and every constructor), which is observably identical
/// since `Schema` here carries no mutable identity callers rely on sharing.
fn build_table_record_schema() -> Schema {
    Schema::new(
        0,
        FieldType::Long,
        "TableNum".to_string(),
        vec![
            FieldType::String, // name of table
            FieldType::Int,    // Schema version
            FieldType::Int,    // Root buffer ID (first buffer)
            FieldType::Byte,   // Key field type
            FieldType::Binary, // Schema field types
            FieldType::String, // Schema key/field names
            FieldType::Int,    // indexing column (-1 = primary)
            FieldType::Long,   // max primary key value ever used
            FieldType::Int,    // number of records
        ],
        vec![
            "TableName".to_string(),
            "SchemaVersion".to_string(),
            "RootBufferId".to_string(),
            "KeyType".to_string(),
            "FieldTypes".to_string(),
            "FieldNames".to_string(),
            "IndexColumn".to_string(),
            "MaxKey".to_string(),
            "RecordCount".to_string(),
        ],
        vec![],
    )
}

/// Manages information about a table. Each `TableRecord` corresponds to a stored record within
/// the master table.
///
/// Port of `db.TableRecord`, a package-private `class TableRecord implements
/// Comparable<TableRecord>`.
///
/// # `table` linkage
/// Java holds a `Table table` field purely so [`Self::set_record`]/[`Self::invalidate`] can
/// notify a live `Table` instance (`table.tableRecordChanged()`/`table.invalidate()`) when the
/// master-table record backing it changes or is deleted. This port's [`Table`] does not yet
/// expose either hook (it has no notion of a master-table-driven cache invalidation callback), so
/// `table` is retained here for shape/API parity (the presence/absence distinction
/// [`Self::set_table`]/[`Self::invalidate`] establish is still meaningful bookkeeping for this
/// struct itself) but the Java-side notification calls are simply not there to make -- a capability
/// gap, documented rather than silently pretended away.
///
/// # Post-`invalidate()` access
/// Mirroring Java (where `record`/`tableSchema` become `null` and most accessors have no
/// null-guard, so using this instance further raises a `NullPointerException`), most accessors
/// below `.expect()` a present record and will panic if called after [`Self::invalidate`].
/// [`Self::get_record`], [`Self::get_schema`], and [`Self::get_record_count`] instead return
/// `Option`/a defaulted value, mirroring the specific Java methods that are written to tolerate
/// (or, for `getRecordCount()`, explicitly null-check for) a `null` record.
pub struct TableRecord {
    record: Option<DBRecord>,
    table_schema: Option<Schema>,
    table: Option<Arc<RwLock<Table>>>,
}

impl TableRecord {
    /// Construct a new master table record.
    ///
    /// `table_num` -- table number assigned by the master table.
    /// `name` -- table name (index tables use the same name as the indexed table).
    /// `table_schema` -- table schema.
    /// `indexed_column` -- primary table index key column, or -1 for a primary table.
    ///
    /// Mirrors `TableRecord(long, String, Schema, int)`.
    pub fn new(table_num: i64, name: String, table_schema: Schema, indexed_column: i32) -> Self {
        let mut record = DBRecord::new(Arc::new(build_table_record_schema()), Field::Long(Some(table_num)));
        record.set_field(NAME_COLUMN, Field::String(Some(name)));
        record.set_field(
            KEY_TYPE_COLUMN,
            Field::Byte(Some(table_schema.get_encoded_key_field_type() as i8)),
        );
        record.set_field(
            FIELD_TYPES_COLUMN,
            Field::Binary(Some(table_schema.get_encoded_field_types())),
        );
        record.set_field(
            FIELD_NAMES_COLUMN,
            Field::String(Some(table_schema.get_packed_field_names())),
        );
        record.set_field(VERSION_COLUMN, Field::Int(Some(table_schema.get_version())));
        record.set_field(COLUMN_INDEXED_COLUMN, Field::Int(Some(indexed_column)));
        record.set_field(MAX_KEY_COLUMN, Field::Long(Some(i64::MIN)));
        record.set_field(RECORD_COUNT_COLUMN, Field::Int(Some(0)));
        record.set_field(BUFFER_ID_COLUMN, Field::Int(Some(-1))); // first buffer not yet allocated

        Self { record: Some(record), table_schema: Some(table_schema), table: None }
    }

    /// Construct an existing master table storage record.
    ///
    /// `dbh` -- database handle.
    /// `record` -- master table storage record.
    ///
    /// Mirrors `TableRecord(DBHandle, DBRecord)`.
    ///
    /// # Errors
    /// Returns an error if the stored schema contains an unsupported field.
    pub fn from_stored(dbh: &DBHandle, record: DBRecord) -> Result<Self, UnsupportedFieldException> {
        let table_schema = Self::parse_schema(dbh, &record)?;
        Ok(Self { record: Some(record), table_schema: Some(table_schema), table: None })
    }

    /// Get the underlying storage record for this instance, or `None` if this instance has been
    /// [`invalidate`](Self::invalidate)d. Mirrors `TableRecord.getRecord()`.
    pub fn get_record(&self) -> Option<&DBRecord> {
        self.record.as_ref()
    }

    /// Set the table instance associated with this master table record. Mirrors
    /// `TableRecord.setTable(Table)`.
    pub fn set_table(&mut self, table: Arc<RwLock<Table>>) {
        self.table = Some(table);
    }

    /// Set the storage record for this instance. Data is refreshed from the record provided.
    /// Mirrors `TableRecord.setRecord(DBHandle, DBRecord)`.
    ///
    /// # Errors
    /// Returns an error if the stored schema contains an unsupported field.
    pub fn set_record(&mut self, dbh: &DBHandle, record: DBRecord) -> Result<(), UnsupportedFieldException> {
        let table_schema = Self::parse_schema(dbh, &record)?;
        self.table_schema = Some(table_schema);
        self.record = Some(record);
        // Java: `if (table != null) table.tableRecordChanged();` -- see this struct's doc
        // comment for why that notification has no equivalent to make here.
        Ok(())
    }

    /// Mark this instance as invalid. This method should be invoked if the associated master
    /// table record is deleted. Mirrors `TableRecord.invalidate()`.
    pub fn invalidate(&mut self) {
        // Java: `if (table != null) { table.invalidate(); table = null; }` -- see this struct's
        // doc comment for why `Table::invalidate()` has no equivalent to call here.
        self.table = None;
        self.record = None;
        self.table_schema = None;
    }

    /// Get the table number. Mirrors `TableRecord.getTableNum()`.
    ///
    /// # Panics
    /// Panics if called after [`Self::invalidate`], mirroring Java's `NullPointerException` from
    /// `record.getKey()` on a `null` record.
    pub fn get_table_num(&self) -> i64 {
        self.record().get_key().get_long_value()
    }

    /// Get the table name. Mirrors `TableRecord.getName()`.
    ///
    /// # Panics
    /// Panics if called after [`Self::invalidate`] (see [`Self::get_table_num`]).
    pub fn get_name(&self) -> &str {
        self.record().get_field(NAME_COLUMN).get_string_value().unwrap_or("")
    }

    /// Set the table name. Mirrors `TableRecord.setName(String)`.
    ///
    /// # Panics
    /// Panics if called after [`Self::invalidate`] (see [`Self::get_table_num`]).
    pub fn set_name(&mut self, name: String) {
        self.record_mut().set_field(NAME_COLUMN, Field::String(Some(name)));
    }

    /// Get the table schema, or `None` if this instance has been [`invalidate`](Self::invalidate)d.
    /// Mirrors `TableRecord.getSchema()`.
    pub fn get_schema(&self) -> Option<&Schema> {
        self.table_schema.as_ref()
    }

    /// Get the table's root buffer ID. Mirrors `TableRecord.getRootBufferId()`.
    ///
    /// # Panics
    /// Panics if called after [`Self::invalidate`] (see [`Self::get_table_num`]).
    pub fn get_root_buffer_id(&self) -> i32 {
        self.record().get_field(BUFFER_ID_COLUMN).get_int_value()
    }

    /// Set the table's root buffer ID. Mirrors `TableRecord.setRootBufferId(int)`.
    ///
    /// # Panics
    /// Panics if called after [`Self::invalidate`] (see [`Self::get_table_num`]).
    pub fn set_root_buffer_id(&mut self, id: i32) {
        self.record_mut().set_field(BUFFER_ID_COLUMN, Field::Int(Some(id)));
    }

    /// Get the table's maximum long key value. Mirrors `TableRecord.getMaxKey()`.
    ///
    /// # Panics
    /// Panics if called after [`Self::invalidate`] (see [`Self::get_table_num`]).
    pub fn get_max_key(&self) -> i64 {
        self.record().get_field(MAX_KEY_COLUMN).get_long_value()
    }

    /// Set the table's maximum long key value. Mirrors `TableRecord.setMaxKey(long)`.
    ///
    /// # Panics
    /// Panics if called after [`Self::invalidate`] (see [`Self::get_table_num`]).
    pub fn set_max_key(&mut self, max_key: i64) {
        self.record_mut().set_field(MAX_KEY_COLUMN, Field::Long(Some(max_key)));
    }

    /// Get the table's current record count, or `0` if this instance has been
    /// [`invalidate`](Self::invalidate)d. Mirrors `TableRecord.getRecordCount()`'s explicit
    /// `record == null ? 0 : ...` null-check.
    pub fn get_record_count(&self) -> i32 {
        self.record.as_ref().map_or(0, |r| r.get_field(RECORD_COUNT_COLUMN).get_int_value())
    }

    /// Set the table's current record count. Mirrors `TableRecord.setRecordCount(int)`.
    ///
    /// # Panics
    /// Panics if called after [`Self::invalidate`] (see [`Self::get_table_num`]).
    pub fn set_record_count(&mut self, count: i32) {
        self.record_mut().set_field(RECORD_COUNT_COLUMN, Field::Int(Some(count)));
    }

    /// Get the column number which is indexed by this table. A value of -1 indicates that this
    /// is the primary table indexed by a long key value; positive values name a secondary index
    /// table's indexed column within the primary table. Mirrors
    /// `TableRecord.getIndexedColumn()`.
    ///
    /// # Panics
    /// Panics if called after [`Self::invalidate`] (see [`Self::get_table_num`]).
    pub fn get_indexed_column(&self) -> i32 {
        self.record().get_field(COLUMN_INDEXED_COLUMN).get_int_value()
    }

    /// Get the master table record storage schema. Mirrors the static
    /// `TableRecord.getTableRecordSchema()`.
    pub fn table_record_schema() -> Schema {
        build_table_record_schema()
    }

    fn record(&self) -> &DBRecord {
        self.record.as_ref().expect("TableRecord used after invalidate()")
    }

    fn record_mut(&mut self) -> &mut DBRecord {
        self.record.as_mut().expect("TableRecord used after invalidate()")
    }

    /// Mirrors `TableRecord.parseSchema(DBHandle, DBRecord)`.
    fn parse_schema(dbh: &DBHandle, record: &DBRecord) -> Result<Schema, UnsupportedFieldException> {
        let version = record.get_field(VERSION_COLUMN).get_int_value();
        let key_type_byte = record.get_field(KEY_TYPE_COLUMN).get_int_value() as u8;
        let field_types_bytes =
            record.get_field(FIELD_TYPES_COLUMN).get_binary_data().unwrap_or(&[]).to_vec();
        let field_names_packed =
            record.get_field(FIELD_NAMES_COLUMN).get_string_value().unwrap_or("").to_string();

        let mut table_schema =
            Schema::from_encoded(version, key_type_byte, &field_types_bytes, &field_names_packed)?;

        let root_buffer_id = record.get_field(BUFFER_ID_COLUMN).get_int_value();
        Self::force_use_of_variable_length_key_nodes_if_needed(dbh, &mut table_schema, root_buffer_id);
        Ok(table_schema)
    }

    /// Determine if legacy schema should be forced to use `VarKeyNode` table storage for
    /// compatibility. Mirrors `TableRecord.forceUseOfVariableLengthKeyNodesIfNeeded(DBHandle,
    /// Schema, int)`.
    ///
    /// Java's version can raise `IOException` (from reading the root buffer to check its stored
    /// node type). This port's [`NodeMgr::is_var_key_node`] never actually fails (see its own doc
    /// comment on why it is currently a conservative always-`false` stub), so this function has
    /// no error to propagate and does not return a `Result`.
    fn force_use_of_variable_length_key_nodes_if_needed(
        dbh: &DBHandle,
        table_schema: &mut Schema,
        root_buffer_id: i32,
    ) {
        if root_buffer_id < 0 {
            return;
        }
        let key_type = table_schema.get_key_type();
        if key_type.is_variable_length() {
            return;
        }
        // Java also excludes `LongField`, `IndexField`, and `FixedField` key types here. This
        // port's `Schema` models column/key types as the bare `FieldType` enum rather than boxed
        // `Field` instances, which has no distinct `IndexField` case of its own (see
        // `index_field.rs`), so only the `Long`/`Fixed` exclusions have a reachable equivalent.
        if matches!(key_type, FieldType::Long | FieldType::Fixed(_)) {
            return;
        }
        if NodeMgr::is_var_key_node(&dbh.get_buffer_mgr(), root_buffer_id).unwrap_or(false) {
            table_schema.force_use_of_variable_length_key_nodes();
        }
    }
}

impl PartialEq for TableRecord {
    fn eq(&self, other: &Self) -> bool {
        self.get_table_num() == other.get_table_num()
    }
}

impl Eq for TableRecord {}

impl PartialOrd for TableRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Compares the key associated with this table record with the key of another table record.
/// Mirrors `TableRecord.compareTo(TableRecord)`.
impl Ord for TableRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_table_num().cmp(&other.get_table_num())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_schema() -> Schema {
        Schema::new(
            2,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String, FieldType::Int],
            vec!["Name".to_string(), "Count".to_string()],
            vec![],
        )
    }

    #[test]
    fn test_new_populates_expected_defaults() {
        let tr = TableRecord::new(5, "MyTable".to_string(), sample_schema(), -1);
        assert_eq!(tr.get_table_num(), 5);
        assert_eq!(tr.get_name(), "MyTable");
        assert_eq!(tr.get_root_buffer_id(), -1);
        assert_eq!(tr.get_max_key(), i64::MIN);
        assert_eq!(tr.get_record_count(), 0);
        assert_eq!(tr.get_indexed_column(), -1);
        let schema = tr.get_schema().unwrap();
        assert_eq!(schema.get_version(), 2);
        assert_eq!(schema.get_key_type(), FieldType::Long);
        assert_eq!(schema.get_field_count(), 2);
    }

    #[test]
    fn test_setters_round_trip() {
        let mut tr = TableRecord::new(1, "T".to_string(), sample_schema(), -1);
        tr.set_name("Renamed".to_string());
        tr.set_root_buffer_id(42);
        tr.set_max_key(1000);
        tr.set_record_count(7);

        assert_eq!(tr.get_name(), "Renamed");
        assert_eq!(tr.get_root_buffer_id(), 42);
        assert_eq!(tr.get_max_key(), 1000);
        assert_eq!(tr.get_record_count(), 7);
    }

    #[test]
    fn test_round_trip_through_stored_record() {
        let dbh = DBHandle::new().unwrap();
        let original = TableRecord::new(9, "Indexed".to_string(), sample_schema(), 3);
        let stored_record = original.get_record().unwrap().clone();

        let restored = TableRecord::from_stored(&dbh, stored_record).unwrap();
        assert_eq!(restored.get_table_num(), 9);
        assert_eq!(restored.get_name(), "Indexed");
        assert_eq!(restored.get_indexed_column(), 3);
        let schema = restored.get_schema().unwrap();
        assert_eq!(schema.get_version(), 2);
        assert_eq!(schema.get_field_count(), 2);
        assert_eq!(schema.get_field_name(0), "Name");
    }

    #[test]
    fn test_invalidate_clears_state_and_get_record_count_defaults_to_zero() {
        let mut tr = TableRecord::new(1, "T".to_string(), sample_schema(), -1);
        tr.set_record_count(3);
        tr.invalidate();
        assert!(tr.get_record().is_none());
        assert!(tr.get_schema().is_none());
        assert_eq!(tr.get_record_count(), 0);
    }

    #[test]
    #[should_panic(expected = "TableRecord used after invalidate()")]
    fn test_get_table_num_panics_after_invalidate() {
        let mut tr = TableRecord::new(1, "T".to_string(), sample_schema(), -1);
        tr.invalidate();
        tr.get_table_num();
    }

    #[test]
    fn test_ordering_matches_table_num() {
        let a = TableRecord::new(1, "A".to_string(), sample_schema(), -1);
        let b = TableRecord::new(2, "B".to_string(), sample_schema(), -1);
        assert!(a < b);
        assert_eq!(a.cmp(&a), Ordering::Equal);
    }

    #[test]
    fn test_table_record_schema_matches_java_field_layout() {
        let schema = TableRecord::table_record_schema();
        assert_eq!(schema.get_key_name(), "TableNum");
        assert_eq!(schema.get_field_count(), 9);
        assert_eq!(schema.get_field_name(0), "TableName");
        assert_eq!(schema.get_field_name(8), "RecordCount");
    }

    #[test]
    fn test_set_table_and_invalidate_clear_linkage() {
        let dbh = DBHandle::new().unwrap();
        let schema = Arc::new(sample_schema());
        let mut dbh2 = dbh;
        let table = dbh2.create_table("Linked".to_string(), schema).unwrap();

        let mut tr = TableRecord::new(1, "T".to_string(), sample_schema(), -1);
        tr.set_table(table);
        tr.invalidate();
        // After invalidate(), the record/schema are gone even though we can't observe the
        // (nonexistent, in this port) Table-side notification directly.
        assert!(tr.get_record().is_none());
    }
}
