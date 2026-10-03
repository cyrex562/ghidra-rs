use std::io;
use std::sync::{Arc, RwLock};

use super::buffer_mgr::BufferMgr;
use super::field::{Field, FieldType};
use super::table::Table;
use super::table_record::TableRecord;
use super::table_statistics::TableStatistics;
use crate::util::exception::AssertException;

/// Maintains a secondary index within a private [`Table`] instance. This index facilitates the
/// indexing of non-unique secondary keys within a user table.
///
/// Port of the package-private `abstract class db.IndexTable`. Its abstract methods
/// (`findPrimaryKeys`, `getKeyCount`, `addEntry`, `deleteEntry`, and every `indexIterator`/
/// `keyIterator*` overload) are already fully represented by the
/// [`super::field_index_table::FieldIndexTable`] trait (ported earlier this session as an
/// object-safe cycle cut-point, since `FieldIndexTable` is the sole concrete subclass of
/// `IndexTable` in the real codebase). This struct instead ports the *concrete* shared state and
/// behavior `IndexTable` itself defines: the fields every subclass inherits, plus the non-abstract
/// methods. Per this crate's composition-over-inheritance convention, a concrete
/// `FieldIndexTable`-trait implementor is expected to hold one of these as a field (mirroring
/// `extends IndexTable`) rather than this port trying to fake trait-based inheritance.
///
/// # Static factories not ported
/// Java's `static IndexTable getIndexTable(DBHandle, TableRecord)` and `static IndexTable
/// createIndexTable(Table, int)` factories both unconditionally construct a `new
/// FieldIndexTable(...)` (the only concrete subclass). Since no concrete `FieldIndexTable` struct
/// exists yet in this port (see that trait's own doc comment), there is nothing for either
/// factory to construct, and they are omitted rather than faked -- a documented capability gap,
/// consistent with this crate's established pattern (e.g. `TableRecord`'s `table`-linkage gap).
/// `getIndexTable`'s dynamic dispatch on `indexTableRecord.getSchema().getKeyFieldType()
/// instanceof IndexField` also has no reachable equivalent here regardless, since this port's
/// [`super::schema::Schema`] models key types as the bare [`FieldType`] enum rather than boxed
/// `Field` instances (no distinct `IndexField` case of its own -- see `table_record.rs`'s own note
/// on the same limitation).
///
/// # `primaryTable.addIndex(this)` not ported
/// Java's constructor also calls `primaryTable.addIndex(this)`, registering the new index so that
/// writes to the primary table automatically propagate into every registered index's
/// `addEntry`/`deleteEntry`. This port's [`Table`] has no registered-index list or write-path
/// hook to call into (a capability gap: wiring it in would require `Table`'s `put_record`/
/// `delete_record` to fan out into arbitrary `Box<dyn FieldIndexTable>` entries, which is out of
/// scope for this port), so no such registration happens here; callers must invoke
/// `add_entry`/`delete_entry` on a `FieldIndexTable` implementor themselves.
pub struct IndexTable {
    /// Master table record for this index table. Mirrors `IndexTable.indexTableRecord`.
    index_table_record: TableRecord,

    /// Primary table being indexed. Mirrors `IndexTable.primaryTable`.
    primary_table: Arc<RwLock<Table>>,

    /// Underlying table which contains secondary index data. Mirrors `IndexTable.indexTable`.
    index_table: Table,

    /// Indexed column within the primary table schema. Mirrors `IndexTable.indexColumn`.
    index_column: usize,

    /// Mirrors `IndexTable.isSparseIndex`.
    is_sparse_index: bool,
}

impl IndexTable {
    /// Construct a new or existing secondary index. An existing index must have its root ID
    /// specified within `index_table_record`.
    ///
    /// Mirrors `IndexTable(Table, TableRecord)`. Panics with an [`AssertException`] message if
    /// `primary_table` uses neither long nor fixed-length keys, mirroring Java's `throw new
    /// AssertException("Only fixed-length key tables may be indexed")` (an unchecked exception,
    /// translated to a panic per this crate's established convention -- see e.g.
    /// `data_utilities.rs`'s `panic!("{}", AssertException::with_cause(e))`).
    pub fn new(
        primary_table: Arc<RwLock<Table>>,
        index_table_record: TableRecord,
        buffer_mgr: Arc<RwLock<BufferMgr>>,
    ) -> io::Result<Self> {
        let (schema, use_long, use_fixed) = {
            let pt = primary_table.read().unwrap();
            let schema = pt.get_schema();
            (schema.clone(), schema.use_long_key_nodes(), schema.use_fixed_key_nodes())
        };
        if !use_long && !use_fixed {
            panic!(
                "{}",
                AssertException::with_message("Only fixed-length key tables may be indexed")
            );
        }

        let index_column = index_table_record.get_indexed_column() as usize;
        let is_sparse_index = schema.is_sparse_column(index_column);

        let index_table_schema = index_table_record
            .get_schema()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "index table record has no schema")
            })?
            .clone();
        let index_table =
            Table::new(index_table_record.get_name().to_string(), Arc::new(index_table_schema), buffer_mgr);

        Ok(Self { index_table_record, primary_table, index_table, index_column, is_sparse_index })
    }

    /// Check the consistency of this index table.
    ///
    /// Mirrors `IndexTable.isConsistent(TaskMonitor)`. This port's [`Table`] is a simplified,
    /// `BTreeMap`-backed store with no B-tree node structure to validate (see `table.rs`'s own
    /// "Fallback for tests" comments), so there is nothing to detect: this always reports
    /// consistent, rather than fabricating a monitor-driven traversal Java's real B-tree
    /// implementation performs.
    pub fn is_consistent(&self) -> io::Result<bool> {
        Ok(true)
    }

    /// Get the primary table's key type. Mirrors `IndexTable.getPrimaryTableKeyType()`.
    ///
    /// Real Java returns a representative `Field` instance (`schema.getKeyFieldType()`); this
    /// port's [`super::schema::Schema`] models the key type as a bare [`FieldType`] instead (see
    /// this struct's top-level doc comment on the same `IndexField` limitation).
    pub fn get_primary_table_key_type(&self) -> FieldType {
        self.primary_table.read().unwrap().get_schema().get_key_type()
    }

    /// Get the table number associated with the underlying index table. Mirrors
    /// `IndexTable.getTableNum()`.
    pub fn get_table_num(&self) -> i64 {
        self.index_table_record.get_table_num()
    }

    /// Get the indexed column within the primary table schema. Mirrors
    /// `IndexTable.getColumnIndex()`.
    pub fn get_column_index(&self) -> i32 {
        self.index_column as i32
    }

    /// Whether the indexed column uses sparse storage. Mirrors `IndexTable.isSparseIndex` (a bare
    /// field in Java with no dedicated getter, but exposed here since subclasses/composers need
    /// it and this port has no `protected` visibility to lean on).
    pub fn is_sparse_index(&self) -> bool {
        self.is_sparse_index
    }

    /// Get index table statistics. Mirrors `IndexTable.getStatistics()`.
    pub fn get_statistics(&self) -> io::Result<TableStatistics> {
        let mut stats = TableStatistics::new();
        stats.name = self.index_table.get_name().to_string();
        stats.index_column = self.get_column_index();
        stats.record_node_cnt = self.index_table.get_record_count() as i32;
        Ok(stats)
    }

    /// Determine if there is an occurrence of the specified index key value. Mirrors
    /// `IndexTable.hasRecord(Field)`.
    pub fn has_record(&self, field: &Field) -> io::Result<bool> {
        Ok(self.index_table.has_record(field))
    }

    /// Delete all records within this index table. Mirrors `IndexTable.deleteAll()`.
    pub fn delete_all(&mut self) -> io::Result<()> {
        self.index_table.clear_all()
    }

    /// Direct access to the underlying index-data storage table, for a composing
    /// `FieldIndexTable` implementor to read/write index entries through. Not present as a
    /// distinct Java accessor (Java's subclass inherits `protected Table indexTable` directly);
    /// needed here since this port uses composition instead of inheritance.
    pub fn index_table(&self) -> &Table {
        &self.index_table
    }

    /// Mutable access to the underlying index-data storage table. See [`Self::index_table`].
    pub fn index_table_mut(&mut self) -> &mut Table {
        &mut self.index_table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer_mgr::BufferMgr;
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::schema::Schema;

    fn primary_schema() -> Schema {
        Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Int],
            vec!["Value".to_string()],
            vec![],
        )
    }

    fn index_schema() -> Schema {
        Schema::new(
            1,
            FieldType::Long,
            "IndexKey".to_string(),
            vec![],
            vec![],
            vec![],
        )
    }

    fn make_index_table() -> (IndexTable, Arc<RwLock<BufferMgr>>) {
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(BufferMgr::DEFAULT_BUFFER_SIZE)));
        let primary_table =
            Arc::new(RwLock::new(Table::new("Primary".to_string(), Arc::new(primary_schema()), buffer_mgr.clone())));
        let index_table_record = TableRecord::new(1, "Primary".to_string(), index_schema(), 0);
        let it = IndexTable::new(primary_table, index_table_record, buffer_mgr.clone()).unwrap();
        (it, buffer_mgr)
    }

    #[test]
    fn test_new_populates_fields_from_table_record() {
        let (it, _bm) = make_index_table();
        assert_eq!(it.get_table_num(), 1);
        assert_eq!(it.get_column_index(), 0);
        assert!(!it.is_sparse_index());
        assert_eq!(it.get_primary_table_key_type(), FieldType::Long);
    }

    #[test]
    #[should_panic(expected = "Only fixed-length key tables may be indexed")]
    fn test_new_rejects_non_fixed_non_long_primary_key() {
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(BufferMgr::DEFAULT_BUFFER_SIZE)));
        // A String-keyed table uses neither long nor fixed-length key nodes.
        let bad_schema = Schema::new(
            1,
            FieldType::String,
            "Name".to_string(),
            vec![],
            vec![],
            vec![],
        );
        let primary_table =
            Arc::new(RwLock::new(Table::new("Primary".to_string(), Arc::new(bad_schema), buffer_mgr.clone())));
        let index_table_record = TableRecord::new(1, "Primary".to_string(), index_schema(), 0);
        let _ = IndexTable::new(primary_table, index_table_record, buffer_mgr);
    }

    #[test]
    fn test_has_record_and_delete_all_delegate_to_index_storage() {
        let (mut it, _bm) = make_index_table();
        let key = Field::Long(Some(5));
        assert!(!it.has_record(&key).unwrap());

        let schema = Arc::new(index_schema());
        let rec = DBRecord::new(schema, key.clone());
        it.index_table_mut().put_record(rec).unwrap();

        assert!(it.has_record(&key).unwrap());
        assert_eq!(it.index_table().get_record_count(), 1);

        it.delete_all().unwrap();
        assert!(!it.has_record(&key).unwrap());
        assert_eq!(it.index_table().get_record_count(), 0);
    }

    #[test]
    fn test_get_statistics_reflects_index_storage() {
        let (mut it, _bm) = make_index_table();
        let schema = Arc::new(index_schema());
        it.index_table_mut().put_record(DBRecord::new(schema.clone(), Field::Long(Some(1)))).unwrap();
        it.index_table_mut().put_record(DBRecord::new(schema, Field::Long(Some(2)))).unwrap();

        let stats = it.get_statistics().unwrap();
        assert_eq!(stats.name, "Primary");
        assert_eq!(stats.index_column, 0);
        assert_eq!(stats.record_node_cnt, 2);
    }

    #[test]
    fn test_is_consistent_always_true_for_this_ports_simplified_table() {
        let (it, _bm) = make_index_table();
        assert!(it.is_consistent().unwrap());
    }
}
