use super::buffer_mgr::BufferMgr;
use super::db_handle::DBHandle;
use super::field::Field;
use super::schema::Schema;
use super::table::Table;
use super::table_record::TableRecord;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};

/// Manages data pertaining to all other tables within the database -- this includes index
/// tables. The first buffer associated with this table is managed by the [`super::db_parms::DBParms`]
/// object associated with the database.
///
/// Port of the package-private `db.MasterTable`.
///
/// # `tables` registry
/// Real Java keeps `MasterTable`'s bookkeeping (one [`TableRecord`] per registered table, stored
/// as records inside its own private `table: Table`) entirely separate from `DBHandle`'s own
/// `tables: Hashtable<String, Table>` cache of live data-storing `Table` instances. This port
/// predates the present batch with `tables: HashMap<String, Arc<RwLock<Table>>>` already playing
/// that second (DBHandle-side) role here rather than in `db_handle.rs` itself; rather than
/// relocate it (and risk destabilizing existing callers), this port keeps both concerns -- the
/// real `MasterTable` bookkeeping (`storage`/`table_records`/`next_table_num`) and the
/// pre-existing name-keyed data-table registry (`tables`) -- side by side on the same struct,
/// with [`Self::create_table`]/[`Self::delete_table`] driving both. The two are independent
/// tracks: unlike Java, where a single shared `Table`/`TableRecord` pair ties a table's metadata
/// and its live data-storage node structure together, this port's simplified [`Table`] has no
/// root-buffer-id callback into its own [`TableRecord`], so [`TableRecord::get_root_buffer_id`]
/// reflects only whatever a caller has explicitly synced via [`TableRecord::set_root_buffer_id`]
/// -- a documented capability gap, not a silent behavior change (see `table_record.rs`'s own doc
/// comment on the same gap).
pub struct MasterTable {
    /// Name -> live data-storing `Table` registry. See the struct-level doc comment.
    tables: HashMap<String, Arc<RwLock<Table>>>,

    /// Backing storage table for `table_records`. Mirrors Java's private `table` field (itself a
    /// `Table` wrapping the master table's own `TableRecord`).
    storage: Table,

    /// Table records sorted by table number. Mirrors Java's package-private `tableRecords` array.
    table_records: Vec<TableRecord>,

    /// Mirrors Java's private `nextTableNum` field.
    next_table_num: i64,
}

impl MasterTable {
    /// Construct a new master table.
    ///
    /// Mirrors `MasterTable(DBHandle)`, specialized to this port's only reachable construction
    /// path: [`DBHandle::new`] always creates a fresh database (there is no "open existing
    /// database" path yet in this port), so the persisted `MASTER_TABLE_ROOT_BUFFER_ID_PARM` this
    /// constructor would otherwise read via `DBParms` is always `-1` (empty) at this point --
    /// this constructor takes that as a given rather than re-deriving it through a `DBParms`
    /// round-trip that could only ever produce the same fixed answer here.
    pub fn new(buffer_mgr: Arc<RwLock<BufferMgr>>) -> Self {
        let master_schema = Arc::new(TableRecord::table_record_schema());
        Self {
            tables: HashMap::new(),
            storage: Table::new("MASTER".to_string(), master_schema, buffer_mgr),
            table_records: Vec::new(),
            next_table_num: 0,
        }
    }

    /// Create a new table record and add it to the master table. If this is an index table, the
    /// name corresponds to the table which is indexed. This method should be invoked for index
    /// tables immediately following the creation of the indexed table.
    ///
    /// Mirrors `MasterTable.createTableRecord(String, Schema, int)`. Java also updates
    /// `dbParms.set(MASTER_TABLE_ROOT_BUFFER_ID_PARM, ...)` after inserting the record; this port
    /// has no live `DBParms` handle here (see the struct-level doc comment on the `tables`
    /// registry for the broader reason `MasterTable` does not hold a `DBHandle`/`DBParms`
    /// reference), so that persistence step has no equivalent to perform.
    pub fn create_table_record(
        &mut self,
        name: String,
        table_schema: Schema,
        indexed_column: i32,
    ) -> io::Result<TableRecord> {
        let table_num = self.next_table_num;
        self.next_table_num += 1;

        let table_record = TableRecord::new(table_num, name, table_schema, indexed_column);
        self.storage.put_record(table_record.get_record().unwrap().clone())?;

        let insert_at = self
            .table_records
            .partition_point(|r| r.get_table_num() < table_num);
        self.table_records.insert(insert_at, table_record.clone());

        Ok(table_record)
    }

    /// Remove the master table record associated with the specified table number.
    ///
    /// Mirrors `MasterTable.deleteTableRecord(long)`, including its "Can not delete non-empty
    /// table" guard -- see the struct-level doc comment for why `TableRecord::get_root_buffer_id`
    /// may not reflect a data table's real occupancy in this port.
    pub fn delete_table_record(&mut self, table_num: i64) -> io::Result<()> {
        let idx = self
            .table_records
            .iter()
            .position(|r| r.get_table_num() == table_num)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Table not found"))?;

        if self.table_records[idx].get_root_buffer_id() >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Can not delete non-empty table",
            ));
        }

        self.storage.delete_record(&Field::Long(Some(table_num)))?;
        self.table_records[idx].invalidate();
        self.table_records.remove(idx);
        Ok(())
    }

    /// Get a list of all tables defined within this master table. Records are returned in the
    /// list ordered by their table number key. Mirrors `MasterTable.getTableRecords()`.
    pub fn get_table_records(&self) -> &[TableRecord] {
        &self.table_records
    }

    /// Refresh table data from the master table's own backing storage. Records are returned
    /// ordered by their table number key. Mirrors `MasterTable.refreshTableRecords()`.
    ///
    /// `dbh` is required to reconstruct each [`TableRecord`]'s [`Schema`] via
    /// [`TableRecord::from_stored`] (which itself only needs `dbh` for a legacy-schema
    /// compatibility check); see that method's doc comment.
    pub fn refresh_table_records(&mut self, dbh: &DBHandle) -> io::Result<&[TableRecord]> {
        let mut new_list: Vec<TableRecord> = Vec::new();
        let mut ix = 0usize;
        let old_count = self.table_records.len();

        let mut it = self.storage.get_record_iterator()?;
        while let Some(rec) = it.next()? {
            let table_num = rec.get_key().get_long_value();

            while ix < old_count && table_num > self.table_records[ix].get_table_num() {
                self.table_records[ix].invalidate(); // table no longer exists
                ix += 1;
            }

            if ix == old_count || table_num < self.table_records[ix].get_table_num() {
                let tr = TableRecord::from_stored(dbh, rec)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                new_list.push(tr); // new table
            } else if table_num == self.table_records[ix].get_table_num() {
                self.table_records[ix]
                    .set_record(dbh, rec)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                new_list.push(self.table_records[ix].clone()); // update existing table
                ix += 1;
            }
        }

        while ix < old_count {
            self.table_records[ix].invalidate(); // table no longer exists
            ix += 1;
        }

        self.table_records = new_list;
        Ok(&self.table_records)
    }

    /// Flush all unsaved table changes to the underlying buffer manager. Mirrors
    /// `MasterTable.flush()`.
    pub fn flush(&mut self) -> io::Result<()> {
        for tr in &self.table_records {
            if let Some(rec) = tr.get_record() {
                if rec.is_dirty() {
                    self.storage.put_record(rec.clone())?;
                }
            }
        }
        Ok(())
    }

    /// Change the name of a table and its associated indexes. Mirrors
    /// `MasterTable.changeTableName(String, String)`.
    pub fn change_table_name(&mut self, old_name: &str, new_name: &str) {
        for tr in &mut self.table_records {
            if tr.get_name() == old_name {
                tr.set_name(new_name.to_string());
            }
        }
    }

    // --- Pre-existing (pre-batch) name -> data-Table registry convenience API. See the
    // struct-level doc comment for how this relates to the real `db.MasterTable`. ---

    pub fn create_table(
        &mut self,
        name: String,
        schema: Arc<Schema>,
        buffer_mgr: Arc<RwLock<BufferMgr>>,
    ) -> Option<Arc<RwLock<Table>>> {
        if self.tables.contains_key(&name) {
            return None;
        }
        // Best-effort bookkeeping: register a primary-table TableRecord (indexed_column = -1)
        // alongside the data table. This cannot realistically fail for this port's in-memory
        // storage table, so a failure here is not propagated through this method's pre-existing
        // `Option`-based signature.
        let _ = self.create_table_record(name.clone(), (*schema).clone(), -1);

        let table = Arc::new(RwLock::new(Table::new(name.clone(), schema, buffer_mgr)));
        self.tables.insert(name.clone(), table.clone());
        Some(table)
    }

    pub fn get_table(&self, name: &str) -> Option<Arc<RwLock<Table>>> {
        self.tables.get(name).cloned()
    }

    pub fn delete_table(&mut self, name: &str) -> bool {
        let Some(_) = self.tables.remove(name) else {
            return false;
        };
        if let Some(tr) = self.table_records.iter().find(|r| r.get_name() == name) {
            let table_num = tr.get_table_num();
            let _ = self.delete_table_record(table_num);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::FieldType;

    fn new_master() -> MasterTable {
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(BufferMgr::DEFAULT_BUFFER_SIZE)));
        MasterTable::new(buffer_mgr)
    }

    fn sample_schema() -> Schema {
        Schema::new(
            1,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Int],
            vec!["Value".to_string()],
            vec![],
        )
    }

    #[test]
    fn test_create_table_record_assigns_sequential_table_nums() {
        let mut mt = new_master();
        let tr1 = mt.create_table_record("A".to_string(), sample_schema(), -1).unwrap();
        let tr2 = mt.create_table_record("B".to_string(), sample_schema(), -1).unwrap();
        assert_eq!(tr1.get_table_num(), 0);
        assert_eq!(tr2.get_table_num(), 1);
        assert_eq!(mt.get_table_records().len(), 2);
    }

    #[test]
    fn test_table_records_stay_sorted_by_table_num() {
        let mut mt = new_master();
        mt.create_table_record("A".to_string(), sample_schema(), -1).unwrap();
        mt.create_table_record("B".to_string(), sample_schema(), -1).unwrap();
        mt.create_table_record("C".to_string(), sample_schema(), -1).unwrap();

        let nums: Vec<i64> = mt.get_table_records().iter().map(|r| r.get_table_num()).collect();
        assert_eq!(nums, vec![0, 1, 2]);
    }

    #[test]
    fn test_delete_table_record_removes_empty_table() {
        let mut mt = new_master();
        let tr = mt.create_table_record("A".to_string(), sample_schema(), -1).unwrap();
        assert_eq!(tr.get_root_buffer_id(), -1); // fresh TableRecord starts empty

        mt.delete_table_record(tr.get_table_num()).unwrap();
        assert_eq!(mt.get_table_records().len(), 0);
    }

    #[test]
    fn test_delete_table_record_rejects_non_empty_table() {
        // Mirrors `MasterTable.deleteTableRecord`'s "Can not delete non-empty table" guard: a
        // TableRecord whose rootBufferId has been set non-negative (i.e. synced as occupied)
        // cannot be deleted.
        let mut mt = new_master();
        let mut tr = mt.create_table_record("A".to_string(), sample_schema(), -1).unwrap();
        tr.set_root_buffer_id(5);
        // Push the synced value back into the master table's own copy (this port has no
        // automatic Table -> TableRecord root-buffer-id callback; see the struct doc comment).
        let idx = mt.table_records.iter().position(|r| r.get_table_num() == tr.get_table_num()).unwrap();
        mt.table_records[idx].set_root_buffer_id(5);

        let err = mt.delete_table_record(tr.get_table_num()).unwrap_err();
        assert_eq!(err.to_string(), "Can not delete non-empty table");
    }

    #[test]
    fn test_delete_table_record_missing_table_errors() {
        let mut mt = new_master();
        let err = mt.delete_table_record(42).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_change_table_name_updates_matching_records() {
        let mut mt = new_master();
        mt.create_table_record("Old".to_string(), sample_schema(), -1).unwrap();
        mt.change_table_name("Old", "New");
        assert_eq!(mt.get_table_records()[0].get_name(), "New");
    }

    #[test]
    fn test_flush_writes_dirty_records() {
        let mut mt = new_master();
        let tr = mt.create_table_record("A".to_string(), sample_schema(), -1).unwrap();
        // A freshly-created TableRecord's underlying DBRecord starts dirty (DBRecord::new marks
        // itself dirty), so flush() should be able to write it without error.
        assert!(tr.get_record().unwrap().is_dirty());
        mt.flush().unwrap();
    }

    #[test]
    fn test_refresh_table_records_reconciles_with_storage() {
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(BufferMgr::DEFAULT_BUFFER_SIZE)));
        let mut mt = MasterTable::new(buffer_mgr.clone());
        mt.create_table_record("A".to_string(), sample_schema(), -1).unwrap();
        mt.create_table_record("B".to_string(), sample_schema(), -1).unwrap();

        let dbh = DBHandle::new().unwrap();
        let refreshed = mt.refresh_table_records(&dbh).unwrap();
        assert_eq!(refreshed.len(), 2);
        assert_eq!(refreshed[0].get_name(), "A");
        assert_eq!(refreshed[1].get_name(), "B");
    }

    #[test]
    fn test_create_and_get_and_delete_data_table_registry() {
        let buffer_mgr = Arc::new(RwLock::new(BufferMgr::new(BufferMgr::DEFAULT_BUFFER_SIZE)));
        let mut mt = new_master();
        let schema = Arc::new(sample_schema());

        let table = mt.create_table("Data".to_string(), schema.clone(), buffer_mgr.clone());
        assert!(table.is_some());
        assert!(mt.create_table("Data".to_string(), schema, buffer_mgr).is_none()); // duplicate

        assert!(mt.get_table("Data").is_some());
        // Creating the data table also registers a bookkeeping TableRecord.
        assert_eq!(mt.get_table_records().len(), 1);
        assert_eq!(mt.get_table_records()[0].get_name(), "Data");

        assert!(mt.delete_table("Data"));
        assert!(mt.get_table("Data").is_none());
        assert_eq!(mt.get_table_records().len(), 0);
        assert!(!mt.delete_table("Data")); // already gone
    }
}
