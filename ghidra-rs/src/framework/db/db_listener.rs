use super::db_handle::DBHandle;
use super::table::Table;

/// Database Listener.
pub trait DBListener {
    /// Provides notification that an undo or redo was performed.
    /// During the restore process `table_added` and `table_deleted`
    /// notifications will be suppressed.
    /// Any listener concerned with tables added or removed should reacquire their table(s).
    fn db_restored(&self, dbh: &DBHandle);

    /// Database has been closed.
    fn db_closed(&self, dbh: &DBHandle);

    /// Provides notification that a table was deleted.
    /// The state of the database may still be in transition and should not be accessed
    /// by this callback method.
    fn table_deleted(&self, dbh: &DBHandle, table: &Table);

    /// Provides notification that a table was added.
    /// The state of the database may still be in transition and should not be accessed
    /// by this callback method.
    fn table_added(&self, dbh: &DBHandle, table: &Table);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockListener {
        restored_count: std::cell::Cell<u32>,
        closed_count: std::cell::Cell<u32>,
        added_count: std::cell::Cell<u32>,
        deleted_count: std::cell::Cell<u32>,
    }

    impl DBListener for MockListener {
        fn db_restored(&self, _dbh: &DBHandle) {
            self.restored_count.set(self.restored_count.get() + 1);
        }

        fn db_closed(&self, _dbh: &DBHandle) {
            self.closed_count.set(self.closed_count.get() + 1);
        }

        fn table_deleted(&self, _dbh: &DBHandle, _table: &Table) {
            self.deleted_count.set(self.deleted_count.get() + 1);
        }

        fn table_added(&self, _dbh: &DBHandle, _table: &Table) {
            self.added_count.set(self.added_count.get() + 1);
        }
    }

    #[test]
    fn test_object_safe_dyn_usage() {
        let dbh = DBHandle::new().unwrap();
        let listener: Box<dyn DBListener> = Box::new(MockListener {
            restored_count: std::cell::Cell::new(0),
            closed_count: std::cell::Cell::new(0),
            added_count: std::cell::Cell::new(0),
            deleted_count: std::cell::Cell::new(0),
        });

        listener.db_restored(&dbh);
        listener.db_closed(&dbh);
    }

    #[test]
    fn test_mock_records_table_notifications() {
        let mut dbh = DBHandle::new().unwrap();
        let schema = Arc::new(crate::framework::db::Schema::new(
            1,
            crate::framework::db::FieldType::Long,
            "ID".to_string(),
            vec![],
            vec![],
            vec![],
        ));
        let table = dbh
            .create_table("MyTable".to_string(), schema)
            .unwrap();

        let listener = MockListener {
            restored_count: std::cell::Cell::new(0),
            closed_count: std::cell::Cell::new(0),
            added_count: std::cell::Cell::new(0),
            deleted_count: std::cell::Cell::new(0),
        };

        listener.table_added(&dbh, &table.read().unwrap());
        listener.table_deleted(&dbh, &table.read().unwrap());
        listener.db_restored(&dbh);
        listener.db_closed(&dbh);

        assert_eq!(listener.added_count.get(), 1);
        assert_eq!(listener.deleted_count.get(), 1);
        assert_eq!(listener.restored_count.get(), 1);
        assert_eq!(listener.closed_count.get(), 1);
    }
}
