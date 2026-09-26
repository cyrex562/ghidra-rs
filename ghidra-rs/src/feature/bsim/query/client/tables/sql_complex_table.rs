use super::{CachedStatement, SqlStatement, SqlStringTableError};

/// Executes a raw SQL statement, mirroring `java.sql.Statement.executeUpdate`.
///
/// Abstracts the caller-supplied statement used by [`SqlComplexTable::drop_table`]
/// (and, in embedding tables, `create`).
pub trait SqlStatementExec {
    /// Execute `sql` as an update/DDL command and return the number of rows affected.
    fn execute_update(&mut self, sql: &str) -> Result<u64, SqlStringTableError>;
}

/// A prepared statement capable of deleting a single row by its numeric id.
///
/// Rust equivalent of the `PreparedStatement` cached by `SQLComplexTable.deleteStatement`.
pub trait DeleteStatement: SqlStatement {
    /// Bind `id` and execute the delete, returning the number of rows removed.
    fn execute_delete(&mut self, id: i64) -> Result<u64, SqlStringTableError>;
}

/// Abstracts the database connection required by [`SqlComplexTable`] to prepare its
/// cached delete statement.
pub trait SqlComplexTableConn {
    /// Prepared-statement type produced for row deletion.
    type DeleteStatement: DeleteStatement;

    /// Prepare a `DELETE ... WHERE <id column> = ?` statement for `sql`.
    fn prepare_delete_statement(
        &self,
        sql: &str,
    ) -> Result<Self::DeleteStatement, SqlStringTableError>;
}

/// Shared state and behavior for BSim's complex (multi-column) SQL tables.
///
/// Mirrors the abstract class `ghidra.features.bsim.query.client.tables.SQLComplexTable`.
/// `create` and `insert` have no shared implementation in the original Java class either
/// (both are abstract there), so tables embed this struct and provide their own.
pub struct SqlComplexTable<C: SqlComplexTableConn> {
    table_name: String,
    id_column_name: Option<String>,
    conn: Option<C>,
    // Java only allocates `deleteStatement` when `idColumnName != null`; here it is always
    // constructed since an unused `CachedStatement` is inert and `delete` already rejects
    // tables without an id column.
    delete_statement: CachedStatement<C::DeleteStatement>,
}

impl<C: SqlComplexTableConn> SqlComplexTable<C> {
    /// Create a new table description for `table_name`, optionally supporting
    /// [`Self::delete`] via `id_column_name`.
    pub fn new(table_name: impl Into<String>, id_column_name: Option<impl Into<String>>) -> Self {
        Self {
            table_name: table_name.into(),
            id_column_name: id_column_name.map(Into::into),
            conn: None,
            delete_statement: CachedStatement::new(),
        }
    }

    /// Attach a database connection.
    pub fn set_connection(&mut self, conn: C) {
        self.conn = Some(conn);
    }

    /// Release the cached delete statement and relinquish the connection.
    pub fn close(&mut self) {
        self.delete_statement.close();
        self.conn = None;
    }

    /// The formal SQL name of the table.
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// The id column used by [`Self::delete`], or `None` if this table does not support it.
    pub fn id_column_name(&self) -> Option<&str> {
        self.id_column_name.as_deref()
    }

    /// The attached connection, if any.
    pub fn conn(&self) -> Option<&C> {
        self.conn.as_ref()
    }

    /// The attached connection, if any, for mutation.
    pub fn conn_mut(&mut self) -> Option<&mut C> {
        self.conn.as_mut()
    }

    /// Deletes the row with the given id from the db.
    ///
    /// # Errors
    /// Returns [`SqlStringTableError::UnsupportedOperation`] if this table was constructed
    /// without an id column, or [`SqlStringTableError::NoConnection`] if no connection is
    /// attached.
    pub fn delete(&mut self, id: i64) -> Result<u64, SqlStringTableError> {
        let id_column_name = self.id_column_name.as_deref().ok_or_else(|| {
            SqlStringTableError::UnsupportedOperation(
                "delete not supported without id column".to_string(),
            )
        })?;
        let sql = format!("DELETE FROM {} WHERE {} = ?", self.table_name, id_column_name);
        let conn = self.conn.as_ref().ok_or(SqlStringTableError::NoConnection)?;
        let supplier = || conn.prepare_delete_statement(&sql);
        let stmt = self.delete_statement.prepare_if_needed(&supplier)?;
        stmt.execute_delete(id)
    }

    /// Drops the current table using the caller-supplied statement.
    ///
    /// NOTE: If explicitly created index tables exist they should be removed first,
    /// or this method overridden by the embedding table.
    pub fn drop_table(&mut self, st: &mut impl SqlStatementExec) -> Result<(), SqlStringTableError> {
        let sql = format!("DROP TABLE {}", self.table_name);
        st.execute_update(&sql)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Default)]
    struct TestDeleteStatement {
        closed: Rc<Cell<bool>>,
        last_id: Rc<Cell<i64>>,
        calls: Rc<Cell<u32>>,
    }

    impl SqlStatement for TestDeleteStatement {
        fn close(&mut self) -> Result<(), SqlStringTableError> {
            self.closed.set(true);
            Ok(())
        }
    }

    impl DeleteStatement for TestDeleteStatement {
        fn execute_delete(&mut self, id: i64) -> Result<u64, SqlStringTableError> {
            self.last_id.set(id);
            self.calls.set(self.calls.get() + 1);
            Ok(1)
        }
    }

    #[derive(Default)]
    struct MemConn {
        prepare_calls: Cell<u32>,
        closed: Rc<Cell<bool>>,
        last_id: Rc<Cell<i64>>,
        delete_calls: Rc<Cell<u32>>,
    }

    impl SqlComplexTableConn for MemConn {
        type DeleteStatement = TestDeleteStatement;

        fn prepare_delete_statement(
            &self,
            _sql: &str,
        ) -> Result<Self::DeleteStatement, SqlStringTableError> {
            self.prepare_calls.set(self.prepare_calls.get() + 1);
            Ok(TestDeleteStatement {
                closed: self.closed.clone(),
                last_id: self.last_id.clone(),
                calls: self.delete_calls.clone(),
            })
        }
    }

    struct RecordingStatement {
        executed: Vec<String>,
    }

    impl SqlStatementExec for RecordingStatement {
        fn execute_update(&mut self, sql: &str) -> Result<u64, SqlStringTableError> {
            self.executed.push(sql.to_string());
            Ok(0)
        }
    }

    fn make_table() -> SqlComplexTable<MemConn> {
        let mut t = SqlComplexTable::new("weighttable", Some("id"));
        t.set_connection(MemConn::default());
        t
    }

    #[test]
    fn new_stores_metadata() {
        let t: SqlComplexTable<MemConn> = SqlComplexTable::new("weighttable", Some("id"));
        assert_eq!(t.table_name(), "weighttable");
        assert_eq!(t.id_column_name(), Some("id"));
    }

    #[test]
    fn new_without_id_column() {
        let t: SqlComplexTable<MemConn> = SqlComplexTable::new("keyvaluetable", None::<String>);
        assert_eq!(t.id_column_name(), None);
    }

    #[test]
    fn delete_without_id_column_is_unsupported() {
        let mut t: SqlComplexTable<MemConn> = SqlComplexTable::new("keyvaluetable", None::<String>);
        t.set_connection(MemConn::default());
        let err = t.delete(1).unwrap_err();
        assert!(matches!(err, SqlStringTableError::UnsupportedOperation(_)));
    }

    #[test]
    fn delete_without_connection_errors() {
        let mut t: SqlComplexTable<MemConn> = SqlComplexTable::new("weighttable", Some("id"));
        let err = t.delete(1).unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }

    #[test]
    fn delete_prepares_once_and_reuses_statement() {
        let mut t = make_table();
        t.delete(5).unwrap();
        t.delete(6).unwrap();

        let conn = t.conn().unwrap();
        assert_eq!(conn.prepare_calls.get(), 1);
        assert_eq!(conn.last_id.get(), 6);
        assert_eq!(conn.delete_calls.get(), 2);
    }

    #[test]
    fn drop_table_executes_expected_sql() {
        let mut t: SqlComplexTable<MemConn> = SqlComplexTable::new("weighttable", Some("id"));
        let mut st = RecordingStatement { executed: Vec::new() };
        t.drop_table(&mut st).unwrap();
        assert_eq!(st.executed, vec!["DROP TABLE weighttable".to_string()]);
    }

    #[test]
    fn close_clears_connection_and_closes_statement() {
        let mut t = make_table();
        t.delete(1).unwrap();
        let closed = t.conn().unwrap().closed.clone();

        t.close();

        assert!(closed.get());
        assert!(t.conn().is_none());
    }
}
