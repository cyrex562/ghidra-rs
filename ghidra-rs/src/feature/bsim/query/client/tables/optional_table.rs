use thiserror::Error;

/// Error type for [`OptionalTable`] operations.
#[derive(Debug, Error)]
pub enum OptionalTableError {
    #[error("SQL error: {0}")]
    Sql(String),
    #[error("No database connection")]
    NoConnection,
}

/// `java.sql.Types.INTEGER`
pub const TYPE_INTEGER: i32 = 4;
/// `java.sql.Types.VARCHAR`
pub const TYPE_VARCHAR: i32 = 12;
/// `java.sql.Types.REAL`
pub const TYPE_REAL: i32 = 7;

/// A key or value bound to a column of an [`OptionalTable`].
///
/// Rust equivalent of the `Object` values Java binds via `PreparedStatement.setObject`.
/// Only the SQL types produced by [`sql_type_name`] are supported.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Integer(i32),
    Text(String),
    Real(f64),
}

/// Given a `java.sql.Types` type-code, return the SQL type name suitable for a
/// `CREATE TABLE` command, or `None` if the type-code is not one of the supported types.
///
/// Mirrors `OptionalTable.getSQLType`.
fn sql_type_name(type_code: i32) -> Option<&'static str> {
    match type_code {
        TYPE_INTEGER => Some("INTEGER"),
        TYPE_VARCHAR => Some("TEXT"),
        TYPE_REAL => Some("REAL"),
        _ => None,
    }
}

/// Replace the first (and optionally second) `#` in `template` with `name`.
///
/// Mirrors `OptionalTable.generateSQLCommand`.
fn generate_sql_command(template: &str, name: &str) -> String {
    template.replacen('#', name, 2)
}

/// Abstracts the SQL back-end operations required by [`OptionalTable`].
///
/// Implementors supply the actual database connectivity, including any statement
/// caching; [`OptionalTable`] only ever deals with generated SQL text and [`SqlValue`]s.
pub trait OptionalTableConn {
    /// Execute a DDL statement (no result expected).
    fn execute_ddl(&mut self, sql: &str) -> Result<(), OptionalTableError>;

    /// Execute an update/DML statement, returning the number of rows affected.
    fn execute_update(&mut self, sql: &str) -> Result<u64, OptionalTableError>;

    /// Execute the table-existence query, returning the schema name of the first
    /// result row, if any.
    fn table_exists(&mut self, sql: &str) -> Result<Option<String>, OptionalTableError>;

    /// Execute the value-lookup query bound to `key`, returning the stored value if present.
    fn read_value(
        &mut self,
        sql: &str,
        key: &SqlValue,
    ) -> Result<Option<SqlValue>, OptionalTableError>;

    /// Execute the UPDATE statement binding `value` then `key`, returning the number of
    /// rows affected.
    fn update_value(
        &mut self,
        sql: &str,
        key: &SqlValue,
        value: &SqlValue,
    ) -> Result<u64, OptionalTableError>;

    /// Execute the INSERT statement binding `key` then `value`.
    fn insert_value(
        &mut self,
        sql: &str,
        key: &SqlValue,
        value: &SqlValue,
    ) -> Result<(), OptionalTableError>;

    /// Execute the DELETE statement bound to `key`.
    fn delete_value(&mut self, sql: &str, key: &SqlValue) -> Result<(), OptionalTableError>;
}

/// Database table that has exactly two columns: key and value.
///
/// The column types are variable and are determined upon initialization. They are
/// specified by giving an integer "type code" as listed in `java.sql.Types`
/// (see [`TYPE_INTEGER`], [`TYPE_VARCHAR`], [`TYPE_REAL`]). The key column is marked UNIQUE.
///
/// Mirrors `ghidra.features.bsim.query.client.tables.OptionalTable`.
pub struct OptionalTable<C> {
    name: String,
    key_type: i32,
    value_type: i32,

    table_exists_sql: String,
    grant_sql: String,
    delete_all_sql: String,
    insert_sql: String,
    update_sql: String,
    select_sql: String,
    delete_sql: String,
    lock_sql: String,

    conn: Option<C>,
}

impl<C: OptionalTableConn> OptionalTable<C> {
    /// Construct this table for a specific formal SQL `name`, key type-code, and value
    /// type-code. The connection is attached separately via [`Self::set_connection`].
    pub fn new(name: impl Into<String>, key_type: i32, value_type: i32) -> Self {
        let name = name.into();
        Self {
            table_exists_sql: generate_sql_command(
                "SELECT schemaname FROM pg_tables where tablename='#'",
                &name,
            ),
            grant_sql: generate_sql_command("GRANT SELECT ON # TO PUBLIC", &name),
            delete_all_sql: generate_sql_command("DELETE FROM #", &name),
            insert_sql: generate_sql_command("INSERT INTO # (key,value) VALUES(?,?)", &name),
            update_sql: generate_sql_command("UPDATE # SET value = ? WHERE key = ?", &name),
            select_sql: generate_sql_command("SELECT value FROM # WHERE key = ?", &name),
            delete_sql: generate_sql_command("DELETE FROM # WHERE key = ?", &name),
            lock_sql: generate_sql_command("LOCK TABLE # IN SHARE ROW EXCLUSIVE MODE", &name),
            name,
            key_type,
            value_type,
            conn: None,
        }
    }

    /// Attach a database connection.
    pub fn set_connection(&mut self, conn: C) {
        self.conn = Some(conn);
    }

    /// Free any resources and relinquish the connection. This table does not own the
    /// connection.
    pub fn close(&mut self) {
        self.conn = None;
    }

    /// The formal SQL name of the table.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The type-code of the key column.
    pub fn key_type(&self) -> i32 {
        self.key_type
    }

    /// The type-code of the value column.
    pub fn value_type(&self) -> i32 {
        self.value_type
    }

    /// Lock the table for writing.
    pub fn lock_for_write(&mut self) -> Result<(), OptionalTableError> {
        let sql = self.lock_sql.clone();
        self.conn_mut()?.execute_update(&sql)?;
        Ok(())
    }

    /// Create this specific table in the database.
    pub fn create_table(&mut self) -> Result<(), OptionalTableError> {
        // Java builds this with StringBuilder.append(Object), which renders a null
        // type name (unsupported type-code) as the literal string "null".
        let key_sql_type = sql_type_name(self.key_type).unwrap_or("null");
        let value_sql_type = sql_type_name(self.value_type).unwrap_or("null");
        let sql = format!(
            "CREATE TABLE {} (key {} UNIQUE,value {})",
            self.name, key_sql_type, value_sql_type
        );
        let grant_sql = self.grant_sql.clone();
        let conn = self.conn_mut()?;
        conn.execute_ddl(&sql)?;
        conn.execute_update(&grant_sql)?;
        Ok(())
    }

    /// Clear all rows from the table.
    pub fn clear_table(&mut self) -> Result<(), OptionalTableError> {
        let sql = self.delete_all_sql.clone();
        self.conn_mut()?.execute_update(&sql)?;
        Ok(())
    }

    /// Determine whether this table exists in the database.
    pub fn exists(&mut self) -> Result<bool, OptionalTableError> {
        let sql = self.table_exists_sql.clone();
        let schema = self.conn_mut()?.table_exists(&sql)?;
        Ok(schema.as_deref() == Some("public"))
    }

    /// Given a key, retrieve the corresponding value.
    pub fn read_value(&mut self, key: &SqlValue) -> Result<Option<SqlValue>, OptionalTableError> {
        let sql = self.select_sql.clone();
        self.conn_mut()?.read_value(&sql, key)
    }

    /// Associate a new value with a given key, updating the row if it already exists,
    /// otherwise inserting a new one.
    pub fn write_value(&mut self, key: &SqlValue, value: &SqlValue) -> Result<(), OptionalTableError> {
        let update_sql = self.update_sql.clone();
        let rows = self.conn_mut()?.update_value(&update_sql, key, value)?;
        if rows == 1 {
            return Ok(());
        }
        let insert_sql = self.insert_sql.clone();
        self.conn_mut()?.insert_value(&insert_sql, key, value)
    }

    /// Delete the row corresponding to a given key.
    pub fn delete_value(&mut self, key: &SqlValue) -> Result<(), OptionalTableError> {
        let sql = self.delete_sql.clone();
        self.conn_mut()?.delete_value(&sql, key)
    }

    fn conn_mut(&mut self) -> Result<&mut C, OptionalTableError> {
        self.conn.as_mut().ok_or(OptionalTableError::NoConnection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory back-end for unit testing without a real database.
    #[derive(Default)]
    struct MemConn {
        rows: HashMap<String, SqlValue>,
        exists: bool,
        update_calls: u32,
    }

    impl MemConn {
        fn key_str(key: &SqlValue) -> String {
            match key {
                SqlValue::Integer(i) => i.to_string(),
                SqlValue::Text(s) => s.clone(),
                SqlValue::Real(r) => r.to_string(),
            }
        }
    }

    impl OptionalTableConn for MemConn {
        fn execute_ddl(&mut self, _sql: &str) -> Result<(), OptionalTableError> {
            self.exists = true;
            Ok(())
        }

        fn execute_update(&mut self, sql: &str) -> Result<u64, OptionalTableError> {
            self.update_calls += 1;
            if sql.starts_with("DELETE FROM") {
                self.rows.clear();
            }
            Ok(0)
        }

        fn table_exists(&mut self, _sql: &str) -> Result<Option<String>, OptionalTableError> {
            Ok(if self.exists { Some("public".to_string()) } else { None })
        }

        fn read_value(
            &mut self,
            _sql: &str,
            key: &SqlValue,
        ) -> Result<Option<SqlValue>, OptionalTableError> {
            Ok(self.rows.get(&Self::key_str(key)).cloned())
        }

        fn update_value(
            &mut self,
            _sql: &str,
            key: &SqlValue,
            value: &SqlValue,
        ) -> Result<u64, OptionalTableError> {
            let k = Self::key_str(key);
            if self.rows.contains_key(&k) {
                self.rows.insert(k, value.clone());
                Ok(1)
            }
            else {
                Ok(0)
            }
        }

        fn insert_value(
            &mut self,
            _sql: &str,
            key: &SqlValue,
            value: &SqlValue,
        ) -> Result<(), OptionalTableError> {
            self.rows.insert(Self::key_str(key), value.clone());
            Ok(())
        }

        fn delete_value(&mut self, _sql: &str, key: &SqlValue) -> Result<(), OptionalTableError> {
            self.rows.remove(&Self::key_str(key));
            Ok(())
        }
    }

    fn make_table() -> OptionalTable<MemConn> {
        let mut t = OptionalTable::new("options", TYPE_VARCHAR, TYPE_VARCHAR);
        t.set_connection(MemConn::default());
        t
    }

    #[test]
    fn generate_sql_command_replaces_both_hashes() {
        assert_eq!(
            generate_sql_command("SELECT value FROM # WHERE key = ?", "options"),
            "SELECT value FROM options WHERE key = ?"
        );
        assert_eq!(
            generate_sql_command(
                "SELECT schemaname FROM pg_tables where tablename='#'",
                "options"
            ),
            "SELECT schemaname FROM pg_tables where tablename='options'"
        );
    }

    #[test]
    fn sql_type_name_covers_known_types() {
        assert_eq!(sql_type_name(TYPE_INTEGER), Some("INTEGER"));
        assert_eq!(sql_type_name(TYPE_VARCHAR), Some("TEXT"));
        assert_eq!(sql_type_name(TYPE_REAL), Some("REAL"));
        assert_eq!(sql_type_name(9999), None);
    }

    #[test]
    fn new_stores_metadata() {
        let t: OptionalTable<MemConn> = OptionalTable::new("options", TYPE_VARCHAR, TYPE_INTEGER);
        assert_eq!(t.name(), "options");
        assert_eq!(t.key_type(), TYPE_VARCHAR);
        assert_eq!(t.value_type(), TYPE_INTEGER);
    }

    #[test]
    fn no_connection_error() {
        let mut t: OptionalTable<MemConn> = OptionalTable::new("options", TYPE_VARCHAR, TYPE_VARCHAR);
        let err = t.read_value(&SqlValue::Text("k".into())).unwrap_err();
        assert!(matches!(err, OptionalTableError::NoConnection));
    }

    #[test]
    fn create_table_then_exists() {
        let mut t = make_table();
        assert!(!t.exists().unwrap());
        t.create_table().unwrap();
        assert!(t.exists().unwrap());
    }

    #[test]
    fn write_value_inserts_then_updates() {
        let mut t = make_table();
        t.create_table().unwrap();

        let key = SqlValue::Text("k1".into());
        t.write_value(&key, &SqlValue::Text("v1".into())).unwrap();
        assert_eq!(t.read_value(&key).unwrap(), Some(SqlValue::Text("v1".into())));

        t.write_value(&key, &SqlValue::Text("v2".into())).unwrap();
        assert_eq!(t.read_value(&key).unwrap(), Some(SqlValue::Text("v2".into())));
    }

    #[test]
    fn read_value_missing_key_returns_none() {
        let mut t = make_table();
        t.create_table().unwrap();
        assert_eq!(t.read_value(&SqlValue::Text("missing".into())).unwrap(), None);
    }

    #[test]
    fn delete_value_removes_row() {
        let mut t = make_table();
        t.create_table().unwrap();
        let key = SqlValue::Text("k1".into());
        t.write_value(&key, &SqlValue::Text("v1".into())).unwrap();
        t.delete_value(&key).unwrap();
        assert_eq!(t.read_value(&key).unwrap(), None);
    }

    #[test]
    fn clear_table_removes_all_rows() {
        let mut t = make_table();
        t.create_table().unwrap();
        let key = SqlValue::Text("k1".into());
        t.write_value(&key, &SqlValue::Text("v1".into())).unwrap();
        t.clear_table().unwrap();
        assert_eq!(t.read_value(&key).unwrap(), None);
    }

    #[test]
    fn lock_for_write_invokes_reusable_statement() {
        let mut t = make_table();
        t.lock_for_write().unwrap();
    }

    #[test]
    fn close_drops_connection() {
        let mut t = make_table();
        t.close();
        let err = t.exists().unwrap_err();
        assert!(matches!(err, OptionalTableError::NoConnection));
    }
}
