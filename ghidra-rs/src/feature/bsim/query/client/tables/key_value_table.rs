use super::{SqlStatementExec, SqlStringTableError};
use crate::feature::bsim::query::description::DatabaseInformation;

/// Formal SQL name of the table (fixed; the Java constructor always passes `"keyvaluetable"`).
const TABLE_NAME: &str = "keyvaluetable";

/// Abstracts the SQL back-end operations required by [`KeyValueTable`] that operate on
/// its own connection (as opposed to the caller-supplied statement used by
/// [`KeyValueTable::create`]).
///
/// Mirrors the `db` field inherited from `SQLComplexTable`, together with the cached
/// prepared statements the Java class keeps for its update/insert/select operations.
pub trait KeyValueTableConn {
    /// Update the value for an existing `key`, returning the number of rows affected.
    fn update_value(&mut self, key: &str, value: &str) -> Result<u64, SqlStringTableError>;

    /// Insert a new `(key, value)` row, returning the number of rows affected.
    fn insert_value(&mut self, key: &str, value: &str) -> Result<u64, SqlStringTableError>;

    /// Fetch the value stored for `key`, or `None` if absent.
    fn select_value(&mut self, key: &str) -> Result<Option<String>, SqlStringTableError>;
}

/// Database table storing a simple string-to-string key/value map, used to hold
/// [`DatabaseInformation`] properties.
///
/// Mirrors `ghidra.features.bsim.query.client.tables.KeyValueTable`.
pub struct KeyValueTable<C> {
    conn: Option<C>,
}

impl<C: KeyValueTableConn> KeyValueTable<C> {
    /// Create a new, unconnected `KeyValueTable`.
    pub fn new() -> Self {
        Self { conn: None }
    }

    /// Attach a database connection.
    pub fn set_connection(&mut self, conn: C) {
        self.conn = Some(conn);
    }

    /// Relinquish the connection.
    pub fn close(&mut self) {
        self.conn = None;
    }

    /// The formal SQL name of the table.
    pub fn table_name(&self) -> &str {
        TABLE_NAME
    }

    /// Create the backing SQL table using the caller-supplied statement.
    pub fn create(&self, st: &mut impl SqlStatementExec) -> Result<(), SqlStringTableError> {
        st.execute_update("CREATE TABLE keyvaluetable (key TEXT UNIQUE,value TEXT)")?;
        Ok(())
    }

    /// Always fails: `KeyValueTable` may not be dropped.
    pub fn drop_table(&self, _st: &mut impl SqlStatementExec) -> Result<(), SqlStringTableError> {
        Err(SqlStringTableError::UnsupportedOperation(
            "KeyValueTable may not be dropped".to_string(),
        ))
    }

    /// Insert `value` under `key`, updating the existing row if one is already present.
    pub fn insert(&mut self, key: &str, value: &str) -> Result<u64, SqlStringTableError> {
        let conn = self.conn_mut()?;
        if conn.update_value(key, value)? == 1 {
            return Ok(0);
        }
        conn.insert_value(key, value)?;
        Ok(0)
    }

    /// Inserts some properties from the [`DatabaseInformation`] object into the table.
    ///
    /// Mirrors `KeyValueTable.writeBasicInfo`.
    pub fn write_basic_info(&mut self, info: &DatabaseInformation) -> Result<(), SqlStringTableError> {
        self.insert("name", info.databasename.as_deref().unwrap_or(""))?;
        self.insert("owner", info.owner.as_deref().unwrap_or(""))?;
        self.insert("description", info.description.as_deref().unwrap_or(""))?;
        self.insert("major", &info.major.to_string())?;
        self.insert("minor", &info.minor.to_string())?;
        self.insert("settings", &info.settings.to_string())?;
        self.insert("layout", &info.layout_version.to_string())?;
        self.insert("readonly", if info.readonly { "t" } else { "f" })?;
        self.insert("trackcallgraph", if info.trackcallgraph { "t" } else { "f" })?;
        let datename = info.date_column_name.as_deref().unwrap_or("Ingest Date");
        self.insert("datecolumn", datename)?;
        self.write_executable_categories(info)?;
        self.write_function_tags(info)?;
        Ok(())
    }

    /// Mirrors `KeyValueTable.writeExecutableCategories`.
    pub fn write_executable_categories(
        &mut self,
        info: &DatabaseInformation,
    ) -> Result<(), SqlStringTableError> {
        let Some(execats) = info.execats.as_ref() else {
            self.insert("execatcount", "0")?;
            return Ok(());
        };
        self.insert("execatcount", &execats.len().to_string())?;
        for (i, execat) in execats.iter().enumerate() {
            let key = format!("execat{}", i + 1);
            self.insert(&key, execat)?;
        }
        Ok(())
    }

    /// Mirrors `KeyValueTable.writeFunctionTags`.
    pub fn write_function_tags(
        &mut self,
        info: &DatabaseInformation,
    ) -> Result<(), SqlStringTableError> {
        let Some(function_tags) = info.function_tags.as_ref() else {
            self.insert("functiontagcount", "0")?;
            return Ok(());
        };
        self.insert("functiontagcount", &function_tags.len().to_string())?;
        for (i, tag) in function_tags.iter().enumerate() {
            let key = format!("functiontag{}", i + 1);
            self.insert(&key, tag)?;
        }
        Ok(())
    }

    /// Fetch the value stored under `key`.
    ///
    /// # Errors
    /// Returns [`SqlStringTableError::Sql`] if `key` is not present in the table.
    pub fn get_value(&mut self, key: &str) -> Result<String, SqlStringTableError> {
        match self.conn_mut()?.select_value(key)? {
            Some(value) => Ok(value),
            None => Err(SqlStringTableError::Sql(format!("Could not fetch key value: {}", key))),
        }
    }

    fn conn_mut(&mut self) -> Result<&mut C, SqlStringTableError> {
        self.conn.as_mut().ok_or(SqlStringTableError::NoConnection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemConn {
        rows: BTreeMap<String, String>,
        executed: Vec<String>,
    }

    impl KeyValueTableConn for MemConn {
        fn update_value(&mut self, key: &str, value: &str) -> Result<u64, SqlStringTableError> {
            self.executed.push(format!("UPDATE {} = {}", key, value));
            if self.rows.contains_key(key) {
                self.rows.insert(key.to_string(), value.to_string());
                Ok(1)
            }
            else {
                Ok(0)
            }
        }

        fn insert_value(&mut self, key: &str, value: &str) -> Result<u64, SqlStringTableError> {
            self.executed.push(format!("INSERT {} = {}", key, value));
            self.rows.insert(key.to_string(), value.to_string());
            Ok(1)
        }

        fn select_value(&mut self, key: &str) -> Result<Option<String>, SqlStringTableError> {
            Ok(self.rows.get(key).cloned())
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

    fn make_table() -> KeyValueTable<MemConn> {
        let mut t = KeyValueTable::new();
        t.set_connection(MemConn::default());
        t
    }

    #[test]
    fn table_name_is_fixed() {
        let t: KeyValueTable<MemConn> = KeyValueTable::new();
        assert_eq!(t.table_name(), "keyvaluetable");
    }

    #[test]
    fn create_executes_expected_sql() {
        let t: KeyValueTable<MemConn> = KeyValueTable::new();
        let mut st = RecordingStatement { executed: Vec::new() };
        t.create(&mut st).unwrap();
        assert_eq!(
            st.executed,
            vec!["CREATE TABLE keyvaluetable (key TEXT UNIQUE,value TEXT)".to_string()]
        );
    }

    #[test]
    fn drop_table_is_unsupported() {
        let t: KeyValueTable<MemConn> = KeyValueTable::new();
        let mut st = RecordingStatement { executed: Vec::new() };
        let err = t.drop_table(&mut st).unwrap_err();
        assert!(matches!(err, SqlStringTableError::UnsupportedOperation(_)));
        assert!(st.executed.is_empty());
    }

    #[test]
    fn insert_new_key_falls_back_to_insert_statement() {
        let mut t = make_table();
        t.insert("name", "MyDb").unwrap();
        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows.get("name"), Some(&"MyDb".to_string()));
        assert_eq!(conn.executed, vec!["UPDATE name = MyDb", "INSERT name = MyDb"]);
    }

    #[test]
    fn insert_existing_key_uses_update_only() {
        let mut t = make_table();
        t.insert("name", "MyDb").unwrap();
        t.insert("name", "OtherDb").unwrap();
        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows.get("name"), Some(&"OtherDb".to_string()));
        assert_eq!(
            conn.executed,
            vec!["UPDATE name = MyDb", "INSERT name = MyDb", "UPDATE name = OtherDb"]
        );
    }

    #[test]
    fn insert_without_connection_errors() {
        let mut t: KeyValueTable<MemConn> = KeyValueTable::new();
        let err = t.insert("name", "MyDb").unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }

    #[test]
    fn get_value_returns_stored_value() {
        let mut t = make_table();
        t.insert("owner", "MyOwner").unwrap();
        assert_eq!(t.get_value("owner").unwrap(), "MyOwner");
    }

    #[test]
    fn get_value_missing_key_errors() {
        let mut t = make_table();
        let err = t.get_value("missing").unwrap_err();
        assert!(matches!(err, SqlStringTableError::Sql(msg) if msg.contains("missing")));
    }

    #[test]
    fn get_value_without_connection_errors() {
        let mut t: KeyValueTable<MemConn> = KeyValueTable::new();
        let err = t.get_value("owner").unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }

    #[test]
    fn write_basic_info_inserts_all_scalar_fields() {
        let mut t = make_table();
        let mut info = DatabaseInformation::new();
        info.major = 1;
        info.minor = 2;
        info.settings = 3;
        info.layout_version = 4;
        info.readonly = true;
        info.trackcallgraph = false;

        t.write_basic_info(&info).unwrap();

        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows.get("name"), info.databasename.as_ref());
        assert_eq!(conn.rows.get("owner"), info.owner.as_ref());
        assert_eq!(conn.rows.get("description"), info.description.as_ref());
        assert_eq!(conn.rows.get("major"), Some(&"1".to_string()));
        assert_eq!(conn.rows.get("minor"), Some(&"2".to_string()));
        assert_eq!(conn.rows.get("settings"), Some(&"3".to_string()));
        assert_eq!(conn.rows.get("layout"), Some(&"4".to_string()));
        assert_eq!(conn.rows.get("readonly"), Some(&"t".to_string()));
        assert_eq!(conn.rows.get("trackcallgraph"), Some(&"f".to_string()));
        assert_eq!(conn.rows.get("datecolumn"), Some(&"Ingest Date".to_string()));
        assert_eq!(conn.rows.get("execatcount"), Some(&"0".to_string()));
        assert_eq!(conn.rows.get("functiontagcount"), Some(&"0".to_string()));
    }

    #[test]
    fn write_basic_info_uses_custom_date_column_name() {
        let mut t = make_table();
        let mut info = DatabaseInformation::new();
        info.date_column_name = Some("Custom Date".to_string());

        t.write_basic_info(&info).unwrap();

        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows.get("datecolumn"), Some(&"Custom Date".to_string()));
    }

    #[test]
    fn write_executable_categories_none_writes_zero_count() {
        let mut t = make_table();
        let info = DatabaseInformation::new();
        t.write_executable_categories(&info).unwrap();
        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows.get("execatcount"), Some(&"0".to_string()));
        assert!(!conn.rows.contains_key("execat1"));
    }

    #[test]
    fn write_executable_categories_writes_each_entry() {
        let mut t = make_table();
        let mut info = DatabaseInformation::new();
        info.execats = Some(vec!["Compiler".to_string(), "Vendor".to_string()]);

        t.write_executable_categories(&info).unwrap();

        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows.get("execatcount"), Some(&"2".to_string()));
        assert_eq!(conn.rows.get("execat1"), Some(&"Compiler".to_string()));
        assert_eq!(conn.rows.get("execat2"), Some(&"Vendor".to_string()));
    }

    #[test]
    fn write_function_tags_writes_each_entry() {
        let mut t = make_table();
        let mut info = DatabaseInformation::new();
        info.function_tags = Some(vec!["thunk".to_string()]);

        t.write_function_tags(&info).unwrap();

        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows.get("functiontagcount"), Some(&"1".to_string()));
        assert_eq!(conn.rows.get("functiontag1"), Some(&"thunk".to_string()));
    }

    #[test]
    fn close_relinquishes_connection() {
        let mut t = make_table();
        t.close();
        let err = t.insert("name", "MyDb").unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }
}
