use std::collections::{BTreeMap, VecDeque};
use thiserror::Error;

/// Error type for [`SqlStringTable`] operations.
#[derive(Debug, Error)]
pub enum SqlStringTableError {
    #[error("Id not present in string table: {table}")]
    IdNotFound { table: String },
    #[error("SQL error: {0}")]
    Sql(String),
    #[error("No database connection")]
    NoConnection,
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
}

/// Abstracts the SQL back-end operations required by [`SqlStringTable`].
///
/// Implementors supply the actual database connectivity; the table handles caching.
pub trait StringTableConn {
    /// Execute a DDL statement (no result expected).
    fn execute_ddl(&mut self, sql: &str) -> Result<(), SqlStringTableError>;

    /// Insert `value` using `sql` (an INSERT with one `?` placeholder) and return
    /// the generated row id.
    fn insert_string(&mut self, sql: &str, value: &str) -> Result<i64, SqlStringTableError>;

    /// Execute a SELECT returning a single `TEXT` column, bound to `id`.
    fn select_by_id(&mut self, sql: &str, id: i64) -> Result<Option<String>, SqlStringTableError>;

    /// Execute a SELECT returning a single integer column, bound to `value`.
    fn select_by_value(
        &mut self,
        sql: &str,
        value: &str,
    ) -> Result<Option<i64>, SqlStringTableError>;
}

/// In-memory LRU cache backed by a SQL string table.
///
/// Mirrors `ghidra.features.bsim.query.client.tables.SQLStringTable`.
///
/// The cache tracks at most `max_loaded` entries; the least-recently-used entry is
/// evicted when the limit is reached.  The database connection is abstracted through
/// [`StringTableConn`], so any SQL back-end can be plugged in without adding a hard
/// crate dependency.
pub struct SqlStringTable<C> {
    name: String,
    max_loaded: usize,
    insert_sql: String,
    select_by_id_sql: String,
    select_by_value_sql: String,
    /// value → id
    string_map: BTreeMap<String, i64>,
    /// id → value
    id_map: BTreeMap<i64, String>,
    /// LRU order: front = least-recently-used, back = most-recently-used.
    lru_order: VecDeque<i64>,
    conn: Option<C>,
}

impl<C: StringTableConn> SqlStringTable<C> {
    /// Create a new [`SqlStringTable`] for `name` caching at most `max_loaded` entries.
    pub fn new(name: impl Into<String>, max_loaded: usize) -> Self {
        let name = name.into();
        let insert_sql =
            Self::generate_sql_command(&name, "INSERT INTO # (id,val) VALUES(DEFAULT,?)");
        let select_by_id_sql =
            Self::generate_sql_command(&name, "SELECT val FROM # WHERE id = ?");
        let select_by_value_sql =
            Self::generate_sql_command(&name, "SELECT id FROM # WHERE val = ?");
        Self {
            name,
            max_loaded,
            insert_sql,
            select_by_id_sql,
            select_by_value_sql,
            string_map: BTreeMap::new(),
            id_map: BTreeMap::new(),
            lru_order: VecDeque::new(),
            conn: None,
        }
    }

    /// Attach a database connection.
    pub fn set_connection(&mut self, conn: C) {
        self.conn = Some(conn);
    }

    /// Close the connection and clear all cached data.
    pub fn close(&mut self) {
        self.conn = None;
        self.string_map.clear();
        self.id_map.clear();
        self.lru_order.clear();
    }

    /// Create the backing SQL table in the database.
    pub fn create_table(&mut self) -> Result<(), SqlStringTableError> {
        let sql = Self::generate_sql_command(
            &self.name,
            "CREATE TABLE # (id SERIAL PRIMARY KEY,val TEXT UNIQUE)",
        );
        self.conn_mut()?.execute_ddl(&sql)
    }

    /// Fetch the string for `id` from cache or database.
    ///
    /// Returns `Ok(None)` when `id == 0` (Java returns `null`).
    /// Returns `Err(SqlStringTableError::IdNotFound)` when the id is absent from the table.
    pub fn get_string(&mut self, id: i64) -> Result<Option<String>, SqlStringTableError> {
        if id == 0 {
            return Ok(None);
        }
        if let Some(value) = self.id_map.get(&id).cloned() {
            self.move_to_end(id);
            return Ok(Some(value));
        }
        let sql = self.select_by_id_sql.clone();
        match self.conn_mut()?.select_by_id(&sql, id)? {
            None => Err(SqlStringTableError::IdNotFound { table: self.name.clone() }),
            Some(v) => {
                self.insert_record(id, v.clone());
                Ok(Some(v))
            }
        }
    }

    /// Write `val` to the table if it does not already exist, returning its row id.
    ///
    /// Returns `0` for `null`/empty strings (mirrors the Java behaviour).
    pub fn write_string(&mut self, val: &str) -> Result<i64, SqlStringTableError> {
        if val.is_empty() {
            return Ok(0);
        }
        if let Some(&id) = self.string_map.get(val) {
            self.move_to_end(id);
            return Ok(id);
        }
        let id = self.read_string_id(val)?;
        if id != 0 {
            return Ok(id);
        }
        self.write_new_string(val)
    }

    /// Look up the row id of `value` in the database, returning `0` if absent.
    pub fn read_string_id(&mut self, value: &str) -> Result<i64, SqlStringTableError> {
        let sql = self.select_by_value_sql.clone();
        match self.conn_mut()?.select_by_value(&sql, value)? {
            None => Ok(0),
            Some(id) => {
                self.insert_record(id, value.to_string());
                Ok(id)
            }
        }
    }

    // ── private helpers ─────────────────────────────────────────────────────

    fn write_new_string(&mut self, value: &str) -> Result<i64, SqlStringTableError> {
        let sql = self.insert_sql.clone();
        let id = self.conn_mut()?.insert_string(&sql, value)?;
        self.insert_record(id, value.to_string());
        Ok(id)
    }

    fn insert_record(&mut self, id: i64, value: String) {
        while self.id_map.len() >= self.max_loaded {
            self.purge_string();
        }
        self.string_map.insert(value.clone(), id);
        self.id_map.insert(id, value);
        self.lru_order.push_back(id);
    }

    fn purge_string(&mut self) {
        if let Some(id) = self.lru_order.pop_front() {
            if let Some(value) = self.id_map.remove(&id) {
                self.string_map.remove(&value);
            }
        }
    }

    fn move_to_end(&mut self, id: i64) {
        if let Some(pos) = self.lru_order.iter().position(|&x| x == id) {
            if pos == self.lru_order.len() - 1 {
                return;
            }
            self.lru_order.remove(pos);
            self.lru_order.push_back(id);
        }
    }

    fn conn_mut(&mut self) -> Result<&mut C, SqlStringTableError> {
        self.conn.as_mut().ok_or(SqlStringTableError::NoConnection)
    }

    /// Replace the first (and optionally second) `#` in `template` with `name`.
    fn generate_sql_command(name: &str, template: &str) -> String {
        // Mirrors the Java method: replaces up to two '#' occurrences with the table name.
        template.replacen('#', name, 2)
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory back-end for unit testing without a real database.
    struct MemConn {
        /// table_name → (next_id, rows: Vec<(id, value)>)
        tables: HashMap<String, (i64, Vec<(i64, String)>)>,
    }

    impl MemConn {
        fn new() -> Self {
            Self { tables: HashMap::new() }
        }

        fn table_name(sql: &str) -> &str {
            // The table name appears right after FROM, INTO, TABLE, etc.
            // Simple extraction: find the first word that is a known table.
            // For these tests we just extract the third whitespace-delimited token.
            let tokens: Vec<&str> = sql.split_whitespace().collect();
            // INSERT INTO <name> …  → tokens[2]
            // SELECT … FROM <name> … → after FROM
            // CREATE TABLE <name> … → tokens[2]
            for (i, t) in tokens.iter().enumerate() {
                let upper = t.to_uppercase();
                if (upper == "INTO" || upper == "TABLE" || upper == "FROM")
                    && i + 1 < tokens.len()
                {
                    return tokens[i + 1];
                }
            }
            ""
        }
    }

    impl StringTableConn for MemConn {
        fn execute_ddl(&mut self, sql: &str) -> Result<(), SqlStringTableError> {
            let name = Self::table_name(sql).to_string();
            self.tables.entry(name).or_insert((1, vec![]));
            Ok(())
        }

        fn insert_string(
            &mut self,
            sql: &str,
            value: &str,
        ) -> Result<i64, SqlStringTableError> {
            let name = Self::table_name(sql).to_string();
            let entry = self.tables.entry(name).or_insert((1, vec![]));
            let id = entry.0;
            entry.1.push((id, value.to_string()));
            entry.0 += 1;
            Ok(id)
        }

        fn select_by_id(
            &mut self,
            sql: &str,
            id: i64,
        ) -> Result<Option<String>, SqlStringTableError> {
            let name = Self::table_name(sql);
            Ok(self.tables.get(name).and_then(|(_, rows)| {
                rows.iter().find(|(rid, _)| *rid == id).map(|(_, v)| v.clone())
            }))
        }

        fn select_by_value(
            &mut self,
            sql: &str,
            value: &str,
        ) -> Result<Option<i64>, SqlStringTableError> {
            let name = Self::table_name(sql);
            Ok(self.tables.get(name).and_then(|(_, rows)| {
                rows.iter().find(|(_, v)| v == value).map(|(id, _)| *id)
            }))
        }
    }

    fn make_table(max: usize) -> SqlStringTable<MemConn> {
        let mut t = SqlStringTable::new("strings", max);
        let mut conn = MemConn::new();
        // Pre-create the table in the in-memory backend.
        conn.execute_ddl("CREATE TABLE strings (id SERIAL PRIMARY KEY,val TEXT UNIQUE)").unwrap();
        t.set_connection(conn);
        t
    }

    #[test]
    fn test_write_and_read_string() {
        let mut t = make_table(10);
        let id = t.write_string("hello").unwrap();
        assert!(id > 0);
        let val = t.get_string(id).unwrap();
        assert_eq!(val, Some("hello".to_string()));
    }

    #[test]
    fn test_empty_string_returns_zero() {
        let mut t = make_table(10);
        assert_eq!(t.write_string("").unwrap(), 0);
    }

    #[test]
    fn test_id_zero_returns_none() {
        let mut t = make_table(10);
        assert_eq!(t.get_string(0).unwrap(), None);
    }

    #[test]
    fn test_write_same_string_twice_same_id() {
        let mut t = make_table(10);
        let id1 = t.write_string("duplicate").unwrap();
        let id2 = t.write_string("duplicate").unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_multiple_distinct_strings() {
        let mut t = make_table(10);
        let ids: Vec<i64> = ["a", "b", "c"].iter().map(|s| t.write_string(s).unwrap()).collect();
        assert!(ids[0] != ids[1]);
        assert!(ids[1] != ids[2]);
        for (s, &id) in ["a", "b", "c"].iter().zip(ids.iter()) {
            assert_eq!(t.get_string(id).unwrap(), Some(s.to_string()));
        }
    }

    #[test]
    fn test_lru_eviction() {
        // max_loaded = 2; after writing "a", "b", "c" the cache should hold only 2
        let mut t = make_table(2);
        let id_a = t.write_string("a").unwrap();
        let id_b = t.write_string("b").unwrap();
        let _id_c = t.write_string("c").unwrap();

        // "a" was evicted; reading it goes back to the database
        let val_a = t.get_string(id_a).unwrap();
        assert_eq!(val_a, Some("a".to_string()));

        let val_b = t.get_string(id_b).unwrap();
        assert_eq!(val_b, Some("b".to_string()));
    }

    #[test]
    fn test_get_string_missing_id_returns_error() {
        let mut t = make_table(10);
        let result = t.get_string(999);
        assert!(matches!(result, Err(SqlStringTableError::IdNotFound { .. })));
    }

    #[test]
    fn test_read_string_id_returns_zero_for_absent() {
        let mut t = make_table(10);
        assert_eq!(t.read_string_id("nope").unwrap(), 0);
    }

    #[test]
    fn test_close_clears_cache() {
        let mut t = make_table(10);
        t.write_string("x").unwrap();
        t.close();
        // After close the internal maps are empty.
        assert!(t.id_map.is_empty());
        assert!(t.string_map.is_empty());
        assert!(t.lru_order.is_empty());
    }

    #[test]
    fn test_generate_sql_command_single_hash() {
        let result = SqlStringTable::<MemConn>::generate_sql_command("mytable", "SELECT * FROM #");
        assert_eq!(result, "SELECT * FROM mytable");
    }

    #[test]
    fn test_generate_sql_command_two_hashes() {
        let result = SqlStringTable::<MemConn>::generate_sql_command(
            "t",
            "INSERT INTO # SELECT * FROM #",
        );
        assert_eq!(result, "INSERT INTO t SELECT * FROM t");
    }

    #[test]
    fn test_no_connection_error() {
        let mut t: SqlStringTable<MemConn> = SqlStringTable::new("tbl", 10);
        assert!(matches!(t.write_string("x"), Err(SqlStringTableError::NoConnection)));
    }

    #[test]
    fn test_create_table() {
        let mut t: SqlStringTable<MemConn> = SqlStringTable::new("strings", 10);
        t.set_connection(MemConn::new());
        assert!(t.create_table().is_ok());
    }
}
