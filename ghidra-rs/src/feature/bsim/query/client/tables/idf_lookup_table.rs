use super::{SqlStatementExec, SqlStringTableError};
use crate::generic::lsh::vector::IdfLookup;

/// Formal SQL name of the table (fixed; the Java constructor always passes `"idflookup"`).
const TABLE_NAME: &str = "idflookup";

/// Abstracts the SQL back-end operations required by [`IdfLookupTable`] that operate on
/// its own connection (as opposed to the caller-supplied statement used by
/// [`IdfLookupTable::create`] / [`IdfLookupTable::drop_table`]).
///
/// Mirrors the `db` field inherited from `SQLComplexTable`.
pub trait IdfLookupTableConn {
    /// Execute an update/DML statement, returning the number of rows affected.
    fn execute_update(&mut self, sql: &str) -> Result<u64, SqlStringTableError>;

    /// Execute the `SELECT ALL * from idflookup` query, returning every `(hash, lookup)` row.
    fn select_all(&mut self, sql: &str) -> Result<Vec<(i64, i32)>, SqlStringTableError>;
}

/// Database table storing IDF (inverse document frequency) hash/count lookups.
///
/// Mirrors `ghidra.features.bsim.query.client.tables.IdfLookupTable`.
pub struct IdfLookupTable<C> {
    conn: Option<C>,
}

impl<C: IdfLookupTableConn> IdfLookupTable<C> {
    /// Create a new, unconnected `IdfLookupTable`.
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
        st.execute_update("CREATE TABLE idflookup(hash bigint,lookup integer)")?;
        Ok(())
    }

    /// Drop the backing SQL table (if it exists) using the caller-supplied statement.
    pub fn drop_table(&self, st: &mut impl SqlStatementExec) -> Result<(), SqlStringTableError> {
        let sql = format!("DROP TABLE IF EXISTS {}", TABLE_NAME);
        st.execute_update(&sql)?;
        Ok(())
    }

    /// Insert a `(hash, count)` entry, encoding `hash` as an unsigned 32-bit value.
    ///
    /// A `cnt` of `-1` (i.e. `0xffffffff` as a 32-bit pattern) is treated as a no-op,
    /// mirroring the Java sentinel check.
    pub fn insert(&mut self, cnt: i32, hash: i32) -> Result<u64, SqlStringTableError> {
        if cnt == -1 {
            return Ok(0);
        }
        let rawhash = (hash as u32) as i64;
        let sql =
            format!("INSERT INTO {} (hash,lookup) VALUES({},{})", TABLE_NAME, rawhash, cnt);
        self.conn_mut()?.execute_update(&sql)
    }

    /// Reads every row of this table into `lookup`.
    ///
    /// Mirrors `IdfLookupTable.recoverIDFLookup`.
    pub fn recover_idf_lookup(&mut self, lookup: &mut IdfLookup) -> Result<(), SqlStringTableError> {
        let sql = format!("SELECT ALL * from {}", TABLE_NAME);
        let rows = self.conn_mut()?.select_all(&sql)?;
        let mut hash_count_pairs = Vec::with_capacity(rows.len() * 2);
        for (hash, count) in rows {
            hash_count_pairs.push(hash as i32);
            hash_count_pairs.push(count);
        }
        lookup.set(&hash_count_pairs);
        Ok(())
    }

    fn conn_mut(&mut self) -> Result<&mut C, SqlStringTableError> {
        self.conn.as_mut().ok_or(SqlStringTableError::NoConnection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemConn {
        rows: Vec<(i64, i32)>,
        executed: Vec<String>,
    }

    impl IdfLookupTableConn for MemConn {
        fn execute_update(&mut self, sql: &str) -> Result<u64, SqlStringTableError> {
            self.executed.push(sql.to_string());
            if let Some(rest) = sql.strip_prefix("INSERT INTO idflookup (hash,lookup) VALUES(") {
                let rest = rest.trim_end_matches(')');
                let mut parts = rest.split(',');
                let hash: i64 = parts.next().unwrap().parse().unwrap();
                let count: i32 = parts.next().unwrap().parse().unwrap();
                self.rows.push((hash, count));
            }
            Ok(0)
        }

        fn select_all(&mut self, _sql: &str) -> Result<Vec<(i64, i32)>, SqlStringTableError> {
            Ok(self.rows.clone())
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

    fn make_table() -> IdfLookupTable<MemConn> {
        let mut t = IdfLookupTable::new();
        t.set_connection(MemConn::default());
        t
    }

    #[test]
    fn table_name_is_fixed() {
        let t: IdfLookupTable<MemConn> = IdfLookupTable::new();
        assert_eq!(t.table_name(), "idflookup");
    }

    #[test]
    fn create_executes_expected_sql() {
        let t: IdfLookupTable<MemConn> = IdfLookupTable::new();
        let mut st = RecordingStatement { executed: Vec::new() };
        t.create(&mut st).unwrap();
        assert_eq!(st.executed, vec!["CREATE TABLE idflookup(hash bigint,lookup integer)".to_string()]);
    }

    #[test]
    fn drop_table_executes_expected_sql() {
        let t: IdfLookupTable<MemConn> = IdfLookupTable::new();
        let mut st = RecordingStatement { executed: Vec::new() };
        t.drop_table(&mut st).unwrap();
        assert_eq!(st.executed, vec!["DROP TABLE IF EXISTS idflookup".to_string()]);
    }

    #[test]
    fn insert_sentinel_cnt_is_noop() {
        let mut t = make_table();
        let rows = t.insert(-1, 42).unwrap();
        assert_eq!(rows, 0);
        assert!(t.conn.as_ref().unwrap().executed.is_empty());
    }

    #[test]
    fn insert_encodes_negative_hash_as_unsigned() {
        let mut t = make_table();
        t.insert(7, -1).unwrap();
        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows, vec![(4294967295i64, 7)]);
    }

    #[test]
    fn insert_encodes_positive_hash_directly() {
        let mut t = make_table();
        t.insert(3, 100).unwrap();
        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows, vec![(100i64, 3)]);
    }

    #[test]
    fn insert_without_connection_errors() {
        let mut t: IdfLookupTable<MemConn> = IdfLookupTable::new();
        let err = t.insert(1, 1).unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }

    #[test]
    fn recover_idf_lookup_round_trips_inserted_rows() {
        let mut t = make_table();
        t.insert(100, 10).unwrap();
        t.insert(200, 20).unwrap();
        t.insert(300, -5).unwrap();

        let mut lookup = IdfLookup::new();
        t.recover_idf_lookup(&mut lookup).unwrap();

        assert_eq!(lookup.get_count(10), 100);
        assert_eq!(lookup.get_count(20), 200);
        assert_eq!(lookup.get_count(-5), 300);
    }

    #[test]
    fn recover_idf_lookup_without_connection_errors() {
        let mut t: IdfLookupTable<MemConn> = IdfLookupTable::new();
        let mut lookup = IdfLookup::new();
        let err = t.recover_idf_lookup(&mut lookup).unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }

    #[test]
    fn close_relinquishes_connection() {
        let mut t = make_table();
        t.close();
        let err = t.insert(1, 1).unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }
}
