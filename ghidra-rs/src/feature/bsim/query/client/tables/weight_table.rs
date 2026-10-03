use super::{SqlStatementExec, SqlStringTableError};
use crate::generic::lsh::vector::WeightFactory;

/// Formal SQL name of the table (fixed; the Java constructor always passes `"weighttable"`).
const TABLE_NAME: &str = "weighttable";

/// Abstracts the SQL back-end operations required by [`WeightTable`] that operate on
/// its own connection (as opposed to the caller-supplied statement used by
/// [`WeightTable::create`] / [`WeightTable::drop_table`]).
///
/// Mirrors the `db` field inherited from `SQLComplexTable`.
pub trait WeightTableConn {
    /// Execute an update/DML statement, returning the number of rows affected.
    fn execute_update(&mut self, sql: &str) -> Result<u64, SqlStringTableError>;

    /// Execute the `SELECT ALL * from weighttable` query, returning every `(id, weight)` row.
    fn select_all(&mut self, sql: &str) -> Result<Vec<(i32, f64)>, SqlStringTableError>;
}

/// Database table storing weight values indexed by id.
///
/// Mirrors `ghidra.features.bsim.query.client.tables.WeightTable`.
pub struct WeightTable<C> {
    conn: Option<C>,
}

impl<C: WeightTableConn> WeightTable<C> {
    /// Create a new, unconnected `WeightTable`.
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
        st.execute_update("CREATE TABLE weighttable(id integer,weight NUMERIC(24,20))")?;
        Ok(())
    }

    /// Drop the backing SQL table (if it exists) using the caller-supplied statement.
    pub fn drop_table(&self, st: &mut impl SqlStatementExec) -> Result<(), SqlStringTableError> {
        let sql = format!("DROP TABLE IF EXISTS {}", TABLE_NAME);
        st.execute_update(&sql)?;
        Ok(())
    }

    /// Insert a weight value at the given id.
    ///
    /// Arguments must contain exactly two elements: an int (id) and a double (weight value).
    pub fn insert(&mut self, row: i32, val: f64) -> Result<u64, SqlStringTableError> {
        let sql = format!("INSERT INTO weighttable (id,weight) VALUES({},{})", row, val);
        self.conn_mut()?.execute_update(&sql)
    }

    /// Reads every weight from the table and initializes the factory with them.
    ///
    /// The table must contain exactly `factory.get_size()` rows, indexed from 0 to `size-1`.
    ///
    /// # Errors
    /// Returns [`SqlStringTableError`] if the table does not contain the expected number of rows.
    ///
    /// Mirrors `WeightTable.recoverWeights`.
    pub fn recover_weights(&mut self, factory: &mut WeightFactory) -> Result<(), SqlStringTableError> {
        let sql = "SELECT ALL * FROM weighttable".to_string();
        let rows = self.conn_mut()?.select_all(&sql)?;

        let expected_size = factory.get_size();
        let mut vals = vec![0.0; expected_size];
        let row_count = rows.len();

        for (id, weight) in rows {
            if id < 0 || id >= expected_size as i32 {
                return Err(SqlStringTableError::Sql(format!(
                    "weighttable has invalid id: {}",
                    id
                )));
            }
            vals[id as usize] = weight;
        }

        if row_count != expected_size {
            return Err(SqlStringTableError::Sql(
                "weighttable has wrong number of rows".to_string(),
            ));
        }

        factory.set(&vals).map_err(|e| SqlStringTableError::Sql(e))
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
        rows: Vec<(i32, f64)>,
        executed: Vec<String>,
    }

    impl WeightTableConn for MemConn {
        fn execute_update(&mut self, sql: &str) -> Result<u64, SqlStringTableError> {
            self.executed.push(sql.to_string());
            if let Some(rest) = sql.strip_prefix("INSERT INTO weighttable (id,weight) VALUES(") {
                let rest = rest.trim_end_matches(')');
                let mut parts = rest.split(',');
                let id: i32 = parts.next().unwrap().parse().unwrap();
                let weight: f64 = parts.next().unwrap().parse().unwrap();
                self.rows.push((id, weight));
            }
            Ok(0)
        }

        fn select_all(&mut self, _sql: &str) -> Result<Vec<(i32, f64)>, SqlStringTableError> {
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

    fn make_table() -> WeightTable<MemConn> {
        let mut t = WeightTable::new();
        t.set_connection(MemConn::default());
        t
    }

    #[test]
    fn table_name_is_fixed() {
        let t: WeightTable<MemConn> = WeightTable::new();
        assert_eq!(t.table_name(), "weighttable");
    }

    #[test]
    fn create_executes_expected_sql() {
        let t: WeightTable<MemConn> = WeightTable::new();
        let mut st = RecordingStatement { executed: Vec::new() };
        t.create(&mut st).unwrap();
        assert_eq!(
            st.executed,
            vec!["CREATE TABLE weighttable(id integer,weight NUMERIC(24,20))".to_string()]
        );
    }

    #[test]
    fn drop_table_executes_expected_sql() {
        let t: WeightTable<MemConn> = WeightTable::new();
        let mut st = RecordingStatement { executed: Vec::new() };
        t.drop_table(&mut st).unwrap();
        assert_eq!(st.executed, vec!["DROP TABLE IF EXISTS weighttable".to_string()]);
    }

    #[test]
    fn insert_stores_row() {
        let mut t = make_table();
        t.insert(0, 1.5).unwrap();
        let conn = t.conn.as_ref().unwrap();
        assert_eq!(conn.rows, vec![(0, 1.5)]);
    }

    #[test]
    fn insert_without_connection_errors() {
        let mut t: WeightTable<MemConn> = WeightTable::new();
        let err = t.insert(0, 1.0).unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }

    #[test]
    fn recover_weights_rejects_incomplete_table() {
        let mut t = make_table();
        t.insert(0, 1.0).unwrap();
        t.insert(1, 2.0).unwrap();

        let mut factory = WeightFactory::new();
        let err = t.recover_weights(&mut factory).unwrap_err();
        assert!(matches!(err, SqlStringTableError::Sql(_)));
    }

    #[test]
    fn recover_weights_without_connection_errors() {
        let mut t: WeightTable<MemConn> = WeightTable::new();
        let mut factory = WeightFactory::new();
        let err = t.recover_weights(&mut factory).unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }

    #[test]
    fn close_relinquishes_connection() {
        let mut t = make_table();
        t.close();
        let err = t.insert(0, 1.0).unwrap_err();
        assert!(matches!(err, SqlStringTableError::NoConnection));
    }
}
