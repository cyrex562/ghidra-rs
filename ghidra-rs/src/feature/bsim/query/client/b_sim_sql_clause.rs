/// The SQL clauses for all the filters that are to be used in a BSim query.
///
/// Mirrors `ghidra.features.bsim.query.client.BSimSqlClause`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BSimSqlClause {
    pub table_clause: String,
    pub where_clause: String,
}

impl BSimSqlClause {
    pub fn new(table_clause: impl Into<String>, where_clause: impl Into<String>) -> Self {
        Self {
            table_clause: table_clause.into(),
            where_clause: where_clause.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_stores_clauses() {
        let clause = BSimSqlClause::new("mytable", "col = 1");
        assert_eq!(clause.table_clause, "mytable");
        assert_eq!(clause.where_clause, "col = 1");
    }

    #[test]
    fn test_empty_clauses() {
        let clause = BSimSqlClause::new("", "");
        assert_eq!(clause.table_clause, "");
        assert_eq!(clause.where_clause, "");
    }

    #[test]
    fn test_clone_and_eq() {
        let a = BSimSqlClause::new("t", "w");
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, BSimSqlClause::new("t", "other"));
    }

    #[test]
    fn test_debug() {
        let clause = BSimSqlClause::new("tbl", "x > 0");
        let s = format!("{:?}", clause);
        assert!(s.contains("tbl"));
        assert!(s.contains("x > 0"));
    }
}
