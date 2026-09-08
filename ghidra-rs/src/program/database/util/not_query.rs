use super::query::Query;
use crate::framework::db::DBRecord;

/// Negates the given query such that this query is the logical "NOT" of the given query.
///
/// Port of `ghidra.program.database.util.NotQuery`.
pub struct NotQuery {
    q1: Box<dyn Query>,
}

impl NotQuery {
    /// Construct a new query that results in the not of the given query.
    ///
    /// # Parameters
    /// - `q1`: the query to logically negate.
    pub fn new(q1: Box<dyn Query>) -> Self {
        Self { q1 }
    }
}

impl Query for NotQuery {
    fn matches(&self, record: &DBRecord) -> bool {
        !self.q1.matches(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::sync::Arc;

    fn make_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::Int],
            vec!["Value".to_string()],
            vec![],
        ))
    }

    struct AlwaysTrue;
    impl Query for AlwaysTrue {
        fn matches(&self, _record: &DBRecord) -> bool {
            true
        }
    }

    struct AlwaysFalse;
    impl Query for AlwaysFalse {
        fn matches(&self, _record: &DBRecord) -> bool {
            false
        }
    }

    #[test]
    fn test_not_negates_true_to_false() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        let query = NotQuery::new(Box::new(AlwaysTrue));
        assert!(!query.matches(&record));
    }

    #[test]
    fn test_not_negates_false_to_true() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        let query = NotQuery::new(Box::new(AlwaysFalse));
        assert!(query.matches(&record));
    }
}
