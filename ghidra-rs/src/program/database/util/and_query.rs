use super::query::Query;
use crate::framework::db::DBRecord;

/// Combines two queries such that this query is the logical "AND" of the two queries. If the
/// first query does not match, then the second query is not executed.
///
/// Port of `ghidra.program.database.util.AndQuery`.
pub struct AndQuery {
    q1: Box<dyn Query>,
    q2: Box<dyn Query>,
}

impl AndQuery {
    /// Construct a new AndQuery from two other queries.
    ///
    /// # Parameters
    /// - `q1`: the first query
    /// - `q2`: the second query
    pub fn new(q1: Box<dyn Query>, q2: Box<dyn Query>) -> Self {
        Self { q1, q2 }
    }
}

impl Query for AndQuery {
    fn matches(&self, record: &DBRecord) -> bool {
        // Short-circuits like Java's `&&`: q2 is not evaluated unless q1 matches.
        self.q1.matches(record) && self.q2.matches(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use std::sync::Arc;
    use std::cell::Cell;
    use std::rc::Rc;

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

    struct Constant(bool);
    impl Query for Constant {
        fn matches(&self, _record: &DBRecord) -> bool {
            self.0
        }
    }

    #[test]
    fn test_and_true_true_is_true() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        let query = AndQuery::new(Box::new(Constant(true)), Box::new(Constant(true)));
        assert!(query.matches(&record));
    }

    #[test]
    fn test_and_true_false_is_false() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        let query = AndQuery::new(Box::new(Constant(true)), Box::new(Constant(false)));
        assert!(!query.matches(&record));
    }

    #[test]
    fn test_and_false_true_is_false() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        let query = AndQuery::new(Box::new(Constant(false)), Box::new(Constant(true)));
        assert!(!query.matches(&record));
    }

    #[test]
    fn test_and_false_false_is_false() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        let query = AndQuery::new(Box::new(Constant(false)), Box::new(Constant(false)));
        assert!(!query.matches(&record));
    }

    /// Mirrors the Java doc: "If the first query does not match, then the second query is not
    /// executed."
    struct RecordingQuery {
        result: bool,
        was_called: Rc<Cell<bool>>,
    }
    impl Query for RecordingQuery {
        fn matches(&self, _record: &DBRecord) -> bool {
            self.was_called.set(true);
            self.result
        }
    }

    #[test]
    fn test_and_short_circuits_when_first_query_fails() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        let second_called = Rc::new(Cell::new(false));
        let query = AndQuery::new(
            Box::new(Constant(false)),
            Box::new(RecordingQuery {
                result: true,
                was_called: Rc::clone(&second_called),
            }),
        );
        assert!(!query.matches(&record));
        assert!(!second_called.get(), "second query must not be evaluated");
    }
}
