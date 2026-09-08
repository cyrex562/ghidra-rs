use super::query::Query;
use crate::framework::db::{DBRecord, Field};

/// Query implementation used to test a field in a record to fall within a range of values.
///
/// Port of `ghidra.program.database.util.FieldRangeQuery`. Note that, per the Java
/// implementation, both bounds are **exclusive**: a record matches only if its field is
/// strictly greater than `min` and strictly less than `max`.
pub struct FieldRangeQuery {
    column: usize,
    min: Field,
    max: Field,
}

impl FieldRangeQuery {
    /// Constructs a new FieldRangeQuery that tests a record's field against a range of values.
    ///
    /// # Parameters
    /// - `column`: the field index in the record to test.
    /// - `min`: the minimum field value to test against (exclusive).
    /// - `max`: the maximum field value to test against (exclusive).
    pub fn new(column: usize, min: Field, max: Field) -> Self {
        Self { column, min, max }
    }
}

impl Query for FieldRangeQuery {
    fn matches(&self, record: &DBRecord) -> bool {
        // Java: `(record.compareFieldTo(column, min) > 0) && (record.compareFieldTo(column, max) < 0)`
        // i.e. strictly between min and max -- both bounds excluded.
        let field = record.get_field(self.column);
        *field > self.min && *field < self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
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

    fn record_with(value: i32) -> DBRecord {
        let schema = make_schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(1)));
        record.set_field(0, Field::Int(Some(value)));
        record
    }

    #[test]
    fn test_matches_strictly_inside_range() {
        let query = FieldRangeQuery::new(0, Field::Int(Some(5)), Field::Int(Some(10)));
        assert!(query.matches(&record_with(7)));
    }

    #[test]
    fn test_does_not_match_at_min_boundary_exclusive() {
        let query = FieldRangeQuery::new(0, Field::Int(Some(5)), Field::Int(Some(10)));
        assert!(!query.matches(&record_with(5)));
    }

    #[test]
    fn test_does_not_match_at_max_boundary_exclusive() {
        let query = FieldRangeQuery::new(0, Field::Int(Some(5)), Field::Int(Some(10)));
        assert!(!query.matches(&record_with(10)));
    }

    #[test]
    fn test_does_not_match_below_range() {
        let query = FieldRangeQuery::new(0, Field::Int(Some(5)), Field::Int(Some(10)));
        assert!(!query.matches(&record_with(4)));
    }

    #[test]
    fn test_does_not_match_above_range() {
        let query = FieldRangeQuery::new(0, Field::Int(Some(5)), Field::Int(Some(10)));
        assert!(!query.matches(&record_with(11)));
    }

    #[test]
    fn test_empty_range_matches_nothing() {
        // min == max: no value can be both strictly greater than min and strictly less than it.
        let query = FieldRangeQuery::new(0, Field::Int(Some(5)), Field::Int(Some(5)));
        assert!(!query.matches(&record_with(5)));
        assert!(!query.matches(&record_with(4)));
        assert!(!query.matches(&record_with(6)));
    }
}
