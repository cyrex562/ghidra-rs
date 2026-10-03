use super::query::Query;
use crate::framework::db::{DBRecord, Field};

/// Query implementation used to test a field in a record to match a given value.
///
/// Port of `ghidra.program.database.util.FieldMatchQuery`.
pub struct FieldMatchQuery {
    column: usize,
    value: Field,
}

impl FieldMatchQuery {
    /// Constructs a new FieldMatchQuery that tests a record's field against a particular value.
    ///
    /// # Parameters
    /// - `column`: the field index in the record to test.
    /// - `value`: the Field value to test the record's field against.
    pub fn new(column: usize, value: Field) -> Self {
        Self { column, value }
    }
}

impl Query for FieldMatchQuery {
    fn matches(&self, record: &DBRecord) -> bool {
        // Java: `record.fieldEquals(column, value)`, i.e. `fieldValues[column].equals(value)`.
        *record.get_field(self.column) == self.value
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
            vec![FieldType::Int, FieldType::String],
            vec!["IntCol".to_string(), "StrCol".to_string()],
            vec![],
        ))
    }

    #[test]
    fn test_matches_when_field_equals_value() {
        let schema = make_schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(1)));
        record.set_field(0, Field::Int(Some(42)));
        let query = FieldMatchQuery::new(0, Field::Int(Some(42)));
        assert!(query.matches(&record));
    }

    #[test]
    fn test_does_not_match_when_field_differs() {
        let schema = make_schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(1)));
        record.set_field(0, Field::Int(Some(42)));
        let query = FieldMatchQuery::new(0, Field::Int(Some(7)));
        assert!(!query.matches(&record));
    }

    #[test]
    fn test_matches_string_field() {
        let schema = make_schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(1)));
        record.set_field(1, Field::String(Some("hello".to_string())));
        let query = FieldMatchQuery::new(1, Field::String(Some("hello".to_string())));
        assert!(query.matches(&record));
    }

    #[test]
    fn test_does_not_match_null_vs_value() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        // StrCol defaults to null (sparse-like default for variable-length columns).
        let query = FieldMatchQuery::new(1, Field::String(Some("hello".to_string())));
        assert!(!query.matches(&record));
    }
}
