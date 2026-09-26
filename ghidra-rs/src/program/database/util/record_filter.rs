use crate::framework::db::DBRecord;

/// Filter used to select a subset of records.
///
/// Port of `ghidra.program.database.util.RecordFilter`.
pub trait RecordFilter {
    /// Returns true if the given record matches this filter's criteria.
    fn matches(&self, record: &DBRecord) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, Schema};
    use std::sync::Arc;

    struct KeyEqualsFilter {
        key: Field,
    }

    impl RecordFilter for KeyEqualsFilter {
        fn matches(&self, record: &DBRecord) -> bool {
            *record.get_key() == self.key
        }
    }

    fn make_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            crate::framework::db::FieldType::Long,
            "Key".to_string(),
            vec![],
            vec![],
            vec![],
        ))
    }

    #[test]
    fn test_matches_true_for_equal_key() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(42)));
        let filter = KeyEqualsFilter {
            key: Field::Long(Some(42)),
        };
        assert!(filter.matches(&record));
    }

    #[test]
    fn test_matches_false_for_different_key() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(42)));
        let filter = KeyEqualsFilter {
            key: Field::Long(Some(7)),
        };
        assert!(!filter.matches(&record));
    }

    #[test]
    fn test_object_safe() {
        let schema = make_schema();
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        let filter: Box<dyn RecordFilter> = Box::new(KeyEqualsFilter {
            key: Field::Long(Some(1)),
        });
        assert!(filter.matches(&record));
    }
}
