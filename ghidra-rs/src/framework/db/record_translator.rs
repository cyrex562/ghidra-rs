use crate::framework::db::record::DBRecord;

/// Translates old database records into current database records.
pub trait RecordTranslator {
    /// Translate the indicated old database record into a current database record.
    ///
    /// Returns the new database record in the form required for the current
    /// database version, or an I/O error if translation fails.
    fn translate_record(&self, old_record: DBRecord) -> std::io::Result<DBRecord>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::schema::Schema;
    use std::sync::Arc;

    struct IdentityTranslator;

    impl RecordTranslator for IdentityTranslator {
        fn translate_record(&self, old_record: DBRecord) -> std::io::Result<DBRecord> {
            Ok(old_record)
        }
    }

    #[test]
    fn test_object_safe_dyn_usage() {
        let schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![],
            vec![],
            vec![],
        ));
        let record = DBRecord::new(schema, Field::Long(Some(1)));

        let translator: Box<dyn RecordTranslator> = Box::new(IdentityTranslator);
        let translated = translator.translate_record(record).unwrap();
        assert_eq!(translated.get_key().get_long_value(), 1);
    }
}
