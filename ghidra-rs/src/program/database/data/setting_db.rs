//! Port of `ghidra.program.database.data.SettingDB`.
//!
//! Setting `DBRecord` wrapper for cache use.

use crate::framework::db::{DBRecord, Field};
use crate::program::database::data::settings_db_adapter::{
    SETTINGS_LONG_VALUE_COL, SETTINGS_STRING_VALUE_COL,
};

/// The value held by a [`SettingDB`], mirroring the `Object` returned by the Java
/// `SettingDB.getValue()` method: either a string value or a long value, never both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingValue {
    /// A string-valued setting.
    String(String),
    /// A long-valued setting.
    Long(i64),
}

/// Setting `DBRecord` wrapper for cache use.
///
/// Port of `ghidra.program.database.data.SettingDB`.
pub struct SettingDB {
    name: String,
    record: DBRecord,
}

impl SettingDB {
    /// Construct a setting object.
    ///
    /// `record` is the setting record, `name` is the setting name.
    pub fn new(record: DBRecord, name: String) -> Self {
        SettingDB { name, record }
    }

    /// Get the setting name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the long value, or `None` if the setting holds a string value instead.
    pub fn get_long_value(&self) -> Option<i64> {
        if self.get_string_value().is_some() {
            return None;
        }
        match self.record.get_field(SETTINGS_LONG_VALUE_COL) {
            Field::Long(v) => *v,
            _ => None,
        }
    }

    /// Get the string value, or `None` if the setting holds a long value instead.
    pub fn get_string_value(&self) -> Option<&str> {
        self.record.get_string(SETTINGS_STRING_VALUE_COL)
    }

    /// Get the setting's value: the string value if present, else the long value.
    pub fn get_value(&self) -> Option<SettingValue> {
        if let Some(s) = self.get_string_value() {
            return Some(SettingValue::String(s.to_string()));
        }
        self.get_long_value().map(SettingValue::Long)
    }

    /// Get the record's key.
    pub fn get_key(&self) -> i64 {
        match self.record.get_key() {
            Field::Long(Some(v)) => *v,
            _ => 0,
        }
    }

    /// Get the underlying record.
    pub fn get_record(&self) -> &DBRecord {
        &self.record
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use std::sync::Arc;

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Settings ID".to_string(),
            vec![
                FieldType::Long,
                FieldType::Short,
                FieldType::Long,
                FieldType::String,
            ],
            vec![
                "Association ID".to_string(),
                "Name Index".to_string(),
                "Long Value".to_string(),
                "String Value".to_string(),
            ],
            vec![],
        ))
    }

    #[test]
    fn wraps_long_value_record() {
        let mut record = DBRecord::new(schema(), Field::Long(Some(5)));
        record.set_field(SETTINGS_LONG_VALUE_COL, Field::Long(Some(42)));
        record.set_field(SETTINGS_STRING_VALUE_COL, Field::String(None));

        let setting = SettingDB::new(record, "format".to_string());
        assert_eq!(setting.get_name(), "format");
        assert_eq!(setting.get_long_value(), Some(42));
        assert_eq!(setting.get_string_value(), None);
        assert_eq!(setting.get_value(), Some(SettingValue::Long(42)));
        assert_eq!(setting.get_key(), 5);
    }

    #[test]
    fn wraps_string_value_record() {
        let mut record = DBRecord::new(schema(), Field::Long(Some(6)));
        record.set_field(SETTINGS_LONG_VALUE_COL, Field::Long(Some(-1)));
        record.set_field(
            SETTINGS_STRING_VALUE_COL,
            Field::String(Some("hex".to_string())),
        );

        let setting = SettingDB::new(record, "format".to_string());
        // A non-null string value takes precedence over the long value column, matching the
        // Java `getLongValue`/`getValue` behavior.
        assert_eq!(setting.get_long_value(), None);
        assert_eq!(setting.get_string_value(), Some("hex"));
        assert_eq!(
            setting.get_value(),
            Some(SettingValue::String("hex".to_string()))
        );
    }

    #[test]
    fn get_record_returns_underlying_record() {
        let record = DBRecord::new(schema(), Field::Long(Some(1)));
        let setting = SettingDB::new(record.clone(), "x".to_string());
        assert_eq!(setting.get_record().get_key(), record.get_key());
    }
}
