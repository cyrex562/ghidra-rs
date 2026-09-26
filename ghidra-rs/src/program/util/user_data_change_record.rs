use std::any::Any;
use std::fmt;

use crate::framework::model::DomainObjectChangeRecord;
use crate::program::util::ProgramEvent;

/// Change record for user data modifications on code units and other program entities.
///
/// Port of `ghidra.program.util.UserDataChangeRecord`. Wraps a `DomainObjectChangeRecord`
/// and adds a `property_name` field to track which property was modified.
pub struct UserDataChangeRecord {
    property_name: String,
    record: DomainObjectChangeRecord,
}

impl UserDataChangeRecord {
    /// Create a change record for a user data property modification with old and new values.
    ///
    /// # Arguments
    /// * `property_name` - name of the property being changed
    /// * `old_value` - the previous value
    /// * `new_value` - the new value
    pub fn new_with_values(
        property_name: impl Into<String>,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    ) -> Self {
        Self {
            property_name: property_name.into(),
            record: DomainObjectChangeRecord::with_values(
                Box::new(ProgramEvent::UserDataChanged),
                old_value,
                new_value,
            ),
        }
    }

    /// Create a change record for removal of a range of user data properties.
    ///
    /// # Arguments
    /// * `property_name` - name of the property range being removed
    pub fn new_for_range_removed(property_name: impl Into<String>) -> Self {
        Self {
            property_name: property_name.into(),
            record: DomainObjectChangeRecord::new(Box::new(
                ProgramEvent::CodeUnitPropertyRangeRemoved,
            )),
        }
    }

    /// Returns the name of the property being changed.
    pub fn property_name(&self) -> &str {
        &self.property_name
    }

    /// Returns the underlying change record.
    pub fn record(&self) -> &DomainObjectChangeRecord {
        &self.record
    }
}

impl fmt::Display for UserDataChangeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, property = {}", self.record, self.property_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_values_stores_property_name() {
        let record = UserDataChangeRecord::new_with_values("test_prop", None, None);
        assert_eq!(record.property_name(), "test_prop");
    }

    #[test]
    fn new_with_values_stores_old_and_new_values() {
        let old = Some(Box::new("old".to_string()) as Box<dyn Any + Send + Sync>);
        let new = Some(Box::new("new".to_string()) as Box<dyn Any + Send + Sync>);
        let record = UserDataChangeRecord::new_with_values("my_prop", old, new);

        assert_eq!(record.property_name(), "my_prop");
        assert!(record.record().old_value().is_some());
        assert!(record.record().new_value().is_some());
    }

    #[test]
    fn new_with_values_can_omit_values() {
        let record = UserDataChangeRecord::new_with_values("prop", None, None);
        assert!(record.record().old_value().is_none());
        assert!(record.record().new_value().is_none());
    }

    #[test]
    fn new_for_range_removed_creates_correct_event() {
        let record = UserDataChangeRecord::new_for_range_removed("removed_prop");
        assert_eq!(record.property_name(), "removed_prop");
        assert!(record.record().old_value().is_none());
        assert!(record.record().new_value().is_none());
    }

    #[test]
    fn display_includes_property_name() {
        let record = UserDataChangeRecord::new_with_values("my_property", None, None);
        let display_str = format!("{}", record);
        assert!(display_str.contains("my_property"));
    }

    #[test]
    fn display_includes_record_info() {
        let record = UserDataChangeRecord::new_with_values("prop", None, None);
        let display_str = format!("{}", record);
        assert!(display_str.contains("DomainObjectChangeRecord"));
    }

    #[test]
    fn new_with_values_with_string_property_name() {
        let prop_name = String::from("dynamic_property");
        let record = UserDataChangeRecord::new_with_values(prop_name, None, None);
        assert_eq!(record.property_name(), "dynamic_property");
    }

    #[test]
    fn new_with_values_with_only_old_value() {
        let old = Some(Box::new(42) as Box<dyn Any + Send + Sync>);
        let record = UserDataChangeRecord::new_with_values("int_prop", old, None);
        assert!(record.record().old_value().is_some());
        assert!(record.record().new_value().is_none());
    }

    #[test]
    fn new_with_values_with_only_new_value() {
        let new = Some(Box::new(true) as Box<dyn Any + Send + Sync>);
        let record = UserDataChangeRecord::new_with_values("bool_prop", None, new);
        assert!(record.record().old_value().is_none());
        assert!(record.record().new_value().is_some());
    }
}
