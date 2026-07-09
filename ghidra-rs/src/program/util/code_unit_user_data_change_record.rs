use std::any::Any;
use std::fmt;

use crate::framework::model::DomainObjectChangeRecord;
use crate::program::model::address::Address;
use crate::program::util::ProgramEvent;

/// Change record for user data modifications on code units.
///
/// Port of `ghidra.program.util.CodeUnitUserDataChangeRecord`. Wraps a
/// `DomainObjectChangeRecord` and adds both a `property_name` and an `address` field
/// to track which property was modified and at which code unit address.
pub struct CodeUnitUserDataChangeRecord {
    property_name: String,
    address: Option<Address>,
    record: DomainObjectChangeRecord,
}

impl CodeUnitUserDataChangeRecord {
    /// Create a change record for a code unit user data property modification.
    ///
    /// # Arguments
    /// * `property_name` - name of the property being changed
    /// * `code_unit_addr` - address of the code unit (may be None)
    /// * `old_value` - the previous value
    /// * `new_value` - the new value
    pub fn new(
        property_name: impl Into<String>,
        code_unit_addr: Option<Address>,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    ) -> Self {
        Self {
            property_name: property_name.into(),
            address: code_unit_addr,
            record: DomainObjectChangeRecord::with_values(
                Box::new(ProgramEvent::CodeUnitUserDataChanged),
                old_value,
                new_value,
            ),
        }
    }

    /// Returns the name of the property being changed.
    pub fn property_name(&self) -> &str {
        &self.property_name
    }

    /// Returns the address of the code unit for this property change.
    pub fn address(&self) -> Option<&Address> {
        self.address.as_ref()
    }

    /// Returns the underlying change record.
    pub fn record(&self) -> &DomainObjectChangeRecord {
        &self.record
    }
}

impl fmt::Display for CodeUnitUserDataChangeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, property = {}", self.record, self.property_name)?;
        if let Some(addr) = &self.address {
            write!(f, ", address = {}", addr)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_property_name() {
        let record = CodeUnitUserDataChangeRecord::new("test_prop", None, None, None);
        assert_eq!(record.property_name(), "test_prop");
    }

    #[test]
    fn new_stores_address() {
        // Address creation would require an AddressSpace; testing with None for basic case
        let record = CodeUnitUserDataChangeRecord::new("prop", None, None, None);
        assert!(record.address().is_none());
    }

    #[test]
    fn new_stores_old_and_new_values() {
        let old = Some(Box::new("old".to_string()) as Box<dyn Any + Send + Sync>);
        let new = Some(Box::new("new".to_string()) as Box<dyn Any + Send + Sync>);
        let record = CodeUnitUserDataChangeRecord::new("my_prop", None, old, new);

        assert_eq!(record.property_name(), "my_prop");
        assert!(record.record().old_value().is_some());
        assert!(record.record().new_value().is_some());
    }

    #[test]
    fn new_can_omit_values() {
        let record = CodeUnitUserDataChangeRecord::new("prop", None, None, None);
        assert!(record.record().old_value().is_none());
        assert!(record.record().new_value().is_none());
    }

    #[test]
    fn display_includes_property_name() {
        let record = CodeUnitUserDataChangeRecord::new("my_property", None, None, None);
        let display_str = format!("{}", record);
        assert!(display_str.contains("my_property"));
    }

    #[test]
    fn display_includes_record_info() {
        let record = CodeUnitUserDataChangeRecord::new("prop", None, None, None);
        let display_str = format!("{}", record);
        assert!(display_str.contains("DomainObjectChangeRecord"));
    }

    #[test]
    fn new_with_string_property_name() {
        let prop_name = String::from("dynamic_property");
        let record = CodeUnitUserDataChangeRecord::new(prop_name, None, None, None);
        assert_eq!(record.property_name(), "dynamic_property");
    }

    #[test]
    fn new_with_only_old_value() {
        let old = Some(Box::new(42) as Box<dyn Any + Send + Sync>);
        let record = CodeUnitUserDataChangeRecord::new("int_prop", None, old, None);
        assert!(record.record().old_value().is_some());
        assert!(record.record().new_value().is_none());
    }

    #[test]
    fn new_with_only_new_value() {
        let new = Some(Box::new(true) as Box<dyn Any + Send + Sync>);
        let record = CodeUnitUserDataChangeRecord::new("bool_prop", None, None, new);
        assert!(record.record().old_value().is_none());
        assert!(record.record().new_value().is_some());
    }

    #[test]
    fn record_uses_code_unit_user_data_changed_event() {
        let record = CodeUnitUserDataChangeRecord::new("prop", None, None, None);
        assert_eq!(
            record.record().event_type().get_id(),
            ProgramEvent::CodeUnitUserDataChanged.get_id()
        );
    }
}
