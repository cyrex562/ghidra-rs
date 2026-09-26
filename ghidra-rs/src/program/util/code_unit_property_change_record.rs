use std::any::Any;
use std::fmt;

use crate::program::model::address::Address;
use crate::program::util::{ProgramChangeRecord, ProgramEvent};

/// Change record generated when a property on a code unit changes.
///
/// Port of `ghidra.program.util.CodeUnitPropertyChangeRecord`. Wraps a
/// [`ProgramChangeRecord`] and adds the name of the code unit property that changed.
pub struct CodeUnitPropertyChangeRecord {
    base: ProgramChangeRecord,
    property_name: String,
}

impl CodeUnitPropertyChangeRecord {
    /// Construct a change record for a property change at a single address.
    ///
    /// # Arguments
    /// * `event_type` - the program event type
    /// * `property_name` - the name of the code unit property
    /// * `address` - the address of the property that was changed
    /// * `old_value` - the old property value
    /// * `new_value` - the new property value
    pub fn new(
        event_type: ProgramEvent,
        property_name: impl Into<String>,
        address: Address,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    ) -> Self {
        Self {
            base: ProgramChangeRecord::new(
                event_type,
                Some(address.clone()),
                Some(address),
                None,
                old_value,
                new_value,
            ),
            property_name: property_name.into(),
        }
    }

    /// Construct a change record for a property change affecting a range of addresses.
    ///
    /// # Arguments
    /// * `event_type` - the program event type
    /// * `property_name` - the name of the code unit property
    /// * `start` - the start address of the range affected
    /// * `end` - the end address of the range affected
    pub fn new_range(
        event_type: ProgramEvent,
        property_name: impl Into<String>,
        start: Address,
        end: Address,
    ) -> Self {
        Self {
            base: ProgramChangeRecord::new(event_type, Some(start), Some(end), None, None, None),
            property_name: property_name.into(),
        }
    }

    /// Get the name of the property being changed.
    pub fn property_name(&self) -> &str {
        &self.property_name
    }

    /// Returns a reference to the underlying [`ProgramChangeRecord`].
    pub fn base(&self) -> &ProgramChangeRecord {
        &self.base
    }
}

impl std::ops::Deref for CodeUnitPropertyChangeRecord {
    type Target = ProgramChangeRecord;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl fmt::Display for CodeUnitPropertyChangeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, property = {}", self.base, self.property_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::event_type::EventType;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn new_stores_property_name() {
        let addr = addr(0x1000);
        let record =
            CodeUnitPropertyChangeRecord::new(ProgramEvent::CommentChanged, "EOL", addr, None, None);
        assert_eq!(record.property_name(), "EOL");
    }

    #[test]
    fn new_uses_address_for_both_start_and_end() {
        let addr = addr(0x1000);
        let record = CodeUnitPropertyChangeRecord::new(
            ProgramEvent::CommentChanged,
            "EOL",
            addr.clone(),
            None,
            None,
        );
        assert_eq!(record.start(), Some(&addr));
        assert_eq!(record.end(), Some(&addr));
    }

    #[test]
    fn new_stores_old_and_new_values() {
        let addr = addr(0x1000);
        let old = Some(Box::new("old".to_string()) as Box<dyn Any + Send + Sync>);
        let new = Some(Box::new("new".to_string()) as Box<dyn Any + Send + Sync>);
        let record =
            CodeUnitPropertyChangeRecord::new(ProgramEvent::CommentChanged, "EOL", addr, old, new);
        assert_eq!(
            record.change_record().old_value().unwrap().downcast_ref::<String>(),
            Some(&"old".to_string())
        );
        assert_eq!(
            record.change_record().new_value().unwrap().downcast_ref::<String>(),
            Some(&"new".to_string())
        );
    }

    #[test]
    fn new_range_has_no_old_or_new_value() {
        let start = addr(0x1000);
        let end = addr(0x2000);
        let record = CodeUnitPropertyChangeRecord::new_range(
            ProgramEvent::CommentChanged,
            "EOL",
            start,
            end,
        );
        assert!(record.change_record().old_value().is_none());
        assert!(record.change_record().new_value().is_none());
    }

    #[test]
    fn new_range_stores_start_and_end() {
        let start = addr(0x1000);
        let end = addr(0x2000);
        let record = CodeUnitPropertyChangeRecord::new_range(
            ProgramEvent::CommentChanged,
            "EOL",
            start.clone(),
            end.clone(),
        );
        assert_eq!(record.start(), Some(&start));
        assert_eq!(record.end(), Some(&end));
    }

    #[test]
    fn display_includes_property_name() {
        let addr = addr(0x1000);
        let record =
            CodeUnitPropertyChangeRecord::new(ProgramEvent::CommentChanged, "EOL", addr, None, None);
        let s = format!("{}", record);
        assert!(s.contains(", property = EOL"));
    }

    #[test]
    fn deref_exposes_program_change_record_accessors() {
        let addr = addr(0x1000);
        let record =
            CodeUnitPropertyChangeRecord::new(ProgramEvent::CommentChanged, "EOL", addr, None, None);
        assert_eq!(
            record.change_record().event_type().get_id(),
            ProgramEvent::CommentChanged.get_id()
        );
    }
}
