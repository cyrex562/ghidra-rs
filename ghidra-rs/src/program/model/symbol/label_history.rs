use crate::program::model::address::Address;
use std::time::SystemTime;

/// Label history action identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i8)]
pub enum LabelHistoryAction {
    /// Label added.
    Add = 0,
    /// Label removed.
    Remove = 1,
    /// Label renamed.
    Rename = 2,
}

impl LabelHistoryAction {
    /// Java-compatible action id for added labels.
    pub const ADD: i8 = 0;
    /// Java-compatible action id for removed labels.
    pub const REMOVE: i8 = 1;
    /// Java-compatible action id for renamed labels.
    pub const RENAME: i8 = 2;

    /// Converts a Java action id into a typed action.
    pub const fn from_action_id(action_id: i8) -> Option<Self> {
        match action_id {
            Self::ADD => Some(Self::Add),
            Self::REMOVE => Some(Self::Remove),
            Self::RENAME => Some(Self::Rename),
            _ => None,
        }
    }

    /// Returns the Java-compatible action id.
    pub const fn action_id(self) -> i8 {
        self as i8
    }
}

/// Container for history information about a label change.
///
/// This mirrors Ghidra's `LabelHistory`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelHistory {
    address: Address,
    user_name: String,
    action: LabelHistoryAction,
    label_string: String,
    modification_date: SystemTime,
}

impl LabelHistory {
    /// Constructs a label history entry.
    pub fn new(
        address: Address,
        user_name: impl Into<String>,
        action: LabelHistoryAction,
        label_string: impl Into<String>,
        modification_date: SystemTime,
    ) -> Self {
        Self {
            address,
            user_name: user_name.into(),
            action,
            label_string: label_string.into(),
            modification_date,
        }
    }

    /// Returns the address of the label change.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the user that made the change.
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Returns the label string.
    pub fn label_string(&self) -> &str {
        &self.label_string
    }

    /// Returns the typed action.
    pub fn action(&self) -> LabelHistoryAction {
        self.action
    }

    /// Returns the Java-compatible action id.
    pub fn action_id(&self) -> i8 {
        self.action.action_id()
    }

    /// Returns the modification date.
    pub fn modification_date(&self) -> SystemTime {
        self.modification_date
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::time::{Duration, UNIX_EPOCH};

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0x2000)
    }

    #[test]
    fn action_ids_match_java_constants() {
        assert_eq!(LabelHistoryAction::Add.action_id(), 0);
        assert_eq!(LabelHistoryAction::Remove.action_id(), 1);
        assert_eq!(LabelHistoryAction::Rename.action_id(), 2);
        assert_eq!(
            LabelHistoryAction::from_action_id(0),
            Some(LabelHistoryAction::Add)
        );
        assert_eq!(
            LabelHistoryAction::from_action_id(1),
            Some(LabelHistoryAction::Remove)
        );
        assert_eq!(
            LabelHistoryAction::from_action_id(2),
            Some(LabelHistoryAction::Rename)
        );
        assert_eq!(LabelHistoryAction::from_action_id(3), None);
    }

    #[test]
    fn stores_label_history_fields() {
        let address = test_address();
        let date = UNIX_EPOCH + Duration::from_secs(42);
        let history = LabelHistory::new(
            address.clone(),
            "user",
            LabelHistoryAction::Rename,
            "new_label",
            date,
        );

        assert_eq!(history.address(), &address);
        assert_eq!(history.user_name(), "user");
        assert_eq!(history.label_string(), "new_label");
        assert_eq!(history.action(), LabelHistoryAction::Rename);
        assert_eq!(history.action_id(), LabelHistoryAction::RENAME);
        assert_eq!(history.modification_date(), date);
    }
}
