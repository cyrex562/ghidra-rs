//! Port of `ghidra.feature.fid.db.StringRecord`.

use crate::framework::db::record::DBRecord;
use crate::program::database::db_object::{DbObject, DbObjectState};

/// A string record in the FID database.
///
/// Port of `ghidra.feature.fid.db.StringRecord`. Java's `StringRecord extends DbObject`; per this
/// crate's composition-over-inheritance convention, this embeds a [`DbObjectState`] and
/// implements [`DbObject`] rather than inheriting from a base class.
pub struct StringRecord {
    state: DbObjectState,
    /// The value of the string.
    value: String,
}

impl StringRecord {
    /// Constructor with the primary key and the string value. Java: `StringRecord(long key,
    /// String value)`.
    pub fn new(key: i64, value: impl Into<String>) -> Self {
        Self { state: DbObjectState::new(key), value: value.into() }
    }

    /// Returns the value of the string. Java: `StringRecord.getValue()`.
    pub fn get_value(&self) -> String {
        self.value.clone()
    }
}

impl DbObject for StringRecord {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    /// Never need to refresh...this database object is immutable. Java: `refresh(DBRecord)`.
    fn refresh(&self, _record: Option<&DBRecord>) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_key_and_value() {
        let record = StringRecord::new(42, "hello");
        assert_eq!(record.get_key(), 42);
        assert_eq!(record.get_value(), "hello");
    }

    #[test]
    fn get_value_returns_an_independent_copy() {
        let record = StringRecord::new(1, "immutable");
        let a = record.get_value();
        let b = record.get_value();
        assert_eq!(a, b);
    }

    #[test]
    fn refresh_always_returns_false() {
        // Java: "Never need to refresh...this database object is immutable."
        let record = StringRecord::new(7, "x");
        assert!(!record.refresh(None));
    }

    #[test]
    fn accepts_owned_string_or_str_slice() {
        let from_str = StringRecord::new(1, "abc");
        let from_string = StringRecord::new(2, "def".to_string());
        assert_eq!(from_str.get_value(), "abc");
        assert_eq!(from_string.get_value(), "def");
    }
}
