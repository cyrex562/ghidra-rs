//! A row in the Watches table.
//!
//! Port of `ghidra.debug.api.watch.WatchRow`.

use crate::docking::settings::settings::Settings;
use crate::program::model::address::{Address, AddressRange, AddressSetView};
use crate::program::model::data::data_type::DataType;
use crate::program::model::symbol::Symbol;
use std::any::Any;
use std::sync::Arc;

/// A row in the Watches table.
pub trait WatchRow {
    /// Get the Sleigh expression.
    ///
    /// Port of `WatchRow.getExpression()`.
    fn get_expression(&self) -> String;

    /// Set the Sleigh expression.
    ///
    /// Port of `WatchRow.setExpression(String)`.
    fn set_expression(&mut self, expression: &str);

    /// Get the data type for interpreting the value.
    ///
    /// Port of `WatchRow.getDataType()`.
    fn get_data_type(&self) -> Option<Box<dyn DataType>>;

    /// Set the data type for interpreting the value.
    ///
    /// Port of `WatchRow.setDataType(DataType)`.
    fn set_data_type(&mut self, data_type: Option<Box<dyn DataType>>);

    /// Get the (mutable) settings on the data type.
    ///
    /// The returned settings may be modified, after which
    /// [`settings_changed`](WatchRow::settings_changed) must be called. There is no
    /// `set_settings` method.
    ///
    /// Port of `WatchRow.getSettings()`.
    fn get_settings(&mut self) -> &mut dyn Settings;

    /// Notify the row that the settings were changed.
    ///
    /// Port of `WatchRow.settingsChanged()`.
    fn settings_changed(&mut self);

    /// Get the address of the value, if it exists at one (memory or register).
    ///
    /// Port of `WatchRow.getAddress()`.
    fn get_address(&self) -> Option<Address>;

    /// Get the address range of the value, if it exists at an address (memory or register).
    ///
    /// Port of `WatchRow.getRange()`.
    fn get_range(&self) -> Option<AddressRange>;

    /// Get the complete set of all addresses read to evaluate the expression.
    ///
    /// Port of `WatchRow.getReads()`.
    fn get_reads(&self) -> Option<Box<dyn AddressSetView>>;

    /// Get the nearest symbol before the value's address, if applicable.
    ///
    /// Port of `WatchRow.getSymbol()`.
    fn get_symbol(&self) -> Option<Arc<dyn Symbol>>;

    /// Get the raw value.
    ///
    /// Port of `WatchRow.getValue()`.
    fn get_value(&self) -> Option<Vec<u8>>;

    /// Get the raw value displayed as a string.
    ///
    /// For values in memory, this is a list of hex bytes. For others, it is a hex integer
    /// subject to the platform's endian.
    ///
    /// Port of `WatchRow.getRawValueString()`.
    fn get_raw_value_string(&self) -> Option<String>;

    /// Get the number of bytes in the value, or 0 if evaluation failed.
    ///
    /// Port of `WatchRow.getValueLength()`.
    fn get_value_length(&self) -> i32;

    /// Patch memory or register values such that the expression evaluates to the given raw
    /// value.
    ///
    /// This is only supported when [`is_raw_value_editable`](WatchRow::is_raw_value_editable)
    /// returns true. The given value must be a list of hex bytes (as returned by
    /// [`get_raw_value_string`](WatchRow::get_raw_value_string)), or a hex integer subject to
    /// the platform's endian. Either is accepted, regardless of whether the value resides in
    /// memory.
    ///
    /// Port of `WatchRow.setRawValueString(String)`.
    fn set_raw_value_string(&mut self, value: &str);

    /// Check if [`set_raw_value_string`](WatchRow::set_raw_value_string) is supported.
    ///
    /// Setting the value may not be supported for many reasons: 1) The expression is not valid,
    /// 2) The expression could not be evaluated, 3) The value has no address or register.
    ///
    /// Port of `WatchRow.isRawValueEditable()`.
    fn is_raw_value_editable(&self) -> bool;

    /// Get the value as returned by the data type.
    ///
    /// Port of `WatchRow.getValueObject()`.
    fn get_value_object(&self) -> Option<Box<dyn Any>>;

    /// Get the value as represented by the data type.
    ///
    /// Port of `WatchRow.getValueString()`.
    fn get_value_string(&self) -> Option<String>;

    /// Patch memory or register values such that the expression evaluates to the given value.
    ///
    /// This is only supported when [`is_value_editable`](WatchRow::is_value_editable) returns
    /// true. The given value must be encodable by the data type.
    ///
    /// Port of `WatchRow.setValueString(String)`.
    fn set_value_string(&mut self, value: &str);

    /// Check if [`set_value_string`](WatchRow::set_value_string) is supported.
    ///
    /// In addition to those reasons given in
    /// [`is_raw_value_editable`](WatchRow::is_raw_value_editable), setting the value may not be
    /// supported because: 1) No data type is set, or 2) The selected data type does not support
    /// encoding.
    ///
    /// Port of `WatchRow.isValueEditable()`.
    fn is_value_editable(&self) -> bool;

    /// If the watch could not be evaluated, get the cause.
    ///
    /// Port of `WatchRow.getError()`.
    fn get_error(&self) -> Option<&(dyn std::error::Error + Send + Sync)>;

    /// If the watch could not be evaluated, get a message explaining why.
    ///
    /// This is essentially the message given by [`get_error`](WatchRow::get_error). If the
    /// error does not provide a message, this will at least give the name of the error type.
    ///
    /// Port of `WatchRow.getErrorMessage()`.
    fn get_error_message(&self) -> String;

    /// Check if the value given is actually known to be the value.
    ///
    /// If the value itself or any value encountered during the evaluation of the expression is
    /// stale, then the final value is considered stale, i.e., not known.
    ///
    /// Port of `WatchRow.isKnown()`.
    fn is_known(&self) -> bool;

    /// Check if the value has changed.
    ///
    /// "Changed" technically deals in navigation. In the case of a step, resume-and-break,
    /// patch, etc. This will detect the changes as expected. When manually navigating, this
    /// compares the two most recent times visited. Only the value itself is compared, without
    /// consideration for any intermediate values encountered during evaluation.
    ///
    /// Port of `WatchRow.isChanged()`.
    fn is_changed(&self) -> bool;

    /// Get the user-defined comment for this row.
    ///
    /// Port of `WatchRow.getComment()`.
    fn get_comment(&self) -> String;

    /// Set the user-defined comment for this row.
    ///
    /// Port of `WatchRow.setComment(String)`.
    fn set_comment(&mut self, comment: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use std::any::Any;

    #[derive(Default)]
    struct MockSettings;

    impl Settings for MockSettings {}

    /// Mirrors the relevant fields/behavior of `DefaultWatchRow`, enough to exercise the trait's
    /// default-vs-error-message and changed-value logic against Java behavior.
    #[derive(Default)]
    struct MockWatchRow {
        expression: String,
        comment: String,
        settings: MockSettings,
        value: Option<Vec<u8>>,
        prev_value: Option<Vec<u8>>,
        error: Option<String>,
        known: bool,
    }

    impl WatchRow for MockWatchRow {
        fn get_expression(&self) -> String {
            self.expression.clone()
        }
        fn set_expression(&mut self, expression: &str) {
            self.expression = expression.to_string();
        }
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn set_data_type(&mut self, _data_type: Option<Box<dyn DataType>>) {}
        fn get_settings(&mut self) -> &mut dyn Settings {
            &mut self.settings
        }
        fn settings_changed(&mut self) {}
        fn get_address(&self) -> Option<Address> {
            None
        }
        fn get_range(&self) -> Option<AddressRange> {
            None
        }
        fn get_reads(&self) -> Option<Box<dyn AddressSetView>> {
            None
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_value(&self) -> Option<Vec<u8>> {
            self.value.clone()
        }
        fn get_raw_value_string(&self) -> Option<String> {
            None
        }
        fn get_value_length(&self) -> i32 {
            self.value.as_ref().map(|v| v.len() as i32).unwrap_or(0)
        }
        fn set_raw_value_string(&mut self, _value: &str) {}
        fn is_raw_value_editable(&self) -> bool {
            false
        }
        fn get_value_object(&self) -> Option<Box<dyn Any>> {
            None
        }
        fn get_value_string(&self) -> Option<String> {
            None
        }
        fn set_value_string(&mut self, _value: &str) {}
        fn is_value_editable(&self) -> bool {
            false
        }
        fn get_error(&self) -> Option<&(dyn std::error::Error + Send + Sync)> {
            None
        }
        fn get_error_message(&self) -> String {
            match &self.error {
                None => String::new(),
                Some(message) if !message.trim().is_empty() => message.clone(),
                Some(_) => "Exception".to_string(),
            }
        }
        fn is_known(&self) -> bool {
            self.known
        }
        fn is_changed(&self) -> bool {
            match &self.prev_value {
                None => false,
                Some(prev) => self.value.as_ref() != Some(prev),
            }
        }
        fn get_comment(&self) -> String {
            self.comment.clone()
        }
        fn set_comment(&mut self, comment: &str) {
            self.comment = comment.to_string();
        }
    }

    #[test]
    fn get_error_message_falls_back_to_empty_string_when_no_error() {
        let row = MockWatchRow::default();
        assert_eq!(row.get_error_message(), "");
    }

    #[test]
    fn get_error_message_falls_back_to_exception_name_when_message_is_blank() {
        let mut row = MockWatchRow::default();
        row.error = Some("   ".to_string());
        assert_eq!(row.get_error_message(), "Exception");
    }

    #[test]
    fn get_error_message_uses_message_when_present() {
        let mut row = MockWatchRow::default();
        row.error = Some("bad expression".to_string());
        assert_eq!(row.get_error_message(), "bad expression");
    }

    #[test]
    fn is_changed_false_without_previous_value() {
        let mut row = MockWatchRow::default();
        row.value = Some(vec![1, 2, 3]);
        assert!(!row.is_changed());
    }

    #[test]
    fn is_changed_compares_only_current_and_previous_value() {
        let mut row = MockWatchRow::default();
        row.prev_value = Some(vec![1, 2, 3]);
        row.value = Some(vec![1, 2, 4]);
        assert!(row.is_changed());

        row.value = Some(vec![1, 2, 3]);
        assert!(!row.is_changed());
    }

    #[test]
    fn expression_and_comment_round_trip() {
        let mut row = MockWatchRow::default();
        row.set_expression("*(int *)0x1000");
        row.set_comment("counter");
        assert_eq!(row.get_expression(), "*(int *)0x1000");
        assert_eq!(row.get_comment(), "counter");
    }

    #[test]
    fn usable_as_trait_object() {
        let mut row: Box<dyn WatchRow> = Box::new(MockWatchRow::default());
        row.set_expression("RAX");
        assert_eq!(row.get_expression(), "RAX");
        assert_eq!(row.get_value_length(), 0);
        assert!(!row.is_known());
        let _settings: &mut dyn Settings = row.get_settings();
    }
}
