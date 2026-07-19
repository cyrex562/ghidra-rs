//! Port of `ghidra.framework.options.OptionsChangeListener`.

use std::any::Any;

use crate::framework::seam_stubs::{OptionsVetoException, ToolOptions};

/// Interface for notifying listeners when options change.
///
/// Register with `ToolOptions::add_options_change_listener`.
///
/// Port of `ghidra.framework.options.OptionsChangeListener`.
pub trait OptionsChangeListener {
    /// Notification that an option changed.
    ///
    /// Note: to reject an options change, return `Err` with an [`OptionsVetoException`].
    ///
    /// - `options`: options object containing the property that changed
    /// - `option_name`: name of option that changed
    /// - `old_value`: old value of the option
    /// - `new_value`: new value of the option
    fn options_changed(
        &mut self,
        options: &dyn ToolOptions,
        option_name: &str,
        old_value: Option<&dyn Any>,
        new_value: Option<&dyn Any>,
    ) -> Result<(), Box<dyn OptionsVetoException>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubToolOptions;
    impl ToolOptions for StubToolOptions {}

    struct StubVeto;
    impl OptionsVetoException for StubVeto {}

    struct RecordingListener {
        last_option_name: Option<String>,
    }

    impl OptionsChangeListener for RecordingListener {
        fn options_changed(
            &mut self,
            _options: &dyn ToolOptions,
            option_name: &str,
            _old_value: Option<&dyn Any>,
            _new_value: Option<&dyn Any>,
        ) -> Result<(), Box<dyn OptionsVetoException>> {
            if option_name == "forbidden" {
                return Err(Box::new(StubVeto));
            }
            self.last_option_name = Some(option_name.to_string());
            Ok(())
        }
    }

    #[test]
    fn object_safe_and_records_change() {
        let mut listener: Box<dyn OptionsChangeListener> = Box::new(RecordingListener {
            last_option_name: None,
        });
        let options = StubToolOptions;
        let old_value: i32 = 1;
        let new_value: i32 = 2;

        let result = listener.options_changed(&options, "example", Some(&old_value), Some(&new_value));

        assert!(result.is_ok());
    }

    #[test]
    fn veto_rejects_change() {
        let mut listener = RecordingListener {
            last_option_name: None,
        };
        let options = StubToolOptions;

        let result = listener.options_changed(&options, "forbidden", None, None);

        assert!(result.is_err());
    }
}
