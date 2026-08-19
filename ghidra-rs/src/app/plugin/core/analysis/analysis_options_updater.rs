use std::any::Any;
use std::collections::HashMap;

use crate::framework::options::Options;

/// An object that allows analyzers to rename options. This is required to move old options
/// stored in the program to the new equivalent option. This class is not required for options
/// that have simply been removed.
///
/// Notes:
/// - Replacement options must be registered with one of the `register_replacement` methods of
///   this struct.
/// - This is intended for use with the UI; access to analysis options from the API will not use
///   this replacer. This means that any client, such as a script, retrieving the old option value
///   will not work for new programs that no longer have that old option registered. Further, for
///   programs that have the old options saved, but no longer registered, changing the old option
///   value will have no effect.
/// - Old option values will only be used if they are non-default and the new option value is
///   default.
/// - Clients can change the type of the option if they wish using
///   [`AnalysisOptionsUpdater::register_replacement_with_replacer`].
///
/// Maps to `ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater`.
#[derive(Default)]
pub struct AnalysisOptionsUpdater {
    options_by_new_name: HashMap<String, ReplaceableOption>,
}

impl AnalysisOptionsUpdater {
    /// Creates an updater with no registered replacements.
    pub fn new() -> Self {
        Self {
            options_by_new_name: HashMap::new(),
        }
    }

    /// Register the given old option name to be replaced with the new option name. The
    /// replacement strategy used in this case will be to return the old value for the new
    /// option.
    pub fn register_replacement(&mut self, new_option_name: &str, old_option_name: &str) {
        self.register_replacement_with_replacer(new_option_name, old_option_name, Box::new(old_value_replacer));
    }

    /// Register the given old option name to be replaced with the new option name. The given
    /// replacer function will be called with the old option value to get the new option value.
    pub fn register_replacement_with_replacer(
        &mut self,
        new_option_name: &str,
        old_option_name: &str,
        replacer: Replacer,
    ) {
        self.options_by_new_name.insert(
            new_option_name.to_string(),
            ReplaceableOption::new(new_option_name, old_option_name, replacer),
        );
    }

    /// Returns the registered replaceable options.
    pub(crate) fn get_replaceable_options(&self) -> Vec<&ReplaceableOption> {
        self.options_by_new_name.values().collect()
    }
}

/// The identity replacer used by [`AnalysisOptionsUpdater::register_replacement`]; it returns the
/// old value unchanged as the new value.
///
/// Stands in for the Java class's `OLD_VALUE_REPLACER` static field.
fn old_value_replacer(old_value: Box<dyn Any>) -> Box<dyn Any> {
    old_value
}

/// A function that maps an old option's value to the new option's value.
///
/// Stands in for Java's `Function<Object, Object>`.
pub type Replacer = Box<dyn Fn(Box<dyn Any>) -> Box<dyn Any>>;

/// A simple object that contains the new and old option name along with the replacer function
/// that will handle the option replacement.
///
/// Maps to `ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater.ReplaceableOption`.
pub struct ReplaceableOption {
    new_name: String,
    old_name: String,
    replacer: Replacer,
}

impl ReplaceableOption {
    fn new(new_name: &str, old_name: &str, replacer: Replacer) -> Self {
        Self {
            new_name: new_name.to_string(),
            old_name: old_name.to_string(),
            replacer,
        }
    }

    /// Moves the old option's value to the new option, provided the old option has a non-default
    /// value and the new option still has its default value.
    ///
    /// Note: this method expects to be called within a transaction.
    pub(crate) fn replace(&self, options: &mut dyn Options) {
        if !options.contains(&self.old_name) {
            return;
        }

        if options.is_default_value(&self.old_name) {
            return;
        }

        if !options.is_default_value(&self.new_name) {
            return; // don't overwrite user's updated value
        }

        let old_value = options.get_object(&self.old_name, Box::new(()));
        let new_value = (self.replacer)(old_value);
        options.put_object(&self.new_name, new_value);
    }

    pub(crate) fn get_new_name(&self) -> &str {
        &self.new_name
    }

    pub(crate) fn get_old_name(&self) -> &str {
        &self.old_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap as StdHashMap;

    /// A minimal, mutable mock backed by a string-keyed map, enough to exercise
    /// `ReplaceableOption::replace` end to end.
    struct RecordingOptions {
        values: RefCell<StdHashMap<String, i32>>,
        defaults: RefCell<StdHashMap<String, i32>>,
    }

    impl RecordingOptions {
        fn new() -> Self {
            Self {
                values: RefCell::new(StdHashMap::new()),
                defaults: RefCell::new(StdHashMap::new()),
            }
        }

        fn with_default(mut self, name: &str, value: i32) -> Self {
            self.defaults.get_mut().insert(name.to_string(), value);
            self
        }

        fn set_non_default(&self, name: &str, value: i32) {
            self.values.borrow_mut().insert(name.to_string(), value);
        }
    }

    impl Options for RecordingOptions {
        fn contains(&self, option_name: &str) -> bool {
            self.values.borrow().contains_key(option_name)
                || self.defaults.borrow().contains_key(option_name)
        }

        fn is_default_value(&self, option_name: &str) -> bool {
            !self.values.borrow().contains_key(option_name)
        }

        fn get_object(&self, option_name: &str, default_value: Box<dyn Any>) -> Box<dyn Any> {
            if let Some(value) = self.values.borrow().get(option_name) {
                return Box::new(*value);
            }
            if let Some(value) = self.defaults.borrow().get(option_name) {
                return Box::new(*value);
            }
            default_value
        }

        fn put_object(&mut self, option_name: &str, obj: Box<dyn Any>) {
            let value = *obj.downcast::<i32>().expect("expected i32 value");
            self.values.borrow_mut().insert(option_name.to_string(), value);
        }
    }

    #[test]
    fn register_replacement_uses_identity_replacer() {
        let mut updater = AnalysisOptionsUpdater::new();
        updater.register_replacement("newName", "oldName");

        let options = updater.get_replaceable_options();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].get_new_name(), "newName");
        assert_eq!(options[0].get_old_name(), "oldName");
    }

    #[test]
    fn moves_non_default_old_value_to_default_new_option() {
        let mut updater = AnalysisOptionsUpdater::new();
        updater.register_replacement("newName", "oldName");

        let mut options = RecordingOptions::new().with_default("newName", 0);
        options.set_non_default("oldName", 42);

        for option in updater.get_replaceable_options() {
            option.replace(&mut options);
        }

        assert_eq!(options.values.borrow().get("newName"), Some(&42));
    }

    #[test]
    fn does_not_replace_when_old_value_is_default() {
        let mut updater = AnalysisOptionsUpdater::new();
        updater.register_replacement("newName", "oldName");

        let mut options = RecordingOptions::new()
            .with_default("oldName", 1)
            .with_default("newName", 0);

        for option in updater.get_replaceable_options() {
            option.replace(&mut options);
        }

        assert!(options.values.borrow().get("newName").is_none());
    }

    #[test]
    fn does_not_replace_when_old_option_is_absent() {
        let mut updater = AnalysisOptionsUpdater::new();
        updater.register_replacement("newName", "oldName");

        let mut options = RecordingOptions::new().with_default("newName", 0);

        for option in updater.get_replaceable_options() {
            option.replace(&mut options);
        }

        assert!(options.values.borrow().get("newName").is_none());
    }

    #[test]
    fn does_not_overwrite_new_option_with_non_default_value() {
        let mut updater = AnalysisOptionsUpdater::new();
        updater.register_replacement("newName", "oldName");

        let mut options = RecordingOptions::new();
        options.set_non_default("oldName", 42);
        options.set_non_default("newName", 99);

        for option in updater.get_replaceable_options() {
            option.replace(&mut options);
        }

        assert_eq!(options.values.borrow().get("newName"), Some(&99));
    }

    #[test]
    fn custom_replacer_transforms_old_value() {
        let mut updater = AnalysisOptionsUpdater::new();
        updater.register_replacement_with_replacer(
            "newName",
            "oldName",
            Box::new(|old_value| {
                let old_value = *old_value.downcast::<i32>().unwrap();
                Box::new(old_value * 2)
            }),
        );

        let mut options = RecordingOptions::new().with_default("newName", 0);
        options.set_non_default("oldName", 21);

        for option in updater.get_replaceable_options() {
            option.replace(&mut options);
        }

        assert_eq!(options.values.borrow().get("newName"), Some(&42));
    }

    #[test]
    fn later_registration_for_same_new_name_replaces_earlier_one() {
        let mut updater = AnalysisOptionsUpdater::new();
        updater.register_replacement("newName", "firstOldName");
        updater.register_replacement("newName", "secondOldName");

        let options = updater.get_replaceable_options();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].get_old_name(), "secondOldName");
    }
}
