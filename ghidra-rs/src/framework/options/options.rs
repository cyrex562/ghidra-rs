use std::any::Any;

use crate::framework::seam_stubs::{
    ActionTrigger, Color, CustomOption, Font, HelpLocation, KeyStroke, OptionType, OptionsEditor,
    PropertyEditor,
};
use crate::util::function::Supplier;

/// Character used to build hierarchical option paths (e.g. `"a.b.c"`).
///
/// Stands in for `Options.DELIMITER`.
pub const DELIMITER: char = '.';
/// Stands in for `Options.DELIMITER_STRING`.
pub const DELIMITER_STRING: &str = ".";
/// Stands in for `Options.ILLEGAL_DELIMITER`.
pub const ILLEGAL_DELIMITER: &str = "..";

/// A hierarchical container of named, typed configuration values.
///
/// Options are stored under dot-delimited paths (see [`DELIMITER`]); each leaf option has a
/// registered type, an optional help location, and a value that may differ from its default.
///
/// Port of `ghidra.framework.options.Options`.
///
/// This trait was promoted from a minimal placeholder (see `framework::seam_stubs`) that had no
/// methods. Every method (including ones abstract in the Java interface) is given a default so
/// that existing mock/test implementations which relied on the placeholder's blanket defaults
/// (e.g. `DomainObject`'s `EmptyOptions` fallback) are unaffected by this promotion. Concrete
/// implementations (`OptionsDB`, etc.) will override these with real behavior once they are
/// ported.
///
/// The two `@Deprecated(forRemoval = true)` convenience overloads
/// (`registerOption(..., PropertyEditor)` and `registerOptionsEditor(OptionsEditor)`) are omitted:
/// they only wrap the `Supplier`-based methods below and carry no behavior of their own; callers
/// can build an equivalent `Supplier` inline.
///
/// `getKeyStroke`/`setKeyStroke` are also individually deprecated upstream in favor of
/// `getActionTrigger`/`setActionTrigger`, but are retained here since they are not yet slated for
/// removal.
pub trait Options {
    /// Get the name of this options object.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Returns a unique id for the option in this options with the given name. This will be the
    /// full path name to the root options object.
    fn get_id(&self, option_name: &str) -> String {
        option_name.to_string()
    }

    /// Returns the [`OptionType`] of the given option.
    fn get_type(&self, option_name: &str) -> Box<dyn OptionType> {
        let _ = option_name;
        Box::new(UnknownOptionType)
    }

    /// Get the property editor for the option with the given name. Note: in the original Java API
    /// this must be called from the Swing thread.
    fn get_property_editor(&self, option_name: &str) -> Option<Box<dyn PropertyEditor>> {
        let _ = option_name;
        None
    }

    /// Get the property editor that was registered for the specific option with the given name.
    /// Unlike [`Self::get_property_editor`], this does not have to be called from the Swing
    /// thread.
    fn get_registered_property_editor(&self, option_name: &str) -> Option<Box<dyn PropertyEditor>> {
        let _ = option_name;
        None
    }

    /// Returns the [`Options`] objects that are nested one level down from this options object.
    fn get_child_options(&self) -> Vec<Box<dyn Options>> {
        Vec::new()
    }

    /// Returns the option names that immediately fall under this options. For example, if this
    /// options object had the options named ("a", "b", "c.d"), only "a" and "b" would be
    /// returned. The "c.d" leaf option name could be returned by
    /// `get_options("c").get_leaf_option_names()`.
    fn get_leaf_option_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Set the location for where help can be found for this entire options object.
    fn set_options_help_location(&mut self, help_location: Option<Box<dyn HelpLocation>>) {
        let _ = help_location;
    }

    /// Returns the [`HelpLocation`] for this entire options object.
    fn get_options_help_location(&self) -> Option<Box<dyn HelpLocation>> {
        None
    }

    /// Get the location for where help can be found for the option with the given name, or
    /// `None` if the help location was not set on the option.
    fn get_help_location(&self, option_name: &str) -> Option<Box<dyn HelpLocation>> {
        let _ = option_name;
        None
    }

    /// Registers an option with a description, help location, and a non-null default value,
    /// without specifying the option type (the type is inferred from the default value).
    fn register_option(
        &mut self,
        option_name: &str,
        default_value: Box<dyn Any>,
        help: Option<Box<dyn HelpLocation>>,
        description: &str,
    ) {
        let _ = (option_name, default_value, help, description);
    }

    /// Registers an option with a description, help location, an explicit [`OptionType`], and an
    /// optional default value.
    fn register_option_with_type(
        &mut self,
        option_name: &str,
        option_type: Box<dyn OptionType>,
        default_value: Option<Box<dyn Any>>,
        help: Option<Box<dyn HelpLocation>>,
        description: &str,
    ) {
        let _ = (option_name, option_type, default_value, help, description);
    }

    /// Registers an option with a description, help location, an explicit [`OptionType`], an
    /// optional default value, and an optional supplier of a custom property editor. The supplier
    /// is used (instead of a plain editor) so editor construction can be deferred until needed,
    /// avoiding GUI component creation in headless mode.
    fn register_option_with_editor(
        &mut self,
        option_name: &str,
        option_type: Box<dyn OptionType>,
        default_value: Option<Box<dyn Any>>,
        help: Option<Box<dyn HelpLocation>>,
        description: &str,
        editor: Option<Supplier<Box<dyn PropertyEditor>>>,
    ) {
        let _ = (
            option_name,
            option_type,
            default_value,
            help,
            description,
            editor,
        );
    }

    /// Register/binds the option to a theme color id. Changing the option's color via the options
    /// GUI will directly change the theme color of the given color id.
    fn register_theme_color_binding(
        &mut self,
        option_name: &str,
        color_id: &str,
        help: Option<Box<dyn HelpLocation>>,
        description: &str,
    ) {
        let _ = (option_name, color_id, help, description);
    }

    /// Register/binds the option to a theme font id. Changing the option's font via the options
    /// GUI will directly change the theme font of the given font id.
    fn register_theme_font_binding(
        &mut self,
        option_name: &str,
        font_id: &str,
        help: Option<Box<dyn HelpLocation>>,
        description: &str,
    ) {
        let _ = (option_name, font_id, help, description);
    }

    /// Register the options editor that will handle the editing for all the options or a
    /// sub-group of options.
    fn register_options_editor(&mut self, editor: Supplier<Box<dyn OptionsEditor>>) {
        let _ = editor;
    }

    /// Get the editor that will handle editing all the values in this options or sub group of
    /// options, or `None` if no options editor was registered.
    fn get_options_editor(&self) -> Option<Box<dyn OptionsEditor>> {
        None
    }

    /// Put the object value. If the option exists, the type must match the type of the existing
    /// object.
    fn put_object(&mut self, option_name: &str, obj: Box<dyn Any>) {
        let _ = (option_name, obj);
    }

    /// Get the object value, returning `default_value` if no option was found with the given
    /// name (the default is not stored in the option maps).
    fn get_object(&self, option_name: &str, default_value: Box<dyn Any>) -> Box<dyn Any> {
        let _ = option_name;
        default_value
    }

    /// Get the boolean value for the given option name.
    fn get_boolean(&self, option_name: &str, default_value: bool) -> bool {
        let _ = option_name;
        default_value
    }

    /// Get the byte array for the given option name.
    fn get_byte_array(&self, option_name: &str, default_value: &[u8]) -> Vec<u8> {
        let _ = option_name;
        default_value.to_vec()
    }

    /// Get the int value for the given option name.
    fn get_int(&self, option_name: &str, default_value: i32) -> i32 {
        let _ = option_name;
        default_value
    }

    /// Get the double value for the given option name.
    fn get_double(&self, option_name: &str, default_value: f64) -> f64 {
        let _ = option_name;
        default_value
    }

    /// Get the float value for the given option name.
    fn get_float(&self, option_name: &str, default_value: f32) -> f32 {
        let _ = option_name;
        default_value
    }

    /// Get the long value for the given option name.
    fn get_long(&self, option_name: &str, default_value: i64) -> i64 {
        let _ = option_name;
        default_value
    }

    /// Get the custom option value for the given option name.
    fn get_custom_option(
        &self,
        option_name: &str,
        default_value: Box<dyn CustomOption>,
    ) -> Box<dyn CustomOption> {
        let _ = option_name;
        default_value
    }

    /// Get the [`Color`] for the given option name.
    fn get_color(&self, option_name: &str, default_value: Box<dyn Color>) -> Box<dyn Color> {
        let _ = option_name;
        default_value
    }

    /// Get the file path for the given option name.
    ///
    /// Stands in for `Options.getFile`, using `PathBuf` in place of `java.io.File`.
    fn get_file(
        &self,
        option_name: &str,
        default_value: std::path::PathBuf,
    ) -> std::path::PathBuf {
        let _ = option_name;
        default_value
    }

    /// Get the date (milliseconds since the Unix epoch) for the given option name.
    ///
    /// Stands in for `Options.getDate`, using epoch millis in place of `java.util.Date` (see
    /// `crate::util::date_utils`, which uses the same representation).
    fn get_date(&self, option_name: &str, default_value: i64) -> i64 {
        let _ = option_name;
        default_value
    }

    /// Get the [`Font`] for the given option name.
    fn get_font(&self, option_name: &str, default_value: Box<dyn Font>) -> Box<dyn Font> {
        let _ = option_name;
        default_value
    }

    /// Get the [`KeyStroke`] for the given action name.
    ///
    /// Deprecated upstream in favor of [`Self::get_action_trigger`].
    fn get_key_stroke(
        &self,
        option_name: &str,
        default_value: Box<dyn KeyStroke>,
    ) -> Box<dyn KeyStroke> {
        let _ = option_name;
        default_value
    }

    /// Get the [`ActionTrigger`] for the given full action name.
    fn get_action_trigger(
        &self,
        option_name: &str,
        default_value: Box<dyn ActionTrigger>,
    ) -> Box<dyn ActionTrigger> {
        let _ = option_name;
        default_value
    }

    /// Get the string value for the given option name.
    fn get_string(&self, option_name: &str, default_value: &str) -> String {
        let _ = option_name;
        default_value.to_string()
    }

    /// Get the enum value for the given option name.
    ///
    /// Generic over `T` (mirroring Java's `<T extends Enum<T>>`), so this method requires
    /// `Self: Sized` and is not available through `dyn Options` -- the same trade-off already
    /// used elsewhere in this crate (e.g. `DomainObject::with_transaction_result`,
    /// `InjectPayload::restore_xml`) to keep the rest of the trait object-safe.
    fn get_enum<T>(&self, option_name: &str, default_value: T) -> T
    where
        Self: Sized,
        T: Copy + PartialEq + ToString,
    {
        let _ = option_name;
        default_value
    }

    /// Sets the long value for the option.
    fn set_long(&mut self, option_name: &str, value: i64) {
        let _ = (option_name, value);
    }

    /// Sets the boolean value for the option.
    fn set_boolean(&mut self, option_name: &str, value: bool) {
        let _ = (option_name, value);
    }

    /// Sets the int value for the option.
    fn set_int(&mut self, option_name: &str, value: i32) {
        let _ = (option_name, value);
    }

    /// Sets the double value for the option.
    fn set_double(&mut self, option_name: &str, value: f64) {
        let _ = (option_name, value);
    }

    /// Sets the float value for the option.
    fn set_float(&mut self, option_name: &str, value: f32) {
        let _ = (option_name, value);
    }

    /// Sets the custom option value for the option.
    fn set_custom_option(&mut self, option_name: &str, value: Box<dyn CustomOption>) {
        let _ = (option_name, value);
    }

    /// Sets the byte array value for the given option name.
    fn set_byte_array(&mut self, option_name: &str, value: &[u8]) {
        let _ = (option_name, value);
    }

    /// Sets the file path value for the option.
    fn set_file(&mut self, option_name: &str, value: std::path::PathBuf) {
        let _ = (option_name, value);
    }

    /// Sets the date (milliseconds since the Unix epoch) value for the option.
    fn set_date(&mut self, option_name: &str, value: i64) {
        let _ = (option_name, value);
    }

    /// Sets the [`Color`] value for the option.
    fn set_color(&mut self, option_name: &str, value: Box<dyn Color>) {
        let _ = (option_name, value);
    }

    /// Sets the [`Font`] value for the option.
    fn set_font(&mut self, option_name: &str, value: Box<dyn Font>) {
        let _ = (option_name, value);
    }

    /// Sets the [`KeyStroke`] value for the option.
    ///
    /// Deprecated upstream in favor of [`Self::set_action_trigger`].
    fn set_key_stroke(&mut self, option_name: &str, value: Box<dyn KeyStroke>) {
        let _ = (option_name, value);
    }

    /// Sets the [`ActionTrigger`] value for the option.
    fn set_action_trigger(&mut self, option_name: &str, value: Box<dyn ActionTrigger>) {
        let _ = (option_name, value);
    }

    /// Set the string value for the option.
    fn set_string(&mut self, option_name: &str, value: &str) {
        let _ = (option_name, value);
    }

    /// Set the enum value for the option. See [`Self::get_enum`] for why this requires
    /// `Self: Sized`.
    fn set_enum<T>(&mut self, option_name: &str, value: T)
    where
        Self: Sized,
        T: Copy + PartialEq + ToString,
    {
        let _ = (option_name, value);
    }

    /// Remove the option with the given name.
    fn remove_option(&mut self, option_name: &str) {
        let _ = option_name;
    }

    /// Get the names (paths) of all options contained in this options object or below. For
    /// example, if the options has ("aaa", "bbb", "ccc.ddd"), all three will be returned; compare
    /// with [`Self::get_leaf_option_names`], which would only return "aaa" and "bbb".
    fn get_option_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Return true if an option exists with the given name.
    fn contains(&self, option_name: &str) -> bool {
        let _ = option_name;
        false
    }

    /// Get the description for the given option name, or `None` if the description or option
    /// name does not exist.
    fn get_description(&self, option_name: &str) -> Option<String> {
        let _ = option_name;
        None
    }

    /// Returns true if the specified option has been registered. Only registered names are
    /// saved.
    fn is_registered(&self, option_name: &str) -> bool {
        let _ = option_name;
        false
    }

    /// Returns true if the option with the given name's current value is the default value.
    fn is_default_value(&self, option_name: &str) -> bool {
        let _ = option_name;
        true
    }

    /// Restores **all** options contained herein to their default values.
    fn restore_default_values(&mut self) {}

    /// Restores the option denoted by the given name to its default value.
    fn restore_default_value(&mut self, option_name: &str) {
        let _ = option_name;
    }

    /// Returns an [`Options`] object that is a sub-options of this options.
    ///
    /// Note: the option path can have [`DELIMITER`] characters, which are used to create a
    /// hierarchy with each element in the path resulting in a sub-option of the previous path
    /// element.
    fn get_options(&self, path: &str) -> Box<dyn Options> {
        let _ = path;
        Box::new(EmptySubOptions)
    }

    /// Create an alias in this options for an existing option in some other options object.
    fn create_alias(&mut self, alias_name: &str, options: &dyn Options, options_name: &str) {
        let _ = (alias_name, options, options_name);
    }

    /// Returns true if `alias_name` is an alias in this options object.
    fn is_alias(&self, alias_name: &str) -> bool {
        let _ = alias_name;
        false
    }

    /// Returns the default value for the given option.
    fn get_default_value(&self, option_name: &str) -> Option<Box<dyn Any>> {
        let _ = option_name;
        None
    }

    /// Returns the value as a string for the given option.
    fn get_value_as_string(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }

    /// Returns the default value as a string for the given option.
    fn get_default_value_as_string(&self, option_name: &str) -> Option<String> {
        let _ = option_name;
        None
    }
}

/// Trivial fallback [`OptionType`] used by [`Options::get_type`]'s default implementation.
struct UnknownOptionType;
impl OptionType for UnknownOptionType {}

/// Trivial fallback [`Options`] (with no properties of its own) used by [`Options::get_options`]'s
/// default implementation.
struct EmptySubOptions;
impl Options for EmptySubOptions {}

/// Returns true if the two options objects have the same set of options and the same values.
///
/// Port of the static `Options.hasSameOptionsAndValues` method. The Java implementation compares
/// raw `Object` values via `Objects.equals`; since `Box<dyn Any>` has no general structural
/// equality in Rust, this instead compares each option's canonical string form via
/// [`Options::get_value_as_string`], which is equivalent for this purpose.
pub fn has_same_options_and_values(options1: &dyn Options, options2: &dyn Options) -> bool {
    let mut names1 = options1.get_option_names();
    let mut names2 = options2.get_option_names();
    names1.sort();
    names2.sort();

    if names1 != names2 {
        return false;
    }

    names1
        .iter()
        .all(|name| options1.get_value_as_string(name) == options2.get_value_as_string(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct MockOptions;
    impl Options for MockOptions {}

    /// A minimal, mutable mock backed by a string-value map, enough to exercise `&mut dyn
    /// Options` and prove the overridden methods round-trip.
    struct RecordingOptions {
        name: String,
        booleans: RefCell<HashMap<String, bool>>,
    }

    impl Options for RecordingOptions {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_boolean(&self, option_name: &str, default_value: bool) -> bool {
            *self
                .booleans
                .borrow()
                .get(option_name)
                .unwrap_or(&default_value)
        }

        fn set_boolean(&mut self, option_name: &str, value: bool) {
            self.booleans
                .borrow_mut()
                .insert(option_name.to_string(), value);
        }

        fn contains(&self, option_name: &str) -> bool {
            self.booleans.borrow().contains_key(option_name)
        }
    }

    #[test]
    fn empty_impl_uses_defaults() {
        let options = MockOptions;
        let dyn_options: &dyn Options = &options;

        assert_eq!(dyn_options.get_name(), "");
        assert!(dyn_options.get_boolean("x", true));
        assert!(!dyn_options.contains("x"));
        assert!(dyn_options.get_child_options().is_empty());
        assert_eq!(dyn_options.get_string("s", "default"), "default");
    }

    #[test]
    fn usable_as_trait_object() {
        let mut options = RecordingOptions {
            name: "Test Options".to_string(),
            booleans: RefCell::new(HashMap::new()),
        };

        let dyn_options: &mut dyn Options = &mut options;
        assert!(!dyn_options.contains("enabled"));
        dyn_options.set_boolean("enabled", true);

        assert!(dyn_options.contains("enabled"));
        assert!(dyn_options.get_boolean("enabled", false));
        assert_eq!(dyn_options.get_name(), "Test Options");
    }

    #[test]
    fn has_same_options_and_values_compares_names_and_string_values() {
        let a = MockOptions;
        let b = MockOptions;
        assert!(has_same_options_and_values(&a, &b));
    }

    #[test]
    fn delimiter_constants_match_java() {
        assert_eq!(DELIMITER, '.');
        assert_eq!(DELIMITER_STRING, ".");
        assert_eq!(ILLEGAL_DELIMITER, "..");
    }
}
