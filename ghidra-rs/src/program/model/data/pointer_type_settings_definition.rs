//! Port of `ghidra.program.model.data.PointerTypeSettingsDefinition`.
//!
//! This is a real, full port of the Java class -- not a leaf `DataType`, but a concrete singleton
//! `EnumSettingsDefinition`/`TypeDefSettingsDefinition`, mirroring the shape of already-ported
//! siblings like
//! [`OffsetShiftSettingsDefinition`](crate::program::model::data::offset_shift_settings_definition::OffsetShiftSettingsDefinition).
//! It is built directly on the already-ported [`PointerType`] trait (and its `DEFAULT`/
//! `IMAGE_BASE_RELATIVE`/`RELATIVE`/`FILE_OFFSET` unit-struct constants plus [`pointer_type::value_of`]),
//! since that is the actual (if not yet wired-up) real port of `ghidra.program.model.data.PointerType`.
//!
//! A separate, narrower placeholder already exists at
//! [`seam_stubs::PointerTypeSettingsDefinition`](crate::program::seam_stubs::PointerTypeSettingsDefinition)
//! (paired with [`seam_stubs::PointerType`](crate::program::seam_stubs::PointerType), a plain
//! `enum` rather than a trait), and the already-DONE
//! [`PointerDataType`](crate::program::model::data::pointer_data_type::PointerDataType) is built
//! against *that* pair, matching on the enum directly rather than a `PointerType::value()` trait
//! object. Reconciling the two (switching `PointerDataType` over to this real port) would require
//! rewriting `PointerDataType`'s own settings/address-decoding logic, which is out of scope for
//! this port and risks an already-verified 1000+ line file; that reconciliation is left to
//! whenever `PointerDataType` is next substantially touched. This file and the `seam_stubs` pair
//! coexist under the same class name at different Rust paths in the meantime.
//!
//! `getType(Settings)` accepts a possibly-`null` `settings` in Java (`if (settings == null) return
//! PointerType.DEFAULT;`); ported as [`PointerTypeSettingsDefinition::get_type`] taking
//! `Option<&dyn Settings>` to preserve that. `EnumSettingsDefinition::get_choice`, by contrast,
//! keeps this crate's already-established non-optional `&dyn Settings` signature (every other
//! `EnumSettingsDefinition` implementor in this crate takes it unwrapped) and simply forwards to
//! `get_type(Some(settings))`.
//!
//! `SettingsDefinition::has_same_value` is not overridden in the Java source -- it inherits a real
//! default from the `EnumSettingsDefinition` interface (`getChoice(s1) == getChoice(s2)`) via
//! Java's single interface hierarchy. This crate's [`SettingsDefinition`] and
//! [`EnumSettingsDefinition`] are two independent Rust traits with their own separate (and
//! different) default bodies for the same-named method, so -- mirroring
//! [`OffsetShiftSettingsDefinition`]'s own `impl SettingsDefinition` block -- this port explicitly
//! forwards `SettingsDefinition::has_same_value` to `EnumSettingsDefinition::has_same_value` to
//! reproduce that inherited behavior.

use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::pointer_type::{self, DefaultPointerType, PointerType};
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;

const POINTER_TYPE_SETTINGS_NAME: &str = "ptr_type";
const DESCRIPTION: &str = "Specifies the pointer type which affects interpretation of offset";
const DISPLAY_NAME: &str = "Pointer Type";

/// Port of the private `PointerTypeSettingsDefinition.choices` array (indexed by
/// [`PointerType::value`]).
const CHOICES: [&str; 4] = ["default", "image-base-relative", "relative", "file-offset"];

/// The settings definition for the numeric display format.
///
/// Port of `ghidra.program.model.data.PointerTypeSettingsDefinition`. See the module-level
/// documentation for how this relates to the pre-existing `seam_stubs` placeholder of the same
/// Java class name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerTypeSettingsDefinition;

impl PointerTypeSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const DEF: PointerTypeSettingsDefinition = PointerTypeSettingsDefinition;

    /// Returns the format based on the specified settings.
    ///
    /// Port of `PointerTypeSettingsDefinition.getType(Settings)`. `settings` being `None` stands
    /// in for a `null` Java argument; [`DefaultPointerType`] is returned in that case, or when no
    /// setting has been made, or when a stored value does not correspond to any known
    /// [`PointerType`] constant (mirroring the Java `catch (NoSuchElementException e)` branch).
    pub fn get_type(&self, settings: Option<&dyn Settings>) -> Box<dyn PointerType> {
        let Some(settings) = settings else {
            return Box::new(DefaultPointerType);
        };
        let Some(value) = settings.get_long(POINTER_TYPE_SETTINGS_NAME) else {
            return Box::new(DefaultPointerType);
        };
        pointer_type::value_of(value as i32).unwrap_or_else(|_| Box::new(DefaultPointerType))
    }

    /// Port of `PointerTypeSettingsDefinition.setType(Settings, PointerType)`.
    pub fn set_type(&self, settings: &mut dyn Settings, pointer_type: &dyn PointerType) {
        if pointer_type.value() == DefaultPointerType.value() {
            settings.clear_setting(POINTER_TYPE_SETTINGS_NAME);
        } else {
            settings.set_long(POINTER_TYPE_SETTINGS_NAME, pointer_type.value() as i64);
        }
    }

    /// Port of the non-interface `PointerTypeSettingsDefinition.getDisplayChoice(Settings)`
    /// overload.
    pub fn get_display_choice_for(&self, settings: &dyn Settings) -> String {
        CHOICES[self.get_choice(settings) as usize].to_string()
    }

    /// Sets the settings object to the enum value indicating the specified choice as a string.
    ///
    /// Port of `PointerTypeSettingsDefinition.setDisplayChoice(Settings, String)`.
    pub fn set_display_choice(&self, settings: &mut dyn Settings, choice: &str) {
        if let Some(index) = CHOICES.iter().position(|c| *c == choice) {
            self.set_choice(settings, index as i32);
        }
    }
}

impl EnumSettingsDefinition for PointerTypeSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        self.get_type(Some(settings)).value()
    }

    fn set_choice(&self, settings: &mut dyn Settings, value: i32) {
        match pointer_type::value_of(value) {
            Ok(pointer_type) => self.set_type(settings, pointer_type.as_ref()),
            Err(_) => settings.clear_setting(POINTER_TYPE_SETTINGS_NAME),
        }
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        CHOICES[value as usize].to_string()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        CHOICES.iter().map(|c| c.to_string()).collect()
    }
}

impl SettingsDefinition for PointerTypeSettingsDefinition {
    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value(POINTER_TYPE_SETTINGS_NAME).is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        Some(CHOICES[self.get_choice(settings) as usize].to_string())
    }

    fn get_name(&self) -> String {
        DISPLAY_NAME.to_string()
    }

    fn get_storage_key(&self) -> String {
        POINTER_TYPE_SETTINGS_NAME.to_string()
    }

    fn get_description(&self) -> String {
        DESCRIPTION.to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(POINTER_TYPE_SETTINGS_NAME);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_long(POINTER_TYPE_SETTINGS_NAME) {
            Some(value) => dest_settings.set_long(POINTER_TYPE_SETTINGS_NAME, value),
            None => dest_settings.clear_setting(POINTER_TYPE_SETTINGS_NAME),
        }
    }

    fn has_same_value(&self, settings1: &dyn Settings, settings2: &dyn Settings) -> bool {
        // See the module docs: PointerTypeSettingsDefinition.java does not override hasSameValue
        // itself, inheriting EnumSettingsDefinition's real default; Rust needs this forwarded
        // explicitly since the two traits' own has_same_value defaults differ.
        EnumSettingsDefinition::has_same_value(self, settings1, settings2)
    }
}

impl TypeDefSettingsDefinition for PointerTypeSettingsDefinition {
    fn get_attribute_specification(&self, settings: &dyn Settings) -> Option<String> {
        let choice = self.get_choice(settings);
        if choice != 0 {
            Some(CHOICES[choice as usize].to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct MockSettings {
        longs: RefCell<HashMap<String, i64>>,
    }

    impl MockSettings {
        fn new() -> Self {
            MockSettings {
                longs: RefCell::new(HashMap::new()),
            }
        }
    }

    impl Settings for MockSettings {
        fn get_long(&self, name: &str) -> Option<i64> {
            self.longs.borrow().get(name).copied()
        }

        fn set_long(&mut self, name: &str, value: i64) {
            self.longs.borrow_mut().insert(name.to_string(), value);
        }

        fn get_value(&self, name: &str) -> Option<Box<dyn std::any::Any>> {
            // A real Settings implementation's generic getValue reflects whatever was stored
            // through any setter (including set_long); this mock mirrors that so has_value's
            // `settings.getValue(name) != null` port is meaningfully testable.
            self.longs.borrow().get(name).map(|v| Box::new(*v) as Box<dyn std::any::Any>)
        }

        fn clear_setting(&mut self, name: &str) {
            self.longs.borrow_mut().remove(name);
        }

        fn is_empty(&self) -> bool {
            self.longs.borrow().is_empty()
        }
    }

    #[test]
    fn get_type_defaults_when_settings_missing_or_null() {
        let def = PointerTypeSettingsDefinition::DEF;
        assert_eq!(def.get_type(None).value(), DefaultPointerType.value());

        let settings = MockSettings::new();
        assert_eq!(def.get_type(Some(&settings)).value(), DefaultPointerType.value());
    }

    #[test]
    fn set_type_then_get_type_round_trips_each_constant() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut settings = MockSettings::new();

        for value in 0..=3 {
            let pointer_type = pointer_type::value_of(value).unwrap();
            def.set_type(&mut settings, pointer_type.as_ref());
            assert_eq!(def.get_type(Some(&settings)).value(), value);
        }
    }

    #[test]
    fn set_type_default_clears_stored_setting() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut settings = MockSettings::new();

        def.set_type(&mut settings, &pointer_type::RelativePointerType);
        assert!(def.has_value(&settings));

        def.set_type(&mut settings, &DefaultPointerType);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn get_type_falls_back_to_default_for_unknown_stored_value() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut settings = MockSettings::new();
        settings.set_long(POINTER_TYPE_SETTINGS_NAME, 99);
        assert_eq!(def.get_type(Some(&settings)).value(), DefaultPointerType.value());
    }

    #[test]
    fn enum_settings_definition_choice_and_display_choices() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut settings = MockSettings::new();

        assert_eq!(def.get_choice(&settings), 0);
        def.set_choice(&mut settings, 2);
        assert_eq!(def.get_choice(&settings), 2);
        assert_eq!(def.get_display_choice(2, &settings), "relative");
        assert_eq!(
            def.get_display_choices(&settings),
            vec!["default", "image-base-relative", "relative", "file-offset"]
        );
    }

    #[test]
    fn display_choice_helpers_round_trip_by_name() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut settings = MockSettings::new();

        def.set_display_choice(&mut settings, "file-offset");
        assert_eq!(def.get_display_choice_for(&settings), "file-offset");
        assert_eq!(def.get_choice(&settings), 3);
    }

    #[test]
    fn set_display_choice_with_unknown_name_is_a_no_op() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut settings = MockSettings::new();
        def.set_display_choice(&mut settings, "relative");
        def.set_display_choice(&mut settings, "not-a-real-choice");
        // Unknown choice strings are silently ignored, matching the Java for-loop's fallthrough.
        assert_eq!(def.get_display_choice_for(&settings), "relative");
    }

    #[test]
    fn settings_definition_name_storage_key_and_description() {
        let def = PointerTypeSettingsDefinition::DEF;
        assert_eq!(def.get_name(), "Pointer Type");
        assert_eq!(def.get_storage_key(), "ptr_type");
        assert_eq!(
            def.get_description(),
            "Specifies the pointer type which affects interpretation of offset"
        );
    }

    #[test]
    fn value_string_reflects_current_choice() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut settings = MockSettings::new();
        assert_eq!(def.get_value_string(&settings), Some("default".to_string()));
        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_value_string(&settings), Some("image-base-relative".to_string()));
    }

    #[test]
    fn clear_removes_stored_value() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut settings = MockSettings::new();
        def.set_choice(&mut settings, 1);
        assert!(def.has_value(&settings));
        def.clear(&mut settings);
        assert!(!def.has_value(&settings));
    }

    #[test]
    fn copy_setting_copies_and_clears() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();

        def.set_choice(&mut src, 3);
        def.copy_setting(&src, &mut dest);
        assert_eq!(def.get_choice(&dest), 3);

        let empty_src = MockSettings::new();
        def.copy_setting(&empty_src, &mut dest);
        assert!(!def.has_value(&dest));
    }

    #[test]
    fn has_same_value_matches_enum_settings_definition_default() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut a = MockSettings::new();
        let mut b = MockSettings::new();
        assert!(SettingsDefinition::has_same_value(&def, &a, &b));

        def.set_choice(&mut a, 2);
        assert!(!SettingsDefinition::has_same_value(&def, &a, &b));

        def.set_choice(&mut b, 2);
        assert!(SettingsDefinition::has_same_value(&def, &a, &b));
    }

    #[test]
    fn attribute_specification_none_for_default_choice() {
        let def = PointerTypeSettingsDefinition::DEF;
        let settings = MockSettings::new();
        assert_eq!(def.get_attribute_specification(&settings), None);
    }

    #[test]
    fn attribute_specification_names_non_default_choice() {
        let def = PointerTypeSettingsDefinition::DEF;
        let mut settings = MockSettings::new();
        def.set_choice(&mut settings, 1);
        assert_eq!(def.get_attribute_specification(&settings), Some("image-base-relative".to_string()));
    }
}
