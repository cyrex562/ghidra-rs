use std::collections::HashMap;
use std::sync::OnceLock;

use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;

const CHARSET_SETTING_NAME: &str = "charset";

/// Backward compatible to the setting from MBCS data type. This setting value will be cleared
/// whenever the charset is changed.
const DEPRECATED_ENCODING_SETTING_NAME: &str = "encoding";

/// Backward compatible to the setting from MBCS data type. This setting value will be cleared
/// whenever the charset is changed.
const DEPRECATED_LANGUAGE_SETTING_NAME: &str = "language";

const CHARSET_NAME: &str = "Charset";

/// Best-effort fallback name list used to build the [`CharsetSettingsDefinition::charset`]
/// singleton until `ghidra.util.charset.CharsetInfoManager` (still `TODO` in
/// `PORT_MANIFEST.tsv`) is ported and can supply the full, platform-derived charset name list
/// that the Java constructor pulls from `CharsetInfoManager.getInstance().getCharsetNames()`.
/// These are the charset names this crate's own ported code already produces or consumes by name
/// (see [`DEFAULT_CHARSET_NAME`](crate::program::model::data::string_data_instance::DEFAULT_CHARSET_NAME)
/// and the `CharsetInfoManager.UTF8`/`UTF16`/`UTF32` placeholders in
/// [`crate::program::seam_stubs`]), so the singleton's ordinal/display-choice list at least
/// round-trips every name this crate currently uses, even though it is not the exhaustive list
/// the real `CharsetInfoManager` would provide.
const FALLBACK_CHARSET_NAMES: &[&str] = &["US-ASCII", "UTF-8", "UTF-16", "UTF-32"];

static CHARSET_SINGLETON: OnceLock<CharsetSettingsDefinition> = OnceLock::new();

/// Backward compatibility map from old MBCS `(language_index, charset_index)` tuples to a simple
/// charset-name value. Mirrors `CharsetSettingsDefinition.languageToCharsetIndexMap`.
static LANGUAGE_TO_CHARSET_INDEX_MAP: OnceLock<std::sync::Mutex<HashMap<i64, Vec<String>>>> =
    OnceLock::new();

fn language_map() -> &'static std::sync::Mutex<HashMap<i64, Vec<String>>> {
    LANGUAGE_TO_CHARSET_INDEX_MAP.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// [`EnumSettingsDefinition`] for setting the charset of a string instance.
///
/// Charsets control how raw bytes are converted to native string instances. `CharsetInfo`
/// (`ghidra.util.charset.CharsetInfo`, not yet ported) controls the list of character sets that
/// the user is shown; see [`FALLBACK_CHARSET_NAMES`] for the gap this leaves in
/// [`CharsetSettingsDefinition::charset`]'s ordinal list until that dependency lands.
///
/// Port of `ghidra.program.model.data.CharsetSettingsDefinition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharsetSettingsDefinition {
    ordinal_to_string: Vec<String>,
    string_to_ordinal: HashMap<String, i32>,
}

impl CharsetSettingsDefinition {
    /// Builds a `CharsetSettingsDefinition` whose choice list is exactly `charset_names`, in
    /// order. Mirrors the private Java constructor, which instead always sources this list from
    /// `CharsetInfoManager.getInstance().getCharsetNames()`; since that manager is not yet
    /// ported, callers (including [`Self::charset`]) must supply the list explicitly.
    pub fn new(charset_names: Vec<String>) -> Self {
        let mut string_to_ordinal = HashMap::with_capacity(charset_names.len());
        for (index, name) in charset_names.iter().enumerate() {
            string_to_ordinal.insert(name.clone(), index as i32);
        }
        CharsetSettingsDefinition {
            ordinal_to_string: charset_names,
            string_to_ordinal,
        }
    }

    /// Returns the shared `CharsetSettingsDefinition` singleton, standing in for the Java
    /// `CharsetSettingsDefinition.CHARSET` static field. Built once from
    /// [`FALLBACK_CHARSET_NAMES`] -- see that constant's docs for the fidelity gap this implies.
    pub fn charset() -> &'static CharsetSettingsDefinition {
        CHARSET_SINGLETON.get_or_init(|| {
            CharsetSettingsDefinition::new(
                FALLBACK_CHARSET_NAMES.iter().map(|s| s.to_string()).collect(),
            )
        })
    }

    /// Port of `CharsetSettingsDefinition.getCharset(Settings, String)`.
    ///
    /// Returns the charset name stored in `settings`, falling back to the deprecated MBCS
    /// `(language, encoding)` index lookup, and finally to `default_value` if neither is present.
    pub fn get_charset(&self, settings: &dyn Settings, default_value: &str) -> String {
        let cs = settings
            .get_string(CHARSET_SETTING_NAME)
            .or_else(|| self.get_deprecated_encoding_value(settings));
        cs.unwrap_or_else(|| default_value.to_string())
    }

    fn get_deprecated_encoding_value(&self, settings: &dyn Settings) -> Option<String> {
        let lang_index = settings.get_long(DEPRECATED_LANGUAGE_SETTING_NAME)?;
        let encoding_index = settings.get_long(DEPRECATED_ENCODING_SETTING_NAME)?;

        let map = language_map().lock().unwrap();
        let encodings = map.get(&lang_index)?;
        if encoding_index < 0 || encoding_index as usize >= encodings.len() {
            return None;
        }
        Some(encodings[encoding_index as usize].clone())
    }

    /// Port of `CharsetSettingsDefinition.setCharset(Settings, String)`.
    pub fn set_charset(&self, settings: &mut dyn Settings, charset: Option<&str>) {
        match charset {
            None => settings.clear_setting(CHARSET_SETTING_NAME),
            Some(charset) if charset.is_empty() => settings.clear_setting(CHARSET_SETTING_NAME),
            Some(charset) => settings.set_string(CHARSET_SETTING_NAME, charset),
        }
        settings.clear_setting(DEPRECATED_ENCODING_SETTING_NAME);
        settings.clear_setting(DEPRECATED_LANGUAGE_SETTING_NAME);
    }

    /// Port of the static `CharsetSettingsDefinition.setStaticEncodingMappingValues(Map)`.
    ///
    /// Sets a static lookup table that maps from old deprecated `(language, encoding)` index
    /// values to a charset name. The old index values were used by the old-style MBCS data type.
    pub fn set_static_encoding_mapping_values(mapping_values: HashMap<i64, Vec<String>>) {
        let mut map = language_map().lock().unwrap();
        *map = mapping_values;
    }
}

impl EnumSettingsDefinition for CharsetSettingsDefinition {
    fn get_choice(&self, settings: &dyn Settings) -> i32 {
        let charset = self.get_charset(settings, "");
        self.string_to_ordinal.get(&charset).copied().unwrap_or(0)
    }

    fn set_choice(&self, settings: &mut dyn Settings, ordinal_of_value: i32) {
        if ordinal_of_value < 0 || ordinal_of_value as usize >= self.ordinal_to_string.len() {
            settings.clear_setting(CHARSET_SETTING_NAME);
        } else {
            settings.set_string(
                CHARSET_SETTING_NAME,
                &self.ordinal_to_string[ordinal_of_value as usize],
            );
        }
        settings.clear_setting(DEPRECATED_ENCODING_SETTING_NAME);
        settings.clear_setting(DEPRECATED_LANGUAGE_SETTING_NAME);
    }

    fn get_display_choice(&self, value: i32, _settings: &dyn Settings) -> String {
        self.ordinal_to_string[value as usize].clone()
    }

    fn get_display_choices(&self, _settings: &dyn Settings) -> Vec<String> {
        self.ordinal_to_string.clone()
    }
}

impl SettingsDefinition for CharsetSettingsDefinition {
    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        let value = self.get_charset(settings, "");
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }

    fn get_name(&self) -> String {
        CHARSET_NAME.to_string()
    }

    fn get_storage_key(&self) -> String {
        CHARSET_SETTING_NAME.to_string()
    }

    fn get_description(&self) -> String {
        "Character set".to_string()
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting(CHARSET_SETTING_NAME);
    }

    fn copy_setting(&self, src_settings: &dyn Settings, dest_settings: &mut dyn Settings) {
        match src_settings.get_string(CHARSET_SETTING_NAME) {
            None => dest_settings.clear_setting(CHARSET_SETTING_NAME),
            Some(s) => dest_settings.set_string(CHARSET_SETTING_NAME, &s),
        }
    }

    fn has_value(&self, setting: &dyn Settings) -> bool {
        setting.get_value(CHARSET_SETTING_NAME).is_some()
            || setting.get_value(DEPRECATED_ENCODING_SETTING_NAME).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::cell::RefCell;
    use std::collections::HashMap as StdHashMap;

    struct MockSettings {
        strings: RefCell<StdHashMap<String, String>>,
        longs: RefCell<StdHashMap<String, i64>>,
    }

    impl MockSettings {
        fn new() -> Self {
            MockSettings {
                strings: RefCell::new(StdHashMap::new()),
                longs: RefCell::new(StdHashMap::new()),
            }
        }
    }

    impl Settings for MockSettings {
        fn get_long(&self, name: &str) -> Option<i64> {
            self.longs.borrow().get(name).copied()
        }

        fn get_string(&self, name: &str) -> Option<String> {
            self.strings.borrow().get(name).cloned()
        }

        fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
            if let Some(s) = self.strings.borrow().get(name) {
                return Some(Box::new(s.clone()));
            }
            self.longs.borrow().get(name).map(|v| Box::new(*v) as Box<dyn Any>)
        }

        fn set_long(&mut self, name: &str, value: i64) {
            self.longs.borrow_mut().insert(name.to_string(), value);
        }

        fn set_string(&mut self, name: &str, value: &str) {
            self.strings.borrow_mut().insert(name.to_string(), value.to_string());
        }

        fn clear_setting(&mut self, name: &str) {
            self.strings.borrow_mut().remove(name);
            self.longs.borrow_mut().remove(name);
        }

        fn is_empty(&self) -> bool {
            self.strings.borrow().is_empty() && self.longs.borrow().is_empty()
        }
    }

    fn def() -> CharsetSettingsDefinition {
        CharsetSettingsDefinition::new(vec![
            "US-ASCII".to_string(),
            "UTF-8".to_string(),
            "UTF-16".to_string(),
        ])
    }

    #[test]
    fn get_charset_returns_default_when_unset() {
        let d = def();
        let s = MockSettings::new();
        assert_eq!(d.get_charset(&s, "fallback"), "fallback");
    }

    #[test]
    fn set_and_get_charset_round_trips() {
        let d = def();
        let mut s = MockSettings::new();
        d.set_charset(&mut s, Some("UTF-16"));
        assert_eq!(d.get_charset(&s, "fallback"), "UTF-16");
    }

    #[test]
    fn set_charset_none_clears_setting() {
        let d = def();
        let mut s = MockSettings::new();
        d.set_charset(&mut s, Some("UTF-16"));
        d.set_charset(&mut s, None);
        assert_eq!(d.get_charset(&s, "fallback"), "fallback");
    }

    #[test]
    fn set_charset_empty_string_clears_setting() {
        let d = def();
        let mut s = MockSettings::new();
        d.set_charset(&mut s, Some("UTF-16"));
        d.set_charset(&mut s, Some(""));
        assert_eq!(d.get_charset(&s, "fallback"), "fallback");
    }

    #[test]
    fn set_charset_clears_deprecated_settings() {
        let d = def();
        let mut s = MockSettings::new();
        s.set_long(super::DEPRECATED_LANGUAGE_SETTING_NAME, 1);
        s.set_long(super::DEPRECATED_ENCODING_SETTING_NAME, 0);
        d.set_charset(&mut s, Some("UTF-8"));
        assert_eq!(s.get_long(super::DEPRECATED_LANGUAGE_SETTING_NAME), None);
        assert_eq!(s.get_long(super::DEPRECATED_ENCODING_SETTING_NAME), None);
    }

    #[test]
    fn deprecated_encoding_lookup_used_when_charset_unset() {
        CharsetSettingsDefinition::set_static_encoding_mapping_values(HashMap::from([(
            7i64,
            vec!["Big5".to_string(), "Shift-JIS".to_string()],
        )]));
        let d = def();
        let mut s = MockSettings::new();
        s.set_long(super::DEPRECATED_LANGUAGE_SETTING_NAME, 7);
        s.set_long(super::DEPRECATED_ENCODING_SETTING_NAME, 1);

        assert_eq!(d.get_charset(&s, "fallback"), "Shift-JIS");

        // Clean up global state so other tests in this module aren't affected.
        CharsetSettingsDefinition::set_static_encoding_mapping_values(HashMap::new());
    }

    #[test]
    fn get_choice_and_set_choice_round_trip() {
        let d = def();
        let mut s = MockSettings::new();
        d.set_choice(&mut s, 2);
        assert_eq!(d.get_choice(&s), 2);
        assert_eq!(EnumSettingsDefinition::get_display_choice(&d, 2, &s), "UTF-16");
    }

    #[test]
    fn set_choice_out_of_range_clears_setting() {
        let d = def();
        let mut s = MockSettings::new();
        d.set_choice(&mut s, 1);
        d.set_choice(&mut s, 99);
        assert_eq!(d.get_charset(&s, "fallback"), "fallback");
    }

    #[test]
    fn get_display_choices_matches_constructor_list() {
        let d = def();
        let s = MockSettings::new();
        assert_eq!(
            d.get_display_choices(&s),
            vec!["US-ASCII".to_string(), "UTF-8".to_string(), "UTF-16".to_string()]
        );
    }

    #[test]
    fn has_value_reflects_charset_or_deprecated_encoding() {
        let d = def();
        let mut s = MockSettings::new();
        assert!(!d.has_value(&s));

        d.set_charset(&mut s, Some("UTF-8"));
        assert!(d.has_value(&s));

        d.clear(&mut s);
        assert!(!d.has_value(&s));

        s.set_long(super::DEPRECATED_ENCODING_SETTING_NAME, 3);
        assert!(d.has_value(&s));
    }

    #[test]
    fn copy_setting_copies_charset_value() {
        let d = def();
        let mut src = MockSettings::new();
        let mut dest = MockSettings::new();
        d.set_charset(&mut src, Some("UTF-8"));

        d.copy_setting(&src, &mut dest);
        assert_eq!(d.get_charset(&dest, "fallback"), "UTF-8");
    }

    #[test]
    fn copy_setting_clears_dest_when_src_unset() {
        let d = def();
        let src = MockSettings::new();
        let mut dest = MockSettings::new();
        d.set_charset(&mut dest, Some("UTF-8"));

        d.copy_setting(&src, &mut dest);
        assert!(!d.has_value(&dest));
    }

    #[test]
    fn name_storage_key_and_description() {
        let d = def();
        assert_eq!(d.get_name(), "Charset");
        assert_eq!(d.get_storage_key(), "charset");
        assert_eq!(d.get_description(), "Character set");
    }

    #[test]
    fn charset_singleton_contains_fallback_names() {
        let singleton = CharsetSettingsDefinition::charset();
        let choices = singleton.get_display_choices(&MockSettings::new());
        assert!(choices.contains(&"US-ASCII".to_string()));
        assert!(choices.contains(&"UTF-8".to_string()));
        assert!(choices.contains(&"UTF-16".to_string()));
        assert!(choices.contains(&"UTF-32".to_string()));
    }

    #[test]
    fn usable_as_trait_object() {
        let d = def();
        let dyn_def: &dyn SettingsDefinition = &d;
        assert_eq!(dyn_def.get_name(), "Charset");
    }
}
