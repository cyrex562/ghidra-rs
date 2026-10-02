//! Port of `generic.theme.JavaPropertyValue` and its two concrete kinds,
//! `BooleanPropertyValue` (`[laf.boolean]...`) and `StringPropertyValue`
//! (`[laf.string]...`): external look-and-feel `UIManager` properties.
//!
//! Java's `installValue` throws `UnsupportedOperationException` and is not ported.

use super::g_theme_value_map::GThemeValueMap;
use super::theme_value::{ThemeValue, ThemeValueError, UnresolvedReference};

/// Which Java property class a value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropertyKind {
    /// `BooleanPropertyValue`
    Boolean,
    /// `StringPropertyValue`
    String,
}

impl PropertyKind {
    fn external_prefix(self) -> &'static str {
        match self {
            PropertyKind::Boolean => "[laf.boolean]",
            PropertyKind::String => "[laf.string]",
        }
    }

    fn is_key(self, key: &str) -> bool {
        key.to_lowercase().starts_with(self.external_prefix())
    }

    /// Returns the raw property name (e.g. `TextArea.background`), not a normalized id.
    fn strip_external_prefix(self, external_id: &str) -> String {
        if !self.is_key(external_id) {
            return external_id.to_string();
        }
        external_id[self.external_prefix().len()..].to_string()
    }
}

/// A property's concrete value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PropertyValue {
    /// A boolean property.
    Boolean(bool),
    /// A string property.
    String(String),
}

/// A Java look-and-feel property theme value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JavaPropertyValue {
    kind: PropertyKind,
    base: ThemeValue<PropertyValue>,
}

impl AsRef<ThemeValue<PropertyValue>> for JavaPropertyValue {
    fn as_ref(&self) -> &ThemeValue<PropertyValue> {
        &self.base
    }
}

impl JavaPropertyValue {
    /// `new BooleanPropertyValue(id, value)`
    pub fn boolean(id: impl Into<String>, value: bool) -> Result<Self, ThemeValueError> {
        Ok(Self {
            kind: PropertyKind::Boolean,
            base: ThemeValue::with_value(id, PropertyValue::Boolean(value))?,
        })
    }

    /// `new StringPropertyValue(id, value)`
    pub fn string(
        id: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, ThemeValueError> {
        Ok(Self {
            kind: PropertyKind::String,
            base: ThemeValue::with_value(id, PropertyValue::String(value.into()))?,
        })
    }

    /// `BooleanPropertyValue.isBooleanKey(key)` (case-insensitive prefix).
    pub fn is_boolean_key(key: &str) -> bool {
        PropertyKind::Boolean.is_key(key)
    }

    /// `StringPropertyValue.isStringKey(key)` (case-insensitive prefix).
    pub fn is_string_key(key: &str) -> bool {
        PropertyKind::String.is_key(key)
    }

    /// `BooleanPropertyValue.parse(key, value)`: `Boolean.parseBoolean` semantics.
    ///
    /// Java builds a reference value with the *unnormalized* key as its id, which the
    /// `ThemeValue` constructor rejects; that rejection is reproduced as an error.
    pub fn parse_boolean(key: &str, value: &str) -> Result<Self, ThemeValueError> {
        let kind = PropertyKind::Boolean;
        if kind.is_key(value) {
            return Ok(Self {
                kind,
                base: ThemeValue::with_reference(key, kind.strip_external_prefix(value))?,
            });
        }
        Self::boolean(
            kind.strip_external_prefix(key),
            value.eq_ignore_ascii_case("true"),
        )
    }

    /// `StringPropertyValue.parse(key, value)`
    pub fn parse_string(key: &str, value: &str) -> Result<Self, ThemeValueError> {
        let kind = PropertyKind::String;
        let id = kind.strip_external_prefix(key);
        if kind.is_key(value) {
            return Ok(Self {
                kind,
                base: ThemeValue::with_reference(id, kind.strip_external_prefix(value))?,
            });
        }
        Self::string(id, value)
    }

    /// Which property class this is.
    pub fn kind(&self) -> PropertyKind {
        self.kind
    }

    /// `getId()`
    pub fn id(&self) -> &str {
        self.base.id()
    }

    /// `getReferenceId()`
    pub fn reference_id(&self) -> Option<&str> {
        self.base.reference_id()
    }

    /// `getRawValue()`
    pub fn raw_value(&self) -> Option<&PropertyValue> {
        self.base.raw_value()
    }

    /// `isExternal()`: Java properties are always external.
    pub fn is_external(&self) -> bool {
        true
    }

    /// `get(values)`: follows references through the map's properties.
    pub fn get<'a>(
        &'a self,
        values: &'a GThemeValueMap,
    ) -> Result<&'a PropertyValue, UnresolvedReference> {
        self.base.get(|id| values.get_property(id))
    }

    /// [`get`](Self::get) with Java's unresolved fallback (`false` / `""`).
    pub fn get_or_default(&self, values: &GThemeValueMap) -> PropertyValue {
        match self.get(values) {
            Ok(v) => v.clone(),
            Err(_) => match self.kind {
                PropertyKind::Boolean => PropertyValue::Boolean(false),
                PropertyKind::String => PropertyValue::String(String::new()),
            },
        }
    }

    /// `getSerializationString()`
    pub fn serialization_string(&self) -> String {
        let prefix = self.kind.external_prefix();
        let value = match self.raw_value() {
            Some(PropertyValue::Boolean(b)) => b.to_string(),
            Some(PropertyValue::String(s)) => s.clone(),
            // Java's String.valueOf(null) / Boolean.toString(null)
            None => "null".to_string(),
        };
        format!("{prefix}{} = {value}", self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_case_insensitive() {
        assert!(JavaPropertyValue::is_boolean_key("[LAF.Boolean]x"));
        assert!(JavaPropertyValue::is_string_key("[laf.string]x"));
        assert!(!JavaPropertyValue::is_string_key("[laf.boolean]x"));
    }

    #[test]
    fn parse_and_serialize() {
        let v =
            JavaPropertyValue::parse_boolean("[laf.boolean]PopupMenu.consumeEventOnClose", "false")
                .unwrap();
        assert_eq!(v.id(), "PopupMenu.consumeEventOnClose");
        assert_eq!(v.raw_value(), Some(&PropertyValue::Boolean(false)));
        assert_eq!(
            v.serialization_string(),
            "[laf.boolean]PopupMenu.consumeEventOnClose = false"
        );
        assert_eq!(
            JavaPropertyValue::parse_boolean("[laf.boolean]a", "TRUE")
                .unwrap()
                .raw_value(),
            Some(&PropertyValue::Boolean(true))
        );
        let v =
            JavaPropertyValue::parse_string("[laf.string]Fake.title", "This is my title").unwrap();
        assert_eq!(
            v.serialization_string(),
            "[laf.string]Fake.title = This is my title"
        );
        let r =
            JavaPropertyValue::parse_string("[laf.string]Other", "[laf.string]Fake.title").unwrap();
        assert_eq!(r.reference_id(), Some("Fake.title"));
    }

    #[test]
    fn boolean_reference_reproduces_java_constructor_rejection() {
        assert_eq!(
            JavaPropertyValue::parse_boolean("[laf.boolean]a", "[laf.boolean]b").unwrap_err(),
            ThemeValueError::ExternalId("[laf.boolean]a".into())
        );
    }

    #[test]
    fn unresolved_falls_back_to_java_defaults() {
        let values = GThemeValueMap::new();
        let r =
            JavaPropertyValue::parse_string("[laf.string]Other", "[laf.string]Missing").unwrap();
        assert_eq!(
            r.get_or_default(&values),
            PropertyValue::String(String::new())
        );
    }
}
