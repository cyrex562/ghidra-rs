//! Port of the id/reference side of `generic.theme.ColorValue`.
//!
//! The color text is kept raw (e.g. `white`, `#ff0000`, `rgba(255,0,0,0.5)`): Java converts
//! it with `ghidra.util.WebColors`, which is not ported yet, so converting to
//! [`crate::util::awt::Color`] is left to that port.

use super::g_theme_value_map::GThemeValueMap;
use super::theme_value::{ThemeValue, ThemeValueError, UnresolvedReference};

/// A color theme value: a raw color string or a reference to another color id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ColorValue {
    base: ThemeValue<String>,
}

impl AsRef<ThemeValue<String>> for ColorValue {
    fn as_ref(&self) -> &ThemeValue<String> {
        &self.base
    }
}

impl ColorValue {
    /// Normalized prefix of look-and-feel color ids.
    pub const LAF_ID_PREFIX: &'static str = "laf.color.";
    /// External (file) prefix of look-and-feel color ids.
    pub const EXTERNAL_LAF_ID_PREFIX: &'static str = "[laf.color]";
    /// Prefix of application color ids.
    pub const COLOR_ID_PREFIX: &'static str = "color.";
    const EXTERNAL_PREFIX: &'static str = "[color]";

    /// A value holding raw color text.
    pub fn new(
        id: impl Into<String>,
        color_text: impl Into<String>,
    ) -> Result<Self, ThemeValueError> {
        Ok(Self {
            base: ThemeValue::with_value(id, color_text.into())?,
        })
    }

    /// A value inheriting from color `ref_id`.
    pub fn reference(
        id: impl Into<String>,
        ref_id: impl Into<String>,
    ) -> Result<Self, ThemeValueError> {
        Ok(Self {
            base: ThemeValue::with_reference(id, ref_id)?,
        })
    }

    /// `isColorKey(key)`
    pub fn is_color_key(key: &str) -> bool {
        key.starts_with(Self::COLOR_ID_PREFIX)
            || key.starts_with(Self::EXTERNAL_PREFIX)
            || key.starts_with(Self::EXTERNAL_LAF_ID_PREFIX)
    }

    /// `parse(key, value)`: a reference when `value` is a color key, else raw color text.
    pub fn parse(key: &str, value: &str) -> Result<Self, ThemeValueError> {
        let id = from_external_id(key);
        if Self::is_color_key(value) {
            return Self::reference(id, from_external_id(value));
        }
        Self::new(id, value)
    }

    /// `getId()`
    pub fn id(&self) -> &str {
        self.base.id()
    }

    /// `getReferenceId()`
    pub fn reference_id(&self) -> Option<&str> {
        self.base.reference_id()
    }

    /// `getRawValue()`: the raw color text.
    pub fn raw_value(&self) -> Option<&str> {
        self.base.raw_value().map(String::as_str)
    }

    /// `isExternal()`
    pub fn is_external(&self) -> bool {
        !self.id().starts_with(Self::COLOR_ID_PREFIX)
    }

    /// `get(values)`: the raw color text, following references.
    pub fn get<'a>(&'a self, values: &'a GThemeValueMap) -> Result<&'a str, UnresolvedReference> {
        self.base.get(|id| values.get_color(id)).map(String::as_str)
    }

    /// `getSerializationString()` (value side written as the raw text).
    pub fn serialization_string(&self) -> String {
        let value = match self.reference_id() {
            Some(r) => to_external_id(r),
            None => self.raw_value().unwrap_or_default().to_string(),
        };
        format!("{} = {value}", to_external_id(self.id()))
    }
}

fn to_external_id(internal_id: &str) -> String {
    if internal_id.starts_with(ColorValue::COLOR_ID_PREFIX) {
        return internal_id.to_string();
    }
    if let Some(base) = internal_id.strip_prefix(ColorValue::LAF_ID_PREFIX) {
        return format!("{}{base}", ColorValue::EXTERNAL_LAF_ID_PREFIX);
    }
    format!("{}{internal_id}", ColorValue::EXTERNAL_PREFIX)
}

fn from_external_id(external_id: &str) -> String {
    if let Some(rest) = external_id.strip_prefix(ColorValue::EXTERNAL_PREFIX) {
        return rest.to_string();
    }
    if let Some(rest) = external_id.strip_prefix(ColorValue::EXTERNAL_LAF_ID_PREFIX) {
        return format!("{}{rest}", ColorValue::LAF_ID_PREFIX);
    }
    external_id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_value_and_references() {
        let v = ColorValue::parse("color.b.1", "white").unwrap();
        assert_eq!(v.raw_value(), Some("white"));
        let v = ColorValue::parse("[laf.color]TextArea.background", "color.b.1").unwrap();
        assert_eq!(v.id(), "laf.color.TextArea.background");
        assert!(v.is_external());
        assert_eq!(v.reference_id(), Some("color.b.1"));
        let v = ColorValue::parse("color.test", "[color]xyz.abc").unwrap();
        assert_eq!(v.reference_id(), Some("xyz.abc"));
        assert_eq!(v.serialization_string(), "color.test = [color]xyz.abc");
    }

    #[test]
    fn is_color_key() {
        assert!(ColorValue::is_color_key("color.a.b.c"));
        assert!(ColorValue::is_color_key("[color]a.b.c"));
        assert!(ColorValue::is_color_key("[laf.color]a.b.c"));
        assert!(!ColorValue::is_color_key("a.b.c"));
    }
}
