//! Port of the id/reference side of `generic.theme.FontValue`.
//!
//! The crate has no `java.awt.Font` value type yet (`util::awt` holds only `Color` and
//! `KeyStroke`), so the font text (e.g. `dialog-PLAIN-14`) and any `FontModifier` text
//! (e.g. `[20][BOLD]`) are kept raw rather than inventing a font type here.

use thiserror::Error;

use super::g_theme_value_map::GThemeValueMap;
use super::theme_value::{ThemeValue, ThemeValueError, UnresolvedReference};
use super::theme_value_utils::parse_groupings;

/// Error parsing a font value (Java's `ParseException` / `IllegalArgumentException`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct FontParseError(pub String);

impl From<ThemeValueError> for FontParseError {
    fn from(e: ThemeValueError) -> Self {
        FontParseError(e.to_string())
    }
}

/// A font theme value: raw font text or a reference to another font id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FontValue {
    base: ThemeValue<String>,
    modifier_text: Option<String>,
}

impl AsRef<ThemeValue<String>> for FontValue {
    fn as_ref(&self) -> &ThemeValue<String> {
        &self.base
    }
}

impl FontValue {
    /// Normalized prefix of look-and-feel font ids.
    pub const LAF_ID_PREFIX: &'static str = "laf.font.";
    /// External (file) prefix of look-and-feel font ids.
    pub const EXTERNAL_LAF_ID_PREFIX: &'static str = "[laf.font]";
    /// Prefix of application font ids.
    pub const FONT_ID_PREFIX: &'static str = "font.";
    const EXTERNAL_PREFIX: &'static str = "[font]";

    /// `isFontKey(key)`
    pub fn is_font_key(key: &str) -> bool {
        key.starts_with(Self::FONT_ID_PREFIX)
            || key.starts_with(Self::EXTERNAL_PREFIX)
            || key.starts_with(Self::EXTERNAL_LAF_ID_PREFIX)
    }

    /// `parse(key, value)`: strips the optional surrounding parentheses, then yields a
    /// reference (with optional raw modifier text) when the value is a font key, else the
    /// raw font text. `Ok(None)` when the text is not `family-STYLE-size` (Java's `null`).
    pub fn parse(key: &str, value: &str) -> Result<Option<Self>, FontParseError> {
        let id = from_external_id(key);
        let mut value = value.trim();
        value = value.strip_prefix('(').unwrap_or(value);
        value = value.strip_suffix(')').unwrap_or(value);
        if Self::is_font_key(value) {
            let value = from_external_id(value);
            let Some(i) = value.find('[') else {
                return Ok(Some(Self {
                    base: ThemeValue::with_reference(id, value)?,
                    modifier_text: None,
                }));
            };
            let modifier = &value[i..];
            // FontModifier.parse accepts any well-formed [..] groups (unknown ones name a
            // family); an empty group list means no modifier.
            let groups =
                parse_groupings(modifier, '[', ']').map_err(|e| FontParseError(e.to_string()))?;
            return Ok(Some(Self {
                base: ThemeValue::with_reference(id, value[..i].trim())?,
                modifier_text: (!groups.is_empty()).then(|| modifier.to_string()),
            }));
        }
        if !is_font_text(value) {
            return Ok(None);
        }
        Ok(Some(Self {
            base: ThemeValue::with_value(id, value.to_string())?,
            modifier_text: None,
        }))
    }

    /// `getStyle(styleString)`: the `java.awt.Font` style bits, or `-1` if unknown.
    pub fn get_style(style: &str) -> i32 {
        match style.to_ascii_lowercase().as_str() {
            "plain" => 0,
            "bold" => 1,
            "italic" => 2,
            "bolditalic" => 3,
            _ => -1,
        }
    }

    /// `getId()`
    pub fn id(&self) -> &str {
        self.base.id()
    }

    /// `getReferenceId()`
    pub fn reference_id(&self) -> Option<&str> {
        self.base.reference_id()
    }

    /// `getRawValue()`: the raw font text.
    pub fn raw_value(&self) -> Option<&str> {
        self.base.raw_value().map(String::as_str)
    }

    /// The raw `FontModifier` text of a reference value, e.g. `[20][BOLD]`.
    pub fn modifier_text(&self) -> Option<&str> {
        self.modifier_text.as_deref()
    }

    /// `isExternal()`
    pub fn is_external(&self) -> bool {
        !self.id().starts_with(Self::FONT_ID_PREFIX)
    }

    /// `get(values)`: the raw font text, following references (modifiers not applied).
    pub fn get<'a>(&'a self, values: &'a GThemeValueMap) -> Result<&'a str, UnresolvedReference> {
        self.base.get(|id| values.get_font(id)).map(String::as_str)
    }
}

/// Java's `parseFont` acceptance test: `family-STYLE-size` with a known style and an
/// integer size.
fn is_font_text(value: &str) -> bool {
    let Some(size_index) = value.rfind('-') else {
        return false;
    };
    let Some(style_index) = value[..size_index].rfind('-') else {
        return false;
    };
    if size_index == 0 || style_index == 0 {
        return false;
    }
    value[size_index + 1..].parse::<i32>().is_ok()
        && FontValue::get_style(&value[style_index + 1..size_index]) >= 0
}

fn from_external_id(external_id: &str) -> String {
    if let Some(rest) = external_id.strip_prefix(FontValue::EXTERNAL_PREFIX) {
        return rest.to_string();
    }
    if let Some(rest) = external_id.strip_prefix(FontValue::EXTERNAL_LAF_ID_PREFIX) {
        return format!("{}{rest}", FontValue::LAF_ID_PREFIX);
    }
    external_id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_value_reference_and_modified_reference() {
        let v = FontValue::parse("font.a.8", "dialog-PLAIN-14")
            .unwrap()
            .unwrap();
        assert_eq!(v.raw_value(), Some("dialog-PLAIN-14"));
        let v = FontValue::parse("[laf.font]PasswordField.font", "font.a.8")
            .unwrap()
            .unwrap();
        assert_eq!(v.id(), "laf.font.PasswordField.font");
        assert_eq!(v.reference_id(), Some("font.a.8"));
        let v = FontValue::parse("font.a.b", "(font.a.8[20][BOLD])")
            .unwrap()
            .unwrap();
        assert_eq!(v.reference_id(), Some("font.a.8"));
        assert_eq!(v.modifier_text(), Some("[20][BOLD]"));
    }

    #[test]
    fn invalid_font_text_and_modifier() {
        assert!(FontValue::parse("font.b.2", "Dialog-PLANE-13")
            .unwrap()
            .is_none());
        assert!(FontValue::parse("font.b.3", "Dialog-BOLD-ITALIC")
            .unwrap()
            .is_none());
        assert!(FontValue::parse("font.b.4", "-PLAIN-12").unwrap().is_none());
        assert!(FontValue::parse("font.b.5", "Dialog-bolditalic-9")
            .unwrap()
            .is_some());
        assert!(FontValue::parse("font.b.2", "(font.b.1[)").is_err());
    }
}
