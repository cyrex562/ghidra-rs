//! Port of `ghidra.program.model.data.DataTypeWithCharset`.

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_encode_exception::DataTypeEncodeException;
use crate::program::model::data::string_data_instance::{StringDataInstance, DEFAULT_CHARSET_NAME};
use crate::program::model::mem::MemBuffer;

/// A character value to encode: the `Object value` of `DataTypeWithCharset.encodeCharacterValue`,
/// which Java accepts as a `Character` or as a `char[]` holding a single code point. Both are Java
/// chars (UTF-16 code units).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CharacterValue {
    /// A `Character`.
    Char(u16),
    /// A `char[]`; it must represent a single code point (at most 2 chars).
    Chars(Vec<u16>),
}

impl CharacterValue {
    /// Converts the value a caller passes to [`DataType::encode_value`]: a [`CharacterValue`], a
    /// Rust `char` (its UTF-16 form), a `u16` (`Character`) or a `Vec<u16>` (`char[]`). `None`
    /// is Java's "Requires Character or char[] with a single code point".
    pub fn from_any(value: &dyn Any) -> Option<CharacterValue> {
        if let Some(v) = value.downcast_ref::<CharacterValue>() {
            return Some(v.clone());
        }
        if let Some(c) = value.downcast_ref::<char>() {
            let mut buf = [0u16; 2];
            let units = c.encode_utf16(&mut buf);
            return Some(if units.len() == 1 { CharacterValue::Char(units[0]) } else { CharacterValue::Chars(units.to_vec()) });
        }
        if let Some(c) = value.downcast_ref::<u16>() {
            return Some(CharacterValue::Char(*c));
        }
        value.downcast_ref::<Vec<u16>>().map(|chars| CharacterValue::Chars(chars.clone()))
    }
}

impl std::fmt::Display for CharacterValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let units: &[u16] = match self {
            CharacterValue::Char(c) => std::slice::from_ref(c),
            CharacterValue::Chars(chars) => chars,
        };
        f.write_str(&String::from_utf16_lossy(units))
    }
}

/// The error the `DataType` encode methods report, carrying the message of the Java
/// `DataTypeEncodeException` they throw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeEncodeError(pub String);

impl std::fmt::Display for DataTypeEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DataTypeEncodeError {}

impl From<DataTypeEncodeException> for DataTypeEncodeError {
    fn from(e: DataTypeEncodeException) -> Self {
        DataTypeEncodeError(e.to_string())
    }
}

/// A [`DataType`] with a charset: string and character data types.
///
/// Port of `ghidra.program.model.data.DataTypeWithCharset`.
pub trait DataTypeWithCharset: DataType {
    /// Utility for character data types to encode a value (`encodeCharacterValue`).
    fn encode_character_value(
        &self,
        value: CharacterValue,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let normalized_value = match &value {
            CharacterValue::Char(c) => vec![*c],
            CharacterValue::Chars(chars) => {
                if chars.len() > 2 {
                    return Err(DataTypeEncodeException::new(
                        "char[] must represent a single code point",
                        &value,
                        self.get_display_name(),
                    )
                    .into());
                }
                chars.clone()
            }
        };
        let sdi = StringDataInstance::new(self, settings, buf, self.get_length());
        sdi.encode_replacement_from_char_value(&normalized_value)
            .map_err(|e| DataTypeEncodeException::with_cause_only(&value, self.get_display_name(), Box::new(e)).into())
    }

    /// Utility for character data types to encode a representation
    /// (`encodeCharacterRepresentation`).
    fn encode_character_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let sdi = StringDataInstance::new(self, settings, buf, self.get_length());
        sdi.encode_replacement_from_char_representation(repr)
            .map_err(|e| DataTypeEncodeException::with_cause_only(repr, self.get_display_name(), Box::new(e)).into())
    }

    /// Get the character set for a specific data type and settings (`getCharsetName`).
    fn get_charset_name(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        DEFAULT_CHARSET_NAME.to_string()
    }
}

/// [`DataTypeWithCharset::encode_character_value`] for the `&dyn Any` a
/// [`DataType::encode_value`] receives.
pub fn encode_character_value_from_any<T: DataTypeWithCharset + ?Sized>(
    dt: &T,
    value: &dyn Any,
    buf: &dyn MemBuffer,
    settings: &dyn Settings,
) -> Result<Vec<u8>, DataTypeEncodeError> {
    match CharacterValue::from_any(value) {
        Some(value) => dt.encode_character_value(value, buf, settings),
        None => Err(DataTypeEncodeException::new(
            "Requires Character or char[] with a single code point",
            "?",
            dt.get_display_name(),
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::string_data_instance::test_support::{mb, SettingsBuilder};

    struct AsciiChar;
    impl DataType for AsciiChar {
        fn get_name(&self) -> String {
            "achar".into()
        }
        fn get_length(&self) -> i32 {
            1
        }
        fn as_data_type_with_charset(&self) -> Option<&dyn DataTypeWithCharset> {
            Some(self)
        }
    }
    impl DataTypeWithCharset for AsciiChar {}

    #[test]
    fn encodes_a_char_value_with_the_default_charset() {
        let dt = AsciiChar;
        let buf = mb(false, &[]);
        let settings = SettingsBuilder::new();
        assert_eq!(dt.encode_character_value(CharacterValue::Char(b'a' as u16), &buf, &settings).unwrap(), b"a");
        assert_eq!(dt.get_charset_name(&settings), "US-ASCII");
        let err = dt.encode_character_value(CharacterValue::Chars(vec![1, 2, 3]), &buf, &settings).unwrap_err();
        assert!(err.0.contains("char[] must represent a single code point"));
        assert!(dt.encode_character_value(CharacterValue::Char(0xE9), &buf, &settings).is_err());
    }

    #[test]
    fn encodes_a_char_representation() {
        let dt = AsciiChar;
        let buf = mb(false, &[]);
        assert_eq!(dt.encode_character_representation("'a'", &buf, &SettingsBuilder::new()).unwrap(), b"a");
        assert_eq!(dt.encode_character_representation("41h", &buf, &SettingsBuilder::new()).unwrap(), b"A");
        assert!(dt.encode_character_representation("'a", &buf, &SettingsBuilder::new()).is_err());
    }

    #[test]
    fn character_value_from_any() {
        assert_eq!(CharacterValue::from_any(&'a'), Some(CharacterValue::Char(0x61)));
        assert_eq!(CharacterValue::from_any(&'\u{1F600}'), Some(CharacterValue::Chars(vec![0xD83D, 0xDE00])));
        assert_eq!(CharacterValue::from_any(&vec![0x41u16]), Some(CharacterValue::Chars(vec![0x41])));
        assert_eq!(CharacterValue::from_any(&5i32), None);
        let dt = AsciiChar;
        assert!(encode_character_value_from_any(&dt, &5i32, &mb(false, &[]), &SettingsBuilder::new()).is_err());
    }
}
