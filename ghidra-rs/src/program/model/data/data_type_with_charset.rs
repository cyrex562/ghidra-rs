use crate::program::seam_stubs::{DataType, MemBuffer, Settings, StringDataInstance, DEFAULT_CHARSET_NAME};

/// A character value to encode, standing in for the `Object value` parameter of
/// `DataTypeWithCharset.encodeCharacterValue`, which Java accepts as either a `Character` or a
/// `char[]` representing a single code point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CharacterValue {
    /// A single character.
    Char(char),
    /// A short run of chars representing one code point (mirrors a Java UTF-16 surrogate pair).
    CodePoint(Vec<char>),
}

/// Error returned when a character value or representation cannot be encoded, standing in for
/// `ghidra.program.model.data.DataTypeEncodeException` before that class is ported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeEncodeError(pub String);

impl std::fmt::Display for DataTypeEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DataTypeEncodeError {}

/// Extension of [`DataType`] for character-oriented data types that can encode a character
/// value or representation into bytes using an associated charset.
///
/// Port of `ghidra.program.model.data.DataTypeWithCharset`.
pub trait DataTypeWithCharset: DataType {
    /// Builds the (not yet ported) `StringDataInstance` used to perform the actual encoding for
    /// this data type, settings, and buffer, mirroring
    /// `new StringDataInstance(this, settings, buf, getLength())` from the Java default methods
    /// below. Required until `StringDataInstance` itself is ported.
    fn string_data_instance(
        &self,
        settings: &dyn Settings,
        buf: &dyn MemBuffer,
    ) -> Box<dyn StringDataInstance>;

    /// Utility for character data types to encode a value.
    fn encode_character_value(
        &self,
        value: CharacterValue,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let normalized_value = match value {
            CharacterValue::Char(c) => vec![c],
            CharacterValue::CodePoint(chars) => {
                if chars.len() > 2 {
                    return Err(DataTypeEncodeError(
                        "char[] must represent a single code point".to_string(),
                    ));
                }
                chars
            }
        };
        let sdi = self.string_data_instance(settings, buf);
        sdi.encode_replacement_from_char_value(&normalized_value)
            .map_err(DataTypeEncodeError)
    }

    /// Utility for character data types to encode a representation.
    fn encode_character_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let sdi = self.string_data_instance(settings, buf);
        sdi.encode_replacement_from_char_representation(repr)
            .map_err(DataTypeEncodeError)
    }

    /// Get the character set for a specific data type and settings.
    fn get_charset_name(&self, _settings: &dyn Settings) -> String {
        DEFAULT_CHARSET_NAME.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockMemBuffer;
    impl MemBuffer for MockMemBuffer {}

    struct MockStringDataInstance;
    impl StringDataInstance for MockStringDataInstance {
        fn encode_replacement_from_char_value(&self, value: &[char]) -> Result<Vec<u8>, String> {
            Ok(value.iter().collect::<String>().into_bytes())
        }

        fn encode_replacement_from_char_representation(
            &self,
            repr: &str,
        ) -> Result<Vec<u8>, String> {
            Ok(repr.as_bytes().to_vec())
        }
    }

    struct MockCharDataType;
    impl DataType for MockCharDataType {
        fn get_length(&self) -> i32 {
            1
        }
    }
    impl DataTypeWithCharset for MockCharDataType {
        fn string_data_instance(
            &self,
            _settings: &dyn Settings,
            _buf: &dyn MemBuffer,
        ) -> Box<dyn StringDataInstance> {
            Box::new(MockStringDataInstance)
        }
    }

    #[test]
    fn encodes_single_char_value() {
        let dt = MockCharDataType;
        let encoded = dt
            .encode_character_value(CharacterValue::Char('a'), &MockMemBuffer, &MockSettings)
            .unwrap();
        assert_eq!(encoded, b"a".to_vec());
    }

    #[test]
    fn rejects_code_point_longer_than_two_chars() {
        let dt = MockCharDataType;
        let err = dt
            .encode_character_value(
                CharacterValue::CodePoint(vec!['a', 'b', 'c']),
                &MockMemBuffer,
                &MockSettings,
            )
            .unwrap_err();
        assert_eq!(err.to_string(), "char[] must represent a single code point");
    }

    #[test]
    fn encodes_character_representation() {
        let dt = MockCharDataType;
        let encoded = dt
            .encode_character_representation("z", &MockMemBuffer, &MockSettings)
            .unwrap();
        assert_eq!(encoded, b"z".to_vec());
    }

    #[test]
    fn default_charset_name_matches_string_data_instance_default() {
        let dt = MockCharDataType;
        assert_eq!(dt.get_charset_name(&MockSettings), "US-ASCII");
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockCharDataType;
        let dyn_dt: &dyn DataTypeWithCharset = &dt;
        assert_eq!(dyn_dt.get_length(), 1);
        assert!(dyn_dt
            .encode_character_value(CharacterValue::Char('x'), &MockMemBuffer, &MockSettings)
            .is_ok());
    }
}
