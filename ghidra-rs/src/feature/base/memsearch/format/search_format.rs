//! Port of `ghidra.features.base.memsearch.format.SearchFormat`.
//!
//! `SearchFormat`s are responsible for parsing user input data into a `ByteMatcher` that can be
//! used for searching memory. A format can also convert search matches back into string data and
//! can convert string data from other formats into string data for this format.
//!
//! Java's `SearchFormat` is an abstract class: it carries the one `name` field and the
//! concrete/overridable methods that read it or fall back to a default behavior (`getName`,
//! `toString`, `getValueString`, `compareValues`, `isValidText`), alongside the abstract methods
//! each concrete format must supply (`parse`, `getToolTip`, `convertText`, `getFormatType`). Rust
//! has no field inheritance, so [`SearchFormatBase`] holds the field; a concrete format embeds it
//! and implements [`SearchFormat`] for the abstract methods (and `base()`, which lets the trait's
//! default methods reach the embedded state). This is the same split
//! [`VtMarkupType`](crate::feature::vt::api::markuptype::vt_markup_type::VtMarkupType) uses for
//! the same reason.
//!
//! `SearchFormat`'s own static fields (`HEX`, `BINARY`, `DECIMAL`, `STRING`, `REG_EX`, `FLOAT`,
//! `DOUBLE`, `ALL`) instantiate its six concrete subclasses (`BinarySearchFormat`,
//! `DecimalSearchFormat`, `FloatSearchFormat`, `HexSearchFormat`, `RegExSearchFormat`,
//! `StringSearchFormat`), which are not ported yet and depend back on `SearchFormat` itself
//! (a cycle). Rather than change this type's shape, that cycle is broken by stubbing those six
//! classes as minimal placeholders in [`crate::feature::seam_stubs`] that implement
//! [`SearchFormat`]'s abstract methods with `unimplemented!()` bodies; replace each with the real
//! port as its own file is ported. `SearchSettings` and `UserInputByteMatcher` are stubbed the
//! same way, trimmed to the one member ([`UserInputByteMatcher::is_valid_search`]) this file
//! actually calls.

use crate::feature::seam_stubs::{SearchSettings, UserInputByteMatcher};

/// SearchFormats fall into one of 4 types.
///
/// Port of `SearchFormat.SearchFormatType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchFormatType {
    Byte,
    Integer,
    FloatingPoint,
    StringType,
}

/// The shared state of a [`SearchFormat`].
///
/// Port of the `name` field of `ghidra.features.base.memsearch.format.SearchFormat`.
pub struct SearchFormatBase {
    name: String,
}

impl SearchFormatBase {
    /// Java: `SearchFormat(String name)`.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Java: `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Java: `reverse(byte[] bytes)` (protected). Stateless, so kept as an associated function
    /// rather than threading `&self` through for no reason.
    pub fn reverse(bytes: &mut [u8]) {
        bytes.reverse();
    }
}

/// The abstract operations of a search format, plus the concrete convenience methods every
/// format shares (forwarded to its embedded [`SearchFormatBase`]) or may override.
///
/// Port of `ghidra.features.base.memsearch.format.SearchFormat`.
pub trait SearchFormat: Send + Sync {
    /// The shared state (currently just the format's display name) every format carries.
    fn base(&self) -> &SearchFormatBase;

    /// Java: `parse(String, SearchSettings)` (abstract). Parses the given input and settings into
    /// a `ByteMatcher` that can be used for searching bytes (or an error version of a matcher).
    fn parse(&self, input: &str, settings: &dyn SearchSettings) -> Box<dyn UserInputByteMatcher>;

    /// Java: `getToolTip()` (abstract). Returns a tool tip describing this search format.
    fn get_tool_tip(&self) -> String;

    /// Java: `convertText(String, SearchSettings, SearchSettings)` (abstract). Returns a new
    /// search input string, doing its best to convert an input string that was parsed by a
    /// previous `SearchFormat`.
    fn convert_text(
        &self,
        text: &str,
        old_settings: &dyn SearchSettings,
        new_settings: &dyn SearchSettings,
    ) -> String;

    /// Java: `getFormatType()` (abstract). Used to help with [`convert_text`](Self::convert_text).
    fn get_format_type(&self) -> SearchFormatType;

    /// Java: `getName()`. Returns the name of the search format.
    fn get_name(&self) -> &str {
        self.base().get_name()
    }

    /// Java: `toString()`.
    fn to_string(&self) -> String {
        self.get_name().to_string()
    }

    /// Java: `getValueString(byte[], SearchSettings)`. Reverse parses the bytes back into input
    /// value strings. Only used by numerical and string type formats; byte oriented formats just
    /// return an empty string, which is the default here too.
    fn get_value_string(&self, bytes: &[u8], settings: &dyn SearchSettings) -> String {
        let _ = (bytes, settings);
        String::new()
    }

    /// Java: `compareValues(byte[], byte[], SearchSettings)`. Compares bytes from search results
    /// based on how this format interprets the bytes. By default, formats just compare the bytes
    /// one by one as if they were unsigned values.
    fn compare_values(&self, bytes1: &[u8], bytes2: &[u8], settings: &dyn SearchSettings) -> i32 {
        let _ = settings;
        compare_bytes_unsigned(bytes1, bytes2)
    }

    /// Java: `isValidText(String, SearchSettings)` (protected).
    fn is_valid_text(&self, text: &str, settings: &dyn SearchSettings) -> bool {
        self.parse(text, settings).is_valid_search()
    }
}

/// Java: `compareBytesUnsigned(byte[], byte[])` (private).
fn compare_bytes_unsigned(old_bytes: &[u8], new_bytes: &[u8]) -> i32 {
    for i in 0..old_bytes.len() {
        let value1 = old_bytes[i] as i32;
        let value2 = new_bytes[i] as i32;
        if value1 != value2 {
            return value1 - value2;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::seam_stubs::{
        BinarySearchFormat, DecimalSearchFormat, FloatSearchFormat, HexSearchFormat,
        RegExSearchFormat, StringSearchFormat,
    };

    struct StubSettings;
    impl SearchSettings for StubSettings {}

    /// A minimal, fully-working [`SearchFormat`] used to exercise the trait's default methods
    /// (which the placeholder subclasses in `seam_stubs` deliberately leave `unimplemented!()`).
    struct TestFormat {
        base: SearchFormatBase,
        valid: bool,
    }

    struct TestMatcher {
        valid: bool,
    }

    impl UserInputByteMatcher for TestMatcher {
        fn is_valid_search(&self) -> bool {
            self.valid
        }
    }

    impl SearchFormat for TestFormat {
        fn base(&self) -> &SearchFormatBase {
            &self.base
        }

        fn parse(&self, _input: &str, _settings: &dyn SearchSettings) -> Box<dyn UserInputByteMatcher> {
            Box::new(TestMatcher { valid: self.valid })
        }

        fn get_tool_tip(&self) -> String {
            "test tool tip".to_string()
        }

        fn convert_text(
            &self,
            text: &str,
            _old_settings: &dyn SearchSettings,
            _new_settings: &dyn SearchSettings,
        ) -> String {
            text.to_string()
        }

        fn get_format_type(&self) -> SearchFormatType {
            SearchFormatType::Byte
        }
    }

    /// Java: `SearchFormat.HEX.getName()` etc. return the name each subclass's constructor passes
    /// to `super(name)`.
    #[test]
    fn well_known_formats_have_the_expected_names() {
        assert_eq!(HexSearchFormat::new().get_name(), "Hex");
        assert_eq!(BinarySearchFormat::new().get_name(), "Binary");
        assert_eq!(DecimalSearchFormat::new().get_name(), "Decimal");
        assert_eq!(StringSearchFormat::new().get_name(), "String");
        assert_eq!(RegExSearchFormat::new().get_name(), "Reg Ex");
        assert_eq!(FloatSearchFormat::new_float().get_name(), "Float");
        assert_eq!(FloatSearchFormat::new_double().get_name(), "Double");
    }

    /// Java: `SearchFormat.HEX.getFormatType()` etc.
    #[test]
    fn well_known_formats_have_the_expected_format_types() {
        assert_eq!(HexSearchFormat::new().get_format_type(), SearchFormatType::Byte);
        assert_eq!(BinarySearchFormat::new().get_format_type(), SearchFormatType::Byte);
        assert_eq!(DecimalSearchFormat::new().get_format_type(), SearchFormatType::Integer);
        assert_eq!(StringSearchFormat::new().get_format_type(), SearchFormatType::StringType);
        assert_eq!(RegExSearchFormat::new().get_format_type(), SearchFormatType::StringType);
        assert_eq!(FloatSearchFormat::new_float().get_format_type(), SearchFormatType::FloatingPoint);
        assert_eq!(FloatSearchFormat::new_double().get_format_type(), SearchFormatType::FloatingPoint);
    }

    /// Java: `SearchFormat.ALL = { HEX, BINARY, DECIMAL, STRING, REG_EX, FLOAT, DOUBLE }`.
    #[test]
    fn all_contains_the_seven_well_known_formats_in_order() {
        let all: Vec<Box<dyn SearchFormat>> = vec![
            Box::new(HexSearchFormat::new()),
            Box::new(BinarySearchFormat::new()),
            Box::new(DecimalSearchFormat::new()),
            Box::new(StringSearchFormat::new()),
            Box::new(RegExSearchFormat::new()),
            Box::new(FloatSearchFormat::new_float()),
            Box::new(FloatSearchFormat::new_double()),
        ];
        let names: Vec<&str> = all.iter().map(|f| f.get_name()).collect();
        assert_eq!(names, ["Hex", "Binary", "Decimal", "String", "Reg Ex", "Float", "Double"]);
    }

    /// Java: `toString()` returns `getName()`.
    #[test]
    fn to_string_returns_the_name() {
        let format = TestFormat { base: SearchFormatBase::new("Test"), valid: true };
        assert_eq!(SearchFormat::to_string(&format), "Test");
    }

    /// Java: the base `getValueString` always returns the empty string.
    #[test]
    fn default_value_string_is_empty() {
        let format = TestFormat { base: SearchFormatBase::new("Test"), valid: true };
        assert_eq!(format.get_value_string(&[1, 2, 3], &StubSettings), "");
    }

    /// Java: `compareValues` defaults to `compareBytesUnsigned`, which compares byte-by-byte as
    /// unsigned values and returns the difference at the first mismatch.
    #[test]
    fn default_compare_values_compares_bytes_as_unsigned() {
        let format = TestFormat { base: SearchFormatBase::new("Test"), valid: true };
        assert_eq!(format.compare_values(&[0x01, 0x02], &[0x01, 0x02], &StubSettings), 0);
        assert_eq!(format.compare_values(&[0x00], &[0xFF], &StubSettings), -255);
        assert_eq!(format.compare_values(&[0xFF], &[0x00], &StubSettings), 255);
    }

    /// Java: `reverse(byte[])` reverses the array in place.
    #[test]
    fn reverse_flips_the_byte_array() {
        let mut bytes = [1u8, 2, 3, 4, 5];
        SearchFormatBase::reverse(&mut bytes);
        assert_eq!(bytes, [5, 4, 3, 2, 1]);
    }

    /// Java: `isValidText` delegates to `parse(text, settings).isValidSearch()`.
    #[test]
    fn is_valid_text_delegates_to_parse_and_is_valid_search() {
        let valid = TestFormat { base: SearchFormatBase::new("Valid"), valid: true };
        let invalid = TestFormat { base: SearchFormatBase::new("Invalid"), valid: false };
        assert!(valid.is_valid_text("anything", &StubSettings));
        assert!(!invalid.is_valid_text("anything", &StubSettings));
    }
}
