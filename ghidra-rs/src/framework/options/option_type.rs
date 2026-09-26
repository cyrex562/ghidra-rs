//! Port of `ghidra.framework.options.OptionType`.
//!
//! Java's `OptionType` is an `enum` whose constants each carry a value class and a private
//! `StringAdapter` that converts option values to and from their persisted string form. Here the
//! enum is a plain Rust `enum` (shape rule R1), the value classes are reported as their Java class
//! names, option values are the closed [`OptionValue`] set, and each adapter becomes a `match` arm
//! of [`OptionType::convert_string_to_object`] / [`OptionType::convert_object_to_string`].

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::framework::options::custom_option::CustomOption;
use crate::framework::seam_stubs::{ActionTrigger, Color, Font, KeyStroke};

/// The kind of value an option holds, together with how that value is persisted as a string.
///
/// Port of `ghidra.framework.options.OptionType`. The constants appear in Java declaration
/// order, which [`OptionType::values`] preserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionType {
    /// `INT_TYPE` -- a `java.lang.Integer` (`i32`).
    IntType,
    /// `LONG_TYPE` -- a `java.lang.Long` (`i64`).
    LongType,
    /// `STRING_TYPE` -- a `java.lang.String`.
    StringType,
    /// `DOUBLE_TYPE` -- a `java.lang.Double` (`f64`).
    DoubleType,
    /// `BOOLEAN_TYPE` -- a `java.lang.Boolean`.
    BooleanType,
    /// `DATE_TYPE` -- a `java.util.Date`, persisted as milliseconds since the epoch.
    DateType,
    /// `NO_TYPE` -- no value class; every string converts to no value.
    NoType,
    /// `FLOAT_TYPE` -- a `java.lang.Float` (`f32`).
    FloatType,
    /// `ENUM_TYPE` -- any Java `enum` constant.
    EnumType,
    /// `CUSTOM_TYPE` -- a [`CustomOption`].
    CustomType,
    /// `BYTE_ARRAY_TYPE` -- a `byte[]`.
    ByteArrayType,
    /// `FILE_TYPE` -- a `java.io.File`.
    FileType,
    /// `COLOR_TYPE` -- a `java.awt.Color`.
    ColorType,
    /// `FONT_TYPE` -- a `java.awt.Font`.
    FontType,
    /// `KEYSTROKE_TYPE` -- a `javax.swing.KeyStroke`.
    KeystrokeType,
    /// `ACTION_TRIGGER` -- a `ghidra.framework.options.ActionTrigger`.
    ActionTrigger,
}

/// A Java `enum` constant held as an option value: the enum's fully-qualified class name plus the
/// constant's `name()`.
///
/// Java resolves the pair back to a live constant through reflection; in Rust that resolution is
/// the consumer's job (see [`EnumValues`](crate::framework::options::EnumValues)).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnumOptionValue {
    /// Fully-qualified Java class name of the enum (`Enum.getClass().getName()`).
    pub class_name: String,
    /// The constant's `name()`.
    pub name: String,
}

/// A value stored in an option: the Rust counterpart of the `Object` Java's `OptionType` methods
/// accept and return. There is one variant per [`OptionType`] other than
/// [`OptionType::NoType`], which has no value class (Java's `null`, here `None`).
#[derive(Clone)]
pub enum OptionValue {
    /// A `java.lang.Integer`.
    Int(i32),
    /// A `java.lang.Long`.
    Long(i64),
    /// A `java.lang.String`.
    String(String),
    /// A `java.lang.Double`.
    Double(f64),
    /// A `java.lang.Boolean`.
    Boolean(bool),
    /// A `java.util.Date`.
    Date(SystemTime),
    /// A `java.lang.Float`.
    Float(f32),
    /// A Java `enum` constant.
    Enum(EnumOptionValue),
    /// A [`CustomOption`].
    Custom(Arc<dyn CustomOption + Send + Sync>),
    /// A `byte[]`.
    ByteArray(Vec<u8>),
    /// A `java.io.File`.
    File(PathBuf),
    /// A `java.awt.Color`.
    Color(Arc<dyn Color + Send + Sync>),
    /// A `java.awt.Font`.
    Font(Arc<dyn Font + Send + Sync>),
    /// A `javax.swing.KeyStroke`.
    KeyStroke(Arc<dyn KeyStroke + Send + Sync>),
    /// A `ghidra.framework.options.ActionTrigger`.
    ActionTrigger(Arc<dyn ActionTrigger + Send + Sync>),
}

impl fmt::Debug for OptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionValue::Int(v) => f.debug_tuple("Int").field(v).finish(),
            OptionValue::Long(v) => f.debug_tuple("Long").field(v).finish(),
            OptionValue::String(v) => f.debug_tuple("String").field(v).finish(),
            OptionValue::Double(v) => f.debug_tuple("Double").field(v).finish(),
            OptionValue::Boolean(v) => f.debug_tuple("Boolean").field(v).finish(),
            OptionValue::Date(v) => f.debug_tuple("Date").field(v).finish(),
            OptionValue::Float(v) => f.debug_tuple("Float").field(v).finish(),
            OptionValue::Enum(v) => f.debug_tuple("Enum").field(v).finish(),
            OptionValue::Custom(v) => f.debug_tuple("Custom").field(&v.to_string()).finish(),
            OptionValue::ByteArray(v) => f.debug_tuple("ByteArray").field(v).finish(),
            OptionValue::File(v) => f.debug_tuple("File").field(v).finish(),
            OptionValue::Color(_) => f.write_str("Color(..)"),
            OptionValue::Font(_) => f.write_str("Font(..)"),
            OptionValue::KeyStroke(_) => f.write_str("KeyStroke(..)"),
            OptionValue::ActionTrigger(_) => f.write_str("ActionTrigger(..)"),
        }
    }
}

impl OptionValue {
    /// The [`OptionType`] whose value class this value is an instance of.
    pub fn option_type(&self) -> OptionType {
        match self {
            OptionValue::Int(_) => OptionType::IntType,
            OptionValue::Long(_) => OptionType::LongType,
            OptionValue::String(_) => OptionType::StringType,
            OptionValue::Double(_) => OptionType::DoubleType,
            OptionValue::Boolean(_) => OptionType::BooleanType,
            OptionValue::Date(_) => OptionType::DateType,
            OptionValue::Float(_) => OptionType::FloatType,
            OptionValue::Enum(_) => OptionType::EnumType,
            OptionValue::Custom(_) => OptionType::CustomType,
            OptionValue::ByteArray(_) => OptionType::ByteArrayType,
            OptionValue::File(_) => OptionType::FileType,
            OptionValue::Color(_) => OptionType::ColorType,
            OptionValue::Font(_) => OptionType::FontType,
            OptionValue::KeyStroke(_) => OptionType::KeystrokeType,
            OptionValue::ActionTrigger(_) => OptionType::ActionTrigger,
        }
    }

    /// Java's `Object.toString()` for the value kinds whose `toString` is plain data.
    ///
    /// This is what Java's base `StringAdapter.objectToString` produces for any object handed to
    /// one of the types that do not override it.
    fn java_to_string(&self) -> Option<String> {
        match self {
            OptionValue::Int(v) => Some(v.to_string()),
            OptionValue::Long(v) => Some(v.to_string()),
            OptionValue::String(v) => Some(v.clone()),
            OptionValue::Double(v) => Some(java_double_to_string(*v)),
            OptionValue::Boolean(v) => Some(v.to_string()),
            OptionValue::Float(v) => Some(java_float_to_string(*v)),
            OptionValue::File(v) => Some(v.to_string_lossy().into_owned()),
            OptionValue::Custom(v) => Some(v.to_string()),
            _ => None,
        }
    }
}

/// Why an [`OptionType`] string conversion failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionConversionError {
    /// The string is not a valid number for the option type -- Java's `NumberFormatException`.
    InvalidNumber {
        /// The type being converted to.
        option_type: OptionType,
        /// The rejected input.
        input: String,
    },
    /// The value is not an instance of the class the type's adapter casts to -- Java's
    /// `ClassCastException`.
    TypeMismatch {
        /// The type whose adapter was used.
        option_type: OptionType,
        /// The type of the value that was supplied.
        actual: OptionType,
    },
    /// The type's Java adapter delegates to a class that has no Rust port yet
    /// (`SaveState`, `java.awt.Color`, `java.awt.Font`, `KeyStroke`, `ActionTrigger`), so the
    /// conversion cannot be performed faithfully.
    UnportedValueClass {
        /// The type whose adapter was used.
        option_type: OptionType,
        /// The Java class the adapter depends on.
        java_class: &'static str,
    },
}

impl fmt::Display for OptionConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionConversionError::InvalidNumber { option_type, input } => {
                write!(f, "For input string: \"{input}\" ({})", option_type.name())
            }
            OptionConversionError::TypeMismatch {
                option_type,
                actual,
            } => write!(
                f,
                "{} value cannot be converted by {}",
                actual.name(),
                option_type.name()
            ),
            OptionConversionError::UnportedValueClass {
                option_type,
                java_class,
            } => write!(
                f,
                "{} conversion requires {java_class}, which is not ported",
                option_type.name()
            ),
        }
    }
}

impl std::error::Error for OptionConversionError {}

impl OptionType {
    /// All constants in Java declaration order, mirroring `OptionType.values()`.
    pub const fn values() -> &'static [OptionType] {
        &[
            OptionType::IntType,
            OptionType::LongType,
            OptionType::StringType,
            OptionType::DoubleType,
            OptionType::BooleanType,
            OptionType::DateType,
            OptionType::NoType,
            OptionType::FloatType,
            OptionType::EnumType,
            OptionType::CustomType,
            OptionType::ByteArrayType,
            OptionType::FileType,
            OptionType::ColorType,
            OptionType::FontType,
            OptionType::KeystrokeType,
            OptionType::ActionTrigger,
        ]
    }

    /// The Java constant name, mirroring `Enum.name()`.
    pub const fn name(self) -> &'static str {
        match self {
            OptionType::IntType => "INT_TYPE",
            OptionType::LongType => "LONG_TYPE",
            OptionType::StringType => "STRING_TYPE",
            OptionType::DoubleType => "DOUBLE_TYPE",
            OptionType::BooleanType => "BOOLEAN_TYPE",
            OptionType::DateType => "DATE_TYPE",
            OptionType::NoType => "NO_TYPE",
            OptionType::FloatType => "FLOAT_TYPE",
            OptionType::EnumType => "ENUM_TYPE",
            OptionType::CustomType => "CUSTOM_TYPE",
            OptionType::ByteArrayType => "BYTE_ARRAY_TYPE",
            OptionType::FileType => "FILE_TYPE",
            OptionType::ColorType => "COLOR_TYPE",
            OptionType::FontType => "FONT_TYPE",
            OptionType::KeystrokeType => "KEYSTROKE_TYPE",
            OptionType::ActionTrigger => "ACTION_TRIGGER",
        }
    }

    /// Looks a constant up by its Java name, mirroring `OptionType.valueOf(String)`.
    pub fn value_of(name: &str) -> Option<OptionType> {
        Self::values().iter().copied().find(|t| t.name() == name)
    }

    /// The fully-qualified name of the Java class values of this type are instances of,
    /// mirroring `getValueClass()`. `None` for [`OptionType::NoType`], whose Java class is `null`.
    pub const fn value_class_name(self) -> Option<&'static str> {
        match self {
            OptionType::IntType => Some("java.lang.Integer"),
            OptionType::LongType => Some("java.lang.Long"),
            OptionType::StringType => Some("java.lang.String"),
            OptionType::DoubleType => Some("java.lang.Double"),
            OptionType::BooleanType => Some("java.lang.Boolean"),
            OptionType::DateType => Some("java.util.Date"),
            OptionType::NoType => None,
            OptionType::FloatType => Some("java.lang.Float"),
            OptionType::EnumType => Some("java.lang.Enum"),
            OptionType::CustomType => Some("ghidra.framework.options.CustomOption"),
            OptionType::ByteArrayType => Some("[B"),
            OptionType::FileType => Some("java.io.File"),
            OptionType::ColorType => Some("java.awt.Color"),
            OptionType::FontType => Some("java.awt.Font"),
            OptionType::KeystrokeType => Some("javax.swing.KeyStroke"),
            OptionType::ActionTrigger => Some("ghidra.framework.options.ActionTrigger"),
        }
    }

    /// Returns the type of the given value, mirroring `OptionType.getOptionType(Object)`:
    /// [`OptionType::NoType`] for `None`.
    pub fn get_option_type(value: Option<&OptionValue>) -> OptionType {
        value.map_or(OptionType::NoType, OptionValue::option_type)
    }

    /// Returns true if the given value is of the correct type for this option type, mirroring
    /// `isCompatible(Object)`. `None` (Java's `null`) is compatible with every type.
    ///
    /// Java dereferences [`OptionType::NoType`]'s `null` value class for a non-null value; here
    /// no value is an instance of that non-existent class, so the answer is `false`.
    pub fn is_compatible(self, value: Option<&OptionValue>) -> bool {
        match value {
            None => true,
            Some(value) => value.option_type() == self,
        }
    }

    /// Converts a persisted string to a value of this type, mirroring
    /// `convertStringToObject(String)`. `None` input yields `Ok(None)`, as Java returns `null`.
    pub fn convert_string_to_object(
        self,
        string: Option<&str>,
    ) -> Result<Option<OptionValue>, OptionConversionError> {
        let Some(string) = string else {
            return Ok(None);
        };
        let invalid = || OptionConversionError::InvalidNumber {
            option_type: self,
            input: string.to_string(),
        };
        let value = match self {
            OptionType::IntType => OptionValue::Int(string.parse().map_err(|_| invalid())?),
            OptionType::LongType => OptionValue::Long(string.parse().map_err(|_| invalid())?),
            OptionType::StringType => OptionValue::String(string.to_string()),
            OptionType::DoubleType => {
                OptionValue::Double(java_parse_double(string).ok_or_else(invalid)?)
            }
            OptionType::BooleanType => OptionValue::Boolean(string.eq_ignore_ascii_case("true")),
            OptionType::DateType => {
                let millis: i64 = string.parse().map_err(|_| invalid())?;
                OptionValue::Date(date_from_millis(millis))
            }
            OptionType::NoType => return Ok(None),
            OptionType::FloatType => {
                OptionValue::Float(java_parse_double(string).ok_or_else(invalid)? as f32)
            }
            OptionType::FileType => OptionValue::File(PathBuf::from(string)),
            OptionType::EnumType
            | OptionType::CustomType
            | OptionType::ByteArrayType
            | OptionType::ColorType
            | OptionType::FontType
            | OptionType::KeystrokeType
            | OptionType::ActionTrigger => return Err(self.unported()),
        };
        Ok(Some(value))
    }

    /// Converts a value of this type to its persisted string form, mirroring
    /// `convertObjectToString(Object)`. `None` input yields `Ok(None)`, as Java returns `null`.
    ///
    /// Types whose Java adapter does not override `objectToString` use the value's `toString()`
    /// whatever its class, so e.g. `INT_TYPE` converts a string value unchanged; the adapters that
    /// cast (`DATE_TYPE`, `FILE_TYPE`) fail with [`OptionConversionError::TypeMismatch`].
    pub fn convert_object_to_string(
        self,
        object: Option<&OptionValue>,
    ) -> Result<Option<String>, OptionConversionError> {
        let Some(object) = object else {
            return Ok(None);
        };
        let mismatch = || OptionConversionError::TypeMismatch {
            option_type: self,
            actual: object.option_type(),
        };
        let string = match self {
            OptionType::DateType => match object {
                OptionValue::Date(date) => date_to_millis(*date).to_string(),
                _ => return Err(mismatch()),
            },
            OptionType::FileType => match object {
                OptionValue::File(path) => std::path::absolute(path)
                    .unwrap_or_else(|_| path.clone())
                    .to_string_lossy()
                    .into_owned(),
                _ => return Err(mismatch()),
            },
            OptionType::IntType
            | OptionType::LongType
            | OptionType::StringType
            | OptionType::DoubleType
            | OptionType::BooleanType
            | OptionType::NoType
            | OptionType::FloatType => object.java_to_string().ok_or_else(mismatch)?,
            OptionType::EnumType
            | OptionType::CustomType
            | OptionType::ByteArrayType
            | OptionType::ColorType
            | OptionType::FontType
            | OptionType::KeystrokeType
            | OptionType::ActionTrigger => return Err(self.unported()),
        };
        Ok(Some(string))
    }

    fn unported(self) -> OptionConversionError {
        let java_class = match self {
            OptionType::EnumType | OptionType::CustomType | OptionType::ByteArrayType => {
                "ghidra.framework.options.SaveState"
            }
            OptionType::ColorType => "java.awt.Color",
            OptionType::FontType => "java.awt.Font",
            OptionType::KeystrokeType => "javax.swing.KeyStroke",
            _ => "ghidra.framework.options.ActionTrigger",
        };
        OptionConversionError::UnportedValueClass {
            option_type: self,
            java_class,
        }
    }
}

impl fmt::Display for OptionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// `new Date(millis)`.
fn date_from_millis(millis: i64) -> SystemTime {
    if millis >= 0 {
        UNIX_EPOCH + Duration::from_millis(millis as u64)
    } else {
        UNIX_EPOCH - Duration::from_millis(millis.unsigned_abs())
    }
}

/// `Date.getTime()`: whole milliseconds since the epoch, rounded toward negative infinity.
fn date_to_millis(date: SystemTime) -> i64 {
    match date.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_millis() as i64,
        Err(before) => {
            let before = before.duration();
            let whole = before.as_millis() as i64;
            let partial = before.as_nanos() % 1_000_000 != 0;
            -whole - i64::from(partial)
        }
    }
}

/// `Double.valueOf(String)` for decimal input: surrounding whitespace (chars `<= ' '`) is ignored,
/// a trailing `f`/`F`/`d`/`D` type suffix is allowed, and the only accepted non-numeric forms are
/// `NaN` and `[+-]Infinity`. Hexadecimal floating-point literals are not accepted.
fn java_parse_double(input: &str) -> Option<f64> {
    let s = input.trim_matches(|c: char| c <= ' ');
    let unsigned = s.strip_prefix(['+', '-']).unwrap_or(s);
    match unsigned {
        "NaN" => return Some(f64::NAN),
        "Infinity" => {
            return Some(if s.starts_with('-') {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            });
        }
        _ => {}
    }
    let body = s.strip_suffix(['f', 'F', 'd', 'D']).unwrap_or(s);
    let digits = body.strip_prefix(['+', '-']).unwrap_or(body);
    // Rust also accepts "inf"/"nan" spellings and a second sign; Java does not.
    if !digits.starts_with(|c: char| c.is_ascii_digit() || c == '.') {
        return None;
    }
    body.parse().ok()
}

/// `Double.toString(double)`.
fn java_double_to_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    java_fp_format(
        value == 0.0,
        value.is_sign_negative(),
        &format!("{:e}", value.abs()),
        {
            let a = value.abs();
            (1e-3..1e7).contains(&a)
        },
    )
}

/// `Float.toString(float)`.
fn java_float_to_string(value: f32) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    java_fp_format(
        value == 0.0,
        value.is_sign_negative(),
        &format!("{:e}", value.abs()),
        {
            let a = value.abs();
            (1e-3..1e7).contains(&a)
        },
    )
}

/// Lays out a shortest-representation digit string (Rust's `{:e}` of the magnitude) the way
/// Java's `Double.toString`/`Float.toString` do: plain notation with at least one fractional
/// digit for magnitudes in `[1e-3, 1e7)`, otherwise computerized scientific notation.
fn java_fp_format(is_zero: bool, negative: bool, sci: &str, plain: bool) -> String {
    let sign = if negative { "-" } else { "" };
    if is_zero {
        return format!("{sign}0.0");
    }
    let (mantissa, exponent) = sci.split_once('e').expect("{:e} always has an exponent");
    let exponent: i32 = exponent.parse().expect("{:e} exponent is an integer");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    if plain {
        if exponent >= 0 {
            let int_len = exponent as usize + 1;
            let (int_part, frac_part) = if digits.len() > int_len {
                (digits[..int_len].to_string(), digits[int_len..].to_string())
            } else {
                (format!("{digits:0<int_len$}"), "0".to_string())
            };
            format!("{sign}{int_part}.{frac_part}")
        } else {
            let zeros = "0".repeat((-exponent - 1) as usize);
            format!("{sign}0.{zeros}{digits}")
        }
    } else {
        let frac = if digits.len() > 1 { &digits[1..] } else { "0" };
        format!("{sign}{}.{frac}E{exponent}", &digits[..1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn to_obj(t: OptionType, s: &str) -> Option<OptionValue> {
        t.convert_string_to_object(Some(s)).unwrap()
    }

    fn to_str(t: OptionType, v: OptionValue) -> String {
        t.convert_object_to_string(Some(&v)).unwrap().unwrap()
    }

    #[test]
    fn values_are_in_java_declaration_order() {
        let names: Vec<_> = OptionType::values().iter().map(|t| t.name()).collect();
        assert_eq!(
            names,
            [
                "INT_TYPE",
                "LONG_TYPE",
                "STRING_TYPE",
                "DOUBLE_TYPE",
                "BOOLEAN_TYPE",
                "DATE_TYPE",
                "NO_TYPE",
                "FLOAT_TYPE",
                "ENUM_TYPE",
                "CUSTOM_TYPE",
                "BYTE_ARRAY_TYPE",
                "FILE_TYPE",
                "COLOR_TYPE",
                "FONT_TYPE",
                "KEYSTROKE_TYPE",
                "ACTION_TRIGGER",
            ]
        );
        for t in OptionType::values() {
            assert_eq!(OptionType::value_of(t.name()), Some(*t));
        }
        assert_eq!(OptionType::value_of("int_type"), None);
    }

    #[test]
    fn value_classes_match_java() {
        assert_eq!(
            OptionType::IntType.value_class_name(),
            Some("java.lang.Integer")
        );
        assert_eq!(
            OptionType::DateType.value_class_name(),
            Some("java.util.Date")
        );
        assert_eq!(OptionType::NoType.value_class_name(), None);
        assert_eq!(OptionType::ByteArrayType.value_class_name(), Some("[B"));
        assert_eq!(
            OptionType::CustomType.value_class_name(),
            Some("ghidra.framework.options.CustomOption")
        );
        for t in OptionType::values() {
            assert_eq!(t.value_class_name().is_none(), *t == OptionType::NoType);
        }
    }

    #[test]
    fn null_converts_to_null_for_every_type() {
        for t in OptionType::values() {
            assert!(t.convert_string_to_object(None).unwrap().is_none());
            assert!(t.convert_object_to_string(None).unwrap().is_none());
        }
    }

    #[test]
    fn int_and_long_round_trip() {
        assert!(matches!(
            to_obj(OptionType::IntType, "-42"),
            Some(OptionValue::Int(-42))
        ));
        assert!(matches!(
            to_obj(OptionType::IntType, "+7"),
            Some(OptionValue::Int(7))
        ));
        assert_eq!(
            to_str(OptionType::IntType, OptionValue::Int(i32::MIN)),
            "-2147483648"
        );
        assert!(matches!(
            to_obj(OptionType::LongType, "9223372036854775807"),
            Some(OptionValue::Long(i64::MAX))
        ));
        assert_eq!(to_str(OptionType::LongType, OptionValue::Long(-5)), "-5");
    }

    #[test]
    fn number_format_errors_match_java() {
        for (t, s) in [
            (OptionType::IntType, "2147483648"),
            (OptionType::IntType, "0x10"),
            (OptionType::IntType, ""),
            (OptionType::LongType, "1.5"),
            (OptionType::DateType, "abc"),
            (OptionType::DoubleType, "inf"),
            (OptionType::DoubleType, "nan"),
            (OptionType::FloatType, "x"),
        ] {
            assert_eq!(
                t.convert_string_to_object(Some(s)).unwrap_err(),
                OptionConversionError::InvalidNumber {
                    option_type: t,
                    input: s.to_string()
                },
                "{t} {s:?}"
            );
        }
    }

    #[test]
    fn string_is_identity() {
        assert!(matches!(
            to_obj(OptionType::StringType, " a b "),
            Some(OptionValue::String(s)) if s == " a b "
        ));
        assert_eq!(
            to_str(OptionType::StringType, OptionValue::String("x".into())),
            "x"
        );
    }

    #[test]
    fn double_parsing_and_formatting_match_java() {
        let d = |s| match to_obj(OptionType::DoubleType, s) {
            Some(OptionValue::Double(v)) => v,
            other => panic!("{other:?}"),
        };
        assert_eq!(d("1.5"), 1.5);
        assert_eq!(d(" 2.5d "), 2.5);
        assert_eq!(d("1e3"), 1000.0);
        assert_eq!(d(".5"), 0.5);
        assert_eq!(d("-Infinity"), f64::NEG_INFINITY);
        assert!(d("NaN").is_nan());

        let s = |v| to_str(OptionType::DoubleType, OptionValue::Double(v));
        assert_eq!(s(1.0), "1.0");
        assert_eq!(s(-0.0), "-0.0");
        assert_eq!(s(0.1), "0.1");
        assert_eq!(s(100.0), "100.0");
        assert_eq!(s(123.456), "123.456");
        assert_eq!(s(0.001), "0.001");
        assert_eq!(s(0.0001), "1.0E-4");
        assert_eq!(s(1.0e7), "1.0E7");
        assert_eq!(s(9_999_999.0), "9999999.0");
        assert_eq!(s(1.2345e10), "1.2345E10");
        assert_eq!(s(f64::NAN), "NaN");
        assert_eq!(s(f64::INFINITY), "Infinity");
    }

    #[test]
    fn float_parsing_and_formatting_match_java() {
        assert!(
            matches!(to_obj(OptionType::FloatType, "0.1f"), Some(OptionValue::Float(v)) if v == 0.1f32)
        );
        let s = |v| to_str(OptionType::FloatType, OptionValue::Float(v));
        assert_eq!(s(0.1), "0.1");
        assert_eq!(s(3.0), "3.0");
        assert_eq!(s(1.0e-5), "1.0E-5");
        assert_eq!(s(1.5e8), "1.5E8");
    }

    #[test]
    fn boolean_matches_boolean_value_of() {
        for (s, b) in [
            ("true", true),
            ("TRUE", true),
            ("TrUe", true),
            ("false", false),
            ("yes", false),
            ("", false),
        ] {
            assert!(
                matches!(to_obj(OptionType::BooleanType, s), Some(OptionValue::Boolean(v)) if v == b),
                "{s}"
            );
        }
        assert_eq!(
            to_str(OptionType::BooleanType, OptionValue::Boolean(false)),
            "false"
        );
    }

    #[test]
    fn date_is_epoch_millis() {
        let Some(OptionValue::Date(date)) = to_obj(OptionType::DateType, "1234567890123") else {
            panic!()
        };
        assert_eq!(date, UNIX_EPOCH + Duration::from_millis(1_234_567_890_123));
        assert_eq!(
            to_str(OptionType::DateType, OptionValue::Date(date)),
            "1234567890123"
        );

        let Some(before) = to_obj(OptionType::DateType, "-1500") else {
            panic!()
        };
        assert_eq!(to_str(OptionType::DateType, before), "-1500");

        // Date.getTime() floors: 0.5 ms before the epoch is -1.
        let half = UNIX_EPOCH - Duration::from_micros(500);
        assert_eq!(to_str(OptionType::DateType, OptionValue::Date(half)), "-1");

        assert_eq!(
            OptionType::DateType
                .convert_object_to_string(Some(&OptionValue::Long(5)))
                .unwrap_err(),
            OptionConversionError::TypeMismatch {
                option_type: OptionType::DateType,
                actual: OptionType::LongType
            }
        );
    }

    #[test]
    fn no_type_converts_every_string_to_null() {
        assert!(to_obj(OptionType::NoType, "anything").is_none());
        // Base StringAdapter.objectToString is toString().
        assert_eq!(to_str(OptionType::NoType, OptionValue::Int(3)), "3");
    }

    #[test]
    fn default_adapters_use_to_string_on_any_value() {
        // INT_TYPE's adapter does not cast: Java returns object.toString().
        assert_eq!(
            to_str(OptionType::IntType, OptionValue::String("abc".into())),
            "abc"
        );
        assert_eq!(
            to_str(OptionType::StringType, OptionValue::Double(2.0)),
            "2.0"
        );
    }

    #[test]
    fn file_uses_absolute_path() {
        let Some(OptionValue::File(p)) = to_obj(OptionType::FileType, "rel/x.txt") else {
            panic!()
        };
        assert_eq!(p, Path::new("rel/x.txt"));
        let abs = to_str(OptionType::FileType, OptionValue::File(p));
        assert!(Path::new(&abs).is_absolute());
        assert!(abs.ends_with("rel/x.txt"));
        assert_eq!(
            to_str(
                OptionType::FileType,
                OptionValue::File(PathBuf::from("/a/b"))
            ),
            "/a/b"
        );
        assert!(matches!(
            OptionType::FileType.convert_object_to_string(Some(&OptionValue::Int(1))),
            Err(OptionConversionError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn get_option_type_and_is_compatible() {
        assert_eq!(OptionType::get_option_type(None), OptionType::NoType);
        let cases = [
            (OptionValue::Int(1), OptionType::IntType),
            (OptionValue::Long(1), OptionType::LongType),
            (OptionValue::String(String::new()), OptionType::StringType),
            (OptionValue::Double(1.0), OptionType::DoubleType),
            (OptionValue::Boolean(true), OptionType::BooleanType),
            (OptionValue::Date(UNIX_EPOCH), OptionType::DateType),
            (OptionValue::Float(1.0), OptionType::FloatType),
            (
                OptionValue::Enum(EnumOptionValue {
                    class_name: "a.B".into(),
                    name: "C".into(),
                }),
                OptionType::EnumType,
            ),
            (OptionValue::ByteArray(vec![1]), OptionType::ByteArrayType),
            (OptionValue::File(PathBuf::from("f")), OptionType::FileType),
        ];
        for (value, t) in &cases {
            assert_eq!(OptionType::get_option_type(Some(value)), *t);
            assert!(t.is_compatible(Some(value)));
            assert!(t.is_compatible(None));
            assert!(!OptionType::NoType.is_compatible(Some(value)));
        }
        assert!(!OptionType::StringType.is_compatible(Some(&OptionValue::Int(0))));
        assert!(!OptionType::LongType.is_compatible(Some(&OptionValue::Int(0))));
        assert!(OptionType::NoType.is_compatible(None));
    }

    #[test]
    fn adapters_backed_by_unported_classes_report_it() {
        for (t, class) in [
            (OptionType::EnumType, "ghidra.framework.options.SaveState"),
            (OptionType::CustomType, "ghidra.framework.options.SaveState"),
            (
                OptionType::ByteArrayType,
                "ghidra.framework.options.SaveState",
            ),
            (OptionType::ColorType, "java.awt.Color"),
            (OptionType::FontType, "java.awt.Font"),
            (OptionType::KeystrokeType, "javax.swing.KeyStroke"),
            (
                OptionType::ActionTrigger,
                "ghidra.framework.options.ActionTrigger",
            ),
        ] {
            let expected = OptionConversionError::UnportedValueClass {
                option_type: t,
                java_class: class,
            };
            assert_eq!(t.convert_string_to_object(Some("x")).unwrap_err(), expected);
            assert_eq!(
                t.convert_object_to_string(Some(&OptionValue::ByteArray(vec![])))
                    .unwrap_err(),
                expected
            );
        }
    }
}
