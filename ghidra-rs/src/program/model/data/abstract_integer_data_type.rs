//! Port of `ghidra.program.model.data.AbstractIntegerDataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn implements ArrayStringable`. `BuiltIn` itself is not yet
//! ported, so -- mirroring [`AbstractFloatDataType`](super::abstract_float_data_type::AbstractFloatDataType)
//! and [`AbstractStringDataType`](super::abstract_string_data_type::AbstractStringDataType) --
//! this trait extends [`DataType`] + [`BuiltInDataType`] + [`ArrayStringable`] directly, the
//! already-ported interfaces `BuiltIn`/`ArrayStringable` that `AbstractIntegerDataType` actually
//! relies on.
//!
//! Several Java methods here share a name with an already-provided method on [`DataType`]
//! (`getMnemonic`, `getDefaultLabelPrefix`, `getValue`, `isEncodable`, `encodeValue`,
//! `getRepresentation`, `encodeRepresentation`, `getValueClass`, `isEquivalent`) or with a
//! *required* (no-default) method on [`ArrayStringable`] (`hasStringValue`,
//! `getArrayDefaultLabelPrefix`, `getArrayDefaultOffcutLabelPrefix`). Rust does not allow a
//! subtrait to override (or default) a supertrait's method by redeclaring the same name -- it
//! would just create an ambiguous method for any type implementing both -- so, mirroring the
//! convention established by [`CharDataType`](super::char_data_type::CharDataType) and the other
//! `Abstract*DataType` traits, those overrides are exposed here under distinct `integer_*` names.
//! A concrete implementation (once `BuiltIn` and the various concrete integer data types --
//! `IntegerDataType`, `CharDataType`, `LongDataType`, etc. -- are ported) should implement
//! `DataType`/`BuiltInDataType`/`ArrayStringable` directly and delegate to these helpers.
//!
//! The Java class's constructor is not translated (traits cannot declare constructors or store
//! fields); implementors are expected to persist their own `name`/`DataTypeManager` state and
//! expose it via [`DataType::get_name`]/[`DataType::get_data_organization`], both of which the
//! default methods here rely on instead of private fields.
//!
//! `getValue`/`encodeValue`/`getValueClass` do not use `java.lang.Object`/`Class<?>` here: instead
//! of Java's runtime `instanceof`-driven acceptance of `BigInteger`, `Scalar`, `Character`,
//! `Byte`, `Short`, `Integer`, or `Long`, [`IntegerValue`] and [`IntegerEncodeValue`] enumerate the
//! same set of accepted shapes directly (mirroring how
//! [`AbstractFloatDataType::encode_float_value`] replaces `Object value` with
//! [`FloatEncodeValue`](super::abstract_float_data_type::FloatEncodeValue)). Since
//! [`Scalar`](crate::program::model::scalar::Scalar) is itself a plain, already-ported struct
//! (not a cycle cut-point), it is used directly rather than through a placeholder.
//!
//! `isEquivalent(DataType)` (renamed [`integer_is_equivalent`](AbstractIntegerDataType::integer_is_equivalent))
//! compares `dt.getClass().equals(getClass())` in Java, which has no Rust equivalent without full
//! reflection. This port approximates "same concrete integer data type" using
//! [`DataType::is_integer_type`]/[`DataType::is_signed_integer_type`] (added to [`DataType`]
//! specifically so that a concrete `AbstractIntegerDataType` implementor's overrides of those two
//! methods double as the RTTI this comparison needs) plus a name match.
//!
//! Two static factory method pairs are omitted entirely, mirroring the precedent set by
//! [`AbstractFloatDataType`]'s own `getFloatDataType`/`getFloatDataTypes`: `getSignedDataType`/
//! `getSignedDataTypes` and `getUnsignedDataType`/`getUnsignedDataTypes` (plus their private
//! `getSignedTypes`/`getUnsignedTypes` helpers) all build a registry keyed off concrete sibling
//! singletons (`SignedByteDataType.dataType`, `WordDataType.dataType`, `Integer16DataType.dataType`,
//! etc.) that are not yet ported and are unrelated to breaking this cycle, so no placeholder is
//! created for them; port them alongside those concrete types instead.
//!
//! The CHAR-format branches of `getRepresentation`/`encodeRepresentation` (rendering/parsing this
//! integer's bytes as a character instead of a number) are also simplified away:
//! [`string_data_instance`](super::string_data_instance)'s module docs already note that the
//! static `StringDataInstance.getCharRepresentation(DataType, byte[], Settings)` factory those
//! branches need is not ported ("needs `BitFieldDataType`-aware charset/size derivation from a
//! bare `DataType`"). [`integer_representation`](AbstractIntegerDataType::integer_representation)
//! always falls through to the standard numeric rendering, and
//! [`integer_encode_representation`](AbstractIntegerDataType::integer_encode_representation)
//! returns an error for CHAR-format input. The *array* label helpers
//! (`getArrayDefaultLabelPrefix`/`getArrayDefaultOffcutLabelPrefix`, which render this integer's
//! bytes as a char-array label rather than a single char) are still fully ported, via a small
//! internal [`StringDataInstance`] view ([`build_char_view`](AbstractIntegerDataType::build_char_view))
//! built the same way [`AbstractStringDataType::get_string_data_instance`] builds its own view --
//! including that method's same caveat about the returned box borrowing `buf` (`'a`) rather than
//! being `'static`, so a concrete `impl ArrayStringable for ...` cannot delegate
//! `string_data_instance` straight to it (see that method's docs).
//!
//! `Utils.bigIntegerToBytes`/`DataConverter` (Java) are replaced by
//! [`crate::pcode::utils::utils`]'s `bytes_to_long`/`long_to_bytes`/`bytes_to_big_integer`/
//! `big_integer_to_bytes` (the same helpers [`AbstractFloatDataType`] uses), which represent
//! `BigInteger` as `i128`. As with every other use of that representation in this crate, integer
//! lengths whose magnitude cannot fit in an `i128` (i.e. 16-byte *unsigned* values near or above
//! `2^127`) are not perfectly representable; [`encode_bounds`] and [`pow2_i128`] saturate rather
//! than panic in that case instead of silently wrapping.

use std::any::TypeId;
use std::fmt;

use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::format_settings_definition::{self, FormatSettingsDefinition};
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::pcode::utils::utils::{big_integer_to_bytes, bytes_to_big_integer, bytes_to_long};
use crate::program::model::data::abstract_string_data_type::{
    charset_char_size, DEFAULT_ABBREV_PREFIX, DEFAULT_LABEL, DEFAULT_LABEL_PREFIX,
};
use crate::program::model::data::array_stringable::ArrayStringable;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_encode_exception::DataTypeEncodeException;
use crate::program::model::data::data_type_mnemonic_settings_definition::{
    self, DataTypeMnemonicSettingsDefinition,
};
use crate::program::model::data::endian_settings_definition::{self, EndianSettingsDefinition};
use crate::program::model::data::padding_settings_definition::PaddingSettingsDefinition;
use crate::program::model::data::string_data_instance::{StringDataInstance, DEFAULT_CHARSET_NAME};
use crate::program::model::lang::endian::Endian;
use crate::program::model::scalar::Scalar;
use crate::program::seam_stubs::{CharsetSettingsDefinition};
use crate::program::model::mem::MemBuffer;
use crate::util::StringFormat;

/// Package-private `AbstractIntegerDataType.C_SIGNED_CHAR`.
pub const C_SIGNED_CHAR: &str = "signed char";
/// Package-private `AbstractIntegerDataType.C_UNSIGNED_CHAR`.
pub const C_UNSIGNED_CHAR: &str = "unsigned char";
/// Package-private `AbstractIntegerDataType.C_SIGNED_SHORT`.
pub const C_SIGNED_SHORT: &str = "short";
/// Package-private `AbstractIntegerDataType.C_UNSIGNED_SHORT`.
pub const C_UNSIGNED_SHORT: &str = "unsigned short";
/// Package-private `AbstractIntegerDataType.C_SIGNED_INT`.
pub const C_SIGNED_INT: &str = "int";
/// Package-private `AbstractIntegerDataType.C_UNSIGNED_INT`.
pub const C_UNSIGNED_INT: &str = "unsigned int";
/// Package-private `AbstractIntegerDataType.C_SIGNED_LONG`.
pub const C_SIGNED_LONG: &str = "long";
/// Package-private `AbstractIntegerDataType.C_UNSIGNED_LONG`.
pub const C_UNSIGNED_LONG: &str = "unsigned long";
/// Package-private `AbstractIntegerDataType.C_SIGNED_LONGLONG`.
pub const C_SIGNED_LONGLONG: &str = "long long";
/// Package-private `AbstractIntegerDataType.C_UNSIGNED_LONGLONG`.
pub const C_UNSIGNED_LONGLONG: &str = "unsigned long long";

/// Value returned by [`AbstractIntegerDataType::integer_value`], standing in for the `Object`
/// (`Scalar` or `BigInteger`) returned by `AbstractIntegerDataType.getValue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerValue {
    /// Used when this data-type's length is 8 bytes or fewer.
    Scalar(Scalar),
    /// Used when this data-type's length exceeds 8 bytes, represented as an `i128` in place of
    /// Java's arbitrary-precision `BigInteger` (see the module docs).
    Big(i128),
}

/// Value accepted by [`AbstractIntegerDataType::integer_encode_value`], standing in for the
/// `Object value` parameter of `AbstractIntegerDataType.encodeValue`/`castValueToEncode`,
/// documented in the Java source as accepting a `BigInteger`, `Scalar`, `Character`, `Byte`,
/// `Short`, `Integer`, or `Long`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerEncodeValue {
    /// Stands in for a `BigInteger` value.
    BigInt(i128),
    /// Stands in for a `Scalar` value; its own signedness (not this data-type's) is used.
    Scalar(Scalar),
    /// Stands in for a `Character` value, interpreted via `Character.getNumericValue` (i.e. as a
    /// base-36 digit, matching `'0'..='9'`/`'a'..='z'`/`'A'..='Z'`) rather than as a code point.
    Char(char),
    /// Stands in for a `Byte` value.
    I8(i8),
    /// Stands in for a `Short` value.
    I16(i16),
    /// Stands in for an `Integer` value.
    I32(i32),
    /// Stands in for a `Long` value.
    I64(i64),
}

impl fmt::Display for IntegerEncodeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntegerEncodeValue::BigInt(v) => write!(f, "{v}"),
            IntegerEncodeValue::Scalar(s) => write!(f, "{s}"),
            IntegerEncodeValue::Char(c) => write!(f, "{c}"),
            IntegerEncodeValue::I8(v) => write!(f, "{v}"),
            IntegerEncodeValue::I16(v) => write!(f, "{v}"),
            IntegerEncodeValue::I32(v) => write!(f, "{v}"),
            IntegerEncodeValue::I64(v) => write!(f, "{v}"),
        }
    }
}

/// Computes `2^bits` as an `i128`, saturating to `i128::MAX` rather than panicking/wrapping once
/// `bits` would overflow `i128`'s 127-bit positive range. See the module docs' note on the
/// `i128`-as-`BigInteger` representation's limits.
fn pow2_i128(bits: u32) -> i128 {
    if bits >= 127 {
        i128::MAX
    } else {
        1i128 << bits
    }
}

/// Computes `(min_value_inclusive, max_value_exclusive)` for a `length`-byte integer of the given
/// signedness, standing in for the two `BigInteger` bounds `AbstractIntegerDataType.encodeValue`
/// computes inline. `max_value_exclusive` is `None` when it cannot be represented as an `i128`
/// (only possible for unsigned lengths of 16 bytes), meaning "no representable value can reach
/// this bound".
fn encode_bounds(length: i32, signed: bool) -> (i128, Option<i128>) {
    let bits = (length * 8) as u32;
    let min_inclusive = if !signed || bits == 0 {
        0
    } else if bits - 1 >= 127 {
        i128::MIN
    } else {
        -(1i128 << (bits - 1))
    };
    let max_bits = if signed { bits.saturating_sub(1) } else { bits };
    let max_exclusive = if max_bits >= 127 { None } else { Some(1i128 << max_bits) };
    (min_inclusive, max_exclusive)
}

/// Resolves the endianness to use for a byte<->value conversion, standing in for
/// `ENDIAN.isBigEndian(settings, buf)`. [`EndianSettingsDefinition::is_big_endian`] takes a
/// different `MemBuffer` placeholder (`crate::program::model::lang::sleigh::walker::MemBuffer`)
/// than the one this trait's methods use (`crate::program::model::mem::MemBuffer`), so -- mirroring
/// [`AbstractStringDataType::get_string_data_instance`]'s identical workaround -- this reads the
/// raw enum choice via [`EnumSettingsDefinition::get_choice`] and falls back to the buffer's own
/// endianness exactly as [`EndianSettingsDefinition::is_big_endian`] would.
fn resolve_big_endian(settings: &dyn Settings, buf: &dyn MemBuffer) -> bool {
    match EndianSettingsDefinition::DEF.get_choice(settings) {
        endian_settings_definition::BIG => true,
        endian_settings_definition::LITTLE => false,
        _ => buf.is_big_endian(),
    }
}

/// Port of the package-private `AbstractIntegerDataType.getRepresentation(BigInteger, Settings,
/// int, boolean)`, used by [`AbstractIntegerDataType::integer_representation`]. Always reads the
/// format via the literal [`FormatSettingsDefinition::DEF_HEX`] (not a per-instance override),
/// exactly matching the Java source.
fn format_integer_representation(mut big_int: i128, settings: &dyn Settings, bit_length: i32, is_signed: bool) -> String {
    let padded = PaddingSettingsDefinition::DEF.is_padded(Some(settings));
    let negative = big_int < 0;
    let format = FormatSettingsDefinition::DEF_HEX.get_choice(settings);
    if negative && (!is_signed || format != format_settings_definition::DECIMAL) {
        big_int += pow2_i128(bit_length.max(0) as u32);
    }
    let (val_str, nominal_len) = match format {
        format_settings_definition::DECIMAL => return big_int.to_string(),
        format_settings_definition::BINARY => (format!("{big_int:b}b"), bit_length),
        format_settings_definition::OCTAL => (format!("{big_int:o}o"), (bit_length + 2) / 3),
        _ => (format!("{big_int:X}h"), (bit_length + 3) / 4),
    };
    if padded {
        StringFormat::pad_it(&val_str, (nominal_len + 1).max(0) as usize, '\0', true)
    } else {
        val_str
    }
}

/// A minimal [`StringDataInstance`] view over this integer's raw bytes treated as a fixed-length
/// char array, standing in for `new StringDataInstance(this, settings, buf, len, true)`. See the
/// module docs and [`AbstractIntegerDataType::build_char_view`].
struct IntegerCharView<'a> {
    charset_name: String,
    char_size: i32,
    length: i32,
    buf: &'a dyn MemBuffer,
    endian_setting: Option<Endian>,
}

impl StringDataInstance for IntegerCharView<'_> {
    fn encode_replacement_from_char_value(&self, _value: &[char]) -> Result<Vec<u8>, String> {
        Err("AbstractIntegerDataType's char-array view does not support encoding".to_string())
    }

    fn encode_replacement_from_char_representation(&self, _repr: &str) -> Result<Vec<u8>, String> {
        Err("AbstractIntegerDataType's char-array view does not support encoding".to_string())
    }

    fn charset_name(&self) -> String {
        self.charset_name.clone()
    }

    fn char_size(&self) -> i32 {
        self.char_size
    }

    fn padded_char_size(&self) -> i32 {
        self.char_size
    }

    fn data_length(&self) -> i32 {
        self.length
    }

    fn mem_buffer(&self) -> Option<&dyn MemBuffer> {
        Some(self.buf)
    }

    fn endian_setting(&self) -> Option<Endian> {
        self.endian_setting
    }
}

/// Base type for integer data types such as chars, ints, and longs.
///
/// Port of `ghidra.program.model.data.AbstractIntegerDataType`. See the module-level
/// documentation for the conventions used to resolve name clashes with
/// [`DataType`]/[`ArrayStringable`] and for what was intentionally simplified or left unported.
pub trait AbstractIntegerDataType: DataType + BuiltInDataType + ArrayStringable {
    /// Determine if this type is signed.
    ///
    /// Port of the abstract `AbstractIntegerDataType.isSigned()`.
    fn is_signed(&self) -> bool;

    /// Returns the data-type with the opposite signedness from this data-type. For example, this
    /// method on an `IntegerDataType`-equivalent implementor would return an instance of the
    /// `UnsignedIntegerDataType`-equivalent type.
    ///
    /// Port of the abstract `AbstractIntegerDataType.getOppositeSignednessDataType()`.
    fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType>;

    /// Return the Format settings definition included in the settings definition array.
    ///
    /// Port of the protected `AbstractIntegerDataType.getFormatSettingsDefinition()`.
    fn get_format_settings_definition(&self) -> FormatSettingsDefinition {
        FormatSettingsDefinition::DEF_HEX
    }

    /// Port of the protected `AbstractIntegerDataType.getBuiltInSettingsDefinitions()`. Always
    /// `[FormatSettingsDefinition.DEF_HEX, PADDING, ENDIAN, MNEMONIC]`, using the literal
    /// `DEF_HEX` rather than [`get_format_settings_definition`](Self::get_format_settings_definition),
    /// exactly matching the Java source's `SETTINGS_DEFS` constant.
    fn get_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        vec![
            Box::new(FormatSettingsDefinition::DEF_HEX),
            Box::new(PaddingSettingsDefinition::DEF),
            Box::new(EndianSettingsDefinition::DEF),
            Box::new(DataTypeMnemonicSettingsDefinition::DEF),
        ]
    }

    /// Port of `AbstractIntegerDataType.getDefaultLabelPrefix()`, exposed under a distinct name
    /// since [`DataType::get_default_label_prefix`] already provides a default. A concrete `impl
    /// DataType for ...` should delegate `get_default_label_prefix` to this.
    fn integer_default_label_prefix(&self) -> String {
        self.get_name().to_uppercase()
    }

    /// Port of `AbstractIntegerDataType.getMnemonic(Settings)`, exposed under a distinct name
    /// since [`DataType::get_mnemonic`] already provides a default. A concrete `impl DataType for
    /// ...` should delegate `get_mnemonic` to this.
    fn integer_mnemonic(&self, settings: &dyn Settings) -> String {
        let style = DataTypeMnemonicSettingsDefinition::DEF.get_mnemonic_style(Some(settings));
        if style == data_type_mnemonic_settings_definition::ASSEMBLY {
            self.get_assembly_mnemonic()
        } else if style == data_type_mnemonic_settings_definition::CSPEC {
            self.get_c_mnemonic()
        } else {
            self.get_name()
        }
    }

    /// The Assembly style data-type declaration for this data-type.
    ///
    /// Port of `AbstractIntegerDataType.getAssemblyMnemonic()`.
    fn get_assembly_mnemonic(&self) -> String {
        self.get_name()
    }

    /// The C style data-type mnemonic for this data-type.
    ///
    /// Port of `AbstractIntegerDataType.getCMnemonic()`.
    fn get_c_mnemonic(&self) -> String {
        self.get_c_declaration().unwrap_or_else(|| self.get_name())
    }

    /// The C style data-type declaration for this data-type, or `None` if no appropriate
    /// declaration exists.
    ///
    /// Port of `AbstractIntegerDataType.getCDeclaration()`.
    fn get_c_declaration(&self) -> Option<String> {
        let size = self.get_length();
        if size <= 0 {
            return None;
        }
        let signed = self.is_signed();
        let data_organization = self.get_data_organization();
        if size == data_organization.get_char_size() {
            return Some(if signed { C_SIGNED_CHAR } else { C_UNSIGNED_CHAR }.to_string());
        }
        if size == data_organization.get_integer_size() {
            return Some(if signed { C_SIGNED_INT } else { C_UNSIGNED_INT }.to_string());
        }
        if size == data_organization.get_short_size() {
            return Some(if signed { C_SIGNED_SHORT } else { C_UNSIGNED_SHORT }.to_string());
        }
        if size == data_organization.get_long_size() {
            return Some(if signed { C_SIGNED_LONG } else { C_UNSIGNED_LONG }.to_string());
        }
        if size == data_organization.get_long_long_size() {
            return Some(if signed { C_SIGNED_LONGLONG } else { C_UNSIGNED_LONGLONG }.to_string());
        }
        None
    }

    /// Port of `AbstractIntegerDataType.getValue(MemBuffer, Settings, int)`, exposed under a
    /// distinct name since [`DataType::get_value`] already provides a default with a different
    /// return type (`Option<Box<dyn Any>>` vs `Option<IntegerValue>`). The `length` parameter is
    /// ignored, matching the Java method (which always uses [`DataType::get_length`]). A concrete
    /// `impl DataType for ...` should delegate `get_value` to this.
    fn integer_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, _length: i32) -> Option<IntegerValue> {
        let size = self.get_length();
        if size <= 0 {
            return None;
        }
        let mut bytes = vec![0u8; size as usize];
        if buf.get_bytes_into(&mut bytes, 0) != size {
            return None;
        }
        let big_endian = resolve_big_endian(settings, buf);
        if size > 8 {
            let value = bytes_to_big_integer(&bytes, size as usize, big_endian, self.is_signed());
            Some(IntegerValue::Big(value))
        } else {
            let value = bytes_to_long(&bytes, size as usize, big_endian);
            Some(IntegerValue::Scalar(Scalar::new_with_signedness(size as u8 * 8, value, self.is_signed())))
        }
    }

    /// Port of `AbstractIntegerDataType.isEncodable()`, exposed under a distinct name since
    /// [`DataType::is_encodable`] already provides a default. Always `true`. A concrete `impl
    /// DataType for ...` should delegate `is_encodable` to this.
    fn is_integer_encodable(&self) -> bool {
        true
    }

    /// Port of the protected `AbstractIntegerDataType.castValueToEncode(Object)`.
    fn cast_value_to_encode(&self, value: &IntegerEncodeValue) -> Result<i128, DataTypeEncodeException> {
        match *value {
            IntegerEncodeValue::BigInt(v) => Ok(v),
            IntegerEncodeValue::Scalar(s) => Ok(s.get_big_integer()),
            IntegerEncodeValue::Char(c) => match c.to_digit(36) {
                Some(n) => Ok(n as i128),
                None => Err(DataTypeEncodeException::new(
                    "Character cannot be converted to number",
                    value,
                    self.get_name(),
                )),
            },
            IntegerEncodeValue::I8(n) => Ok(self.cast_fixed_width(n as i64, 8)),
            IntegerEncodeValue::I16(n) => Ok(self.cast_fixed_width(n as i64, 16)),
            IntegerEncodeValue::I32(n) => Ok(self.cast_fixed_width(n as i64, 32)),
            IntegerEncodeValue::I64(n) => Ok(self.cast_fixed_width(n, 64)),
        }
    }

    /// Port of the inline logic in `castValueToEncode` shared by the `Byte`/`Short`/`Integer`/
    /// `Long` branches (including the private `getBitCount(Class)` helper, folded in here since
    /// each caller already knows its own bit width statically).
    fn cast_fixed_width(&self, n: i64, bits: u32) -> i128 {
        let signed_val = n as i128;
        if self.is_signed() || signed_val >= 0 {
            signed_val
        } else {
            signed_val + pow2_i128(bits)
        }
    }

    /// Port of `AbstractIntegerDataType.encodeValue(Object, MemBuffer, Settings, int)`, exposed
    /// under a distinct name since [`DataType::encode_value`] already provides a default with a
    /// different `value` type (`&dyn Any` vs [`IntegerEncodeValue`]) and error type
    /// ([`DataTypeEncodeError`](crate::program::model::data::data_type_with_charset::DataTypeEncodeError)
    /// vs [`DataTypeEncodeException`]). A concrete `impl DataType for ...` should delegate
    /// `encode_value` to this.
    fn integer_encode_value(
        &self,
        value: &IntegerEncodeValue,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeException> {
        let length = if length == -1 { self.get_length() } else { length };
        if length != self.get_length() {
            return Err(DataTypeEncodeException::new("Length mismatch", value, self.get_name()));
        }
        let big_value = self.cast_value_to_encode(value)?;
        if big_value.is_negative() && !self.is_signed() {
            return Err(DataTypeEncodeException::new(
                "Unsigned type cannot have negative value",
                value,
                self.get_name(),
            ));
        }
        let (min_value_inclusive, max_value_exclusive) = encode_bounds(length, self.is_signed());
        if let Some(max_value_exclusive) = max_value_exclusive {
            if big_value >= max_value_exclusive {
                return Err(DataTypeEncodeException::new("Value is too large", big_value, self.get_name()));
            }
        }
        if min_value_inclusive > big_value {
            return Err(DataTypeEncodeException::new("Value is too small", big_value, self.get_name()));
        }
        let big_endian = resolve_big_endian(settings, buf);
        Ok(big_integer_to_bytes(big_value, length as usize, big_endian))
    }

    /// Port of `AbstractIntegerDataType.getValueClass(Settings)`, exposed under a distinct name
    /// since [`DataType::get_value_class`] already provides a default. Identifies
    /// [`Scalar`](crate::program::model::scalar::Scalar) when this data-type's length is 8 bytes
    /// or fewer, or `i128` (standing in for `BigInteger`) otherwise. A concrete `impl DataType for
    /// ...` should delegate `get_value_class` to this.
    fn integer_value_type_id(&self, _settings: &dyn Settings) -> TypeId {
        if self.get_length() > 8 {
            TypeId::of::<i128>()
        } else {
            TypeId::of::<Scalar>()
        }
    }

    /// Port of `AbstractIntegerDataType.getRepresentation(MemBuffer, Settings, int)`, exposed
    /// under a distinct name since [`DataType::get_representation`] already provides a default.
    /// See the module docs for the CHAR-format simplification. A concrete `impl DataType for ...`
    /// should delegate `get_representation` to this.
    fn integer_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let mut size = self.get_length();
        if size <= 0 {
            size = length;
            if size <= 0 {
                return "??".to_string();
            }
        }
        let mut bytes = vec![0u8; size as usize];
        if buf.get_bytes_into(&mut bytes, 0) != size {
            return "??".to_string();
        }
        let big_endian = resolve_big_endian(settings, buf);
        let value = bytes_to_big_integer(&bytes, size as usize, big_endian, true);
        format_integer_representation(value, settings, 8 * length, self.is_signed())
    }

    /// Port of `AbstractIntegerDataType.encodeRepresentation(String, MemBuffer, Settings, int)`,
    /// exposed under a distinct name since [`DataType::encode_representation`] already provides a
    /// default. See the module docs for the CHAR-format simplification (returns an error instead
    /// of decoding a character). A concrete `impl DataType for ...` should delegate
    /// `encode_representation` to this.
    fn integer_encode_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeException> {
        let format = self.get_format_settings_definition().get_format(Some(settings));
        let (radix, suffix) = match format {
            format_settings_definition::CHAR => {
                return Err(DataTypeEncodeException::new(
                    "CHAR format decoding is not supported by this port",
                    repr,
                    self.get_name(),
                ));
            }
            format_settings_definition::DECIMAL => (10u32, ""),
            format_settings_definition::BINARY => (2u32, "b"),
            format_settings_definition::OCTAL => (8u32, "o"),
            _ => (16u32, "h"),
        };
        let Some(digits) = repr.strip_suffix(suffix) else {
            return Err(DataTypeEncodeException::new(
                format!("value must have {suffix} suffix"),
                repr,
                self.get_name(),
            ));
        };
        let mut value = i128::from_str_radix(digits, radix)
            .map_err(|e| DataTypeEncodeException::with_cause_only(repr, self.get_name(), Box::new(e)))?;

        // Ghidra doesn't actually heed signedness unless the format is DECIMAL. Thus, for user
        // input, and to make this an inverse of getRepresentation, we'll adjust values between
        // SMAX and UMAX to ensure they get encoded as expected, rather than rejected. We'll still
        // accept signed values, though, since the user would rightly expect those to work, even
        // though it'll get echoed back in unsigned form.
        if format != format_settings_definition::DECIMAL && self.is_signed() {
            let umax = pow2_i128((8 * length) as u32);
            let smax = umax >> 1;
            if smax <= value && value < umax {
                value -= umax;
            }
        }
        self.integer_encode_value(&IntegerEncodeValue::BigInt(value), buf, settings, length)
    }

    /// Port of `AbstractIntegerDataType.hasStringValue(Settings)`, implementing the abstract
    /// [`ArrayStringable::has_string_value`] but exposed under a distinct name since that
    /// supertrait method has no default to override (see the module docs). A concrete `impl
    /// ArrayStringable for ...` should delegate `has_string_value` to this.
    fn integer_has_string_value(&self, settings: &dyn Settings) -> bool {
        self.get_format_settings_definition().get_format(Some(settings)) == format_settings_definition::CHAR
    }

    /// Builds the [`StringDataInstance`] view over this integer's raw bytes used by
    /// [`integer_array_default_label_prefix`](Self::integer_array_default_label_prefix)/
    /// [`integer_array_default_offcut_label_prefix`](Self::integer_array_default_offcut_label_prefix),
    /// standing in for `new StringDataInstance(this, settings, buf, len, true)`. Also usable to
    /// implement [`ArrayStringable::string_data_instance`], with the same caveat
    /// [`AbstractStringDataType::get_string_data_instance`] documents: the returned box borrows
    /// `buf`'s lifetime (`'a`) rather than being `'static`, so a concrete
    /// `impl ArrayStringable::string_data_instance` cannot delegate to this directly.
    fn build_char_view<'a>(&self, buf: &'a dyn MemBuffer, settings: &dyn Settings, len: i32) -> Box<dyn StringDataInstance + 'a> {
        let charset_name = CharsetSettingsDefinition::CHARSET.get_charset(settings, DEFAULT_CHARSET_NAME);
        let char_size = charset_char_size(&charset_name);
        let endian_setting = match EndianSettingsDefinition::DEF.get_choice(settings) {
            endian_settings_definition::BIG => Some(Endian::Big),
            endian_settings_definition::LITTLE => Some(Endian::Little),
            _ => None,
        };
        Box::new(IntegerCharView {
            charset_name,
            char_size,
            length: len,
            buf,
            endian_setting,
        })
    }

    /// Port of `AbstractIntegerDataType.getArrayDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`, implementing the abstract
    /// [`ArrayStringable::get_array_default_label_prefix`] but exposed under a distinct name since
    /// that supertrait method has no default to override (see the module docs). A concrete `impl
    /// ArrayStringable for ...` should delegate `get_array_default_label_prefix` to this.
    fn integer_array_default_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        if !self.integer_has_string_value(settings) || !buf.is_initialized_memory() {
            return None;
        }
        let abbrev_prefix = format!("{DEFAULT_ABBREV_PREFIX}_");
        Some(self.build_char_view(buf, settings, len).get_label(&abbrev_prefix, DEFAULT_LABEL_PREFIX, DEFAULT_LABEL, options))
    }

    /// Port of `AbstractIntegerDataType.getArrayDefaultOffcutLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions, int)`, implementing the abstract
    /// [`ArrayStringable::get_array_default_offcut_label_prefix`] but exposed under a distinct
    /// name since that supertrait method has no default to override (see the module docs). A
    /// concrete `impl ArrayStringable for ...` should delegate
    /// `get_array_default_offcut_label_prefix` to this.
    fn integer_array_default_offcut_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
        offcut_offset: i32,
    ) -> Option<String> {
        if !self.integer_has_string_value(settings) || !buf.is_initialized_memory() {
            return None;
        }
        let abbrev_prefix = format!("{DEFAULT_ABBREV_PREFIX}_");
        Some(
            self.build_char_view(buf, settings, len)
                .get_offcut_label_string(&abbrev_prefix, DEFAULT_LABEL_PREFIX, DEFAULT_LABEL, options, offcut_offset),
        )
    }

    /// Port of `AbstractIntegerDataType.isEquivalent(DataType)`, exposed under a distinct name
    /// since [`DataType::is_equivalent`] already provides a default. See the module docs for how
    /// this approximates Java's `getClass().equals(getClass())` comparison. A concrete `impl
    /// DataType for ...` should delegate `is_equivalent` to this.
    fn integer_is_equivalent(&self, dt: &dyn DataType) -> bool {
        dt.is_integer_type() && dt.is_signed_integer_type() == self.is_signed() && dt.get_name() == self.get_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type_display_options::DEFAULT;

    struct BytesBuffer {
        data: Vec<u8>,
        big_endian: bool,
    }

    impl MemBuffer for BytesBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }

        fn is_initialized_memory(&self) -> bool {
            true
        }

        fn get_bytes(&self, buffer: &mut [u8], offset: i32) -> usize {
            if offset < 0 {
                return 0;
            }
            let o = offset as usize;
            if o >= self.data.len() {
                return 0;
            }
            let n = buffer.len().min(self.data.len() - o);
            buffer[..n].copy_from_slice(&self.data[o..o + n]);
            n
        }

        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
    }

    struct NoSettings;
    impl Settings for NoSettings {}

    struct MockDataOrganization;
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            2
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            0
        }
        fn get_machine_alignment(&self) -> i32 {
            8
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(&self) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
            struct P;
            impl crate::program::model::data::bit_field_packing::BitFieldPacking for P {
                fn use_ms_convention(&self) -> bool {
                    false
                }
                fn is_type_alignment_enabled(&self) -> bool {
                    true
                }
                fn get_zero_length_boundary(&self) -> i32 {
                    0
                }
            }
            Box::new(P)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            "int".to_string()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    struct MockOppositeSignedness;
    impl DataType for MockOppositeSignedness {
        fn get_name(&self) -> String {
            "uint".to_string()
        }
    }
    impl BuiltInDataType for MockOppositeSignedness {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl ArrayStringable for MockOppositeSignedness {
        fn has_string_value(&self, _settings: &dyn Settings) -> bool {
            false
        }
        fn string_data_instance(&self, _buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> Box<dyn StringDataInstance> {
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_array_default_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
            _offcut_length: i32,
        ) -> Option<String> {
            None
        }
    }
    impl AbstractIntegerDataType for MockOppositeSignedness {
        fn is_signed(&self) -> bool {
            false
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    struct MockIntDataType {
        name: &'static str,
        length: i32,
        signed: bool,
    }

    impl DataType for MockIntDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
        fn get_default_label_prefix(&self) -> Option<String> {
            Some(self.integer_default_label_prefix())
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.integer_mnemonic(settings)
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_signed_integer_type(&self) -> bool {
            self.signed
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.integer_is_equivalent(dt)
        }
    }

    impl BuiltInDataType for MockIntDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl ArrayStringable for MockIntDataType {
        fn has_string_value(&self, settings: &dyn Settings) -> bool {
            self.integer_has_string_value(settings)
        }
        fn string_data_instance(&self, _buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> Box<dyn StringDataInstance> {
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_array_default_label_prefix(
            &self,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            len: i32,
            options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            self.integer_array_default_label_prefix(buf, settings, len, options)
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            len: i32,
            options: &dyn DataTypeDisplayOptions,
            offcut_length: i32,
        ) -> Option<String> {
            self.integer_array_default_offcut_label_prefix(buf, settings, len, options, offcut_length)
        }
    }

    impl AbstractIntegerDataType for MockIntDataType {
        fn is_signed(&self) -> bool {
            self.signed
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            Box::new(MockOppositeSignedness)
        }
    }

    #[test]
    fn usable_as_trait_object_and_computes_c_declaration_and_mnemonic() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        let dyn_dt: &dyn AbstractIntegerDataType = &dt;
        assert_eq!(dyn_dt.get_c_declaration(), Some(C_SIGNED_INT.to_string()));
        assert_eq!(dyn_dt.get_c_mnemonic(), C_SIGNED_INT.to_string());
        assert_eq!(dyn_dt.integer_default_label_prefix(), "INT".to_string());
        assert_eq!(dyn_dt.get_assembly_mnemonic(), "int".to_string());
    }

    #[test]
    fn unsigned_c_declaration_by_size() {
        let dt = MockIntDataType { name: "uchar", length: 1, signed: false };
        assert_eq!(dt.get_c_declaration(), Some(C_UNSIGNED_CHAR.to_string()));
        let dt = MockIntDataType { name: "ushort", length: 2, signed: false };
        assert_eq!(dt.get_c_declaration(), Some(C_UNSIGNED_SHORT.to_string()));
        // `get_long_size` and `get_long_long_size` are both 8 in `MockDataOrganization` (matching
        // a typical LP64 data organization), so a size-8 lookup matches "long" first, exactly
        // like the ported check order (char, int, short, long, long long).
        let dt = MockIntDataType { name: "ulong", length: 8, signed: false };
        assert_eq!(dt.get_c_declaration(), Some(C_UNSIGNED_LONG.to_string()));
        let dt = MockIntDataType { name: "big", length: 16, signed: false };
        assert_eq!(dt.get_c_declaration(), None);
    }

    #[test]
    fn integer_value_reads_scalar_for_small_lengths() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        let buf = BytesBuffer { data: vec![0xff, 0xff, 0xff, 0xff], big_endian: true };
        let settings = NoSettings;
        match dt.integer_value(&buf, &settings, -1) {
            Some(IntegerValue::Scalar(s)) => assert_eq!(s.get_value(), -1),
            other => panic!("expected Scalar, got {other:?}"),
        }
    }

    #[test]
    fn integer_value_reads_big_for_large_lengths() {
        let dt = MockIntDataType { name: "int128", length: 16, signed: true };
        let mut data = vec![0u8; 16];
        data[15] = 5;
        let buf = BytesBuffer { data, big_endian: true };
        let settings = NoSettings;
        match dt.integer_value(&buf, &settings, -1) {
            Some(IntegerValue::Big(v)) => assert_eq!(v, 5),
            other => panic!("expected Big, got {other:?}"),
        }
    }

    #[test]
    fn integer_value_none_when_length_unreadable() {
        let dt = MockIntDataType { name: "short", length: 2, signed: true };
        let buf = BytesBuffer { data: vec![0x01], big_endian: true };
        let settings = NoSettings;
        assert!(dt.integer_value(&buf, &settings, -1).is_none());
    }

    #[test]
    fn encode_value_round_trips_through_get_value() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        let buf = BytesBuffer { data: vec![0u8; 4], big_endian: true };
        let settings = NoSettings;
        let encoded = dt
            .integer_encode_value(&IntegerEncodeValue::I32(-2), &buf, &settings, -1)
            .expect("encodes");
        assert_eq!(encoded, vec![0xff, 0xff, 0xff, 0xfe]);
    }

    #[test]
    fn encode_value_rejects_negative_for_unsigned() {
        let dt = MockIntDataType { name: "uint", length: 4, signed: false };
        let buf = BytesBuffer { data: vec![0u8; 4], big_endian: true };
        let settings = NoSettings;
        // A direct BigInt value (unlike a fixed-width Byte/Short/Integer/Long value) is not
        // reinterpreted as unsigned by `cast_value_to_encode`, so it stays negative here.
        let err = dt
            .integer_encode_value(&IntegerEncodeValue::BigInt(-1), &buf, &settings, -1)
            .unwrap_err();
        assert!(err.message().contains("Unsigned type cannot have negative value"));
    }

    #[test]
    fn encode_value_rejects_out_of_range() {
        let dt = MockIntDataType { name: "byte", length: 1, signed: true };
        let buf = BytesBuffer { data: vec![0u8; 1], big_endian: true };
        let settings = NoSettings;
        let err = dt
            .integer_encode_value(&IntegerEncodeValue::I32(200), &buf, &settings, -1)
            .unwrap_err();
        assert!(err.message().contains("too large"));
    }

    #[test]
    fn encode_value_unsigned_negative_input_reinterpreted() {
        let dt = MockIntDataType { name: "ubyte", length: 1, signed: false };
        let buf = BytesBuffer { data: vec![0u8; 1], big_endian: true };
        let settings = NoSettings;
        // -1i8 reinterpreted as an unsigned byte is 0xFF, which fits.
        let encoded = dt
            .integer_encode_value(&IntegerEncodeValue::I8(-1), &buf, &settings, -1)
            .expect("encodes");
        assert_eq!(encoded, vec![0xff]);
    }

    #[test]
    fn cast_value_to_encode_char_uses_base36_digit_value() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        assert_eq!(dt.cast_value_to_encode(&IntegerEncodeValue::Char('7')).unwrap(), 7);
        assert_eq!(dt.cast_value_to_encode(&IntegerEncodeValue::Char('a')).unwrap(), 10);
        assert!(dt.cast_value_to_encode(&IntegerEncodeValue::Char('!')).is_err());
    }

    #[test]
    fn integer_representation_hex_default() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        let buf = BytesBuffer { data: vec![0x00, 0x00, 0x00, 0x2a], big_endian: true };
        let settings = NoSettings;
        assert_eq!(dt.integer_representation(&buf, &settings, 4), "2Ah");
    }

    #[test]
    fn integer_representation_negative_hex_uses_unsigned_pattern() {
        let dt = MockIntDataType { name: "int", length: 1, signed: true };
        let buf = BytesBuffer { data: vec![0xff], big_endian: true };
        let settings = NoSettings;
        assert_eq!(dt.integer_representation(&buf, &settings, 1), "FFh");
    }

    #[test]
    fn integer_representation_too_short_returns_placeholder() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        let buf = BytesBuffer { data: vec![0x00], big_endian: true };
        let settings = NoSettings;
        assert_eq!(dt.integer_representation(&buf, &settings, 4), "??");
    }

    #[test]
    fn encode_representation_round_trips_hex() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        let buf = BytesBuffer { data: vec![0u8; 4], big_endian: true };
        let settings = NoSettings;
        let bytes = dt.integer_encode_representation("2Ah", &buf, &settings, 4).expect("encodes");
        assert_eq!(bytes, vec![0x00, 0x00, 0x00, 0x2a]);
    }

    #[test]
    fn encode_representation_requires_suffix() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        let buf = BytesBuffer { data: vec![0u8; 4], big_endian: true };
        let settings = NoSettings;
        let err = dt.integer_encode_representation("2A", &buf, &settings, 4).unwrap_err();
        assert!(err.message().contains("must have"));
    }

    #[test]
    fn integer_value_type_id_matches_length() {
        let small = MockIntDataType { name: "int", length: 4, signed: true };
        assert_eq!(small.integer_value_type_id(&NoSettings), TypeId::of::<Scalar>());
        let big = MockIntDataType { name: "int128", length: 16, signed: true };
        assert_eq!(big.integer_value_type_id(&NoSettings), TypeId::of::<i128>());
    }

    #[test]
    fn integer_is_equivalent_compares_signedness_and_name() {
        let a = MockIntDataType { name: "int", length: 4, signed: true };
        let b = MockIntDataType { name: "int", length: 4, signed: true };
        let c = MockIntDataType { name: "int", length: 4, signed: false };
        assert!(a.integer_is_equivalent(&b));
        assert!(!a.integer_is_equivalent(&c));
        assert!(a.is_equivalent(&b));
    }

    #[test]
    fn integer_has_string_value_reflects_char_format() {
        let dt = MockIntDataType { name: "char", length: 1, signed: true };
        let mut longs = std::collections::HashMap::new();
        longs.insert("format".to_string(), format_settings_definition::CHAR as i64);
        struct CharSettings(std::collections::HashMap<String, i64>);
        impl Settings for CharSettings {
            fn get_long(&self, name: &str) -> Option<i64> {
                self.0.get(name).copied()
            }
        }
        let settings = CharSettings(longs);
        assert!(dt.integer_has_string_value(&settings));
        assert!(dt.has_string_value(&settings));
        assert!(!dt.integer_has_string_value(&NoSettings));
    }

    #[test]
    fn array_default_label_prefix_uses_char_view_when_has_string_value() {
        let dt = MockIntDataType { name: "char", length: 1, signed: true };
        let mut longs = std::collections::HashMap::new();
        longs.insert("format".to_string(), format_settings_definition::CHAR as i64);
        struct CharSettings(std::collections::HashMap<String, i64>);
        impl Settings for CharSettings {
            fn get_long(&self, name: &str) -> Option<i64> {
                self.0.get(name).copied()
            }
        }
        let settings = CharSettings(longs);
        let buf = BytesBuffer { data: b"Cat\0".to_vec(), big_endian: false };
        let prefix = dt.integer_array_default_label_prefix(&buf, &settings, 4, &DEFAULT);
        assert_eq!(prefix, Some("s_Cat".to_string()));
    }

    #[test]
    fn array_default_label_prefix_none_when_not_char_format() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        let buf = BytesBuffer { data: vec![0u8; 4], big_endian: false };
        let settings = NoSettings;
        assert_eq!(dt.integer_array_default_label_prefix(&buf, &settings, 4, &DEFAULT), None);
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockIntDataType { name: "int", length: 4, signed: true };
        let opposite = dt.get_opposite_signedness_data_type();
        assert!(!opposite.is_signed());
    }
}
