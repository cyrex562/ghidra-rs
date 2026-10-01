//! Port of `ghidra.program.model.data.StringDataInstance`.
//!
//! Represents an instance of a string in a [`MemBuffer`]: detects a terminated string's length,
//! converts the buffer's bytes into a string through the charset the data type and settings
//! select, and renders that string in the human-readable, quoted/escaped form Ghidra displays.
//!
//! A Java `StringDataInstance` holds a reference to the `MemBuffer` it reads, so the Rust struct
//! borrows its buffer for `'a`. Where Java wraps the buffer in a `WrappedMemBuffer` to look at an
//! offcut, the Rust instance keeps the same borrow and a byte offset into it.
//!
//! Java's `StaticStringInstance` subclass (and the `NULL_INSTANCE` built from it) is the
//! "static string" kind of this struct: an instance that reports a fixed string and length
//! instead of reading memory. See [`static_string_instance`] and [`null_instance`].
//!
//! Java strings are UTF-16 code units; the string value is decoded as such (see
//! [`JavaCharset`]) and converted to a Rust `String` at the API boundary, where an unpaired
//! surrogate can only be represented as `U+FFFD`.
//!
//! A translated value (`TranslationSettingsDefinition.getTranslatedValue(Data)`) comes from the
//! program's user property map. The Rust `Settings` passed to the constructor cannot be
//! recognised as a `Data`, and the property-map lookup itself is not available yet (see
//! `TranslationSettingsDefinition`), so an instance built here starts without one; a caller that
//! has a translation supplies it with [`with_translated_value`](StringDataInstance::with_translated_value).

use std::any::TypeId;
use std::fmt;
use std::sync::Arc;

use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::program::model::address::{Address, AddressRange, SpecialAddress};
use crate::program::model::data::array_stringable::get_array_stringable;
use crate::program::model::data::char_data_type::CharDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::endian_settings_definition::{self, EndianSettingsDefinition};
use crate::program::model::data::pascal_string255_data_type::PascalString255DataType;
use crate::program::model::data::pascal_string_data_type::PascalStringDataType;
use crate::program::model::data::pascal_unicode_data_type::PascalUnicodeDataType;
use crate::program::model::data::render_unicode_settings_definition::{RenderEnum, RenderUnicodeSettingsDefinition};
use crate::program::model::data::signed_char_data_type::SignedCharDataType;
use crate::program::model::data::string_data_type::StringDataType;
use crate::program::model::data::string_layout_enum::StringLayoutEnum;
use crate::program::model::data::string_render_builder::StringRenderBuilder;
use crate::program::model::data::string_render_parser::{StringRenderParseError, StringRenderParser};
use crate::program::model::data::string_utf8_data_type::StringUTF8DataType;
use crate::program::model::data::terminated_string_data_type::TerminatedStringDataType;
use crate::program::model::data::terminated_unicode32_data_type::TerminatedUnicode32DataType;
use crate::program::model::data::terminated_unicode_data_type::TerminatedUnicodeDataType;
use crate::program::model::data::translation_settings_definition::TranslationSettingsDefinition;
use crate::program::model::data::unicode32_data_type::Unicode32DataType;
use crate::program::model::data::unicode_data_type::UnicodeDataType;
use crate::program::model::data::unsigned_char_data_type::UnsignedCharDataType;
use crate::program::model::data::wide_char16_data_type::WideChar16DataType;
use crate::program::model::data::wide_char32_data_type::WideChar32DataType;
use crate::program::model::data::wide_char_data_type::WideCharDataType;
use crate::program::model::lang::endian::Endian;
use crate::program::model::listing::data::Data;
use crate::program::model::mem::{ByteMemBufferImpl, MemBuffer, Memory, MemoryAccessException};
use crate::util::charset::charset_info_manager::{self, CharsetInfoManager};
use crate::util::charset::java_charset::{CharacterCodingException, JavaCharset};
use crate::util::charset::UnicodeScript;
use crate::util::msg::Msg;
use crate::util::string_utilities::{
    is_displayable, UNICODE_BE_BYTE_ORDER_MARK, UNICODE_LE16_BYTE_ORDER_MARK, UNICODE_LE32_BYTE_ORDER_MARK,
};

/// `StringDataInstance.MAX_STRING_LENGTH`: the most bytes searched for a null terminator.
pub const MAX_STRING_LENGTH: i32 = 16 * 1024;

/// `StringDataInstance.DEFAULT_CHARSET_NAME` (`CharsetInfoManager.USASCII`).
pub const DEFAULT_CHARSET_NAME: &str = charset_info_manager::USASCII;

/// `StringDataInstance.UNKNOWN`.
pub const UNKNOWN: &str = "??";

/// `StringDataInstance.UNKNOWN_DOT_DOT_DOT`.
pub const UNKNOWN_DOT_DOT_DOT: &str = "??...";

/// `StringDataInstance.SIZEOF_PASCAL255_STR_LEN_FIELD`.
pub(crate) const SIZEOF_PASCAL255_STR_LEN_FIELD: i32 = 1;
/// `StringDataInstance.SIZEOF_PASCAL64k_STR_LEN_FIELD`.
pub(crate) const SIZEOF_PASCAL64K_STR_LEN_FIELD: i32 = 2;

/// [`Settings`] with nothing stored, standing in for `SettingsImpl.NO_SETTINGS`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSettings;
impl Settings for NoSettings {
    fn is_immutable_settings(&self) -> bool {
        true
    }
}

/// An error encoding a replacement value, standing in for the exceptions the Java
/// `encodeReplacementFrom*` methods throw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringEncodeError {
    /// `CharacterCodingException` from the charset encoder.
    Coding(CharacterCodingException),
    /// `StringParseException`, `MalformedInputException` or `UnmappableCharacterException` from
    /// parsing a representation.
    Parse(StringRenderParseError),
    /// `UnsupportedCharsetException`: the instance's charset is not available.
    UnsupportedCharset(String),
    /// `IllegalArgumentException("Encoded string does not fit")`.
    DoesNotFit,
}

impl fmt::Display for StringEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StringEncodeError::Coding(e) => e.fmt(f),
            StringEncodeError::Parse(e) => e.fmt(f),
            StringEncodeError::UnsupportedCharset(name) => f.write_str(name),
            StringEncodeError::DoesNotFit => f.write_str("Encoded string does not fit"),
        }
    }
}

impl std::error::Error for StringEncodeError {}

impl From<CharacterCodingException> for StringEncodeError {
    fn from(e: CharacterCodingException) -> Self {
        StringEncodeError::Coding(e)
    }
}

impl From<StringRenderParseError> for StringEncodeError {
    fn from(e: StringRenderParseError) -> Self {
        StringEncodeError::Parse(e)
    }
}

/// A view of a [`MemBuffer`] starting `offset` bytes in, standing in for `WrappedMemBuffer`.
#[derive(Clone, Copy)]
struct OffsetBuffer<'a> {
    inner: &'a dyn MemBuffer,
    offset: i32,
}

impl MemBuffer for OffsetBuffer<'_> {
    fn get_address(&self) -> Address {
        let base = self.inner.get_address();
        if self.offset == 0 {
            return base;
        }
        base.add_no_wrap(self.offset as i64).unwrap_or(base)
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.inner.get_byte(self.offset + offset)
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        self.inner.get_bytes(buf, self.offset + offset)
    }

    fn is_big_endian(&self) -> bool {
        self.inner.is_big_endian()
    }

    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        self.inner.get_memory()
    }

    fn is_initialized_memory(&self) -> bool {
        if self.offset == 0 {
            self.inner.is_initialized_memory()
        } else {
            self.get_byte(0).is_ok()
        }
    }

    fn get_short(&self, offset: i32) -> Result<i16, MemoryAccessException> {
        self.inner.get_short(self.offset + offset)
    }
}

/// What an instance reports: memory it reads, or Java's `StaticStringInstance` fixed values.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Memory,
    /// `StaticStringInstance(fakeStr, fakeLen)`.
    StaticString { fake_str: Option<String>, fake_len: i32 },
}

/// Represents an instance of a string in a [`MemBuffer`].
///
/// This handles all the details of detecting a terminated string's length, converting the bytes
/// in the buffer into a native string, and converting the raw string into a formatted
/// human-readable version, according to the various settings definitions attached to the string
/// data location.
///
/// Port of `ghidra.program.model.data.StringDataInstance`; see the module docs.
#[derive(Clone)]
pub struct StringDataInstance<'a> {
    charset_name: String,
    char_size: i32,
    padded_char_size: i32,
    string_layout: StringLayoutEnum,
    /// Java: `null` means not initialized.
    translated_value: Option<String>,
    endian_setting: Option<Endian>,
    show_translation: bool,
    render_setting: RenderEnum,
    length: i32,
    buf: Option<OffsetBuffer<'a>>,
    kind: Kind,
}

impl fmt::Debug for StringDataInstance<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringDataInstance")
            .field("charset_name", &self.charset_name)
            .field("char_size", &self.char_size)
            .field("padded_char_size", &self.padded_char_size)
            .field("string_layout", &self.string_layout)
            .field("length", &self.length)
            .field("kind", &self.kind)
            .finish()
    }
}

/// `StaticStringInstance(fakeStr, fakeLen)`: an instance that reports `fake_str` as its value and
/// representation and `fake_len` as its length, and the default string for any label.
pub fn static_string_instance(fake_str: Option<String>, fake_len: i32) -> StringDataInstance<'static> {
    StringDataInstance {
        // default field values for the Dummy constructor
        charset_name: UNKNOWN.to_string(),
        char_size: 0,
        padded_char_size: 0,
        string_layout: StringLayoutEnum::FixedLen,
        translated_value: None,
        endian_setting: None,
        show_translation: false,
        render_setting: RenderEnum::All,
        length: 0,
        buf: None,
        kind: Kind::StaticString { fake_str, fake_len },
    }
}

/// `StringDataInstance.NULL_INSTANCE`: an instance that represents a non-existent string. Its
/// methods generally return `None`.
pub fn null_instance() -> StringDataInstance<'static> {
    static_string_instance(None, -1)
}

/// `StringDataInstance.isString(Data)`: whether `data` is a 'string'.
pub fn is_string(data: Option<&dyn Data>) -> bool {
    let Some(data) = data else {
        return false;
    };
    if !data.is_initialized_memory() {
        return false;
    }
    let dt = data.get_base_data_type();
    if dt.as_abstract_string().is_some() {
        return true;
    }
    if let Some(array_dt) = dt.as_array() {
        let settings: &dyn Settings = data;
        return get_array_stringable(array_dt.get_data_type()).is_some_and(|stringable| stringable.has_string_value(settings));
    }
    false
}

/// `StringDataInstance.isStringDataType(DataType)`: whether `dt` is (or could be) a string.
/// Arrays of char-like elements are treated as string data types; the actual data instance needs
/// to be inspected to determine if the array is an actual string.
pub fn is_string_data_type(dt: &dyn DataType) -> bool {
    let resolved;
    let dt: &dyn DataType = if let Some(td) = dt.as_typedef() {
        resolved = td.get_base_data_type();
        resolved.as_ref()
    } else {
        dt
    };
    dt.as_abstract_string().is_some()
        || dt.as_array().is_some_and(|array_dt| get_array_stringable(array_dt.get_data_type()).is_some())
}

/// `StringDataInstance.isChar(Data)`: whether `data` is one of the many 'char' data types.
pub fn is_char(data: Option<&dyn Data>) -> bool {
    let Some(data) = data else {
        return false;
    };
    is_char_data_type(data.get_base_data_type().as_ref())
}

/// `dt instanceof CharDataType || WideCharDataType || WideChar16DataType || WideChar32DataType`
/// (`SignedCharDataType`/`UnsignedCharDataType` extend `CharDataType`).
pub fn is_char_data_type(dt: &dyn DataType) -> bool {
    let Some(class) = dt.runtime_class() else {
        return false;
    };
    [
        TypeId::of::<CharDataType>(),
        TypeId::of::<SignedCharDataType>(),
        TypeId::of::<UnsignedCharDataType>(),
        TypeId::of::<WideCharDataType>(),
        TypeId::of::<WideChar16DataType>(),
        TypeId::of::<WideChar32DataType>(),
    ]
    .contains(&class)
}

/// `StringDataInstance.getCharRepresentation(DataType, byte[], Settings)`: the representation of
/// the character(s) in `bytes` (big-endian ordered), suitable for display as a single character
/// (`'a'`) or a sequence of characters (`"a\x12bc"`).
pub fn get_char_representation(data_type: &dyn DataType, bytes: &[u8], settings: Option<&dyn Settings>) -> String {
    if bytes.is_empty() {
        return UNKNOWN.to_string();
    }
    let single;
    let bytes = if bytes.len() != 1 && is_single_ascii_value(bytes) {
        single = [bytes[bytes.len() - 1]];
        &single[..]
    } else {
        bytes
    };
    let mem_buf = ByteMemBufferImpl::new(SpecialAddress::no_address(), bytes.to_vec(), true);
    let settings = settings.unwrap_or(&NoSettings);
    let sdi = StringDataInstance::new(data_type, settings, &mem_buf, bytes.len() as i32);
    sdi.get_char_representation()
}

/// Whether `bytes` (big-endian) hold a single ASCII value in the least significant byte.
fn is_single_ascii_value(bytes: &[u8]) -> bool {
    let lsb_index = bytes.len() - 1;
    if bytes[lsb_index] >= 0x80 {
        return false;
    }
    bytes[..lsb_index].iter().all(|&b| b == 0)
}

/// `StringDataInstance.getStringDataInstance(Data)`: an instance over the bytes of `data`, or
/// [`null_instance`] if it is not a string.
pub fn get_string_data_instance_for_data<'a>(data: Option<&'a dyn Data>) -> StringDataInstance<'a> {
    let Some(data) = data else {
        return null_instance();
    };
    let dt = data.get_base_data_type();
    let buf: &'a dyn MemBuffer = data;
    let settings: &dyn Settings = data;
    if let Some(asdt) = dt.as_abstract_string() {
        return asdt.get_string_data_instance(buf, settings, data.get_length());
    }
    if let Some(array_dt) = dt.as_array() {
        if data.is_initialized_memory() {
            if let Some(stringable) = get_array_stringable(array_dt.get_data_type()) {
                if stringable.has_string_value(settings) {
                    return StringDataInstance::new_element(stringable.as_ref(), settings, buf, data.get_length(), true);
                }
            }
        }
    }
    null_instance()
}

/// `StringDataInstance.getStringDataInstance(DataType, MemBuffer, Settings, int)`: an instance
/// over the bytes in `buf`, or [`null_instance`] if `data_type` is not a string there.
pub fn get_string_data_instance<'a>(
    data_type: &dyn DataType,
    buf: &'a dyn MemBuffer,
    settings: &dyn Settings,
    length: i32,
) -> StringDataInstance<'a> {
    if let Some(asdt) = data_type.as_abstract_string() {
        return asdt.get_string_data_instance(buf, settings, length);
    }
    if let Some(array_dt) = data_type.as_array() {
        return match get_array_stringable(array_dt.get_data_type()) {
            Some(stringable) if stringable.has_string_value(settings) && buf.is_initialized_memory() => {
                // this could be either a charsequence or an array of char elements
                StringDataInstance::new_element(stringable.as_ref(), settings, buf, length, true)
            }
            _ => null_instance(),
        };
    }
    match data_type.as_array_stringable() {
        Some(stringable) if stringable.has_string_value(settings) && buf.is_initialized_memory() => {
            StringDataInstance::new_element(data_type, settings, buf, length, false)
        }
        _ => null_instance(),
    }
}

/// `StringDataInstance.makeStringLabel(String, String, DataTypeDisplayOptions)`: formats a string
/// value so that it is in the form of a symbol label.
pub fn make_string_label(prefix_str: &str, s: &str, options: &dyn DataTypeDisplayOptions) -> String {
    let mut needs_underscore = false;
    let mut found_scripts: Vec<UnicodeScript> = Vec::new();
    let mut buffer = String::new();
    let max = options.get_label_string_length().max(0) as usize;
    for c in s.chars() {
        // Only ASCII is appended, so the byte length is Java's char length.
        if buffer.len() >= max {
            break;
        }
        let code_point = c as u32;
        if is_displayable(code_point) && c != ' ' {
            if needs_underscore {
                if !buffer.is_empty() {
                    buffer.push('_');
                }
                needs_underscore = false;
            }
            buffer.push(c);
        } else {
            let script = UnicodeScript::of(code_point);
            if !found_scripts.contains(&script) {
                found_scripts.push(script);
            }
            needs_underscore = true;
            // discard character
        }
    }
    found_scripts.retain(|s| *s != UnicodeScript::Latin && *s != UnicodeScript::Common);
    let mut script_summary = String::new();
    if !found_scripts.is_empty() {
        let mut script_names: Vec<String> = found_scripts.iter().map(|s| script_name(*s)).collect();
        script_names.sort();
        script_summary = format!("{}#", script_names.join("_"));
    }
    format!("{prefix_str}{script_summary}{buffer}")
}

/// `UnicodeScript.name()`.
fn script_name(script: UnicodeScript) -> String {
    serde_json::to_value(script).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// `(detected charset name, BOM bytes to skip, detected endianness)`, Java's private
/// `AdjustedCharsetInfo`.
struct AdjustedCharsetInfo {
    charset_name: String,
    byte_start_offset: usize,
    endian: Endian,
}

impl<'a> StringDataInstance<'a> {
    /// `StringDataInstance(DataType, Settings, MemBuffer, int)`: an instance over `buf` using the
    /// settings of the string data type `data_type` (an `AbstractStringDataType`, or an
    /// `ArrayStringable` element type of a char array).
    ///
    /// `length` is the length passed from the caller to the datatype: `-1` is a 'probe' trying to
    /// detect the length of an unknown string, otherwise it is the length of the containing field.
    pub fn new<D: DataType + ?Sized>(data_type: &D, settings: &dyn Settings, buf: &'a dyn MemBuffer, length: i32) -> Self {
        Self::new_element(data_type, settings, buf, length, false)
    }

    /// `StringDataInstance(DataType, Settings, MemBuffer, int, boolean)`. `is_array_element`
    /// indicates that `data_type` is an element in an array (`char[]` vs. a plain `char`), which
    /// forces the string layout to [`StringLayoutEnum::NullTerminatedBounded`].
    pub fn new_element<D: DataType + ?Sized>(
        data_type: &D,
        settings: &dyn Settings,
        buf: &'a dyn MemBuffer,
        length: i32,
        is_array_element: bool,
    ) -> Self {
        let charset_name = get_charset_name_from_data_type_or_settings(data_type, settings);
        let char_size = CharsetInfoManager::get_instance().get_charset_char_size(&charset_name);
        // NOTE: for now only handle padding for charSize == 1 and the data type is an array of
        // elements, not a "string"
        let padded_char_size = if data_type.is_array_stringable_type() && char_size == 1 {
            data_type.get_data_organization().get_char_size()
        } else {
            char_size
        };
        let string_layout = if is_array_element {
            StringLayoutEnum::NullTerminatedBounded
        } else {
            get_layout_from_data_type(data_type)
        };
        let endian_setting = match EndianSettingsDefinition::DEF.get_choice(settings) {
            endian_settings_definition::BIG => Some(Endian::Big),
            endian_settings_definition::LITTLE => Some(Endian::Little),
            _ => None,
        };
        StringDataInstance {
            charset_name,
            char_size,
            padded_char_size,
            string_layout,
            show_translation: TranslationSettingsDefinition::translation().is_show_translated(settings),
            translated_value: None,
            render_setting: RenderUnicodeSettingsDefinition::DEF.get_enum_value(settings),
            endian_setting,
            length,
            buf: Some(OffsetBuffer { inner: buf, offset: 0 }),
            kind: Kind::Memory,
        }
    }

    /// Supplies the translated value Java reads from the program's translation property map for a
    /// defined `Data` (see the module docs).
    pub fn with_translated_value(mut self, translated_value: Option<String>) -> Self {
        self.translated_value = translated_value;
        self
    }

    /// The private copy constructor `StringDataInstance(StringDataInstance, StringLayoutEnum,
    /// MemBuffer, int, String)`.
    fn derive(&self, new_layout: StringLayoutEnum, new_buf: Option<OffsetBuffer<'a>>, new_len: i32, new_charset_name: String) -> Self {
        StringDataInstance {
            charset_name: new_charset_name,
            char_size: self.char_size,
            padded_char_size: self.padded_char_size,
            string_layout: new_layout,
            translated_value: None,
            endian_setting: self.endian_setting,
            show_translation: false,
            render_setting: self.render_setting,
            length: new_len,
            buf: new_buf,
            kind: Kind::Memory,
        }
    }

    fn mem(&self) -> Option<&dyn MemBuffer> {
        self.buf.as_ref().map(|b| b as &dyn MemBuffer)
    }

    /// Returns the name of the charset (`getCharsetName()`).
    pub fn get_charset_name(&self) -> &str {
        &self.charset_name
    }

    /// Returns the address of the buffer (`getAddress()`), or `None` for an instance with no
    /// buffer (where Java would throw `NullPointerException`).
    pub fn get_address(&self) -> Option<Address> {
        self.mem().map(|b| b.get_address())
    }

    /// `getEndAddress()`: the address of this string's last byte.
    pub fn get_end_address(&self) -> Option<Address> {
        let address = self.get_address()?;
        if self.length > 0 {
            Some(address.add_no_wrap((self.length - 1) as i64).unwrap_or(address))
        } else {
            Some(address)
        }
    }

    /// `getAddressRange()`.
    pub fn get_address_range(&self) -> Option<AddressRange> {
        Some(AddressRange::new(self.get_address()?, self.get_end_address()?))
    }

    fn is_bad_char_size(&self) -> bool {
        (self.padded_char_size < 1 || self.padded_char_size > 8)
            || !(self.char_size == 1 || self.char_size == 2 || self.char_size == 4)
            || (self.padded_char_size < self.char_size)
    }

    fn is_probe(&self) -> bool {
        self.length == -1
    }

    fn is_already_determined_fixed_len(&self) -> bool {
        self.length >= 0 && self.string_layout.is_fixed_len()
    }

    /// Returns the length of this string's data, in bytes (`getDataLength()`).
    pub fn get_data_length(&self) -> i32 {
        self.length
    }

    /// `getStringLength()`: the length, in bytes, of the string data object contained in the
    /// buffer, or `-1` if the length could not be determined.
    ///
    /// This is not the number of characters: pascal strings have a 1 or 2 byte length field, and
    /// null terminated strings include the terminator. For length-specified layouts with a known
    /// instance length this is the constructor's `length`; otherwise a null terminator is searched
    /// for, respecting or ignoring `length` depending on the layout, and limited to
    /// [`MAX_STRING_LENGTH`] bytes when unbounded. The buffer's endianness selects which end of a
    /// padded character field holds the character tested for null.
    pub fn get_string_length(&self) -> i32 {
        if let Kind::StaticString { fake_len, .. } = self.kind {
            return fake_len;
        }
        if self.string_layout.is_pascal() {
            self.get_pascal_length()
        } else if self.is_bad_char_size() || self.buf.is_none() || self.is_already_determined_fixed_len() {
            self.length
        } else {
            self.get_null_terminated_length()
        }
    }

    /// Java also returns `offset` (or `-1` when unbounded) when a read throws
    /// `AddressOutOfBoundsException`; a Rust [`MemBuffer`] reports that as a short read, which is
    /// handled like the "ran out of bytes" case.
    fn get_null_terminated_length(&self) -> i32 {
        let Some(buf) = self.mem() else {
            return self.length;
        };
        let mut local_len = self.length;
        let mut local_nt = self.string_layout.is_null_terminated();
        if self.is_probe() || self.string_layout == StringLayoutEnum::NullTerminatedUnbounded {
            local_len = MAX_STRING_LENGTH;
            local_nt = true;
        }

        let internal_char_offset = if buf.is_big_endian() { self.padded_char_size - self.char_size } else { 0 };
        let mut char_buf = vec![0u8; self.char_size as usize];
        let mut offset = 0;
        while offset < local_len {
            if buf.get_bytes(&mut char_buf, offset + internal_char_offset) != char_buf.len() {
                break;
            }
            if local_nt && char_buf.iter().all(|&b| b == 0) {
                return offset + self.padded_char_size;
            }
            offset += self.padded_char_size;
        }

        if self.string_layout == StringLayoutEnum::NullTerminatedUnbounded {
            -1
        } else {
            self.length
        }
    }

    /// `isMissingNullTerminator()`: whether the string should have a trailing null character and
    /// doesn't.
    pub fn is_missing_null_terminator(&self) -> bool {
        if self.string_layout.should_trim_trailing_nulls() {
            if let Some(units) = self.get_string_value_no_trim() {
                return units.last().is_some_and(|&c| c != 0);
            }
        }
        false
    }

    fn get_pascal_length(&self) -> i32 {
        let Some(buf) = self.mem() else {
            return -1;
        };
        let result = match self.string_layout {
            StringLayoutEnum::Pascal255 => buf
                .get_unsigned_byte(0)
                .map(|len| SIZEOF_PASCAL255_STR_LEN_FIELD + (len as i32) * self.padded_char_size),
            StringLayoutEnum::Pascal64k => buf
                .get_short(0)
                .map(|len| SIZEOF_PASCAL64K_STR_LEN_FIELD + (len as u16 as i32) * self.padded_char_size),
            _ => return -1,
        };
        result.unwrap_or_else(|e| {
            Msg::error("StringDataInstance", &format!("PascalString error: {e}"));
            -1
        })
    }

    /// `getStringValue()`: the string contained in the buffer, or `None` if all the bytes of the
    /// string could not be read. Trailing nulls are trimmed for the layouts that call for it.
    pub fn get_string_value(&self) -> Option<String> {
        if let Kind::StaticString { fake_str, .. } = &self.kind {
            return fake_str.clone();
        }
        let mut units = self.get_string_value_no_trim()?;
        if self.string_layout.should_trim_trailing_nulls() {
            while units.last() == Some(&0) {
                units.pop();
            }
        }
        Some(String::from_utf16_lossy(&units))
    }

    fn get_string_value_no_trim(&self) -> Option<Vec<u16>> {
        let buf = self.mem()?;
        if self.is_probe() || self.is_bad_char_size() || !buf.is_initialized_memory() {
            return None;
        }
        let unknown = || Some(UNKNOWN_DOT_DOT_DOT.encode_utf16().collect());
        let Some(string_bytes) = self.get_string_bytes().map(|b| self.convert_padded_to_unpadded(b)) else {
            return unknown();
        };
        // force BE or LE variants of UTF charsets, consume any BOM
        let (adjusted_charset_name, start) = self.get_adjusted_charset_name(&string_bytes);
        let Some(cs) = JavaCharset::for_name(&adjusted_charset_name) else {
            return unknown();
        };
        Some(cs.decode_to_units(&string_bytes[start..]))
    }

    fn get_string_bytes(&self) -> Option<Vec<u8>> {
        if self.string_layout.is_pascal() {
            self.get_pascal_char_bytes()
        } else {
            self.get_normal_string_char_bytes()
        }
    }

    fn get_normal_string_char_bytes(&self) -> Option<Vec<u8>> {
        let str_length = self.get_string_length();
        self.get_bytes_from_mem_buff(0, if str_length >= 0 { str_length } else { self.length })
    }

    fn get_pascal_char_bytes(&self) -> Option<Vec<u8>> {
        let buf = self.mem()?;
        let result = match self.string_layout {
            StringLayoutEnum::Pascal255 => buf
                .get_unsigned_byte(0)
                .map(|len| ((len as i32) * self.padded_char_size, SIZEOF_PASCAL255_STR_LEN_FIELD)),
            StringLayoutEnum::Pascal64k => buf
                .get_short(0)
                .map(|len| ((len as u16 as i32) * self.padded_char_size, SIZEOF_PASCAL64K_STR_LEN_FIELD)),
            _ => panic!("IllegalArgumentException: not a pascal layout"),
        };
        match result {
            Ok((len, offset)) => self.get_bytes_from_mem_buff(offset, len),
            Err(e) => {
                Msg::error("StringDataInstance", &format!("PascalString error: {e}"));
                None
            }
        }
    }

    fn is_valid_offcut_offset(&self, offcut_bytes: i32) -> bool {
        // The Java switch has no breaks, so every layout falls through to `minValid = 0`.
        let min_valid = 0;
        offcut_bytes >= min_valid && offcut_bytes < self.length
    }

    fn get_char_offset(&self, char_count: i32) -> i32 {
        let char_bytes = char_count * self.char_size;
        match self.string_layout {
            StringLayoutEnum::Pascal255 => (SIZEOF_PASCAL255_STR_LEN_FIELD + char_bytes).max(0),
            StringLayoutEnum::Pascal64k => (SIZEOF_PASCAL64K_STR_LEN_FIELD + char_bytes).max(0),
            _ => char_bytes,
        }
    }

    fn get_offcut_layout(&self) -> StringLayoutEnum {
        match self.string_layout {
            StringLayoutEnum::Pascal255 | StringLayoutEnum::Pascal64k => StringLayoutEnum::FixedLen,
            other => other,
        }
    }

    /// `getBytesFromMemBuff(MemBuffer, int)`, reading from `base_offset` (Java wraps the buffer).
    fn get_bytes_from_mem_buff(&self, base_offset: i32, copy_len: i32) -> Option<Vec<u8>> {
        let buf = self.mem()?;
        // round copyLen down to multiple of paddedCharSize
        let copy_len = (copy_len / self.padded_char_size) * self.padded_char_size;
        if copy_len < 0 {
            return None;
        }
        let mut bytes = vec![0u8; copy_len as usize];
        if buf.get_bytes(&mut bytes, base_offset) != bytes.len() {
            return None;
        }
        Some(bytes)
    }

    fn buf_is_big_endian(&self) -> bool {
        self.mem().is_some_and(|b| b.is_big_endian())
    }

    fn convert_padded_to_unpadded(&self, padded_bytes: Vec<u8>) -> Vec<u8> {
        if self.padded_char_size == self.char_size {
            return padded_bytes;
        }
        let char_size = self.char_size as usize;
        let padded = self.padded_char_size as usize;
        let mut unpadded = vec![0u8; (padded_bytes.len() / padded) * char_size];
        let mut src = if self.buf_is_big_endian() { padded - char_size } else { 0 };
        let mut dest = 0;
        while src < padded_bytes.len() {
            unpadded[dest..dest + char_size].copy_from_slice(&padded_bytes[src..src + char_size]);
            src += padded;
            dest += char_size;
        }
        unpadded
    }

    fn convert_unpadded_to_padded(&self, unpadded_bytes: Vec<u8>) -> Vec<u8> {
        if self.padded_char_size == self.char_size {
            return unpadded_bytes;
        }
        let char_size = self.char_size as usize;
        let padded = self.padded_char_size as usize;
        let mut padded_bytes = vec![0u8; (unpadded_bytes.len() / char_size) * padded];
        let mut src = 0;
        let mut dest = if self.buf_is_big_endian() { padded - char_size } else { 0 };
        while src < unpadded_bytes.len() {
            padded_bytes[dest..dest + char_size].copy_from_slice(&unpadded_bytes[src..src + char_size]);
            src += char_size;
            dest += padded;
        }
        padded_bytes
    }

    fn get_memory_endianness(&self) -> Endian {
        if self.buf_is_big_endian() {
            Endian::Big
        } else {
            Endian::Little
        }
    }

    /// The private `getAdjustedCharsetInfo()` used when encoding: sniffs a byte-order mark from
    /// the current bytes.
    fn get_adjusted_charset_info(&self) -> AdjustedCharsetInfo {
        if self.length == -1 && self.get_string_length() == -1 {
            return self.get_adjusted_charset_info_for(&[]);
        }
        match self.get_string_bytes() {
            Some(bytes) => {
                let unpadded = self.convert_padded_to_unpadded(bytes);
                self.get_adjusted_charset_info_for(&unpadded)
            }
            None => self.get_adjusted_charset_info_for(&[]),
        }
    }

    fn get_adjusted_charset_info_for(&self, bytes: &[u8]) -> AdjustedCharsetInfo {
        let mut charset_name = self.charset_name.clone();
        let mut byte_start_offset = 0;
        let mut endian = None;
        if CharsetInfoManager::is_bom_charset(&self.charset_name) {
            endian = get_endianness_from_bom(bytes, self.char_size);
            if endian.is_some() {
                // skip the BOM char when creating the string
                byte_start_offset = self.char_size as usize;
            }
            let resolved = endian.or(self.endian_setting).unwrap_or_else(|| self.get_memory_endianness());
            endian = Some(resolved);
            // add "LE" or "BE" to end of charset's name depending of the discovered endianness
            charset_name.push_str(resolved.to_short_string());
        }
        AdjustedCharsetInfo {
            charset_name,
            byte_start_offset,
            endian: endian.unwrap_or_else(|| self.get_memory_endianness()),
        }
    }

    /// The private `getAdjustedCharsetInfo(ByteBuffer)`: the charset to decode `bytes` with and how
    /// many leading byte-order-mark bytes to skip.
    fn get_adjusted_charset_name(&self, bytes: &[u8]) -> (String, usize) {
        let info = self.get_adjusted_charset_info_for(bytes);
        (info.charset_name, info.byte_start_offset)
    }

    /// `getStringRepresentation()`: a formatted version of the string value, with quotes around
    /// the parts that contain plain ASCII alpha characters (and simple escape sequences) and
    /// out-of-range byte values listed as comma separated hex values, e.g.
    /// `"Test\tstring",01h,02h,"Second\npart",00h`. Returns the translated value instead when
    /// present and the "show translated" setting is enabled.
    pub fn get_string_representation(&self) -> String {
        if let Kind::StaticString { fake_str, .. } = &self.kind {
            // Java returns the (possibly null) fake string.
            return fake_str.clone().unwrap_or_else(|| "null".to_string());
        }
        match (&self.translated_value, self.show_translation) {
            (Some(translated), true) => get_translated_string_representation(translated),
            _ => self.get_string_rep(StringRenderBuilder::DOUBLE_QUOTE),
        }
    }

    /// `getStringRepresentation(boolean)`: the representation of the string value when
    /// `original_or_translated` is set, otherwise of the translated value.
    pub fn get_string_representation_for(&self, original_or_translated: bool) -> String {
        if original_or_translated {
            return self.get_string_rep(StringRenderBuilder::DOUBLE_QUOTE);
        }
        match &self.translated_value {
            Some(translated) => get_translated_string_representation(translated),
            None => UNKNOWN.to_string(),
        }
    }

    fn get_string_rep(&self, quote_char: char) -> String {
        let Some(buf) = self.mem() else {
            return UNKNOWN.to_string();
        };
        if self.is_probe() || self.is_bad_char_size() || !buf.is_initialized_memory() {
            return UNKNOWN.to_string();
        }
        let Some(string_bytes) = self.get_string_bytes().map(|b| self.convert_padded_to_unpadded(b)) else {
            return UNKNOWN_DOT_DOT_DOT.to_string();
        };
        // force BE or LE variants of UTF charsets, consume any BOM
        let (adjusted_charset_name, start) = self.get_adjusted_charset_name(&string_bytes);
        let Some(cs) = JavaCharset::for_name(&adjusted_charset_name) else {
            return UNKNOWN_DOT_DOT_DOT.to_string();
        };
        let mut renderer = StringRenderBuilder::with_quote_char(cs, self.char_size, quote_char);
        renderer.decode_bytes_using_charset(
            &string_bytes[start..],
            self.render_setting,
            self.string_layout.should_trim_trailing_nulls(),
        );
        renderer.build()
    }

    /// `hasTranslatedValue()`.
    pub fn has_translated_value(&self) -> bool {
        self.translated_value.is_some()
    }

    /// `getTranslatedValue()`.
    pub fn get_translated_value(&self) -> Option<&str> {
        self.translated_value.as_deref()
    }

    /// `isShowTranslation()`: whether the user should be shown the translated value instead of
    /// the real value.
    pub fn is_show_translation(&self) -> bool {
        self.show_translation
    }

    /// `getCharRepresentation()`: the canonical representation of the char value (or sequence of
    /// char values) in memory, using the attached charset and encoding information.
    pub fn get_char_representation(&self) -> String {
        if self.length < self.char_size {
            // also covers case of isProbe()
            return UNKNOWN_DOT_DOT_DOT.to_string();
        }
        let charseq = self.derive(StringLayoutEnum::CharSeq, self.buf, self.length, self.charset_name.clone());
        let quote_char = if self.length == self.char_size {
            StringRenderBuilder::SINGLE_QUOTE
        } else {
            StringRenderBuilder::DOUBLE_QUOTE
        };
        charseq.get_string_rep(quote_char)
    }

    /// `getLabel(String, String, String, DataTypeDisplayOptions)`.
    pub fn get_label(
        &self,
        prefix_str: &str,
        abbrev_prefix_str: &str,
        default_str: &str,
        options: &dyn DataTypeDisplayOptions,
    ) -> String {
        if matches!(self.kind, Kind::StaticString { .. }) || self.is_probe() || self.is_bad_char_size() {
            return default_str.to_string();
        }
        if options.use_abbreviated_form() {
            // no data from the data instance is used, just its abbrev type prefix and its address
            return abbrev_prefix_str.to_string();
        }
        let s = match (&self.translated_value, self.show_translation) {
            (Some(translated), true) => Some(translated.clone()),
            _ => self.get_string_value(),
        };
        match s {
            None => default_str.to_string(),
            Some(s) if s.is_empty() => prefix_str.to_string(),
            Some(s) => make_string_label(prefix_str, &s, options),
        }
    }

    /// `getOffcutLabelString(String, String, String, DataTypeDisplayOptions, int)`.
    pub fn get_offcut_label_string(
        &self,
        prefix_str: &str,
        abbrev_prefix_str: &str,
        default_str: &str,
        options: &dyn DataTypeDisplayOptions,
        byte_offset: i32,
    ) -> String {
        if matches!(self.kind, Kind::StaticString { .. }) || self.is_bad_char_size() || self.is_probe() {
            return default_str.to_string();
        }
        self.get_byte_offcut(byte_offset).get_label(prefix_str, abbrev_prefix_str, default_str, options)
    }

    /// `getByteOffcut(int)`: an instance over the string characters that start `byte_offset`
    /// bytes into this one, or [`null_instance`] if the offset is not valid.
    pub fn get_byte_offcut(&self, byte_offset: i32) -> StringDataInstance<'a> {
        if self.is_bad_char_size() || self.is_probe() || !self.is_valid_offcut_offset(byte_offset) {
            return null_instance();
        }
        if byte_offset == 0 {
            return self.clone();
        }
        let new_length = (self.length - byte_offset).max(0);
        let new_buf = self.buf.map(|b| OffsetBuffer { inner: b.inner, offset: b.offset + byte_offset });
        self.derive(self.get_offcut_layout(), new_buf, new_length, self.charset_name.clone())
    }

    /// `getCharOffcut(int)`: an instance over a portion of this one, starting `offset_chars`
    /// characters in.
    pub fn get_char_offcut(&self, offset_chars: i32) -> StringDataInstance<'a> {
        self.get_byte_offcut(self.get_char_offset(offset_chars))
    }

    /// `getStringDataTypeGuess()`: the string data type that best handles this kind of data
    /// instance (by layout and charset), defaulting to `StringDataType`.
    pub fn get_string_data_type_guess(&self) -> Arc<dyn DataType> {
        use charset_info_manager::{UTF16, UTF32, UTF8};
        use StringLayoutEnum::*;
        let cs = self.charset_name.as_str();
        match (self.string_layout, cs) {
            (Pascal64k, UTF16) => PascalUnicodeDataType::data_type(),
            (FixedLen, UTF8) => StringUTF8DataType::data_type(),
            (FixedLen, UTF16) => UnicodeDataType::data_type(),
            (FixedLen, UTF32) => Unicode32DataType::data_type(),
            (NullTerminatedUnbounded, UTF16) => TerminatedUnicodeDataType::data_type(),
            (NullTerminatedUnbounded, UTF32) => TerminatedUnicode32DataType::data_type(),
            (Pascal255, _) => PascalString255DataType::data_type(),
            (Pascal64k, _) => PascalStringDataType::data_type(),
            (FixedLen, _) | (NullTerminatedBounded, _) => StringDataType::data_type(),
            (NullTerminatedUnbounded, _) => TerminatedStringDataType::data_type(),
            (CharSeq, _) => StringDataType::data_type(),
        }
    }

    /// `encodeReplacementFromStringValue(CharSequence)`: encodes `value` to replace the current
    /// value.
    pub fn encode_replacement_from_string_value(&self, value: &str) -> Result<Vec<u8>, StringEncodeError> {
        let cs = JavaCharset::for_name(&self.charset_name)
            .ok_or_else(|| StringEncodeError::UnsupportedCharset(self.charset_name.clone()))?;
        let encoded = cs.encode_str(value)?;
        Ok(self.convert_unpadded_to_padded(self.check_and_encode_layout(encoded)?))
    }

    /// `encodeReplacementFromStringRepresentation(CharSequence)`: parses and encodes a string from
    /// its representation to replace the current value.
    pub fn encode_replacement_from_string_representation(&self, repr: &str) -> Result<Vec<u8>, StringEncodeError> {
        let encoded = self.parse_representation(StringRenderBuilder::DOUBLE_QUOTE, repr)?;
        Ok(self.convert_unpadded_to_padded(self.check_and_encode_layout(encoded)?))
    }

    /// `encodeReplacementFromCharValue(char[])`: encodes a single character (one code point, as
    /// Java chars) to replace the current value.
    pub fn encode_replacement_from_char_value(&self, value: &[u16]) -> Result<Vec<u8>, StringEncodeError> {
        let cs = JavaCharset::for_name(&self.charset_name)
            .ok_or_else(|| StringEncodeError::UnsupportedCharset(self.charset_name.clone()))?;
        Ok(cs.encode_units(value)?)
    }

    /// `encodeReplacementFromCharRepresentation(CharSequence)`: parses and encodes a single
    /// character from its representation to replace the current value.
    pub fn encode_replacement_from_char_representation(&self, repr: &str) -> Result<Vec<u8>, StringEncodeError> {
        self.parse_representation(StringRenderBuilder::SINGLE_QUOTE, repr)
    }

    fn parse_representation(&self, quote_char: char, repr: &str) -> Result<Vec<u8>, StringEncodeError> {
        let aci = self.get_adjusted_charset_info();
        if !JavaCharset::is_supported(&aci.charset_name) {
            return Err(StringEncodeError::UnsupportedCharset(aci.charset_name));
        }
        let mut parser =
            StringRenderParser::new(quote_char, aci.endian, Some(&aci.charset_name), aci.byte_start_offset != 0);
        Ok(parser.parse(repr)?)
    }

    fn check_and_encode_layout(&self, encoded: Vec<u8>) -> Result<Vec<u8>, StringEncodeError> {
        let length = self.length;
        let char_size = self.char_size.max(0) as usize;
        let limit = encoded.len();
        match self.string_layout {
            StringLayoutEnum::CharSeq | StringLayoutEnum::FixedLen => {
                if length != -1 && limit > length as usize {
                    return Err(StringEncodeError::DoesNotFit);
                }
                let mut result = vec![0u8; if length != -1 { length as usize } else { limit }];
                result[..limit].copy_from_slice(&encoded);
                Ok(result)
            }
            StringLayoutEnum::NullTerminatedBounded => {
                if length != -1 && limit + char_size > length as usize {
                    return Err(StringEncodeError::DoesNotFit);
                }
                let mut result = encoded;
                result.resize(limit + char_size, 0);
                Ok(result)
            }
            StringLayoutEnum::NullTerminatedUnbounded => {
                let mut result = encoded;
                result.resize(limit + char_size, 0);
                Ok(result)
            }
            StringLayoutEnum::Pascal255 => {
                if !fits_in(limit, SIZEOF_PASCAL255_STR_LEN_FIELD) {
                    return Err(StringEncodeError::DoesNotFit);
                }
                let mut result = Vec::with_capacity(limit + 1);
                result.push(limit as u8);
                result.extend_from_slice(&encoded);
                Ok(result)
            }
            StringLayoutEnum::Pascal64k => {
                if !fits_in(limit, SIZEOF_PASCAL64K_STR_LEN_FIELD) {
                    return Err(StringEncodeError::DoesNotFit);
                }
                let len = limit as u16;
                let mut result = Vec::with_capacity(limit + 2);
                result.extend_from_slice(&if self.buf_is_big_endian() { len.to_be_bytes() } else { len.to_le_bytes() });
                result.extend_from_slice(&encoded);
                Ok(result)
            }
        }
    }
}

impl fmt::Display for StringDataInstance<'_> {
    /// `toString()`: the string value (`null` when there is none).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_string_value() {
            Some(s) => f.write_str(&s),
            None => f.write_str("null"),
        }
    }
}

fn fits_in(limit: usize, len_len: i32) -> bool {
    limit < (1usize << (8 * len_len))
}

fn get_translated_string_representation(translated_string: &str) -> String {
    format!("\u{00BB}{translated_string}\u{00AB}")
}

fn get_layout_from_data_type<D: DataType + ?Sized>(data_type: &D) -> StringLayoutEnum {
    if let Some(asdt) = data_type.as_abstract_string() {
        return asdt.get_string_layout();
    }
    if data_type.as_abstract_integer().is_some() || data_type.as_bit_field_data_type().is_some() {
        return StringLayoutEnum::CharSeq;
    }
    StringLayoutEnum::NullTerminatedBounded
}

/// The package-private static `getCharsetNameFromDataTypeOrSettings(DataType, Settings)`.
pub(crate) fn get_charset_name_from_data_type_or_settings<D: DataType + ?Sized>(data_type: &D, settings: &dyn Settings) -> String {
    let charset_of = |dt: &dyn DataType| {
        dt.as_data_type_with_charset()
            .map(|dtwcs| dtwcs.get_charset_name(settings))
            .unwrap_or_else(|| DEFAULT_CHARSET_NAME.to_string())
    };
    match data_type.as_bit_field_data_type() {
        Some(bfdt) => charset_of(bfdt.referenced_base_data_type()),
        None => data_type
            .as_data_type_with_charset()
            .map(|dtwcs| dtwcs.get_charset_name(settings))
            .unwrap_or_else(|| DEFAULT_CHARSET_NAME.to_string()),
    }
}

fn get_endianness_from_bom(bytes: &[u8], char_size: i32) -> Option<Endian> {
    let char_size = char_size.max(0) as usize;
    if bytes.len() < char_size || char_size == 0 {
        return None;
    }
    // BigEndianDataConverter.getValue(bytes, charSize), truncated to a Java int.
    let be_val = bytes[..char_size.min(8)].iter().fold(0u64, |acc, &b| (acc << 8) | b as u64) as u32;
    match be_val {
        UNICODE_BE_BYTE_ORDER_MARK => Some(Endian::Big),
        UNICODE_LE16_BYTE_ORDER_MARK | UNICODE_LE32_BYTE_ORDER_MARK => Some(Endian::Little),
        _ => None,
    }
}

/// Helpers shared by the string and char data type tests: Java's `SettingsBuilder` and the
/// `mb(isBE, bytes...)` buffer factory.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::HashMap;

    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::charset_settings_definition::CharsetSettingsDefinition;
    use crate::program::model::data::render_unicode_settings_definition::{RenderEnum, RenderUnicodeSettingsDefinition};
    use crate::program::model::mem::ByteMemBufferImpl;
    use crate::util::charset::JavaCharset;

    /// `new ByteMemBufferImpl(new GenericAddressSpace("test", 32, TYPE_RAM, 1).getAddress(0), ...)`.
    pub(crate) fn mb(big_endian: bool, bytes: &[u8]) -> ByteMemBufferImpl {
        let space = AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 1);
        ByteMemBufferImpl::new(Address::new(space, 0), bytes.to_vec(), big_endian)
    }

    /// Port of the test helper `SettingsBuilder`: mutable settings with chainable setters.
    #[derive(Default, Clone)]
    pub(crate) struct SettingsBuilder {
        longs: HashMap<String, i64>,
        strings: HashMap<String, String>,
    }

    impl SettingsBuilder {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// `set(Charset)`.
        pub(crate) fn charset(mut self, cs: JavaCharset) -> Self {
            CharsetSettingsDefinition::charset().set_charset(&mut self, Some(cs.name()));
            self
        }

        /// `set(RENDER_ENUM)`.
        pub(crate) fn render(mut self, value: RenderEnum) -> Self {
            RenderUnicodeSettingsDefinition::DEF.set_enum_value(&mut self, value);
            self
        }

        /// A raw long setting (e.g. `format`).
        pub(crate) fn long(mut self, name: &str, value: i64) -> Self {
            self.longs.insert(name.to_string(), value);
            self
        }
    }

    impl Settings for SettingsBuilder {
        fn get_long(&self, name: &str) -> Option<i64> {
            self.longs.get(name).copied()
        }
        fn get_string(&self, name: &str) -> Option<String> {
            self.strings.get(name).cloned()
        }
        fn get_value(&self, name: &str) -> Option<Box<dyn std::any::Any>> {
            if let Some(v) = self.longs.get(name) {
                return Some(Box::new(*v));
            }
            self.strings.get(name).map(|v| Box::new(v.clone()) as Box<dyn std::any::Any>)
        }
        fn set_long(&mut self, name: &str, value: i64) {
            self.strings.remove(name);
            self.longs.insert(name.to_string(), value);
        }
        fn set_string(&mut self, name: &str, value: &str) {
            self.longs.remove(name);
            self.strings.insert(name.to_string(), value.to_string());
        }
        fn clear_setting(&mut self, name: &str) {
            self.longs.remove(name);
            self.strings.remove(name);
        }
        fn get_names(&self) -> Vec<String> {
            self.longs.keys().chain(self.strings.keys()).cloned().collect()
        }
        fn is_empty(&self) -> bool {
            self.longs.is_empty() && self.strings.is_empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{mb, SettingsBuilder};
    use super::*;
    use crate::program::model::data::data_type_display_options::DEFAULT;

    fn sdi<'a>(dt: &dyn DataType, buf: &'a dyn MemBuffer, len: i32) -> StringDataInstance<'a> {
        StringDataInstance::new(dt, &SettingsBuilder::new(), buf, len)
    }

    #[test]
    fn null_instance_reports_nothing() {
        let inst = null_instance();
        assert_eq!(inst.get_string_value(), None);
        assert_eq!(inst.get_string_length(), -1);
        assert_eq!(inst.get_label("P", "A", "DEF", &DEFAULT), "DEF");
        assert_eq!(inst.get_offcut_label_string("P", "A", "DEF", &DEFAULT, 0), "DEF");
        assert_eq!(inst.to_string(), "null");
        let fake = static_string_instance(Some("fake".into()), 4);
        assert_eq!(fake.get_string_value().as_deref(), Some("fake"));
        assert_eq!(fake.get_string_representation(), "fake");
        assert_eq!(fake.get_string_length(), 4);
    }

    #[test]
    fn make_string_label_matches_java() {
        assert_eq!(make_string_label("STR_", "ab\tcd", &DEFAULT), "STR_ab_cd");
        assert_eq!(make_string_label("s_", "hello world", &DEFAULT), "s_hello_world");
        // Non-Latin scripts are summarized, sorted by Java enum name.
        assert_eq!(make_string_label("s_", "a\u{0E01}b\u{4E00}", &DEFAULT), "s_HAN_THAI#a_b");
        // The label is limited to the display option's length (32).
        let long = "x".repeat(40);
        assert_eq!(make_string_label("s_", &long, &DEFAULT), format!("s_{}", "x".repeat(32)));
    }

    #[test]
    fn labels_and_offcuts() {
        let dt = TerminatedStringDataType::new(None);
        let buf = mb(false, b"XXCAT\0");
        let inst = sdi(&dt, &buf, 6);
        assert_eq!(inst.get_label("STR_", "S", "?", &DEFAULT), "STR_XXCAT");
        assert_eq!(inst.get_offcut_label_string("STR_", "S", "?", &DEFAULT, 2), "STR_CAT");
        assert_eq!(inst.get_offcut_label_string("STR_", "S", "?", &DEFAULT, 6), "?");
        let offcut = inst.get_char_offcut(3);
        assert_eq!(offcut.get_string_value().as_deref(), Some("AT"));
        assert_eq!(offcut.get_data_length(), 3);
        assert_eq!(offcut.get_address().unwrap().offset(), 3);
        assert_eq!(inst.get_end_address().unwrap().offset(), 5);
        let empty = mb(false, b"\0");
        assert_eq!(sdi(&dt, &empty, 1).get_label("STR_", "S", "?", &DEFAULT), "STR_");
    }

    #[test]
    fn pascal_offcut_becomes_fixed_length() {
        let dt = PascalString255DataType::new(None);
        let buf = mb(false, &[3, b'a', b'b', b'c']);
        let inst = sdi(&dt, &buf, 4);
        assert_eq!(inst.get_string_value().as_deref(), Some("abc"));
        let offcut = inst.get_char_offcut(1);
        assert_eq!(offcut.get_string_value().as_deref(), Some("bc"));
    }

    #[test]
    fn translated_value_is_shown_when_enabled() {
        let dt = StringDataType::new(None);
        let buf = mb(false, b"abc");
        let settings = SettingsBuilder::new().long("translated", 1);
        let inst = StringDataInstance::new(&dt, &settings, &buf, 3).with_translated_value(Some("xyz".into()));
        assert!(inst.is_show_translation());
        assert!(inst.has_translated_value());
        assert_eq!(inst.get_string_representation(), "\u{00BB}xyz\u{00AB}");
        assert_eq!(inst.get_string_representation_for(true), "\"abc\"");
        assert_eq!(inst.get_label("s_", "S", "?", &DEFAULT), "s_xyz");
        let plain = StringDataInstance::new(&dt, &SettingsBuilder::new(), &buf, 3);
        assert_eq!(plain.get_string_representation_for(false), UNKNOWN);
    }

    #[test]
    fn string_data_type_guess() {
        let buf = mb(false, &[]);
        let guess = |dt: &dyn DataType| sdi(dt, &buf, 0).get_string_data_type_guess().get_name();
        assert_eq!(guess(&StringDataType::new(None)), "string");
        assert_eq!(guess(&TerminatedStringDataType::new(None)), "TerminatedCString");
        assert_eq!(guess(&UnicodeDataType::new(None)), "unicode");
        assert_eq!(guess(&TerminatedUnicode32DataType::new(None)), "TerminatedUnicode32");
        assert_eq!(guess(&PascalUnicodeDataType::new(None)), "PascalUnicode");
        assert_eq!(guess(&PascalString255DataType::new(None)), "PascalString255");
        assert_eq!(guess(&StringUTF8DataType::new(None)), "string-utf8");
    }

    #[test]
    fn get_char_representation_static_helper() {
        let char_dt = CharDataType::new(None);
        assert_eq!(get_char_representation(&char_dt, &[], None), UNKNOWN);
        assert_eq!(get_char_representation(&char_dt, &[b'A'], None), "'A'");
        // A single ASCII value in the low byte collapses to one char.
        assert_eq!(get_char_representation(&char_dt, &[0, 0, b'A'], None), "'A'");
        assert_eq!(get_char_representation(&char_dt, &[b'A', b'B'], None), "\"AB\"");
    }

    #[test]
    fn encode_layouts() {
        let buf = mb(true, &[]);
        let fixed = StringDataType::new(None);
        assert_eq!(sdi(&fixed, &buf, 4).encode_replacement_from_string_value("Hi").unwrap(), b"Hi\0\0");
        assert_eq!(sdi(&fixed, &buf, 1).encode_replacement_from_string_value("Hi"), Err(StringEncodeError::DoesNotFit));
        let term = TerminatedStringDataType::new(None);
        assert_eq!(sdi(&term, &buf, -1).encode_replacement_from_string_value("Hi").unwrap(), b"Hi\0");
        let pascal = PascalStringDataType::new(None);
        assert_eq!(sdi(&pascal, &buf, -1).encode_replacement_from_string_value("Hi").unwrap(), vec![0, 2, b'H', b'i']);
        let p255 = PascalString255DataType::new(None);
        assert_eq!(sdi(&p255, &buf, -1).encode_replacement_from_string_value("Hi").unwrap(), vec![2, b'H', b'i']);
        let too_long = "x".repeat(256);
        assert_eq!(sdi(&p255, &buf, -1).encode_replacement_from_string_value(&too_long), Err(StringEncodeError::DoesNotFit));
        // The unadjusted "UTF-16" charset encoder writes a byte-order mark, as Java's does.
        let uni = UnicodeDataType::new(None);
        assert_eq!(sdi(&uni, &buf, -1).encode_replacement_from_string_value("A").unwrap(), vec![0xFE, 0xFF, 0, b'A']);
        assert!(matches!(
            sdi(&fixed, &buf, -1).encode_replacement_from_string_value("\u{e9}"),
            Err(StringEncodeError::Coding(CharacterCodingException::Unmappable(1)))
        ));
    }
}
