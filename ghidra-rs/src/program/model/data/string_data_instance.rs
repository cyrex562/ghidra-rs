//! Port of `ghidra.program.model.data.StringDataInstance`.
//!
//! Promoted straight to a trait: `StringDataInstance` was selected as a dependency-cycle
//! cut-point, and was referenced by
//! [`DataTypeWithCharset`](super::data_type_with_charset::DataTypeWithCharset) and
//! [`ArrayStringable`](super::array_stringable::ArrayStringable) as a minimal placeholder in
//! `seam_stubs` before this port existed.
//!
//! The Java class is concrete, with fields fixed at construction time from a
//! `DataType`/`Settings`/`MemBuffer`/`length` tuple. A trait has no fields of its own, so those
//! constructor-derived values are modeled here as `&self` accessor methods, each defaulting to the
//! same "no value" state as Java's no-arg `StringDataInstance()` constructor (which Java itself
//! documents as existing only to provide "default field values for Dummy subclass"). The real Java
//! instance methods are then default trait methods built on top of those accessors, so a concrete
//! implementation only needs to override the accessors that apply to it (mirroring how
//! [`StaticStringInstance`] below only overrides the handful of methods it needs to).
//!
//! Not ported, with reasons:
//! - `getByteOffcut`/`getCharOffcut`, which in Java construct a new `StringDataInstance` view over
//!   a `WrappedMemBuffer`. Object safety would require any such view to be returned as
//!   `Box<dyn StringDataInstance>`, which in turn requires an owned (`'static`) buffer; this
//!   crate's placeholder `MemBuffer` is normally borrowed with the caller's lifetime instead.
//!   [`get_offcut_label_string`](StringDataInstance::get_offcut_label_string), their only caller
//!   within this class, is ported directly, using the same buffer-offset math via the private
//!   [`OffcutView`] helper.
//! - `getStringDataTypeGuess`, which maps to the `DataType` singletons for ten concrete string
//!   data types (`PascalString255DataType`, `StringUTF8DataType`, etc.), none of which are ported
//!   yet, and nothing in this crate currently calls through this trait.
//! - The static factory methods `isString(Data)`, `isStringDataType(DataType)`, `isChar(Data)`, and
//!   both `getStringDataInstance` overloads, which need `Data`/`AbstractStringDataType` (not
//!   ported) to recognize a string-shaped data type/instance.
//! - The static `getCharRepresentation(DataType, byte[], Settings)` factory, which needs
//!   `BitFieldDataType`-aware charset/size derivation from a bare `DataType` (the instance-side
//!   [`get_char_representation`](StringDataInstance::get_char_representation) is ported).
//! - `encodeReplacementFromStringRepresentation`/`encodeReplacementFromCharRepresentation`'s
//!   parsing, and the quoted/escaped rendering performed by `getStringRepresentation`/
//!   `getCharRepresentation`, which in Java go through `StringRenderParser`/`StringRenderBuilder`
//!   (neither ported). This port uses a simplified quoting scheme with no per-character escaping
//!   instead.
//! - Charset support is limited to the handful of charsets Rust's standard library can decode/
//!   encode without a full `java.nio.charset.Charset` registry: `US-ASCII`, `UTF-8`, `UTF-16BE`/
//!   `UTF-16LE`, `UTF-32BE`/`UTF-32LE`, and `ISO-8859-1`.

use std::fmt;

use crate::program::model::address::{Address, AddressRange};
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::string_layout_enum::StringLayoutEnum;
use crate::program::model::data::render_unicode_settings_definition::RenderEnum;
use crate::program::model::lang::endian::Endian;
use crate::program::model::mem::MemoryAccessException;
use crate::program::seam_stubs::{CHARSET_UTF16, CHARSET_UTF32};
use crate::program::model::mem::MemBuffer;

/// Maximum number of bytes searched for a null terminator, standing in for
/// `StringDataInstance.MAX_STRING_LENGTH`.
pub const MAX_STRING_LENGTH: i32 = 16 * 1024;

/// Charset used when no charset can be determined, standing in for
/// `StringDataInstance.DEFAULT_CHARSET_NAME` (`CharsetInfoManager.USASCII`).
pub const DEFAULT_CHARSET_NAME: &str = "US-ASCII";

/// Placeholder value returned in place of an unreadable/unknown string, standing in for
/// `StringDataInstance.UNKNOWN`.
pub const UNKNOWN: &str = "??";

/// Placeholder value returned when a string's bytes are only partially readable, standing in for
/// `StringDataInstance.UNKNOWN_DOT_DOT_DOT`.
pub const UNKNOWN_DOT_DOT_DOT: &str = "??...";

const SIZEOF_PASCAL255_STR_LEN_FIELD: i32 = 1;
const SIZEOF_PASCAL64K_STR_LEN_FIELD: i32 = 2;

/// Represents an instance of a string in a [`MemBuffer`].
///
/// Port of `ghidra.program.model.data.StringDataInstance`. See the module documentation for the
/// design of the trait and what was intentionally left unported.
pub trait StringDataInstance {
    /// Encode a normalized character value (one code point) as replacement bytes.
    ///
    /// Stands in for `StringDataInstance.encodeReplacementFromCharValue(char[])`. Kept as a
    /// required method (no default) since it predates this port as a `seam_stubs` placeholder
    /// method that [`DataTypeWithCharset`](super::data_type_with_charset::DataTypeWithCharset)
    /// already depends on.
    fn encode_replacement_from_char_value(&self, value: &[char]) -> Result<Vec<u8>, String>;

    /// Encode a single-character string representation as replacement bytes.
    ///
    /// Stands in for `StringDataInstance.encodeReplacementFromCharRepresentation(CharSequence)`.
    /// Kept as a required method for the same reason as
    /// [`encode_replacement_from_char_value`](Self::encode_replacement_from_char_value).
    fn encode_replacement_from_char_representation(&self, repr: &str) -> Result<Vec<u8>, String>;

    // ---- Constructor-derived accessors (defaults mirror the Java no-arg "Dummy" constructor) ----

    /// Stands in for the `charsetName` field, set from
    /// `getCharsetNameFromDataTypeOrSettings(dataType, settings)` at construction.
    fn charset_name(&self) -> String {
        UNKNOWN.to_string()
    }

    /// Stands in for the `charSize` field.
    fn char_size(&self) -> i32 {
        0
    }

    /// Stands in for the `paddedCharSize` field.
    fn padded_char_size(&self) -> i32 {
        0
    }

    /// Stands in for the `stringLayout` field.
    fn string_layout(&self) -> StringLayoutEnum {
        StringLayoutEnum::FixedLen
    }

    /// Stands in for the `translatedValue` field.
    fn translated_value(&self) -> Option<String> {
        None
    }

    /// Stands in for the `endianSetting` field.
    fn endian_setting(&self) -> Option<Endian> {
        None
    }

    /// Stands in for the `showTranslation` field.
    fn show_translation(&self) -> bool {
        false
    }

    /// Stands in for the `renderSetting` field.
    fn render_setting(&self) -> RenderEnum {
        RenderEnum::All
    }

    /// Stands in for the `length` field.
    fn data_length(&self) -> i32 {
        0
    }

    /// Stands in for the `buf` field. `None` mirrors a `null` buffer (e.g.
    /// [`StaticStringInstance::NULL_INSTANCE`](StaticStringInstance)), which the real Java class
    /// never dereferences because [`StaticStringInstance`] overrides every method that touches
    /// `buf`.
    fn mem_buffer(&self) -> Option<&dyn MemBuffer> {
        None
    }

    // ---------------------------------- Derived instance methods ---------------------------------

    /// Port of `StringDataInstance.getCharsetName()`.
    fn get_charset_name(&self) -> String {
        self.charset_name()
    }

    /// Port of `StringDataInstance.getAddress()`. Returns `None` where the Java method would
    /// dereference a `null` `buf`.
    fn get_address(&self) -> Option<Address> {
        self.mem_buffer().map(|b| b.get_address())
    }

    /// Port of `StringDataInstance.getEndAddress()`.
    fn get_end_address(&self) -> Option<Address> {
        let addr = self.get_address()?;
        let length = self.data_length();
        if length > 0 {
            match addr.add_no_wrap((length - 1) as i64) {
                Ok(end) => Some(end),
                Err(_) => Some(addr),
            }
        } else {
            Some(addr)
        }
    }

    /// Port of `StringDataInstance.getAddressRange()`.
    fn get_address_range(&self) -> Option<AddressRange> {
        let start = self.get_address()?;
        let end = self.get_end_address()?;
        Some(AddressRange::new(start, end))
    }

    /// Port of the private `StringDataInstance.isBadCharSize()`.
    fn is_bad_char_size(&self) -> bool {
        let padded = self.padded_char_size();
        let char_size = self.char_size();
        !(1..=8).contains(&padded) || !matches!(char_size, 1 | 2 | 4) || padded < char_size
    }

    /// Port of the private `StringDataInstance.isProbe()`.
    fn is_probe(&self) -> bool {
        self.data_length() == -1
    }

    /// Port of the private `StringDataInstance.isAlreadyDeterminedFixedLen()`.
    fn is_already_determined_fixed_len(&self) -> bool {
        self.data_length() >= 0 && self.string_layout().is_fixed_len()
    }

    /// Port of `StringDataInstance.getDataLength()`.
    fn get_data_length(&self) -> i32 {
        self.data_length()
    }

    /// Port of `StringDataInstance.getStringLength()`.
    fn get_string_length(&self) -> i32 {
        if self.string_layout().is_pascal() {
            return self.get_pascal_length();
        }
        if self.is_bad_char_size() || self.mem_buffer().is_none() || self.is_already_determined_fixed_len() {
            return self.data_length();
        }
        self.get_null_terminated_length()
    }

    /// Port of the private `StringDataInstance.getNullTerminatedLength()`.
    ///
    /// Simplified relative to Java: the placeholder [`MemBuffer`] does not distinguish a
    /// short-read (fewer bytes available than requested) from an out-of-bounds address, so both
    /// are treated as the "stopped reading early" (non-exception) case Java handles by breaking
    /// out of its search loop.
    fn get_null_terminated_length(&self) -> i32 {
        let Some(buf) = self.mem_buffer() else {
            return self.data_length();
        };
        let layout = self.string_layout();
        let mut local_len = self.data_length();
        let mut local_nt = layout.is_null_terminated();
        if self.is_probe() || layout == StringLayoutEnum::NullTerminatedUnbounded {
            local_len = MAX_STRING_LENGTH;
            local_nt = true;
        }

        let char_size = self.char_size();
        let padded_char_size = self.padded_char_size();
        let internal_char_offset = if buf.is_big_endian() { padded_char_size - char_size } else { 0 };
        let mut char_buf = vec![0u8; char_size.max(0) as usize];

        let mut offset = 0;
        while offset < local_len {
            let read = buf.get_bytes_into(&mut char_buf, offset + internal_char_offset);
            if read != char_size {
                break;
            }
            if local_nt && char_buf.iter().all(|&b| b == 0) {
                return offset + padded_char_size;
            }
            offset += padded_char_size;
        }

        if layout == StringLayoutEnum::NullTerminatedUnbounded { -1 } else { self.data_length() }
    }

    /// Port of the private `StringDataInstance.getPascalLength()`.
    fn get_pascal_length(&self) -> i32 {
        let Some(buf) = self.mem_buffer() else {
            return -1;
        };
        let padded = self.padded_char_size();
        match self.string_layout() {
            StringLayoutEnum::Pascal255 => match buf.get_unsigned_byte(0) {
                Ok(b) => SIZEOF_PASCAL255_STR_LEN_FIELD + (b as i32) * padded,
                Err(_) => -1,
            },
            StringLayoutEnum::Pascal64k => match buf.get_short(0) {
                Ok(s) => SIZEOF_PASCAL64K_STR_LEN_FIELD + ((s as u16) as i32) * padded,
                Err(_) => -1,
            },
            _ => -1,
        }
    }

    /// Port of `StringDataInstance.isMissingNullTerminator()`.
    fn is_missing_null_terminator(&self) -> bool {
        if self.string_layout().should_trim_trailing_nulls() {
            if let Some(s) = self.get_string_value_no_trim() {
                return !s.is_empty() && s.chars().last() != Some('\u{0}');
            }
        }
        false
    }

    /// Port of `StringDataInstance.getStringValue()`.
    fn get_string_value(&self) -> Option<String> {
        let str_val = self.get_string_value_no_trim()?;
        Some(if self.string_layout().should_trim_trailing_nulls() {
            trim_nulls(&str_val)
        } else {
            str_val
        })
    }

    /// Port of the private `StringDataInstance.getStringValueNoTrim()`.
    fn get_string_value_no_trim(&self) -> Option<String> {
        let buf = self.mem_buffer()?;
        if self.is_probe() || self.is_bad_char_size() || !buf.is_initialized_memory() {
            return None;
        }
        let Some(padded_bytes) = self.get_string_bytes() else {
            return Some(UNKNOWN_DOT_DOT_DOT.to_string());
        };
        let unpadded = convert_padded_to_unpadded(&padded_bytes, self.char_size(), self.padded_char_size(), buf.is_big_endian());
        match decode_string(&self.get_charset_name(), self.char_size(), &unpadded, self.endian_setting(), buf.is_big_endian()) {
            Some(s) => Some(s),
            None => Some(UNKNOWN_DOT_DOT_DOT.to_string()),
        }
    }

    /// Port of the private `StringDataInstance.getStringBytes()`.
    fn get_string_bytes(&self) -> Option<Vec<u8>> {
        if self.string_layout().is_pascal() {
            self.get_pascal_char_bytes()
        } else {
            self.get_normal_string_char_bytes()
        }
    }

    /// Port of the private `StringDataInstance.getNormalStringCharBytes()`.
    fn get_normal_string_char_bytes(&self) -> Option<Vec<u8>> {
        let str_length = self.get_string_length();
        let len = if str_length >= 0 { str_length } else { self.data_length() };
        self.get_bytes_from_mem_buf(0, len)
    }

    /// Port of the private `StringDataInstance.getPascalCharBytes()`.
    fn get_pascal_char_bytes(&self) -> Option<Vec<u8>> {
        let buf = self.mem_buffer()?;
        let padded = self.padded_char_size();
        match self.string_layout() {
            StringLayoutEnum::Pascal255 => {
                let n = buf.get_unsigned_byte(0).ok()? as i32;
                self.get_bytes_from_mem_buf(SIZEOF_PASCAL255_STR_LEN_FIELD, n * padded)
            }
            StringLayoutEnum::Pascal64k => {
                let n = (buf.get_short(0).ok()? as u16) as i32;
                self.get_bytes_from_mem_buf(SIZEOF_PASCAL64K_STR_LEN_FIELD, n * padded)
            }
            _ => None,
        }
    }

    /// Port of the private `StringDataInstance.getBytesFromMemBuff(MemBuffer, int)`, folding in
    /// the `base_offset` that Java achieves by first wrapping `buf` in a `WrappedMemBuffer`.
    fn get_bytes_from_mem_buf(&self, base_offset: i32, copy_len: i32) -> Option<Vec<u8>> {
        let buf = self.mem_buffer()?;
        let padded = self.padded_char_size();
        if padded <= 0 || copy_len < 0 {
            return None;
        }
        let copy_len = (copy_len / padded) * padded;
        let mut bytes = vec![0u8; copy_len as usize];
        if buf.get_bytes_into(&mut bytes, base_offset) != copy_len {
            return None;
        }
        Some(bytes)
    }

    /// Port of the private `StringDataInstance.convertPaddedToUnpadded(byte[])`.
    fn convert_padded_to_unpadded(&self, padded_bytes: &[u8]) -> Vec<u8> {
        let big_endian = self.mem_buffer().map(|b| b.is_big_endian()).unwrap_or(false);
        convert_padded_to_unpadded(padded_bytes, self.char_size(), self.padded_char_size(), big_endian)
    }

    /// Port of the private `StringDataInstance.convertUnpaddedToPadded(byte[])`.
    fn convert_unpadded_to_padded(&self, unpadded_bytes: &[u8]) -> Vec<u8> {
        let big_endian = self.mem_buffer().map(|b| b.is_big_endian()).unwrap_or(false);
        convert_unpadded_to_padded(unpadded_bytes, self.char_size(), self.padded_char_size(), big_endian)
    }

    /// Port of `StringDataInstance.getStringRepresentation()`.
    fn get_string_representation(&self) -> String {
        if self.show_translation() {
            if let Some(t) = self.translated_value() {
                return format!("\u{00BB}{t}\u{00AB}");
            }
        }
        self.get_string_rep()
    }

    /// Port of the overloaded `StringDataInstance.getStringRepresentation(boolean)`.
    fn get_string_representation_for(&self, original_or_translated: bool) -> String {
        if !original_or_translated {
            return match self.translated_value() {
                Some(t) => format!("\u{00BB}{t}\u{00AB}"),
                None => UNKNOWN.to_string(),
            };
        }
        self.get_string_rep()
    }

    /// Port of the private `StringDataInstance.getStringRep(char)`, simplified to always use
    /// double quotes (Java selects the quote character per call site; every call in the Java
    /// source passes `DOUBLE_QUOTE`). See the module docs for the quoting/escaping simplification.
    fn get_string_rep(&self) -> String {
        if self.is_probe() || self.is_bad_char_size() {
            return UNKNOWN.to_string();
        }
        let Some(buf) = self.mem_buffer() else {
            return UNKNOWN.to_string();
        };
        if !buf.is_initialized_memory() {
            return UNKNOWN.to_string();
        }
        match self.get_string_bytes() {
            None => UNKNOWN_DOT_DOT_DOT.to_string(),
            Some(padded) => {
                let unpadded = self.convert_padded_to_unpadded(&padded);
                match decode_string(&self.get_charset_name(), self.char_size(), &unpadded, self.endian_setting(), buf.is_big_endian()) {
                    Some(s) => {
                        let s = if self.string_layout().should_trim_trailing_nulls() { trim_nulls(&s) } else { s };
                        format!("\"{s}\"")
                    }
                    None => UNKNOWN_DOT_DOT_DOT.to_string(),
                }
            }
        }
    }

    /// Port of `StringDataInstance.hasTranslatedValue()`.
    fn has_translated_value(&self) -> bool {
        self.translated_value().is_some()
    }

    /// Port of `StringDataInstance.getTranslatedValue()`.
    fn get_translated_value(&self) -> Option<String> {
        self.translated_value()
    }

    /// Port of `StringDataInstance.isShowTranslation()`.
    fn is_show_translation(&self) -> bool {
        self.show_translation()
    }

    /// Port of `StringDataInstance.getCharRepresentation()`.
    fn get_char_representation(&self) -> String {
        if self.data_length() < self.char_size() {
            return UNKNOWN_DOT_DOT_DOT.to_string();
        }
        let Some(buf) = self.mem_buffer() else {
            return UNKNOWN_DOT_DOT_DOT.to_string();
        };
        let length = self.data_length();
        let Some(bytes) = self.get_bytes_from_mem_buf(0, length) else {
            return UNKNOWN_DOT_DOT_DOT.to_string();
        };
        let unpadded = self.convert_padded_to_unpadded(&bytes);
        let Some(s) = decode_string(&self.get_charset_name(), self.char_size(), &unpadded, self.endian_setting(), buf.is_big_endian()) else {
            return UNKNOWN_DOT_DOT_DOT.to_string();
        };
        let quote = if length == self.char_size() { '\'' } else { '"' };
        format!("{quote}{s}{quote}")
    }

    /// Port of `StringDataInstance.getLabel(String, String, String, DataTypeDisplayOptions)`.
    fn get_label(
        &self,
        prefix_str: &str,
        abbrev_prefix_str: &str,
        default_str: &str,
        options: &dyn DataTypeDisplayOptions,
    ) -> String {
        if self.is_probe() || self.is_bad_char_size() {
            return default_str.to_string();
        }
        if options.use_abbreviated_form() {
            return abbrev_prefix_str.to_string();
        }
        let str_val = if self.show_translation() && self.translated_value().is_some() {
            self.translated_value()
        } else {
            self.get_string_value()
        };
        match str_val {
            None => default_str.to_string(),
            Some(s) if s.is_empty() => prefix_str.to_string(),
            Some(s) => make_string_label(prefix_str, &s, options),
        }
    }

    /// Port of `StringDataInstance.getOffcutLabelString(String, String, String,
    /// DataTypeDisplayOptions, int)`. See the module docs for why this inlines
    /// `getByteOffcut(byteOffset).getLabel(...)` instead of materializing a new
    /// `StringDataInstance`.
    fn get_offcut_label_string(
        &self,
        prefix_str: &str,
        abbrev_prefix_str: &str,
        default_str: &str,
        options: &dyn DataTypeDisplayOptions,
        byte_offset: i32,
    ) -> String {
        if self.is_bad_char_size() || self.is_probe() || !self.is_valid_offcut_offset(byte_offset) {
            return default_str.to_string();
        }
        if byte_offset == 0 {
            return self.get_label(prefix_str, abbrev_prefix_str, default_str, options);
        }
        let Some(buf) = self.mem_buffer() else {
            return default_str.to_string();
        };
        let new_length = (self.data_length() - byte_offset).max(0);
        let offcut = OffcutView {
            charset_name: self.charset_name(),
            char_size: self.char_size(),
            padded_char_size: self.padded_char_size(),
            layout: self.get_offcut_layout(),
            length: new_length,
            buf: OffsetMemBuffer { inner: buf, offset: byte_offset },
            endian_setting: self.endian_setting(),
            render_setting: self.render_setting(),
        };
        offcut.get_label(prefix_str, abbrev_prefix_str, default_str, options)
    }

    /// Port of the private `StringDataInstance.isValidOffcutOffset(int)`.
    ///
    /// The Java source's `switch` on `stringLayout` has no `break` statements, so every case
    /// (including the `default`) executes in sequence and `minValid` ends up `0` regardless of
    /// layout; this port keeps that behavior for fidelity rather than "fixing" what may be an
    /// unintentional bug upstream.
    fn is_valid_offcut_offset(&self, offcut_bytes: i32) -> bool {
        let min_valid = 0;
        offcut_bytes >= min_valid && offcut_bytes < self.data_length()
    }

    /// Port of the private `StringDataInstance.getOffcutLayout()`.
    fn get_offcut_layout(&self) -> StringLayoutEnum {
        match self.string_layout() {
            StringLayoutEnum::Pascal255 | StringLayoutEnum::Pascal64k => StringLayoutEnum::FixedLen,
            other => other,
        }
    }

    /// Port of the private `StringDataInstance.getCharOffset(int)`.
    fn get_char_offset(&self, char_count: i32) -> i32 {
        let char_bytes = char_count * self.char_size();
        match self.string_layout() {
            StringLayoutEnum::Pascal255 => (SIZEOF_PASCAL255_STR_LEN_FIELD + char_bytes).max(0),
            StringLayoutEnum::Pascal64k => (SIZEOF_PASCAL64K_STR_LEN_FIELD + char_bytes).max(0),
            _ => char_bytes,
        }
    }

    /// Resolves the charset actually used to encode/decode this instance's bytes, expanding a
    /// BOM-style charset name (`UTF-16`/`UTF-32`) to its `BE`/`LE` variant using
    /// [`endian_setting`](Self::endian_setting) or, failing that, the backing buffer's
    /// endianness. Port of the encode-side half of the private
    /// `StringDataInstance.getAdjustedCharsetInfo()` (the decode side additionally sniffs a
    /// byte-order-mark from the data; see [`decode_string`]).
    fn resolve_output_charset(&self) -> String {
        let name = self.charset_name();
        if !is_bom_charset(&name) {
            return name;
        }
        let endian = self.endian_setting().unwrap_or_else(|| {
            self.mem_buffer()
                .map(|b| if b.is_big_endian() { Endian::Big } else { Endian::Little })
                .unwrap_or(Endian::Little)
        });
        format!("{name}{}", endian.to_short_string())
    }

    /// Port of `StringDataInstance.encodeReplacementFromStringValue(CharSequence)`, limited to
    /// the charsets [`decode_string`]/[`encode_string`] support.
    fn encode_replacement_from_string_value(&self, value: &str) -> Result<Vec<u8>, String> {
        let encoded = encode_string(value, &self.resolve_output_charset())?;
        let laid_out = self.check_and_encode_layout(&encoded)?;
        Ok(self.convert_unpadded_to_padded(&laid_out))
    }

    /// Port of the private `StringDataInstance.checkAndEncodeLayout(ByteBuffer)`.
    fn check_and_encode_layout(&self, encoded: &[u8]) -> Result<Vec<u8>, String> {
        let length = self.data_length();
        let char_size = self.char_size();
        match self.string_layout() {
            StringLayoutEnum::CharSeq | StringLayoutEnum::FixedLen => {
                if length != -1 && encoded.len() as i32 > length {
                    return Err("Encoded string does not fit".to_string());
                }
                let out_len = if length != -1 { length } else { encoded.len() as i32 };
                let mut result = vec![0u8; out_len.max(0) as usize];
                let n = encoded.len().min(result.len());
                result[..n].copy_from_slice(&encoded[..n]);
                Ok(result)
            }
            StringLayoutEnum::NullTerminatedBounded => {
                if length != -1 && encoded.len() as i32 + char_size > length {
                    return Err("Encoded string does not fit".to_string());
                }
                let mut result = vec![0u8; encoded.len() + char_size.max(0) as usize];
                result[..encoded.len()].copy_from_slice(encoded);
                Ok(result)
            }
            StringLayoutEnum::NullTerminatedUnbounded => {
                let mut result = vec![0u8; encoded.len() + char_size.max(0) as usize];
                result[..encoded.len()].copy_from_slice(encoded);
                Ok(result)
            }
            StringLayoutEnum::Pascal255 => {
                if encoded.len() >= (1usize << (8 * SIZEOF_PASCAL255_STR_LEN_FIELD)) {
                    return Err("Encoded string does not fit".to_string());
                }
                let mut result = Vec::with_capacity(encoded.len() + SIZEOF_PASCAL255_STR_LEN_FIELD as usize);
                result.push(encoded.len() as u8);
                result.extend_from_slice(encoded);
                Ok(result)
            }
            StringLayoutEnum::Pascal64k => {
                if encoded.len() >= (1usize << (8 * SIZEOF_PASCAL64K_STR_LEN_FIELD)) {
                    return Err("Encoded string does not fit".to_string());
                }
                let big_endian = self.mem_buffer().map(|b| b.is_big_endian()).unwrap_or(false);
                let len_bytes = if big_endian {
                    (encoded.len() as u16).to_be_bytes()
                } else {
                    (encoded.len() as u16).to_le_bytes()
                };
                let mut result = Vec::with_capacity(encoded.len() + 2);
                result.extend_from_slice(&len_bytes);
                result.extend_from_slice(encoded);
                Ok(result)
            }
        }
    }
}

/// Port of `StringDataInstance.toString()`.
impl fmt::Display for dyn StringDataInstance + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_string_value().unwrap_or_default())
    }
}

/// Port of the static `StringDataInstance.makeStringLabel(String, String, DataTypeDisplayOptions)`.
///
/// Simplified relative to Java: non-displayable runs collapse to a single `_` exactly as upstream,
/// but this port does not additionally prefix the label with a summary of which Unicode scripts
/// were found (Java's `foundScripts`/`scriptSummary` machinery), since that needs a full
/// `Character.UnicodeScript.of(codePoint)` classification table this crate does not have.
pub fn make_string_label(prefix_str: &str, s: &str, options: &dyn DataTypeDisplayOptions) -> String {
    let max_len = options.get_label_string_length();
    let mut needs_underscore = false;
    let mut buffer = String::new();
    for c in s.chars() {
        if buffer.chars().count() as i32 >= max_len {
            break;
        }
        if is_displayable(c) && c != ' ' {
            if needs_underscore {
                if !buffer.is_empty() {
                    buffer.push('_');
                }
                needs_underscore = false;
            }
            buffer.push(c);
        } else {
            needs_underscore = true;
        }
    }
    format!("{prefix_str}{buffer}")
}

/// Port of `ghidra.util.StringUtilities.isDisplayable(int)`.
fn is_displayable(c: char) -> bool {
    (0x20..0x7F).contains(&(c as u32))
}

/// Port of the private `StringDataInstance.trimNulls(String)`.
fn trim_nulls(s: &str) -> String {
    s.trim_end_matches('\u{0}').to_string()
}

/// Port of `ghidra.util.charset.CharsetInfoManager.isBOMCharset(String)`, using the already-ported
/// `CHARSET_UTF16`/`CHARSET_UTF32` placeholder constants.
fn is_bom_charset(charset_name: &str) -> bool {
    charset_name == CHARSET_UTF16 || charset_name == CHARSET_UTF32
}

/// Port of the private `StringDataInstance.convertPaddedToUnpadded(byte[])`, as a free function so
/// [`OffcutView`] and the trait's default methods can share it.
fn convert_padded_to_unpadded(padded_bytes: &[u8], char_size: i32, padded_char_size: i32, big_endian: bool) -> Vec<u8> {
    if padded_char_size == char_size || char_size <= 0 || padded_char_size <= 0 {
        return padded_bytes.to_vec();
    }
    let cs = char_size as usize;
    let pcs = padded_char_size as usize;
    let mut out = Vec::with_capacity((padded_bytes.len() / pcs) * cs);
    let mut src = if big_endian { pcs - cs } else { 0 };
    while src + cs <= padded_bytes.len() {
        out.extend_from_slice(&padded_bytes[src..src + cs]);
        src += pcs;
    }
    out
}

/// Port of the private `StringDataInstance.convertUnpaddedToPadded(byte[])`.
fn convert_unpadded_to_padded(unpadded_bytes: &[u8], char_size: i32, padded_char_size: i32, big_endian: bool) -> Vec<u8> {
    if padded_char_size == char_size || char_size <= 0 || padded_char_size <= 0 {
        return unpadded_bytes.to_vec();
    }
    let cs = char_size as usize;
    let pcs = padded_char_size as usize;
    let mut out = vec![0u8; (unpadded_bytes.len() / cs) * pcs];
    let mut src = 0;
    let mut dest = if big_endian { pcs - cs } else { 0 };
    while src + cs <= unpadded_bytes.len() && dest + cs <= out.len() {
        out[dest..dest + cs].copy_from_slice(&unpadded_bytes[src..src + cs]);
        src += cs;
        dest += pcs;
    }
    out
}

/// Decodes `bytes` (already unpadded) using `charset_name`, resolving a BOM-style charset name
/// (`UTF-16`/`UTF-32`) to its `BE`/`LE` variant and skipping a leading byte-order-mark if present.
/// Port of the decode-side half of the private `StringDataInstance.getAdjustedCharsetInfo`
/// overloads plus `getStringValueNoTrim`'s `Charset.forName(...).decode(...)` call.
fn decode_string(charset_name: &str, char_size: i32, bytes: &[u8], endian_setting: Option<Endian>, mem_big_endian: bool) -> Option<String> {
    let (effective_name, skip) = if is_bom_charset(charset_name) {
        let (bom_endian, consumed) = detect_bom(bytes, char_size);
        let endian = bom_endian.or(endian_setting).unwrap_or(if mem_big_endian { Endian::Big } else { Endian::Little });
        (format!("{charset_name}{}", endian.to_short_string()), consumed)
    } else {
        (charset_name.to_string(), 0)
    };
    decode_with_charset(&effective_name, bytes.get(skip..)?)
}

/// Port of the private `StringDataInstance.getEndiannessFromBOM(byte[], int)`.
fn detect_bom(bytes: &[u8], char_size: i32) -> (Option<Endian>, usize) {
    let cs = char_size as usize;
    if cs == 0 || cs > 4 || bytes.len() < cs {
        return (None, 0);
    }
    let mut padded = [0u8; 4];
    padded[4 - cs..].copy_from_slice(&bytes[..cs]);
    let be_val = u32::from_be_bytes(padded);
    match be_val {
        0x0000_FEFF => (Some(Endian::Big), cs),
        0x0000_FFFE => (Some(Endian::Little), cs),
        0xFFFE_0000 => (Some(Endian::Little), cs),
        _ => (None, 0),
    }
}

/// Decodes `bytes` using one of the charsets this crate supports without a full
/// `java.nio.charset.Charset` registry. See the module docs.
fn decode_with_charset(name: &str, bytes: &[u8]) -> Option<String> {
    match name {
        "US-ASCII" => Some(bytes.iter().map(|&b| if b.is_ascii() { b as char } else { char::REPLACEMENT_CHARACTER }).collect()),
        "ISO-8859-1" => Some(bytes.iter().map(|&b| b as char).collect()),
        "UTF-8" => Some(String::from_utf8_lossy(bytes).into_owned()),
        "UTF-16BE" => decode_utf16_bytes(bytes, true),
        "UTF-16LE" => decode_utf16_bytes(bytes, false),
        "UTF-32BE" => decode_utf32_bytes(bytes, true),
        "UTF-32LE" => decode_utf32_bytes(bytes, false),
        _ => None,
    }
}

fn decode_utf16_bytes(bytes: &[u8], big_endian: bool) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units = bytes
        .chunks_exact(2)
        .map(|c| if big_endian { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) });
    Some(char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)).collect())
}

fn decode_utf32_bytes(bytes: &[u8], big_endian: bool) -> Option<String> {
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut s = String::new();
    for c in bytes.chunks_exact(4) {
        let v = if big_endian {
            u32::from_be_bytes([c[0], c[1], c[2], c[3]])
        } else {
            u32::from_le_bytes([c[0], c[1], c[2], c[3]])
        };
        s.push(char::from_u32(v).unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    Some(s)
}

/// Encodes `value` using one of the charsets this crate supports without a full
/// `java.nio.charset.Charset` registry. See the module docs.
///
/// `pub(crate)` so [`AbstractStringDataType`](super::abstract_string_data_type) can reuse it for
/// its own `encode_replacement_from_char_value`/`encode_replacement_from_char_representation`
/// implementations, which (per Java) skip the layout/padding wrapping
/// [`StringDataInstance::encode_replacement_from_string_value`] applies.
pub(crate) fn encode_string(value: &str, charset_name: &str) -> Result<Vec<u8>, String> {
    match charset_name {
        "US-ASCII" => {
            if value.chars().all(|c| c.is_ascii()) {
                Ok(value.bytes().collect())
            } else {
                Err(format!("Cannot encode non-ASCII characters as {charset_name}"))
            }
        }
        "ISO-8859-1" => {
            if value.chars().all(|c| (c as u32) < 256) {
                Ok(value.chars().map(|c| c as u8).collect())
            } else {
                Err(format!("Cannot encode characters outside Latin-1 as {charset_name}"))
            }
        }
        "UTF-8" => Ok(value.as_bytes().to_vec()),
        "UTF-16BE" => Ok(value.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()),
        "UTF-16LE" => Ok(value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()),
        "UTF-32BE" => Ok(value.chars().flat_map(|c| (c as u32).to_be_bytes()).collect()),
        "UTF-32LE" => Ok(value.chars().flat_map(|c| (c as u32).to_le_bytes()).collect()),
        _ => Err(format!("Unsupported charset: {charset_name}")),
    }
}

/// A [`MemBuffer`] adapter that adds a fixed byte offset to every access, standing in for the
/// `WrappedMemBuffer` Java constructs inside `getByteOffcut`. See the module docs for why this
/// crate uses a borrowing adapter here instead of the real (but lifetime-incompatible)
/// `WrappedMemBuffer` port.
struct OffsetMemBuffer<'a> {
    inner: &'a dyn MemBuffer,
    offset: i32,
}

impl MemBuffer for OffsetMemBuffer<'_> {
    fn get_address(&self) -> Address {
        self.inner.get_address().add(self.offset as i64).unwrap_or_else(|_| self.inner.get_address())
    }

    fn is_initialized_memory(&self) -> bool {
        self.inner.is_initialized_memory()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.inner.get_byte(offset + self.offset)
    }

    fn get_bytes(&self, buffer: &mut [u8], offset: i32) -> usize {
        self.inner.get_bytes(buffer, offset + self.offset)
    }

    fn get_signed_byte(&self, offset: i32) -> Result<i8, MemoryAccessException> {
        self.inner.get_signed_byte(offset + self.offset)
    }

    fn get_short(&self, offset: i32) -> Result<i16, MemoryAccessException> {
        self.inner.get_short(offset + self.offset)
    }

    fn get_int(&self, offset: i32) -> Result<i32, MemoryAccessException> {
        self.inner.get_int(offset + self.offset)
    }



    fn is_big_endian(&self) -> bool {
        self.inner.is_big_endian()
    }
}

/// A borrowed offcut view over another [`StringDataInstance`]'s data, used by
/// [`StringDataInstance::get_offcut_label_string`]. Standing in for what Java produces from
/// `getByteOffcut`, minus materializing a whole new (boxed, owned) instance -- see the module
/// docs. Holds copies of the handful of accessor values `get_label` actually needs rather than a
/// `&dyn StringDataInstance` back-reference, since a default trait method cannot unsize `&Self` to
/// `&dyn StringDataInstance` without requiring `Self: Sized` (which would make the method
/// uncallable through a `dyn StringDataInstance`).
struct OffcutView<'a> {
    charset_name: String,
    char_size: i32,
    padded_char_size: i32,
    layout: StringLayoutEnum,
    length: i32,
    buf: OffsetMemBuffer<'a>,
    endian_setting: Option<Endian>,
    render_setting: RenderEnum,
}

impl StringDataInstance for OffcutView<'_> {
    /// Not meaningful for an offcut label-only view; nothing in
    /// [`get_offcut_label_string`](StringDataInstance::get_offcut_label_string)'s call path
    /// (`get_label`) invokes this.
    fn encode_replacement_from_char_value(&self, _value: &[char]) -> Result<Vec<u8>, String> {
        Err("OffcutView does not support encoding".to_string())
    }

    /// See [`encode_replacement_from_char_value`](Self::encode_replacement_from_char_value).
    fn encode_replacement_from_char_representation(&self, _repr: &str) -> Result<Vec<u8>, String> {
        Err("OffcutView does not support encoding".to_string())
    }

    fn charset_name(&self) -> String {
        self.charset_name.clone()
    }

    fn char_size(&self) -> i32 {
        self.char_size
    }

    fn padded_char_size(&self) -> i32 {
        self.padded_char_size
    }

    fn string_layout(&self) -> StringLayoutEnum {
        self.layout
    }

    fn translated_value(&self) -> Option<String> {
        None
    }

    fn endian_setting(&self) -> Option<Endian> {
        self.endian_setting
    }

    fn show_translation(&self) -> bool {
        false
    }

    fn render_setting(&self) -> RenderEnum {
        self.render_setting
    }

    fn data_length(&self) -> i32 {
        self.length
    }

    fn mem_buffer(&self) -> Option<&dyn MemBuffer> {
        Some(&self.buf)
    }
}

/// A [`StringDataInstance`] that represents a non-existent string. Port of
/// `StringDataInstance.StaticStringInstance`, including its `NULL_INSTANCE` usage (see
/// [`null_instance`]).
pub struct StaticStringInstance {
    fake_str: Option<String>,
    fake_len: i32,
}

impl StaticStringInstance {
    /// Port of the `StaticStringInstance(String, int)` constructor.
    pub fn new(fake_str: Option<String>, fake_len: i32) -> Self {
        StaticStringInstance { fake_str, fake_len }
    }
}

/// Port of `StringDataInstance.NULL_INSTANCE`.
pub fn null_instance() -> StaticStringInstance {
    StaticStringInstance::new(None, -1)
}

impl StringDataInstance for StaticStringInstance {
    fn encode_replacement_from_char_value(&self, _value: &[char]) -> Result<Vec<u8>, String> {
        Err("StaticStringInstance has no backing memory to encode into".to_string())
    }

    fn encode_replacement_from_char_representation(&self, _repr: &str) -> Result<Vec<u8>, String> {
        Err("StaticStringInstance has no backing memory to encode into".to_string())
    }

    fn get_string_value(&self) -> Option<String> {
        self.fake_str.clone()
    }

    fn get_string_representation(&self) -> String {
        self.fake_str.clone().unwrap_or_default()
    }

    fn get_string_representation_for(&self, _original_or_translated: bool) -> String {
        self.fake_str.clone().unwrap_or_default()
    }

    fn get_string_length(&self) -> i32 {
        self.fake_len
    }

    fn get_label(
        &self,
        _prefix_str: &str,
        _abbrev_prefix_str: &str,
        default_str: &str,
        _options: &dyn DataTypeDisplayOptions,
    ) -> String {
        default_str.to_string()
    }

    fn get_offcut_label_string(
        &self,
        _prefix_str: &str,
        _abbrev_prefix_str: &str,
        default_str: &str,
        _options: &dyn DataTypeDisplayOptions,
        _byte_offset: i32,
    ) -> String {
        default_str.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::SpecialAddress;
    use crate::program::model::data::data_type_display_options::DEFAULT;

    struct BytesBuffer {
        data: Vec<u8>,
        big_endian: bool,
    }

    impl MemBuffer for BytesBuffer {
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }

        fn is_initialized_memory(&self) -> bool {
            true
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.data.get(offset as usize).map(|&b| b ).ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_unsigned_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.data.get(offset as usize).copied().ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_short(&self, offset: i32) -> Result<i16, MemoryAccessException> {
            let o = offset as usize;
            let b = self.data.get(o..o + 2).ok_or_else(|| MemoryAccessException::new("out of bounds"))?;
            Ok(if self.big_endian { i16::from_be_bytes([b[0], b[1]]) } else { i16::from_le_bytes([b[0], b[1]]) })
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

    struct TestInstance<'a> {
        charset_name: String,
        char_size: i32,
        padded_char_size: i32,
        layout: StringLayoutEnum,
        length: i32,
        buf: Option<&'a dyn MemBuffer>,
    }

    impl StringDataInstance for TestInstance<'_> {
        fn encode_replacement_from_char_value(&self, value: &[char]) -> Result<Vec<u8>, String> {
            encode_string(&value.iter().collect::<String>(), &self.resolve_output_charset())
        }

        fn encode_replacement_from_char_representation(&self, repr: &str) -> Result<Vec<u8>, String> {
            encode_string(repr, &self.resolve_output_charset())
        }

        fn charset_name(&self) -> String {
            self.charset_name.clone()
        }

        fn char_size(&self) -> i32 {
            self.char_size
        }

        fn padded_char_size(&self) -> i32 {
            self.padded_char_size
        }

        fn string_layout(&self) -> StringLayoutEnum {
            self.layout
        }

        fn data_length(&self) -> i32 {
            self.length
        }

        fn mem_buffer(&self) -> Option<&dyn MemBuffer> {
            self.buf
        }
    }

    #[test]
    fn null_terminated_unbounded_reads_up_to_nul() {
        let buf = BytesBuffer { data: b"Hello\0World".to_vec(), big_endian: false };
        // A non-probe length (Java's `length != -1`) is required for `get_string_value` to
        // return anything at all -- like Java, `isProbe()` (`length == -1`) short-circuits
        // `getStringValueNoTrim` to `null` even though `NULL_TERMINATED_UNBOUNDED` still searches
        // for a terminator independent of `length` when computing `get_string_length`.
        let inst = TestInstance {
            charset_name: "US-ASCII".to_string(),
            char_size: 1,
            padded_char_size: 1,
            layout: StringLayoutEnum::NullTerminatedUnbounded,
            length: 11,
            buf: Some(&buf),
        };
        assert_eq!(inst.get_string_length(), 6);
        assert_eq!(inst.get_string_value(), Some("Hello".to_string()));
        assert_eq!(inst.get_string_representation(), "\"Hello\"".to_string());
    }

    #[test]
    fn missing_null_terminator_detected_when_absent() {
        let buf = BytesBuffer { data: b"Hello".to_vec(), big_endian: false };
        let inst = TestInstance {
            charset_name: "US-ASCII".to_string(),
            char_size: 1,
            padded_char_size: 1,
            layout: StringLayoutEnum::NullTerminatedBounded,
            length: 5,
            buf: Some(&buf),
        };
        assert_eq!(inst.get_string_value(), Some("Hello".to_string()));
        assert!(inst.is_missing_null_terminator());
    }

    #[test]
    fn pascal255_decodes_length_prefixed_bytes() {
        let buf = BytesBuffer { data: vec![5, b'H', b'i', b'y', b'a', b'!'], big_endian: false };
        let inst = TestInstance {
            charset_name: "US-ASCII".to_string(),
            char_size: 1,
            padded_char_size: 1,
            layout: StringLayoutEnum::Pascal255,
            length: 6,
            buf: Some(&buf),
        };
        assert_eq!(inst.get_string_length(), 6);
        assert_eq!(inst.get_string_value(), Some("Hiya!".to_string()));
    }

    #[test]
    fn utf16be_round_trip_through_decode() {
        let mut data = Vec::new();
        for u in "Hi".encode_utf16() {
            data.extend_from_slice(&u.to_be_bytes());
        }
        data.extend_from_slice(&0u16.to_be_bytes());
        let data_len = data.len() as i32;
        let buf = BytesBuffer { data, big_endian: true };
        // See the `length` comment on `null_terminated_unbounded_reads_up_to_nul`: a probe
        // (`length == -1`) makes `get_string_value` return `None`.
        let inst = TestInstance {
            charset_name: "UTF-16BE".to_string(),
            char_size: 2,
            padded_char_size: 2,
            layout: StringLayoutEnum::NullTerminatedUnbounded,
            length: data_len,
            buf: Some(&buf),
        };
        assert_eq!(inst.get_string_value(), Some("Hi".to_string()));
    }

    #[test]
    fn get_offcut_label_string_reads_through_adjusted_buffer() {
        let buf = BytesBuffer { data: b"XXCAT".to_vec(), big_endian: false };
        let inst = TestInstance {
            charset_name: "US-ASCII".to_string(),
            char_size: 1,
            padded_char_size: 1,
            layout: StringLayoutEnum::FixedLen,
            length: 5,
            buf: Some(&buf),
        };
        let label = inst.get_offcut_label_string("STR_", "S", "?", &DEFAULT, 2);
        assert_eq!(label, "STR_CAT".to_string());
    }

    #[test]
    fn get_offcut_label_string_invalid_offset_returns_default() {
        let buf = BytesBuffer { data: b"XXCAT".to_vec(), big_endian: false };
        let inst = TestInstance {
            charset_name: "US-ASCII".to_string(),
            char_size: 1,
            padded_char_size: 1,
            layout: StringLayoutEnum::FixedLen,
            length: 5,
            buf: Some(&buf),
        };
        assert_eq!(inst.get_offcut_label_string("STR_", "S", "?", &DEFAULT, 5), "?".to_string());
    }

    #[test]
    fn null_instance_overrides_return_fallbacks() {
        let inst = null_instance();
        assert_eq!(inst.get_string_value(), None);
        assert_eq!(inst.get_string_length(), -1);
        assert_eq!(inst.get_label("P", "A", "DEF", &DEFAULT), "DEF".to_string());
        assert_eq!(inst.get_offcut_label_string("P", "A", "DEF", &DEFAULT, 0), "DEF".to_string());
    }

    #[test]
    fn make_string_label_replaces_non_displayable_runs_with_underscore() {
        let label = make_string_label("STR_", "ab\tcd", &DEFAULT);
        assert_eq!(label, "STR_ab_cd".to_string());
    }

    #[test]
    fn usable_as_trait_object_and_displays_string_value() {
        let buf = BytesBuffer { data: b"Hello\0".to_vec(), big_endian: false };
        let inst = TestInstance {
            charset_name: "US-ASCII".to_string(),
            char_size: 1,
            padded_char_size: 1,
            layout: StringLayoutEnum::NullTerminatedUnbounded,
            length: 6,
            buf: Some(&buf),
        };
        let dyn_ref: &dyn StringDataInstance = &inst;
        assert_eq!(dyn_ref.get_string_value(), Some("Hello".to_string()));
        assert_eq!(format!("{dyn_ref}"), "Hello".to_string());
    }

    #[test]
    fn encode_replacement_from_string_value_round_trips_ascii() {
        let buf = BytesBuffer { data: vec![0u8; 8], big_endian: false };
        let inst = TestInstance {
            charset_name: "US-ASCII".to_string(),
            char_size: 1,
            padded_char_size: 1,
            layout: StringLayoutEnum::NullTerminatedUnbounded,
            length: -1,
            buf: Some(&buf),
        };
        let encoded = inst.encode_replacement_from_string_value("Hi").unwrap();
        assert_eq!(encoded, b"Hi\0".to_vec());
    }
}
