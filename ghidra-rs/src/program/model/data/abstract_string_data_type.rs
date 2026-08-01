//! Port of `ghidra.program.model.data.AbstractStringDataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn implements Dynamic, DataTypeWithCharset`. `BuiltIn` itself is
//! not yet ported, so -- mirroring [`AbstractFloatDataType`](super::abstract_float_data_type::AbstractFloatDataType)
//! and [`AbstractComplexDataType`](super::abstract_complex_data_type::AbstractComplexDataType) --
//! this trait extends [`DataType`] + [`Dynamic`] + [`DataTypeWithCharset`] directly, the
//! already-ported interfaces `BuiltIn`/`Dynamic`/`DataTypeWithCharset` that `AbstractStringDataType`
//! actually relies on (`Dynamic` itself already carries [`BuiltInDataType`] as a supertrait).
//!
//! Several Java methods here share a name with an already-provided default method on [`DataType`]
//! (`getMnemonic`, `getLength`, `getDescription`, `getValue`, `isEncodable`, `encodeValue`,
//! `getRepresentation`, `encodeRepresentation`, `getValueClass`, `getDefaultLabelPrefix`,
//! `getDefaultAbbreviatedLabelPrefix`, `getDefaultLabelPrefix(MemBuffer,..)`,
//! `getDefaultOffcutLabelPrefix`), [`Dynamic`] (`canSpecifyLength`, `getReplacementBaseType`), or
//! [`DataTypeWithCharset`] (`getCharsetName`). Rust does not allow a subtrait to override a
//! supertrait's method (default or required) by redeclaring the same name -- it would just create
//! an ambiguous method for any type implementing both -- so, mirroring the convention established
//! by [`CharDataType`](super::char_data_type::CharDataType) and the two `Abstract*DataType` traits
//! above, those overrides are exposed here under distinct `string_*` names. A concrete
//! implementation (once `BuiltIn` and the various concrete string data types -- `StringDataType`,
//! `TerminatedStringDataType`, `PascalStringDataType`, etc. -- are ported) should implement
//! `DataType`/`Dynamic`/`DataTypeWithCharset` directly and delegate to these helpers.
//!
//! The Java class's constructor-derived `final` fields (`mnemonic`, `description`,
//! `replacementDataType`, `stringLayout`, `defaultLabel`, `defaultLabelPrefix`,
//! `defaultAbbrevLabelPrefix`, and the optional `charsetName`) have no home on a trait (traits
//! cannot declare constructors or store fields), so -- mirroring
//! [`StringDataInstance`]'s own accessor convention -- they are modeled as required `&self`
//! accessor methods (`charset_name_override` gets a `None` default, mirroring the Java static
//! sentinel `USE_CHARSET_DEF_DEFAULT = null`); implementors are expected to store the real values
//! themselves and return them from these accessors.
//!
//! [`getStringDataInstance(MemBuffer, Settings, int)`](AbstractStringDataType::get_string_data_instance)
//! constructs the real `new StringDataInstance(this, settings, buf, length)` call, using
//! `getCharsetNameFromDataTypeOrSettings`/`getLayoutFromDataType`'s `this instanceof
//! AbstractStringDataType`/`this instanceof DataTypeWithCharset` branches directly (since `this`
//! -- `self` here -- always satisfies both). Two simplifications from the Java original, both
//! consistent with scope already dropped elsewhere in this port:
//! - `paddedCharSize` does not special-case `ArrayStringable` data types (Java only pads when
//!   `dataType instanceof ArrayStringable && charSize == 1`, using
//!   `dtm.getDataOrganization().getCharSize()`); this port always uses `paddedCharSize ==
//!   charSize`. A concrete `ArrayStringable` string type that needs padding can construct its own
//!   [`StringDataInstance`] directly instead of going through this default.
//! - `translatedValue` is always `None`: the real lookup needs `settings instanceof Data` plus
//!   `Program.getUsrPropertyManager()`, which -- per
//!   [`TranslationSettingsDefinition`]'s own module docs -- this port does not have access to.
//!
//! Because [`get_string_data_instance`](AbstractStringDataType::get_string_data_instance) is a
//! new method (not overriding anything), it is free to tie its returned box's lifetime to `buf`'s
//! lifetime (`Box<dyn StringDataInstance + 'a>`) instead of the implicit `'static` bound
//! [`DataTypeWithCharset::string_data_instance`] carries; every use within this trait consumes
//! the box immediately (matching every actual Java call site), so the shorter lifetime is never a
//! problem here. A concrete `impl DataTypeWithCharset for ...` cannot delegate `string_data_instance`
//! straight to `get_string_data_instance`, though, since that method's `'static` box cannot borrow
//! a non-`'static` `buf`; see the `impl DataTypeWithCharset` block in this module's tests for how
//! the mock sidesteps that (by not holding `buf` at all, matching how [`StaticStringInstance`]
//! already ignores its backing buffer).
//!
//! `encodeReplacementFromCharValue`/`encodeReplacementFromCharRepresentation`'s parsing/encoding
//! goes through the same charset table [`string_data_instance`] already established (`US-ASCII`,
//! `UTF-8`, `ISO-8859-1`, `UTF-16BE`/`LE`, `UTF-32BE`/`LE`), reusing its `pub(crate)`
//! `encode_string` helper directly -- unlike [`StringDataInstance::encode_replacement_from_string_value`],
//! the Java originals apply no layout/padding wrapping, so the higher-level default method is not
//! reused here.
//!
//! `getCharsetName`'s charset-name-to-byte-width mapping (`CharsetInfoManager.getCharsetCharSize`)
//! is reproduced as the free function [`charset_char_size`], limited to the same charset names
//! [`string_data_instance`] supports.
//!
//! Not ported: the constructor itself (see above), and the two static factory-style TODOs the
//! Java source already leaves as comments on `getLength(MemBuffer, int)` ("when does buf == null?
//! ... round result to paddedCharSize if buf == null").

use std::any::TypeId;

use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_with_charset::{DataTypeEncodeError, DataTypeWithCharset};
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::data::endian_settings_definition::{self, EndianSettingsDefinition};
use crate::program::model::data::render_unicode_settings_definition::{RenderEnum, RenderUnicodeSettingsDefinition};
use crate::program::model::data::string_data_instance::{encode_string, StringDataInstance, DEFAULT_CHARSET_NAME};
use crate::program::model::data::string_layout_enum::StringLayoutEnum;
use crate::program::model::data::translation_settings_definition::TranslationSettingsDefinition;
use crate::program::model::lang::endian::Endian;
use crate::program::seam_stubs::{CharsetSettingsDefinition, MemBuffer};

/// Port of `AbstractStringDataType.DEFAULT_UNICODE_LABEL`.
pub const DEFAULT_UNICODE_LABEL: &str = "UNICODE";
/// Port of `AbstractStringDataType.DEFAULT_UNICODE_LABEL_PREFIX`.
pub const DEFAULT_UNICODE_LABEL_PREFIX: &str = "UNI";
/// Port of `AbstractStringDataType.DEFAULT_UNICODE_ABBREV_PREFIX`.
pub const DEFAULT_UNICODE_ABBREV_PREFIX: &str = "u";

/// Port of `AbstractStringDataType.DEFAULT_LABEL`.
pub const DEFAULT_LABEL: &str = "STRING";
/// Port of `AbstractStringDataType.DEFAULT_LABEL_PREFIX`.
pub const DEFAULT_LABEL_PREFIX: &str = "STR";
/// Port of `AbstractStringDataType.DEFAULT_ABBREV_PREFIX`.
pub const DEFAULT_ABBREV_PREFIX: &str = "s";

/// Port of `AbstractStringDataType.USE_CHARSET_DEF_DEFAULT`, the sentinel meaning "use the
/// charset settings instead of a fixed charset". Modeled as `None` for
/// [`AbstractStringDataType::charset_name_override`]; kept as a named constant purely for
/// documentation parity with the Java source.
pub const USE_CHARSET_DEF_DEFAULT: Option<&str> = None;

/// Port of `AbstractStringDataType.COMMON_STRING_SETTINGS_DEFS`.
///
/// The Java array is `{ TRANSLATION, RENDER }`; `TRANSLATION` is omitted here because the ported
/// [`TranslationSettingsDefinition`] does not itself implement [`SettingsDefinition`] (only its
/// internal `JavaEnumSettingsDefinition` does) -- the same precedent
/// [`CharDataType::char_settings_definitions`](super::char_data_type::CharDataType::char_settings_definitions)
/// already established.
pub fn common_string_settings_defs() -> Vec<Box<dyn SettingsDefinition>> {
    vec![Box::new(RenderUnicodeSettingsDefinition::DEF)]
}

/// Port of `AbstractStringDataType.COMMON_WITH_CHARSET_STRING_SETTINGS_DEFS`
/// (`SettingsDefinition.concat(COMMON_STRING_SETTINGS_DEFS, CHARSET)`).
pub fn common_with_charset_string_settings_defs() -> Vec<Box<dyn SettingsDefinition>> {
    let mut defs = common_string_settings_defs();
    defs.push(Box::new(CharsetSettingsDefinition::CHARSET));
    defs
}

/// Maps a charset name to its fixed byte width, standing in for
/// `CharsetInfoManager.getCharsetCharSize(String)`. Limited to the charset names
/// [`string_data_instance`](super::string_data_instance) supports (see that module's docs);
/// unrecognized names -- including the single-byte charsets it does support -- default to `1`.
fn charset_char_size(charset_name: &str) -> i32 {
    match charset_name {
        "UTF-16" | "UTF-16BE" | "UTF-16LE" => 2,
        "UTF-32" | "UTF-32BE" | "UTF-32LE" => 4,
        _ => 1,
    }
}

/// [`Settings`] with nothing stored, standing in for `SettingsImpl.NO_SETTINGS`.
struct NoSettings;
impl Settings for NoSettings {}

/// A [`StringDataInstance`] built from an [`AbstractStringDataType`] + [`Settings`] + [`MemBuffer`]
/// + length, standing in for what `new StringDataInstance(dataType, settings, buf, length)`
/// constructs. See the module docs for why its buffer reference's lifetime (`'a`) is not `'static`.
struct StringDataInstanceView<'a> {
    charset_name: String,
    char_size: i32,
    padded_char_size: i32,
    layout: StringLayoutEnum,
    length: i32,
    buf: &'a dyn MemBuffer,
    endian_setting: Option<Endian>,
    show_translation: bool,
    render_setting: RenderEnum,
}

impl StringDataInstance for StringDataInstanceView<'_> {
    fn encode_replacement_from_char_value(&self, value: &[char]) -> Result<Vec<u8>, String> {
        let text: String = value.iter().collect();
        encode_string(&text, &self.resolve_output_charset())
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

    fn translated_value(&self) -> Option<String> {
        None
    }

    fn endian_setting(&self) -> Option<Endian> {
        self.endian_setting
    }

    fn show_translation(&self) -> bool {
        self.show_translation
    }

    fn render_setting(&self) -> RenderEnum {
        self.render_setting
    }

    fn data_length(&self) -> i32 {
        self.length
    }

    fn mem_buffer(&self) -> Option<&dyn MemBuffer> {
        Some(self.buf)
    }
}

/// Common base for all Ghidra string data types.
///
/// Port of `ghidra.program.model.data.AbstractStringDataType`. See the module-level documentation
/// for the conventions used to resolve name clashes with [`DataType`]/[`Dynamic`]/
/// [`DataTypeWithCharset`] and for what was intentionally simplified or left unported.
pub trait AbstractStringDataType: DataType + Dynamic + DataTypeWithCharset {
    /// Stands in for the private final `mnemonic` field.
    fn mnemonic(&self) -> String;

    /// Stands in for the private final `description` field.
    fn description(&self) -> String;

    /// Stands in for the private final `defaultLabel` field.
    fn default_label(&self) -> String;

    /// Stands in for the private final `defaultLabelPrefix` field.
    fn default_label_prefix(&self) -> String;

    /// Stands in for the private final `defaultAbbrevLabelPrefix` field.
    fn default_abbrev_label_prefix(&self) -> String;

    /// Stands in for the private final `stringLayout` field. Unlike the other fields, Java
    /// exposes this one directly via the public `getStringLayout()`, which has no clash with any
    /// already-ported supertrait, so it keeps that name (with the `get_` prefix matching this
    /// crate's usual `getXxx` -> `get_xxx` convention) rather than a bare accessor name.
    fn get_string_layout(&self) -> StringLayoutEnum;

    /// Stands in for the private final `replacementDataType` field, exposed under a distinct name
    /// since [`Dynamic::get_replacement_base_type`] is a required (non-default) supertrait method
    /// of the same underlying Java name and cannot be redeclared here (see the module docs). A
    /// concrete `impl Dynamic for ...` should delegate `get_replacement_base_type` to this,
    /// substituting a fallback datatype for `None` (the Java field may be `null`, but
    /// `Dynamic::get_replacement_base_type` is not optional).
    fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>>;

    /// Stands in for the private final `charsetName` field. Defaults to `None`, mirroring the
    /// Java static sentinel `USE_CHARSET_DEF_DEFAULT = null` most concrete subclasses pass.
    fn charset_name_override(&self) -> Option<String> {
        None
    }

    /// Port of the final `AbstractStringDataType.getMnemonic(Settings)`, exposed under a distinct
    /// name since [`DataType::get_mnemonic`] already provides a default. A concrete `impl
    /// DataType for ...` should delegate `get_mnemonic` to this.
    fn string_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.mnemonic()
    }

    /// Port of the final `AbstractStringDataType.getDefaultLabelPrefix()`, exposed under a
    /// distinct name since [`DataType::get_default_label_prefix`] already provides a default. A
    /// concrete `impl DataType for ...` should delegate `get_default_label_prefix` to this.
    fn string_default_label_prefix(&self) -> String {
        self.default_label_prefix()
    }

    /// Port of the final `AbstractStringDataType.getDefaultAbbreviatedLabelPrefix()`, exposed
    /// under a distinct name since [`DataType::get_default_abbreviated_label_prefix`] already
    /// provides a default. A concrete `impl DataType for ...` should delegate
    /// `get_default_abbreviated_label_prefix` to this.
    fn string_default_abbreviated_label_prefix(&self) -> String {
        self.default_abbrev_label_prefix()
    }

    /// Port of the final `AbstractStringDataType.getDescription()`, exposed under a distinct name
    /// since [`DataType::get_description`] already provides a default. A concrete `impl DataType
    /// for ...` should delegate `get_description` to this.
    fn string_description(&self) -> String {
        self.description()
    }

    /// Port of the protected `AbstractStringDataType.getBuiltInSettingsDefinitions()`, computed
    /// from [`charset_name_override`](Self::charset_name_override) exactly like the Java
    /// constructor computes the private `settingsDefinition` field.
    fn get_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        match self.charset_name_override() {
            Some(_) => common_string_settings_defs(),
            None => common_with_charset_string_settings_defs(),
        }
    }

    /// Port of `AbstractStringDataType.getStringDataInstance(MemBuffer, Settings, int)`. See the
    /// module-level documentation for why the returned box's lifetime is tied to `buf` (`'a`)
    /// rather than `'static`.
    fn get_string_data_instance<'a>(
        &self,
        buf: &'a dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Box<dyn StringDataInstance + 'a> {
        let charset_name = self.string_charset_name(settings);
        let char_size = charset_char_size(&charset_name);
        let endian_setting = match EndianSettingsDefinition::DEF.get_choice(settings) {
            endian_settings_definition::BIG => Some(Endian::Big),
            endian_settings_definition::LITTLE => Some(Endian::Little),
            _ => None,
        };
        Box::new(StringDataInstanceView {
            charset_name,
            char_size,
            padded_char_size: char_size,
            layout: self.get_string_layout(),
            length,
            buf,
            endian_setting,
            show_translation: TranslationSettingsDefinition::new().is_show_translated(settings),
            render_setting: RenderUnicodeSettingsDefinition::DEF.get_enum_value(settings),
        })
    }

    /// Port of the overridden `AbstractStringDataType.getCharsetName(Settings)`, exposed under a
    /// distinct name since [`DataTypeWithCharset::get_charset_name`] already provides a default.
    /// A concrete `impl DataTypeWithCharset for ...` should delegate `get_charset_name` to this.
    fn string_charset_name(&self, settings: &dyn Settings) -> String {
        match self.charset_name_override() {
            Some(name) => name,
            None => CharsetSettingsDefinition::CHARSET.get_charset(settings, DEFAULT_CHARSET_NAME),
        }
    }

    /// Port of the overridden `AbstractStringDataType.getLength()`, exposed under a distinct name
    /// since [`DataType::get_length`] already provides a default. Always `-1` (length is
    /// determined dynamically). A concrete `impl DataType for ...` should delegate `get_length`
    /// to this.
    fn string_length(&self) -> i32 {
        -1
    }

    /// Port of the overridden `AbstractStringDataType.canSpecifyLength()`, exposed under a
    /// distinct name since [`Dynamic::can_specify_length`] already provides a default. Always
    /// `true`. A concrete `impl Dynamic for ...` should delegate `can_specify_length` to this.
    fn string_can_specify_length(&self) -> bool {
        true
    }

    /// Port of the overridden `AbstractStringDataType.getLength(MemBuffer, int)`, exposed under a
    /// distinct name since [`Dynamic::get_dynamic_length`] is a required supertrait method of the
    /// same underlying Java name and cannot be redeclared here (see the module docs). A concrete
    /// `impl Dynamic for ...` should delegate `get_dynamic_length` to this.
    fn string_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        self.get_string_data_instance(buf, &NoSettings, max_length).get_string_length()
    }

    /// Port of `AbstractStringDataType.getValueClass(Settings)`, exposed under a distinct name
    /// since [`DataType::get_value_class`] already provides a default. Always identifies
    /// `String`. A concrete `impl DataType for ...` should delegate `get_value_class` to this.
    fn string_value_type_id(&self, settings: &dyn Settings) -> TypeId {
        let _ = settings;
        TypeId::of::<String>()
    }

    /// Port of `AbstractStringDataType.isEncodable()`, exposed under a distinct name since
    /// [`DataType::is_encodable`] already provides a default. Always `true`. A concrete `impl
    /// DataType for ...` should delegate `is_encodable` to this.
    fn is_string_encodable(&self) -> bool {
        true
    }

    /// Port of `AbstractStringDataType.getValue(MemBuffer, Settings, int)`, exposed under a
    /// distinct name since [`DataType::get_value`] already provides a default with a different
    /// return type (`Option<Box<dyn Any>>` vs `Option<String>`). A concrete `impl DataType for
    /// ...` should delegate `get_value` to this.
    fn string_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<String> {
        self.get_string_data_instance(buf, settings, length).get_string_value()
    }

    /// Port of `AbstractStringDataType.encodeValue(Object, MemBuffer, Settings, int)`, exposed
    /// under a distinct name since [`DataType::encode_value`] already provides a default with a
    /// different `value` type (`&dyn Any` vs `&str`). Java's `instanceof CharSequence` runtime
    /// check is replaced by this method only accepting `&str` in the first place. A concrete
    /// `impl DataType for ...` should delegate `encode_value` to this.
    fn string_encode_value(
        &self,
        value: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        self.get_string_data_instance(buf, settings, length)
            .encode_replacement_from_string_value(value)
            .map_err(DataTypeEncodeError)
    }

    /// Port of `AbstractStringDataType.getRepresentation(MemBuffer, Settings, int)`, exposed
    /// under a distinct name since [`DataType::get_representation`] already provides a default. A
    /// concrete `impl DataType for ...` should delegate `get_representation` to this.
    fn string_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        self.get_string_data_instance(buf, settings, length).get_string_representation()
    }

    /// Port of `AbstractStringDataType.encodeRepresentation(String, MemBuffer, Settings, int)`,
    /// exposed under a distinct name since [`DataType::encode_representation`] already provides a
    /// default. Simplified relative to Java: rather than
    /// `StringDataInstance.encodeReplacementFromStringRepresentation` (not ported; see
    /// [`string_data_instance`](super::string_data_instance)'s module docs), this strips a single
    /// pair of surrounding double quotes (if present, matching the simplified quoting
    /// [`StringDataInstance::get_string_rep`] produces) and encodes the rest as a plain string
    /// value. A concrete `impl DataType for ...` should delegate `encode_representation` to this.
    fn string_encode_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let unquoted = repr.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(repr);
        self.get_string_data_instance(buf, settings, length)
            .encode_replacement_from_string_value(unquoted)
            .map_err(DataTypeEncodeError)
    }

    /// Port of `AbstractStringDataType.getDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`, exposed under a distinct name since
    /// [`DataType::get_default_label_prefix_for_data`] already provides a default. A concrete
    /// `impl DataType for ...` should delegate `get_default_label_prefix_for_data` to this.
    fn string_default_label_prefix_for_data(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> String {
        let abbrev_prefix = format!("{}_", self.default_abbrev_label_prefix());
        self.get_string_data_instance(buf, settings, len).get_label(
            &abbrev_prefix,
            &self.default_label_prefix(),
            &self.default_label(),
            options,
        )
    }

    /// Port of `AbstractStringDataType.getDefaultOffcutLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions, int)`, exposed under a distinct name since
    /// [`DataType::get_default_offcut_label_prefix`] already provides a default. A concrete `impl
    /// DataType for ...` should delegate `get_default_offcut_label_prefix` to this.
    fn string_default_offcut_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
        offcut_length: i32,
    ) -> String {
        let abbrev_prefix = format!("{}_", self.default_abbrev_label_prefix());
        self.get_string_data_instance(buf, settings, len).get_offcut_label_string(
            &abbrev_prefix,
            &self.default_label_prefix(),
            &self.default_label(),
            options,
            offcut_length,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use std::any::Any;

    struct BytesBuffer {
        data: Vec<u8>,
    }

    impl MemBuffer for BytesBuffer {
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }

        fn is_initialized_memory(&self) -> bool {
            true
        }

        fn get_bytes_into(&self, buffer: &mut [u8], offset: i32) -> i32 {
            if offset < 0 {
                return 0;
            }
            let o = offset as usize;
            if o >= self.data.len() {
                return 0;
            }
            let n = buffer.len().min(self.data.len() - o);
            buffer[..n].copy_from_slice(&self.data[o..o + n]);
            n as i32
        }

        fn is_big_endian(&self) -> bool {
            false
        }
    }

    /// Fallback used by [`MockStringDataType`]'s `Dynamic::get_replacement_base_type` since that
    /// method is not optional even though the underlying Java field may be `null`.
    struct NoReplacementDataType;
    impl DataType for NoReplacementDataType {}

    struct MockStringDataType;

    impl DataType for MockStringDataType {
        fn get_name(&self) -> String {
            "string".to_string()
        }

        fn get_length(&self) -> i32 {
            self.string_length()
        }

        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.string_mnemonic(settings)
        }

        fn get_default_label_prefix(&self) -> Option<String> {
            Some(self.string_default_label_prefix())
        }

        fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
            Some(self.string_default_abbreviated_label_prefix())
        }

        fn get_description(&self) -> String {
            self.string_description()
        }

        fn get_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
            Some(self.string_value_type_id(settings))
        }

        fn is_encodable(&self) -> bool {
            self.is_string_encodable()
        }

        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.string_value(buf, settings, length).map(|s| Box::new(s) as Box<dyn Any>)
        }

        fn encode_value(
            &self,
            value: &dyn Any,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            length: i32,
        ) -> Result<Vec<u8>, DataTypeEncodeError> {
            let s = value
                .downcast_ref::<String>()
                .ok_or_else(|| DataTypeEncodeError("Requires CharSequence".to_string()))?;
            self.string_encode_value(s, buf, settings, length)
        }

        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.string_representation(buf, settings, length)
        }

        fn encode_representation(
            &self,
            repr: &str,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            length: i32,
        ) -> Result<Vec<u8>, DataTypeEncodeError> {
            self.string_encode_representation(repr, buf, settings, length)
        }

        fn get_default_label_prefix_for_data(
            &self,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            len: i32,
            options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            Some(self.string_default_label_prefix_for_data(buf, settings, len, options))
        }

        fn get_default_offcut_label_prefix(
            &self,
            buf: &dyn MemBuffer,
            settings: &dyn Settings,
            len: i32,
            options: &dyn DataTypeDisplayOptions,
            offcut_offset: i32,
        ) -> Option<String> {
            Some(self.string_default_offcut_label_prefix(buf, settings, len, options, offcut_offset))
        }
    }

    impl BuiltInDataType for MockStringDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }

        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockStringDataType {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.string_dynamic_length(buf, max_length)
        }

        fn can_specify_length(&self) -> bool {
            self.string_can_specify_length()
        }

        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.string_replacement_base_type().unwrap_or_else(|| Box::new(NoReplacementDataType))
        }
    }

    impl DataTypeWithCharset for MockStringDataType {
        fn string_data_instance(&self, settings: &dyn Settings, buf: &dyn MemBuffer) -> Box<dyn StringDataInstance> {
            // `DataTypeWithCharset::string_data_instance` needs a `'static` box, but
            // `get_string_data_instance`'s box borrows `buf`; see the module docs. Since nothing
            // in this smoke test calls through `DataTypeWithCharset` directly, fall back to the
            // buffer-less `StaticStringInstance::NULL_INSTANCE`, matching how that type already
            // ignores its (nonexistent) backing memory.
            let _ = (settings, buf);
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }

        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.string_charset_name(settings)
        }
    }

    impl AbstractStringDataType for MockStringDataType {
        fn mnemonic(&self) -> String {
            "string".to_string()
        }

        fn description(&self) -> String {
            "test string".to_string()
        }

        fn default_label(&self) -> String {
            DEFAULT_LABEL.to_string()
        }

        fn default_label_prefix(&self) -> String {
            DEFAULT_LABEL_PREFIX.to_string()
        }

        fn default_abbrev_label_prefix(&self) -> String {
            DEFAULT_ABBREV_PREFIX.to_string()
        }

        fn get_string_layout(&self) -> StringLayoutEnum {
            StringLayoutEnum::NullTerminatedUnbounded
        }

        fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
    }

    #[test]
    fn usable_as_trait_object_and_computes_dynamic_length_and_value() {
        let dt = MockStringDataType;
        let buf = BytesBuffer { data: b"Hello\0World".to_vec() };
        let settings = NoSettings;

        let dyn_dt: &dyn AbstractStringDataType = &dt;
        assert_eq!(dyn_dt.string_dynamic_length(&buf, 11), 6);
        assert_eq!(dyn_dt.string_value(&buf, &settings, 6), Some("Hello".to_string()));
        assert_eq!(dyn_dt.string_representation(&buf, &settings, 6), "\"Hello\"".to_string());
    }

    #[test]
    fn string_length_and_can_specify_length_match_java_overrides() {
        let dt = MockStringDataType;
        assert_eq!(dt.string_length(), -1);
        assert!(dt.string_can_specify_length());
        assert_eq!(dt.get_length(), -1);
        assert!(dt.can_specify_length());
    }

    #[test]
    fn string_value_type_id_identifies_string() {
        let dt = MockStringDataType;
        let settings = NoSettings;
        assert_eq!(dt.string_value_type_id(&settings), TypeId::of::<String>());
        assert!(dt.is_string_encodable());
    }

    #[test]
    fn encode_value_round_trips_through_get_value() {
        let dt = MockStringDataType;
        let buf = BytesBuffer { data: vec![0u8; 8] };
        let settings = NoSettings;
        let encoded = dt.string_encode_value("Hi", &buf, &settings, -1).expect("encodes");
        assert_eq!(encoded, b"Hi\0".to_vec());
    }

    #[test]
    fn encode_representation_strips_surrounding_quotes() {
        let dt = MockStringDataType;
        let buf = BytesBuffer { data: vec![0u8; 8] };
        let settings = NoSettings;
        let encoded = dt.string_encode_representation("\"Hi\"", &buf, &settings, -1).expect("encodes");
        assert_eq!(encoded, b"Hi\0".to_vec());
    }

    #[test]
    fn default_label_prefix_for_data_uses_string_value() {
        let dt = MockStringDataType;
        let buf = BytesBuffer { data: b"Cat\0".to_vec() };
        let settings = NoSettings;
        let options = crate::program::model::data::data_type_display_options::DEFAULT;
        assert_eq!(
            dt.string_default_label_prefix_for_data(&buf, &settings, 4, &options),
            "s_Cat".to_string()
        );
    }

    #[test]
    fn built_in_settings_definitions_include_charset_when_unspecified() {
        let dt = MockStringDataType;
        assert_eq!(dt.charset_name_override(), None);
        assert_eq!(dt.get_built_in_settings_definitions().len(), 2);
    }

    #[test]
    fn charset_char_size_maps_known_charsets() {
        assert_eq!(charset_char_size("US-ASCII"), 1);
        assert_eq!(charset_char_size("UTF-16BE"), 2);
        assert_eq!(charset_char_size("UTF-32LE"), 4);
        assert_eq!(charset_char_size("UTF-16"), 2);
    }
}
