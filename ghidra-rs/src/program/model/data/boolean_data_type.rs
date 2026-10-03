//! Port of `ghidra.program.model.data.BooleanDataType`.

use std::any::{Any, TypeId};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::abstract_integer_data_type::{
    encode_any_value, AbstractIntegerDataType,
};
use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::array_stringable::ArrayStringable;
use crate::program::model::data::built_in::{
    built_in_data_type_methods, built_in_singleton, impl_built_in, BuiltIn, BuiltInBase,
};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_with_charset::DataTypeEncodeError;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::model::mem::MemBuffer;

/// Provides a definition of a boolean in a program.
///
/// Port of `ghidra.program.model.data.BooleanDataType`: a one-byte unsigned integer rendered as
/// `TRUE`/`FALSE`, whose value is a `bool`. Java's static `dataType` is
/// [`BooleanDataType::data_type`].
#[derive(Debug, Clone)]
pub struct BooleanDataType {
    base: BuiltInBase,
}

impl BooleanDataType {
    /// Creates a boolean datatype bound to `dtm`'s data organization (Java:
    /// `new BooleanDataType(dtm)`; `None` is the no-argument constructor).
    pub fn new(dtm: Option<&dyn DataTypeManager>) -> Self {
        Self { base: BuiltInBase::new(None, "bool", dtm) }
    }

    /// Port of `BooleanDataType.getRepresentation(BigInteger, Settings, int)`: `FALSE` for zero,
    /// `TRUE` otherwise.
    pub fn get_big_representation(&self, big_int: i128, _settings: &dyn Settings, _bit_length: i32) -> String {
        if big_int == 0 { "FALSE" } else { "TRUE" }.to_string()
    }

    /// Port of `BooleanDataType.getValue`: whether the byte is non-zero.
    fn bool_value(buf: &dyn MemBuffer) -> Option<bool> {
        buf.get_byte(0).ok().map(|b| b != 0)
    }

    fn c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        BuiltIn::built_in_get_c_type_declaration(self, data_organization)
    }

    /// `BOOLEAN_SETTINGS_DEFS`: no settings beyond `BuiltIn`'s mutability setting.
    fn built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }

    fn decompiler_display_name(&self, language: DecompilerLanguage) -> String {
        if language == DecompilerLanguage::JavaLanguage {
            "boolean".to_string()
        } else {
            self.base.name().to_string()
        }
    }
}

built_in_singleton!(BooleanDataType);
impl_built_in!(BooleanDataType);

impl std::fmt::Display for BooleanDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.base.name())
    }
}

impl DataType for BooleanDataType {
    built_in_data_type_methods!();

    fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
        "bool".to_string()
    }

    fn get_length(&self) -> i32 {
        1
    }

    fn get_description(&self) -> String {
        "Boolean".to_string()
    }

    fn get_default_label_prefix(&self) -> Option<String> {
        Some("BOOL".to_string())
    }

    fn get_value(&self, buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> Option<Box<dyn Any>> {
        Self::bool_value(buf).map(|b| Box::new(b) as Box<dyn Any>)
    }

    fn get_value_class(&self, _settings: &dyn Settings) -> Option<TypeId> {
        Some(TypeId::of::<bool>())
    }

    fn get_representation(&self, buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> String {
        match Self::bool_value(buf) {
            Some(true) => "TRUE".to_string(),
            Some(false) => "FALSE".to_string(),
            None => "??".to_string(),
        }
    }

    fn is_encodable(&self) -> bool {
        true
    }

    fn encode_value(
        &self,
        value: &dyn Any,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        encode_any_value(self, value, buf, settings, length)
    }

    fn encode_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        self.integer_encode_representation(repr, buf, settings, length)
            .map_err(|e| DataTypeEncodeError(e.to_string()))
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        self.integer_is_equivalent(dt)
    }

    fn is_integer_type(&self) -> bool {
        true
    }

    fn is_boolean_type(&self) -> bool {
        true
    }

    fn is_array_stringable_type(&self) -> bool {
        true
    }

    fn as_abstract_integer(&self) -> Option<&dyn AbstractIntegerDataType> {
        Some(self)
    }

    fn as_array_stringable(&self) -> Option<&dyn ArrayStringable> {
        Some(self)
    }
}

impl ArrayStringable for BooleanDataType {
    fn has_string_value(&self, settings: &dyn Settings) -> bool {
        self.integer_has_string_value(settings)
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

impl AbstractIntegerDataType for BooleanDataType {

    fn as_data_type(&self) -> &dyn crate::program::model::data::data_type::DataType {

        self

    }
    fn is_signed(&self) -> bool {
        false
    }

    /// Only the unsigned form exists, so this returns the type itself.
    fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
        Box::new(self.clone())
    }

    /// Port of `BooleanDataType.getCDeclaration()`: the name.
    fn get_c_declaration(&self) -> Option<String> {
        Some(self.base.name().to_string())
    }
}

impl AbstractUnsignedIntegerDataType for BooleanDataType {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::abstract_integer_data_type::test_support::{buf, LongSettings};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::byte_data_type::ByteDataType;
    use std::sync::Arc;

    #[test]
    fn java_constants() {
        let dt = BooleanDataType::instance();
        let s = LongSettings::default();
        assert_eq!(dt.get_name(), "bool");
        assert_eq!(dt.get_length(), 1);
        assert_eq!(dt.get_description(), "Boolean");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 2)])), "bool");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("BOOL"));
        assert_eq!(dt.get_c_declaration().as_deref(), Some("bool"));
        assert_eq!(dt.get_c_mnemonic(), "bool");
        assert_eq!(dt.get_value_class(&s), Some(TypeId::of::<bool>()));
        assert!(!dt.is_signed());
        // Mutability only: BOOLEAN_SETTINGS_DEFS is empty.
        assert_eq!(dt.get_settings_definitions().len(), 1);
        let org = dt.get_data_organization();
        assert_eq!(
            dt.get_c_type_declaration(Some(&org)).as_deref(),
            Some("typedef unsigned char    bool;")
        );
    }

    #[test]
    fn decompiler_display_name() {
        let dt = BooleanDataType::new(None);
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::JavaLanguage), "boolean");
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::CLanguage), "bool");
    }

    #[test]
    fn value_and_representation() {
        let dt = BooleanDataType::new(None);
        let s = LongSettings::default();
        let t = dt.get_value(&buf(&[2], false), &s, 1).unwrap();
        assert!(*t.downcast_ref::<bool>().unwrap());
        let f = dt.get_value(&buf(&[0], false), &s, 1).unwrap();
        assert!(!*f.downcast_ref::<bool>().unwrap());
        assert!(dt.get_value(&buf(&[], false), &s, 1).is_none());
        assert_eq!(dt.get_representation(&buf(&[0xff], false), &s, 1), "TRUE");
        assert_eq!(dt.get_representation(&buf(&[0], false), &s, 1), "FALSE");
        assert_eq!(dt.get_representation(&buf(&[], false), &s, 1), "??");
        assert_eq!(dt.get_big_representation(0, &s, 8), "FALSE");
        assert_eq!(dt.get_big_representation(-3, &s, 8), "TRUE");
    }

    #[test]
    fn encodes_as_unsigned_byte() {
        let dt = BooleanDataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0], false);
        assert_eq!(dt.encode_value(&1i32, &b, &s, 1).unwrap(), vec![1]);
        assert!(dt.encode_value(&256i32, &b, &s, 1).is_err());
        assert_eq!(dt.encode_representation("1h", &b, &s, 1).unwrap(), vec![1]);
    }

    #[test]
    fn opposite_is_itself_and_flags() {
        let dt = BooleanDataType::data_type();
        assert!(Arc::ptr_eq(&dt, &BooleanDataType::data_type()));
        assert!(dt.is_boolean_type());
        assert!(dt.is_integer_type());
        let integer = dt.as_abstract_integer().unwrap();
        assert_eq!(integer.get_opposite_signedness_data_type().get_name(), "bool");
        assert!(dt.is_equivalent(&BooleanDataType::new(None)));
        assert!(!dt.is_equivalent(ByteDataType::instance().as_ref()));
    }
}
