//! Port of `ghidra.program.model.data.WideChar32DataType`.

use crate::program::model::data::wide_char_data_type::wide_char_data_type;

wide_char_data_type! {
    /// A 4-byte wide character in the UTF32 charset.
    ///
    /// Port of `ghidra.program.model.data.WideChar32DataType`.
    WideChar32DataType {
        name: "wchar32",
        length: 4,
        description: "Wide-Character (32-bit/UTF32)",
        label_prefix: "WCHAR32",
        value: scalar32,
        label_value: int,
        charset: UTF32,
        c_type_declaration: built_in,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::array_stringable::ArrayStringable;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_with_charset::DataTypeWithCharset;
    use crate::program::model::data::string_data_instance::test_support::SettingsBuilder;

    #[test]
    fn java_constants() {
        let dt = WideChar32DataType::instance();
        assert_eq!(dt.get_name(), "wchar32");
        assert_eq!(dt.get_length(), 4);
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_mnemonic(&SettingsBuilder::new()), "wchar32");
        assert_eq!(dt.get_description(), "Wide-Character (32-bit/UTF32)");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("WCHAR32"));
        assert_eq!(dt.get_charset_name(&SettingsBuilder::new()), crate::util::charset::charset_info_manager::UTF32);
        assert_eq!(dt.get_value_class(&SettingsBuilder::new()), Some(std::any::TypeId::of::<crate::program::model::scalar::Scalar>()));
        assert_eq!(dt.get_settings_definitions().len(), 4);
        assert!(dt.has_string_value(&SettingsBuilder::new()));
        let org = dt.get_data_organization();
        let expected = format!("typedef {}    wchar32;", org.get_integer_c_type_approximation(4, false));
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some(expected.as_str()));
    }
}
