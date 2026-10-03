//! Port of `ghidra.program.model.data.WideChar16DataType`.

use crate::program::model::data::wide_char_data_type::wide_char_data_type;

wide_char_data_type! {
    /// A 2-byte wide character in the UTF16 charset.
    ///
    /// Port of `ghidra.program.model.data.WideChar16DataType`.
    WideChar16DataType {
        name: "wchar16",
        length: 2,
        description: "Wide-Character (16-bit/UTF16)",
        label_prefix: "WCHAR16",
        value: char16,
        label_value: ushort,
        charset: UTF16,
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
        let dt = WideChar16DataType::instance();
        assert_eq!(dt.get_name(), "wchar16");
        assert_eq!(dt.get_length(), 2);
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_mnemonic(&SettingsBuilder::new()), "wchar16");
        assert_eq!(dt.get_description(), "Wide-Character (16-bit/UTF16)");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("WCHAR16"));
        assert_eq!(dt.get_charset_name(&SettingsBuilder::new()), crate::util::charset::charset_info_manager::UTF16);
        assert_eq!(dt.get_value_class(&SettingsBuilder::new()), Some(std::any::TypeId::of::<u16>()));
        assert_eq!(dt.get_settings_definitions().len(), 4);
        assert!(dt.has_string_value(&SettingsBuilder::new()));
        let org = dt.get_data_organization();
        let expected = format!("typedef {}    wchar16;", org.get_integer_c_type_approximation(2, false));
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some(expected.as_str()));
    }
}
