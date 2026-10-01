//! Port of `ghidra.program.model.data.StringUTF8DataType`.

use crate::program::model::data::abstract_string_data_type::string_data_type;
use crate::program::model::data::char_data_type::CharDataType;
use crate::program::model::data::string_layout_enum::StringLayoutEnum;
use crate::util::charset::charset_info_manager::UTF8;

string_data_type! {
    /// String (Fixed Length UTF-8 Unicode).
    ///
    /// Port of `ghidra.program.model.data.StringUTF8DataType`.
    StringUTF8DataType {
        name: "string-utf8",
        mnemonic: "utf8",
        default_label: "STRING",
        default_label_prefix: "STR",
        default_abbrev_label_prefix: "s",
        description: "String (Fixed Length UTF-8 Unicode)",
        charset: Some(UTF8),
        replacement: CharDataType,
        layout: StringLayoutEnum::FixedLen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_with_charset::DataTypeWithCharset;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::string_data_instance::test_support::SettingsBuilder;

    #[test]
    fn java_constructor_arguments() {
        let dt = StringUTF8DataType::instance();
        assert_eq!(dt.get_name(), "string-utf8");
        assert_eq!(dt.get_mnemonic(&SettingsBuilder::new()), "utf8");
        assert_eq!(dt.get_description(), "String (Fixed Length UTF-8 Unicode)");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("STR"));
        assert_eq!(dt.get_default_abbreviated_label_prefix().as_deref(), Some("s"));
        assert_eq!(dt.spec().default_label, "STRING");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::FixedLen);
        assert_eq!(dt.get_charset_name(&SettingsBuilder::new()), "UTF-8");
        assert_eq!(dt.get_length(), -1);
        assert!(dt.can_specify_length());
        assert_eq!(dt.get_replacement_base_type().get_name(), "char");
        // TRANSLATION, RENDER (+ CHARSET when the charset is not fixed) after Mutability.
        assert_eq!(dt.get_settings_definitions().len(), 3);
        assert_eq!(crate::program::model::data::built_in_data_type::BuiltInDataType::get_c_type_declaration(dt.as_ref(), Some(&dt.get_data_organization())), None);
    }

    #[test]
    fn singleton_and_class_identity() {
        let a = StringUTF8DataType::data_type();
        assert!(Arc::ptr_eq(&a, &StringUTF8DataType::data_type()));
        assert!(a.as_abstract_string().is_some());
        assert!(a.as_dynamic().is_some());
        assert!(a.is_equivalent(&StringUTF8DataType::new(None)));
        assert!(!a.is_equivalent(&crate::program::model::data::char_data_type::CharDataType::new(None)));
    }
}
