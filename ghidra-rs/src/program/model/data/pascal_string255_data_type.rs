//! Port of `ghidra.program.model.data.PascalString255DataType`.

use crate::program::model::data::abstract_string_data_type::string_data_type;
use crate::program::model::data::byte_data_type::ByteDataType;
use crate::program::model::data::string_layout_enum::StringLayoutEnum;

string_data_type! {
    /// String (Pascal 255).
    ///
    /// Port of `ghidra.program.model.data.PascalString255DataType`.
    PascalString255DataType {
        name: "PascalString255",
        mnemonic: "p_string255",
        default_label: "PASCAL255",
        default_label_prefix: "P_STR",
        default_abbrev_label_prefix: "p",
        description: "String (Pascal 255)",
        charset: None,
        replacement: ByteDataType,
        layout: StringLayoutEnum::Pascal255,
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
        let dt = PascalString255DataType::instance();
        assert_eq!(dt.get_name(), "PascalString255");
        assert_eq!(dt.get_mnemonic(&SettingsBuilder::new()), "p_string255");
        assert_eq!(dt.get_description(), "String (Pascal 255)");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("P_STR"));
        assert_eq!(dt.get_default_abbreviated_label_prefix().as_deref(), Some("p"));
        assert_eq!(dt.spec().default_label, "PASCAL255");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::Pascal255);
        assert_eq!(dt.get_charset_name(&SettingsBuilder::new()), "US-ASCII");
        assert_eq!(dt.get_length(), -1);
        assert!(dt.can_specify_length());
        assert_eq!(dt.get_replacement_base_type().get_name(), "byte");
        // TRANSLATION, RENDER (+ CHARSET when the charset is not fixed) after Mutability.
        assert_eq!(dt.get_settings_definitions().len(), 4);
        assert_eq!(crate::program::model::data::built_in_data_type::BuiltInDataType::get_c_type_declaration(dt.as_ref(), Some(&dt.get_data_organization())), None);
    }

    #[test]
    fn singleton_and_class_identity() {
        let a = PascalString255DataType::data_type();
        assert!(Arc::ptr_eq(&a, &PascalString255DataType::data_type()));
        assert!(a.as_abstract_string().is_some());
        assert!(a.as_dynamic().is_some());
        assert!(a.is_equivalent(&PascalString255DataType::new(None)));
        assert!(!a.is_equivalent(&crate::program::model::data::char_data_type::CharDataType::new(None)));
    }
}
