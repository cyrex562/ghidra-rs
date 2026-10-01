//! Port of `ghidra.program.model.data.TerminatedUnicodeDataType`.

use crate::program::model::data::abstract_string_data_type::{DEFAULT_UNICODE_ABBREV_PREFIX, DEFAULT_UNICODE_LABEL, DEFAULT_UNICODE_LABEL_PREFIX};
use crate::program::model::data::abstract_string_data_type::string_data_type;
use crate::program::model::data::wide_char16_data_type::WideChar16DataType;
use crate::program::model::data::string_layout_enum::StringLayoutEnum;
use crate::util::charset::charset_info_manager::UTF16;

string_data_type! {
    /// String (Null Terminated UTF-16 Unicode).
    ///
    /// Port of `ghidra.program.model.data.TerminatedUnicodeDataType`.
    TerminatedUnicodeDataType {
        name: "TerminatedUnicode",
        mnemonic: "unicode",
        default_label: DEFAULT_UNICODE_LABEL,
        default_label_prefix: DEFAULT_UNICODE_LABEL_PREFIX,
        default_abbrev_label_prefix: DEFAULT_UNICODE_ABBREV_PREFIX,
        description: "String (Null Terminated UTF-16 Unicode)",
        charset: Some(UTF16),
        replacement: WideChar16DataType,
        layout: StringLayoutEnum::NullTerminatedUnbounded,
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
        let dt = TerminatedUnicodeDataType::instance();
        assert_eq!(dt.get_name(), "TerminatedUnicode");
        assert_eq!(dt.get_mnemonic(&SettingsBuilder::new()), "unicode");
        assert_eq!(dt.get_description(), "String (Null Terminated UTF-16 Unicode)");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("UNI"));
        assert_eq!(dt.get_default_abbreviated_label_prefix().as_deref(), Some("u"));
        assert_eq!(dt.spec().default_label, "UNICODE");
        assert_eq!(dt.get_string_layout(), StringLayoutEnum::NullTerminatedUnbounded);
        assert_eq!(dt.get_charset_name(&SettingsBuilder::new()), "UTF-16");
        assert_eq!(dt.get_length(), -1);
        assert!(dt.can_specify_length());
        assert_eq!(dt.get_replacement_base_type().get_name(), "wchar16");
        // TRANSLATION, RENDER (+ CHARSET when the charset is not fixed) after Mutability.
        assert_eq!(dt.get_settings_definitions().len(), 3);
        assert_eq!(crate::program::model::data::built_in_data_type::BuiltInDataType::get_c_type_declaration(dt.as_ref(), Some(&dt.get_data_organization())), None);
    }

    #[test]
    fn singleton_and_class_identity() {
        let a = TerminatedUnicodeDataType::data_type();
        assert!(Arc::ptr_eq(&a, &TerminatedUnicodeDataType::data_type()));
        assert!(a.as_abstract_string().is_some());
        assert!(a.as_dynamic().is_some());
        assert!(a.is_equivalent(&TerminatedUnicodeDataType::new(None)));
        assert!(!a.is_equivalent(&crate::program::model::data::char_data_type::CharDataType::new(None)));
    }
}
