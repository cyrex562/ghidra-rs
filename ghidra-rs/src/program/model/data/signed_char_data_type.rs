//! Port of `ghidra.program.model.data.SignedCharDataType`.

use crate::program::model::data::char_data_type::char_data_type;

char_data_type! {
    /// Provides a definition of a primitive signed char in a program. The size of this type is
    /// determined by the data organization of the associated data type manager.
    ///
    /// Port of `ghidra.program.model.data.SignedCharDataType` (`extends CharDataType`).
    SignedCharDataType {
        name: "schar",
        signed: true,
        description: "Signed Character (ASCII)",
        label_prefix: "SCHAR",
        c_declaration: "signed char",
        c_type_declaration: named,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::char_data_type::CharDataType;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::string_data_instance::test_support::{mb, SettingsBuilder};

    #[test]
    fn java_constants() {
        let dt = SignedCharDataType::instance();
        assert_eq!(dt.get_name(), "schar");
        assert_eq!(dt.is_signed(), true);
        assert_eq!(dt.get_description(), "Signed Character (ASCII)");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("SCHAR"));
        assert_eq!(dt.get_c_declaration().as_deref(), Some("signed char"));
        assert_eq!(
            dt.get_c_type_declaration(Some(&dt.get_data_organization())).as_deref(),
            Some("typedef signed char    schar;")
        );
        assert_eq!(dt.get_opposite_signedness_data_type().get_name(), "uchar");
        assert!(!dt.is_equivalent(CharDataType::instance().as_ref()));
        assert!(dt.is_equivalent(&SignedCharDataType::new(None)));
    }

    #[test]
    fn renders_as_a_char() {
        let dt = SignedCharDataType::new(None);
        assert_eq!(dt.get_representation(&mb(false, b"a"), &SettingsBuilder::new(), 1), "'a'");
        assert_eq!(dt.encode_representation("'a'", &mb(false, &[]), &SettingsBuilder::new(), -1).unwrap(), b"a");
    }
}
