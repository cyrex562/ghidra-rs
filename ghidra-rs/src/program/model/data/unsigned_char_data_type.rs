//! Port of `ghidra.program.model.data.UnsignedCharDataType`.

use crate::program::model::data::char_data_type::char_data_type;

char_data_type! {
    /// Provides a definition of a primitive unsigned char in a program. The size of this type is
    /// determined by the data organization of the associated data type manager.
    ///
    /// Port of `ghidra.program.model.data.UnsignedCharDataType` (`extends CharDataType`).
    UnsignedCharDataType {
        name: "uchar",
        signed: false,
        description: "Unsigned Character (ASCII)",
        label_prefix: "UCHAR",
        c_declaration: "unsigned char",
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
        let dt = UnsignedCharDataType::instance();
        assert_eq!(dt.get_name(), "uchar");
        assert_eq!(dt.is_signed(), false);
        assert_eq!(dt.get_description(), "Unsigned Character (ASCII)");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("UCHAR"));
        assert_eq!(dt.get_c_declaration().as_deref(), Some("unsigned char"));
        assert_eq!(
            dt.get_c_type_declaration(Some(&dt.get_data_organization())).as_deref(),
            Some("typedef unsigned char    uchar;")
        );
        assert_eq!(dt.get_opposite_signedness_data_type().get_name(), "schar");
        assert!(!dt.is_equivalent(CharDataType::instance().as_ref()));
        assert!(dt.is_equivalent(&UnsignedCharDataType::new(None)));
    }

    #[test]
    fn renders_as_a_char() {
        let dt = UnsignedCharDataType::new(None);
        assert_eq!(dt.get_representation(&mb(false, b"a"), &SettingsBuilder::new(), 1), "'a'");
        assert_eq!(dt.encode_representation("'a'", &mb(false, &[]), &SettingsBuilder::new(), -1).unwrap(), b"a");
    }
}
