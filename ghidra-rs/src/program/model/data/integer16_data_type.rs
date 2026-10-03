//! Port of `ghidra.program.model.data.Integer16DataType`.

use crate::program::model::data::abstract_integer_data_type::integer_data_type;
use crate::program::model::data::unsigned_integer16_data_type::UnsignedInteger16DataType;

integer_data_type! {
    /// A signed 16-byte integer.
    ///
    /// Port of `ghidra.program.model.data.Integer16DataType`.
    Integer16DataType {
        name: "int16",
        sign: signed,
        length: 16,
        description: "Signed 16-Byte Integer",
        assembly_mnemonic: default,
        c_declaration: default,
        c_type_declaration: this_signed,
        java_display_name: default,
        opposite: UnsignedInteger16DataType,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::program::model::data::abstract_integer_data_type::test_support::{buf, LongSettings};
    use crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType;
    use crate::program::model::data::built_in::BuiltIn;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::ROOT;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;

    #[test]
    fn java_constants() {
        let dt = Integer16DataType::instance();
        assert_eq!(dt.get_name(), "int16");
        assert_eq!(dt.get_length(), 16);
        assert_eq!(dt.get_description(), "Signed 16-Byte Integer");
        assert_eq!(dt.is_signed(), true);
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_assembly_mnemonic(), "int16");
        assert_eq!(dt.get_c_declaration().as_deref(), None);
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("INT16"));
        assert_eq!(dt.get_path_name(), "/int16");
        assert_eq!(dt.get_category_path(), ROOT.clone());
    }

    #[test]
    fn mnemonic_follows_mnemonic_setting() {
        let dt = Integer16DataType::new(None);
        // With no mnemonic setting the style is ASSEMBLY.
        assert_eq!(dt.get_mnemonic(&LongSettings::default()), "int16");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 0)])), "int16");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "int16");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 2)])), "int16");
    }

    #[test]
    fn c_type_declaration() {
        let dt = Integer16DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some("typedef long long    int16;"));
    }

    #[test]
    fn decompiler_display_name() {
        let dt = Integer16DataType::new(None);
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::CLanguage), "int16");
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::JavaLanguage), "int16");
    }

    #[test]
    fn value_is_big_integer_beyond_eight_bytes() {
        let dt = Integer16DataType::new(None);
        let s = LongSettings::default();
        let mut max = vec![0xffu8; 16];
        max[15] = 0x7f;
        let value = dt.get_value(&buf(&max, false), &s, 16).unwrap();
        assert_eq!(*value.downcast_ref::<i128>().unwrap(), i128::MAX);
        assert_eq!(dt.get_value_class(&s), Some(std::any::TypeId::of::<i128>()));
        assert_eq!(dt.get_representation(&buf(&max, false), &s, 16), "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFh");
        let mut last_one = vec![0u8; 16];
        last_one[15] = 1;
        let big = dt.get_value(&buf(&last_one, true), &s, 16).unwrap();
        assert_eq!(*big.downcast_ref::<i128>().unwrap(), 1);
    }

    #[test]
    fn opposite_signedness_and_class_equivalence() {
        let dt = Integer16DataType::new(None);
        let opposite = dt.get_opposite_signedness_data_type();
        assert_eq!(opposite.get_name(), "uint16");
        assert_eq!(opposite.is_signed(), false);
        assert!(dt.is_equivalent(Integer16DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(UnsignedInteger16DataType::instance().as_ref()));
        assert!(dt.built_in_is_equivalent(&Integer16DataType::new(None)));
    }

    #[test]
    fn singleton_is_shared_and_exposes_built_in_views() {
        let a = Integer16DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Integer16DataType::data_type()));
        assert!(a.as_built_in().is_some());
        assert!(a.as_abstract_integer().is_some());
        assert!(a.is_integer_type());
        assert_eq!(a.is_signed_integer_type(), true);
        // Mutability + format, padding, endian and mnemonic.
        assert_eq!(a.get_settings_definitions().len(), 5);
        assert!(a.get_source_archive().is_some());
    }
}
