//! Port of `ghidra.program.model.data.UnsignedInteger7DataType`.

use crate::program::model::data::abstract_integer_data_type::integer_data_type;
use crate::program::model::data::integer7_data_type::Integer7DataType;

integer_data_type! {
    /// An unsigned 7-byte integer.
    ///
    /// Port of `ghidra.program.model.data.UnsignedInteger7DataType`.
    UnsignedInteger7DataType {
        name: "uint7",
        sign: unsigned,
        length: 7,
        description: "Unsigned 7-Byte Integer",
        assembly_mnemonic: default,
        c_declaration: default,
        c_type_declaration: this_unsigned,
        java_display_name: default,
        opposite: Integer7DataType,
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
    use crate::program::model::scalar::Scalar;

    #[test]
    fn java_constants() {
        let dt = UnsignedInteger7DataType::instance();
        assert_eq!(dt.get_name(), "uint7");
        assert_eq!(dt.get_length(), 7);
        assert_eq!(dt.get_description(), "Unsigned 7-Byte Integer");
        assert_eq!(dt.is_signed(), false);
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_assembly_mnemonic(), "uint7");
        assert_eq!(dt.get_c_declaration().as_deref(), None);
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("UINT7"));
        assert_eq!(dt.get_path_name(), "/uint7");
        assert_eq!(dt.get_category_path(), ROOT.clone());
    }

    #[test]
    fn mnemonic_follows_mnemonic_setting() {
        let dt = UnsignedInteger7DataType::new(None);
        // With no mnemonic setting the style is ASSEMBLY.
        assert_eq!(dt.get_mnemonic(&LongSettings::default()), "uint7");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 0)])), "uint7");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "uint7");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 2)])), "uint7");
    }

    #[test]
    fn c_type_declaration() {
        let dt = UnsignedInteger7DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some("typedef unsigned long long    uint7;"));
    }

    #[test]
    fn decompiler_display_name() {
        let dt = UnsignedInteger7DataType::new(None);
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::CLanguage), "uint7");
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::JavaLanguage), "uint7");
    }

    #[test]
    fn value_and_representation_honor_signedness_and_endianness() {
        let dt = UnsignedInteger7DataType::new(None);
        let s = LongSettings::default();
        let all_ones = buf(&[255, 255, 255, 255, 255, 255, 255], false);
        let value = dt.get_value(&all_ones, &s, 7).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.is_signed(), false);
        assert_eq!(scalar.bit_length(), 56);
        assert_eq!(scalar.get_big_integer(), 72057594037927935i128);
        assert_eq!(dt.get_value_class(&s), Some(std::any::TypeId::of::<Scalar>()));
        assert_eq!(dt.get_representation(&all_ones, &s, 7), "FFFFFFFFFFFFFFh");
        assert_eq!(dt.get_representation(&all_ones, &LongSettings::of(&[("format", 1)]), 7), "72057594037927935");

        let mut first_one = vec![0u8; 7];
        first_one[0] = 1;
        let little = dt.get_value(&buf(&first_one, false), &s, 7).unwrap();
        assert_eq!(little.downcast_ref::<Scalar>().unwrap().get_big_integer(), 1);
        let big = dt.get_value(&buf(&first_one, true), &s, 7).unwrap();
        assert_eq!(big.downcast_ref::<Scalar>().unwrap().get_big_integer(), 281474976710656i128);
        // An explicit endian setting (2 = big) overrides the buffer's byte order.
        let forced = dt.get_value(&buf(&first_one, false), &LongSettings::of(&[("endian", 2)]), 7).unwrap();
        assert_eq!(forced.downcast_ref::<Scalar>().unwrap().get_big_integer(), 281474976710656i128);
        assert!(dt.get_value(&buf(&first_one[..6], false), &s, 7).is_none());
    }

    #[test]
    fn encode_value_checks_range() {
        let dt = UnsignedInteger7DataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0u8; 7], false);
        let mut one = vec![0u8; 7];
        one[0] = 1;
        assert_eq!(dt.encode_value(&1i64, &b, &s, -1).unwrap(), one);
        assert_eq!(dt.encode_value(&(72057594037927935i128), &b, &s, 7).unwrap().len(), 7);
        assert!(dt.encode_value(&(72057594037927935i128 + 1), &b, &s, 7).is_err());
        assert_eq!(dt.encode_value(&-1i128, &b, &s, 7).is_ok(), false);
        assert!(dt.encode_value(&1i64, &b, &s, 8).is_err());
        assert!(dt.encode_value(&1.5f64, &b, &s, 7).is_err());
        assert_eq!(dt.encode_representation("1h", &b, &s, 7).unwrap(), one);
        assert!(dt.encode_representation("1", &b, &s, 7).is_err());
    }

    #[test]
    fn opposite_signedness_and_class_equivalence() {
        let dt = UnsignedInteger7DataType::new(None);
        let opposite = dt.get_opposite_signedness_data_type();
        assert_eq!(opposite.get_name(), "int7");
        assert_eq!(opposite.is_signed(), true);
        assert!(dt.is_equivalent(UnsignedInteger7DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(Integer7DataType::instance().as_ref()));
        assert!(dt.built_in_is_equivalent(&UnsignedInteger7DataType::new(None)));
    }

    #[test]
    fn singleton_is_shared_and_exposes_built_in_views() {
        let a = UnsignedInteger7DataType::data_type();
        assert!(Arc::ptr_eq(&a, &UnsignedInteger7DataType::data_type()));
        assert!(a.as_built_in().is_some());
        assert!(a.as_abstract_integer().is_some());
        assert!(a.is_integer_type());
        assert_eq!(a.is_signed_integer_type(), false);
        // Mutability + format, padding, endian and mnemonic.
        assert_eq!(a.get_settings_definitions().len(), 5);
        assert!(a.get_source_archive().is_some());
    }
}
