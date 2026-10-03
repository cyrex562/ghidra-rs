//! Port of `ghidra.program.model.data.UnsignedLongDataType`.

use crate::program::model::data::abstract_integer_data_type::integer_data_type;
use crate::program::model::data::long_data_type::LongDataType;

integer_data_type! {
    /// Basic implementation for an Unsigned Long Integer dataType.
    ///
    /// Port of `ghidra.program.model.data.UnsignedLongDataType`.
    UnsignedLongDataType {
        name: "ulong",
        sign: unsigned,
        length: get_long_size,
        description: "Unsigned Long Integer (compiler-specific size)",
        assembly_mnemonic: default,
        c_declaration: C_UNSIGNED_LONG,
        c_type_declaration: "unsigned long",
        java_display_name: default,
        opposite: LongDataType,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::program::model::data::abstract_integer_data_type::test_support::{buf, LongSettings, Lp64Manager};
    use crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType;
    use crate::program::model::data::built_in::BuiltIn;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::ROOT;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::scalar::Scalar;

    #[test]
    fn java_constants() {
        let dt = UnsignedLongDataType::instance();
        assert_eq!(dt.get_name(), "ulong");
        assert_eq!(dt.get_length(), 4);
        assert_eq!(dt.get_description(), "Unsigned Long Integer (compiler-specific size)");
        assert_eq!(dt.is_signed(), false);
        assert!(dt.has_language_dependant_length());
        assert_eq!(dt.get_assembly_mnemonic(), "ulong");
        assert_eq!(dt.get_c_declaration().as_deref(), Some("unsigned long"));
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("ULONG"));
        assert_eq!(dt.get_path_name(), "/ulong");
        assert_eq!(dt.get_category_path(), ROOT.clone());
    }

    #[test]
    fn mnemonic_follows_mnemonic_setting() {
        let dt = UnsignedLongDataType::new(None);
        // With no mnemonic setting the style is ASSEMBLY.
        assert_eq!(dt.get_mnemonic(&LongSettings::default()), "ulong");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 0)])), "ulong");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "ulong");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 2)])), "unsigned long");
    }

    #[test]
    fn c_type_declaration() {
        let dt = UnsignedLongDataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some("typedef unsigned long    ulong;"));
    }

    #[test]
    fn decompiler_display_name() {
        let dt = UnsignedLongDataType::new(None);
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::CLanguage), "ulong");
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::JavaLanguage), "ulong");
    }

    #[test]
    fn value_and_representation_honor_signedness_and_endianness() {
        let dt = UnsignedLongDataType::new(None);
        let s = LongSettings::default();
        let all_ones = buf(&[255, 255, 255, 255], false);
        let value = dt.get_value(&all_ones, &s, 4).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.is_signed(), false);
        assert_eq!(scalar.bit_length(), 32);
        assert_eq!(scalar.get_big_integer(), 4294967295i128);
        assert_eq!(dt.get_value_class(&s), Some(std::any::TypeId::of::<Scalar>()));
        assert_eq!(dt.get_representation(&all_ones, &s, 4), "FFFFFFFFh");
        assert_eq!(dt.get_representation(&all_ones, &LongSettings::of(&[("format", 1)]), 4), "4294967295");

        let mut first_one = vec![0u8; 4];
        first_one[0] = 1;
        let little = dt.get_value(&buf(&first_one, false), &s, 4).unwrap();
        assert_eq!(little.downcast_ref::<Scalar>().unwrap().get_big_integer(), 1);
        let big = dt.get_value(&buf(&first_one, true), &s, 4).unwrap();
        assert_eq!(big.downcast_ref::<Scalar>().unwrap().get_big_integer(), 16777216i128);
        // An explicit endian setting (2 = big) overrides the buffer's byte order.
        let forced = dt.get_value(&buf(&first_one, false), &LongSettings::of(&[("endian", 2)]), 4).unwrap();
        assert_eq!(forced.downcast_ref::<Scalar>().unwrap().get_big_integer(), 16777216i128);
        assert!(dt.get_value(&buf(&first_one[..3], false), &s, 4).is_none());
    }

    #[test]
    fn encode_value_checks_range() {
        let dt = UnsignedLongDataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0u8; 4], false);
        let mut one = vec![0u8; 4];
        one[0] = 1;
        assert_eq!(dt.encode_value(&1i64, &b, &s, -1).unwrap(), one);
        assert_eq!(dt.encode_value(&(4294967295i128), &b, &s, 4).unwrap().len(), 4);
        assert!(dt.encode_value(&(4294967295i128 + 1), &b, &s, 4).is_err());
        assert_eq!(dt.encode_value(&-1i128, &b, &s, 4).is_ok(), false);
        assert!(dt.encode_value(&1i64, &b, &s, 5).is_err());
        assert!(dt.encode_value(&1.5f64, &b, &s, 4).is_err());
        assert_eq!(dt.encode_representation("1h", &b, &s, 4).unwrap(), one);
        assert!(dt.encode_representation("1", &b, &s, 4).is_err());
    }

    #[test]
    fn opposite_signedness_and_class_equivalence() {
        let dt = UnsignedLongDataType::new(None);
        let opposite = dt.get_opposite_signedness_data_type();
        assert_eq!(opposite.get_name(), "long");
        assert_eq!(opposite.is_signed(), true);
        assert!(dt.is_equivalent(UnsignedLongDataType::instance().as_ref()));
        assert!(!dt.is_equivalent(LongDataType::instance().as_ref()));
        assert!(dt.built_in_is_equivalent(&UnsignedLongDataType::new(None)));
    }

    #[test]
    fn singleton_is_shared_and_exposes_built_in_views() {
        let a = UnsignedLongDataType::data_type();
        assert!(Arc::ptr_eq(&a, &UnsignedLongDataType::data_type()));
        assert!(a.as_built_in().is_some());
        assert!(a.as_abstract_integer().is_some());
        assert!(a.is_integer_type());
        assert_eq!(a.is_signed_integer_type(), false);
        // Mutability + format, padding, endian and mnemonic.
        assert_eq!(a.get_settings_definitions().len(), 5);
        assert!(a.get_source_archive().is_some());
    }

    #[test]
    fn length_follows_the_manager_data_organization() {
        let dt = UnsignedLongDataType::new(Some(&Lp64Manager));
        assert_eq!(dt.get_length(), 8);
        assert_eq!(dt.get_opposite_signedness_data_type().get_length(), 8);
        let cloned = UnsignedLongDataType::instance().clone_data_type(&Lp64Manager);
        assert_eq!(cloned.get_length(), 8);
        assert_eq!(UnsignedLongDataType::instance().get_length(), 4);
    }
}
