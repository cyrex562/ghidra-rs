//! Port of `ghidra.program.model.data.SignedByteDataType`.

use crate::program::model::data::abstract_integer_data_type::integer_data_type;
use crate::program::model::data::byte_data_type::ByteDataType;

integer_data_type! {
    /// Provides a definition of a Signed Byte within a program.
    ///
    /// Port of `ghidra.program.model.data.SignedByteDataType`.
    SignedByteDataType {
        name: "sbyte",
        sign: signed,
        length: 1,
        description: "Signed Byte (sdb)",
        assembly_mnemonic: "sdb",
        c_declaration: default,
        c_type_declaration: this_signed,
        java_display_name: "byte",
        opposite: ByteDataType,
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
        let dt = SignedByteDataType::instance();
        assert_eq!(dt.get_name(), "sbyte");
        assert_eq!(dt.get_length(), 1);
        assert_eq!(dt.get_description(), "Signed Byte (sdb)");
        assert_eq!(dt.is_signed(), true);
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_assembly_mnemonic(), "sdb");
        assert_eq!(dt.get_c_declaration().as_deref(), Some("signed char"));
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("SBYTE"));
        assert_eq!(dt.get_path_name(), "/sbyte");
        assert_eq!(dt.get_category_path(), ROOT.clone());
    }

    #[test]
    fn mnemonic_follows_mnemonic_setting() {
        let dt = SignedByteDataType::new(None);
        // With no mnemonic setting the style is ASSEMBLY.
        assert_eq!(dt.get_mnemonic(&LongSettings::default()), "sdb");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 0)])), "sbyte");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "sdb");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 2)])), "signed char");
    }

    #[test]
    fn c_type_declaration() {
        let dt = SignedByteDataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some("typedef char    sbyte;"));
    }

    #[test]
    fn decompiler_display_name() {
        let dt = SignedByteDataType::new(None);
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::CLanguage), "sbyte");
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::JavaLanguage), "byte");
    }

    #[test]
    fn value_and_representation_honor_signedness_and_endianness() {
        let dt = SignedByteDataType::new(None);
        let s = LongSettings::default();
        let all_ones = buf(&[255], false);
        let value = dt.get_value(&all_ones, &s, 1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.is_signed(), true);
        assert_eq!(scalar.bit_length(), 8);
        assert_eq!(scalar.get_big_integer(), -1i128);
        assert_eq!(dt.get_value_class(&s), Some(std::any::TypeId::of::<Scalar>()));
        assert_eq!(dt.get_representation(&all_ones, &s, 1), "FFh");
        assert_eq!(dt.get_representation(&all_ones, &LongSettings::of(&[("format", 1)]), 1), "-1");

        let mut first_one = vec![0u8; 1];
        first_one[0] = 1;
        let little = dt.get_value(&buf(&first_one, false), &s, 1).unwrap();
        assert_eq!(little.downcast_ref::<Scalar>().unwrap().get_big_integer(), 1);
        let big = dt.get_value(&buf(&first_one, true), &s, 1).unwrap();
        assert_eq!(big.downcast_ref::<Scalar>().unwrap().get_big_integer(), 1i128);
        // An explicit endian setting (2 = big) overrides the buffer's byte order.
        let forced = dt.get_value(&buf(&first_one, false), &LongSettings::of(&[("endian", 2)]), 1).unwrap();
        assert_eq!(forced.downcast_ref::<Scalar>().unwrap().get_big_integer(), 1i128);
        assert!(dt.get_value(&buf(&first_one[..0], false), &s, 1).is_none());
    }

    #[test]
    fn encode_value_checks_range() {
        let dt = SignedByteDataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0u8; 1], false);
        let mut one = vec![0u8; 1];
        one[0] = 1;
        assert_eq!(dt.encode_value(&1i64, &b, &s, -1).unwrap(), one);
        assert_eq!(dt.encode_value(&(127i128), &b, &s, 1).unwrap().len(), 1);
        assert!(dt.encode_value(&(127i128 + 1), &b, &s, 1).is_err());
        assert_eq!(dt.encode_value(&-1i128, &b, &s, 1).is_ok(), true);
        assert!(dt.encode_value(&1i64, &b, &s, 2).is_err());
        assert!(dt.encode_value(&1.5f64, &b, &s, 1).is_err());
        assert_eq!(dt.encode_representation("1h", &b, &s, 1).unwrap(), one);
        assert!(dt.encode_representation("1", &b, &s, 1).is_err());
    }

    #[test]
    fn opposite_signedness_and_class_equivalence() {
        let dt = SignedByteDataType::new(None);
        let opposite = dt.get_opposite_signedness_data_type();
        assert_eq!(opposite.get_name(), "byte");
        assert_eq!(opposite.is_signed(), false);
        assert!(dt.is_equivalent(SignedByteDataType::instance().as_ref()));
        assert!(!dt.is_equivalent(ByteDataType::instance().as_ref()));
        assert!(dt.built_in_is_equivalent(&SignedByteDataType::new(None)));
    }

    #[test]
    fn singleton_is_shared_and_exposes_built_in_views() {
        let a = SignedByteDataType::data_type();
        assert!(Arc::ptr_eq(&a, &SignedByteDataType::data_type()));
        assert!(a.as_built_in().is_some());
        assert!(a.as_abstract_integer().is_some());
        assert!(a.is_integer_type());
        assert_eq!(a.is_signed_integer_type(), true);
        // Mutability + format, padding, endian and mnemonic.
        assert_eq!(a.get_settings_definitions().len(), 5);
        assert!(a.get_source_archive().is_some());
    }
}
