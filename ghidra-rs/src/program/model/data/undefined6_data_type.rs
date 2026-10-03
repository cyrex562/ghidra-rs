//! Port of `ghidra.program.model.data.Undefined6DataType`.

use crate::program::model::data::undefined::undefined_data_type;

undefined_data_type! {
    /// Provides an implementation of a 6-byte datatype that has not been defined yet as a
    /// particular type of data in the program.
    ///
    /// Port of `ghidra.program.model.data.Undefined6DataType`.
    ///
    /// Java computes `getInt(0) << 16` in 32-bit `int` arithmetic, which drops the int's top two
    /// bytes before the 48-bit mask is applied; the port reproduces that (`wrapping_shl` on `i32`).
    Undefined6DataType {
        name: "undefined6",
        length: 6,
        description: "Undefined 6-Byte",
        bits: 48,
        value: |buf| Ok((buf.get_int(0)?.wrapping_shl(16) as i64 + (buf.get_short(4)? as i64 & 0xffff)) & 0xffff_ffff_ffff),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::program::model::data::abstract_integer_data_type::test_support::{buf, LongSettings};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::undefined::{get_undefined_data_type, is_undefined};
    use crate::program::model::data::undefined1_data_type::Undefined1DataType;
    use crate::program::model::scalar::Scalar;

    #[test]
    fn java_constants() {
        let dt = Undefined6DataType::instance();
        assert_eq!(dt.get_name(), "undefined6");
        assert_eq!(dt.get_length(), 6);
        assert_eq!(dt.get_description(), "Undefined 6-Byte");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "undefined6");
        assert_eq!(dt.get_path_name(), "/undefined6");
        assert!(dt.is_undefined_type());
        assert!(is_undefined(Box::new(Undefined6DataType::new(None))));
        assert!(dt.get_value_class(&LongSettings::default()).is_none());
        // Only the BuiltIn mutability setting.
        assert_eq!(dt.get_settings_definitions().len(), 1);
    }

    #[test]
    fn c_type_declaration_is_unsigned_approximation() {
        let dt = Undefined6DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(
            dt.get_c_type_declaration(Some(&org)).as_deref(),
            Some("typedef unsigned long long    undefined6;")
        );
    }

    #[test]
    fn value_and_representation_match_java() {
        let dt = Undefined6DataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0x91, 0x22, 0x33, 0x44, 0x55, 0x66], false);
        let value = dt.get_value(&b, &s, 6).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 48);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x22916655);
        assert_eq!(dt.get_representation(&b, &s, 6), "000022916655h");
        let b = buf(&[0x91, 0x22, 0x33, 0x44, 0x55, 0x66], true);
        let value = dt.get_value(&b, &s, 6).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 48);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x33445566);
        assert_eq!(dt.get_representation(&b, &s, 6), "000033445566h");
        let b = buf(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff], false);
        let value = dt.get_value(&b, &s, 6).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 48);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffffff);
        assert_eq!(dt.get_representation(&b, &s, 6), "FFFFFFFFFFFFh");
        let b = buf(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff], true);
        let value = dt.get_value(&b, &s, 6).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 48);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffffff);
        assert_eq!(dt.get_representation(&b, &s, 6), "FFFFFFFFFFFFh");
        let short = buf(&[0u8; 5], false);
        assert!(dt.get_value(&short, &s, 6).is_none());
        assert_eq!(dt.get_representation(&short, &s, 6), "??");
    }

    #[test]
    fn equivalence_is_by_class_and_singleton_is_shared() {
        let dt = Undefined6DataType::new(None);
        assert!(dt.is_equivalent(Undefined6DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(Undefined1DataType::instance().as_ref()));
        let a = Undefined6DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Undefined6DataType::data_type()));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(6)));
        assert!(a.as_built_in().is_some());
    }
}
