//! Port of `ghidra.program.model.data.Undefined7DataType`.

use crate::program::model::data::undefined::undefined_data_type;

undefined_data_type! {
    /// Provides an implementation of a 7-byte datatype that has not been defined yet as a
    /// particular type of data in the program.
    ///
    /// Port of `ghidra.program.model.data.Undefined7DataType`.
    ///
    /// Java computes `getInt(0) << 24` in 32-bit `int` arithmetic and masks the result to 48 bits;
    /// the port reproduces both (`wrapping_shl` on `i32`, `0xffff_ffff_ffff` mask).
    Undefined7DataType {
        name: "undefined7",
        length: 7,
        description: "Undefined 7-Byte",
        bits: 56,
        value: |buf| Ok((buf.get_int(0)?.wrapping_shl(24) as i64
                + ((buf.get_short(4)? as i64 & 0xffff) << 8)
                + (buf.get_byte(6)? as i64 & 0xff))
                & 0xffff_ffff_ffff),
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
        let dt = Undefined7DataType::instance();
        assert_eq!(dt.get_name(), "undefined7");
        assert_eq!(dt.get_length(), 7);
        assert_eq!(dt.get_description(), "Undefined 7-Byte");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "undefined7");
        assert_eq!(dt.get_path_name(), "/undefined7");
        assert!(dt.is_undefined_type());
        assert!(is_undefined(Box::new(Undefined7DataType::new(None))));
        assert!(dt.get_value_class(&LongSettings::default()).is_none());
        // Only the BuiltIn mutability setting.
        assert_eq!(dt.get_settings_definitions().len(), 1);
    }

    #[test]
    fn c_type_declaration_is_unsigned_approximation() {
        let dt = Undefined7DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(
            dt.get_c_type_declaration(Some(&org)).as_deref(),
            Some("typedef unsigned long long    undefined7;")
        );
    }

    #[test]
    fn value_and_representation_match_java() {
        let dt = Undefined7DataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77], false);
        let value = dt.get_value(&b, &s, 7).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 56);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffff91665577);
        assert_eq!(dt.get_representation(&b, &s, 7), "00FFFF91665577h");
        let b = buf(&[0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77], true);
        let value = dt.get_value(&b, &s, 7).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 56);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x44556677);
        assert_eq!(dt.get_representation(&b, &s, 7), "00000044556677h");
        let b = buf(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], false);
        let value = dt.get_value(&b, &s, 7).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 56);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffffff);
        assert_eq!(dt.get_representation(&b, &s, 7), "00FFFFFFFFFFFFh");
        let b = buf(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], true);
        let value = dt.get_value(&b, &s, 7).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 56);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffffff);
        assert_eq!(dt.get_representation(&b, &s, 7), "00FFFFFFFFFFFFh");
        let short = buf(&[0u8; 6], false);
        assert!(dt.get_value(&short, &s, 7).is_none());
        assert_eq!(dt.get_representation(&short, &s, 7), "??");
    }

    #[test]
    fn equivalence_is_by_class_and_singleton_is_shared() {
        let dt = Undefined7DataType::new(None);
        assert!(dt.is_equivalent(Undefined7DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(Undefined1DataType::instance().as_ref()));
        let a = Undefined7DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Undefined7DataType::data_type()));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(7)));
        assert!(a.as_built_in().is_some());
    }
}
