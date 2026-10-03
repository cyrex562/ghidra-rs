//! Port of `ghidra.program.model.data.Undefined5DataType`.

use crate::program::model::data::undefined::undefined_data_type;

undefined_data_type! {
    /// Provides an implementation of a 5-byte datatype that has not been defined yet as a
    /// particular type of data in the program.
    ///
    /// Port of `ghidra.program.model.data.Undefined5DataType`.
    ///
    /// Java computes `getInt(0) << 8` in 32-bit `int` arithmetic, which drops the int's top byte
    /// before the 40-bit mask is applied; the port reproduces that (`wrapping_shl` on `i32`).
    Undefined5DataType {
        name: "undefined5",
        length: 5,
        description: "Undefined 5-Byte",
        bits: 40,
        value: |buf| Ok((buf.get_int(0)?.wrapping_shl(8) as i64 + (buf.get_byte(4)? as i64 & 0xff)) & 0xff_ffff_ffff),
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
        let dt = Undefined5DataType::instance();
        assert_eq!(dt.get_name(), "undefined5");
        assert_eq!(dt.get_length(), 5);
        assert_eq!(dt.get_description(), "Undefined 5-Byte");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "undefined5");
        assert_eq!(dt.get_path_name(), "/undefined5");
        assert!(dt.is_undefined_type());
        assert!(is_undefined(Box::new(Undefined5DataType::new(None))));
        assert!(dt.get_value_class(&LongSettings::default()).is_none());
        // Only the BuiltIn mutability setting.
        assert_eq!(dt.get_settings_definitions().len(), 1);
    }

    #[test]
    fn c_type_declaration_is_unsigned_approximation() {
        let dt = Undefined5DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(
            dt.get_c_type_declaration(Some(&org)).as_deref(),
            Some("typedef unsigned long long    undefined5;")
        );
    }

    #[test]
    fn value_and_representation_match_java() {
        let dt = Undefined5DataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0x91, 0x22, 0x33, 0x44, 0x55], false);
        let value = dt.get_value(&b, &s, 5).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 40);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x33229155);
        assert_eq!(dt.get_representation(&b, &s, 5), "0033229155h");
        let b = buf(&[0x91, 0x22, 0x33, 0x44, 0x55], true);
        let value = dt.get_value(&b, &s, 5).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 40);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x22334455);
        assert_eq!(dt.get_representation(&b, &s, 5), "0022334455h");
        let b = buf(&[0xff, 0xff, 0xff, 0xff, 0xff], false);
        let value = dt.get_value(&b, &s, 5).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 40);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffff);
        assert_eq!(dt.get_representation(&b, &s, 5), "FFFFFFFFFFh");
        let b = buf(&[0xff, 0xff, 0xff, 0xff, 0xff], true);
        let value = dt.get_value(&b, &s, 5).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 40);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffff);
        assert_eq!(dt.get_representation(&b, &s, 5), "FFFFFFFFFFh");
        let short = buf(&[0u8; 4], false);
        assert!(dt.get_value(&short, &s, 5).is_none());
        assert_eq!(dt.get_representation(&short, &s, 5), "??");
    }

    #[test]
    fn equivalence_is_by_class_and_singleton_is_shared() {
        let dt = Undefined5DataType::new(None);
        assert!(dt.is_equivalent(Undefined5DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(Undefined1DataType::instance().as_ref()));
        let a = Undefined5DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Undefined5DataType::data_type()));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(5)));
        assert!(a.as_built_in().is_some());
    }
}
