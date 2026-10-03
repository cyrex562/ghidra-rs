//! Port of `ghidra.program.model.data.Undefined3DataType`.

use crate::program::model::data::undefined::undefined_data_type;

undefined_data_type! {
    /// Provides an implementation of a 3-byte datatype that has not been defined yet as a
    /// particular type of data in the program.
    ///
    /// Port of `ghidra.program.model.data.Undefined3DataType`.
    ///
    /// `getValue` combines the byte-order-aware `getShort(0)` with the byte at offset 2 exactly as
    /// Java does, so the result depends on the buffer's byte order.
    Undefined3DataType {
        name: "undefined3",
        length: 3,
        description: "Undefined 3-Byte",
        bits: 24,
        value: |buf| Ok((((buf.get_short(0)? as i32) << 8) as i64 + (buf.get_byte(2)? as i64 & 0xff)) & 0xff_ffff),
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
        let dt = Undefined3DataType::instance();
        assert_eq!(dt.get_name(), "undefined3");
        assert_eq!(dt.get_length(), 3);
        assert_eq!(dt.get_description(), "Undefined 3-Byte");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "undefined3");
        assert_eq!(dt.get_path_name(), "/undefined3");
        assert!(dt.is_undefined_type());
        assert!(is_undefined(Box::new(Undefined3DataType::new(None))));
        assert!(dt.get_value_class(&LongSettings::default()).is_none());
        // Only the BuiltIn mutability setting.
        assert_eq!(dt.get_settings_definitions().len(), 1);
    }

    #[test]
    fn c_type_declaration_is_unsigned_approximation() {
        let dt = Undefined3DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(
            dt.get_c_type_declaration(Some(&org)).as_deref(),
            Some("typedef unsigned int    undefined3;")
        );
    }

    #[test]
    fn value_and_representation_match_java() {
        let dt = Undefined3DataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0x91, 0x22, 0x33], false);
        let value = dt.get_value(&b, &s, 3).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 24);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x229133);
        assert_eq!(dt.get_representation(&b, &s, 3), "229133h");
        let b = buf(&[0x91, 0x22, 0x33], true);
        let value = dt.get_value(&b, &s, 3).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 24);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x912233);
        assert_eq!(dt.get_representation(&b, &s, 3), "912233h");
        let b = buf(&[0xff, 0xff, 0xff], false);
        let value = dt.get_value(&b, &s, 3).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 24);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffff);
        assert_eq!(dt.get_representation(&b, &s, 3), "FFFFFFh");
        let b = buf(&[0xff, 0xff, 0xff], true);
        let value = dt.get_value(&b, &s, 3).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 24);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffff);
        assert_eq!(dt.get_representation(&b, &s, 3), "FFFFFFh");
        let short = buf(&[0u8; 2], false);
        assert!(dt.get_value(&short, &s, 3).is_none());
        assert_eq!(dt.get_representation(&short, &s, 3), "??");
    }

    #[test]
    fn equivalence_is_by_class_and_singleton_is_shared() {
        let dt = Undefined3DataType::new(None);
        assert!(dt.is_equivalent(Undefined3DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(Undefined1DataType::instance().as_ref()));
        let a = Undefined3DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Undefined3DataType::data_type()));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(3)));
        assert!(a.as_built_in().is_some());
    }
}
