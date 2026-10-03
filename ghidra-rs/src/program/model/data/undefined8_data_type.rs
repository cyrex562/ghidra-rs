//! Port of `ghidra.program.model.data.Undefined8DataType`.

use crate::program::model::data::undefined::undefined_data_type;

undefined_data_type! {
    /// Provides an implementation of a 8-byte datatype that has not been defined yet as a
    /// particular type of data in the program.
    ///
    /// Port of `ghidra.program.model.data.Undefined8DataType`.
    Undefined8DataType {
        name: "undefined8",
        length: 8,
        description: "Undefined Quad Word",
        bits: 64,
        value: |buf| buf.get_long(0),
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
        let dt = Undefined8DataType::instance();
        assert_eq!(dt.get_name(), "undefined8");
        assert_eq!(dt.get_length(), 8);
        assert_eq!(dt.get_description(), "Undefined Quad Word");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "undefined8");
        assert_eq!(dt.get_path_name(), "/undefined8");
        assert!(dt.is_undefined_type());
        assert!(is_undefined(Box::new(Undefined8DataType::new(None))));
        assert!(dt.get_value_class(&LongSettings::default()).is_none());
        // Only the BuiltIn mutability setting.
        assert_eq!(dt.get_settings_definitions().len(), 1);
    }

    #[test]
    fn c_type_declaration_is_unsigned_approximation() {
        let dt = Undefined8DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(
            dt.get_c_type_declaration(Some(&org)).as_deref(),
            Some("typedef unsigned long long    undefined8;")
        );
    }

    #[test]
    fn value_and_representation_match_java() {
        let dt = Undefined8DataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], false);
        let value = dt.get_value(&b, &s, 8).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 64);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x8877665544332291);
        assert_eq!(dt.get_representation(&b, &s, 8), "8877665544332291h");
        let b = buf(&[0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], true);
        let value = dt.get_value(&b, &s, 8).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 64);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x9122334455667788);
        assert_eq!(dt.get_representation(&b, &s, 8), "9122334455667788h");
        let b = buf(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], false);
        let value = dt.get_value(&b, &s, 8).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 64);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffffffffff);
        assert_eq!(dt.get_representation(&b, &s, 8), "FFFFFFFFFFFFFFFFh");
        let b = buf(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], true);
        let value = dt.get_value(&b, &s, 8).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 64);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffffffffff);
        assert_eq!(dt.get_representation(&b, &s, 8), "FFFFFFFFFFFFFFFFh");
        let short = buf(&[0u8; 7], false);
        assert!(dt.get_value(&short, &s, 8).is_none());
        assert_eq!(dt.get_representation(&short, &s, 8), "??");
    }

    #[test]
    fn equivalence_is_by_class_and_singleton_is_shared() {
        let dt = Undefined8DataType::new(None);
        assert!(dt.is_equivalent(Undefined8DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(Undefined1DataType::instance().as_ref()));
        let a = Undefined8DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Undefined8DataType::data_type()));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(8)));
        assert!(a.as_built_in().is_some());
    }
}
