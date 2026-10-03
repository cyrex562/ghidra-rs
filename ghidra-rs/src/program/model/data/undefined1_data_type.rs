//! Port of `ghidra.program.model.data.Undefined1DataType`.

use crate::program::model::data::undefined::undefined_data_type;

undefined_data_type! {
    /// Provides an implementation of a 1-byte datatype that has not been defined yet as a
    /// particular type of data in the program.
    ///
    /// Port of `ghidra.program.model.data.Undefined1DataType`.
    Undefined1DataType {
        name: "undefined1",
        length: 1,
        description: "Undefined Byte",
        bits: 8,
        value: |buf| Ok(buf.get_byte(0)? as i64 & 0xff),
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
    use crate::program::model::data::undefined2_data_type::Undefined2DataType;
    use crate::program::model::scalar::Scalar;

    #[test]
    fn java_constants() {
        let dt = Undefined1DataType::instance();
        assert_eq!(dt.get_name(), "undefined1");
        assert_eq!(dt.get_length(), 1);
        assert_eq!(dt.get_description(), "Undefined Byte");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "undefined1");
        assert_eq!(dt.get_path_name(), "/undefined1");
        assert!(dt.is_undefined_type());
        assert!(is_undefined(Box::new(Undefined1DataType::new(None))));
        assert!(dt.get_value_class(&LongSettings::default()).is_none());
        // Only the BuiltIn mutability setting.
        assert_eq!(dt.get_settings_definitions().len(), 1);
    }

    #[test]
    fn c_type_declaration_is_unsigned_approximation() {
        let dt = Undefined1DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(
            dt.get_c_type_declaration(Some(&org)).as_deref(),
            Some("typedef unsigned char    undefined1;")
        );
    }

    #[test]
    fn value_and_representation_match_java() {
        let dt = Undefined1DataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0x91], false);
        let value = dt.get_value(&b, &s, 1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 8);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x91);
        assert_eq!(dt.get_representation(&b, &s, 1), "91h");
        let b = buf(&[0x91], true);
        let value = dt.get_value(&b, &s, 1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 8);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x91);
        assert_eq!(dt.get_representation(&b, &s, 1), "91h");
        let b = buf(&[0xff], false);
        let value = dt.get_value(&b, &s, 1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 8);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xff);
        assert_eq!(dt.get_representation(&b, &s, 1), "FFh");
        let b = buf(&[0xff], true);
        let value = dt.get_value(&b, &s, 1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 8);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xff);
        assert_eq!(dt.get_representation(&b, &s, 1), "FFh");
        let short = buf(&[0u8; 0], false);
        assert!(dt.get_value(&short, &s, 1).is_none());
        assert_eq!(dt.get_representation(&short, &s, 1), "??");
    }

    #[test]
    fn equivalence_is_by_class_and_singleton_is_shared() {
        let dt = Undefined1DataType::new(None);
        assert!(dt.is_equivalent(Undefined1DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(Undefined2DataType::instance().as_ref()));
        let a = Undefined1DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Undefined1DataType::data_type()));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(1)));
        assert!(a.as_built_in().is_some());
    }
}
