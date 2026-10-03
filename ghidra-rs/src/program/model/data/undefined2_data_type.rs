//! Port of `ghidra.program.model.data.Undefined2DataType`.

use crate::program::model::data::undefined::undefined_data_type;

undefined_data_type! {
    /// Provides an implementation of a 2-byte datatype that has not been defined yet as a
    /// particular type of data in the program.
    ///
    /// Port of `ghidra.program.model.data.Undefined2DataType`.
    Undefined2DataType {
        name: "undefined2",
        length: 2,
        description: "Undefined Word",
        bits: 16,
        value: |buf| Ok(buf.get_short(0)? as i64 & 0xffff),
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
        let dt = Undefined2DataType::instance();
        assert_eq!(dt.get_name(), "undefined2");
        assert_eq!(dt.get_length(), 2);
        assert_eq!(dt.get_description(), "Undefined Word");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "undefined2");
        assert_eq!(dt.get_path_name(), "/undefined2");
        assert!(dt.is_undefined_type());
        assert!(is_undefined(Box::new(Undefined2DataType::new(None))));
        assert!(dt.get_value_class(&LongSettings::default()).is_none());
        // Only the BuiltIn mutability setting.
        assert_eq!(dt.get_settings_definitions().len(), 1);
    }

    #[test]
    fn c_type_declaration_is_unsigned_approximation() {
        let dt = Undefined2DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(
            dt.get_c_type_declaration(Some(&org)).as_deref(),
            Some("typedef unsigned short    undefined2;")
        );
    }

    #[test]
    fn value_and_representation_match_java() {
        let dt = Undefined2DataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0x91, 0x22], false);
        let value = dt.get_value(&b, &s, 2).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 16);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x2291);
        assert_eq!(dt.get_representation(&b, &s, 2), "2291h");
        let b = buf(&[0x91, 0x22], true);
        let value = dt.get_value(&b, &s, 2).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 16);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x9122);
        assert_eq!(dt.get_representation(&b, &s, 2), "9122h");
        let b = buf(&[0xff, 0xff], false);
        let value = dt.get_value(&b, &s, 2).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 16);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffff);
        assert_eq!(dt.get_representation(&b, &s, 2), "FFFFh");
        let b = buf(&[0xff, 0xff], true);
        let value = dt.get_value(&b, &s, 2).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 16);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffff);
        assert_eq!(dt.get_representation(&b, &s, 2), "FFFFh");
        let short = buf(&[0u8; 1], false);
        assert!(dt.get_value(&short, &s, 2).is_none());
        assert_eq!(dt.get_representation(&short, &s, 2), "??");
    }

    #[test]
    fn equivalence_is_by_class_and_singleton_is_shared() {
        let dt = Undefined2DataType::new(None);
        assert!(dt.is_equivalent(Undefined2DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(Undefined1DataType::instance().as_ref()));
        let a = Undefined2DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Undefined2DataType::data_type()));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(2)));
        assert!(a.as_built_in().is_some());
    }
}
