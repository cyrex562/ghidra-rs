//! Port of `ghidra.program.model.data.Undefined4DataType`.

use crate::program::model::data::undefined::undefined_data_type;

undefined_data_type! {
    /// Provides an implementation of a 4-byte datatype that has not been defined yet as a
    /// particular type of data in the program.
    ///
    /// Port of `ghidra.program.model.data.Undefined4DataType`.
    Undefined4DataType {
        name: "undefined4",
        length: 4,
        description: "Undefined Double Word",
        bits: 32,
        value: |buf| Ok(buf.get_int(0)? as i64 & 0xffff_ffff),
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
        let dt = Undefined4DataType::instance();
        assert_eq!(dt.get_name(), "undefined4");
        assert_eq!(dt.get_length(), 4);
        assert_eq!(dt.get_description(), "Undefined Double Word");
        assert_eq!(dt.get_mnemonic(&LongSettings::of(&[("mnemonic", 1)])), "undefined4");
        assert_eq!(dt.get_path_name(), "/undefined4");
        assert!(dt.is_undefined_type());
        assert!(is_undefined(Box::new(Undefined4DataType::new(None))));
        assert!(dt.get_value_class(&LongSettings::default()).is_none());
        // Only the BuiltIn mutability setting.
        assert_eq!(dt.get_settings_definitions().len(), 1);
    }

    #[test]
    fn c_type_declaration_is_unsigned_approximation() {
        let dt = Undefined4DataType::new(None);
        let org = dt.get_data_organization();
        assert_eq!(
            dt.get_c_type_declaration(Some(&org)).as_deref(),
            Some("typedef unsigned int    undefined4;")
        );
    }

    #[test]
    fn value_and_representation_match_java() {
        let dt = Undefined4DataType::new(None);
        let s = LongSettings::default();
        let b = buf(&[0x91, 0x22, 0x33, 0x44], false);
        let value = dt.get_value(&b, &s, 4).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 32);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x44332291);
        assert_eq!(dt.get_representation(&b, &s, 4), "44332291h");
        let b = buf(&[0x91, 0x22, 0x33, 0x44], true);
        let value = dt.get_value(&b, &s, 4).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 32);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0x91223344);
        assert_eq!(dt.get_representation(&b, &s, 4), "91223344h");
        let b = buf(&[0xff, 0xff, 0xff, 0xff], false);
        let value = dt.get_value(&b, &s, 4).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 32);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffff);
        assert_eq!(dt.get_representation(&b, &s, 4), "FFFFFFFFh");
        let b = buf(&[0xff, 0xff, 0xff, 0xff], true);
        let value = dt.get_value(&b, &s, 4).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.bit_length(), 32);
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xffffffff);
        assert_eq!(dt.get_representation(&b, &s, 4), "FFFFFFFFh");
        let short = buf(&[0u8; 3], false);
        assert!(dt.get_value(&short, &s, 4).is_none());
        assert_eq!(dt.get_representation(&short, &s, 4), "??");
    }

    #[test]
    fn equivalence_is_by_class_and_singleton_is_shared() {
        let dt = Undefined4DataType::new(None);
        assert!(dt.is_equivalent(Undefined4DataType::instance().as_ref()));
        assert!(!dt.is_equivalent(Undefined1DataType::instance().as_ref()));
        let a = Undefined4DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Undefined4DataType::data_type()));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(4)));
        assert!(a.as_built_in().is_some());
    }
}
