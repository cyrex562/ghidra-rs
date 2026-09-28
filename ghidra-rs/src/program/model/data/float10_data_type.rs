//! Port of `ghidra.program.model.data.Float10DataType`.

use crate::program::model::data::abstract_float_data_type::float_data_type;

float_data_type! {
    /// Provides a definition of a Float10 (x87 80-bit extended precision) within a program.
    ///
    /// Port of `ghidra.program.model.data.Float10DataType`.
    Float10DataType {
        name: "float10",
        length: 10,
        description_prefix: "",
        c_type_declaration: default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::pcode::floatformat::{get_float_format, BigFloat};
    use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
    use crate::program::model::data::abstract_integer_data_type::test_support::{buf, LongSettings};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::float8_data_type::Float8DataType;

    #[test]
    fn java_constants() {
        let dt = Float10DataType::instance();
        let s = LongSettings::default();
        assert_eq!(dt.get_name(), "float10");
        assert_eq!(dt.get_length(), 10);
        assert_eq!(dt.get_aligned_length(), 16);
        assert_eq!(dt.get_description(), "IEEE 754 floating-point type (80-bit / 10-byte format, aligned-length is 16-bytes)");
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_mnemonic(&s), "float10");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("FLOAT10"));
        assert_eq!(dt.get_value_class(&s), Some(std::any::TypeId::of::<BigFloat>()));
        assert!(dt.is_encodable());
        assert!(dt.is_floating_point());
        // Only the BuiltIn mutability setting (AbstractFloatDataType.SETTINGS_DEFS is empty).
        assert_eq!(dt.get_settings_definitions().len(), 1);
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some("float10"));
    }

    #[test]
    fn value_representation_and_encoding() {
        let dt = Float10DataType::new(None);
        let s = LongSettings::default();
        let expected = get_float_format(10).unwrap().get_big_float_f64(7.0);
        let value = dt.get_value(&buf(&[64, 1, 224, 0, 0, 0, 0, 0, 0, 0], true), &s, 10).unwrap();
        assert_eq!(value.downcast_ref::<BigFloat>().unwrap(), &expected);
        let value = dt.get_value(&buf(&[0, 0, 0, 0, 0, 0, 0, 224, 1, 64], false), &s, 10).unwrap();
        assert_eq!(value.downcast_ref::<BigFloat>().unwrap(), &expected);
        assert_eq!(dt.encode_value(&expected, &buf(&[], true), &s, 10).unwrap(), vec![64, 1, 224, 0, 0, 0, 0, 0, 0, 0]);
        assert!(dt.encode_value(&7.0f64, &buf(&[], true), &s, 10).is_err());
        assert!(dt.get_value(&buf(&[0], true), &s, 10).is_none());
        assert_eq!(dt.get_representation(&buf(&[0], true), &s, 10), "??");
    }

    #[test]
    fn singleton_and_class_equivalence() {
        let a = Float10DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Float10DataType::data_type()));
        assert!(a.is_equivalent(&Float10DataType::new(None)));
        assert!(!a.is_equivalent(Float8DataType::instance().as_ref()));
        assert!(a.as_built_in().is_some());
    }
}
