//! Port of `ghidra.program.model.data.Float16DataType`.

use crate::program::model::data::abstract_float_data_type::float_data_type;

float_data_type! {
    /// Provides a definition of a Float16 (IEEE 754 quadruple precision) within a program.
    ///
    /// Port of `ghidra.program.model.data.Float16DataType`.
    Float16DataType {
        name: "float16",
        length: 16,
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
        let dt = Float16DataType::instance();
        let s = LongSettings::default();
        assert_eq!(dt.get_name(), "float16");
        assert_eq!(dt.get_length(), 16);
        assert_eq!(dt.get_aligned_length(), 16);
        assert_eq!(dt.get_description(), "IEEE 754 floating-point type (128-bit / 16-byte format, aligned-length is 16-bytes)");
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_mnemonic(&s), "float16");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("FLOAT16"));
        assert_eq!(dt.get_value_class(&s), Some(std::any::TypeId::of::<BigFloat>()));
        assert!(dt.is_encodable());
        assert!(dt.is_floating_point());
        // Only the BuiltIn mutability setting (AbstractFloatDataType.SETTINGS_DEFS is empty).
        assert_eq!(dt.get_settings_definitions().len(), 1);
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some("float16"));
    }

    #[test]
    fn value_representation_and_encoding() {
        let dt = Float16DataType::new(None);
        let s = LongSettings::default();
        let expected = get_float_format(16).unwrap().get_big_float_f64(1.0);
        let value = dt.get_value(&buf(&[63, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], true), &s, 16).unwrap();
        assert_eq!(value.downcast_ref::<BigFloat>().unwrap(), &expected);
        let value = dt.get_value(&buf(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 63], false), &s, 16).unwrap();
        assert_eq!(value.downcast_ref::<BigFloat>().unwrap(), &expected);
        assert_eq!(dt.encode_value(&expected, &buf(&[], true), &s, 16).unwrap(), vec![63, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(dt.encode_value(&1.0f64, &buf(&[], true), &s, 16).is_err());
        assert!(dt.get_value(&buf(&[0], true), &s, 16).is_none());
        assert_eq!(dt.get_representation(&buf(&[0], true), &s, 16), "??");
    }

    #[test]
    fn singleton_and_class_equivalence() {
        let a = Float16DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Float16DataType::data_type()));
        assert!(a.is_equivalent(&Float16DataType::new(None)));
        assert!(!a.is_equivalent(Float8DataType::instance().as_ref()));
        assert!(a.as_built_in().is_some());
    }
}
