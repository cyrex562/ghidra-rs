//! Port of `ghidra.program.model.data.Float2DataType`.

use crate::program::model::data::abstract_float_data_type::float_data_type;

float_data_type! {
    /// Provides a definition of a Float2 (IEEE 754 half precision) within a program.
    ///
    /// Port of `ghidra.program.model.data.Float2DataType`.
    Float2DataType {
        name: "float2",
        length: 2,
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
        let dt = Float2DataType::instance();
        let s = LongSettings::default();
        assert_eq!(dt.get_name(), "float2");
        assert_eq!(dt.get_length(), 2);
        assert_eq!(dt.get_aligned_length(), 2);
        assert_eq!(dt.get_description(), "IEEE 754 floating-point type (16-bit / 2-byte format, aligned-length is 2-bytes)");
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_mnemonic(&s), "float2");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("FLOAT2"));
        assert_eq!(dt.get_value_class(&s), Some(std::any::TypeId::of::<BigFloat>()));
        assert!(dt.is_encodable());
        assert!(dt.is_floating_point());
        // Only the BuiltIn mutability setting (AbstractFloatDataType.SETTINGS_DEFS is empty).
        assert_eq!(dt.get_settings_definitions().len(), 1);
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some("float2"));
    }

    #[test]
    fn value_representation_and_encoding() {
        let dt = Float2DataType::new(None);
        let s = LongSettings::default();
        assert_eq!(dt.get_representation(&buf(&[62, 0], true), &s, 2), "1.5");
        assert_eq!(dt.get_representation(&buf(&[0, 62], false), &s, 2), "1.5");
        let encoded = dt.encode_representation("1.5", &buf(&[], true), &s, 2);
        assert_eq!(encoded.unwrap(), vec![62, 0]);
        // A plain number is only accepted for the 4- and 8-byte formats.
        assert!(dt.encode_value(&1.5f64, &buf(&[], true), &s, 2).is_err());
        assert!(dt.get_value(&buf(&[0], true), &s, 2).is_none());
        assert_eq!(dt.get_representation(&buf(&[0], true), &s, 2), "??");
    }

    #[test]
    fn singleton_and_class_equivalence() {
        let a = Float2DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Float2DataType::data_type()));
        assert!(a.is_equivalent(&Float2DataType::new(None)));
        assert!(!a.is_equivalent(Float8DataType::instance().as_ref()));
        assert!(a.as_built_in().is_some());
    }
}
