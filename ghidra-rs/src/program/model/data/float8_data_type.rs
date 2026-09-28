//! Port of `ghidra.program.model.data.Float8DataType`.

use crate::program::model::data::abstract_float_data_type::float_data_type;

float_data_type! {
    /// Provides a definition of a Float8 (IEEE 754 double precision) within a program.
    ///
    /// Port of `ghidra.program.model.data.Float8DataType`.
    Float8DataType {
        name: "float8",
        length: 8,
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
    use crate::program::model::data::float4_data_type::Float4DataType;

    #[test]
    fn java_constants() {
        let dt = Float8DataType::instance();
        let s = LongSettings::default();
        assert_eq!(dt.get_name(), "float8");
        assert_eq!(dt.get_length(), 8);
        assert_eq!(dt.get_aligned_length(), 8);
        assert_eq!(dt.get_description(), "IEEE 754 floating-point type (64-bit / 8-byte format, aligned-length is 8-bytes)");
        assert!(!dt.has_language_dependant_length());
        assert_eq!(dt.get_mnemonic(&s), "float8");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("FLOAT8"));
        assert_eq!(dt.get_value_class(&s), Some(std::any::TypeId::of::<BigFloat>()));
        assert!(dt.is_encodable());
        assert!(dt.is_floating_point());
        // Only the BuiltIn mutability setting (AbstractFloatDataType.SETTINGS_DEFS is empty).
        assert_eq!(dt.get_settings_definitions().len(), 1);
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), Some("float8"));
    }

    #[test]
    fn value_representation_and_encoding() {
        let dt = Float8DataType::new(None);
        let s = LongSettings::default();
        assert_eq!(dt.get_representation(&buf(&[191, 224, 0, 0, 0, 0, 0, 0], true), &s, 8), "-0.5");
        assert_eq!(dt.get_representation(&buf(&[0, 0, 0, 0, 0, 0, 224, 191], false), &s, 8), "-0.5");
        let encoded = dt.encode_representation("-0.5", &buf(&[], true), &s, 8);
        assert_eq!(encoded.unwrap(), vec![191, 224, 0, 0, 0, 0, 0, 0]);
        assert_eq!(dt.encode_value(&-0.5f64, &buf(&[], false), &s, 8).unwrap(), vec![0, 0, 0, 0, 0, 0, 224, 191]);
        assert!(dt.get_value(&buf(&[0], true), &s, 8).is_none());
        assert_eq!(dt.get_representation(&buf(&[0], true), &s, 8), "??");
    }

    #[test]
    fn singleton_and_class_equivalence() {
        let a = Float8DataType::data_type();
        assert!(Arc::ptr_eq(&a, &Float8DataType::data_type()));
        assert!(a.is_equivalent(&Float8DataType::new(None)));
        assert!(!a.is_equivalent(Float4DataType::instance().as_ref()));
        assert!(a.as_built_in().is_some());
    }
}
