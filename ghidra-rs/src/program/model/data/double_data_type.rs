//! Port of `ghidra.program.model.data.DoubleDataType`.

use crate::program::model::data::abstract_float_data_type::float_data_type;

float_data_type! {
    /// Provides a definition of the compiler-defined `double` within a program.
    ///
    /// Port of `ghidra.program.model.data.DoubleDataType`.
    DoubleDataType {
        name: "double",
        length: get_double_size,
        description_prefix: "Compiler-defined 'double' ",
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
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type_manager::DataTypeManager;

    #[test]
    fn java_constants() {
        let dt = DoubleDataType::instance();
        let s = LongSettings::default();
        assert_eq!(dt.get_name(), "double");
        assert_eq!(dt.get_length(), 8);
        assert_eq!(dt.get_aligned_length(), 8);
        assert_eq!(dt.get_description(), "Compiler-defined 'double' IEEE 754 floating-point type (64-bit / 8-byte format, aligned-length is 8-bytes)");
        assert!(dt.has_language_dependant_length());
        assert_eq!(dt.get_mnemonic(&s), "double");
        assert_eq!(dt.get_default_label_prefix().as_deref(), Some("DOUBLE"));
        assert_eq!(dt.get_value_class(&s), Some(std::any::TypeId::of::<BigFloat>()));
        assert!(dt.is_encodable());
        assert!(dt.is_floating_point());
        // Only the BuiltIn mutability setting (AbstractFloatDataType.SETTINGS_DEFS is empty).
        assert_eq!(dt.get_settings_definitions().len(), 1);
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)).as_deref(), None);
    }

    #[test]
    fn value_representation_and_encoding() {
        let dt = DoubleDataType::new(None);
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
        let a = DoubleDataType::data_type();
        assert!(Arc::ptr_eq(&a, &DoubleDataType::data_type()));
        assert!(a.is_equivalent(&DoubleDataType::new(None)));
        assert!(!a.is_equivalent(Float8DataType::instance().as_ref()));
        assert!(a.as_built_in().is_some());
    }

    #[test]
    fn length_follows_the_manager_data_organization() {
        struct WideFloats;
        impl DataTypeManager for WideFloats {
            fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
                let mut org = DataOrganizationImpl::get_default_organization(None);
                org.set_float_size(8);
                org.set_double_size(10);
                org.set_long_double_size(16);
                Arc::new(org)
            }
        }
        let dt = DoubleDataType::new(Some(&WideFloats));
        let expected = 10;
        assert_eq!(dt.get_length(), expected);
        assert!(dt.float_format().is_some());
        assert_eq!(DoubleDataType::instance().clone_data_type(&WideFloats).get_length(), expected);
    }
}
