//! Port of `ghidra.program.model.data.AbstractSignedIntegerDataType`, promoted to a trait because
//! it was selected as a dependency-cycle cut-point.
//!
//! The Java class is tiny: it just extends [`AbstractIntegerDataType`] and pins
//! `isSigned()` to `final boolean isSigned() { return true; }`. Its constructor
//! (`protected AbstractSignedIntegerDataType(String name, DataTypeManager dtm)`) merely forwards
//! to the superclass constructor, so -- mirroring
//! [`AbstractUnsignedIntegerDataType`](super::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType),
//! its exact unsigned counterpart -- it is not translated (traits cannot declare constructors or
//! store fields).
//!
//! `is_signed` is already a required (no-default) method on the supertrait
//! [`AbstractIntegerDataType`], and Rust does not allow a subtrait to override/default a
//! supertrait's method under the same name (it would create an ambiguous method for any type
//! implementing both). So, mirroring the convention established by
//! [`AbstractUnsignedIntegerDataType::unsigned_is_signed`], this pinned override is exposed under
//! the distinct name [`signed_is_signed`](AbstractSignedIntegerDataType::signed_is_signed). A
//! concrete `impl AbstractIntegerDataType for ...` should delegate `is_signed` to this.

use crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType;

/// Base type for signed integer data types.
///
/// Port of `ghidra.program.model.data.AbstractSignedIntegerDataType`. See the module-level
/// documentation for why `isSigned()` is exposed under a distinct name.
pub trait AbstractSignedIntegerDataType: AbstractIntegerDataType {
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`. Always `true`.
    fn signed_is_signed(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::array_stringable::ArrayStringable;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::mem::MemBuffer;

    struct MockSignedIntDataType {
        name: &'static str,
        length: i32,
    }

    impl DataType for MockSignedIntDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_signed_integer_type(&self) -> bool {
            self.is_signed()
        }
    }

    impl BuiltInDataType for MockSignedIntDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl ArrayStringable for MockSignedIntDataType {
        fn has_string_value(&self, _settings: &dyn crate::docking::settings::settings::Settings) -> bool {
            false
        }
        fn string_data_instance(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn crate::docking::settings::settings::Settings,
            _length: i32,
        ) -> Box<dyn StringDataInstance> {
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_array_default_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn crate::docking::settings::settings::Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn crate::docking::settings::settings::Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
            _offcut_length: i32,
        ) -> Option<String> {
            None
        }
    }

    impl AbstractIntegerDataType for MockSignedIntDataType {
        fn is_signed(&self) -> bool {
            self.signed_is_signed()
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl AbstractSignedIntegerDataType for MockSignedIntDataType {}

    #[test]
    fn usable_as_trait_object_and_always_signed() {
        let dt = MockSignedIntDataType { name: "int", length: 4 };
        let dyn_dt: &dyn AbstractSignedIntegerDataType = &dt;
        assert!(dyn_dt.signed_is_signed());
        // The supertrait's `is_signed`, delegated to `signed_is_signed`, agrees.
        assert!(dt.is_signed());
        assert!(dt.is_signed_integer_type());
    }
}
