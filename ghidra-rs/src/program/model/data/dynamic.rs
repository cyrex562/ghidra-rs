use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::seam_stubs::MemBuffer;

/// A DataType class that must compute its length based upon actual data.
/// This type may be referred to directly within a listing (including pointers).
/// This type may only appear within a structure if [`Dynamic::can_specify_length`] returns
/// true. A pointer to this type can always appear within a structure.
/// TypeDef to this data-type should not be allowed.
///
/// Port of `ghidra.program.model.data.Dynamic`. The overloaded Java `getLength(MemBuffer, int)`
/// is renamed to `get_dynamic_length` since Rust does not support overloading against
/// [`DataType::get_length`].
pub trait Dynamic: BuiltInDataType {
    /// Compute the length for this data-type which corresponds to the specified memory
    /// location.
    ///
    /// `max_length` is the maximum number of bytes to consume in computing length, or -1 for
    /// unspecified.
    ///
    /// Returns the data length or -1 if it could not be determined. The returned length may
    /// exceed `max_length` if the data-type does not support constrained lengths.
    fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32;

    /// Determine if the length may be specified for an instance of this datatype (e.g., `Data`,
    /// `Array`, `DataTypeComponent`, etc.).
    ///
    /// Returns true if a user-specified length can be used, else false.
    fn can_specify_length(&self) -> bool {
        false
    }

    /// Returns a suitable replacement base data-type for pointers and arrays when exporting to C
    /// code.
    fn get_replacement_base_type(&self) -> Box<dyn DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::docking::settings::settings::Settings;

    struct MockMemBuffer;
    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockDynamic;

    impl DataType for MockDynamic {
        fn get_length(&self) -> i32 {
            -1
        }
    }

    impl BuiltInDataType for MockDynamic {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }

        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockDynamic {
        fn get_dynamic_length(&self, _buf: &dyn MemBuffer, max_length: i32) -> i32 {
            max_length
        }

        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            struct ReplacementBaseType;
            impl DataType for ReplacementBaseType {
                fn get_length(&self) -> i32 {
                    -1
                }
            }
            Box::new(ReplacementBaseType)
        }
    }

    #[test]
    fn default_can_specify_length_is_false() {
        let dynamic = MockDynamic;
        assert!(!dynamic.can_specify_length());
    }

    #[test]
    fn usable_as_trait_object() {
        let dynamic = MockDynamic;
        let dyn_dynamic: &dyn Dynamic = &dynamic;
        assert_eq!(dyn_dynamic.get_dynamic_length(&MockMemBuffer, 16), 16);
        assert_eq!(dyn_dynamic.get_replacement_base_type().get_length(), -1);
    }
}
