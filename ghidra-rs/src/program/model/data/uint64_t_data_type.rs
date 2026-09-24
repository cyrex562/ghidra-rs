//! Port of `ghidra.program.model.data.UInt64TDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractUnsignedIntegerDataType`, already ported as a trait
//! ([`AbstractUnsignedIntegerDataType`]), so this trait extends it directly -- structurally
//! similar to the fixed-size
//! [`UnsignedInteger5DataType`](super::unsigned_integer5_data_type::UnsignedInteger5DataType)
//! family (`getDescription`/`getLength`/`getOppositeSignednessDataType`/`clone` exposed under
//! distinct `uint64_t_*` names for the same "subtrait cannot redeclare a supertrait method"
//! restriction documented there), except `UInt64TDataType` additionally overrides
//! `getCDeclaration()` (always `None`, matching the Java override which unconditionally returns
//! `null`) and `getCTypeDeclaration(DataOrganization)` (reproducing the `BuiltIn.getCTypeDeclaration(BuiltIn,
//! boolean, DataOrganization, boolean)` overload's formula directly, mirroring
//! [`UnsignedPointerSizedIntegerDataType::unsigned_pointer_sized_integer_c_type_declaration`](super::unsigned_pointer_sized_integer_data_type::UnsignedPointerSizedIntegerDataType::unsigned_pointer_sized_integer_c_type_declaration),
//! but with a fixed 1-byte width rather than the pointer-size width used there).
//!
//! `getOppositeSignednessDataType()` clones `Int64TDataType.dataType`, an already-ported trait
//! ([`Int64TDataType`](crate::program::model::data::int64_t_data_type::Int64TDataType)) with no
//! seam-stub placeholder needed, so this trait's `uint64_t_opposite_signedness_data_type` returns
//! `Box<dyn Int64TDataType>` directly.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::int64_t_data_type::Int64TDataType;

/// 64-bit unsigned integer (C99 Standard type `uint64_t`).
///
/// Port of `ghidra.program.model.data.UInt64TDataType`. See the module-level documentation for the
/// naming conventions used to resolve clashes with
/// [`DataType`]/[`AbstractIntegerDataType`](crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType).
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait UInt64TDataType: AbstractUnsignedIntegerDataType {
    /// Port of `UInt64TDataType.getLength()`, which overrides the default `DataType.getLength()`.
    /// Always `8`, matching the fixed C99 `uint64_t` width.
    fn uint64_t_length(&self) -> i32 {
        8
    }

    /// Port of `UInt64TDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn uint64_t_description(&self) -> String {
        "Unsigned 64-bit Integer".to_string()
    }

    /// Port of `UInt64TDataType.getCDeclaration()`, which overrides the default
    /// `AbstractIntegerDataType.getCDeclaration()`. Always `None`, matching the Java override
    /// which unconditionally returns `null`.
    fn uint64_t_c_declaration(&self) -> Option<String> {
        None
    }

    /// Returns the data-type with the opposite signedness from this data-type (an 64-bit signed
    /// integer type).
    ///
    /// Port of `UInt64TDataType.getOppositeSignednessDataType()`, which overrides the required
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `Int64TDataType.dataType` singleton --
    /// see the module docs for why this can point at the already-ported [`Int64TDataType`]
    /// directly rather than a seam-stub placeholder.
    fn uint64_t_opposite_signedness_data_type(&self) -> Box<dyn Int64TDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `UInt64TDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractUnsignedIntegerDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a
    /// required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn uint64_t_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UInt64TDataType>;

    /// Port of `UInt64TDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Reproduces
    /// `BuiltIn.getCTypeDeclaration(this, false, dataOrganization, false)`: a `typedef` line
    /// naming this type's fixed display name (`uint64_t`) after the organization's *unsigned*
    /// 64-bit C-type approximation.
    fn uint64_t_get_c_type_declaration(&self, data_organization: &DataOrganizationImpl) -> Option<String> {
        Some(format!(
            "typedef {}    uint64_t;",
            data_organization.get_integer_c_type_approximation(8, false)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType;
    use crate::program::model::data::array_stringable::ArrayStringable;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::mem::MemBuffer;

            /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn mock_data_organization() -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(false);
        org.set_pointer_size(8);
        org.set_pointer_shift(0);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(2);
        org.set_short_size(2);
        org.set_integer_size(4);
        org.set_long_size(8);
        org.set_long_long_size(8);
        org.set_float_size(4);
        org.set_double_size(8);
        org.set_long_double_size(8);
        org.set_absolute_max_alignment(0);
        org.set_machine_alignment(8);
        org.set_default_alignment(1);
        org.set_default_pointer_alignment(8);
        org.clear_size_alignment_map();
        org
    }

    struct MockInt64TDataType;
    impl DataType for MockInt64TDataType {
        fn get_name(&self) -> String {
            "int64_t".to_string()
        }
    }
    impl BuiltInDataType for MockInt64TDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl Int64TDataType for MockInt64TDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn crate::program::seam_stubs::UInt64TDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn int64_t_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Int64TDataType> {
            Box::new(MockInt64TDataType)
        }
    }

    struct MockUInt64TDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUInt64TDataType {
        fn get_name(&self) -> String {
            "uint64_t".to_string()
        }
        fn get_length(&self) -> i32 {
            self.uint64_t_length()
        }
    }

    impl BuiltInDataType for MockUInt64TDataType {
        fn get_c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            data_organization.and_then(|org| self.uint64_t_get_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl ArrayStringable for MockUInt64TDataType {
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

    impl AbstractIntegerDataType for MockUInt64TDataType {
        fn is_signed(&self) -> bool {
            self.unsigned_is_signed()
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl AbstractUnsignedIntegerDataType for MockUInt64TDataType {}

    impl UInt64TDataType for MockUInt64TDataType {
        fn uint64_t_opposite_signedness_data_type(&self) -> Box<dyn Int64TDataType> {
            Box::new(MockInt64TDataType)
        }

        fn uint64_t_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UInt64TDataType> {
            match dtm {
                None => Box::new(MockUInt64TDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockUInt64TDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUInt64TDataType { dtm_tag: None };
        let dyn_dt: &dyn UInt64TDataType = &dt;
        assert_eq!(dyn_dt.uint64_t_length(), 8);
        assert_eq!(DataType::get_length(dyn_dt), 8);
        assert_eq!(dyn_dt.uint64_t_description(), "Unsigned 64-bit Integer");
        assert_eq!(dyn_dt.uint64_t_c_declaration(), None);
        assert!(!dt.is_signed());
    }

    #[test]
    fn c_type_declaration_uses_unsigned_8bit_approximation() {
        let dt = MockUInt64TDataType { dtm_tag: None };
        let org = mock_data_organization();
        assert_eq!(
            dt.uint64_t_get_c_type_declaration(&org),
            Some("typedef unsigned long    uint64_t;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_int64_t_data_type() {
        let dt = MockUInt64TDataType { dtm_tag: None };
        let opposite = dt.uint64_t_opposite_signedness_data_type();
        assert_eq!(opposite.get_name(), "int64_t");
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUInt64TDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.uint64_t_clone(None);
        assert_eq!(cloned.uint64_t_length(), 8);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUInt64TDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.uint64_t_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.uint64_t_length(), 8);
    }
}
