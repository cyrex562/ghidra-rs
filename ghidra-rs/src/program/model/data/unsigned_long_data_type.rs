//! Port of `ghidra.program.model.data.UnsignedLongDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractUnsignedIntegerDataType`, already ported as a trait
//! ([`AbstractUnsignedIntegerDataType`]), so this trait extends it directly. Structurally similar
//! to [`UnsignedIntegerDataType`](super::unsigned_integer_data_type::UnsignedIntegerDataType) --
//! see that trait's module docs for the shared rationale (`getLength`/
//! `hasLanguageDependantLength`/`getDescription`/`getCTypeDeclaration` overriding
//! already-provided defaults, `getCDeclaration` overriding the reached-transitively default
//! `AbstractIntegerDataType.getCDeclaration()`, `getOppositeSignednessDataType` overriding the
//! required no-default `AbstractIntegerDataType.getOppositeSignednessDataType()`, all five
//! therefore exposed under distinct `unsigned_long_*` names) -- except `getOppositeSignednessDataType()`
//! clones `LongDataType.dataType`, and unlike `UnsignedIntegerDataType`'s own `IntegerDataType`
//! counterpart, [`LongDataType`](crate::program::model::data::long_data_type::LongDataType) is an
//! already-ported trait with no seam-stub placeholder needed at all, so this trait's
//! `unsigned_long_opposite_signedness_data_type` returns `Box<dyn LongDataType>` directly.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::abstract_integer_data_type::C_UNSIGNED_LONG;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::long_data_type::LongDataType;

/// Basic implementation for a Signed Long Integer dataType.
///
/// Port of `ghidra.program.model.data.UnsignedLongDataType`. See the module-level documentation
/// for the naming conventions used to resolve clashes with
/// [`DataType`]/[`AbstractIntegerDataType`](crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType).
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait UnsignedLongDataType: AbstractUnsignedIntegerDataType {
    /// Port of `UnsignedLongDataType.getLength()`, which overrides the default
    /// `DataType.getLength()`.
    fn unsigned_long_length(&self) -> i32 {
        self.get_data_organization().get_long_size()
    }

    /// Port of `UnsignedLongDataType.hasLanguageDependantLength()`, which overrides the default
    /// `DataType.hasLanguageDependantLength()`. Always `true`.
    fn unsigned_long_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Port of `UnsignedLongDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn unsigned_long_description(&self) -> String {
        "Unsigned Long Integer (compiler-specific size)".to_string()
    }

    /// Port of `UnsignedLongDataType.getCDeclaration()`, which overrides the default
    /// `AbstractIntegerDataType.getCDeclaration()`.
    fn unsigned_long_c_declaration(&self) -> String {
        C_UNSIGNED_LONG.to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (a signed long
    /// type).
    ///
    /// Port of `UnsignedLongDataType.getOppositeSignednessDataType()`, which overrides the
    /// required `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required
    /// method (no default) since the real implementation clones the `LongDataType.dataType`
    /// singleton -- see the module docs for why this can point at the already-ported
    /// [`LongDataType`] directly rather than a seam-stub placeholder.
    fn unsigned_long_opposite_signedness_data_type(&self) -> Box<dyn LongDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `UnsignedLongDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractUnsignedIntegerDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a
    /// required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn unsigned_long_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedLongDataType>;

    /// Port of `UnsignedLongDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. `data_organization` is
    /// unused, matching the Java original (which only ever formats `getName()`/`"unsigned
    /// long"`). Reproduces `getCTypeDeclaration(getName(), "unsigned long", false)`'s trivial
    /// `typedef` formula directly, mirroring
    /// [`UnsignedIntegerDataType::unsigned_integer_c_type_declaration`](super::unsigned_integer_data_type::UnsignedIntegerDataType::unsigned_integer_c_type_declaration).
    fn unsigned_long_c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        let _ = data_organization;
        Some(format!("typedef {}    {};", C_UNSIGNED_LONG, self.get_name()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use crate::program::model::data::array_stringable::ArrayStringable;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::mem::MemBuffer;

            /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn mock_data_organization(long_size: i32) -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(false);
        org.set_pointer_size(8);
        org.set_pointer_shift(0);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(2);
        org.set_short_size(2);
        org.set_integer_size(4);
        org.set_long_size(long_size);
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

    struct MockLongDataType;
    impl DataType for MockLongDataType {
        fn get_name(&self) -> String {
            "long".to_string()
        }
    }
    impl BuiltInDataType for MockLongDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl LongDataType for MockLongDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn crate::program::seam_stubs::UnsignedLongDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn long_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn LongDataType> {
            Box::new(MockLongDataType)
        }
    }

    struct MockUnsignedLongDataType {
        long_size: i32,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUnsignedLongDataType {
        fn get_name(&self) -> String {
            "ulong".to_string()
        }
        fn get_length(&self) -> i32 {
            self.unsigned_long_length()
        }
        fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
            Arc::new(mock_data_organization(self.long_size))
        }
    }

    impl BuiltInDataType for MockUnsignedLongDataType {
        fn get_c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            self.unsigned_long_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl ArrayStringable for MockUnsignedLongDataType {
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

    impl crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType for MockUnsignedLongDataType {
        fn is_signed(&self) -> bool {
            self.unsigned_is_signed()
        }
        fn get_opposite_signedness_data_type(
            &self,
        ) -> Box<dyn crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl AbstractUnsignedIntegerDataType for MockUnsignedLongDataType {}

    impl UnsignedLongDataType for MockUnsignedLongDataType {
        fn unsigned_long_opposite_signedness_data_type(&self) -> Box<dyn LongDataType> {
            Box::new(MockLongDataType)
        }

        fn unsigned_long_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedLongDataType> {
            match dtm {
                None => Box::new(MockUnsignedLongDataType {
                    long_size: self.long_size,
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockUnsignedLongDataType {
                    long_size: self.long_size,
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUnsignedLongDataType { long_size: 8, dtm_tag: None };
        let dyn_dt: &dyn UnsignedLongDataType = &dt;
        assert_eq!(dyn_dt.unsigned_long_length(), 8);
        assert_eq!(DataType::get_length(dyn_dt), 8);
        assert!(dyn_dt.unsigned_long_has_language_dependant_length());
        assert_eq!(dyn_dt.unsigned_long_description(), "Unsigned Long Integer (compiler-specific size)");
        assert_eq!(dyn_dt.unsigned_long_c_declaration(), "unsigned long");
    }

    #[test]
    fn c_type_declaration_formats_typedef() {
        let dt = MockUnsignedLongDataType { long_size: 8, dtm_tag: None };
        assert_eq!(
            dt.unsigned_long_c_type_declaration(None),
            Some("typedef unsigned long    ulong;".to_string())
        );
        let via_trait: &dyn BuiltInDataType = &dt;
        assert_eq!(via_trait.get_c_type_declaration(None), dt.unsigned_long_c_type_declaration(None));
    }

    #[test]
    fn opposite_signedness_returns_long_data_type() {
        let dt = MockUnsignedLongDataType { long_size: 8, dtm_tag: None };
        let opposite = dt.unsigned_long_opposite_signedness_data_type();
        assert_eq!(opposite.get_name(), "long");
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUnsignedLongDataType { long_size: 8, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_long_clone(None);
        assert_eq!(cloned.unsigned_long_length(), 8);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUnsignedLongDataType { long_size: 8, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_long_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.unsigned_long_length(), 8);
    }
}
