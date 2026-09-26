//! Port of `ghidra.program.model.data.UnsignedCharDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends CharDataType`, already ported as a trait
//! ([`CharDataType`](crate::program::model::data::char_data_type::CharDataType)), so this trait
//! extends it directly -- unlike its `UnsignedInteger*` siblings
//! ([`UnsignedIntegerDataType`](super::unsigned_integer_data_type::UnsignedIntegerDataType) etc.),
//! which extend `AbstractUnsignedIntegerDataType`.
//!
//! `isSigned()`, `getDescription()`, `getDefaultLabelPrefix()`, and `getCDeclaration()` each
//! override an already-provided default method on [`DataType`]/[`CharDataType`]; `getCTypeDeclaration(DataOrganization)`
//! overrides the abstract, required `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Rust
//! does not allow a subtrait to override a supertrait's method (default or required) by
//! redeclaring it under the same name -- see this crate's other `Abstract*`/leaf cut-point traits
//! for the same restriction -- so all five are exposed here under distinct `unsigned_char_*`
//! names. A concrete `impl DataType + BuiltInDataType + CharDataType for ...` should delegate to
//! these.
//!
//! `getCTypeDeclaration(DataOrganization)` calls `getCTypeDeclaration(getName(),
//! getCDeclaration(), false)` -- i.e. it uses *this* class's own overridden `getCDeclaration()`
//! (`"unsigned char"`), not `CharDataType`'s. Mirroring
//! [`UnsignedIntegerDataType`](super::unsigned_integer_data_type::UnsignedIntegerDataType)'s
//! identical situation, the `BuiltIn.getCTypeDeclaration(String, String, boolean)` helper's
//! trivial `typedef` formula is reproduced directly here rather than stubbed, since `BuiltIn` is
//! not a supertrait reached from `CharDataType`.

use crate::program::model::data::char_data_type::CharDataType;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Provides a definition of a primitive unsigned char data type. While in most environments the
/// size is one 8-bit byte, this can vary based upon data organization imposed by the associated
/// data type manager.
///
/// Port of `ghidra.program.model.data.UnsignedCharDataType`. See the module-level documentation
/// for the naming conventions used to resolve clashes with
/// [`DataType`](crate::program::model::data::data_type::DataType)/[`CharDataType`].
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait UnsignedCharDataType: CharDataType {
    /// Port of `UnsignedCharDataType.isSigned()`, which overrides the default
    /// `CharDataType.isSigned()` (which delegates to `DataOrganization::is_signed_char`). Always
    /// `false`.
    fn unsigned_char_is_signed(&self) -> bool {
        false
    }

    /// Port of `UnsignedCharDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn unsigned_char_description(&self) -> String {
        "Unsigned Character (ASCII)".to_string()
    }

    /// Port of `UnsignedCharDataType.getDefaultLabelPrefix()`, which overrides the default
    /// `DataType.getDefaultLabelPrefix()`.
    fn unsigned_char_default_label_prefix(&self) -> Option<String> {
        Some("UCHAR".to_string())
    }

    /// Port of `UnsignedCharDataType.getCDeclaration()`, which overrides the default
    /// `CharDataType.getCDeclaration()` (`Some(self.get_name())`). Unlike that default, this
    /// override always succeeds with a fixed value, matching the Java `return "unsigned char";`
    /// body.
    fn unsigned_char_c_declaration(&self) -> String {
        "unsigned char".to_string()
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `UnsignedCharDataType.clone(DataTypeManager)`, which overrides
    /// `CharDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required method (no
    /// default); see [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone)
    /// for why.
    fn unsigned_char_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedCharDataType>;

    /// Port of `UnsignedCharDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. `data_organization` is
    /// unused, matching the Java original. See the module docs for why the
    /// `BuiltIn.getCTypeDeclaration(String, String, boolean)` helper's formula is reproduced
    /// directly instead of stubbed, and for why this uses
    /// [`unsigned_char_c_declaration`](Self::unsigned_char_c_declaration) rather than
    /// `CharDataType::get_c_declaration`.
    fn unsigned_char_c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        let _ = data_organization;
        Some(format!("typedef {}    {};", self.unsigned_char_c_declaration(), self.get_name()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_with_charset::DataTypeWithCharset;
    use crate::program::model::mem::MemBuffer;

            /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn mock_data_organization() -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(true);
        org.set_pointer_size(8);
        org.set_pointer_shift(0);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(4);
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
        org
    }

    struct MockUnsignedCharDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUnsignedCharDataType {
        fn get_name(&self) -> String {
            "uchar".to_string()
        }
        fn get_length(&self) -> i32 {
            1
        }
        fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
            Arc::new(mock_data_organization())
        }
    }

    impl DataTypeWithCharset for MockUnsignedCharDataType {
        fn string_data_instance(
            &self,
            _settings: &dyn Settings,
            _buf: &dyn MemBuffer,
        ) -> Box<dyn crate::program::model::data::string_data_instance::StringDataInstance> {
            unimplemented!("not exercised by these tests")
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.char_charset_name(settings)
        }
    }

    impl BuiltInDataType for MockUnsignedCharDataType {
        fn get_c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            self.unsigned_char_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl CharDataType for MockUnsignedCharDataType {
        fn is_signed(&self) -> bool {
            self.unsigned_char_is_signed()
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn CharDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl UnsignedCharDataType for MockUnsignedCharDataType {
        fn unsigned_char_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedCharDataType> {
            match dtm {
                None => Box::new(MockUnsignedCharDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockUnsignedCharDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUnsignedCharDataType { dtm_tag: None };
        let dyn_dt: &dyn UnsignedCharDataType = &dt;
        assert!(!dyn_dt.unsigned_char_is_signed());
        // Even though the underlying DataOrganization claims signed char, the override always
        // reports unsigned -- matching CharDataType::is_signed being pinned by this override.
        assert!(!dt.is_signed());
        assert_eq!(dyn_dt.unsigned_char_description(), "Unsigned Character (ASCII)");
        assert_eq!(dyn_dt.unsigned_char_default_label_prefix(), Some("UCHAR".to_string()));
        assert_eq!(dyn_dt.unsigned_char_c_declaration(), "unsigned char");
    }

    #[test]
    fn c_type_declaration_uses_own_c_declaration_override() {
        let dt = MockUnsignedCharDataType { dtm_tag: None };
        assert_eq!(
            dt.unsigned_char_c_type_declaration(None),
            Some("typedef unsigned char    uchar;".to_string())
        );
        let via_trait: &dyn BuiltInDataType = &dt;
        assert_eq!(via_trait.get_c_type_declaration(None), dt.unsigned_char_c_type_declaration(None));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUnsignedCharDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_char_clone(None);
        assert_eq!(cloned.unsigned_char_description(), dt.unsigned_char_description());
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUnsignedCharDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_char_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.unsigned_char_c_declaration(), "unsigned char");
    }
}
