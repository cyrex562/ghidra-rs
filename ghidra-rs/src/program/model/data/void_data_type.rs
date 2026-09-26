use crate::docking::settings::settings::Settings;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Special dataType used only for function return types. Used to indicate that a function has no
/// return value.
///
/// Port of `ghidra.program.model.data.VoidDataType`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point.
///
/// The Java class `extends BuiltIn`, already ported as a trait ([`BuiltIn`]), so this trait
/// extends it directly.
///
/// `getLength()`, `getRepresentation(MemBuffer, Settings, int)`, and `getValue(MemBuffer,
/// Settings, int)` are all overridden in Java, but each override is byte-for-byte identical to
/// the [`DataType`](crate::program::model::data::data_type::DataType) default already in place
/// (`0`, `""`, and `null`/`None` respectively) -- mirroring the precedent set by
/// [`DataTypeImpl`](crate::program::model::data::data_type_impl::DataTypeImpl)'s own module docs
/// for identical-to-default overrides -- so none of the three are re-declared here.
///
/// `getMnemonic(Settings)` and `getDescription()` override defaults with genuinely different
/// (constant) values, so -- following the same ambiguous-redeclare restriction documented
/// throughout this crate's other `Abstract*`/cut-point traits -- they are exposed here under
/// distinct `void_*` names.
///
/// `isVoidDataType(DataType)` is not ported as a method on this trait: the already-ported
/// [`is_void_data_type`](crate::program::seam_stubs::is_void_data_type) placeholder implements it
/// generically via [`DataType::is_void_type`](crate::program::model::data::data_type::DataType::is_void_type),
/// which a concrete `VoidDataType` implementation is expected to override to return `true` (see
/// that method's own doc comment) -- no new plumbing is needed here.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `ClassTranslator`-adjacent bits BuiltIn's constructor would otherwise wire up.
pub trait VoidDataType: BuiltIn {
    /// Port of `VoidDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Always `"void"`, regardless of `settings` or this
    /// instance's name.
    fn void_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "void".to_string()
    }

    /// Port of `VoidDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn void_description(&self) -> String {
        "void datatype".to_string()
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `VoidDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn void_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn VoidDataType>;

    /// Port of `VoidDataType.getCTypeDeclaration(DataOrganization)`, which overrides the abstract
    /// `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Always `None`, matching the Java
    /// original's comment that `void` is a standard C-primitive name and type. Exposed under a
    /// distinct name since `BuiltInDataType::get_c_type_declaration` is a required (no-default)
    /// method; a concrete `impl BuiltInDataType for ...` should delegate to this.
    fn void_c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        let _ = data_organization;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::mem::MemBuffer;
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockMemBuffer;
    impl MemBuffer for MockMemBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    struct MockVoidDataType {
        dtm_tag: Option<&'static str>,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
        parents: Vec<Weak<dyn DataType>>,
    }

    impl MockVoidDataType {
        fn new() -> Self {
            Self {
                dtm_tag: None,
                last_change_time: 0,
                last_change_time_in_source_archive: 0,
                parents: Vec::new(),
            }
        }
    }

    impl DataType for MockVoidDataType {
        fn get_name(&self) -> String {
            "void".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn is_void_type(&self) -> bool {
            true
        }
    }

    impl DataTypeImpl for MockVoidDataType {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
        fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}
        fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
            None
        }
        fn set_stored_source_archive(&mut self, _archive: Option<Box<dyn SourceArchive>>) {}
        fn stored_universal_id(&self) -> UniversalID {
            UniversalID::new(0)
        }
        fn stored_last_change_time(&self) -> i64 {
            self.last_change_time
        }
        fn set_stored_last_change_time(&mut self, last_change_time: i64) {
            self.last_change_time = last_change_time;
        }
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            self.last_change_time_in_source_archive
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, last_change_time: i64) {
            self.last_change_time_in_source_archive = last_change_time;
        }
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            self.parents.clone()
        }
        fn set_stored_parent_refs(&mut self, parents: Vec<Weak<dyn DataType>>) {
            self.parents = parents;
        }
    }

    impl BuiltInDataType for MockVoidDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            self.void_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockVoidDataType {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.is_void_type()
        }
    }

    impl VoidDataType for MockVoidDataType {
        fn void_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn VoidDataType> {
            match dtm {
                None => Box::new(MockVoidDataType {
                    dtm_tag: self.dtm_tag,
                    ..MockVoidDataType::new()
                }),
                Some(_) => Box::new(MockVoidDataType {
                    dtm_tag: Some("new-manager"),
                    ..MockVoidDataType::new()
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockVoidDataType::new();
        let dyn_dt: &dyn VoidDataType = &dt;
        assert_eq!(dyn_dt.void_mnemonic(&MockSettings), "void");
        assert_eq!(dyn_dt.void_description(), "void datatype");
        assert_eq!(dyn_dt.void_c_type_declaration(None), None);
        // Untouched DataType defaults still hold for the identical-to-default overrides.
        assert_eq!(DataType::get_length(dyn_dt), 0);
        assert_eq!(DataType::get_representation(dyn_dt, &MockMemBuffer, &MockSettings, -1), "");
        assert!(DataType::get_value(dyn_dt, &MockMemBuffer, &MockSettings, -1).is_none());
    }

    #[test]
    fn is_void_type_is_reachable_for_the_seam_stub_helper() {
        let dt = MockVoidDataType::new();
        assert!(crate::program::seam_stubs::is_void_data_type(Some(&dt as &dyn DataType)));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockVoidDataType {
            dtm_tag: Some("mgr-a"),
            ..MockVoidDataType::new()
        };
        let cloned = dt.void_clone(None);
        assert_eq!(cloned.void_description(), dt.void_description());
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockVoidDataType {
            dtm_tag: Some("mgr-a"),
            ..MockVoidDataType::new()
        };
        let cloned = dt.void_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.void_mnemonic(&MockSettings), "void");
    }
}
