//! Port of `ghidra.program.model.data.UnsignedInteger3DataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractUnsignedIntegerDataType`, already ported as a trait
//! ([`AbstractUnsignedIntegerDataType`]), so this trait extends it directly.
//!
//! `getDescription()`/`getLength()` each override an already-provided default method on
//! [`DataType`]; `getOppositeSignednessDataType()` overrides the required
//! `AbstractIntegerDataType.getOppositeSignednessDataType()`. Rust does not allow a subtrait to
//! override a supertrait's method (default or required) by redeclaring it under the same name --
//! see this crate's other `Abstract*`/leaf cut-point traits for the same restriction -- so all
//! three are exposed here under distinct `unsigned_integer3_*` names. A concrete `impl DataType +
//! AbstractIntegerDataType for ...` should delegate to these.
//!
//! The `static { ClassTranslator.put(...) }` block (registering the legacy class name
//! `ghidra.program.model.data.ThreeByteDataType`) has no Rust equivalent -- `ClassTranslator` is
//! not ported -- and is dropped, mirroring every other `ClassTranslator.put` registration already
//! skipped elsewhere in this crate (e.g.
//! [`CharDataType`](crate::program::model::data::char_data_type::CharDataType)'s own module docs).
//!
//! No `getCTypeDeclaration(DataOrganization)` override exists in Java for this class (unlike its
//! `UnsignedInteger`/`UnsignedShort`/`UnsignedChar` siblings), so this trait adds nothing for it;
//! [`AbstractUnsignedIntegerDataType`]'s own supertrait chain provides no default either, so a
//! concrete `BuiltInDataType::get_c_type_declaration` implementation is expected to supply its own
//! (matching the Java class's inherited `AbstractIntegerDataType` behavior, not reproduced by any
//! cut-point trait here).

use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::integer3_data_type::Integer3DataType;

/// A fixed size 3 byte unsigned integer.
///
/// Port of `ghidra.program.model.data.UnsignedInteger3DataType`. See the module-level
/// documentation for the naming conventions used to resolve clashes with
/// [`DataType`](crate::program::model::data::data_type::DataType).
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `ClassTranslator` legacy-name registration (needs `ClassTranslator`, not yet ported).
pub trait UnsignedInteger3DataType: AbstractUnsignedIntegerDataType {
    /// Port of `UnsignedInteger3DataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`. The trailing unmatched `)` is copied verbatim from the Java
    /// source's literal string (`"Unsigned 3-Byte Integer)"`), not a typo introduced by this port.
    fn unsigned_integer3_description(&self) -> String {
        "Unsigned 3-Byte Integer)".to_string()
    }

    /// Port of `UnsignedInteger3DataType.getLength()`, which overrides the default
    /// `DataType.getLength()`. Always `3`.
    fn unsigned_integer3_length(&self) -> i32 {
        3
    }

    /// Port of `UnsignedInteger3DataType.getOppositeSignednessDataType()`, which overrides the
    /// required `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required
    /// method (no default); see
    /// [`UnsignedIntegerDataType::unsigned_integer_opposite_signedness_data_type`](super::unsigned_integer_data_type::UnsignedIntegerDataType::unsigned_integer_opposite_signedness_data_type)
    /// for why.
    fn unsigned_integer3_opposite_signedness_data_type(&self) -> Box<dyn Integer3DataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `UnsignedInteger3DataType.clone(DataTypeManager)`, which overrides
    /// `AbstractUnsignedIntegerDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a
    /// required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn unsigned_integer3_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedInteger3DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType;
    use crate::program::model::data::array_stringable::ArrayStringable;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::mem::MemBuffer;

    struct MockInteger3DataType;
    impl DataType for MockInteger3DataType {
        fn get_name(&self) -> String {
            "int3".to_string()
        }
    }
    impl BuiltInDataType for MockInteger3DataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl Integer3DataType for MockInteger3DataType {
        fn get_opposite_signedness_data_type(
            &self,
        ) -> Box<dyn crate::program::seam_stubs::UnsignedInteger3DataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn integer3_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Integer3DataType> {
            Box::new(MockInteger3DataType)
        }
    }

    struct MockUnsignedInteger3DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUnsignedInteger3DataType {
        fn get_name(&self) -> String {
            "uint3".to_string()
        }
        fn get_length(&self) -> i32 {
            self.unsigned_integer3_length()
        }
    }

    impl BuiltInDataType for MockUnsignedInteger3DataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl ArrayStringable for MockUnsignedInteger3DataType {
        fn has_string_value(&self, _settings: &dyn Settings) -> bool {
            false
        }
        fn string_data_instance(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _length: i32,
        ) -> Box<dyn StringDataInstance> {
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_array_default_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
            _offcut_length: i32,
        ) -> Option<String> {
            None
        }
    }

    impl AbstractIntegerDataType for MockUnsignedInteger3DataType {
        fn is_signed(&self) -> bool {
            self.unsigned_is_signed()
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl AbstractUnsignedIntegerDataType for MockUnsignedInteger3DataType {}

    impl UnsignedInteger3DataType for MockUnsignedInteger3DataType {
        fn unsigned_integer3_opposite_signedness_data_type(&self) -> Box<dyn Integer3DataType> {
            Box::new(MockInteger3DataType)
        }

        fn unsigned_integer3_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedInteger3DataType> {
            match dtm {
                None => Box::new(MockUnsignedInteger3DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockUnsignedInteger3DataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUnsignedInteger3DataType { dtm_tag: None };
        let dyn_dt: &dyn UnsignedInteger3DataType = &dt;
        assert_eq!(dyn_dt.unsigned_integer3_description(), "Unsigned 3-Byte Integer)");
        assert_eq!(dyn_dt.unsigned_integer3_length(), 3);
        assert_eq!(DataType::get_length(dyn_dt), 3);
        assert!(!dt.is_signed());
    }

    #[test]
    fn opposite_signedness_returns_integer3_data_type() {
        let dt = MockUnsignedInteger3DataType { dtm_tag: None };
        let _opposite = dt.unsigned_integer3_opposite_signedness_data_type();
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUnsignedInteger3DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_integer3_clone(None);
        assert_eq!(cloned.unsigned_integer3_length(), 3);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUnsignedInteger3DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_integer3_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.unsigned_integer3_length(), 3);
    }
}
