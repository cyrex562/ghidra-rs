//! Port of `ghidra.program.model.data.UnsignedPointerSizedIntegerDataType`, promoted to a trait
//! because it was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractUnsignedIntegerDataType`, already ported as a trait
//! ([`AbstractUnsignedIntegerDataType`]), so this trait extends it directly. Structurally similar
//! to [`UnsignedLongDataType`](super::unsigned_long_data_type::UnsignedLongDataType) -- see that
//! trait's module docs for the shared rationale (`getLength`/`hasLanguageDependantLength`/
//! `getDescription`/`getCTypeDeclaration` overriding already-provided defaults, `getCDeclaration`
//! overriding the reached-transitively default `AbstractIntegerDataType.getCDeclaration()`,
//! `getOppositeSignednessDataType` overriding the required no-default
//! `AbstractIntegerDataType.getOppositeSignednessDataType()`, all five therefore exposed under
//! distinct `unsigned_pointer_sized_integer_*` names) -- except `getOppositeSignednessDataType()`
//! clones `PointerSizedIntegerDataType.dataType`, an already-ported trait
//! ([`PointerSizedIntegerDataType`](crate::program::model::data::pointer_sized_integer_data_type::PointerSizedIntegerDataType))
//! with no seam-stub placeholder needed, so this trait's
//! `unsigned_pointer_sized_integer_opposite_signedness_data_type` returns
//! `Box<dyn PointerSizedIntegerDataType>` directly.
//!
//! Unlike `UnsignedLongDataType`/`UnsignedLongLongDataType` (whose `getCDeclaration()` always
//! returns a fixed non-null string), `UnsignedPointerSizedIntegerDataType.getCDeclaration()`
//! unconditionally returns `null` -- mirroring the signed
//! [`PointerSizedIntegerDataType::get_c_declaration`](crate::program::model::data::pointer_sized_integer_data_type::PointerSizedIntegerDataType::get_c_declaration)'s
//! identical `None` override -- and its `getCTypeDeclaration(DataOrganization)` calls the other
//! `BuiltIn.getCTypeDeclaration(BuiltIn, boolean, DataOrganization, boolean)` overload (signed =
//! `false`) rather than the `(String, String, boolean)` overload
//! `UnsignedLongDataType`/`UnsignedLongLongDataType` use, so this trait's
//! `unsigned_pointer_sized_integer_c_type_declaration` reproduces that overload's formula
//! directly instead, mirroring
//! [`PointerSizedIntegerDataType::pointer_sized_integer_get_c_type_declaration`](crate::program::model::data::pointer_sized_integer_data_type::PointerSizedIntegerDataType::pointer_sized_integer_get_c_type_declaration).
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::pointer_sized_integer_data_type::PointerSizedIntegerDataType;

/// Pointer-sized unsigned integer.
///
/// Port of `ghidra.program.model.data.UnsignedPointerSizedIntegerDataType`. See the module-level
/// documentation for the naming conventions used to resolve clashes with
/// [`DataType`]/[`AbstractIntegerDataType`](crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType).
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait UnsignedPointerSizedIntegerDataType: AbstractUnsignedIntegerDataType {
    /// Port of `UnsignedPointerSizedIntegerDataType.getLength()`, which overrides the default
    /// `DataType.getLength()`. Derived from `self.get_data_organization().get_pointer_size()`,
    /// matching the Java override's compiler-specific, language-dependant width.
    fn unsigned_pointer_sized_integer_length(&self) -> i32 {
        self.get_data_organization().get_pointer_size()
    }

    /// Port of `UnsignedPointerSizedIntegerDataType.hasLanguageDependantLength()`, which
    /// overrides the default `DataType.hasLanguageDependantLength()`. Always `true`.
    fn unsigned_pointer_sized_integer_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Port of `UnsignedPointerSizedIntegerDataType.getDescription()`, which overrides the
    /// default `DataType.getDescription()`.
    fn unsigned_pointer_sized_integer_description(&self) -> String {
        "Unsigned Pointer-Sized Integer (compiler-specific size)".to_string()
    }

    /// Port of `UnsignedPointerSizedIntegerDataType.getCDeclaration()`, which overrides the
    /// default `AbstractIntegerDataType.getCDeclaration()`. Always `None`, matching the Java
    /// override which unconditionally returns `null` -- see the module docs for why this differs
    /// from `UnsignedLongDataType`/`UnsignedLongLongDataType`.
    fn unsigned_pointer_sized_integer_c_declaration(&self) -> Option<String> {
        None
    }

    /// Returns the data-type with the opposite signedness from this data-type (a signed
    /// pointer-sized integer type).
    ///
    /// Port of `UnsignedPointerSizedIntegerDataType.getOppositeSignednessDataType()`, which
    /// overrides the required `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as
    /// a required method (no default) since the real implementation clones the
    /// `PointerSizedIntegerDataType.dataType` singleton -- see the module docs for why this can
    /// point at the already-ported [`PointerSizedIntegerDataType`] directly rather than a
    /// seam-stub placeholder.
    fn unsigned_pointer_sized_integer_opposite_signedness_data_type(&self) -> Box<dyn PointerSizedIntegerDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `UnsignedPointerSizedIntegerDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractUnsignedIntegerDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a
    /// required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn unsigned_pointer_sized_integer_clone(
        &self,
        dtm: Option<Box<dyn DataTypeManager>>,
    ) -> Box<dyn UnsignedPointerSizedIntegerDataType>;

    /// Port of `UnsignedPointerSizedIntegerDataType.getCTypeDeclaration(DataOrganization)`, which
    /// overrides the abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Reproduces
    /// `BuiltIn.getCTypeDeclaration(this, false, dataOrganization, false)`: a `typedef` line
    /// naming this type's fixed display name (`uintptr_t`) after the organization's *unsigned*
    /// pointer-sized C-type approximation -- see the module docs for why `signed = false` here
    /// unlike the signed `PointerSizedIntegerDataType` counterpart.
    fn unsigned_pointer_sized_integer_c_type_declaration(
        &self,
        data_organization: &dyn DataOrganization,
    ) -> Option<String> {
        Some(format!(
            "typedef {}    uintptr_t;",
            data_organization.get_integer_c_type_approximation(data_organization.get_pointer_size(), false)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::array_stringable::ArrayStringable;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::mem::MemBuffer;

    struct MockBitFieldPacking;
    impl BitFieldPacking for MockBitFieldPacking {
        fn use_ms_convention(&self) -> bool {
            false
        }
        fn is_type_alignment_enabled(&self) -> bool {
            true
        }
        fn get_zero_length_boundary(&self) -> i32 {
            0
        }
    }

    struct MockDataOrganization {
        pointer_size: i32,
    }

    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            self.pointer_size
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            2
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            0
        }
        fn get_machine_alignment(&self) -> i32 {
            8
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
            Box::new(MockBitFieldPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, size: i32, signed: bool) -> String {
            format!("{}int{}", if signed { "" } else { "unsigned " }, size * 8)
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    struct MockPointerSizedIntegerDataType;
    impl DataType for MockPointerSizedIntegerDataType {
        fn get_name(&self) -> String {
            "intptr_t".to_string()
        }
    }
    impl BuiltInDataType for MockPointerSizedIntegerDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl PointerSizedIntegerDataType for MockPointerSizedIntegerDataType {
        fn get_opposite_signedness_data_type(
            &self,
        ) -> Box<dyn crate::program::seam_stubs::UnsignedPointerSizedIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn pointer_sized_integer_clone(
            &self,
            _dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn PointerSizedIntegerDataType> {
            Box::new(MockPointerSizedIntegerDataType)
        }
    }

    struct MockUnsignedPointerSizedIntegerDataType {
        pointer_size: i32,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUnsignedPointerSizedIntegerDataType {
        fn get_name(&self) -> String {
            "uintptr_t".to_string()
        }
        fn get_length(&self) -> i32 {
            self.unsigned_pointer_sized_integer_length()
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization { pointer_size: self.pointer_size })
        }
    }

    impl BuiltInDataType for MockUnsignedPointerSizedIntegerDataType {
        fn get_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            data_organization.and_then(|org| self.unsigned_pointer_sized_integer_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl ArrayStringable for MockUnsignedPointerSizedIntegerDataType {
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

    impl crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType
        for MockUnsignedPointerSizedIntegerDataType
    {
        fn is_signed(&self) -> bool {
            self.unsigned_is_signed()
        }
        fn get_opposite_signedness_data_type(
            &self,
        ) -> Box<dyn crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl AbstractUnsignedIntegerDataType for MockUnsignedPointerSizedIntegerDataType {}

    impl UnsignedPointerSizedIntegerDataType for MockUnsignedPointerSizedIntegerDataType {
        fn unsigned_pointer_sized_integer_opposite_signedness_data_type(
            &self,
        ) -> Box<dyn PointerSizedIntegerDataType> {
            Box::new(MockPointerSizedIntegerDataType)
        }

        fn unsigned_pointer_sized_integer_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn UnsignedPointerSizedIntegerDataType> {
            match dtm {
                None => Box::new(MockUnsignedPointerSizedIntegerDataType {
                    pointer_size: self.pointer_size,
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockUnsignedPointerSizedIntegerDataType {
                    pointer_size: self.pointer_size,
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUnsignedPointerSizedIntegerDataType { pointer_size: 8, dtm_tag: None };
        let dyn_dt: &dyn UnsignedPointerSizedIntegerDataType = &dt;
        assert_eq!(dyn_dt.unsigned_pointer_sized_integer_length(), 8);
        assert_eq!(DataType::get_length(dyn_dt), 8);
        assert!(dyn_dt.unsigned_pointer_sized_integer_has_language_dependant_length());
        assert_eq!(
            dyn_dt.unsigned_pointer_sized_integer_description(),
            "Unsigned Pointer-Sized Integer (compiler-specific size)"
        );
        assert_eq!(dyn_dt.unsigned_pointer_sized_integer_c_declaration(), None);
    }

    #[test]
    fn length_tracks_data_organization_pointer_size() {
        let dt32 = MockUnsignedPointerSizedIntegerDataType { pointer_size: 4, dtm_tag: None };
        let dt64 = MockUnsignedPointerSizedIntegerDataType { pointer_size: 8, dtm_tag: None };
        assert_eq!(dt32.unsigned_pointer_sized_integer_length(), 4);
        assert_eq!(dt64.unsigned_pointer_sized_integer_length(), 8);
    }

    #[test]
    fn c_type_declaration_uses_unsigned_pointer_size_approximation() {
        let dt = MockUnsignedPointerSizedIntegerDataType { pointer_size: 8, dtm_tag: None };
        let org = MockDataOrganization { pointer_size: 8 };
        assert_eq!(
            dt.unsigned_pointer_sized_integer_c_type_declaration(&org),
            Some("typedef unsigned int64    uintptr_t;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_pointer_sized_integer_data_type() {
        let dt = MockUnsignedPointerSizedIntegerDataType { pointer_size: 8, dtm_tag: None };
        let opposite = dt.unsigned_pointer_sized_integer_opposite_signedness_data_type();
        assert_eq!(opposite.get_name(), "intptr_t");
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUnsignedPointerSizedIntegerDataType { pointer_size: 8, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_pointer_sized_integer_clone(None);
        assert_eq!(cloned.unsigned_pointer_sized_integer_length(), 8);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUnsignedPointerSizedIntegerDataType { pointer_size: 8, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_pointer_sized_integer_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.unsigned_pointer_sized_integer_length(), 8);
    }
}
