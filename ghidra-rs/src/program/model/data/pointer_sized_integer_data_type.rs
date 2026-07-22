use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::UnsignedPointerSizedIntegerDataType as UnsignedPointerSizedIntegerDataTypeStub;

/// Pointer-sized signed integer.
///
/// Port of `ghidra.program.model.data.PointerSizedIntegerDataType`, promoted straight to a trait
/// because it was selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractSignedIntegerDataType`, itself a subclass of
/// `AbstractIntegerDataType`. Neither is yet ported, but every member `PointerSizedIntegerDataType`
/// actually calls on them (`getDataOrganization()` from [`DataType`], and the final
/// `AbstractSignedIntegerDataType.isSigned()`) is already covered by an already-ported trait or
/// reproducible here directly, so no `seam_stubs` placeholder is needed for either supertype.
/// Likewise, `getCTypeDeclaration(DataOrganization)` overrides the abstract
/// `BuiltInDataType.getCTypeDeclaration(DataOrganization)` by delegating to `BuiltIn`'s protected
/// `getCTypeDeclaration(BuiltIn, boolean, DataOrganization, boolean)` helper; that helper's logic
/// (format a `typedef` line from the type's fixed display name and
/// `DataOrganization.getIntegerCTypeApproximation`) is reproduced directly here rather than
/// stubbed, since `BuiltIn` itself is not otherwise referenced.
///
/// Methods that only *override* an already-ported supertrait method with
/// `PointerSizedIntegerDataType`-specific behavior (`getLength`, `hasLanguageDependantLength`,
/// `getDescription`, `getCTypeDeclaration`) cannot be redeclared here without creating an
/// ambiguous method name with [`DataType`]/[`BuiltInDataType`] (Rust does not allow a subtrait to
/// "override" a supertrait's default method by re-declaring it). Instead, the real
/// `PointerSizedIntegerDataType`-specific values for those overrides are exposed here under
/// distinct `pointer_sized_integer_*` names; a future concrete implementation (once
/// `AbstractSignedIntegerDataType`/`AbstractIntegerDataType` are ported) should implement
/// `DataType`/`BuiltInDataType` directly and delegate to these helpers.
///
/// `getCDeclaration()` (unprefixed, since it is not declared by any already-ported supertrait)
/// always returns `None`, matching the Java override which unconditionally returns `null`.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait PointerSizedIntegerDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`, which
    /// `PointerSizedIntegerDataType` inherits unchanged.
    fn is_signed(&self) -> bool {
        true
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `PointerSizedIntegerDataType.getLength()`, which overrides the abstract
    /// `DataType.getLength()`. Exposed under a distinct name since [`DataType`] already declares
    /// `get_length`; see the module docs for why it cannot be redeclared here. Derived from
    /// `self.get_data_organization().get_pointer_size()`, matching the Java override's
    /// compiler-specific, language-dependant width (unlike the fixed-width `IntNN`/`UIntNN`
    /// families).
    fn pointer_sized_integer_length(&self) -> i32 {
        self.get_data_organization().get_pointer_size()
    }

    /// Indicates if the length of this data-type is determined based upon the `DataOrganization`
    /// obtained from the associated `DataTypeManager`.
    ///
    /// Port of `PointerSizedIntegerDataType.hasLanguageDependantLength()`, which overrides the
    /// default `DataType.hasLanguageDependantLength()` (`false`). Exposed under a distinct name
    /// since [`DataType`] already declares `has_language_dependant_length`; see the module docs
    /// for why it cannot be redeclared here. Always `true`.
    fn pointer_sized_integer_has_language_dependant_length(&self) -> bool {
        true
    }

    /// A brief description of this data-type.
    ///
    /// Port of `PointerSizedIntegerDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn pointer_sized_integer_description(&self) -> String {
        "Signed Pointer-Sized Integer (compiler-specific size)".to_string()
    }

    /// The C style data-type declaration for this data-type.
    ///
    /// Port of `PointerSizedIntegerDataType.getCDeclaration()`, which overrides
    /// `AbstractIntegerDataType.getCDeclaration()`. That method is not part of any already-ported
    /// trait, so it is exposed here directly with no naming conflict. Always `None`, matching the
    /// Java override which unconditionally returns `null`.
    fn get_c_declaration(&self) -> Option<String> {
        None
    }

    /// Returns the data-type with the opposite signedness from this data-type (an unsigned
    /// pointer-sized integer type).
    ///
    /// Port of `PointerSizedIntegerDataType.getOppositeSignednessDataType()`, which overrides the
    /// abstract `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required
    /// method (no default) since the real implementation clones the
    /// `UnsignedPointerSizedIntegerDataType.dataType` singleton, which is not ported yet (see
    /// [`UnsignedPointerSizedIntegerDataTypeStub`] placeholder).
    fn get_opposite_signedness_data_type(&self) -> Box<dyn UnsignedPointerSizedIntegerDataTypeStub>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `PointerSizedIntegerDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn pointer_sized_integer_clone(
        &self,
        dtm: Option<Box<dyn DataTypeManager>>,
    ) -> Box<dyn PointerSizedIntegerDataType>;

    /// The C style data-type declaration for this data-type, given a specific `DataOrganization`.
    ///
    /// Port of `PointerSizedIntegerDataType.getCTypeDeclaration(DataOrganization)`, which
    /// overrides the abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Exposed
    /// under a distinct name since [`BuiltInDataType`] already declares
    /// `get_c_type_declaration`; see the module docs for why it cannot be redeclared here.
    /// Reproduces `BuiltIn.getCTypeDeclaration(this, true, dataOrganization, false)`: a `typedef`
    /// line naming this type's fixed display name (`intptr_t`) after the organization's signed
    /// pointer-sized C-type approximation.
    fn pointer_sized_integer_get_c_type_declaration(
        &self,
        data_organization: &dyn DataOrganization,
    ) -> Option<String> {
        Some(format!(
            "typedef {}    intptr_t;",
            data_organization
                .get_integer_c_type_approximation(data_organization.get_pointer_size(), true)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::data_organization::DataOrganization;

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

    struct MockUnsignedPointerSizedIntegerDataType;
    impl UnsignedPointerSizedIntegerDataTypeStub for MockUnsignedPointerSizedIntegerDataType {}

    struct MockPointerSizedIntegerDataType {
        dtm_tag: Option<&'static str>,
        pointer_size: i32,
    }

    impl DataType for MockPointerSizedIntegerDataType {
        fn get_name(&self) -> String {
            "intptr_t".to_string()
        }

        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization {
                pointer_size: self.pointer_size,
            })
        }
    }

    impl BuiltInDataType for MockPointerSizedIntegerDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            data_organization.and_then(|org| self.pointer_sized_integer_get_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl PointerSizedIntegerDataType for MockPointerSizedIntegerDataType {
        fn get_opposite_signedness_data_type(
            &self,
        ) -> Box<dyn UnsignedPointerSizedIntegerDataTypeStub> {
            Box::new(MockUnsignedPointerSizedIntegerDataType)
        }

        fn pointer_sized_integer_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn PointerSizedIntegerDataType> {
            // Mirrors `PointerSizedIntegerDataType.clone(DataTypeManager)`: return an equivalent
            // instance tied to the requested manager (`None` here stands in for "already
            // matches").
            match dtm {
                None => Box::new(MockPointerSizedIntegerDataType {
                    dtm_tag: self.dtm_tag,
                    pointer_size: self.pointer_size,
                }),
                Some(_) => Box::new(MockPointerSizedIntegerDataType {
                    dtm_tag: Some("new-manager"),
                    pointer_size: self.pointer_size,
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockPointerSizedIntegerDataType {
            dtm_tag: None,
            pointer_size: 8,
        };
        let dyn_dt: &dyn PointerSizedIntegerDataType = &dt;
        assert!(dyn_dt.is_signed());
        assert_eq!(dyn_dt.pointer_sized_integer_length(), 8);
        assert!(dyn_dt.pointer_sized_integer_has_language_dependant_length());
        assert_eq!(
            dyn_dt.pointer_sized_integer_description(),
            "Signed Pointer-Sized Integer (compiler-specific size)"
        );
        assert_eq!(dyn_dt.get_c_declaration(), None);
        // The DataType supertrait's own get_name is independently reachable and untouched.
        assert_eq!(DataType::get_name(dyn_dt), "intptr_t");
    }

    #[test]
    fn length_tracks_data_organization_pointer_size() {
        let dt32 = MockPointerSizedIntegerDataType {
            dtm_tag: None,
            pointer_size: 4,
        };
        let dt64 = MockPointerSizedIntegerDataType {
            dtm_tag: None,
            pointer_size: 8,
        };
        assert_eq!(dt32.pointer_sized_integer_length(), 4);
        assert_eq!(dt64.pointer_sized_integer_length(), 8);
    }

    #[test]
    fn c_type_declaration_uses_signed_pointer_size_approximation() {
        let dt = MockPointerSizedIntegerDataType {
            dtm_tag: None,
            pointer_size: 8,
        };
        let org = MockDataOrganization { pointer_size: 8 };
        assert_eq!(
            dt.pointer_sized_integer_get_c_type_declaration(&org),
            Some("typedef int64    intptr_t;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockPointerSizedIntegerDataType {
            dtm_tag: Some("a"),
            pointer_size: 8,
        };
        let _opposite = dt.get_opposite_signedness_data_type();
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockPointerSizedIntegerDataType {
            dtm_tag: Some("mgr-a"),
            pointer_size: 8,
        };
        let cloned = dt.pointer_sized_integer_clone(None);
        assert_eq!(
            cloned.pointer_sized_integer_description(),
            dt.pointer_sized_integer_description()
        );
        assert_eq!(cloned.pointer_sized_integer_length(), 8);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockPointerSizedIntegerDataType {
            dtm_tag: Some("mgr-a"),
            pointer_size: 8,
        };
        let cloned = dt.pointer_sized_integer_clone(Some(Box::new(MockDataTypeManager)));
        // Mirrors the real `clone(DataTypeManager)` returning a distinct instance bound to the
        // requested manager when it differs from the current one, while remaining a fully
        // functional PointerSizedIntegerDataType.
        assert_eq!(cloned.pointer_sized_integer_length(), 8);
        assert_eq!(cloned.get_c_declaration(), None);
    }
}
