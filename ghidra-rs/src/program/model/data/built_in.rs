//! Port of `ghidra.program.model.data.BuiltIn`, promoted to a trait because it was selected as a
//! dependency-cycle cut-point.
//!
//! NOTE: ALL DATATYPE CLASSES MUST END IN "DataType". If not, the (Java) `ClassSearcher` will not
//! find them; this naming convention is not enforced by the Rust trait.
//!
//! The Java class `extends DataTypeImpl implements BuiltInDataType`, so this trait extends both
//! already-ported traits: [`DataTypeImpl`] and [`BuiltInDataType`].
//!
//! The constructor (`BuiltIn(CategoryPath, String, DataTypeManager)`) has no trait equivalent
//! (traits have no constructors); its behavior -- forcing any `null` category path to
//! [`CategoryPath::ROOT`](crate::program::model::data::category_path::ROOT) and wiring the
//! datatype to [`BuiltInSourceArchive::INSTANCE`](crate::app::plugin::core::datamgr::archive::built_in_source_archive::INSTANCE)
//! with [`NO_SOURCE_SYNC_TIME`](crate::program::model::data::data_type::NO_SOURCE_SYNC_TIME)/
//! [`NO_LAST_CHANGE_TIME`](crate::program::model::data::data_type::NO_LAST_CHANGE_TIME) -- is left
//! to whatever concrete constructor function a real implementor provides.
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]/
//! [`BuiltInDataType`] (`copy(DataTypeManager)` vs. [`DataType::copy_data_type`],
//! `getSettingsDefinitions()` vs. [`DataType::get_settings_definitions`], `isEquivalent(DataType)`
//! vs. [`DataType::is_equivalent`]). Rust does not allow a subtrait to override a supertrait's
//! same-named default without creating an ambiguous call site, so -- mirroring
//! [`DataTypeImpl`]'s `data_type_impl_*` convention and
//! [`ByteDataType`](super::byte_data_type::ByteDataType)'s `byte_*` convention -- those overrides
//! are exposed here under distinct `built_in_*` names. A concrete `impl DataType +
//! BuiltInDataType for ...` should delegate to these.
//!
//! Two Java overrides are *identical* to an already-in-place default, so they are intentionally
//! not re-declared here (matching the precedent set by [`DataTypeImpl`]'s own module docs):
//!   - `addParent(DataType)`/`removeParent(DataType)` are both `final` no-ops in `BuiltIn`,
//!     exactly [`DataType::add_parent`]/[`DataType::remove_parent`]'s existing no-op defaults.
//!   - `getLastChangeTime()` always returns `0`, exactly
//!     [`DataType::get_last_change_time`]'s existing default
//!     ([`NO_LAST_CHANGE_TIME`](crate::program::model::data::data_type::NO_LAST_CHANGE_TIME)).
//!
//! `setDefaultSettings(Settings)` needs no new method here: it is already a *required* (no
//! default) method on [`BuiltInDataType`], and `BuiltIn`'s override (`defaultSettings =
//! settings;`) is exactly the real behavior any implementor of that supertrait method must
//! already supply.
//!
//! `getSettingsDefinitions()`'s private `settingDefs` cache (computed once, lazily, then reused)
//! has no trait-level home -- unlike [`DataTypeImpl`]'s backing fields, this port does not expose
//! a `stored_*`/`set_stored_*` accessor pair for it, since [`built_in_get_settings_definitions`]
//! is cheap to recompute and a caching layer is a pure performance detail a concrete
//! implementation is free to add on top.
//!
//! `getCTypeDeclaration(String, String, boolean)` and `getCTypeDeclaration(String, int, boolean,
//! DataOrganization, boolean)` (the two protected helpers with no `BuiltIn`-typed parameter) map
//! directly onto [`get_c_type_declaration_str`](BuiltIn::get_c_type_declaration_str)/
//! [`get_c_type_declaration_len`](BuiltIn::get_c_type_declaration_len). The third overload,
//! `getCTypeDeclaration(BuiltIn, boolean, DataOrganization, boolean)`, is only ever called by
//! `BuiltIn` subclasses as `getCTypeDeclaration(this, ..., dataOrganization, ...)` (confirmed
//! against every subclass in the original Java sources), so it is folded directly into
//! [`built_in_get_c_type_declaration_for_self`](BuiltIn::built_in_get_c_type_declaration_for_self),
//! which uses `self` instead of taking a second `BuiltIn` parameter -- this avoids needing to
//! unsize `self` into a `&dyn BuiltIn` (which would require an unavailable `Self: Sized` bound and
//! drop the method from the `dyn BuiltIn` vtable).
//!
//! `getDecompilerDisplayName(DecompilerLanguage)` is not an override of anything already declared
//! on [`DataType`]/[`BuiltInDataType`], so it is declared here directly under its natural name
//! with no ambiguity.
//!
//! `isEquivalent(DataType)`'s real logic (`dt == this` returns `true`; otherwise
//! `getClass() == dt.getClass()`) needs runtime type identity for an arbitrary `&dyn DataType`,
//! which is not obtainable generically since [`DataType`] does not extend `Any`. Left as a
//! required method (no default) since only a concrete implementation can decide how to compare
//! "same class" for its own type -- mirroring the same trade-off already made for
//! [`ByteDataType::get_opposite_signedness_data_type`](super::byte_data_type::ByteDataType::get_opposite_signedness_data_type).
//!
//! `getUniversalID()` always returns `null`, unlike [`DataTypeImpl`]'s real stored-field behavior;
//! since [`DataType::get_universal_id`]'s existing default returns a concrete (non-optional)
//! [`UniversalID`] rather than modeling absence, this override is exposed under a distinct name
//! returning `Option<UniversalID>` so `None` can faithfully stand in for `null`.
//!
//! Static state not translated: the private `settingDefs` cache field (see above) and the
//! `serialVersionUID` field (Java serialization has no Rust equivalent).

use crate::docking::settings::settings_definition::{concat, SettingsDefinition};
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::mutability_settings_definition::MutabilitySettingsDefinition;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::util::UniversalID;

/// Base implementation for built-in datatypes.
///
/// Port of `ghidra.program.model.data.BuiltIn`. See the module-level documentation for the
/// conventions used to resolve name clashes with [`DataType`]/[`BuiltInDataType`], for what needs
/// no new method here, and for what was left required or intentionally omitted.
pub trait BuiltIn: DataTypeImpl + BuiltInDataType {
    /// Port of `BuiltIn.copy(DataTypeManager)`, a `final` method wrapping `clone(DataTypeManager)`.
    ///
    /// Exposed under a distinct name since [`DataType::copy_data_type`] already provides a
    /// (different) default. `clone(DataTypeManager)` itself is modeled by
    /// [`DataType::clone_data_type`], which every concrete datatype already overrides with its
    /// real cloning behavior.
    fn built_in_copy(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        self.clone_data_type(dtm)
    }

    /// Port of the protected `BuiltIn.getBuiltInSettingsDefinitions()`, returning `null` (here,
    /// an empty list) by default. Subclasses that declare additional settings definitions beyond
    /// [`MutabilitySettingsDefinition`] should override this.
    fn get_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }

    /// Port of `BuiltIn.getSettingsDefinitions()`, a `final` method concatenating the standard
    /// `{ MutabilitySettingsDefinition.DEF }` array with
    /// [`get_built_in_settings_definitions`](Self::get_built_in_settings_definitions).
    ///
    /// Exposed under a distinct name since [`DataType::get_settings_definitions`] already
    /// provides a (different, empty) default; see the module docs for why it cannot be
    /// redeclared here, and for why the private `settingDefs` cache is not reproduced.
    fn built_in_get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        let standard: Vec<Box<dyn SettingsDefinition>> =
            vec![Box::new(MutabilitySettingsDefinition::DEF)];
        concat(standard, self.get_built_in_settings_definitions())
    }

    /// Port of `BuiltIn.isEquivalent(DataType)`.
    ///
    /// Exposed under a distinct name since [`DataType::is_equivalent`] already provides a
    /// (different, always-`false`) default; see the module docs for why it cannot be redeclared
    /// here, and for why it is left required rather than defaulted.
    fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool;

    /// Port of `BuiltIn.getUniversalID()`, which always returns `null`.
    ///
    /// Exposed under a distinct name, returning `Option<UniversalID>`, since
    /// [`DataType::get_universal_id`] already provides a different (non-optional) default; see
    /// the module docs for why `null` is modeled as `None` here rather than reusing that default.
    fn built_in_get_universal_id(&self) -> Option<UniversalID> {
        None
    }

    /// Return token used to represent this type in decompiler/source-code output.
    ///
    /// Port of `BuiltIn.getDecompilerDisplayName(DecompilerLanguage)`. Not an override of
    /// anything already declared on [`DataType`]/[`BuiltInDataType`], so declared here directly.
    /// Falls back to [`DataType::get_name`] (standing in for the Java `name` field) by default,
    /// matching `BuiltIn`'s own unconditional `return name;` body.
    fn get_decompiler_display_name(&self, language: DecompilerLanguage) -> String {
        let _ = language;
        self.get_name()
    }

    /// Port of the protected `BuiltIn.getCTypeDeclaration(String typeName, String ctypeName,
    /// boolean useDefine)`.
    fn get_c_type_declaration_str(
        &self,
        type_name: &str,
        ctype_name: &str,
        use_define: bool,
    ) -> String {
        if use_define {
            format!("#define {type_name}    {ctype_name}")
        } else {
            format!("typedef {ctype_name}    {type_name};")
        }
    }

    /// Port of the protected `BuiltIn.getCTypeDeclaration(String typeName, int typeLen, boolean
    /// signed, DataOrganization dataOrganization, boolean useDefine)`.
    fn get_c_type_declaration_len(
        &self,
        type_name: &str,
        type_len: i32,
        signed: bool,
        data_organization: &dyn DataOrganization,
        use_define: bool,
    ) -> String {
        self.get_c_type_declaration_str(
            type_name,
            &data_organization.get_integer_c_type_approximation(type_len, signed),
            use_define,
        )
    }

    /// Port of the protected `BuiltIn.getCTypeDeclaration(BuiltIn dt, boolean signed,
    /// DataOrganization dataOrganization, boolean useDefine)`, specialized to `dt == this` (the
    /// only way any `BuiltIn` subclass ever calls it); see the module docs for why.
    fn built_in_get_c_type_declaration_for_self(
        &self,
        signed: bool,
        data_organization: &dyn DataOrganization,
        use_define: bool,
    ) -> String {
        self.get_c_type_declaration_len(
            &self.get_decompiler_display_name(DecompilerLanguage::CLanguage),
            self.get_length(),
            signed,
            data_organization,
            use_define,
        )
    }

    /// Port of `BuiltIn.getCTypeDeclaration(DataOrganization)`, which overrides the abstract
    /// `BuiltInDataType.getCTypeDeclaration(DataOrganization)`.
    ///
    /// Exposed under a distinct name since [`BuiltInDataType::get_c_type_declaration`] is already
    /// declared (required, no default) on that supertrait; a concrete `impl BuiltInDataType for
    /// ...` should delegate to this. `data_organization` being `None` (standing in for the
    /// default organization) yields `None`, mirroring how every already-ported `BuiltIn` subclass
    /// (e.g. [`Integer7DataType`](super::integer7_data_type::Integer7DataType)) forwards its own
    /// `Option`-shaped `get_c_type_declaration` the same way.
    fn built_in_get_c_type_declaration(
        &self,
        data_organization: Option<&dyn DataOrganization>,
    ) -> Option<String> {
        if self.is_dynamic_type() || self.is_factory_type() {
            return None;
        }
        data_organization
            .map(|org| self.built_in_get_c_type_declaration_for_self(false, org, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::source_archive::SourceArchive;
    use std::cell::RefCell;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

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

    struct MockDataOrganization;
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
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

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockBuiltIn {
        name: String,
        length: i32,
        dynamic: bool,
        factory: bool,
        default_settings: RefCell<Box<dyn Settings>>,
        source_archive: RefCell<Option<Box<dyn SourceArchive>>>,
        last_change_time: RefCell<i64>,
        last_change_time_in_source_archive: RefCell<i64>,
        parents: RefCell<Vec<Weak<dyn DataType>>>,
    }

    impl MockBuiltIn {
        fn new(name: &str, length: i32) -> Self {
            Self {
                name: name.to_string(),
                length,
                dynamic: false,
                factory: false,
                default_settings: RefCell::new(Box::new(MockSettings)),
                source_archive: RefCell::new(None),
                last_change_time: RefCell::new(0),
                last_change_time_in_source_archive: RefCell::new(0),
                parents: RefCell::new(Vec::new()),
            }
        }
    }

    impl DataType for MockBuiltIn {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn is_dynamic_type(&self) -> bool {
            self.dynamic
        }
        fn is_factory_type(&self) -> bool {
            self.factory
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(MockBuiltIn::new(&self.name, self.length))
        }
    }

    impl DataTypeImpl for MockBuiltIn {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
        fn set_stored_default_settings(&mut self, settings: Box<dyn Settings>) {
            *self.default_settings.borrow_mut() = settings;
        }
        fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
            let _ = &self.source_archive;
            None
        }
        fn set_stored_source_archive(&mut self, archive: Option<Box<dyn SourceArchive>>) {
            *self.source_archive.borrow_mut() = archive;
        }
        fn stored_universal_id(&self) -> UniversalID {
            UniversalID::new(0)
        }
        fn stored_last_change_time(&self) -> i64 {
            *self.last_change_time.borrow()
        }
        fn set_stored_last_change_time(&mut self, last_change_time: i64) {
            *self.last_change_time.borrow_mut() = last_change_time;
        }
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            *self.last_change_time_in_source_archive.borrow()
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, last_change_time: i64) {
            *self.last_change_time_in_source_archive.borrow_mut() = last_change_time;
        }
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            self.parents.borrow().clone()
        }
        fn set_stored_parent_refs(&mut self, parents: Vec<Weak<dyn DataType>>) {
            *self.parents.borrow_mut() = parents;
        }
    }

    impl BuiltInDataType for MockBuiltIn {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            self.built_in_get_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, settings: &dyn Settings) {
            let _ = settings;
        }
    }

    impl BuiltIn for MockBuiltIn {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            if std::ptr::eq(
                dt as *const dyn DataType as *const (),
                self as *const Self as *const (),
            ) {
                return true;
            }
            // Mirrors `getClass() == dt.getClass()`: a `&dyn DataType` carries no runtime type
            // identity generically (see the module docs), so a concrete `BuiltIn` approximates
            // "same class" using values that are constant per concrete type -- here, name and
            // length, since every real `BuiltIn` subclass (ByteDataType, WordDataType, ...)
            // reports a single fixed name/length regardless of instance.
            dt.get_name() == self.get_name() && dt.get_length() == self.get_length()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockBuiltIn::new("byte", 1);
        let dyn_dt: &dyn BuiltIn = &dt;
        assert_eq!(dyn_dt.get_name(), "byte");
        assert_eq!(dyn_dt.get_length(), 1);
        assert_eq!(dyn_dt.built_in_get_universal_id(), None);
        assert_eq!(
            dyn_dt.get_decompiler_display_name(DecompilerLanguage::CLanguage),
            "byte"
        );
    }

    #[test]
    fn built_in_copy_delegates_to_clone_data_type() {
        let dt = MockBuiltIn::new("byte", 1);
        let mgr = MockDataTypeManager;
        let copied = dt.built_in_copy(&mgr);
        assert_eq!(copied.get_name(), "byte");
        assert_eq!(copied.get_length(), 1);
    }

    #[test]
    fn settings_definitions_include_mutability_plus_custom() {
        struct CustomSettingsDefinition;
        impl SettingsDefinition for CustomSettingsDefinition {
            fn get_name(&self) -> String {
                "Custom".to_string()
            }
        }

        struct CustomBuiltIn(MockBuiltIn);
        impl DataType for CustomBuiltIn {
            fn get_name(&self) -> String {
                self.0.get_name()
            }
        }
        impl DataTypeImpl for CustomBuiltIn {
            fn stored_default_settings(&self) -> Box<dyn Settings> {
                self.0.stored_default_settings()
            }
            fn set_stored_default_settings(&mut self, settings: Box<dyn Settings>) {
                self.0.set_stored_default_settings(settings)
            }
            fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
                self.0.stored_source_archive()
            }
            fn set_stored_source_archive(&mut self, archive: Option<Box<dyn SourceArchive>>) {
                self.0.set_stored_source_archive(archive)
            }
            fn stored_universal_id(&self) -> UniversalID {
                self.0.stored_universal_id()
            }
            fn stored_last_change_time(&self) -> i64 {
                self.0.stored_last_change_time()
            }
            fn set_stored_last_change_time(&mut self, last_change_time: i64) {
                self.0.set_stored_last_change_time(last_change_time)
            }
            fn stored_last_change_time_in_source_archive(&self) -> i64 {
                self.0.stored_last_change_time_in_source_archive()
            }
            fn set_stored_last_change_time_in_source_archive(&mut self, last_change_time: i64) {
                self.0
                    .set_stored_last_change_time_in_source_archive(last_change_time)
            }
            fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
                self.0.stored_parent_refs()
            }
            fn set_stored_parent_refs(&mut self, parents: Vec<Weak<dyn DataType>>) {
                self.0.set_stored_parent_refs(parents)
            }
        }
        impl BuiltInDataType for CustomBuiltIn {
            fn get_c_type_declaration(
                &self,
                data_organization: Option<&dyn DataOrganization>,
            ) -> Option<String> {
                self.built_in_get_c_type_declaration(data_organization)
            }
            fn set_default_settings(&mut self, settings: &dyn Settings) {
                self.0.set_default_settings(settings)
            }
        }
        impl BuiltIn for CustomBuiltIn {
            fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
                self.0.built_in_is_equivalent(dt)
            }
            fn get_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
                vec![Box::new(CustomSettingsDefinition)]
            }
        }

        let dt = CustomBuiltIn(MockBuiltIn::new("byte", 1));
        let defs = dt.built_in_get_settings_definitions();
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0].get_name(), "Mutability");
        assert_eq!(defs[1].get_name(), "Custom");
    }

    #[test]
    fn is_equivalent_true_for_self() {
        let dt = MockBuiltIn::new("byte", 1);
        assert!(dt.built_in_is_equivalent(&dt));
    }

    #[test]
    fn is_equivalent_true_for_same_class_different_instance() {
        let a = MockBuiltIn::new("byte", 1);
        let b = MockBuiltIn::new("byte", 1);
        assert!(a.built_in_is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_false_for_different_class() {
        let a = MockBuiltIn::new("byte", 1);
        let b = MockBuiltIn::new("word", 2);
        assert!(!a.built_in_is_equivalent(&b));
    }

    #[test]
    fn c_type_declaration_str_formats_typedef_and_define() {
        let dt = MockBuiltIn::new("byte", 1);
        assert_eq!(
            dt.get_c_type_declaration_str("byte", "unsigned char", false),
            "typedef unsigned char    byte;"
        );
        assert_eq!(
            dt.get_c_type_declaration_str("byte", "unsigned char", true),
            "#define byte    unsigned char"
        );
    }

    #[test]
    fn c_type_declaration_len_uses_organization_approximation() {
        let dt = MockBuiltIn::new("byte", 1);
        let org = MockDataOrganization;
        assert_eq!(
            dt.get_c_type_declaration_len("byte", 1, false, &org, false),
            "typedef unsigned int8    byte;"
        );
    }

    #[test]
    fn c_type_declaration_for_self_uses_display_name_and_length() {
        let dt = MockBuiltIn::new("byte", 1);
        let org = MockDataOrganization;
        assert_eq!(
            dt.built_in_get_c_type_declaration_for_self(false, &org, false),
            "typedef unsigned int8    byte;"
        );
    }

    #[test]
    fn built_in_c_type_declaration_delegates_when_organization_present() {
        let dt = MockBuiltIn::new("byte", 1);
        let org = MockDataOrganization;
        assert_eq!(
            dt.built_in_get_c_type_declaration(Some(&org)),
            Some("typedef unsigned int8    byte;".to_string())
        );
        assert_eq!(dt.built_in_get_c_type_declaration(None), None);
    }

    #[test]
    fn built_in_c_type_declaration_is_none_for_dynamic_or_factory_types() {
        let mut dynamic = MockBuiltIn::new("dyn", 0);
        dynamic.dynamic = true;
        let org = MockDataOrganization;
        assert_eq!(dynamic.built_in_get_c_type_declaration(Some(&org)), None);

        let mut factory = MockBuiltIn::new("factory", 0);
        factory.factory = true;
        assert_eq!(factory.built_in_get_c_type_declaration(Some(&org)), None);
    }

    #[test]
    fn get_c_type_declaration_via_built_in_data_type_matches_direct_call() {
        let dt = MockBuiltIn::new("byte", 1);
        let org = MockDataOrganization;
        let via_trait: &dyn BuiltInDataType = &dt;
        assert_eq!(
            via_trait.get_c_type_declaration(Some(&org)),
            dt.built_in_get_c_type_declaration(Some(&org))
        );
    }
}
