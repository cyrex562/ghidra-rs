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

use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::{concat, SettingsDefinition};
use crate::program::model::data::abstract_data_type::check_new_abstract_data_type_args;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_utilities::DataUtilities;
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
        data_organization: &DataOrganizationImpl,
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
        data_organization: &DataOrganizationImpl,
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
        data_organization: Option<&DataOrganizationImpl>,
    ) -> Option<String> {
        if self.is_dynamic_type() || self.is_factory_type() {
            return None;
        }
        data_organization
            .map(|org| self.built_in_get_c_type_declaration_for_self(false, org, false))
    }
}

/// Stands in for the bare `DataUtilities` statics used by the `AbstractDataType` constructor's
/// name validation (see [`check_new_abstract_data_type_args`]).
struct NameValidation;
impl DataUtilities for NameValidation {}

/// The shared default [`DataOrganizationImpl`] (`DataOrganizationImpl.getDefaultOrganization()`),
/// built once and shared by every built-in that is not bound to a data type manager.
pub fn shared_default_organization() -> Arc<DataOrganizationImpl> {
    static DEFAULT: OnceLock<Arc<DataOrganizationImpl>> = OnceLock::new();
    DEFAULT
        .get_or_init(|| Arc::new(DataOrganizationImpl::get_default_organization(None)))
        .clone()
}

/// A by-value copy of the settings a data type manager installs as a built-in's default settings
/// (`BuiltIn.setDefaultSettings(Settings)`), or the empty, immutable `SettingsImpl.NO_SETTINGS`
/// every built-in starts with (`DataTypeImpl`'s constructor).
///
/// Java stores a live reference to the manager's settings object. A [`DataType`] must be
/// `Send + Sync` and the [`Settings`] trait objects are neither, so this port copies the long
/// and string values present when [`BuiltInDataType::set_default_settings`] is called; a manager
/// that later changes its settings re-installs them. Like `NO_SETTINGS`, the copy is immutable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultSettingsSnapshot {
    longs: BTreeMap<String, i64>,
    strings: BTreeMap<String, String>,
}

impl DefaultSettingsSnapshot {
    /// Copies every long/string value `settings` currently holds (including values it inherits
    /// from its own default settings, since lookups through the copy must answer the same).
    pub fn capture(settings: &dyn Settings) -> Self {
        let mut snapshot = Self::default();
        let mut names = settings.get_names();
        if let Some(defaults) = settings.get_default_settings() {
            names.extend(defaults.get_names());
        }
        for name in names {
            if let Some(value) = settings.get_long(&name) {
                snapshot.longs.insert(name, value);
            } else if let Some(value) = settings.get_string(&name) {
                snapshot.strings.insert(name, value);
            }
        }
        snapshot
    }
}

impl Settings for DefaultSettingsSnapshot {
    fn is_immutable_settings(&self) -> bool {
        true
    }

    fn is_change_allowed(&self, _settings_definition: &dyn SettingsDefinition) -> bool {
        false
    }

    fn get_long(&self, name: &str) -> Option<i64> {
        self.longs.get(name).copied()
    }

    fn get_string(&self, name: &str) -> Option<String> {
        self.strings.get(name).cloned()
    }

    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        if let Some(value) = self.longs.get(name) {
            return Some(Box::new(*value));
        }
        self.strings.get(name).map(|value| Box::new(value.clone()) as Box<dyn Any>)
    }

    fn get_names(&self) -> Vec<String> {
        self.longs.keys().chain(self.strings.keys()).cloned().collect()
    }

    fn is_empty(&self) -> bool {
        self.longs.is_empty() && self.strings.is_empty()
    }
}

/// The instance state every `BuiltIn` datatype carries: the `name`/`categoryPath` fields of
/// `AbstractDataType`, the `defaultSettings` field of `DataTypeImpl`, and the data organization
/// of the data type manager the instance was created for.
///
/// This is the shared-state half of the `BuiltIn` port (the [`BuiltIn`] trait is the behaviour
/// half); each concrete built-in embeds one.
///
/// Java keeps a reference to the `DataTypeManager` itself (`dataMgr`) and consults it only for
/// `getDataOrganization()`. [`DataTypeManager`] is not `Send + Sync`, so a built-in here records
/// the manager's [`DataOrganizationImpl`] when it is created; [`DataType::get_data_type_manager`]
/// therefore stays `None` for built-ins.
#[derive(Debug, Clone)]
pub struct BuiltInBase {
    name: String,
    category_path: CategoryPath,
    data_organization: Option<Arc<DataOrganizationImpl>>,
    default_settings: DefaultSettingsSnapshot,
}

impl BuiltInBase {
    /// Port of the `BuiltIn(CategoryPath, String, DataTypeManager)` constructor: a missing
    /// category path becomes [`ROOT`].
    ///
    /// # Panics
    /// Panics, as the `AbstractDataType` constructor throws `IllegalArgumentException`, if `name`
    /// is empty or not a valid data type name.
    pub fn new(path: Option<CategoryPath>, name: &str, dtm: Option<&dyn DataTypeManager>) -> Self {
        check_new_abstract_data_type_args(name, &NameValidation);
        Self {
            name: name.to_string(),
            category_path: path.unwrap_or_else(|| ROOT.clone()),
            data_organization: dtm.map(|dtm| dtm.get_data_organization()),
            default_settings: DefaultSettingsSnapshot::default(),
        }
    }

    /// The state of a different built-in named `name` (in the root category) created for the same
    /// data type manager as this one. Stands in for `Other.dataType.clone(getDataTypeManager())`.
    pub fn rebound(&self, name: &str) -> Self {
        check_new_abstract_data_type_args(name, &NameValidation);
        Self {
            name: name.to_string(),
            category_path: ROOT.clone(),
            data_organization: self.data_organization.clone(),
            default_settings: DefaultSettingsSnapshot::default(),
        }
    }

    /// This state under a new category path and name (Java `BuiltIn` subclasses that rename
    /// themselves, e.g. `PointerDataType.dataTypeReplaced`), keeping the data organization and
    /// default settings. A missing category path becomes [`ROOT`].
    pub fn renamed(&self, path: Option<CategoryPath>, name: &str) -> Self {
        check_new_abstract_data_type_args(name, &NameValidation);
        Self {
            name: name.to_string(),
            category_path: path.unwrap_or_else(|| ROOT.clone()),
            data_organization: self.data_organization.clone(),
            default_settings: self.default_settings.clone(),
        }
    }

    /// The `name` field.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `categoryPath` field.
    pub fn category_path(&self) -> &CategoryPath {
        &self.category_path
    }

    /// Port of the `final` `AbstractDataType.getDataOrganization()`: the bound manager's
    /// organization, or the default organization when there is no manager.
    pub fn data_organization(&self) -> Arc<DataOrganizationImpl> {
        self.data_organization.clone().unwrap_or_else(shared_default_organization)
    }

    /// Whether this instance was created for a data type manager (Java: `dataMgr != null`).
    pub fn is_bound(&self) -> bool {
        self.data_organization.is_some()
    }

    /// The `defaultSettings` field.
    pub fn default_settings(&self) -> &DefaultSettingsSnapshot {
        &self.default_settings
    }

    /// Port of `BuiltIn.setDefaultSettings(Settings)`; see [`DefaultSettingsSnapshot`] for why the
    /// values are copied.
    pub fn set_default_settings(&mut self, settings: &dyn Settings) {
        self.default_settings = DefaultSettingsSnapshot::capture(settings);
    }
}

/// Implements [`DataTypeImpl`], [`BuiltInDataType`] and [`BuiltIn`] for a concrete built-in whose
/// shared state lives in a `base: BuiltInBase` field.
///
/// The type must provide these inherent methods, which carry its own overrides:
/// `c_type_declaration(&self, Option<&DataOrganizationImpl>) -> Option<String>`
/// (`getCTypeDeclaration(DataOrganization)`), `built_in_settings_definitions(&self)`
/// (`getBuiltInSettingsDefinitions()`), and `decompiler_display_name(&self, DecompilerLanguage)`
/// (`getDecompilerDisplayName(DecompilerLanguage)`).
macro_rules! impl_built_in {
    ($ty:ty) => {
        impl $crate::program::model::data::data_type_impl::DataTypeImpl for $ty {
            fn stored_default_settings(
                &self,
            ) -> Box<dyn $crate::docking::settings::settings::Settings> {
                Box::new(self.base.default_settings().clone())
            }
            fn set_stored_default_settings(
                &mut self,
                settings: Box<dyn $crate::docking::settings::settings::Settings>,
            ) {
                self.base.set_default_settings(settings.as_ref());
            }
            fn stored_source_archive(
                &self,
            ) -> Option<Box<dyn $crate::program::model::data::source_archive::SourceArchive>> {
                Some(Box::new(
                    $crate::app::plugin::core::datamgr::archive::built_in_source_archive::INSTANCE,
                ))
            }
            // A built-in's source archive is always `BuiltInSourceArchive.INSTANCE`.
            fn set_stored_source_archive(
                &mut self,
                _archive: Option<Box<dyn $crate::program::model::data::source_archive::SourceArchive>>,
            ) {
            }
            fn stored_universal_id(&self) -> $crate::util::UniversalID {
                $crate::util::UniversalID::new(0)
            }
            // `BuiltIn.getLastChangeTime()` is always 0; the setters of `AbstractDataType`
            // that `BuiltIn` inherits are no-ops.
            fn stored_last_change_time(&self) -> i64 {
                0
            }
            fn set_stored_last_change_time(&mut self, _last_change_time: i64) {}
            fn stored_last_change_time_in_source_archive(&self) -> i64 {
                0
            }
            fn set_stored_last_change_time_in_source_archive(&mut self, _last_change_time: i64) {}
            // `BuiltIn.addParent`/`removeParent` are final no-ops: built-ins never track parents.
            fn stored_parent_refs(
                &self,
            ) -> Vec<std::sync::Weak<dyn $crate::program::model::data::data_type::DataType>> {
                Vec::new()
            }
            fn set_stored_parent_refs(
                &mut self,
                _parents: Vec<std::sync::Weak<dyn $crate::program::model::data::data_type::DataType>>,
            ) {
            }
        }

        impl $crate::program::model::data::built_in_data_type::BuiltInDataType for $ty {
            fn get_c_type_declaration(
                &self,
                data_organization: Option<
                    &$crate::program::model::data::data_organization_impl::DataOrganizationImpl,
                >,
            ) -> Option<String> {
                self.c_type_declaration(data_organization)
            }
            fn set_default_settings(
                &mut self,
                settings: &dyn $crate::docking::settings::settings::Settings,
            ) {
                self.base.set_default_settings(settings);
            }
        }

        impl $crate::program::model::data::built_in::BuiltIn for $ty {
            fn get_built_in_settings_definitions(
                &self,
            ) -> Vec<Box<dyn $crate::docking::settings::settings_definition::SettingsDefinition>>
            {
                self.built_in_settings_definitions()
            }
            fn built_in_is_equivalent(
                &self,
                dt: &dyn $crate::program::model::data::data_type::DataType,
            ) -> bool {
                $crate::program::model::data::built_in::same_class(self, dt)
            }
            fn get_decompiler_display_name(
                &self,
                language: $crate::program::model::lang::decompiler_language::DecompilerLanguage,
            ) -> String {
                self.decompiler_display_name(language)
            }
        }
    };
}
pub(crate) use impl_built_in;

/// The [`DataType`] methods every built-in implements the same way (from `AbstractDataType`,
/// `DataTypeImpl` and `BuiltIn`). Expands to impl items; invoke inside `impl DataType for T`,
/// where `T` has a `base: BuiltInBase` field, a `new(Option<&dyn DataTypeManager>)` constructor,
/// and the [`impl_built_in!`] impls.
///
/// `built_in_data_type_methods!(own_abbreviated_label_prefix)` leaves out
/// `get_default_abbreviated_label_prefix`, for a type that overrides
/// `getDefaultAbbreviatedLabelPrefix()`.
macro_rules! built_in_data_type_methods {
    () => {
        $crate::program::model::data::built_in::built_in_data_type_methods!(own_abbreviated_label_prefix);
        fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
            self.get_default_label_prefix()
        }
    };
    (own_abbreviated_label_prefix) => {
        fn get_name(&self) -> String {
            self.base.name().to_string()
        }
        fn get_category_path(&self) -> $crate::program::model::data::category_path::CategoryPath {
            self.base.category_path().clone()
        }
        fn get_data_organization(
            &self,
        ) -> std::sync::Arc<$crate::program::model::data::data_organization_impl::DataOrganizationImpl>
        {
            self.base.data_organization()
        }
        fn get_settings_definitions(
            &self,
        ) -> Vec<Box<dyn $crate::docking::settings::settings_definition::SettingsDefinition>> {
            $crate::program::model::data::built_in::BuiltIn::built_in_get_settings_definitions(self)
        }
        fn get_default_settings(&self) -> Box<dyn $crate::docking::settings::settings::Settings> {
            $crate::program::model::data::data_type_impl::DataTypeImpl::data_type_impl_get_default_settings(self)
        }
        fn clone_data_type(
            &self,
            dtm: &dyn $crate::program::model::data::data_type_manager::DataTypeManager,
        ) -> Box<dyn $crate::program::model::data::data_type::DataType> {
            Box::new(Self::new(Some(dtm)))
        }
        // `BuiltIn.copy(DataTypeManager)` is final and returns `clone(dtm)`.
        fn copy_data_type(
            &self,
            dtm: &dyn $crate::program::model::data::data_type_manager::DataTypeManager,
        ) -> Box<dyn $crate::program::model::data::data_type::DataType> {
            Box::new(Self::new(Some(dtm)))
        }
        fn get_aligned_length(&self) -> i32 {
            $crate::program::model::data::data_type_impl::DataTypeImpl::data_type_impl_get_aligned_length(self)
        }
        fn get_alignment(&self) -> i32 {
            $crate::program::model::data::data_type_impl::DataTypeImpl::data_type_impl_get_alignment(self)
        }
        fn get_source_archive(
            &self,
        ) -> Option<Box<dyn $crate::program::model::data::source_archive::SourceArchive>> {
            $crate::program::model::data::data_type_impl::DataTypeImpl::data_type_impl_get_source_archive(self)
        }
        fn runtime_class(&self) -> Option<std::any::TypeId> {
            Some(std::any::TypeId::of::<Self>())
        }
        fn as_built_in(&self) -> Option<&dyn $crate::program::model::data::built_in::BuiltIn> {
            Some(self)
        }
        fn as_built_in_data_type(
            &self,
        ) -> Option<&dyn $crate::program::model::data::built_in_data_type::BuiltInDataType> {
            Some(self)
        }
    };
}
pub(crate) use built_in_data_type_methods;

/// Port of `getClass() == dt.getClass()` as used by `BuiltIn.isEquivalent(DataType)`: `dt` is the
/// same object, or an instance of the same concrete type.
pub fn same_class<T: DataType + 'static>(this: &T, dt: &dyn DataType) -> bool {
    if std::ptr::eq(dt as *const dyn DataType as *const (), this as *const T as *const ()) {
        return true;
    }
    dt.runtime_class() == Some(TypeId::of::<T>())
}

/// Declares the Java `dataType` singleton of a built-in: `ty::data_type()` hands out the shared
/// instance (created without a data type manager) as an `Arc<dyn DataType>`, and
/// `ty::instance()` returns the same instance with its concrete type.
macro_rules! built_in_singleton {
    ($ty:ident) => {
        impl $ty {
            /// The shared instance with no data type manager (Java's static `dataType` field).
            pub fn instance() -> &'static std::sync::Arc<$ty> {
                static INSTANCE: std::sync::OnceLock<std::sync::Arc<$ty>> =
                    std::sync::OnceLock::new();
                INSTANCE.get_or_init(|| std::sync::Arc::new($ty::new(None)))
            }

            /// The shared instance as a `DataType` handle (Java's static `dataType` field).
            pub fn data_type() -> std::sync::Arc<dyn $crate::program::model::data::data_type::DataType> {
                $ty::instance().clone()
            }
        }
    };
}
pub(crate) use built_in_singleton;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::source_archive::SourceArchive;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

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

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    // Every `set_stored_*` below takes `&mut self`, so the stored state needs no interior
    // mutability; plain fields also keep this mock `Send + Sync`, as `DataType` requires. The
    // settings and source-archive boxes are dropped entirely, since the mock's getters always
    // answer with a fresh `MockSettings`/`None` and `dyn Settings`/`dyn SourceArchive` are
    // themselves neither `Send` nor `Sync`.
    struct MockBuiltIn {
        name: String,
        length: i32,
        dynamic: bool,
        factory: bool,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
        parents: Vec<Weak<dyn DataType>>,
    }

    impl MockBuiltIn {
        fn new(name: &str, length: i32) -> Self {
            Self {
                name: name.to_string(),
                length,
                dynamic: false,
                factory: false,
                last_change_time: 0,
                last_change_time_in_source_archive: 0,
                parents: Vec::new(),
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

    impl BuiltInDataType for MockBuiltIn {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&DataOrganizationImpl>,
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
                data_organization: Option<&DataOrganizationImpl>,
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
        let org = mock_data_organization();
        assert_eq!(
            dt.get_c_type_declaration_len("byte", 1, false, &org, false),
            "typedef unsigned char    byte;"
        );
    }

    #[test]
    fn c_type_declaration_for_self_uses_display_name_and_length() {
        let dt = MockBuiltIn::new("byte", 1);
        let org = mock_data_organization();
        assert_eq!(
            dt.built_in_get_c_type_declaration_for_self(false, &org, false),
            "typedef unsigned char    byte;"
        );
    }

    #[test]
    fn built_in_c_type_declaration_delegates_when_organization_present() {
        let dt = MockBuiltIn::new("byte", 1);
        let org = mock_data_organization();
        assert_eq!(
            dt.built_in_get_c_type_declaration(Some(&org)),
            Some("typedef unsigned char    byte;".to_string())
        );
        assert_eq!(dt.built_in_get_c_type_declaration(None), None);
    }

    #[test]
    fn built_in_c_type_declaration_is_none_for_dynamic_or_factory_types() {
        let mut dynamic = MockBuiltIn::new("dyn", 0);
        dynamic.dynamic = true;
        let org = mock_data_organization();
        assert_eq!(dynamic.built_in_get_c_type_declaration(Some(&org)), None);

        let mut factory = MockBuiltIn::new("factory", 0);
        factory.factory = true;
        assert_eq!(factory.built_in_get_c_type_declaration(Some(&org)), None);
    }

    #[test]
    fn get_c_type_declaration_via_built_in_data_type_matches_direct_call() {
        let dt = MockBuiltIn::new("byte", 1);
        let org = mock_data_organization();
        let via_trait: &dyn BuiltInDataType = &dt;
        assert_eq!(
            via_trait.get_c_type_declaration(Some(&org)),
            dt.built_in_get_c_type_declaration(Some(&org))
        );
    }
}
