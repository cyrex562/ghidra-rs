//! Port of `ghidra.program.model.data.AbstractPointerTypedefBuiltIn` and
//! `ghidra.program.model.data.PointerTypedef`.
//!
//! Both Java classes are thin wrappers: each constructs an internal `TypedefDataType` (the
//! `modelTypedef` field) around a `PointerDataType`, and delegates almost every method
//! (`getLength`, `getDataType`, `getBaseDataType`, `getValue`, `getRepresentation`,
//! `getSettingsDefinitions`/`getTypeDefSettingsDefinitions`, ...) straight through to it. This
//! port mirrors that shape closely: [`PointerTypedefBuiltInBase`] (standing in for
//! `AbstractPointerTypedefBuiltIn`) and [`PointerTypedef`] each embed a
//! [`TypedefDataType`](crate::program::model::data::typedef_data_type::TypedefDataType) field and
//! forward to it.
//!
//! ## No concrete `Pointer` existed yet
//!
//! `PointerDataType` (the Java class both wrap) was already ported in this crate, but only as a
//! cut-point *trait* -- like every other leaf `BuiltIn` datatype ported so far, no concrete,
//! constructible implementation exists (see that trait's own module docs: "a concrete
//! implementation satisfies it entirely..."). Since both classes here exist specifically to wrap
//! a real pointer, this port needed to supply the first one: [`BasicPointer`] (private to this
//! module), a minimal concrete `DataType + Pointer + PointerDataType` built directly on that
//! trait's already-real default method bodies.
//!
//! ## Collapsed constructor overloads
//!
//! Each Java class has two constructors: one building a fresh `PointerDataType` from a referenced
//! type + size, and one accepting an already-built `Pointer` (used by `copy()`/`clone()` to avoid
//! losing an existing pointer's exact size, including its "-1 = dynamically sized" sentinel).
//! Since [`BasicPointer`] is the only concrete `Pointer` this port has, both collapse to
//! [`PointerTypedefBuiltInBase::new`]/[`PointerTypedef::new`] taking the referenced type + size
//! directly. [`PointerTypedef::copy_typedef`]/[`PointerTypedef::clone_typedef`] therefore rebuild
//! from [`DataType::get_length`] (always resolved/positive) rather than the raw stored length, so
//! copying a dynamically-sized pointer-typedef produces a fixed-size one instead -- a known,
//! narrow divergence from Java's exact-preservation behavior.
//!
//! ## No `DataOrganization`-based default pointer size
//!
//! Java's address-space constructor (`PointerTypedef(..., AddressSpace)`) can infer a pointer size
//! of "matches the DTM's own default, so use -1" via `dtm.getDataOrganization().getPointerSize()`.
//! [`DataTypeManager::get_data_organization`](crate::program::model::data::data_type_manager::DataTypeManager::get_data_organization)
//! has no default body a bare manager can answer with, so [`PointerTypedef::new_with_space`]
//! requires an explicit positive `pointer_size` and returns `Err` otherwise, rather than calling
//! that inference path.
//!
//! ## `BuiltIn`/`GenericDataType`/`DataTypeImpl` not implemented
//!
//! Java's `AbstractPointerTypedefBuiltIn extends BuiltIn` and `PointerTypedef extends
//! GenericDataType`, both of which (transitively) require `DataTypeImpl`'s six storage accessors
//! (default settings, source archive, universal ID, two change-time fields, parent refs). Since
//! both classes here delegate virtually all of their real state to the embedded `model_typedef`
//! (which already implements `DataTypeImpl`/`GenericDataType` fully -- see its own module docs),
//! re-implementing those accessors again on the wrapper would mean tracking the same state twice
//! for no behavioral benefit; this port implements only [`DataType`] + [`TypeDef`] directly for
//! both wrapper structs. `getUniversalID()`'s own field (not part of `DataTypeImpl`) is kept,
//! since both Java classes maintain it directly (`UniversalIdGenerator.nextID()` at
//! construction); this port uses a private, crate-local atomic counter as a stand-in (see
//! [`next_universal_id`]) since no `UniversalIdGenerator` port exists.
//!
//! ## Settings: collapsed one-copy design
//!
//! `AbstractPointerTypedefBuiltIn`'s constructor does `setDefaultSettings(modelTypedef.getDefaultSettings())`,
//! copying `modelTypedef`'s *initial* defaults into `BuiltIn`/`DataTypeImpl`'s own separate
//! settings field, which subsequently evolves independently of `modelTypedef`'s own settings.
//! Since this port never implements that separate `DataTypeImpl` storage (see above), there is
//! only one settings store -- `model_typedef`'s own (itself backed by a shared `Arc<Mutex<...>>`,
//! see that struct's module docs) -- and both `get_default_settings()` overrides here simply
//! live-delegate to it. This is behaviorally equivalent in practice: nothing in this port ever
//! reaches `model_typedef`'s settings through any path other than the outer wrapper's own
//! accessors, so the Java "copy, then diverge" design and this port's "one shared store" design
//! produce identical observable results.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use crate::docking::settings::number_settings_definition::NumberSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::string_settings_definition::StringSettingsDefinition;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::model::address::AddressSpace;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::component_offset_settings_definition::ComponentOffsetSettingsDefinition;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_utilities::DataUtilities;
use crate::program::model::data::address_space_settings_definition::AddressSpaceSettingsDefinition;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::data::pointer_data_type::PointerDataType;
use crate::program::model::data::pointer_type::PointerType;
use crate::program::model::data::pointer_type_settings_definition::PointerTypeSettingsDefinition;
use crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder;
use crate::program::model::data::typedef::TypeDef;
use crate::program::model::data::typedef_data_type::TypedefDataType;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::share_data_type;
use crate::util::UniversalID;

/// Zero-sized marker used purely to call the defaulted trait methods of
/// [`DataTypeUtilities`]/[`DataUtilities`] (both are `&dyn Trait`-object seams -- see their own
/// module docs). Mirrors the identical marker in `typedef_data_type.rs`.
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataTypeUtilities for Utils {}
impl DataUtilities for Utils {}

/// Process-local substitute for `ghidra.util.UniversalIdGenerator.nextID()`, which has no port in
/// this crate. Not a port of any specific Java class; only guarantees uniqueness within a single
/// process run, unlike the real generator's cross-session persistence guarantees.
fn next_universal_id() -> UniversalID {
    static COUNTER: AtomicI64 = AtomicI64::new(1);
    UniversalID::new(COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Minimal concrete `Pointer`, standing in for `new PointerDataType(referencedDataType,
/// pointerSize, dtm)`. See the module docs for why this port needed to supply one. Not itself a
/// full port of `PointerDataType` (that trait already carries all the real logic this delegates
/// to) -- just the storage plus the two `Pointer`-only required methods
/// ([`Pointer::new_pointer`]/[`Pointer::typedef_builder`]) no cut-point trait can supply
/// generically.
struct BasicPointer {
    referenced_data_type: Option<Arc<dyn DataType>>,
    length: i32,
    deleted: bool,
}

impl BasicPointer {
    fn new(referenced_data_type: Option<Box<dyn DataType>>, length: i32) -> Self {
        BasicPointer { referenced_data_type: referenced_data_type.map(Arc::from), length, deleted: false }
    }
}

struct BasicPointerTypedefBuilder;
impl PointerTypedefBuilder for BasicPointerTypedefBuilder {}

impl DataType for BasicPointer {
    fn has_language_dependant_length(&self) -> bool {
        self.pointer_data_type_impl_has_language_dependant_length()
    }
    fn get_length(&self) -> i32 {
        self.pointer_data_type_impl_length()
    }
    fn get_aligned_length(&self) -> i32 {
        self.pointer_data_type_impl_aligned_length()
    }
    fn get_display_name(&self) -> String {
        self.pointer_data_type_impl_display_name()
    }
    fn get_name(&self) -> String {
        self.pointer_data_type_impl_name()
    }
    fn get_description(&self) -> String {
        self.pointer_data_type_impl_description()
    }
    fn get_mnemonic(&self, settings: &dyn Settings) -> String {
        self.pointer_data_type_impl_mnemonic(settings)
    }
    fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        self.pointer_data_type_impl_type_def_settings_definitions()
    }
    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, _length: i32) -> String {
        self.pointer_data_type_impl_representation(buf, settings)
    }
    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        self.pointer_data_type_impl_is_equivalent(dt)
    }
    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        self.pointer_data_type_impl_data_type_deleted(dt);
    }
    fn is_deleted(&self) -> bool {
        self.pointer_data_type_impl_is_deleted()
    }
    fn data_type_replaced(&mut self, old_dt: &dyn DataType, new_dt: &dyn DataType) {
        self.pointer_data_type_impl_data_type_replaced(old_dt, new_dt);
    }
    fn get_category_path(&self) -> CategoryPath {
        self.pointer_data_type_impl_category_path()
    }
    fn depends_on(&self, dt: &dyn DataType) -> bool {
        self.pointer_data_type_impl_depends_on(dt)
    }
    fn is_pointer(&self) -> bool {
        true
    }
    fn as_pointer(&self) -> Option<&dyn Pointer> {
        Some(self)
    }
}

impl Pointer for BasicPointer {
    fn get_data_type(&self) -> Option<Box<dyn DataType>> {
        self.pointer_data_type_impl_get_data_type()
    }

    fn new_pointer(&self, data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
        Box::new(BasicPointer::new(Some(data_type), self.length))
    }

    fn typedef_builder(&self) -> Box<dyn PointerTypedefBuilder> {
        Box::new(BasicPointerTypedefBuilder)
    }
}

impl PointerDataType for BasicPointer {
    fn stored_referenced_data_type(&self) -> Option<Box<dyn DataType>> {
        self.referenced_data_type.as_ref().map(share_data_type)
    }

    fn set_stored_referenced_data_type(&mut self, referenced_data_type: Option<Box<dyn DataType>>) {
        self.referenced_data_type = referenced_data_type.map(Arc::from);
    }

    fn stored_length(&self) -> i32 {
        self.length
    }

    fn set_stored_length(&mut self, length: i32) {
        self.length = length;
    }

    fn stored_deleted(&self) -> bool {
        self.deleted
    }

    fn set_stored_deleted(&mut self, deleted: bool) {
        self.deleted = deleted;
    }
}

fn category_path_for(referenced_data_type: &Option<Box<dyn DataType>>) -> CategoryPath {
    referenced_data_type.as_ref().map(|dt| dt.get_category_path()).unwrap_or_else(|| ROOT.clone())
}

/// `AbstractPointerTypedefDataType` provides an abstract `BuiltIn` datatype implementation for a
/// pointer-typedef datatype.
///
/// Port of `ghidra.program.model.data.AbstractPointerTypedefBuiltIn`. See the module-level
/// documentation for what was collapsed, dropped, or built fresh (this port's own
/// [`BasicPointer`]).
pub struct PointerTypedefBuiltInBase {
    category_path: CategoryPath,
    /// `None` stands in for the Java `typedefName == null` auto-naming sentinel.
    typedef_name: Option<String>,
    model_typedef: TypedefDataType,
    universal_id: UniversalID,
}

impl PointerTypedefBuiltInBase {
    /// Constructs a pointer-typedef. The category path will match that of the
    /// `referenced_data_type`.
    ///
    /// # Errors
    /// Returns `Err` if `name` is `Some` and not a valid data-type name (mirroring
    /// `setTypedefName`'s `IllegalArgumentException`), or if [`TypedefDataType::new_in_root`]
    /// rejects the constructed pointer (should not happen in practice, since a pointer is never
    /// void/default/bitfield/factory/dynamic).
    pub fn new(
        name: Option<&str>,
        referenced_data_type: Option<Box<dyn DataType>>,
        pointer_size: i32,
    ) -> Result<Self, String> {
        if let Some(n) = name {
            if !Utils.is_valid_data_type_name(n) {
                return Err(format!("Invalid DataType name: {n}"));
            }
        }
        let category_path = category_path_for(&referenced_data_type);
        let pointer = BasicPointer::new(referenced_data_type, pointer_size);
        let model_typedef = TypedefDataType::new_in_root("TEMP", Box::new(pointer))?;
        Ok(PointerTypedefBuiltInBase {
            category_path,
            typedef_name: name.map(str::to_string),
            model_typedef,
            universal_id: next_universal_id(),
        })
    }

    /// Get the referenced datatype used to construct this datatype (the datatype which the
    /// pointer references), or `None` for a default pointer.
    pub fn get_referenced_data_type(&self) -> Option<Box<dyn DataType>> {
        self.model_typedef.referenced_data_type().as_pointer().and_then(|p| p.get_data_type())
    }

    /// Port of the package-private `hasGeneratedNamed()`.
    pub fn has_generated_name(&self) -> bool {
        self.typedef_name.is_none()
    }
}

impl DataType for PointerTypedefBuiltInBase {
    fn get_name(&self) -> String {
        match &self.typedef_name {
            Some(n) => n.clone(),
            // Do not cache the name since there are no listeners to detect a settings change
            // which may impact name generation, matching the Java comment verbatim.
            None => TypedefDataType::generate_typedef_name(self),
        }
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    fn get_universal_id(&self) -> UniversalID {
        self.universal_id
    }

    fn has_language_dependant_length(&self) -> bool {
        self.model_typedef.has_language_dependant_length()
    }

    fn get_length(&self) -> i32 {
        self.model_typedef.get_length()
    }

    fn get_aligned_length(&self) -> i32 {
        self.model_typedef.get_aligned_length()
    }

    fn get_settings_definitions(&self) -> Vec<Box<dyn crate::docking::settings::settings_definition::SettingsDefinition>> {
        self.model_typedef.get_settings_definitions()
    }

    fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        self.model_typedef.get_type_def_settings_definitions()
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        // See the module docs on why there is only one (shared) settings store here.
        DataType::get_default_settings(&self.model_typedef)
    }

    fn get_value_class(&self, settings: &dyn Settings) -> Option<std::any::TypeId> {
        self.model_typedef.get_value_class(settings)
    }

    fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn std::any::Any>> {
        self.model_typedef.get_value(buf, settings, length)
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        self.model_typedef.get_representation(buf, settings, length)
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        let Some(other_td) = dt.as_typedef() else {
            return false;
        };
        if !Utils.equals_ignore_conflict(&DataType::get_name(self), &other_td.get_name()) {
            return false;
        }
        if !self.has_same_type_def_settings(other_td) {
            return false;
        }
        let my_dt = TypeDef::get_data_type(self);
        let other_dt = other_td.get_data_type();
        Utils.is_same_or_equivalent_data_type(my_dt.as_ref(), other_dt.as_ref())
    }

    fn depends_on(&self, dt: &dyn DataType) -> bool {
        let my_dt = TypeDef::get_data_type(self);
        my_dt.is_equivalent(dt) || dt.is_equivalent(my_dt.as_ref()) || my_dt.depends_on(dt)
    }

    fn is_typedef(&self) -> bool {
        true
    }

    fn as_typedef(&self) -> Option<&dyn TypeDef> {
        Some(self)
    }
}

impl TypeDef for PointerTypedefBuiltInBase {
    fn is_auto_named(&self) -> bool {
        self.typedef_name.is_none()
    }

    fn enable_auto_naming(&mut self) {
        self.typedef_name = None;
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        self.model_typedef.get_data_type()
    }

    fn get_base_data_type(&self) -> Box<dyn DataType> {
        TypeDef::get_base_data_type(&self.model_typedef)
    }
}

impl std::fmt::Display for PointerTypedefBuiltInBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PointerTypedefBuiltIn: typedef {} {}",
            DataType::get_name(self),
            TypeDef::get_data_type(self).get_name()
        )
    }
}

/// `PointerTypedef` provides a Pointer-Typedef template datatype which may be used as an
/// alternative to `PointerTypedefBuilder` for select use cases.
///
/// Port of `ghidra.program.model.data.PointerTypedef`. See the module-level documentation for
/// what was collapsed, dropped, or built fresh.
///
/// NOTE: unlike other `BuiltIn` datatypes, this type is not discoverable/managed by a
/// `BuiltInDataTypeManager` port -- matching the Java class's own documented intent (its name
/// intentionally does not end in `DataType` for the same reason).
pub struct PointerTypedef {
    category_path: CategoryPath,
    /// Only meaningful when `!is_auto_named` -- mirrors the Java field inherited from
    /// `GenericDataType`, which `getName()` ignores while auto-naming is active.
    name: String,
    is_auto_named: bool,
    model_typedef: TypedefDataType,
    universal_id: UniversalID,
}

impl PointerTypedef {
    /// Constructs a pointer-typedef without any settings.
    ///
    /// `type_def_name` of `None` (or blank) requests auto-naming, matching
    /// `StringUtils.isBlank(typeDefName)`.
    ///
    /// # Errors
    /// See [`TypedefDataType::new_in_root`] (a constructed pointer should never actually trigger
    /// this).
    pub fn new(
        type_def_name: Option<&str>,
        referenced_data_type: Option<Box<dyn DataType>>,
        pointer_size: i32,
    ) -> Result<Self, String> {
        let is_auto_named = type_def_name.map(|n| n.trim().is_empty()).unwrap_or(true);
        let category_path = category_path_for(&referenced_data_type);
        let name = if is_auto_named { "TEMP".to_string() } else { type_def_name.unwrap().to_string() };
        let pointer = BasicPointer::new(referenced_data_type, pointer_size);
        let model_typedef = TypedefDataType::new_in_root("TEMP", Box::new(pointer))?;
        Ok(PointerTypedef {
            category_path,
            name,
            is_auto_named,
            model_typedef,
            universal_id: next_universal_id(),
        })
    }

    /// Constructs a pointer-typedef of a specific [`PointerType`] (IBO, RELATIVE, FILE_OFFSET).
    ///
    /// # Errors
    /// See [`PointerTypedef::new`].
    pub fn new_with_type(
        type_def_name: Option<&str>,
        referenced_data_type: Option<Box<dyn DataType>>,
        pointer_size: i32,
        pointer_type: &dyn PointerType,
    ) -> Result<Self, String> {
        let td = Self::new(type_def_name, referenced_data_type, pointer_size)?;
        let mut settings = DataType::get_default_settings(&td);
        PointerTypeSettingsDefinition::DEF.set_type(settings.as_mut(), pointer_type);
        Ok(td)
    }

    /// Constructs an offset-pointer-typedef with the given signed component offset.
    ///
    /// # Errors
    /// See [`PointerTypedef::new`].
    pub fn new_with_component_offset(
        type_def_name: Option<&str>,
        referenced_data_type: Option<Box<dyn DataType>>,
        pointer_size: i32,
        component_offset: i64,
    ) -> Result<Self, String> {
        let td = Self::new(type_def_name, referenced_data_type, pointer_size)?;
        let mut settings = DataType::get_default_settings(&td);
        ComponentOffsetSettingsDefinition::DEF.set_value(settings.as_mut(), component_offset);
        Ok(td)
    }

    /// Constructs a pointer-typedef which dereferences into a specific address space.
    ///
    /// # Errors
    /// Returns `Err` if `pointer_size <= 0`: unlike Java, this port cannot infer a preferred
    /// pointer size from a `DataTypeManager`'s `DataOrganization` (no concrete implementation
    /// exists in this crate yet -- see the module docs), so an explicit positive size is
    /// required. Also see [`PointerTypedef::new`].
    pub fn new_with_space(
        type_def_name: Option<&str>,
        referenced_data_type: Option<Box<dyn DataType>>,
        pointer_size: i32,
        space: &AddressSpace,
    ) -> Result<Self, String> {
        if pointer_size <= 0 {
            return Err(
                "PointerTypedef::new_with_space requires an explicit positive pointer_size: \
                 preferred-size inference from a DataOrganization is not available in this port"
                    .to_string(),
            );
        }
        let td = Self::new(type_def_name, referenced_data_type, pointer_size)?;
        let mut settings = DataType::get_default_settings(&td);
        AddressSpaceSettingsDefinition::DEF.set_value(settings.as_mut(), space.name());
        Ok(td)
    }

    /// Get the referenced datatype used to construct this datatype (the datatype which the
    /// pointer references), or `None` for a default pointer.
    pub fn get_referenced_data_type(&self) -> Option<Box<dyn DataType>> {
        self.model_typedef.referenced_data_type().as_pointer().and_then(|p| p.get_data_type())
    }

    /// Port of `PointerTypedef.clone(DataTypeManager)`. Since this port tracks no `dataMgr`
    /// identity to compare against (see the module docs on dropped `DataTypeImpl` storage), this
    /// always behaves like [`PointerTypedef::copy_typedef`] rather than Java's `dataMgr == dtm`
    /// short-circuit returning `self` unchanged.
    pub fn clone_typedef(&self) -> PointerTypedef {
        self.copy_typedef()
    }

    /// Port of `PointerTypedef.copy(DataTypeManager)`. See the module docs for why this rebuilds
    /// from the resolved (always-positive) [`DataType::get_length`] rather than the raw stored
    /// pointer length, narrowing fidelity for a dynamically-sized source pointer.
    pub fn copy_typedef(&self) -> PointerTypedef {
        let referenced = self.get_referenced_data_type();
        let length = TypeDef::get_data_type(self).get_length();
        let name = if self.is_auto_named { None } else { Some(self.name.as_str()) };
        let mut copied =
            PointerTypedef::new(name, referenced, length).expect("copying an existing valid pointer-typedef cannot fail validation");
        copied.model_typedef.copy_type_def_settings_from(&self.model_typedef, false);
        copied
    }
}

impl DataType for PointerTypedef {
    fn get_name(&self) -> String {
        if self.is_auto_named {
            // Do not cache the name since there are no listeners to detect a settings change
            // which may impact name generation, matching the Java comment verbatim.
            TypedefDataType::generate_typedef_name(self)
        } else {
            self.name.clone()
        }
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    fn get_universal_id(&self) -> UniversalID {
        self.universal_id
    }

    fn get_description(&self) -> String {
        "Pointer-Typedef".to_string()
    }

    fn has_language_dependant_length(&self) -> bool {
        self.model_typedef.has_language_dependant_length()
    }

    fn get_length(&self) -> i32 {
        self.model_typedef.get_length()
    }

    fn get_aligned_length(&self) -> i32 {
        self.model_typedef.get_aligned_length()
    }

    fn get_settings_definitions(&self) -> Vec<Box<dyn crate::docking::settings::settings_definition::SettingsDefinition>> {
        self.model_typedef.get_settings_definitions()
    }

    fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        self.model_typedef.get_type_def_settings_definitions()
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        DataType::get_default_settings(&self.model_typedef)
    }

    fn get_value_class(&self, settings: &dyn Settings) -> Option<std::any::TypeId> {
        self.model_typedef.get_value_class(settings)
    }

    fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn std::any::Any>> {
        self.model_typedef.get_value(buf, settings, length)
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        self.model_typedef.get_representation(buf, settings, length)
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        let Some(other_td) = dt.as_typedef() else {
            return false;
        };
        if !Utils.equals_ignore_conflict(&DataType::get_name(self), &other_td.get_name()) {
            return false;
        }
        if !self.has_same_type_def_settings(other_td) {
            return false;
        }
        let my_dt = TypeDef::get_data_type(self);
        let other_dt = other_td.get_data_type();
        Utils.is_same_or_equivalent_data_type(my_dt.as_ref(), other_dt.as_ref())
    }

    fn depends_on(&self, dt: &dyn DataType) -> bool {
        let my_dt = TypeDef::get_data_type(self);
        my_dt.is_equivalent(dt) || dt.is_equivalent(my_dt.as_ref()) || my_dt.depends_on(dt)
    }

    fn is_typedef(&self) -> bool {
        true
    }

    fn as_typedef(&self) -> Option<&dyn TypeDef> {
        Some(self)
    }
}

impl TypeDef for PointerTypedef {
    fn is_auto_named(&self) -> bool {
        self.is_auto_named
    }

    fn enable_auto_naming(&mut self) {
        self.is_auto_named = true;
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        self.model_typedef.get_data_type()
    }

    fn get_base_data_type(&self) -> Box<dyn DataType> {
        TypeDef::get_base_data_type(&self.model_typedef)
    }
}

impl std::fmt::Display for PointerTypedef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_auto_named {
            write!(f, "PointerTypedef: {}", DataType::get_name(self))
        } else {
            write!(
                f,
                "PointerTypedef: typedef {} {}",
                DataType::get_name(self),
                TypeDef::get_data_type(self).get_name()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        length: i32,
    }
    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_name() == dt.get_name() && self.get_length() == dt.get_length()
        }
    }

    fn leaf(name: &str, length: i32) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: name.to_string(), length })
    }

    // ---- PointerTypedefBuiltInBase (AbstractPointerTypedefBuiltIn) ----

    #[test]
    fn builtin_base_wraps_referenced_type_through_pointer() {
        let base = PointerTypedefBuiltInBase::new(Some("MyPtr"), Some(leaf("int", 4)), 4).unwrap();
        assert_eq!(DataType::get_name(&base), "MyPtr");
        assert_eq!(base.get_length(), 4);
        assert_eq!(base.get_referenced_data_type().unwrap().get_name(), "int");
    }

    #[test]
    fn builtin_base_rejects_invalid_name() {
        let err = match PointerTypedefBuiltInBase::new(Some(""), None, 4) {
            Err(e) => e,
            Ok(_) => panic!("expected blank name to be rejected"),
        };
        assert!(err.contains("Invalid"));
    }

    #[test]
    fn builtin_base_supports_default_pointer_with_no_referenced_type() {
        let base = PointerTypedefBuiltInBase::new(Some("Raw"), None, 4).unwrap();
        assert!(base.get_referenced_data_type().is_none());
        assert_eq!(base.get_category_path(), ROOT.clone());
    }

    #[test]
    fn builtin_base_auto_naming_generates_name() {
        let base = PointerTypedefBuiltInBase::new(None, Some(leaf("int", 4)), 4).unwrap();
        assert!(base.is_auto_named());
        assert!(base.has_generated_name());
        // "int *" is the pointer's own generated name/mnemonic-ish display; just check it's
        // non-empty and derived (not the literal "TEMP" placeholder name).
        assert_ne!(DataType::get_name(&base), "TEMP");
    }

    // ---- IBO32/IBO64-style construction (validates the actual Phase 3c usage pattern) ----

    #[test]
    fn ibo_style_pointer_type_setting_is_readable_back() {
        let mut base = PointerTypedefBuiltInBase::new(Some("ImageBaseOffset32"), None, 4).unwrap();
        let mut settings = DataType::get_default_settings(&base);
        PointerTypeSettingsDefinition::DEF.set_type(
            settings.as_mut(),
            &crate::program::model::data::pointer_type::ImageBaseRelativePointerType,
        );
        // Since get_default_settings() is a live handle onto the shared store, a second
        // independent call must observe the write made through the first.
        let settings2 = base.get_default_settings();
        assert_eq!(
            PointerTypeSettingsDefinition::DEF.get_type(Some(settings2.as_ref())).value(),
            crate::program::model::data::pointer_type::ImageBaseRelativePointerType.value()
        );
        let _ = &mut base; // silence unused-mut warnings across edits
    }

    // ---- PointerTypedef ----

    #[test]
    fn pointer_typedef_wraps_referenced_type() {
        let td = PointerTypedef::new(Some("MyPtr"), Some(leaf("int", 4)), 4).unwrap();
        assert_eq!(DataType::get_name(&td), "MyPtr");
        assert_eq!(td.get_length(), 4);
        assert_eq!(td.get_referenced_data_type().unwrap().get_name(), "int");
        assert_eq!(DataType::get_description(&td), "Pointer-Typedef");
    }

    #[test]
    fn pointer_typedef_auto_names_on_blank_name() {
        let td = PointerTypedef::new(Some("  "), Some(leaf("int", 4)), 4).unwrap();
        assert!(td.is_auto_named());
    }

    #[test]
    fn pointer_typedef_with_component_offset_persists_setting() {
        let td = PointerTypedef::new_with_component_offset(Some("Off"), Some(leaf("int", 4)), 4, 12).unwrap();
        let settings = DataType::get_default_settings(&td);
        assert_eq!(
            ComponentOffsetSettingsDefinition::DEF.get_value(settings.as_ref()),
            12
        );
    }

    #[test]
    fn pointer_typedef_with_space_requires_positive_size() {
        let space = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 1);
        let err = match PointerTypedef::new_with_space(Some("Sp"), Some(leaf("int", 4)), -1, &space) {
            Err(e) => e,
            Ok(_) => panic!("expected non-positive pointer_size to be rejected"),
        };
        assert!(err.contains("DataOrganization"));
    }

    #[test]
    fn pointer_typedef_with_space_persists_space_name() {
        let space = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 1);
        let td = PointerTypedef::new_with_space(Some("Sp"), Some(leaf("int", 4)), 4, &space).unwrap();
        let settings = DataType::get_default_settings(&td);
        assert_eq!(AddressSpaceSettingsDefinition::DEF.get_value(settings.as_ref()), Some("ram".to_string()));
    }

    #[test]
    fn copy_typedef_preserves_name_and_settings() {
        let original = PointerTypedef::new_with_component_offset(Some("Off"), Some(leaf("int", 4)), 4, 5).unwrap();
        let copied = original.copy_typedef();
        assert_eq!(DataType::get_name(&copied), "Off");
        let settings = DataType::get_default_settings(&copied);
        assert_eq!(ComponentOffsetSettingsDefinition::DEF.get_value(settings.as_ref()), 5);
    }

    #[test]
    fn is_equivalent_compares_names_and_referenced_types() {
        let a = PointerTypedef::new(Some("Foo"), Some(leaf("int", 4)), 4).unwrap();
        let b = PointerTypedef::new(Some("Foo"), Some(leaf("int", 4)), 4).unwrap();
        let c = PointerTypedef::new(Some("Bar"), Some(leaf("int", 4)), 4).unwrap();
        assert!(DataType::is_equivalent(&a, &b));
        assert!(!DataType::is_equivalent(&a, &c));
    }
}
