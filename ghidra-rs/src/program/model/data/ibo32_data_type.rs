//! Port of `ghidra.program.model.data.IBO32DataType`.
//!
//! `IBO32DataType` provides a Pointer-Typedef `BuiltIn` for a 32-bit Image Base Offset Relative
//! Pointer: a fixed-size, `PointerType::IMAGE_BASE_RELATIVE`-tagged pointer-typedef with no
//! referenced datatype. The Java class `extends AbstractPointerTypedefBuiltIn`, composed here
//! (per this crate's "compose, don't inherit" convention) as an embedded
//! [`PointerTypedefBuiltInBase`](crate::program::model::data::pointer_typedef::PointerTypedefBuiltInBase),
//! with every [`DataType`]/[`TypeDef`] method either overridden to match the Java class's own
//! overrides (`getDescription`, `getMnemonic`, `getTypeDefSettingsDefinitions`/
//! `getSettingsDefinitions` narrowed to just the pointer-type setting) or delegated straight
//! through to the embedded base.
//!
//! `getBuiltInSettingsDefinitions()` (a `BuiltInDataType`-specific method, narrowing the exposed
//! settings to just `[PointerTypeSettingsDefinition.DEF]` rather than the wrapped `Pointer`'s full
//! 5-definition set) has no direct counterpart here since [`PointerTypedefBuiltInBase`] does not
//! implement `BuiltInDataType` (see that struct's module docs). This port instead applies the
//! same narrowing directly to [`DataType::get_type_def_settings_definitions`]/
//! [`DataType::get_settings_definitions`], which is what actually determines
//! [`TypedefDataType::generate_typedef_name`](crate::program::model::data::typedef_data_type::TypedefDataType::generate_typedef_name)'s
//! auto-name attribute list and typedef-settings equivalence checks -- the behaviors the Java
//! narrowing exists to control.
//!
//! `ClassTranslator.put(...)` legacy-class-name registrations and ClassSearcher-based
//! `BuiltInDataTypeManager` discovery of the `dataType` singleton are both dropped, matching this
//! crate's established precedent for every other `BuiltIn` leaf datatype (see e.g.
//! [`Pointer64DataType`](crate::program::model::data::pointer64_data_type)'s own module docs).
//! `clone(DataTypeManager)`'s `dataMgr == dtm` short-circuit is dropped for the same reason
//! [`PointerTypedef::clone_typedef`](crate::program::model::data::pointer_typedef::PointerTypedef::clone_typedef)
//! drops it (no `dataMgr` identity is tracked); [`IBO32DataType::clone_typedef`] always
//! constructs fresh.

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::pointer_type::ImageBaseRelativePointerType;
use crate::program::model::data::pointer_type_settings_definition::PointerTypeSettingsDefinition;
use crate::program::model::data::pointer_typedef::{PointerTypedef, PointerTypedefBuiltInBase};
use crate::program::model::data::typedef::TypeDef;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;
use crate::program::model::mem::MemBuffer;
use crate::util::UniversalID;

/// Zero-sized marker used purely to call the defaulted trait methods of [`DataTypeUtilities`]
/// (a `&dyn Trait`-object seam -- see its own module docs). Mirrors the identical marker in
/// `typedef_data_type.rs`/`pointer_typedef.rs`.
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataTypeUtilities for Utils {}

/// Fixed pointer length (in bytes) for an [`IBO32DataType`].
pub const IBO32_LENGTH: i32 = 4;

/// Fixed name used by every [`IBO32DataType`] instance, standing in for the Java `NAME` constant.
pub const IBO32_NAME: &str = "ImageBaseOffset32";

/// 32-bit Image Base Offset Relative Pointer-Typedef.
///
/// Port of `ghidra.program.model.data.IBO32DataType`. See the module-level documentation for what
/// was collapsed or dropped.
pub struct IBO32DataType {
    base: PointerTypedefBuiltInBase,
}

impl IBO32DataType {
    /// Constructs a 32-bit Image Base Offset relative pointer-typedef.
    pub fn new() -> Self {
        let base = PointerTypedefBuiltInBase::new(Some(IBO32_NAME), None, IBO32_LENGTH)
            .expect("IBO32DataType's fixed construction arguments are always valid");
        let mut ibo = IBO32DataType { base };
        let mut settings = DataType::get_default_settings(&ibo.base);
        PointerTypeSettingsDefinition::DEF.set_type(settings.as_mut(), &ImageBaseRelativePointerType);
        // Settings are backed by a shared store (see TypedefDataType's module docs), so the write
        // above through `settings` is already visible through `ibo.base` -- this silences an
        // otherwise-unused-mut warning on `ibo` without implying anything more happened here.
        let _ = &mut ibo;
        ibo
    }

    /// Port of `IBO32DataType.clone(DataTypeManager)`, always constructing fresh -- see the
    /// module docs on why the `dataMgr == dtm` short-circuit is dropped.
    pub fn clone_typedef(&self) -> IBO32DataType {
        IBO32DataType::new()
    }

    /// Create an IBO32 [`PointerTypedef`] with auto-naming. If needed, a name and category may be
    /// assigned to the returned instance. Unlike an immutable [`IBO32DataType`] instance, the
    /// returned instance is mutable.
    ///
    /// Port of the static `IBO32DataType.createIBO32PointerTypedef(DataType)`.
    pub fn create_ibo32_pointer_typedef(referenced_data_type: Option<Box<dyn DataType>>) -> PointerTypedef {
        PointerTypedef::new_with_type(None, referenced_data_type, IBO32_LENGTH, &ImageBaseRelativePointerType)
            .expect("IBO32's fixed construction arguments are always valid")
    }
}

impl Default for IBO32DataType {
    fn default() -> Self {
        Self::new()
    }
}

impl DataType for IBO32DataType {
    fn get_name(&self) -> String {
        DataType::get_name(&self.base)
    }

    fn get_category_path(&self) -> CategoryPath {
        self.base.get_category_path()
    }

    fn get_universal_id(&self) -> UniversalID {
        self.base.get_universal_id()
    }

    fn get_description(&self) -> String {
        "32-bit Image Base Offset Relative Pointer-Typedef".to_string()
    }

    fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
        "ibo32".to_string()
    }

    fn has_language_dependant_length(&self) -> bool {
        self.base.has_language_dependant_length()
    }

    fn get_length(&self) -> i32 {
        self.base.get_length()
    }

    fn get_aligned_length(&self) -> i32 {
        self.base.get_aligned_length()
    }

    /// Narrowed to just the pointer-type setting, matching `IBO32DataType.getBuiltInSettingsDefinitions()`
    /// -- see the module docs.
    fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        vec![Box::new(PointerTypeSettingsDefinition::DEF)]
    }

    /// Narrowed to just the pointer-type setting, matching `IBO32DataType.getBuiltInSettingsDefinitions()`
    /// -- see the module docs.
    fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        vec![Box::new(PointerTypeSettingsDefinition::DEF)]
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        DataType::get_default_settings(&self.base)
    }

    fn get_value_class(&self, settings: &dyn Settings) -> Option<std::any::TypeId> {
        self.base.get_value_class(settings)
    }

    fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn std::any::Any>> {
        self.base.get_value(buf, settings, length)
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        self.base.get_representation(buf, settings, length)
    }

    /// NOTE: reimplemented directly (rather than delegated to `self.base.is_equivalent(dt)`)
    /// because `has_same_type_def_settings` must compare the *narrowed* (1-definition)
    /// `get_settings_definitions()` this override provides on both sides of the comparison;
    /// delegating to `self.base` would compare the base's un-narrowed 5-definition view against
    /// `dt`'s narrowed view, an asymmetry that made every two `IBO32DataType`s spuriously compare
    /// unequal.
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

impl TypeDef for IBO32DataType {
    fn is_auto_named(&self) -> bool {
        self.base.is_auto_named()
    }

    fn enable_auto_naming(&mut self) {
        self.base.enable_auto_naming();
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        TypeDef::get_data_type(&self.base)
    }

    fn get_base_data_type(&self) -> Box<dyn DataType> {
        TypeDef::get_base_data_type(&self.base)
    }
}

impl std::fmt::Display for IBO32DataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IBO32DataType: typedef {} {}",
            DataType::get_name(self),
            TypeDef::get_data_type(self).get_name()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::pointer_type::PointerType;

    #[test]
    fn new_has_fixed_name_and_length() {
        let ibo = IBO32DataType::new();
        assert_eq!(DataType::get_name(&ibo), IBO32_NAME);
        assert_eq!(ibo.get_length(), IBO32_LENGTH);
        assert_eq!(DataType::get_description(&ibo), "32-bit Image Base Offset Relative Pointer-Typedef");
    }

    #[test]
    fn pointer_type_setting_is_image_base_relative() {
        let ibo = IBO32DataType::new();
        let settings = DataType::get_default_settings(&ibo);
        assert_eq!(
            PointerTypeSettingsDefinition::DEF.get_type(Some(settings.as_ref())).value(),
            ImageBaseRelativePointerType.value()
        );
    }

    #[test]
    fn settings_definitions_narrowed_to_pointer_type_only() {
        let ibo = IBO32DataType::new();
        assert_eq!(DataType::get_type_def_settings_definitions(&ibo).len(), 1);
        assert_eq!(DataType::get_settings_definitions(&ibo).len(), 1);
    }

    #[test]
    fn no_referenced_data_type() {
        let ibo = IBO32DataType::new();
        assert!(ibo.base.get_referenced_data_type().is_none());
    }

    #[test]
    fn create_ibo32_pointer_typedef_wraps_referenced_type() {
        struct Leaf;
        impl DataType for Leaf {
            fn get_name(&self) -> String {
                "Foo".to_string()
            }
        }
        let td = IBO32DataType::create_ibo32_pointer_typedef(Some(Box::new(Leaf)));
        assert_eq!(td.get_referenced_data_type().unwrap().get_name(), "Foo");
        assert_eq!(td.get_length(), IBO32_LENGTH);
        let settings = DataType::get_default_settings(&td);
        assert_eq!(
            PointerTypeSettingsDefinition::DEF.get_type(Some(settings.as_ref())).value(),
            ImageBaseRelativePointerType.value()
        );
    }

    #[test]
    fn clone_typedef_produces_equivalent_instance() {
        let a = IBO32DataType::new();
        let b = a.clone_typedef();
        assert!(DataType::is_equivalent(&a, &b));
    }
}
