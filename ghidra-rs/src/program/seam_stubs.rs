//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.program.model.data.DataTypeManager`, referenced by
/// [`FileBasedDataTypeManager`](crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager)
/// before the real interface is ported.
pub trait DataTypeManager {}

/// Placeholder for `ghidra.program.model.data.DataTypePath`, referenced by
/// [`DataType`](crate::program::model::data::data_type::DataType)
/// before the real class is ported. The real class is a simple `(CategoryPath, String)` value
/// holder, but `DataType` never calls methods on the path it returns, so no members are needed
/// yet.
pub trait DataTypePath {}

/// Placeholder for `ghidra.framework.model.DomainObject`, referenced by
/// [`DataTypeManagerDomainObject`](crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject)
/// before the real interface is ported.
pub trait DomainObject {}

/// Placeholder for `ghidra.app.merge.DataTypeManagerOwner`, referenced by
/// [`DataTypeManagerDomainObject`](crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject)
/// before the real interface is ported.
pub trait DataTypeManagerOwner {
    /// Gets the associated data type manager.
    fn get_data_type_manager(&self) -> Box<dyn DataTypeManager>;
}

/// Placeholder for `ghidra.framework.model.DomainFile`, referenced by
/// [`DomainFileBasedDataTypeManager`](crate::program::model::data::domain_file_based_data_type_manager::DomainFileBasedDataTypeManager)
/// before the real interface is ported.
pub trait DomainFile {}

/// Placeholder for `ghidra.program.model.data.Structure`, referenced by
/// [`StructureInternal`](crate::program::model::data::structure_internal::StructureInternal)
/// before the real interface is ported.
pub trait Structure {}

/// Placeholder for `ghidra.program.model.data.CompositeInternal`, referenced by
/// [`StructureInternal`](crate::program::model::data::structure_internal::StructureInternal)
/// before the real interface is ported.
pub trait CompositeInternal {}

/// Placeholder for `ghidra.program.model.listing.BookmarkType`, referenced by
/// [`Bookmark`](crate::program::model::listing::bookmark::Bookmark)
/// before the real interface is ported.
pub trait BookmarkType {}

/// Placeholder for `ghidra.program.model.listing.Variable`, referenced by
/// [`Parameter`](crate::program::model::listing::parameter::Parameter)
/// before the real interface is ported.
pub trait Variable {}

/// Placeholder for `ghidra.program.model.data.DataTypeConflictHandler`, referenced by
/// [`Category`](crate::program::model::data::category::Category)
/// before the real class is ported.
pub trait DataTypeConflictHandler {}

/// Placeholder for `ghidra.docking.settings.Settings`, referenced by
/// [`Enum`](crate::program::model::data::enum_::Enum)
/// before the real interface is ported.
pub trait Settings {}

/// Placeholder for `ghidra.docking.settings.SettingsDefinition`, referenced by
/// [`TypeDefSettingsDefinition`](crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition)
/// and [`TypeDef`](crate::program::model::data::typedef::TypeDef) before the real interface is
/// ported.
pub trait SettingsDefinition {
    /// Stands in for `getClass().equals(other.getClass())`, used by
    /// [`TypeDef::has_same_type_def_settings`](crate::program::model::data::typedef::TypeDef::has_same_type_def_settings)
    /// to confirm two settings-definition arrays declare definitions of the same kind in the
    /// same order.
    fn is_same_kind(&self, other: &dyn SettingsDefinition) -> bool {
        let _ = other;
        false
    }
    /// Stands in for `instanceof TypeDefSettingsDefinition`.
    fn is_type_def_settings_definition(&self) -> bool {
        false
    }
    /// Determine if this and another settings definition, when read from the given settings
    /// objects, currently hold the same value. Real abstract method on
    /// `ghidra.docking.settings.SettingsDefinition`.
    fn has_same_value(&self, settings1: &dyn Settings, settings2: &dyn Settings) -> bool {
        let (_, _) = (settings1, settings2);
        false
    }
}

/// Placeholder for `ghidra.program.model.data.PointerTypedefBuilder`, referenced by
/// [`Pointer`](crate::program::model::data::pointer::Pointer)
/// before the real class is ported.
pub trait PointerTypedefBuilder {}

/// Placeholder for `ghidra.program.model.data.Composite`, referenced by
/// [`AnnotationHandler`](crate::program::model::data::annotation_handler::AnnotationHandler)
/// before the real interface is ported.
pub trait Composite {}

/// Placeholder for `ghidra.program.model.mem.MemBuffer`, referenced by
/// [`DataTypeWithCharset`](crate::program::model::data::data_type_with_charset::DataTypeWithCharset)
/// and [`ArrayStringable`](crate::program::model::data::array_stringable::ArrayStringable)
/// before the real interface is ported.
pub trait MemBuffer {
    /// Stands in for `MemBuffer.isInitializedMemory()`.
    fn is_initialized_memory(&self) -> bool {
        false
    }
}

/// Placeholder for `ghidra.program.model.data.StringDataInstance`, referenced by
/// [`DataTypeWithCharset`](crate::program::model::data::data_type_with_charset::DataTypeWithCharset)
/// and [`ArrayStringable`](crate::program::model::data::array_stringable::ArrayStringable)
/// before the real class is ported.
///
/// Models just the instance methods that `DataTypeWithCharset`'s and `ArrayStringable`'s default
/// methods delegate to once a `StringDataInstance` has been built for a given data
/// type/settings/buffer/length.
pub trait StringDataInstance {
    /// Encode a normalized character value (one code point, as one or two UTF-16 style chars)
    /// as replacement bytes.
    fn encode_replacement_from_char_value(&self, value: &[char]) -> Result<Vec<u8>, String>;

    /// Encode a single-character string representation as replacement bytes.
    fn encode_replacement_from_char_representation(&self, repr: &str) -> Result<Vec<u8>, String>;

    /// Stands in for `StringDataInstance.getStringValue()`.
    fn get_string_value(&self) -> Option<String> {
        None
    }
}

/// Placeholder for `ghidra.program.model.data.StringDataInstance.DEFAULT_CHARSET_NAME`.
pub const DEFAULT_CHARSET_NAME: &str = "US-ASCII";

/// Placeholder for `ghidra.program.model.listing.CodeUnit`, referenced by
/// [`Data`](crate::program::model::listing::data::Data) as a supertrait before the real
/// interface is ported.
pub trait CodeUnit {}

/// Placeholder for `ghidra.program.model.symbol.RefType`, referenced by
/// [`Data`](crate::program::model::listing::data::Data)
/// before the real class is ported.
pub trait RefType {}

/// Placeholder for `ghidra.program.model.symbol.Reference`, referenced by
/// [`Data`](crate::program::model::listing::data::Data)
/// before the real interface is ported.
pub trait Reference {}
