//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.program.model.data.DataTypeManager`, referenced by
/// [`FileBasedDataTypeManager`](crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager)
/// before the real interface is ported.
pub trait DataTypeManager {}

/// Placeholder for `ghidra.program.model.data.DataType`, referenced by
/// [`DataOrganization`](crate::program::model::data::data_organization::DataOrganization),
/// [`DataTypeWithCharset`](crate::program::model::data::data_type_with_charset::DataTypeWithCharset),
/// and [`DataTypeComponent`](crate::program::model::data::data_type_component::DataTypeComponent)
/// before the real interface is ported.
///
/// The `is_structure`/`is_typedef`/`is_array` predicates and `typedef_base_data_type` stand in
/// for `DataTypeComponent`'s `instanceof Structure`/`instanceof TypeDef`/`instanceof Array`
/// checks and `TypeDef.getBaseDataType()` cast, since Rust trait objects cannot be downcast to
/// another trait object without extra machinery. `typedef_base_data_type` is only meaningful
/// when `is_typedef()` is `true`. All methods default so existing implementations of this trait
/// keep compiling as the stub grows.
pub trait DataType {
    /// Get the length of this DataType as a number of 8-bit bytes.
    fn get_length(&self) -> i32 {
        0
    }
    /// Whether this dataType is (or wraps) a zero-length component (e.g. a zero-element array).
    fn is_zero_length(&self) -> bool {
        false
    }
    /// Whether this dataType has not yet had its internal composition specified.
    fn is_not_yet_defined(&self) -> bool {
        false
    }
    /// Stands in for `instanceof Structure`.
    fn is_structure(&self) -> bool {
        false
    }
    /// Stands in for `instanceof TypeDef`.
    fn is_typedef(&self) -> bool {
        false
    }
    /// Stands in for `((TypeDef) dataType).getBaseDataType()`; only meaningful when
    /// `is_typedef()` is `true`.
    fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
        None
    }
    /// Stands in for `instanceof Array`.
    fn is_array(&self) -> bool {
        false
    }
}

/// Placeholder for `ghidra.program.model.data.BuiltInDataType`, referenced by
/// [`FactoryDataType`](crate::program::model::data::factory_data_type::FactoryDataType)
/// before the real interface is ported.
pub trait BuiltInDataType: DataType {}

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

/// Placeholder for `ghidra.program.model.data.Union`, referenced by
/// [`UnionInternal`](crate::program::model::data::union_internal::UnionInternal)
/// before the real interface is ported.
pub trait Union {}

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
/// before the real interface is ported.
pub trait SettingsDefinition {}

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
/// before the real interface is ported.
pub trait MemBuffer {}

/// Placeholder for `ghidra.program.model.data.StringDataInstance`, referenced by
/// [`DataTypeWithCharset`](crate::program::model::data::data_type_with_charset::DataTypeWithCharset)
/// before the real class is ported.
///
/// Models just the two instance methods that `DataTypeWithCharset`'s default methods delegate
/// to once a `StringDataInstance` has been built for a given data type/settings/buffer/length.
pub trait StringDataInstance {
    /// Encode a normalized character value (one code point, as one or two UTF-16 style chars)
    /// as replacement bytes.
    fn encode_replacement_from_char_value(&self, value: &[char]) -> Result<Vec<u8>, String>;

    /// Encode a single-character string representation as replacement bytes.
    fn encode_replacement_from_char_representation(&self, repr: &str) -> Result<Vec<u8>, String>;
}

/// Placeholder for `ghidra.program.model.data.StringDataInstance.DEFAULT_CHARSET_NAME`.
pub const DEFAULT_CHARSET_NAME: &str = "US-ASCII";
