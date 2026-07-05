//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.program.model.data.DataTypeManager`, referenced by
/// [`FileBasedDataTypeManager`](crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager)
/// before the real interface is ported.
pub trait DataTypeManager {}

/// Placeholder for `ghidra.program.model.data.DataType`, referenced by
/// [`DataOrganization`](crate::program::model::data::data_organization::DataOrganization)
/// and [`DataTypeWithCharset`](crate::program::model::data::data_type_with_charset::DataTypeWithCharset)
/// before the real interface is ported.
pub trait DataType {
    /// Get the length of this DataType as a number of 8-bit bytes.
    fn get_length(&self) -> i32 {
        0
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
/// [`DomainFileBasedDataTypeManager`](crate::program::seam_stubs::DomainFileBasedDataTypeManager)
/// before the real interface is ported.
pub trait DomainFile {}

/// Placeholder for `ghidra.program.model.data.DomainFileBasedDataTypeManager`, referenced by
/// [`ProjectArchiveBasedDataTypeManager`](crate::program::model::data::project_archive_based_data_type_manager::ProjectArchiveBasedDataTypeManager)
/// before the real interface is ported.
pub trait DomainFileBasedDataTypeManager:
    crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager
{
    /// Gets the domain file backing this data type manager.
    fn get_domain_file(&self) -> Box<dyn DomainFile>;
}

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

/// Placeholder for `ghidra.program.model.data.CategoryPath`, referenced by
/// [`Category`](crate::program::model::data::category::Category)
/// before the real class is ported.
pub trait CategoryPath {}

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

/// Placeholder for `ghidra.program.model.data.DataTypeComponent`, referenced by
/// [`AnnotationHandler`](crate::program::model::data::annotation_handler::AnnotationHandler)
/// and [`InternalDataTypeComponent`](crate::program::model::data::internal_data_type_component::InternalDataTypeComponent)
/// before the real interface is ported.
///
/// The accessors below give `InternalDataTypeComponent`'s `to_string` helper enough to
/// reproduce the Java interface's static `toString(DataTypeComponent)`. `bit_field_bit_offset`
/// stands in for that code's `((BitFieldDataType) c.getDataType()).getBitOffset()` cast, since
/// `BitFieldDataType` is not yet ported; callers should only trust its value when
/// `is_bit_field_component()` is `true`. All methods default so existing implementations of
/// this trait keep compiling as the stub grows.
pub trait DataTypeComponent {
    /// Ordinal position of this component within its parent.
    fn get_ordinal(&self) -> i32 {
        0
    }
    /// Byte offset of this component within its parent.
    fn get_offset(&self) -> i32 {
        0
    }
    /// Byte length of this component.
    fn get_length(&self) -> i32 {
        0
    }
    /// Name of this component's data type.
    fn get_data_type_name(&self) -> String {
        String::new()
    }
    /// Whether this component represents a bit field.
    fn is_bit_field_component(&self) -> bool {
        false
    }
    /// Bit offset within the containing byte(s); only meaningful when
    /// `is_bit_field_component()` is `true`.
    fn bit_field_bit_offset(&self) -> i32 {
        0
    }
    /// This component's field name, or `None` to indicate the default field name is used.
    fn get_field_name(&self) -> Option<String> {
        None
    }
    /// This component's comment, if any.
    fn get_comment(&self) -> Option<String> {
        None
    }
}

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
