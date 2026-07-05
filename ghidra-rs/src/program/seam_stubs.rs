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
/// before the real interface is ported.
pub trait DataType {}

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

/// Placeholder for `ghidra.docking.settings.Settings`, referenced by
/// [`Enum`](crate::program::model::data::enum_::Enum)
/// before the real interface is ported.
pub trait Settings {}

/// Placeholder for `ghidra.program.model.data.PointerTypedefBuilder`, referenced by
/// [`Pointer`](crate::program::model::data::pointer::Pointer)
/// before the real class is ported.
pub trait PointerTypedefBuilder {}
