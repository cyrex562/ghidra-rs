//! The callback surface a concrete, database-backed [`Category`] needs from the (not yet ported)
//! `DataTypeManagerDB` that owns it.
//!
//! This trait has no single Java counterpart: it is the seam that makes a concrete
//! [`CategoryDb`](super::category_db::CategoryDb) portable at all, following the same pattern
//! already used to cut two other construction cycles in this crate --
//! [`CodeUnitOwner`](crate::program::database::code::code_unit_owner::CodeUnitOwner) for
//! `CodeUnitDB`, and [`ModuleManager`](crate::program::database::module::module_manager::ModuleManager)
//! for `ModuleDB`/`FragmentDB`.
//!
//! In Java, `CategoryDB` holds a `DataTypeManagerDB mgr` field and reaches back through it for
//! everything it cannot answer from its own fields: the category record adapter
//! (`mgr.getCategoryDBAdapter()`), category-scoped datatype listing
//! (`mgr.getDataTypesInCategory(long)`), conflict-name generation
//! (`mgr.getUnusedConflictName(CategoryPath, DataType)`), the category mutation notifications
//! (`mgr.categoryCreated`/`categoryRenamed`/`categoryRemoved`/`categoryMoved`), and error
//! reporting (`mgr.dbError`). `DataTypeManagerDB` itself `implements DataTypeManager`, and
//! [`Category::get_data_type_manager`](crate::program::model::data::category::Category::get_data_type_manager)
//! must be able to hand back a `DataTypeManager` view of the owning manager, so this trait is
//! bounded by the already-ported [`DataTypeManager`] rather than re-declaring its methods.
//! `resolve`, `remove`, `remove_all`, `replace_data_type`, `get_name`, `set_name`,
//! `get_category(id)`, and `create_category(path)` are all reused as-is from that supertrait;
//! what follows is only the genuinely new surface `CategoryDB` calls that has no
//! [`DataTypeManager`] equivalent.
//!
//! # Why this exposes a full adapter rather than named operations
//!
//! [`CodeUnitOwner`] deliberately hides `CommentsDBAdapter` behind three named record operations
//! because `CodeUnitDB` only ever performs three specific, already-wrapped operations against it.
//! [`CategoryDBAdapter`] is different: it was already ported in full (`get_record`,
//! `update_record`, `get_record_ids_with_parent`, `create_category`, `remove_category`,
//! `get_root_record`, `put_record`, `get_record_count`) as a general-purpose adapter trait, and
//! [`CategoryDb`](super::category_db::CategoryDb) needs the majority of that surface directly.
//! Exposing it via [`get_category_adapter`](CategoryOwner::get_category_adapter) instead mirrors
//! how [`ModuleManager`] exposes its own `get_module_adapter`/`get_fragment_adapter`/
//! `get_parent_child_adapter` accessors, which is the closer structural precedent for this port
//! (see [`category_db`](super::category_db)'s module docs for why).
//!
//! [`CategoryDb`]: super::category_db::CategoryDb
//! [`CodeUnitOwner`]: crate::program::database::code::code_unit_owner::CodeUnitOwner
//! [`ModuleManager`]: crate::program::database::module::module_manager::ModuleManager

use std::io;

use crate::program::database::data::category_db_adapter::CategoryDBAdapter;
use crate::program::model::data::category::Category;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// The set of `DataTypeManagerDB` callbacks a concrete, database-backed [`Category`] depends on.
///
/// See the module documentation for why this is separate from (but bounded by) the public
/// [`DataTypeManager`] trait.
pub trait CategoryOwner: DataTypeManager {
    /// Exposes this manager's category record adapter. Stands in for the package-private
    /// `DataTypeManagerDB.getCategoryDBAdapter()`.
    fn get_category_adapter(&mut self) -> &mut dyn CategoryDBAdapter;

    /// Gets the datatypes stored directly in the category identified by `category_id`. Stands in
    /// for the package-private `DataTypeManagerDB.getDataTypesInCategory(long)` -- distinct from
    /// the already-ported
    /// [`DataTypeManagerDb::get_data_types_in_category`](super::data_type_manager_db::DataTypeManagerDb::get_data_types_in_category),
    /// which ports the different, `CategoryPath`-keyed `getDataTypes(CategoryPath)` overload.
    fn get_data_types_for_category_id(&self, category_id: i64) -> Vec<Box<dyn DataType>>;

    /// Gets a `.conflict` name not currently used by any datatype in the category at `path`.
    /// Stands in for `DataTypeManagerDB.getUnusedConflictName(CategoryPath, DataType)`.
    fn get_unused_conflict_name_in_category(&self, path: &CategoryPath, dt: &dyn DataType) -> String;

    /// Notifies the manager that `category` was just created. Stands in for
    /// `DataTypeManagerDB.categoryCreated(Category)`.
    fn category_created(&mut self, category: &dyn Category);

    /// Notifies the manager that `category` was just renamed from `old_path`. Stands in for
    /// `DataTypeManagerDB.categoryRenamed(CategoryPath, Category)`.
    fn category_renamed(&mut self, old_path: CategoryPath, category: &dyn Category);

    /// Notifies the manager that the category named `name` (with id `category_id`) was just
    /// removed from `parent`. Stands in for `DataTypeManagerDB.categoryRemoved(Category, String,
    /// long)`.
    fn category_removed(&mut self, parent: &dyn Category, name: &str, category_id: i64);

    /// Notifies the manager that `category` was just moved from `old_path`. Stands in for
    /// `DataTypeManagerDB.categoryMoved(CategoryPath, Category)`.
    fn category_moved(&mut self, old_path: CategoryPath, category: &dyn Category);

    /// Reports a database failure. Stands in for `DataTypeManagerDB.dbError(IOException)`.
    fn db_error(&self, error: io::Error);
}
