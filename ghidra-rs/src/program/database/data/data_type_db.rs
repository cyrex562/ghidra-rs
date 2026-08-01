//! Port of `ghidra.program.database.data.DataTypeDB`, promoted to a trait because it was selected
//! as a dependency-cycle cut-point.
//!
//! The Java class is an `abstract` base (`DataTypeDB extends DbObject implements DataType`)
//! shared by every DB-backed datatype implementation (`ArrayDB`, `StructureDB`, `EnumDB`,
//! `PointerDB`, `FunctionDefinitionDB`, `TypedefDB`, ...). Four of those subclasses
//! ([`ArrayDb`](super::array_db::ArrayDb), [`PointerDb`](super::pointer_db::PointerDb),
//! [`StructureDb`](super::structure_db::StructureDb),
//! [`FunctionDefinitionDb`](super::function_definition_db::FunctionDefinitionDb)) were already
//! ported as standalone traits that bypass `DataTypeDB` entirely (each extends only its own
//! public interface, e.g. `Array`/`Pointer`); this trait now supplies the actual `DataTypeDB`
//! contract those subclasses inherit from in Java, for future implementors to compose with them
//! (e.g. `trait StructureDb: Structure + DataTypeDb`).
//!
//! `DataTypeDB extends DbObject`, and [`DbObject`] is already a real ported trait (not a
//! placeholder), so this trait is bounded by both it and [`DataType`] rather than re-declaring
//! their methods. `DbObject`'s abstract `refresh(DBRecord)` is inherited unchanged -- each
//! concrete subtype (as already established by `ArrayDb::refresh`, `PointerDb::refresh`, etc.)
//! supplies its own record-driven resync logic.
//!
//! What *is* declared here:
//!   - The genuinely abstract extension points a concrete subclass must implement:
//!     [`do_get_name`](Self::do_get_name), [`do_get_category_id`](Self::do_get_category_id),
//!     [`do_set_category_path_record`](Self::do_set_category_path_record),
//!     [`do_set_name_record`](Self::do_set_name_record),
//!     [`get_source_archive_id`](Self::get_source_archive_id),
//!     [`set_source_archive_id`](Self::set_source_archive_id),
//!     [`is_equivalent_with_handler`](Self::is_equivalent_with_handler) (the abstract
//!     `isEquivalent(DataType, DataTypeConflictHandler)`), and the package-private
//!     [`set_universal_id`](Self::set_universal_id).
//!   - [`owning_data_type_manager`](Self::owning_data_type_manager), standing in for the final
//!     `getDataTypeManager()`/the `dataMgr` field, mirroring the same-purpose method already
//!     established by [`ArrayDb::owning_data_type_manager`](super::array_db::ArrayDb::owning_data_type_manager).
//!   - [`lock`](Self::lock), standing in for the shared `lock` field (`dataMgr.lock`), needed to
//!     reproduce the `try (Closeable c = lock.read()/.write())` pattern used throughout.
//!   - `stored_name`/`set_stored_name` and `stored_category_path`/`set_stored_category_path`,
//!     backing storage for the `volatile` `name`/`category` cache fields -- mirroring
//!     [`DataTypeImpl`](crate::program::model::data::data_type_impl::DataTypeImpl)'s
//!     `stored_*`/`set_stored_*` accessor convention. Both take `&self` (interior mutability is
//!     left to the implementor, e.g. via `Mutex`), matching how the Java fields are mutated
//!     without synchronization beyond the `lock`/`volatile` pair.
//!   - `stored_deleting`/`set_stored_deleting`, backing storage for the `deleting` field read/set
//!     by [`data_type_db_delete_started`](Self::data_type_db_delete_started).
//!   - Default wrapper methods for the non-trivial *concrete* behavior built on top of those
//!     hooks (the caching `getName()`/`getCategoryPath()`, `setName(String)`,
//!     `getDataTypePath()`, `refreshName()`, `getOldName()`, `getAlignment()`, `checkValidName`,
//!     `isDeleted()`, `completeRefresh()`, `deleteStarted()`, `postPointerResolve`,
//!     `hashCode()`/`equals(Object)`), exposed under a `data_type_db_*` naming convention (per
//!     [`DataTypeImpl`](crate::program::model::data::data_type_impl::DataTypeImpl)'s established
//!     precedent) since several share a name with an already-provided [`DataType`] default and
//!     Rust does not allow a subtrait to override a supertrait's same-named default without an
//!     ambiguous call site. A concrete `impl DataType for ...` should delegate to these.
//!
//! `setCategoryPath`/`setNameAndCategory` are intentionally **not** ported: both need to create a
//! category on-demand (`dataMgr.createCategory(path)`), which requires a `&mut` call against the
//! owning manager. [`owning_data_type_manager`](Self::owning_data_type_manager) hands back a
//! shared `Arc<dyn DataTypeManagerDb>` (mirroring `ArrayDb`'s established convention, since many
//! datatypes share one manager), from which a `&mut` call cannot be made without an
//! interior-mutability convention on the manager side that no trait in this crate currently
//! adopts. That decision belongs to whichever concrete manager first needs it, not to this
//! cycle-breaking port; `setName` avoids the problem since its only manager call
//! (`getDataType(CategoryPath, String)`, mirrored here as
//! [`DataTypeManager::get_data_type_in_category`]) is a read.
//!
//! The `resolve(DataType)`/`postPointerResolve` pair's `resolving` flag and the
//! `notifySizeChanged`/`notifyAlignmentChanged`/`notifyNameChanged`/`notifyDeleted` family are
//! also omitted: each needs `dataMgr.getDependencyConflictHandler()` or
//! `dataMgr.getParentDataTypes(key)`/`dataMgr.dataTypeChanged(...)`, none of which exist yet on
//! [`DataTypeManager`]/[`DataTypeManagerDb`]. [`data_type_db_post_pointer_resolve`](Self::data_type_db_post_pointer_resolve)
//! is kept since its default behavior (an unconditional error) needs no such surface.
//!
//! `doGetDefaultSettings`/`getDefaultSettings`'s caching wrapper is also omitted: the Java method
//! constructs a `new DataTypeSettingsDB(dataMgr, this, key)`, a whole not-yet-ported DB-backed
//! settings-storage class, so there is no faithful behavior to give a default here yet; concrete
//! implementors fall back to [`DataType::get_default_settings`]'s existing placeholder default
//! until `DataTypeSettingsDB` is ported.

use std::io;
use std::sync::Arc;

use thiserror::Error;

use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::database::db_object::DbObject;
use crate::program::model::data::category::Category;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_type::{DataType, UnsupportedOperationError};
use crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_path::DataTypePath;
use crate::program::model::data::data_utilities::DataUtilities;
use crate::util::exception::{DuplicateNameException, InvalidNameException};
use crate::util::lock::Lock;
use crate::util::UniversalID;

/// Error produced by [`DataTypeDb::do_set_name_record`], combining the two checked exceptions
/// declared on the abstract Java method `DataTypeDB.doSetNameRecord(String)`.
#[derive(Error, Debug)]
pub enum DoSetNameRecordError {
    #[error("IOException: {0}")]
    Io(String),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// Error produced by [`DataTypeDb::data_type_db_set_name`], combining the outcomes of
/// `DataTypeDB.setName(String)`/the private `doSetName(String)` it delegates to: the duplicate
/// check thrown by `setName`, the invalid-name/IO failures thrown by `doSetName`, and the
/// `checkDeleted()` guard both share (mirrored by [`DbObject::check_deleted`]'s `String` error).
#[derive(Error, Debug)]
pub enum SetNameError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
    #[error("IOException: {0}")]
    Io(String),
    #[error("{0}")]
    Deleted(String),
}

impl From<DoSetNameRecordError> for SetNameError {
    fn from(e: DoSetNameRecordError) -> Self {
        match e {
            DoSetNameRecordError::Io(s) => SetNameError::Io(s),
            DoSetNameRecordError::InvalidName(e) => SetNameError::InvalidName(e),
        }
    }
}

/// Base for data types that are database objects.
///
/// Port of `ghidra.program.database.data.DataTypeDB`. See the module-level documentation for what
/// was ported, defaulted, and intentionally omitted.
pub trait DataTypeDb: DataType + DbObject {
    /// Returns the database-backed manager that owns this datatype's record. Stands in for the
    /// final `DataTypeDB.getDataTypeManager()`/the `dataMgr` field.
    fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb>;

    /// The lock shared with this datatype's owning manager (`dataMgr.lock` in Java), guarding the
    /// cached `name`/`category` fields against concurrent refresh.
    fn lock(&self) -> &Lock<()>;

    /// Backing storage for the `volatile` `name` field.
    fn stored_name(&self) -> Option<String>;

    /// Mutator for the `volatile` `name` field's backing storage.
    fn set_stored_name(&self, name: Option<String>);

    /// Backing storage for the `volatile` `category` field, narrowed to the one thing it's ever
    /// read for (`category.getCategoryPath()`).
    fn stored_category_path(&self) -> Option<CategoryPath>;

    /// Mutator for the `volatile` `category` field's backing storage.
    fn set_stored_category_path(&self, path: Option<CategoryPath>);

    /// Backing storage for the `deleting` field.
    fn stored_deleting(&self) -> bool;

    /// Mutator for the `deleting` field's backing storage.
    fn set_stored_deleting(&self, deleting: bool);

    /// Reads the name directly from the database record, or computes it if derived (e.g. a
    /// pointer or array name). Implementors can assume the database lock is held when called.
    /// Stands in for the abstract `DataTypeDB.doGetName()`.
    fn do_get_name(&self) -> String;

    /// Reads the category ID directly from the database record. Implementors can assume the
    /// database lock is held when called. Stands in for the abstract
    /// `DataTypeDB.doGetCategoryID()`.
    fn do_get_category_id(&self) -> i64;

    /// Updates the category path ID in the database record. Implementors can assume the database
    /// lock is held when called. Stands in for the abstract
    /// `DataTypeDB.doSetCategoryPathRecord(long)`.
    ///
    /// Takes `&self` (interior mutability, backed by the implementor's own storage) rather than
    /// `&mut self`: [`data_type_db_set_name`](Self::data_type_db_set_name) needs to call
    /// [`do_set_name_record`](Self::do_set_name_record) while a [`lock`](Self::lock) guard
    /// (itself borrowed from `&self`) is held, which an `&mut self` hook could not coexist with;
    /// this hook is kept `&self` to match for consistency, mirroring the
    /// [`stored_name`](Self::stored_name)/[`set_stored_name`](Self::set_stored_name) convention.
    fn do_set_category_path_record(&self, category_id: i64) -> io::Result<()>;

    /// Updates the name in the database record. Implementors can assume the database lock is
    /// held when called. Stands in for the abstract `DataTypeDB.doSetNameRecord(String)`. See
    /// [`do_set_category_path_record`](Self::do_set_category_path_record) for why this takes
    /// `&self` rather than `&mut self`.
    fn do_set_name_record(&self, new_name: &str) -> Result<(), DoSetNameRecordError>;

    /// Reads the source archive ID from the database record. Stands in for the abstract
    /// `DataTypeDB.getSourceArchiveID()`.
    fn get_source_archive_id(&self) -> UniversalID;

    /// Updates the source archive ID in the database record. Stands in for the abstract
    /// `DataTypeDB.setSourceArchiveID(UniversalID)`. See
    /// [`do_set_category_path_record`](Self::do_set_category_path_record) for why this takes
    /// `&self` rather than `&mut self`.
    fn set_source_archive_id(&self, id: UniversalID);

    /// Performs an equivalence check while resolving `data_type`. If `handler` (under a conflict
    /// situation) indicates the existing datatype (`self`) should be used in place of
    /// `data_type`, this returns `true`. `handler` of `None` should perform a normal
    /// [`DataType::is_equivalent`] check. Stands in for the abstract
    /// `DataTypeDB.isEquivalent(DataType, DataTypeConflictHandler)`.
    fn is_equivalent_with_handler(
        &self,
        data_type: &dyn DataType,
        handler: Option<&dyn DataTypeConflictHandler>,
    ) -> bool;

    /// Changes this datatype's universal ID. Only intended for use when transforming a newly
    /// parsed data type archive so it can replace the archive from a previous software release.
    /// Stands in for the package-private abstract `DataTypeDB.setUniversalID(UniversalID)`. See
    /// [`do_set_category_path_record`](Self::do_set_category_path_record) for why this takes
    /// `&self` rather than `&mut self`.
    fn set_universal_id(&self, old_universal_id: UniversalID);

    /// Clears the cached name so the next [`data_type_db_get_name`](Self::data_type_db_get_name)
    /// forces a re-read via [`do_get_name`](Self::do_get_name). Stands in for
    /// `DataTypeDB.refreshName()`.
    fn data_type_db_refresh_name(&self) {
        self.set_stored_name(None);
    }

    /// Gets the current cached name without refresh, intended for event generation when an
    /// old name is needed. Stands in for `DataTypeDB.getOldName()`.
    fn data_type_db_get_old_name(&self) -> Option<String> {
        self.stored_name()
    }

    /// Port of `DataTypeDB.getName()`. Exposed under a distinct name since [`DataType::get_name`]
    /// already provides a (placeholder) default. A concrete `impl DataType for ...` should
    /// delegate to this.
    fn data_type_db_get_name(&self) -> String {
        if let Some(n) = self.stored_name() {
            if !self.needs_refreshing() {
                return n;
            }
        }
        let _guard = self.lock().read();
        self.refresh_if_needed();
        if self.stored_name().is_none() {
            self.set_stored_name(Some(self.do_get_name()));
        }
        self.stored_name().unwrap_or_default()
    }

    /// Port of `DataTypeDB.getCategoryPath()`. Exposed under a distinct name since
    /// [`DataType::get_category_path`] already provides a (placeholder) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn data_type_db_get_category_path(&self) -> CategoryPath {
        if let Some(p) = self.stored_category_path() {
            if !self.needs_refreshing() {
                return p;
            }
        }
        let _guard = self.lock().read();
        self.refresh_if_needed();
        if self.stored_category_path().is_none() {
            let mgr = self.owning_data_type_manager();
            let cat = mgr
                .get_category(self.do_get_category_id())
                .unwrap_or_else(|| mgr.get_root_category());
            self.set_stored_category_path(Some(cat.get_category_path()));
        }
        self.stored_category_path().unwrap_or_else(|| ROOT.clone())
    }

    /// Port of `DataTypeDB.getDataTypePath()`. Exposed under a distinct name since
    /// [`DataType::get_data_type_path`] already provides a (different) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn data_type_db_get_data_type_path(&self) -> DataTypePath {
        DataTypePath::new(self.data_type_db_get_category_path(), self.data_type_db_get_name())
    }

    /// Validates a candidate new name using `utilities`'s
    /// [`DataUtilities::is_valid_data_type_name`]. Stands in for
    /// `DataTypeDB.checkValidName(String)`, taking a `&dyn DataUtilities` parameter for the same
    /// reason as
    /// [`DataTypeImpl::data_type_impl_check_valid_name`](crate::program::model::data::data_type_impl::DataTypeImpl::data_type_impl_check_valid_name).
    ///
    /// # Errors
    /// Returns [`InvalidNameException`] if `new_name` is not a valid data-type name.
    fn data_type_db_check_valid_name(
        &self,
        new_name: &str,
        utilities: &dyn DataUtilities,
    ) -> Result<(), InvalidNameException> {
        if !utilities.is_valid_data_type_name(new_name) {
            return Err(InvalidNameException(format!("Invalid Name: {new_name}")));
        }
        Ok(())
    }

    /// Port of `DataTypeDB.setName(String)` (merged with the private `doSetName(String)` it
    /// delegates to, since that helper has no other caller here). Exposed under a distinct name
    /// since [`DataType::set_name`] already provides a (no-op) default. A concrete `impl DataType
    /// for ...` should delegate to this.
    ///
    /// `notifyNameChanged(oldName)` is omitted: it needs `dataMgr.getParentDataTypes(key)`/
    /// `dataMgr.dataTypeNameChanged(...)`, which do not exist yet on
    /// [`DataTypeManager`]/[`DataTypeManagerDb`].
    ///
    /// # Errors
    /// Returns [`SetNameError::Deleted`] if this datatype has been deleted,
    /// [`SetNameError::Duplicate`] if `new_name` is already used by another datatype in this
    /// datatype's category, or [`SetNameError::InvalidName`]/[`SetNameError::Io`] if the
    /// underlying record update fails.
    fn data_type_db_set_name(
        &self,
        new_name: &str,
        utilities: &dyn DataUtilities,
    ) -> Result<(), SetNameError> {
        let _guard = self.lock().write();
        DbObject::check_deleted(self).map_err(SetNameError::Deleted)?;
        let old_name = self.data_type_db_get_name();
        if old_name == new_name {
            return Ok(());
        }
        let category_path = self.data_type_db_get_category_path();
        if self
            .owning_data_type_manager()
            .get_data_type_in_category(&category_path, new_name)
            .is_some()
        {
            return Err(SetNameError::Duplicate(DuplicateNameException(format!(
                "DataType named {new_name} already exists in category {}",
                category_path.get_path()
            ))));
        }
        self.data_type_db_check_valid_name(new_name, utilities)?;
        self.do_set_name_record(new_name)?;
        self.set_stored_name(Some(new_name.to_string()));
        Ok(())
    }

    /// Port of `DataTypeDB.getAlignment()`. Exposed under a distinct name since
    /// [`DataType::get_alignment`] already provides a (different) default.
    ///
    /// Requires `Self: Sized`, matching
    /// [`DataTypeImpl::data_type_impl_get_alignment`](crate::program::model::data::data_type_impl::DataTypeImpl::data_type_impl_get_alignment)'s
    /// precedent: this must hand `self` to [`DataOrganization::get_alignment`], whose signature
    /// is fixed to `&dyn DataType`, which requires an unsized coercion only available for a
    /// known-`Sized` source.
    fn data_type_db_get_alignment(&self) -> i32
    where
        Self: Sized,
    {
        let length = self.get_length();
        if length < 0 {
            return 1;
        }
        self.owning_data_type_manager()
            .get_data_organization()
            .get_alignment(self)
    }

    /// Port of `DataTypeDB.isDeleted()`. Exposed under a distinct name since
    /// [`DataType::is_deleted`] already provides a (placeholder) default, and to disambiguate
    /// from [`DbObject::is_deleted`] (which takes an explicit `&Lock<()>` argument and would
    /// otherwise be an ambiguous call target on a `dyn DataTypeDb`).
    fn data_type_db_is_deleted(&self) -> bool {
        DbObject::is_deleted(self, self.lock())
    }

    /// Clears the cached category/name state, forcing a fresh read on next access. Stands in for
    /// `DataTypeDB.completeRefresh()`.
    fn data_type_db_complete_refresh(&self) {
        self.set_stored_category_path(None);
        self.data_type_db_refresh_name();
    }

    /// Marks this datatype as having started deletion; once set this cannot be reverted for this
    /// instance. While set, any invocation of other datatype changes should be ignored. Stands in
    /// for `DataTypeDB.deleteStarted()`.
    fn data_type_db_delete_started(&self) {
        self.set_stored_deleting(true);
    }

    /// Performs any pointer-specific fixups required once `definition_dt` (the pointer's
    /// referent) has itself been resolved. Stands in for `DataTypeDB.postPointerResolve`, whose
    /// default throws `UnsupportedOperationException`; implementors supporting pointer
    /// post-resolution are expected to override this.
    fn data_type_db_post_pointer_resolve(
        &self,
        definition_dt: &dyn DataType,
        handler: Option<&dyn DataTypeConflictHandler>,
    ) -> Result<(), UnsupportedOperationError> {
        let _ = (definition_dt, handler);
        Err(UnsupportedOperationError(
            "post-resolve of pointers not implemented".to_string(),
        ))
    }

    /// Port of the final `DataTypeDB.hashCode()`. Uses Rust's `DefaultHasher` over `get_name()`
    /// rather than replicating Java's exact `String.hashCode()` algorithm -- only internal
    /// consistency (equal names hash equally) is required, matching
    /// [`DataTypeImpl::data_type_impl_hash_code`](crate::program::model::data::data_type_impl::DataTypeImpl::data_type_impl_hash_code)'s
    /// precedent.
    fn data_type_db_hash_code(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.get_name().hash(&mut hasher);
        hasher.finish()
    }

    /// Port of the final `DataTypeDB.equals(Object)`.
    ///
    /// `otherDt.getDataTypeManager() == getDataTypeManager()`'s reference-equality check is
    /// approximated by comparing `other`'s [`DataType::get_data_type_manager`] (if any) against
    /// this datatype's [`owning_data_type_manager`](Self::owning_data_type_manager) by
    /// [`DataTypeManager::get_universal_id`], mirroring
    /// [`DataTypeImpl::data_type_impl_equals`](crate::program::model::data::data_type_impl::DataTypeImpl::data_type_impl_equals)'s
    /// same approximation.
    fn data_type_db_equals(&self, other: &dyn DataType) -> bool {
        let self_mgr_id = self.owning_data_type_manager().get_universal_id();
        let other_mgr_id = other.get_data_type_manager().map(|m| m.get_universal_id());
        Some(self_mgr_id) == other_mgr_id
            && self.get_category_path() == other.get_category_path()
            && self.get_name() == other.get_name()
            && self.is_equivalent(other)
    }
}

/// Port of the package-private static `DataTypeDB.prependComment(String, String)`.
pub fn prepend_comment(additional_comment: &str, old_comment: Option<&str>) -> String {
    let mut comment = additional_comment.to_string();
    if let Some(oc) = old_comment {
        if !oc.trim().is_empty() {
            comment.push_str("; ");
            comment.push_str(oc);
        }
    }
    comment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::db_cache::DbCacheHandle;
    use crate::program::database::db_object::DbObjectState;
    use crate::program::model::data::archive_type::ArchiveType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::source_archive::SourceArchive;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Mutex;

    struct MockCategory {
        path: CategoryPath,
    }
    impl Category for MockCategory {
        fn get_name(&self) -> String {
            self.path.get_name()
        }
        fn set_name(
            &mut self,
            _name: &str,
        ) -> Result<(), crate::program::model::data::category::SetCategoryNameError> {
            Ok(())
        }
        fn get_categories(&self) -> Vec<Box<dyn Category>> {
            Vec::new()
        }
        fn get_data_types(&self) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn get_data_types_by_base_name(&self, _name: &str) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn add_data_type(
            &mut self,
            dt: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Box<dyn DataType> {
            dt
        }
        fn get_category(&self, _name: &str) -> Option<Box<dyn Category>> {
            None
        }
        fn get_category_path(&self) -> CategoryPath {
            self.path.clone()
        }
        fn get_data_type(&self, _name: &str) -> Option<Box<dyn DataType>> {
            None
        }
        fn create_category(&mut self, _name: &str) -> Result<Box<dyn Category>, InvalidNameException> {
            Err(InvalidNameException::new())
        }
        fn remove_category(&mut self, _name: &str, _monitor: &dyn crate::util::task::TaskMonitor) -> bool {
            false
        }
        fn remove_empty_category(
            &mut self,
            _name: &str,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> bool {
            false
        }
        fn move_category(
            &mut self,
            _category: Box<dyn Category>,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), DuplicateNameException> {
            Ok(())
        }
        fn copy_category(
            &mut self,
            _category: &dyn Category,
            _handler: &dyn DataTypeConflictHandler,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Box<dyn Category> {
            Box::new(MockCategory { path: self.path.clone() })
        }
        fn get_parent(&self) -> Option<Box<dyn Category>> {
            None
        }
        fn is_root(&self) -> bool {
            self.path == *ROOT
        }
        fn get_category_path_name(&self) -> String {
            self.path.get_path()
        }
        fn get_root(&self) -> Box<dyn Category> {
            Box::new(MockCategory { path: ROOT.clone() })
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(ManagerHandle(UniversalID::new(0)))
        }
        fn move_data_type(
            &mut self,
            _dt_type: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Result<(), crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException>
        {
            Ok(())
        }
        fn remove(&mut self, _dt_type: &dyn DataType, _monitor: &dyn crate::util::task::TaskMonitor) -> bool {
            false
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn compare_to(&self, other: &dyn Category) -> std::cmp::Ordering {
            Category::get_name(self).cmp(&other.get_name())
        }
    }

    struct MockDataTypeManagerDb {
        id: UniversalID,
        category_path: CategoryPath,
        duplicate_name: Mutex<Option<String>>,
    }
    impl DataTypeManager for MockDataTypeManagerDb {
        fn get_universal_id(&self) -> UniversalID {
            self.id
        }
        fn get_category(&self, _category_id: i64) -> Option<Box<dyn Category>> {
            Some(Box::new(MockCategory { path: self.category_path.clone() }))
        }
        fn get_root_category(&self) -> Box<dyn Category> {
            Box::new(MockCategory { path: ROOT.clone() })
        }
        fn get_data_type_in_category(
            &self,
            _path: &CategoryPath,
            name: &str,
        ) -> Option<Box<dyn DataType>> {
            if self.duplicate_name.lock().unwrap().as_deref() == Some(name) {
                Some(Box::new(MockPlainDataType))
            } else {
                None
            }
        }
    }
    impl DataTypeManagerDb for MockDataTypeManagerDb {
        fn db_error(&mut self, _error: io::Error) {}
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    struct MockPlainDataType;
    impl DataType for MockPlainDataType {}

    /// Stands in for the `Box<dyn DataTypeManager>` returned by [`DataType::get_data_type_manager`],
    /// exposing only the [`UniversalID`] identity [`DataTypeDb::data_type_db_equals`] compares.
    struct ManagerHandle(UniversalID);
    impl DataTypeManager for ManagerHandle {
        fn get_universal_id(&self) -> UniversalID {
            self.0
        }
    }

    /// Minimal DB-backed [`DataTypeDb`], proving object-safety and exercising real caching,
    /// rename, and delete-tracking behavior rather than trivially-true asserts.
    struct MockDataTypeDb {
        db_state: DbObjectState,
        cache: Arc<AtomicModCache>,
        lock: Lock<()>,
        name: Mutex<Option<String>>,
        category_path: Mutex<Option<CategoryPath>>,
        deleting: Mutex<bool>,
        record_name: Mutex<String>,
        manager: Arc<MockDataTypeManagerDb>,
    }

    struct AtomicModCache(AtomicI32);
    impl DbCacheHandle for AtomicModCache {
        fn get_modification_count(&self) -> i32 {
            self.0.load(Ordering::SeqCst)
        }
        fn delete(&self, _key: i64) {}
        fn key_changed(&self, _old_key: i64, _new_key: i64) {}
    }

    impl MockDataTypeDb {
        fn new(record_name: &str, category_path: CategoryPath) -> Self {
            Self::with_manager_id(record_name, category_path, UniversalID::new(1))
        }

        fn with_manager_id(record_name: &str, category_path: CategoryPath, manager_id: UniversalID) -> Self {
            let db_state = DbObjectState::new(1);
            let cache = Arc::new(AtomicModCache(AtomicI32::new(0)));
            db_state.set_cache(cache.clone());
            MockDataTypeDb {
                db_state,
                cache,
                lock: Lock::new_unit("test"),
                name: Mutex::new(None),
                category_path: Mutex::new(None),
                deleting: Mutex::new(false),
                record_name: Mutex::new(record_name.to_string()),
                manager: Arc::new(MockDataTypeManagerDb {
                    id: manager_id,
                    category_path,
                    duplicate_name: Mutex::new(None),
                }),
            }
        }
    }

    impl DbObject for MockDataTypeDb {
        fn state(&self) -> &DbObjectState {
            &self.db_state
        }
        fn refresh(&self, _record: Option<&crate::framework::db::DBRecord>) -> bool {
            true
        }
    }

    impl DataType for MockDataTypeDb {
        fn get_name(&self) -> String {
            self.data_type_db_get_name()
        }
        fn get_category_path(&self) -> CategoryPath {
            self.data_type_db_get_category_path()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_name() == dt.get_name()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            Some(Box::new(ManagerHandle(self.manager.get_universal_id())))
        }
    }

    impl DataTypeDb for MockDataTypeDb {
        fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb> {
            self.manager.clone()
        }
        fn lock(&self) -> &Lock<()> {
            &self.lock
        }
        fn stored_name(&self) -> Option<String> {
            self.name.lock().unwrap().clone()
        }
        fn set_stored_name(&self, name: Option<String>) {
            *self.name.lock().unwrap() = name;
        }
        fn stored_category_path(&self) -> Option<CategoryPath> {
            self.category_path.lock().unwrap().clone()
        }
        fn set_stored_category_path(&self, path: Option<CategoryPath>) {
            *self.category_path.lock().unwrap() = path;
        }
        fn stored_deleting(&self) -> bool {
            *self.deleting.lock().unwrap()
        }
        fn set_stored_deleting(&self, deleting: bool) {
            *self.deleting.lock().unwrap() = deleting;
        }
        fn do_get_name(&self) -> String {
            self.record_name.lock().unwrap().clone()
        }
        fn do_get_category_id(&self) -> i64 {
            0
        }
        fn do_set_category_path_record(&self, _category_id: i64) -> io::Result<()> {
            Ok(())
        }
        fn do_set_name_record(&self, new_name: &str) -> Result<(), DoSetNameRecordError> {
            *self.record_name.lock().unwrap() = new_name.to_string();
            Ok(())
        }
        fn get_source_archive_id(&self) -> UniversalID {
            UniversalID::new(0)
        }
        fn set_source_archive_id(&self, _id: UniversalID) {}
        fn is_equivalent_with_handler(
            &self,
            data_type: &dyn DataType,
            _handler: Option<&dyn DataTypeConflictHandler>,
        ) -> bool {
            self.get_name() == data_type.get_name()
        }
        fn set_universal_id(&self, _old_universal_id: UniversalID) {}
    }

    struct MockSourceArchive;
    impl SourceArchive for MockSourceArchive {
        fn source_archive_id(&self) -> UniversalID {
            UniversalID::new(0)
        }
        fn domain_file_id(&self) -> String {
            String::new()
        }
        fn archive_type(&self) -> ArchiveType {
            ArchiveType::Program
        }
        fn name(&self) -> String {
            String::new()
        }
        fn last_sync_time(&self) -> i64 {
            0
        }
        fn is_dirty(&self) -> bool {
            false
        }
        fn set_last_sync_time(&mut self, _time: i64) {}
        fn set_name(&mut self, _name: String) {}
        fn set_dirty_flag(&mut self, _dirty: bool) {}
    }

    #[test]
    fn name_is_cached_until_invalidated_and_survives_rename() {
        let cat = ROOT.clone();
        let dt = MockDataTypeDb::new("Foo", cat);

        // First read populates the cache from `do_get_name`.
        assert_eq!(dt.data_type_db_get_name(), "Foo");
        assert_eq!(*dt.record_name.lock().unwrap(), "Foo");

        // Mutating the backing record directly does not change the cached name...
        *dt.record_name.lock().unwrap() = "Bar".to_string();
        assert_eq!(dt.data_type_db_get_name(), "Foo");

        // ...until the cache is invalidated (mirrors a `DbCache` modification-count bump).
        dt.cache.0.fetch_add(1, Ordering::SeqCst);
        assert!(dt.needs_refreshing());
        assert_eq!(dt.data_type_db_get_name(), "Bar");
    }

    #[test]
    fn set_name_updates_record_and_cache_rejects_duplicate() {
        let dt = MockDataTypeDb::new("Foo", ROOT.clone());
        struct Util;
        impl DataUtilities for Util {}

        assert_eq!(dt.data_type_db_get_name(), "Foo");
        assert!(dt.data_type_db_set_name("Bar", &Util).is_ok());
        assert_eq!(dt.data_type_db_get_name(), "Bar");
        assert_eq!(*dt.record_name.lock().unwrap(), "Bar");

        // Renaming to the same name is a no-op success.
        assert!(dt.data_type_db_set_name("Bar", &Util).is_ok());

        // An invalid name is rejected before the record is touched.
        assert!(matches!(
            dt.data_type_db_set_name("", &Util),
            Err(SetNameError::InvalidName(_))
        ));
        assert_eq!(*dt.record_name.lock().unwrap(), "Bar");

        // A name already used in this category by another datatype is rejected as a duplicate.
        *dt.manager.duplicate_name.lock().unwrap() = Some("Taken".to_string());
        assert!(matches!(
            dt.data_type_db_set_name("Taken", &Util),
            Err(SetNameError::Duplicate(_))
        ));
    }

    #[test]
    fn category_path_is_looked_up_from_manager_and_cached() {
        let cat_path = CategoryPath::parse("/foo/bar").unwrap();
        let dt = MockDataTypeDb::new("Foo", cat_path.clone());

        assert_eq!(dt.data_type_db_get_category_path(), cat_path);
        assert_eq!(
            dt.data_type_db_get_data_type_path(),
            DataTypePath::new(cat_path.clone(), "Foo")
        );

        // The lookup result is cached: a second call reuses `stored_category_path` rather than
        // re-querying the manager (observable since it still returns the same value even though
        // nothing re-populates it without an invalidation).
        assert_eq!(dt.stored_category_path(), Some(cat_path.clone()));
        dt.cache.0.fetch_add(1, Ordering::SeqCst);
        assert!(dt.needs_refreshing());
        assert_eq!(dt.data_type_db_get_category_path(), cat_path);
    }

    #[test]
    fn delete_started_and_refresh_name_mutate_expected_state() {
        let dt = MockDataTypeDb::new("Foo", ROOT.clone());
        assert!(!dt.stored_deleting());
        dt.data_type_db_delete_started();
        assert!(dt.stored_deleting());

        assert_eq!(dt.data_type_db_get_name(), "Foo");
        dt.data_type_db_refresh_name();
        assert!(dt.stored_name().is_none());
        // A subsequent read re-populates the cache from the (still current) record.
        assert_eq!(dt.data_type_db_get_name(), "Foo");
    }

    #[test]
    fn hash_code_and_equals_use_name_and_manager_identity() {
        let dt = MockDataTypeDb::with_manager_id("Foo", ROOT.clone(), UniversalID::new(1));
        assert_eq!(dt.data_type_db_hash_code(), dt.data_type_db_hash_code());

        // Same name, category, and manager identity => equal.
        let same = MockDataTypeDb::with_manager_id("Foo", ROOT.clone(), UniversalID::new(1));
        assert!(dt.data_type_db_equals(&same));

        // Different manager identity (different `UniversalID`) => not equal, even with a
        // matching name/category and a mock `is_equivalent` that only checks names.
        let other_manager = MockDataTypeDb::with_manager_id("Foo", ROOT.clone(), UniversalID::new(2));
        assert!(!dt.data_type_db_equals(&other_manager));

        // No manager at all (mirrors two `null` `getDataTypeManager()` results not counting as a
        // match here, since `DataTypeDB` always has one) => not equal.
        struct NoManager;
        impl DataType for NoManager {
            fn get_name(&self) -> String {
                "Foo".to_string()
            }
        }
        assert!(!dt.data_type_db_equals(&NoManager));
    }

    #[test]
    fn post_pointer_resolve_defaults_to_unsupported() {
        let dt = MockDataTypeDb::new("Foo", ROOT.clone());
        struct Target;
        impl DataType for Target {}
        assert!(dt
            .data_type_db_post_pointer_resolve(&Target, None)
            .is_err());
    }

    #[test]
    fn prepend_comment_joins_with_semicolon_or_passes_through() {
        assert_eq!(prepend_comment("new", Some("old")), "new; old");
        assert_eq!(prepend_comment("new", Some("  ")), "new");
        assert_eq!(prepend_comment("new", None), "new");
    }
}
