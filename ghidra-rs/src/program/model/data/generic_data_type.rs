//! Port of `ghidra.program.model.data.GenericDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class is `abstract` (a thin base for hand-built, non-database-backed composite/enum
//! datatypes) and `extends DataTypeImpl`, already ported as a trait ([`DataTypeImpl`]), so this
//! trait extends it directly.
//!
//! `setNameAndCategory(CategoryPath, String)`, `setName(String)`, and `setCategoryPath(CategoryPath)`
//! all override *default* methods already declared directly on
//! [`DataType`](crate::program::model::data::data_type::DataType) (`Ok(())`/no-op placeholders).
//! Rust does not allow a subtrait to override a supertrait's default method by redeclaring it (the
//! same restriction documented throughout this crate's other cut-point traits), so this port does
//! not attempt to redeclare those three methods themselves. Instead, the two private helpers they
//! actually delegate to in Java (`doSetName(String)`/`doSetCategoryPath(CategoryPath)`) are ported
//! under distinct names --
//! [`generic_check_name_change`](GenericDataType::generic_check_name_change)/
//! [`generic_normalize_category_path`](GenericDataType::generic_normalize_category_path) -- since
//! neither collides with anything already declared. A concrete `impl DataType for ...` (which owns
//! the actual mutable `name`/`categoryPath` storage a trait cannot hold) should have its
//! `set_name`/`set_name_and_category`/`set_category_path` overrides call these first, and only
//! commit the new value to storage when they return successfully.
//!
//! `checkValidName(String)` (the package-private helper `doSetName` calls, which throws
//! `InvalidNameException` when invalid) is not re-ported here: it is exactly
//! [`DataTypeImpl::data_type_impl_check_valid_name`], already available on the supertrait this
//! trait extends, and [`generic_check_name_change`](GenericDataType::generic_check_name_change)
//! calls it directly.
//!
//! The `notifyNameChanged(oldName)` call `doSetName` makes after committing the new name is
//! intentionally dropped, mirroring [`DataTypeImpl`]'s own module docs on why the `notify*` family
//! is not ported (soundness issue with `Weak` parent back-references; see there for the full
//! explanation).
//!
//! The two constructors (validating `name` via `DataUtilities.isValidDataTypeName` before storing
//! it) have no trait equivalent (traits cannot declare constructors or store fields); a concrete
//! implementation is expected to run the same validation itself (e.g. by calling
//! [`generic_check_name_change`](GenericDataType::generic_check_name_change) against an empty
//! starting name) before it exists in valid form.

use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_utilities::DataUtilities;
use crate::util::exception::InvalidNameException;

/// Base implementation for a generic (hand-built, non-database-backed) data type.
///
/// Port of `ghidra.program.model.data.GenericDataType`. See the module-level documentation for
/// the naming conventions used to resolve clashes with
/// [`DataType`](crate::program::model::data::data_type::DataType), and for what was left to a
/// concrete implementation.
pub trait GenericDataType: DataTypeImpl {
    /// Port of the private `GenericDataType.doSetName(String)`'s validation half (everything
    /// except the actual field mutation and `notifyNameChanged` call a trait cannot perform; see
    /// the module docs).
    ///
    /// Returns `Ok(false)` with nothing further to do when `new_name` already equals
    /// [`DataType::get_name`](crate::program::model::data::data_type::DataType::get_name)
    /// (mirroring the Java short-circuit `if (this.name.equals(newName)) return;`, run *before*
    /// validation). Otherwise validates `new_name` via `utilities` (delegating to
    /// [`DataTypeImpl::data_type_impl_check_valid_name`]) and returns `Ok(true)` when valid,
    /// meaning the caller should go on to actually store `new_name`.
    fn generic_check_name_change(
        &self,
        new_name: &str,
        utilities: &dyn DataUtilities,
    ) -> Result<bool, InvalidNameException> {
        if self.get_name() == new_name {
            return Ok(false);
        }
        self.data_type_impl_check_valid_name(new_name, utilities)?;
        Ok(true)
    }

    /// Port of the private `GenericDataType.doSetCategoryPath(CategoryPath)`, normalizing `None`
    /// (standing in for a Java `null` `path`) to
    /// [`CategoryPath::ROOT`](crate::program::model::data::category_path::ROOT), matching the
    /// Java `if (path == null) { path = CategoryPath.ROOT; }` guard. The caller is expected to
    /// store the returned path itself.
    fn generic_normalize_category_path(&self, path: Option<CategoryPath>) -> CategoryPath {
        path.unwrap_or_else(|| ROOT.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockDataUtilities;
    impl DataUtilities for MockDataUtilities {}

    struct MockGenericDataType {
        name: String,
    }

    impl DataType for MockGenericDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
    }

    impl DataTypeImpl for MockGenericDataType {
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
            0
        }
        fn set_stored_last_change_time(&mut self, _last_change_time: i64) {}
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, _last_change_time: i64) {}
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            Vec::new()
        }
        fn set_stored_parent_refs(&mut self, _parents: Vec<Weak<dyn DataType>>) {}
    }

    impl GenericDataType for MockGenericDataType {}

    #[test]
    fn unchanged_name_short_circuits_before_validation() {
        let dt = MockGenericDataType { name: "MyType".to_string() };
        // An invalid name would normally fail validation, but since it equals the current name
        // the short-circuit means validation is never reached.
        let result = dt.generic_check_name_change("MyType", &MockDataUtilities);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn valid_new_name_is_accepted() {
        let dt = MockGenericDataType { name: "MyType".to_string() };
        let result = dt.generic_check_name_change("MyRenamedType", &MockDataUtilities);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn invalid_new_name_is_rejected() {
        let dt = MockGenericDataType { name: "MyType".to_string() };
        let result = dt.generic_check_name_change("", &MockDataUtilities);
        assert!(result.is_err());
    }

    #[test]
    fn normalize_category_path_defaults_missing_path_to_root() {
        let dt = MockGenericDataType { name: "MyType".to_string() };
        assert_eq!(dt.generic_normalize_category_path(None), ROOT.clone());
    }

    #[test]
    fn normalize_category_path_preserves_explicit_path() {
        let dt = MockGenericDataType { name: "MyType".to_string() };
        let path = CategoryPath::new(ROOT.clone(), &["foo", "bar"]).unwrap();
        assert_eq!(dt.generic_normalize_category_path(Some(path.clone())), path);
    }
}
