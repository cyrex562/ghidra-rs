use thiserror::Error;

use crate::program::model::data::category::Category;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException;
pub use crate::program::model::data::category_path::{DELIMITER_CHAR, DELIMITER_STRING};
use crate::program::seam_stubs::{DataType, DataTypeConflictHandler, DataTypeManager};
use crate::util::exception::{DuplicateNameException, InvalidNameException};
use crate::util::task::TaskMonitor;

/// Alias for [`DELIMITER_STRING`], matching the Java constant name
/// `ICategory.NAME_DELIMITER`.
pub const NAME_DELIMITER: &str = DELIMITER_STRING;

/// Error produced when renaming an [`ICategory`] fails.
///
/// Combines the two checked exceptions declared on the Java method
/// `ICategory.setName(String)`.
#[derive(Error, Debug, PartialEq)]
pub enum SetICategoryNameError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// Error produced when [`ICategory::create_category`] fails.
///
/// Combines the two checked exceptions declared on the Java method
/// `ICategory.createCategory(String)`.
#[derive(Error, Debug, PartialEq)]
pub enum CreateCategoryError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// Port of `ghidra.program.model.data.ICategory`.
///
/// A category that groups data types; this is the interface later implementations of
/// [`Category`] are built against.
pub trait ICategory {
    /// Get the name of this category.
    fn get_name(&self) -> String;

    /// Sets the name of this category.
    fn set_name(&mut self, name: &str) -> Result<(), SetICategoryNameError>;

    /// Get all categories in this category; empty if there are none.
    fn get_categories(&self) -> Vec<Box<dyn Category>>;

    /// Get all data types in this category; empty if there are none.
    fn get_data_types(&self) -> Vec<Box<dyn DataType>>;

    /// Add a data type to this category.
    fn add_data_type(
        &mut self,
        dt: Box<dyn DataType>,
        handler: &dyn DataTypeConflictHandler,
    ) -> Box<dyn DataType>;

    /// Get a category with the given name, or `None` if there is no category by this name.
    fn get_category(&self, name: &str) -> Option<Box<dyn Category>>;

    /// Return the full [`CategoryPath`] for this category.
    fn get_category_path(&self) -> CategoryPath;

    /// Get a data type with the given name, or `None` if there is no data type by this name.
    fn get_data_type(&self, name: &str) -> Option<Box<dyn DataType>>;

    /// Create a category with the given name.
    fn create_category(&mut self, name: &str) -> Result<Box<dyn Category>, CreateCategoryError>;

    /// Remove the named category from this category, returning true if it was removed.
    fn remove_category(&mut self, name: &str, monitor: &dyn TaskMonitor) -> bool;

    /// Move the given category to this category; the category is removed from its original
    /// parent category.
    fn move_category(
        &mut self,
        category: Box<dyn Category>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DuplicateNameException>;

    /// Make a new sub-category from the given category, returning the category that is added
    /// to this category.
    fn copy_category(
        &mut self,
        category: &dyn Category,
        handler: &dyn DataTypeConflictHandler,
        monitor: &dyn TaskMonitor,
    ) -> Box<dyn Category>;

    /// Return this category's parent; `None` if this is the root category.
    fn get_parent(&self) -> Option<Box<dyn Category>>;

    /// Returns true if this is the root category.
    fn is_root(&self) -> bool;

    /// Get the fully qualified name for this category.
    fn get_category_path_name(&self) -> String;

    /// Get the root category.
    fn get_root(&self) -> Box<dyn Category>;

    /// Get the data type manager associated with this category.
    fn get_data_type_manager(&self) -> Box<dyn DataTypeManager>;

    /// Move a data type into this category.
    fn move_data_type(
        &mut self,
        dt_type: Box<dyn DataType>,
        handler: &dyn DataTypeConflictHandler,
    ) -> Result<(), DataTypeDependencyException>;

    /// Remove a datatype from this category, returning true if it was found and removed.
    fn remove(&mut self, dt_type: &dyn DataType, monitor: &dyn TaskMonitor) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockICategory {
        name: String,
        is_root: bool,
    }

    impl DataTypeManager for MockICategory {}

    impl ICategory for MockICategory {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) -> Result<(), SetICategoryNameError> {
            if name.is_empty() {
                return Err(SetICategoryNameError::InvalidName(InvalidNameException::with_message(
                    "name must not be empty",
                )));
            }
            self.name = name.to_string();
            Ok(())
        }

        fn get_categories(&self) -> Vec<Box<dyn Category>> {
            Vec::new()
        }

        fn get_data_types(&self) -> Vec<Box<dyn DataType>> {
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
            CategoryPath::parse(&format!("/{}", self.name)).unwrap()
        }

        fn get_data_type(&self, _name: &str) -> Option<Box<dyn DataType>> {
            None
        }

        fn create_category(
            &mut self,
            _name: &str,
        ) -> Result<Box<dyn Category>, CreateCategoryError> {
            Err(CreateCategoryError::InvalidName(InvalidNameException::new()))
        }

        fn remove_category(&mut self, _name: &str, _monitor: &dyn TaskMonitor) -> bool {
            false
        }

        fn move_category(
            &mut self,
            _category: Box<dyn Category>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), DuplicateNameException> {
            Ok(())
        }

        fn copy_category(
            &mut self,
            _category: &dyn Category,
            _handler: &dyn DataTypeConflictHandler,
            _monitor: &dyn TaskMonitor,
        ) -> Box<dyn Category> {
            unimplemented!("MockICategory does not model Category")
        }

        fn get_parent(&self) -> Option<Box<dyn Category>> {
            None
        }

        fn is_root(&self) -> bool {
            self.is_root
        }

        fn get_category_path_name(&self) -> String {
            format!("/{}", self.name)
        }

        fn get_root(&self) -> Box<dyn Category> {
            unimplemented!("MockICategory does not model Category")
        }

        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockICategory { name: self.name.clone(), is_root: self.is_root })
        }

        fn move_data_type(
            &mut self,
            _dt_type: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Result<(), DataTypeDependencyException> {
            Ok(())
        }

        fn remove(&mut self, _dt_type: &dyn DataType, _monitor: &dyn TaskMonitor) -> bool {
            false
        }
    }

    #[test]
    fn set_name_rejects_empty() {
        let mut cat = MockICategory { name: "root".to_string(), is_root: true };
        let err = cat.set_name("").unwrap_err();
        assert!(matches!(err, SetICategoryNameError::InvalidName(_)));
    }

    #[test]
    fn set_name_updates_name() {
        let mut cat = MockICategory { name: "old".to_string(), is_root: false };
        cat.set_name("new").unwrap();
        assert_eq!(cat.get_name(), "new");
    }

    #[test]
    fn usable_as_trait_object() {
        let cat = MockICategory { name: "structs".to_string(), is_root: false };
        let dyn_cat: &dyn ICategory = &cat;
        assert_eq!(dyn_cat.get_name(), "structs");
        assert!(!dyn_cat.is_root());
    }

    #[test]
    fn delimiter_constants_match_category_path() {
        assert_eq!(DELIMITER_CHAR, '/');
        assert_eq!(DELIMITER_STRING, "/");
        assert_eq!(NAME_DELIMITER, "/");
    }
}
