use std::cmp::Ordering;

use thiserror::Error;

use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::DataTypeConflictHandler;
use crate::util::exception::{DuplicateNameException, InvalidNameException};
use crate::util::task::TaskMonitor;

/// Error produced when renaming a [`Category`] fails.
///
/// Combines the two checked exceptions declared on the Java method
/// `Category.setName(String)`.
#[derive(Error, Debug, PartialEq)]
pub enum SetCategoryNameError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// Each data type resides in a given category.
///
/// Port of `ghidra.program.model.data.Category`.
///
/// The Java interface extends `Comparable<Category>`; [`compare_to`](Category::compare_to)
/// stands in for that so the trait remains object-safe (`dyn Category` cannot itself implement
/// `Ord`/`PartialOrd`, which require `Sized`).
pub trait Category {
    /// Get the name of this category.
    fn get_name(&self) -> String;

    /// Sets the name of this category.
    fn set_name(&mut self, name: &str) -> Result<(), SetCategoryNameError>;

    /// Get all categories in this category.
    fn get_categories(&self) -> Vec<Box<dyn Category>>;

    /// Get all data types in this category.
    fn get_data_types(&self) -> Vec<Box<dyn DataType>>;

    /// Get all data types whose name matches the given name once any conflict suffixes have
    /// been removed from both the given name and the data types that are being scanned.
    ///
    /// NOTE: `name` must not contain array or pointer decorations.
    fn get_data_types_by_base_name(&self, name: &str) -> Vec<Box<dyn DataType>>;

    /// Adds the given datatype to this category, returning the new datatype with its category
    /// path adjusted.
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

    /// Create a category with the given name; if the category already exists, returns that
    /// category.
    fn create_category(&mut self, name: &str) -> Result<Box<dyn Category>, InvalidNameException>;

    /// Remove the named category from this category, returning true if it was removed.
    fn remove_category(&mut self, name: &str, monitor: &dyn TaskMonitor) -> bool;

    /// Remove the named category from this category, IFF it is empty, returning true if it was
    /// removed.
    fn remove_empty_category(&mut self, name: &str, monitor: &dyn TaskMonitor) -> bool;

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

    /// Get the ID for this category.
    fn get_id(&self) -> i64;

    /// Compares this category to another. Stands in for the Java `Comparable<Category>`
    /// contract.
    fn compare_to(&self, other: &dyn Category) -> Ordering;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCategory {
        name: String,
        id: i64,
    }

    impl DataTypeManager for MockCategory {}

    impl Category for MockCategory {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) -> Result<(), SetCategoryNameError> {
            if name.is_empty() {
                return Err(SetCategoryNameError::InvalidName(InvalidNameException::with_message(
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
            CategoryPath::parse(&format!("/{}", self.name)).unwrap()
        }

        fn get_data_type(&self, _name: &str) -> Option<Box<dyn DataType>> {
            None
        }

        fn create_category(
            &mut self,
            _name: &str,
        ) -> Result<Box<dyn Category>, InvalidNameException> {
            Err(InvalidNameException::new())
        }

        fn remove_category(&mut self, _name: &str, _monitor: &dyn TaskMonitor) -> bool {
            false
        }

        fn remove_empty_category(&mut self, _name: &str, _monitor: &dyn TaskMonitor) -> bool {
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
            Box::new(MockCategory { name: self.name.clone(), id: self.id })
        }

        fn get_parent(&self) -> Option<Box<dyn Category>> {
            None
        }

        fn is_root(&self) -> bool {
            self.id == 0
        }

        fn get_category_path_name(&self) -> String {
            format!("/{}", self.name)
        }

        fn get_root(&self) -> Box<dyn Category> {
            Box::new(MockCategory { name: String::new(), id: 0 })
        }

        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockCategory { name: self.name.clone(), id: self.id })
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

        fn get_id(&self) -> i64 {
            self.id
        }

        fn compare_to(&self, other: &dyn Category) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }
    }

    #[test]
    fn set_name_rejects_empty() {
        let mut cat = MockCategory { name: "root".to_string(), id: 0 };
        let err = cat.set_name("").unwrap_err();
        assert!(matches!(err, SetCategoryNameError::InvalidName(_)));
    }

    #[test]
    fn set_name_updates_name() {
        let mut cat = MockCategory { name: "old".to_string(), id: 1 };
        cat.set_name("new").unwrap();
        assert_eq!(cat.get_name(), "new");
    }

    #[test]
    fn usable_as_trait_object() {
        let cat = MockCategory { name: "structs".to_string(), id: 42 };
        let dyn_cat: &dyn Category = &cat;
        assert_eq!(dyn_cat.get_name(), "structs");
        assert_eq!(dyn_cat.get_id(), 42);
        assert!(!dyn_cat.is_root());
    }

    #[test]
    fn compare_to_orders_by_name() {
        let a = MockCategory { name: "a".to_string(), id: 1 };
        let b = MockCategory { name: "b".to_string(), id: 2 };
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
        assert_eq!(a.compare_to(&a), Ordering::Equal);
    }
}
