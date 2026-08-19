//! Simplified datatype service interface to provide query capabilities to a set of open datatype
//! managers.
//!
//! Port of `ghidra.app.services.DataTypeQueryService`.

use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_path::DataTypePath;
use crate::util::task::TaskMonitor;

/// Simplified datatype service interface to provide query capabilities to a set of open datatype
/// managers.
pub trait DataTypeQueryService {
    /// Gets the sorted list of all datatypes known by this service via its owned
    /// `DataTypeManager`s. This method can be called frequently, as the underlying data is
    /// indexed and only updated as changes are made. The sorting of the list is done using the
    /// `DataTypeComparator`, whose primary sort is based upon the `DataTypeNameComparator`.
    fn get_sorted_data_type_list(&self) -> Vec<Box<dyn DataType>>;

    /// Gets the sorted list of all category paths known by this service via its owned
    /// `DataTypeManager`s. This method can be called frequently, as the underlying data is
    /// indexed and only updated as changes are made. The sorting of the list is done using the
    /// natural sort of the [`CategoryPath`] objects.
    fn get_sorted_category_path_list(&self) -> Vec<CategoryPath>;

    /// This method simply calls [`DataTypeQueryService::prompt_for_data_type`].
    #[deprecated(note = "use `prompt_for_data_type`")]
    fn get_data_type(&self, filter_text: Option<&str>) -> Option<Box<dyn DataType>>;

    /// Obtain the preferred datatype which corresponds to the specified datatype specified by
    /// `filter_text`. A tool-based service provider may prompt the user to select a datatype if
    /// more than one possibility exists.
    ///
    /// `filter_text`, if not `None`, filters the visible data types to only show those that start
    /// with the given text.
    ///
    /// Returns the preferred data type (e.g., chosen by the user), or `None` if no match was
    /// found or the selection was canceled by the user.
    fn prompt_for_data_type(&self, filter_text: Option<&str>) -> Option<Box<dyn DataType>>;

    /// Finds all data types matching the given name. This method will search all open data type
    /// archives.
    ///
    /// Unlike `DataTypeManagerService::find_data_types`, this method will not return `.conflict`
    /// data types. If you need those types, then you must call each data type manager directly.
    ///
    /// In the list of types returned, the program data type manager's types will be in the list
    /// before types from other archives.
    fn find_data_types(&self, name: &str, monitor: &dyn TaskMonitor) -> Vec<Box<dyn DataType>>;

    /// Get the data type for the given data type path.
    ///
    /// This method will check each open data type manager for a data type that matches the path.
    ///
    /// If a type is in the program data type manager, then it will be first in the returned list.
    fn get_data_types_by_path(&self, path: &DataTypePath) -> Vec<Box<dyn DataType>>;

    /// Get the data type for the given data type path from the program's data type manager.
    ///
    /// Returns the data type, or `None` if the type does not exist.
    fn get_program_data_type_by_path(&self, path: &DataTypePath) -> Option<Box<dyn DataType>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockService;

    #[allow(deprecated)]
    impl DataTypeQueryService for MockService {
        fn get_sorted_data_type_list(&self) -> Vec<Box<dyn DataType>> {
            vec![Box::new(MockDataType)]
        }

        fn get_sorted_category_path_list(&self) -> Vec<CategoryPath> {
            vec![crate::program::model::data::category_path::ROOT.clone()]
        }

        fn get_data_type(&self, filter_text: Option<&str>) -> Option<Box<dyn DataType>> {
            self.prompt_for_data_type(filter_text)
        }

        fn prompt_for_data_type(&self, _filter_text: Option<&str>) -> Option<Box<dyn DataType>> {
            Some(Box::new(MockDataType))
        }

        fn find_data_types(&self, _name: &str, _monitor: &dyn TaskMonitor) -> Vec<Box<dyn DataType>> {
            vec![Box::new(MockDataType)]
        }

        fn get_data_types_by_path(&self, _path: &DataTypePath) -> Vec<Box<dyn DataType>> {
            vec![Box::new(MockDataType)]
        }

        fn get_program_data_type_by_path(&self, _path: &DataTypePath) -> Option<Box<dyn DataType>> {
            Some(Box::new(MockDataType))
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn DataTypeQueryService> = Box::new(MockService);
        assert_eq!(service.get_sorted_data_type_list().len(), 1);
        assert_eq!(service.get_sorted_category_path_list().len(), 1);
        assert!(service.get_data_type(None).is_some());
        assert!(service.prompt_for_data_type(Some("int")).is_some());
        assert_eq!(service.find_data_types("int", &DummyMonitor).len(), 1);

        let path = DataTypePath::new(crate::program::model::data::category_path::ROOT.clone(), "int");
        assert_eq!(service.get_data_types_by_path(&path).len(), 1);
        assert!(service.get_program_data_type_by_path(&path).is_some());
    }
}
