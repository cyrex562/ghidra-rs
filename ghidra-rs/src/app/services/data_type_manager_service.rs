//! Service to provide list of cycle groups and data types identified as "favorites." Favorites
//! will show up on the popup menu for creating data and defining function return types and
//! parameters.
//!
//! Port of `ghidra.app.services.DataTypeManagerService`. The Java `@ServiceInfo` annotation
//! (default provider `DataTypeManagerPlugin`) has no Rust equivalent and is omitted.
//!
//! Java overloads two method names across this interface and its supertrait
//! [`DataTypeQueryService`]; Rust traits cannot overload on parameter type/arity alone, so each
//! gets a distinct name:
//! - `getDataType(TreePath)` here would collide with
//!   [`DataTypeQueryService::get_data_type`](super::data_type_query_service::DataTypeQueryService::get_data_type),
//!   so it is named [`choose_data_type_from_tree`](DataTypeManagerService::choose_data_type_from_tree).
//! - `edit(DataType)` and `edit(Composite, String)` are named
//!   [`edit`](DataTypeManagerService::edit) and
//!   [`edit_composite`](DataTypeManagerService::edit_composite) respectively.

use std::collections::HashSet;

use crate::app::seam_stubs::TreePath;
use crate::framework::seam_stubs::HelpLocation;
use crate::program::model::data::category::Category;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager_change_listener::DataTypeManagerChangeListener;

use super::data_type_archive_service::DataTypeArchiveService;
use super::data_type_query_service::DataTypeQueryService;

/// Service to provide list of cycle groups and data types identified as "favorites." Favorites
/// will show up on the popup menu for creating data and defining function return types and
/// parameters.
pub trait DataTypeManagerService: DataTypeQueryService + DataTypeArchiveService {
    /// Get the data types marked as favorites that will show up on a popup menu.
    fn get_favorites(&self) -> Vec<Box<dyn DataType>>;

    /// Adds a listener to be notified when changes occur to any open datatype manager.
    fn add_data_type_manager_change_listener(
        &mut self,
        listener: Box<dyn DataTypeManagerChangeListener>,
    );

    /// Removes the given listener from receiving dataTypeManger change notifications.
    fn remove_data_type_manager_change_listener(
        &mut self,
        listener: &dyn DataTypeManagerChangeListener,
    );

    /// Set the given data type as the most recently used to apply a data type to a Program.
    fn set_recently_used(&mut self, dt: &dyn DataType);

    /// Get the data type that was most recently used to apply data to a Program.
    fn get_recently_used(&self) -> Option<Box<dyn DataType>>;

    /// Gets the location of the help for editing the specified data type.
    fn get_editor_help_location(&self, data_type: &dyn DataType) -> Option<Box<dyn HelpLocation>>;

    /// Determine if the indicated data type can be edited (i.e. it has an editor that this
    /// service knows how to invoke).
    fn is_editable(&self, dt: &dyn DataType) -> bool;

    /// Pop up an editor window for the given data type.
    ///
    /// # Panics
    /// Ports `IllegalArgumentException`: implementations should panic if the given data type has
    /// not been resolved by a `DataTypeManager` (i.e. `DataType::get_data_type_manager` returns
    /// `None`). Built-in types cannot be edited.
    fn edit(&mut self, dt: &dyn DataType);

    /// Pop up an editor window for the given structure or union.
    ///
    /// `field_name` is the optional field name to select in the editor window.
    ///
    /// # Panics
    /// Ports `IllegalArgumentException`: implementations should panic if the given composite has
    /// not been resolved by a `DataTypeManager` (i.e. `DataType::get_data_type_manager` returns
    /// `None`).
    fn edit_composite(&mut self, composite: &dyn Composite, field_name: Option<&str>);

    /// Selects the given data type in the display of data types. `None` clears the current
    /// selection.
    fn set_data_type_selected(&mut self, data_type: Option<&dyn DataType>);

    /// Selects the given data type category in the tree of data types. This method will cause
    /// the data type tree to come to the front, scroll to the category and then to select the
    /// tree node that represents the category. If the category is `None`, the selection is
    /// cleared.
    fn set_category_selected(&mut self, category: Option<&dyn Category>);

    /// Returns the list of data types that are currently selected in the data types tree.
    fn get_selected_data_types(&self) -> Vec<Box<dyn DataType>>;

    /// Shows the user a dialog that allows them to choose a data type from a tree of all
    /// available data types.
    ///
    /// `selected_path` is an optional tree path to select in the tree.
    ///
    /// Returns a data type chosen by the user.
    fn choose_data_type_from_tree(
        &self,
        selected_path: Option<&dyn TreePath>,
    ) -> Option<Box<dyn DataType>>;

    /// Shows the user a dialog that allows them to choose a category path from a tree of all
    /// available categories.
    ///
    /// `selected_path` is an optional tree path to select in the tree.
    ///
    /// Returns a category path chosen by the user.
    fn get_category_path(&self, selected_path: Option<&dyn TreePath>) -> Option<CategoryPath>;

    /// Examines all enum dataTypes for items that match the given value. Returns a set of Strings
    /// that might make sense for the given value.
    fn get_possible_equate_names(&self, value: i64) -> HashSet<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::Archive;
    use crate::framework::model::DomainFile;
    use crate::generic::jar::ResourceFile;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_path::DataTypePath;
    use crate::program::model::listing::DataTypeArchive;
    use crate::util::task::{DummyMonitor, TaskMonitor};
    use std::path::Path;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockArchive;
    impl Archive for MockArchive {}

    struct MockComposite;
    impl DataType for MockComposite {}
    impl Composite for MockComposite {}

    struct MockCategory;
    impl Category for MockCategory {
        fn get_name(&self) -> String {
            "mock".to_string()
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
            _handler: &dyn crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler,
        ) -> Box<dyn DataType> {
            dt
        }

        fn get_category(&self, _name: &str) -> Option<Box<dyn Category>> {
            None
        }

        fn get_category_path(&self) -> CategoryPath {
            crate::program::model::data::category_path::ROOT.clone()
        }

        fn get_data_type(&self, _name: &str) -> Option<Box<dyn DataType>> {
            None
        }

        fn create_category(
            &mut self,
            _name: &str,
        ) -> Result<Box<dyn Category>, crate::util::exception::InvalidNameException> {
            Err(crate::util::exception::InvalidNameException::new())
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
        ) -> Result<(), crate::util::exception::DuplicateNameException> {
            Ok(())
        }

        fn copy_category(
            &mut self,
            _category: &dyn Category,
            _handler: &dyn crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler,
            _monitor: &dyn TaskMonitor,
        ) -> Box<dyn Category> {
            Box::new(MockCategory)
        }

        fn get_parent(&self) -> Option<Box<dyn Category>> {
            None
        }

        fn is_root(&self) -> bool {
            true
        }

        fn get_category_path_name(&self) -> String {
            "/mock".to_string()
        }

        fn get_root(&self) -> Box<dyn Category> {
            Box::new(MockCategory)
        }

        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }

        fn move_data_type(
            &mut self,
            _dt_type: Box<dyn DataType>,
            _handler: &dyn crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler,
        ) -> Result<(), crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException>
        {
            Ok(())
        }

        fn remove(&mut self, _dt_type: &dyn DataType, _monitor: &dyn TaskMonitor) -> bool {
            false
        }

        fn get_id(&self) -> i64 {
            0
        }

        fn compare_to(&self, other: &dyn Category) -> std::cmp::Ordering {
            Category::get_name(self).cmp(&other.get_name())
        }
    }

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

    impl DataTypeArchiveService for MockService {
        fn get_built_in_data_types_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }

        fn get_data_type_managers(&self) -> Vec<Box<dyn DataTypeManager>> {
            vec![Box::new(MockDataTypeManager)]
        }

        fn close_archive(&self, _dtm: &dyn DataTypeManager) {}

        fn open_data_type_archive(
            &self,
            _archive_name: &str,
        ) -> Result<Box<dyn DataTypeManager>, super::super::data_type_archive_service::OpenArchiveError>
        {
            Ok(Box::new(MockDataTypeManager))
        }

        fn open_archive(
            &self,
            _file: &ResourceFile,
            _acquire_write_lock: bool,
        ) -> Result<Box<dyn DataTypeManager>, super::super::data_type_archive_service::OpenArchiveError>
        {
            Ok(Box::new(MockDataTypeManager))
        }

        fn open_project_archive(
            &self,
            _domain_file: &dyn DomainFile,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Box<dyn DataTypeManager>,
            super::super::data_type_archive_service::OpenProjectArchiveError,
        > {
            Ok(Box::new(MockDataTypeManager))
        }

        fn open_archive_for_data_type_archive(
            &self,
            _data_type_archive: &dyn DataTypeArchive,
        ) -> Box<dyn Archive> {
            Box::new(MockArchive)
        }

        fn open_archive_file(
            &self,
            _file: &Path,
            _acquire_write_lock: bool,
        ) -> Result<Box<dyn Archive>, super::super::data_type_archive_service::OpenArchiveError>
        {
            Ok(Box::new(MockArchive))
        }
    }

    impl DataTypeManagerService for MockService {
        fn get_favorites(&self) -> Vec<Box<dyn DataType>> {
            vec![Box::new(MockDataType)]
        }

        fn add_data_type_manager_change_listener(
            &mut self,
            _listener: Box<dyn DataTypeManagerChangeListener>,
        ) {
        }

        fn remove_data_type_manager_change_listener(
            &mut self,
            _listener: &dyn DataTypeManagerChangeListener,
        ) {
        }

        fn set_recently_used(&mut self, _dt: &dyn DataType) {}

        fn get_recently_used(&self) -> Option<Box<dyn DataType>> {
            Some(Box::new(MockDataType))
        }

        fn get_editor_help_location(
            &self,
            _data_type: &dyn DataType,
        ) -> Option<Box<dyn HelpLocation>> {
            None
        }

        fn is_editable(&self, _dt: &dyn DataType) -> bool {
            true
        }

        fn edit(&mut self, _dt: &dyn DataType) {}

        fn edit_composite(&mut self, _composite: &dyn Composite, _field_name: Option<&str>) {}

        fn set_data_type_selected(&mut self, _data_type: Option<&dyn DataType>) {}

        fn set_category_selected(&mut self, _category: Option<&dyn Category>) {}

        fn get_selected_data_types(&self) -> Vec<Box<dyn DataType>> {
            vec![Box::new(MockDataType)]
        }

        fn choose_data_type_from_tree(
            &self,
            _selected_path: Option<&dyn TreePath>,
        ) -> Option<Box<dyn DataType>> {
            Some(Box::new(MockDataType))
        }

        fn get_category_path(&self, _selected_path: Option<&dyn TreePath>) -> Option<CategoryPath> {
            Some(crate::program::model::data::category_path::ROOT.clone())
        }

        fn get_possible_equate_names(&self, _value: i64) -> HashSet<String> {
            let mut names = HashSet::new();
            names.insert("ONE".to_string());
            names
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_mock_service_as_trait_object() {
        let mut service: Box<dyn DataTypeManagerService> = Box::new(MockService);

        assert_eq!(service.get_favorites().len(), 1);
        assert_eq!(service.get_selected_data_types().len(), 1);
        assert!(service.get_recently_used().is_some());
        assert!(service.is_editable(&MockDataType));
        assert!(service.get_category_path(None).is_some());
        assert_eq!(service.get_possible_equate_names(1).len(), 1);

        service.set_recently_used(&MockDataType);
        service.edit(&MockDataType);
        service.edit_composite(&MockComposite, Some("field"));
        service.set_data_type_selected(Some(&MockDataType));
        service.set_category_selected(Some(&MockCategory));
        assert!(service.choose_data_type_from_tree(None).is_some());

        // Confirm the inherited supertrait methods remain reachable through the combined object.
        assert_eq!(service.get_sorted_data_type_list().len(), 1);
        assert_eq!(service.find_data_types("int", &DummyMonitor).len(), 1);
        let _built_in = service.get_built_in_data_types_manager();
    }
}
