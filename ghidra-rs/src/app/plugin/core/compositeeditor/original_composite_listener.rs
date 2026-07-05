use crate::program::model::data::category_path::CategoryPath;

/// Listener for changes to the original composite data type.
///
/// This trait provides notification methods for when properties of the original
/// composite data type being edited have changed, including its name, category,
/// and internal components.
pub trait OriginalCompositeListener {
    /// Called when the name of the original composite data type changes.
    ///
    /// # Arguments
    /// * `new_name` - The new name for the original data type being edited
    fn original_name_changed(&self, new_name: String);

    /// Called when the category path of the original composite data type changes.
    ///
    /// # Arguments
    /// * `new_path` - The new category path where the edited data type is to be applied
    fn original_category_changed(&self, new_path: CategoryPath);

    /// Called when the components of the original composite data type change.
    fn original_components_changed(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockOriginalCompositeListener {
        name_changes: RefCell<Vec<String>>,
        category_changes: RefCell<Vec<CategoryPath>>,
        component_change_count: RefCell<u32>,
    }

    impl MockOriginalCompositeListener {
        fn new() -> Self {
            Self {
                name_changes: RefCell::new(Vec::new()),
                category_changes: RefCell::new(Vec::new()),
                component_change_count: RefCell::new(0),
            }
        }

        fn get_name_changes(&self) -> Vec<String> {
            self.name_changes.borrow().clone()
        }

        fn get_category_changes(&self) -> Vec<CategoryPath> {
            self.category_changes.borrow().clone()
        }

        fn get_component_change_count(&self) -> u32 {
            *self.component_change_count.borrow()
        }
    }

    impl OriginalCompositeListener for MockOriginalCompositeListener {
        fn original_name_changed(&self, new_name: String) {
            self.name_changes.borrow_mut().push(new_name);
        }

        fn original_category_changed(&self, new_path: CategoryPath) {
            self.category_changes.borrow_mut().push(new_path);
        }

        fn original_components_changed(&self) {
            *self.component_change_count.borrow_mut() += 1;
        }
    }

    #[test]
    fn test_original_name_changed() {
        let listener = MockOriginalCompositeListener::new();
        listener.original_name_changed("NewName".to_string());
        assert_eq!(listener.get_name_changes(), vec!["NewName"]);
    }

    #[test]
    fn test_original_name_changed_multiple() {
        let listener = MockOriginalCompositeListener::new();
        listener.original_name_changed("FirstName".to_string());
        listener.original_name_changed("SecondName".to_string());
        listener.original_name_changed("ThirdName".to_string());
        assert_eq!(
            listener.get_name_changes(),
            vec!["FirstName", "SecondName", "ThirdName"]
        );
    }

    #[test]
    fn test_original_name_changed_empty_string() {
        let listener = MockOriginalCompositeListener::new();
        listener.original_name_changed("".to_string());
        assert_eq!(listener.get_name_changes(), vec![""]);
    }

    #[test]
    fn test_original_category_changed() {
        let listener = MockOriginalCompositeListener::new();
        let path = CategoryPath::parse("/some/path").unwrap();
        listener.original_category_changed(path.clone());
        assert_eq!(listener.get_category_changes(), vec![path]);
    }

    #[test]
    fn test_original_category_changed_multiple() {
        let listener = MockOriginalCompositeListener::new();
        let path1 = CategoryPath::parse("/path/one").unwrap();
        let path2 = CategoryPath::parse("/path/two").unwrap();
        listener.original_category_changed(path1.clone());
        listener.original_category_changed(path2.clone());
        assert_eq!(listener.get_category_changes(), vec![path1, path2]);
    }

    #[test]
    fn test_original_category_changed_root() {
        let listener = MockOriginalCompositeListener::new();
        let root_path = CategoryPath::parse("/").unwrap();
        listener.original_category_changed(root_path.clone());
        assert_eq!(listener.get_category_changes(), vec![root_path]);
    }

    #[test]
    fn test_original_components_changed() {
        let listener = MockOriginalCompositeListener::new();
        listener.original_components_changed();
        assert_eq!(listener.get_component_change_count(), 1);
    }

    #[test]
    fn test_original_components_changed_multiple() {
        let listener = MockOriginalCompositeListener::new();
        listener.original_components_changed();
        listener.original_components_changed();
        listener.original_components_changed();
        assert_eq!(listener.get_component_change_count(), 3);
    }

    #[test]
    fn test_all_methods_called() {
        let listener = MockOriginalCompositeListener::new();
        listener.original_name_changed("MyType".to_string());
        let path = CategoryPath::parse("/types/custom").unwrap();
        listener.original_category_changed(path.clone());
        listener.original_components_changed();

        assert_eq!(listener.get_name_changes(), vec!["MyType"]);
        assert_eq!(listener.get_category_changes(), vec![path]);
        assert_eq!(listener.get_component_change_count(), 1);
    }
}
