/// Listener notified when tabs are added, removed, or selected in a MultiTabPanel.
///
/// This trait provides callbacks for tab lifecycle events. Implementers can track
/// when tabs are selected, added, or should be removed.
pub trait MultiTabListener<T> {
    /// Called when the given object is selected.
    ///
    /// # Arguments
    /// * `obj` - The object represented as a tab in the MultiTabPanel
    fn object_selected(&self, obj: &T);

    /// Called when the given object was added.
    ///
    /// # Arguments
    /// * `obj` - The object represented as a tab in the MultiTabPanel
    fn object_added(&self, obj: &T);

    /// Called to determine if the object's tab should be removed.
    ///
    /// # Arguments
    /// * `obj` - The object represented as a tab in the MultiTabPanel
    ///
    /// # Returns
    /// `true` if the object's tab should be removed, `false` otherwise
    fn remove_object(&self, obj: &T) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Clone, PartialEq, Debug)]
    struct TestTab {
        id: u32,
        name: String,
    }

    struct MockMultiTabListener<T> {
        selected_tabs: RefCell<Vec<T>>,
        added_tabs: RefCell<Vec<T>>,
        removed_tabs: RefCell<Vec<T>>,
        remove_filter: Box<dyn Fn(&T) -> bool>,
    }

    impl<T: Clone> MockMultiTabListener<T> {
        fn new(remove_filter: Box<dyn Fn(&T) -> bool>) -> Self {
            Self {
                selected_tabs: RefCell::new(Vec::new()),
                added_tabs: RefCell::new(Vec::new()),
                removed_tabs: RefCell::new(Vec::new()),
                remove_filter,
            }
        }

        fn selected_tabs(&self) -> Vec<T> {
            self.selected_tabs.borrow().clone()
        }

        fn added_tabs(&self) -> Vec<T> {
            self.added_tabs.borrow().clone()
        }

        fn removed_tabs(&self) -> Vec<T> {
            self.removed_tabs.borrow().clone()
        }
    }

    impl<T: Clone> MultiTabListener<T> for MockMultiTabListener<T> {
        fn object_selected(&self, obj: &T) {
            self.selected_tabs.borrow_mut().push(obj.clone());
        }

        fn object_added(&self, obj: &T) {
            self.added_tabs.borrow_mut().push(obj.clone());
        }

        fn remove_object(&self, obj: &T) -> bool {
            let should_remove = (self.remove_filter)(obj);
            if should_remove {
                self.removed_tabs.borrow_mut().push(obj.clone());
            }
            should_remove
        }
    }

    #[test]
    fn test_object_selected() {
        let listener = MockMultiTabListener::new(Box::new(|_| false));
        let tab = TestTab { id: 1, name: "Tab1".to_string() };
        listener.object_selected(&tab);
        assert_eq!(listener.selected_tabs(), vec![tab.clone()]);
    }

    #[test]
    fn test_object_selected_multiple() {
        let listener = MockMultiTabListener::new(Box::new(|_| false));
        let tab1 = TestTab { id: 1, name: "Tab1".to_string() };
        let tab2 = TestTab { id: 2, name: "Tab2".to_string() };
        listener.object_selected(&tab1);
        listener.object_selected(&tab2);
        listener.object_selected(&tab1);
        assert_eq!(listener.selected_tabs(), vec![tab1.clone(), tab2.clone(), tab1.clone()]);
    }

    #[test]
    fn test_object_added() {
        let listener = MockMultiTabListener::new(Box::new(|_| false));
        let tab = TestTab { id: 1, name: "Tab1".to_string() };
        listener.object_added(&tab);
        assert_eq!(listener.added_tabs(), vec![tab.clone()]);
    }

    #[test]
    fn test_object_added_multiple() {
        let listener = MockMultiTabListener::new(Box::new(|_| false));
        let tab1 = TestTab { id: 1, name: "Tab1".to_string() };
        let tab2 = TestTab { id: 2, name: "Tab2".to_string() };
        listener.object_added(&tab1);
        listener.object_added(&tab2);
        assert_eq!(listener.added_tabs(), vec![tab1.clone(), tab2.clone()]);
    }

    #[test]
    fn test_remove_object_returns_true() {
        let listener = MockMultiTabListener::new(Box::new(|tab: &TestTab| tab.id == 1));
        let tab1 = TestTab { id: 1, name: "Tab1".to_string() };
        let result = listener.remove_object(&tab1);
        assert!(result);
        assert_eq!(listener.removed_tabs(), vec![tab1.clone()]);
    }

    #[test]
    fn test_remove_object_returns_false() {
        let listener = MockMultiTabListener::new(Box::new(|tab: &TestTab| tab.id == 1));
        let tab2 = TestTab { id: 2, name: "Tab2".to_string() };
        let result = listener.remove_object(&tab2);
        assert!(!result);
        assert_eq!(listener.removed_tabs(), vec![]);
    }

    #[test]
    fn test_remove_object_with_filter() {
        let listener = MockMultiTabListener::new(Box::new(|tab: &TestTab| {
            tab.name.contains("remove")
        }));
        let tab1 = TestTab { id: 1, name: "keep".to_string() };
        let tab2 = TestTab { id: 2, name: "remove_me".to_string() };

        assert!(!listener.remove_object(&tab1));
        assert!(listener.remove_object(&tab2));
        assert_eq!(listener.removed_tabs(), vec![tab2]);
    }

    #[test]
    fn test_combined_operations() {
        let listener = MockMultiTabListener::new(Box::new(|tab: &TestTab| tab.id == 3));
        let tab1 = TestTab { id: 1, name: "Tab1".to_string() };
        let tab2 = TestTab { id: 2, name: "Tab2".to_string() };
        let tab3 = TestTab { id: 3, name: "Tab3".to_string() };

        listener.object_added(&tab1);
        listener.object_added(&tab2);
        listener.object_selected(&tab1);
        listener.object_added(&tab3);
        listener.object_selected(&tab3);
        let _ = listener.remove_object(&tab3);
        listener.object_selected(&tab2);

        assert_eq!(listener.added_tabs(), vec![tab1.clone(), tab2.clone(), tab3.clone()]);
        assert_eq!(listener.selected_tabs(), vec![tab1.clone(), tab3.clone(), tab2.clone()]);
        assert_eq!(listener.removed_tabs(), vec![tab3.clone()]);
    }

    #[test]
    fn test_remove_object_multiple_matching() {
        let listener = MockMultiTabListener::new(Box::new(|tab: &TestTab| tab.id > 1));
        let tab1 = TestTab { id: 1, name: "Tab1".to_string() };
        let tab2 = TestTab { id: 2, name: "Tab2".to_string() };
        let tab3 = TestTab { id: 3, name: "Tab3".to_string() };

        listener.remove_object(&tab1);
        listener.remove_object(&tab2);
        listener.remove_object(&tab3);

        assert_eq!(listener.removed_tabs(), vec![tab2, tab3]);
    }

    #[test]
    fn test_with_string_tabs() {
        let listener = MockMultiTabListener::new(Box::new(|s: &String| s == "remove"));
        listener.object_added(&"tab1".to_string());
        listener.object_selected(&"tab1".to_string());
        assert!(listener.remove_object(&"remove".to_string()));
        assert!(!listener.remove_object(&"tab1".to_string()));

        assert_eq!(listener.added_tabs(), vec!["tab1".to_string()]);
        assert_eq!(listener.selected_tabs(), vec!["tab1".to_string()]);
        assert_eq!(listener.removed_tabs(), vec!["remove".to_string()]);
    }
}
