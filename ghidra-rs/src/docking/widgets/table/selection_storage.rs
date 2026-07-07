/// Storage for the last selected objects in a table widget.
///
/// Corresponds to `docking.widgets.table.SelectionStorage` in the Java source.
pub trait SelectionStorage<T> {
    /// Returns the list of last selected objects.
    fn get_last_selected_objects(&self) -> &[T];

    /// Sets the list of last selected objects.
    fn set_last_selected_objects(&mut self, last_selected_objects: Vec<T>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleStorage<T> {
        selected: Vec<T>,
    }

    impl<T> SimpleStorage<T> {
        fn new() -> Self {
            Self { selected: Vec::new() }
        }
    }

    impl<T> SelectionStorage<T> for SimpleStorage<T> {
        fn get_last_selected_objects(&self) -> &[T] {
            &self.selected
        }

        fn set_last_selected_objects(&mut self, last_selected_objects: Vec<T>) {
            self.selected = last_selected_objects;
        }
    }

    #[test]
    fn initially_empty() {
        let s: SimpleStorage<i32> = SimpleStorage::new();
        assert!(s.get_last_selected_objects().is_empty());
    }

    #[test]
    fn set_and_get_objects() {
        let mut s: SimpleStorage<i32> = SimpleStorage::new();
        s.set_last_selected_objects(vec![1, 2, 3]);
        assert_eq!(s.get_last_selected_objects(), &[1, 2, 3]);
    }

    #[test]
    fn overwrite_replaces_previous() {
        let mut s: SimpleStorage<&str> = SimpleStorage::new();
        s.set_last_selected_objects(vec!["a", "b"]);
        s.set_last_selected_objects(vec!["c"]);
        assert_eq!(s.get_last_selected_objects(), &["c"]);
    }

    #[test]
    fn set_empty_clears_selection() {
        let mut s: SimpleStorage<u32> = SimpleStorage::new();
        s.set_last_selected_objects(vec![10, 20]);
        s.set_last_selected_objects(vec![]);
        assert!(s.get_last_selected_objects().is_empty());
    }

    #[test]
    fn trait_object_usable() {
        let mut s: Box<dyn SelectionStorage<i32>> = Box::new(SimpleStorage::new());
        s.set_last_selected_objects(vec![7, 8]);
        assert_eq!(s.get_last_selected_objects(), &[7, 8]);
    }
}
