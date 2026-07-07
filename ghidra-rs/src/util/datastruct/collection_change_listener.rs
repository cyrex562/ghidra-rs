/// Listener for changes to a collection — element added, removed, or modified.
///
/// All methods have empty default implementations so implementors only override what they need.
pub trait CollectionChangeListener<E> {
    fn element_added(&mut self, _element: &E) {}
    fn element_removed(&mut self, _element: &E) {}
    fn element_modified(&mut self, _element: &E) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        added: Vec<i32>,
        removed: Vec<i32>,
        modified: Vec<i32>,
    }

    impl Recorder {
        fn new() -> Self {
            Self { added: vec![], removed: vec![], modified: vec![] }
        }
    }

    impl CollectionChangeListener<i32> for Recorder {
        fn element_added(&mut self, element: &i32) {
            self.added.push(*element);
        }
        fn element_removed(&mut self, element: &i32) {
            self.removed.push(*element);
        }
        fn element_modified(&mut self, element: &i32) {
            self.modified.push(*element);
        }
    }

    #[test]
    fn test_all_callbacks_dispatched() {
        let mut r = Recorder::new();
        r.element_added(&1);
        r.element_removed(&2);
        r.element_modified(&3);
        assert_eq!(r.added, vec![1]);
        assert_eq!(r.removed, vec![2]);
        assert_eq!(r.modified, vec![3]);
    }

    #[test]
    fn test_default_impl_is_noop() {
        struct NoOp;
        impl CollectionChangeListener<i32> for NoOp {}
        let mut l = NoOp;
        // none of these should panic
        l.element_added(&1);
        l.element_removed(&2);
        l.element_modified(&3);
    }

    #[test]
    fn test_multiple_events() {
        let mut r = Recorder::new();
        for i in 0..5 {
            r.element_added(&i);
        }
        assert_eq!(r.added, vec![0, 1, 2, 3, 4]);
        assert!(r.removed.is_empty());
        assert!(r.modified.is_empty());
    }
}
