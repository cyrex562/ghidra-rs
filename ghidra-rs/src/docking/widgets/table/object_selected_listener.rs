/// Listener notified when an object is selected or the selection is cleared.
///
/// Corresponds to `docking.widgets.table.ObjectSelectedListener` in the Java source.
pub trait ObjectSelectedListener<T> {
    /// Called when an object is selected, or with `None` when the selection is cleared.
    fn object_selected(&mut self, t: Option<T>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder<T>(Vec<Option<T>>);

    impl<T: Clone> ObjectSelectedListener<T> for Recorder<T> {
        fn object_selected(&mut self, t: Option<T>) {
            self.0.push(t);
        }
    }

    #[test]
    fn records_selected_value() {
        let mut r: Recorder<i32> = Recorder(Vec::new());
        r.object_selected(Some(42));
        assert_eq!(r.0, vec![Some(42)]);
    }

    #[test]
    fn records_cleared_selection() {
        let mut r: Recorder<i32> = Recorder(Vec::new());
        r.object_selected(None);
        assert_eq!(r.0, vec![None]);
    }

    #[test]
    fn multiple_selections_in_order() {
        let mut r: Recorder<&str> = Recorder(Vec::new());
        r.object_selected(Some("first"));
        r.object_selected(None);
        r.object_selected(Some("second"));
        assert_eq!(r.0, vec![Some("first"), None, Some("second")]);
    }

    #[test]
    fn trait_object_usable() {
        let mut r: Box<dyn ObjectSelectedListener<i32>> = Box::new(Recorder::<i32>(Vec::new()));
        r.object_selected(Some(7));
        r.object_selected(None);
    }
}
