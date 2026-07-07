/// Listener notified when a table item is picked (e.g. double-clicked).
///
/// Corresponds to `docking.widgets.table.TableItemPickedListener` in the Java source.
pub trait TableItemPickedListener<T> {
    /// Called when the given item is picked.
    fn item_picked(&mut self, t: T);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder<T>(Vec<T>);

    impl<T> TableItemPickedListener<T> for Recorder<T> {
        fn item_picked(&mut self, t: T) {
            self.0.push(t);
        }
    }

    #[test]
    fn records_picked_value() {
        let mut r: Recorder<i32> = Recorder(Vec::new());
        r.item_picked(42);
        assert_eq!(r.0, vec![42]);
    }

    #[test]
    fn multiple_picks_in_order() {
        let mut r: Recorder<&str> = Recorder(Vec::new());
        r.item_picked("first");
        r.item_picked("second");
        assert_eq!(r.0, vec!["first", "second"]);
    }

    #[test]
    fn trait_object_usable() {
        let mut r: Box<dyn TableItemPickedListener<i32>> = Box::new(Recorder::<i32>(Vec::new()));
        r.item_picked(7);
    }
}
