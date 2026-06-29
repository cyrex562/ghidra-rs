/// Listener for changes to a Field or set of Fields.
///
/// Corresponds to `docking.widgets.fieldpanel.listener.FieldListener`.
pub trait FieldListener {
    /// Notifies the listener when the set of indexes changes — either the number
    /// of indexes or the fundamental data types associated with those indexes.
    fn index_set_changed(&mut self);

    /// Notifies the listener that data in the models has changed within the given
    /// index range.
    fn data_changed(&mut self, min: i32, max: i32);

    /// Notifies the listener that the width of this field has changed.
    fn width_changed(&mut self, width: i32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        index_set_changed_count: u32,
        data_changed_calls: Vec<(i32, i32)>,
        width_changed_calls: Vec<i32>,
    }

    impl FieldListener for Recorder {
        fn index_set_changed(&mut self) {
            self.index_set_changed_count += 1;
        }

        fn data_changed(&mut self, min: i32, max: i32) {
            self.data_changed_calls.push((min, max));
        }

        fn width_changed(&mut self, width: i32) {
            self.width_changed_calls.push(width);
        }
    }

    #[test]
    fn index_set_changed_invoked() {
        let mut r = Recorder::default();
        r.index_set_changed();
        assert_eq!(r.index_set_changed_count, 1);
    }

    #[test]
    fn index_set_changed_multiple_times() {
        let mut r = Recorder::default();
        r.index_set_changed();
        r.index_set_changed();
        r.index_set_changed();
        assert_eq!(r.index_set_changed_count, 3);
    }

    #[test]
    fn data_changed_records_range() {
        let mut r = Recorder::default();
        r.data_changed(0, 10);
        assert_eq!(r.data_changed_calls, vec![(0, 10)]);
    }

    #[test]
    fn data_changed_multiple_calls() {
        let mut r = Recorder::default();
        r.data_changed(0, 5);
        r.data_changed(6, 20);
        assert_eq!(r.data_changed_calls, vec![(0, 5), (6, 20)]);
    }

    #[test]
    fn data_changed_same_min_max() {
        let mut r = Recorder::default();
        r.data_changed(7, 7);
        assert_eq!(r.data_changed_calls, vec![(7, 7)]);
    }

    #[test]
    fn width_changed_records_value() {
        let mut r = Recorder::default();
        r.width_changed(100);
        assert_eq!(r.width_changed_calls, vec![100]);
    }

    #[test]
    fn width_changed_multiple_calls() {
        let mut r = Recorder::default();
        r.width_changed(50);
        r.width_changed(200);
        assert_eq!(r.width_changed_calls, vec![50, 200]);
    }
}
