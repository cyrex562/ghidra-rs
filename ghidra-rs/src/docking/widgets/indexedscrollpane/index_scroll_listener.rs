/// Listener notified when the visible index range or underlying index model changes.
///
/// Corresponds to `docking.widgets.indexedscrollpane.IndexScrollListener`.
///
/// Java's `BigInteger` index parameters are represented as `i128`.
/// Java's `int` pixel-offset parameters are represented as `i32`.
pub trait IndexScrollListener {
    /// Called when the range of visible indexes changes.
    ///
    /// `start_index` and `end_index` are the first and last visible logical
    /// indexes; `y_start` and `y_end` are the corresponding pixel offsets.
    fn index_range_changed(
        &mut self,
        start_index: i128,
        end_index: i128,
        y_start: i32,
        y_end: i32,
    );

    /// Called when the index model itself is replaced or reset.
    fn index_model_changed(&mut self);

    /// Called when data within the existing index model changes between
    /// `start` and `end` (inclusive).
    fn index_model_data_changed(&mut self, start: i128, end: i128);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        range_calls: Vec<(i128, i128, i32, i32)>,
        model_changed_count: usize,
        data_changed_calls: Vec<(i128, i128)>,
    }

    impl IndexScrollListener for Recorder {
        fn index_range_changed(
            &mut self,
            start_index: i128,
            end_index: i128,
            y_start: i32,
            y_end: i32,
        ) {
            self.range_calls.push((start_index, end_index, y_start, y_end));
        }

        fn index_model_changed(&mut self) {
            self.model_changed_count += 1;
        }

        fn index_model_data_changed(&mut self, start: i128, end: i128) {
            self.data_changed_calls.push((start, end));
        }
    }

    #[test]
    fn index_range_changed_records_args() {
        let mut r = Recorder::default();
        r.index_range_changed(0, 99, 0, 400);
        assert_eq!(r.range_calls, vec![(0, 99, 0, 400)]);
    }

    #[test]
    fn index_range_changed_multiple_calls() {
        let mut r = Recorder::default();
        r.index_range_changed(0, 10, 0, 100);
        r.index_range_changed(5, 15, 50, 150);
        assert_eq!(r.range_calls, vec![(0, 10, 0, 100), (5, 15, 50, 150)]);
    }

    #[test]
    fn index_model_changed_is_counted() {
        let mut r = Recorder::default();
        r.index_model_changed();
        r.index_model_changed();
        assert_eq!(r.model_changed_count, 2);
    }

    #[test]
    fn index_model_data_changed_records_args() {
        let mut r = Recorder::default();
        r.index_model_data_changed(3, 7);
        assert_eq!(r.data_changed_calls, vec![(3, 7)]);
    }

    #[test]
    fn index_model_data_changed_multiple_calls() {
        let mut r = Recorder::default();
        r.index_model_data_changed(0, 50);
        r.index_model_data_changed(100, 200);
        assert_eq!(r.data_changed_calls, vec![(0, 50), (100, 200)]);
    }

    #[test]
    fn large_index_values() {
        let mut r = Recorder::default();
        let big: i128 = i128::MAX;
        r.index_range_changed(0, big, 0, i32::MAX);
        assert_eq!(r.range_calls, vec![(0, big, 0, i32::MAX)]);
    }

    #[test]
    fn all_three_methods_independent() {
        let mut r = Recorder::default();
        r.index_range_changed(1, 2, 10, 20);
        r.index_model_changed();
        r.index_model_data_changed(1, 2);
        assert_eq!(r.range_calls.len(), 1);
        assert_eq!(r.model_changed_count, 1);
        assert_eq!(r.data_changed_calls.len(), 1);
    }
}
