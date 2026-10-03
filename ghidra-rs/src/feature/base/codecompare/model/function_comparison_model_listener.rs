use crate::program::model::listing::function::Function;
use crate::util::datastruct::duo::Side;

/// Allows subscribers to register for `FunctionComparisonModel` changes.
///
/// Port of `ghidra.features.base.codecompare.model.FunctionComparisonModelListener`. Java is an
/// `interface` with 2 abstract methods and 2 in-repo implementors, so this becomes a `trait`
/// (rule R-interface-open-ext-point).
pub trait FunctionComparisonModelListener {
    /// Notification that the selected function changed on one side or the other.
    fn active_function_changed(&mut self, side: Side, function: Option<&dyn Function>);

    /// Notification that the set of functions on at least one side changed. The selected
    /// functions on either side may have also changed.
    fn model_data_changed(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingListener {
        active_changes: Vec<(Side, bool)>,
        data_changed_count: usize,
    }

    impl FunctionComparisonModelListener for RecordingListener {
        fn active_function_changed(&mut self, side: Side, function: Option<&dyn Function>) {
            self.active_changes.push((side, function.is_some()));
        }

        fn model_data_changed(&mut self) {
            self.data_changed_count += 1;
        }
    }

    #[test]
    fn active_function_changed_records_side_and_presence() {
        let mut listener = RecordingListener::default();
        listener.active_function_changed(Side::Left, None);
        assert_eq!(listener.active_changes, vec![(Side::Left, false)]);
    }

    #[test]
    fn model_data_changed_increments_count() {
        let mut listener = RecordingListener::default();
        listener.model_data_changed();
        listener.model_data_changed();
        assert_eq!(listener.data_changed_count, 2);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listener: Box<dyn FunctionComparisonModelListener> =
            Box::new(RecordingListener::default());
        listener.active_function_changed(Side::Right, None);
        listener.model_data_changed();
    }
}
