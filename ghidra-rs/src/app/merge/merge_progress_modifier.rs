/// Updates the progress panel during a merge operation.
///
/// Mirrors `ghidra.app.merge.MergeProgressModifier`. Provides methods to notify the UI
/// of progress updates during merge operations, including progress messages, percentages,
/// and phase transitions.
pub trait MergeProgressModifier {
    /// Updates the current phase progress area with a message.
    ///
    /// # Arguments
    /// * `progress_message` - A message indicating what is currently occurring in this phase.
    ///   `None` indicates to use the default message.
    fn update_progress_message(&self, progress_message: Option<&str>);

    /// Updates the current phase progress area with a percentage.
    ///
    /// # Arguments
    /// * `current_progress_percentage` - The progress percentage completed for the current phase.
    ///   This should be a value from 0 to 100.
    fn update_progress_percentage(&self, current_progress_percentage: i32);

    /// Updates the current phase progress area with both percentage and message.
    ///
    /// # Arguments
    /// * `current_progress_percentage` - The progress percentage completed for the current phase.
    ///   This should be a value from 0 to 100.
    /// * `progress_message` - A message indicating what is currently occurring in this phase.
    fn update_progress_with_message(&self, current_progress_percentage: i32, progress_message: &str);

    /// Mark a merge phase as in progress.
    ///
    /// The manager (MergeResolver) for a particular merge phase should call this when its
    /// phase or sub-phase begins. The string slice should match one that is returned by
    /// `MergeResolver::get_phases()`.
    ///
    /// # Arguments
    /// * `merge_phase` - Identifier path for the merge phase to change to in progress status.
    fn set_in_progress(&self, merge_phase: &[String]);

    /// Mark a merge phase as completed.
    ///
    /// The manager (MergeResolver) for a particular merge phase should call this when its
    /// phase or sub-phase completes. The string slice should match one that is returned by
    /// `MergeResolver::get_phases()`.
    ///
    /// # Arguments
    /// * `merge_phase` - Identifier path for the merge phase to change to completed status.
    fn set_completed(&self, merge_phase: &[String]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct TestModifier {
        progress_messages: Arc<Mutex<Vec<Option<String>>>>,
        progress_percentages: Arc<Mutex<Vec<i32>>>,
        messages_with_percentages: Arc<Mutex<Vec<(i32, String)>>>,
        in_progress_phases: Arc<Mutex<Vec<Vec<String>>>>,
        completed_phases: Arc<Mutex<Vec<Vec<String>>>>,
    }

    impl TestModifier {
        fn new() -> Self {
            Self {
                progress_messages: Arc::new(Mutex::new(Vec::new())),
                progress_percentages: Arc::new(Mutex::new(Vec::new())),
                messages_with_percentages: Arc::new(Mutex::new(Vec::new())),
                in_progress_phases: Arc::new(Mutex::new(Vec::new())),
                completed_phases: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl MergeProgressModifier for TestModifier {
        fn update_progress_message(&self, progress_message: Option<&str>) {
            self.progress_messages
                .lock()
                .unwrap()
                .push(progress_message.map(|s| s.to_string()));
        }

        fn update_progress_percentage(&self, current_progress_percentage: i32) {
            self.progress_percentages
                .lock()
                .unwrap()
                .push(current_progress_percentage);
        }

        fn update_progress_with_message(&self, current_progress_percentage: i32, progress_message: &str) {
            self.messages_with_percentages
                .lock()
                .unwrap()
                .push((current_progress_percentage, progress_message.to_string()));
        }

        fn set_in_progress(&self, merge_phase: &[String]) {
            self.in_progress_phases
                .lock()
                .unwrap()
                .push(merge_phase.to_vec());
        }

        fn set_completed(&self, merge_phase: &[String]) {
            self.completed_phases
                .lock()
                .unwrap()
                .push(merge_phase.to_vec());
        }
    }

    #[test]
    fn test_update_progress_message_with_content() {
        let modifier = TestModifier::new();
        modifier.update_progress_message(Some("Processing"));

        let messages = modifier.progress_messages.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], Some("Processing".to_string()));
    }

    #[test]
    fn test_update_progress_message_with_none() {
        let modifier = TestModifier::new();
        modifier.update_progress_message(None);

        let messages = modifier.progress_messages.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], None);
    }

    #[test]
    fn test_update_progress_percentage() {
        let modifier = TestModifier::new();
        modifier.update_progress_percentage(50);

        let percentages = modifier.progress_percentages.lock().unwrap();
        assert_eq!(percentages.len(), 1);
        assert_eq!(percentages[0], 50);
    }

    #[test]
    fn test_update_progress_percentage_boundaries() {
        let modifier = TestModifier::new();
        modifier.update_progress_percentage(0);
        modifier.update_progress_percentage(100);

        let percentages = modifier.progress_percentages.lock().unwrap();
        assert_eq!(percentages.len(), 2);
        assert_eq!(percentages[0], 0);
        assert_eq!(percentages[1], 100);
    }

    #[test]
    fn test_update_progress_with_message() {
        let modifier = TestModifier::new();
        modifier.update_progress_with_message(75, "Merging structures");

        let messages = modifier.messages_with_percentages.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].0, 75);
        assert_eq!(messages[0].1, "Merging structures");
    }

    #[test]
    fn test_set_in_progress_simple_phase() {
        let modifier = TestModifier::new();
        let phase = vec!["Phase A".to_string()];
        modifier.set_in_progress(&phase);

        let phases = modifier.in_progress_phases.lock().unwrap();
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0], phase);
    }

    #[test]
    fn test_set_in_progress_nested_phase() {
        let modifier = TestModifier::new();
        let phase = vec!["Phase A".to_string(), "Sub-Phase 1".to_string()];
        modifier.set_in_progress(&phase);

        let phases = modifier.in_progress_phases.lock().unwrap();
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0], phase);
    }

    #[test]
    fn test_set_completed_simple_phase() {
        let modifier = TestModifier::new();
        let phase = vec!["Phase B".to_string()];
        modifier.set_completed(&phase);

        let phases = modifier.completed_phases.lock().unwrap();
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0], phase);
    }

    #[test]
    fn test_set_completed_nested_phase() {
        let modifier = TestModifier::new();
        let phase = vec!["Phase B".to_string(), "Sub-Phase 2".to_string()];
        modifier.set_completed(&phase);

        let phases = modifier.completed_phases.lock().unwrap();
        assert_eq!(phases.len(), 1);
        assert_eq!(phases[0], phase);
    }

    #[test]
    fn test_multiple_operations() {
        let modifier = TestModifier::new();

        let phase_a = vec!["Phase A".to_string()];
        modifier.set_in_progress(&phase_a);
        modifier.update_progress_message(Some("Starting"));
        modifier.update_progress_percentage(25);
        modifier.update_progress_with_message(50, "Halfway");
        modifier.set_completed(&phase_a);

        assert_eq!(modifier.in_progress_phases.lock().unwrap().len(), 1);
        assert_eq!(modifier.progress_messages.lock().unwrap().len(), 1);
        assert_eq!(modifier.progress_percentages.lock().unwrap().len(), 1);
        assert_eq!(modifier.messages_with_percentages.lock().unwrap().len(), 1);
        assert_eq!(modifier.completed_phases.lock().unwrap().len(), 1);
    }
}
