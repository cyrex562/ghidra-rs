use crate::framework::model::DomainObjectChangeRecord;

/// Listener notified of changes to a trace database.
///
/// Port of `ghidra.trace.database.DBTraceDirectChangeListener`.
pub trait DbTraceDirectChangeListener {
    /// Called when a change is made to the trace.
    ///
    /// # Arguments
    /// * `rec` - The change record describing what changed
    fn changed(&mut self, rec: &DomainObjectChangeRecord);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::{DomainObjectChangeRecord, DomainObjectEvent};

    struct RecordingListener {
        changes: Vec<String>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                changes: Vec::new(),
            }
        }
    }

    impl DbTraceDirectChangeListener for RecordingListener {
        fn changed(&mut self, rec: &DomainObjectChangeRecord) {
            self.changes.push(format!("Change: {}", rec));
        }
    }

    #[test]
    fn test_listener_called_on_change() {
        let mut listener = RecordingListener::new();
        let rec = DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved));

        listener.changed(&rec);

        assert_eq!(listener.changes.len(), 1);
        assert!(listener.changes[0].contains("Change:"));
    }

    #[test]
    fn test_listener_records_multiple_changes() {
        let mut listener = RecordingListener::new();
        let rec1 = DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::Saved));
        let rec2 = DomainObjectChangeRecord::new(Box::new(DomainObjectEvent::PropertyChanged));

        listener.changed(&rec1);
        listener.changed(&rec2);

        assert_eq!(listener.changes.len(), 2);
    }

    #[test]
    fn test_listener_with_change_record_values() {
        let mut listener = RecordingListener::new();
        let rec = DomainObjectChangeRecord::with_values(
            Box::new(DomainObjectEvent::PropertyChanged),
            Some(Box::new("old_value".to_string())),
            Some(Box::new("new_value".to_string())),
        );

        listener.changed(&rec);

        assert_eq!(listener.changes.len(), 1);
        assert!(listener.changes[0].contains("old"));
        assert!(listener.changes[0].contains("new"));
    }
}
