//! Port of `ghidra.trace.util.TraceChangeManager`.

use crate::trace::util::trace_change_record::TraceChangeRecord;

/// A component (typically a trace or one of its managers) that can record that something within
/// it has changed.
///
/// Port of `ghidra.trace.util.TraceChangeManager`.
pub trait TraceChangeManager {
    /// Marks a change, as described by `event`. Mirrors
    /// `TraceChangeManager.setChanged(TraceChangeRecord<?, ?>)`.
    fn set_changed(&mut self, event: &TraceChangeRecord);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObjectEvent;

    struct RecordingChangeManager {
        changes: usize,
    }

    impl TraceChangeManager for RecordingChangeManager {
        fn set_changed(&mut self, _event: &TraceChangeRecord) {
            self.changes += 1;
        }
    }

    fn marker_record() -> TraceChangeRecord {
        TraceChangeRecord::without_affected_object(Box::new(DomainObjectEvent::Saved), None)
    }

    #[test]
    fn trait_object_records_changes() {
        let mut owner = RecordingChangeManager { changes: 0 };
        let mgr: &mut dyn TraceChangeManager = &mut owner;

        mgr.set_changed(&marker_record());
        mgr.set_changed(&marker_record());

        assert_eq!(owner.changes, 2);
    }
}
