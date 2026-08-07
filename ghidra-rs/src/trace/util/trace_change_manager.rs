//! Port of `ghidra.trace.util.TraceChangeManager`.

use crate::trace::seam_stubs::TraceChangeRecord;

/// A component (typically a trace or one of its managers) that can record that something within
/// it has changed.
///
/// Port of `ghidra.trace.util.TraceChangeManager`.
pub trait TraceChangeManager {
    /// Marks a change, as described by `event`. Mirrors
    /// `TraceChangeManager.setChanged(TraceChangeRecord<?, ?>)`.
    fn set_changed(&mut self, event: Box<dyn TraceChangeRecord>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingChangeManager {
        changes: usize,
    }

    struct MarkerChangeRecord;
    impl TraceChangeRecord for MarkerChangeRecord {}

    impl TraceChangeManager for RecordingChangeManager {
        fn set_changed(&mut self, _event: Box<dyn TraceChangeRecord>) {
            self.changes += 1;
        }
    }

    #[test]
    fn trait_object_records_changes() {
        let mut owner = RecordingChangeManager { changes: 0 };
        let mgr: &mut dyn TraceChangeManager = &mut owner;

        mgr.set_changed(Box::new(MarkerChangeRecord));
        mgr.set_changed(Box::new(MarkerChangeRecord));

        assert_eq!(owner.changes, 2);
    }
}
