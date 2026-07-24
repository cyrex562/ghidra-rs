use crate::program::seam_stubs::InstructionError;

/// Trait for handling conflicts detected during disassembly.
pub trait DisassemblerConflictHandler: Send + Sync {
    /// Called to report an instruction error/conflict detected during disassembly.
    fn mark_instruction_error(&self, conflict: &dyn InstructionError);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct DummyInstructionError;

    impl InstructionError for DummyInstructionError {}

    struct RecordingHandler {
        calls: AtomicU32,
    }

    impl DisassemblerConflictHandler for RecordingHandler {
        fn mark_instruction_error(&self, _conflict: &dyn InstructionError) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn records_reported_conflicts() {
        let handler = RecordingHandler { calls: AtomicU32::new(0) };
        let conflict = DummyInstructionError;
        handler.mark_instruction_error(&conflict);
        handler.mark_instruction_error(&conflict);
        assert_eq!(handler.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn works_as_trait_object() {
        let handler: Box<dyn DisassemblerConflictHandler> =
            Box::new(RecordingHandler { calls: AtomicU32::new(0) });
        let conflict = DummyInstructionError;
        handler.mark_instruction_error(&conflict);
    }

    #[test]
    fn works_as_arc_trait_object() {
        let recording = Arc::new(RecordingHandler { calls: AtomicU32::new(0) });
        let handler: Arc<dyn DisassemblerConflictHandler> = recording.clone();
        let conflict = DummyInstructionError;
        handler.mark_instruction_error(&conflict);
        assert_eq!(recording.calls.load(Ordering::SeqCst), 1);
    }
}
