/// The execution state of the emulator.
///
/// Corresponds to `ghidra.pcode.emulate.EmulateExecutionState`.
///
/// # Deprecation
///
/// This type is deprecated since Ghidra 12.1 and is scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmulateExecutionState {
    /// Currently stopped.
    Stopped,
    /// Currently stopped at a breakpoint.
    Breakpoint,
    /// Currently decoding instruction (i.e., generating pcode ops).
    InstructionDecode,
    /// Currently executing instruction pcode.
    Execute,
    /// Execution stopped due to a fault/error.
    Fault,
}

#[cfg(test)]
mod tests {
    #[allow(deprecated)]
    use super::EmulateExecutionState;

    #[test]
    fn variants_are_distinct() {
        let states = [
            EmulateExecutionState::Stopped,
            EmulateExecutionState::Breakpoint,
            EmulateExecutionState::InstructionDecode,
            EmulateExecutionState::Execute,
            EmulateExecutionState::Fault,
        ];
        for i in 0..states.len() {
            for j in 0..states.len() {
                assert_eq!(states[i] == states[j], i == j);
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        #[allow(deprecated)]
        let s = EmulateExecutionState::Execute;
        let cloned = s.clone();
        let copied = s;
        assert_eq!(cloned, copied);
    }

    #[test]
    fn debug_format() {
        #[allow(deprecated)]
        let s = EmulateExecutionState::Fault;
        assert_eq!(format!("{:?}", s), "Fault");
    }
}
