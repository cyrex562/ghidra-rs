/// The execution state of a debug target object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceExecutionState {
    /// The object has been created, but is not yet alive.
    ///
    /// This may apply, e.g., to a GDB "Inferior," which has not yet been used to launch or
    /// attach to a process.
    Inactive,

    /// The object is alive, but its execution state is unspecified.
    ///
    /// Implementations should use [`TraceExecutionState::Stopped`] and
    /// [`TraceExecutionState::Running`] whenever possible. For some objects, e.g., a process,
    /// this is conventionally determined by its parts, e.g., threads: A process is running when
    /// *any* of its threads are running. It is stopped when *all* of its threads are stopped.
    Alive,

    /// The object is alive, but not executing.
    Stopped,

    /// The object is alive and executing.
    ///
    /// "Running" is loosely defined. For example, with respect to a thread, it may indicate the
    /// thread is currently executing, waiting on an event, or scheduled for execution. It does
    /// not necessarily mean it is executing on a CPU at this exact moment.
    Running,

    /// The object is no longer alive.
    ///
    /// The object still exists but no longer represents something alive. This could be used for
    /// stale handles to objects which may still be queried (e.g., for a process exit code), or
    /// e.g., a GDB "Inferior," which could be re-used to launch or attach to another process.
    Terminated,
}

#[cfg(test)]
mod tests {
    use super::TraceExecutionState;

    #[test]
    fn all_variants_distinct() {
        let states = [
            TraceExecutionState::Inactive,
            TraceExecutionState::Alive,
            TraceExecutionState::Stopped,
            TraceExecutionState::Running,
            TraceExecutionState::Terminated,
        ];
        for i in 0..states.len() {
            for j in 0..states.len() {
                if i == j {
                    assert_eq!(states[i], states[j]);
                } else {
                    assert_ne!(states[i], states[j]);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let s = TraceExecutionState::Running;
        let cloned = s;
        assert_eq!(s, cloned);
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", TraceExecutionState::Inactive), "Inactive");
        assert_eq!(format!("{:?}", TraceExecutionState::Alive), "Alive");
        assert_eq!(format!("{:?}", TraceExecutionState::Stopped), "Stopped");
        assert_eq!(format!("{:?}", TraceExecutionState::Running), "Running");
        assert_eq!(format!("{:?}", TraceExecutionState::Terminated), "Terminated");
    }

    #[test]
    fn hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TraceExecutionState::Inactive);
        set.insert(TraceExecutionState::Running);
        set.insert(TraceExecutionState::Running);
        assert_eq!(set.len(), 2);
    }
}
