/// An opaque handle for a thread in the debugged JVM.
///
/// In JDI this is `com.sun.jdi.ThreadReference`; the Rust representation uses a
/// 64-bit integer as a stable, copyable handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadReference(pub u64);

/// Utility for tracking JDI thread state.
///
/// Mirrors `JdiThreadInfo` from the original Ghidra/JDI manager. All operations
/// are no-ops, matching the stub-only Java source.
pub struct JdiThreadInfo;

impl JdiThreadInfo {
    /// Registers a thread with the thread-info tracker.
    pub fn add_thread(_thread: ThreadReference) {}

    /// Removes a thread from the thread-info tracker.
    pub fn remove_thread(_thread: ThreadReference) {}

    /// Invalidates all cached thread information.
    pub fn invalidate_all() {}

    /// Sets the thread that is currently active/selected.
    pub fn set_current_thread(_thread: ThreadReference) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_reference_equality() {
        let a = ThreadReference(1);
        let b = ThreadReference(1);
        assert_eq!(a, b);
    }

    #[test]
    fn thread_reference_inequality() {
        assert_ne!(ThreadReference(1), ThreadReference(2));
    }

    #[test]
    fn thread_reference_is_copy() {
        let a = ThreadReference(42);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn thread_reference_debug() {
        assert_eq!(format!("{:?}", ThreadReference(7)), "ThreadReference(7)");
    }

    #[test]
    fn thread_reference_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ThreadReference(1));
        set.insert(ThreadReference(2));
        set.insert(ThreadReference(1));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn add_thread_does_not_panic() {
        JdiThreadInfo::add_thread(ThreadReference(1));
    }

    #[test]
    fn remove_thread_does_not_panic() {
        JdiThreadInfo::remove_thread(ThreadReference(1));
    }

    #[test]
    fn invalidate_all_does_not_panic() {
        JdiThreadInfo::invalidate_all();
    }

    #[test]
    fn set_current_thread_does_not_panic() {
        JdiThreadInfo::set_current_thread(ThreadReference(99));
    }

    #[test]
    fn add_and_remove_same_thread() {
        JdiThreadInfo::add_thread(ThreadReference(5));
        JdiThreadInfo::remove_thread(ThreadReference(5));
    }

    #[test]
    fn invalidate_then_add() {
        JdiThreadInfo::invalidate_all();
        JdiThreadInfo::add_thread(ThreadReference(10));
    }
}
