/// Returns `true` if any AWT thread is present in the current process.
///
/// Mirrors Java's `ThreadUtils.isAWTThreadPresent()`, which traverses the
/// root `ThreadGroup` hierarchy and returns `true` when it finds a thread
/// whose name starts with `"AWT-"`. The method exists in the GhidraServer
/// test suite to assert that server-side test code has not accidentally
/// pulled in the AWT/Swing subsystem.
///
/// On Linux, threads are discovered by reading `/proc/self/task/<tid>/comm`.
/// On other platforms the function always returns `false`: no AWT threads
/// can exist outside a JVM process.
pub fn is_awt_thread_present() -> bool {
    any_thread_name_starts_with("AWT-")
}

#[cfg(target_os = "linux")]
fn any_thread_name_starts_with(prefix: &str) -> bool {
    use std::fs;
    let Ok(task_dir) = fs::read_dir("/proc/self/task") else {
        return false;
    };
    for entry in task_dir.flatten() {
        let comm_path = entry.path().join("comm");
        if let Ok(name) = fs::read_to_string(comm_path) {
            if name.trim_end_matches('\n').starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn any_thread_name_starts_with(_prefix: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_awt_threads_present_in_rust_process() {
        // A pure Rust process never spawns AWT threads.
        assert!(!is_awt_thread_present());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_main_thread_does_not_match_awt_prefix() {
        // The main thread's comm is the binary name (≤15 chars), never "AWT-".
        assert!(!any_thread_name_starts_with("AWT-"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_nonexistent_prefix_returns_false() {
        assert!(!any_thread_name_starts_with("UNLIKELY_PREFIX_XYZ_"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_empty_prefix_matches_any_thread() {
        // Every thread has a non-empty name, so the empty prefix always matches
        // at least the current thread.
        assert!(any_thread_name_starts_with(""));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_non_linux_always_false() {
        assert!(!any_thread_name_starts_with("anything"));
    }
}
