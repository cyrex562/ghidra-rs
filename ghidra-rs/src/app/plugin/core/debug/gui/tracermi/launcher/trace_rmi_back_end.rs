use std::sync::{Arc, Mutex};

use crate::app::plugin::core::terminal::TerminalListener;

/// A listener that completes when a terminal is terminated, capturing the exit code.
///
/// Maps to `ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiBackEnd`.
pub struct TraceRmiBackEnd {
    exit_code: Arc<Mutex<Option<i32>>>,
}

impl TraceRmiBackEnd {
    /// Creates a new `TraceRmiBackEnd`.
    pub fn new() -> Self {
        TraceRmiBackEnd {
            exit_code: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns the exit code if the terminal has been terminated, or `None` if not yet terminated.
    pub fn get(&self) -> Option<i32> {
        self.exit_code.lock().unwrap().as_ref().copied()
    }
}

impl Default for TraceRmiBackEnd {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalListener for TraceRmiBackEnd {
    fn terminated(&mut self, exitcode: i32) {
        *self.exit_code.lock().unwrap() = Some(exitcode);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_no_exit_code() {
        let backend = TraceRmiBackEnd::new();
        assert_eq!(backend.get(), None);
    }

    #[test]
    fn terminated_stores_exit_code() {
        let mut backend = TraceRmiBackEnd::new();
        backend.terminated(0);
        assert_eq!(backend.get(), Some(0));
    }

    #[test]
    fn terminated_with_nonzero_exit_code() {
        let mut backend = TraceRmiBackEnd::new();
        backend.terminated(42);
        assert_eq!(backend.get(), Some(42));
    }

    #[test]
    fn terminated_with_negative_exit_code() {
        let mut backend = TraceRmiBackEnd::new();
        backend.terminated(-1);
        assert_eq!(backend.get(), Some(-1));
    }

    #[test]
    fn default_creates_uninitialized_backend() {
        let backend = TraceRmiBackEnd::default();
        assert_eq!(backend.get(), None);
    }

    #[test]
    fn terminated_replaces_previous_exit_code() {
        let mut backend = TraceRmiBackEnd::new();
        backend.terminated(1);
        assert_eq!(backend.get(), Some(1));
        backend.terminated(42);
        assert_eq!(backend.get(), Some(42));
    }

    #[test]
    fn cloned_backend_shares_state() {
        let backend1 = TraceRmiBackEnd::new();
        let backend2 = TraceRmiBackEnd {
            exit_code: backend1.exit_code.clone(),
        };
        let mut backend1_mut = backend1;
        backend1_mut.terminated(99);
        assert_eq!(backend2.get(), Some(99));
    }
}
