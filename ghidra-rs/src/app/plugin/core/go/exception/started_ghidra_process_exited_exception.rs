use std::fmt;

/// Thrown when a started Ghidra process exits early during a GhidraGo launch attempt.
///
/// Java equivalent: `ghidra.app.plugin.core.go.exception.StartedGhidraProcessExitedException`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedGhidraProcessExitedException {
    pub exit_value: i32,
}

impl StartedGhidraProcessExitedException {
    pub fn new(exit_value: i32) -> Self {
        Self { exit_value }
    }
}

impl fmt::Display for StartedGhidraProcessExitedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Started Ghidra process exited early with exit-value: {}",
            self.exit_value
        )
    }
}

impl std::error::Error for StartedGhidraProcessExitedException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_is_error() {
        let e = StartedGhidraProcessExitedException::new(1);
        let _: &dyn Error = &e;
    }

    #[test]
    fn test_display() {
        let e = StartedGhidraProcessExitedException::new(1);
        assert_eq!(
            e.to_string(),
            "Started Ghidra process exited early with exit-value: 1"
        );
    }

    #[test]
    fn test_display_zero() {
        let e = StartedGhidraProcessExitedException::new(0);
        assert_eq!(
            e.to_string(),
            "Started Ghidra process exited early with exit-value: 0"
        );
    }

    #[test]
    fn test_display_negative() {
        let e = StartedGhidraProcessExitedException::new(-1);
        assert_eq!(
            e.to_string(),
            "Started Ghidra process exited early with exit-value: -1"
        );
    }

    #[test]
    fn test_exit_value_field() {
        let e = StartedGhidraProcessExitedException::new(42);
        assert_eq!(e.exit_value, 42);
    }

    #[test]
    fn test_clone_and_eq() {
        let a = StartedGhidraProcessExitedException::new(5);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ne() {
        let a = StartedGhidraProcessExitedException::new(1);
        let b = StartedGhidraProcessExitedException::new(2);
        assert_ne!(a, b);
    }

    #[test]
    fn test_source_is_none() {
        let e = StartedGhidraProcessExitedException::new(1);
        assert!(e.source().is_none());
    }
}
