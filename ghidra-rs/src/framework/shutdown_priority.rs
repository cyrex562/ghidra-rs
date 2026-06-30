/// Priority used to order shutdown hooks; lower values run first.
///
/// Named constants cover common shutdown phases. Use [`before`](ShutdownPriority::before)
/// and [`after`](ShutdownPriority::after) to obtain adjacent priorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShutdownPriority {
    priority: i32,
}

impl ShutdownPriority {
    /// Runs before any other shutdown hook.
    pub const FIRST: ShutdownPriority = ShutdownPriority { priority: i32::MIN };

    /// Priority for hooks that dispose database resources.
    pub const DISPOSE_DATABASES: ShutdownPriority =
        ShutdownPriority { priority: i32::MAX / 2 };

    /// Priority for hooks that close file handles.
    pub const DISPOSE_FILE_HANDLES: ShutdownPriority =
        ShutdownPriority { priority: i32::MAX / 2 };

    /// Priority for the shutdown-logging hook.
    pub const SHUTDOWN_LOGGING: ShutdownPriority =
        ShutdownPriority { priority: i32::MAX / 2 };

    /// Runs after every other shutdown hook.
    pub const LAST: ShutdownPriority = ShutdownPriority { priority: i32::MAX };

    pub(crate) fn new(priority: i32) -> Self {
        Self { priority }
    }

    /// Returns the priority immediately before this one, or `None` at [`FIRST`](Self::FIRST).
    pub fn before(&self) -> Option<ShutdownPriority> {
        if self.priority == i32::MIN {
            None
        } else {
            Some(ShutdownPriority {
                priority: self.priority - 1,
            })
        }
    }

    /// Returns the priority immediately after this one, or `None` at [`LAST`](Self::LAST).
    pub fn after(&self) -> Option<ShutdownPriority> {
        if self.priority == i32::MAX {
            None
        } else {
            Some(ShutdownPriority {
                priority: self.priority + 1,
            })
        }
    }

    pub(crate) fn priority(&self) -> i32 {
        self.priority
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_ordering() {
        assert!(ShutdownPriority::FIRST < ShutdownPriority::DISPOSE_DATABASES);
        assert!(ShutdownPriority::DISPOSE_DATABASES < ShutdownPriority::LAST);
    }

    #[test]
    fn test_named_mid_constants_equal() {
        assert_eq!(
            ShutdownPriority::DISPOSE_DATABASES,
            ShutdownPriority::DISPOSE_FILE_HANDLES
        );
        assert_eq!(
            ShutdownPriority::DISPOSE_DATABASES,
            ShutdownPriority::SHUTDOWN_LOGGING
        );
    }

    #[test]
    fn test_after_increments() {
        let p = ShutdownPriority::FIRST.after().unwrap();
        assert_eq!(p.priority(), i32::MIN + 1);
    }

    #[test]
    fn test_before_decrements() {
        let p = ShutdownPriority::LAST.before().unwrap();
        assert_eq!(p.priority(), i32::MAX - 1);
    }

    #[test]
    fn test_before_at_first_returns_none() {
        assert!(ShutdownPriority::FIRST.before().is_none());
    }

    #[test]
    fn test_after_at_last_returns_none() {
        assert!(ShutdownPriority::LAST.after().is_none());
    }

    #[test]
    fn test_before_after_roundtrip() {
        let base = ShutdownPriority::new(0);
        assert_eq!(base.after().unwrap().before().unwrap(), base);
        assert_eq!(base.before().unwrap().after().unwrap(), base);
    }

    #[test]
    fn test_priority_accessor() {
        assert_eq!(ShutdownPriority::FIRST.priority(), i32::MIN);
        assert_eq!(ShutdownPriority::LAST.priority(), i32::MAX);
    }
}
