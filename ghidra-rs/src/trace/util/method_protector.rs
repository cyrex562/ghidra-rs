use std::cell::Cell;

/// Guards against reentrant calls to a protected section.
///
/// Analogous to Java's `ghidra.trace.util.MethodProtector`. A single `bool`
/// flag tracks whether the guard is currently active. Two entry-points are
/// offered:
///
/// * [`take`](MethodProtector::take) — marks the guard active for the duration
///   of the call and resets it afterwards (mirrors Java's `finally` block).
/// * [`avoid`](MethodProtector::avoid) — runs the callable only when the guard
///   is *not* active, but never modifies the flag itself.
pub struct MethodProtector {
    in_use: Cell<bool>,
}

impl MethodProtector {
    pub fn new() -> Self {
        Self {
            in_use: Cell::new(false),
        }
    }

    /// Runs `callable` while holding the guard, or returns immediately if the
    /// guard is already active.
    ///
    /// The guard is always released when `callable` returns (or propagates an
    /// error), mirroring Java's `finally` block.
    pub fn take<E, F: FnOnce() -> Result<(), E>>(&self, callable: F) -> Result<(), E> {
        if self.in_use.get() {
            return Ok(());
        }
        self.in_use.set(true);
        let _guard = ResetOnDrop(&self.in_use);
        callable()
    }

    /// Runs `callable` only when the guard is not active; never modifies the
    /// guard flag.
    pub fn avoid<E, F: FnOnce() -> Result<(), E>>(&self, callable: F) -> Result<(), E> {
        if self.in_use.get() {
            return Ok(());
        }
        callable()
    }
}

impl Default for MethodProtector {
    fn default() -> Self {
        Self::new()
    }
}

struct ResetOnDrop<'a>(&'a Cell<bool>);

impl Drop for ResetOnDrop<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_runs_callable_when_not_in_use() {
        let mp = MethodProtector::new();
        let mut called = false;
        mp.take::<(), _>(|| {
            called = true;
            Ok(())
        })
        .unwrap();
        assert!(called);
    }

    #[test]
    fn take_skips_when_already_in_use() {
        let mp = MethodProtector::new();
        let mut inner_called = false;
        mp.take::<(), _>(|| {
            // Reentrant call — must be skipped.
            mp.take::<(), _>(|| {
                inner_called = true;
                Ok(())
            })
            .unwrap();
            Ok(())
        })
        .unwrap();
        assert!(!inner_called);
    }

    #[test]
    fn take_resets_flag_after_callable_returns() {
        let mp = MethodProtector::new();
        mp.take::<(), _>(|| Ok(())).unwrap();
        // A second outer call must still run.
        let mut called = false;
        mp.take::<(), _>(|| {
            called = true;
            Ok(())
        })
        .unwrap();
        assert!(called);
    }

    #[test]
    fn take_resets_flag_after_error() {
        let mp = MethodProtector::new();
        let result = mp.take::<&str, _>(|| Err("boom"));
        assert_eq!(result, Err("boom"));
        // Flag must be cleared so a subsequent call runs.
        let mut called = false;
        mp.take::<(), _>(|| {
            called = true;
            Ok(())
        })
        .unwrap();
        assert!(called);
    }

    #[test]
    fn avoid_runs_callable_when_not_in_use() {
        let mp = MethodProtector::new();
        let mut called = false;
        mp.avoid::<(), _>(|| {
            called = true;
            Ok(())
        })
        .unwrap();
        assert!(called);
    }

    #[test]
    fn avoid_skips_when_in_use() {
        let mp = MethodProtector::new();
        let mut inner_called = false;
        mp.take::<(), _>(|| {
            mp.avoid::<(), _>(|| {
                inner_called = true;
                Ok(())
            })
            .unwrap();
            Ok(())
        })
        .unwrap();
        assert!(!inner_called);
    }

    #[test]
    fn avoid_does_not_set_flag() {
        // After avoid() runs, the flag should still be false — a subsequent
        // take() must be able to set it and run.
        let mp = MethodProtector::new();
        let mut outer_called = false;
        let mut inner_called = false;
        mp.avoid::<(), _>(|| {
            outer_called = true;
            Ok(())
        })
        .unwrap();
        mp.take::<(), _>(|| {
            inner_called = true;
            Ok(())
        })
        .unwrap();
        assert!(outer_called);
        assert!(inner_called);
    }
}
