use std::cell::{Cell, RefCell};

/// A means of detecting and handling reentrant conditions.
///
/// One example where this has been applied deals with updating actions upon changes in context.
/// If, in the course of determining which actions are enabled, one of the `is_enabled` methods
/// displays an error dialog, the thread reenters its main loop while that dialog is showing,
/// but before `is_enabled` has returned. This can cause all sorts of unexpected behaviors.
///
/// This implementation is **not** thread-safe. It is designed to check for reentrant access,
/// not concurrent access. The caller must ensure that only one thread enters the guarded block
/// or calls [`check_access`](ReentryGuard::check_access) at a time.
///
/// The `violated` closure is called whenever reentrant access is detected. It receives
/// `(nested, previous)`: `nested` is `true` when the violation is a re-entry into
/// [`enter`](ReentryGuard::enter) itself; `previous` carries the prior recorded violation, if any.
/// Its return value becomes the new violation record.
pub struct ReentryGuard<T, F>
where
    F: Fn(bool, Option<T>) -> Option<T>,
{
    in_guarded: Cell<bool>,
    violation: RefCell<Option<T>>,
    violated_fn: F,
}

/// RAII token returned by [`ReentryGuard::enter`]. Exiting the guarded block is signalled by
/// dropping this value.
pub struct Guarded<'a, T, F>
where
    F: Fn(bool, Option<T>) -> Option<T>,
{
    guard: &'a ReentryGuard<T, F>,
}

impl<T, F> Drop for Guarded<'_, T, F>
where
    F: Fn(bool, Option<T>) -> Option<T>,
{
    fn drop(&mut self) {
        self.guard.in_guarded.set(false);
    }
}

impl<T, F> ReentryGuard<T, F>
where
    F: Fn(bool, Option<T>) -> Option<T>,
{
    /// Creates a new `ReentryGuard` with the given violation handler.
    pub fn new(violated: F) -> Self {
        Self {
            in_guarded: Cell::new(false),
            violation: RefCell::new(None),
            violated_fn: violated,
        }
    }

    /// Notifies the guard of entry into the guarded block.
    ///
    /// The returned [`Guarded`] token must be held for the duration of the guarded block; dropping
    /// it exits the block. Returns `None` if already inside the guarded block (a reentrant entry),
    /// and records the violation via the handler passed to [`new`](Self::new).
    pub fn enter(&self) -> Option<Guarded<'_, T, F>> {
        if self.in_guarded.get() {
            let mut v = self.violation.borrow_mut();
            let prev = v.take();
            *v = (self.violated_fn)(true, prev);
            return None;
        }
        self.in_guarded.set(true);
        *self.violation.borrow_mut() = None;
        Some(Guarded { guard: self })
    }

    /// Notifies the guard of access to some resource used by the guarded block.
    ///
    /// If the access is reentrant (the current call stack includes a frame inside the guarded
    /// block) this calls the violation handler and records the result.
    pub fn check_access(&self) {
        if self.in_guarded.get() {
            let mut v = self.violation.borrow_mut();
            let prev = v.take();
            *v = (self.violated_fn)(false, prev);
        }
    }

    /// Returns a borrow of the current violation value, if any.
    ///
    /// Calling this outside a guarded block has undefined behaviour (matching the Java source).
    pub fn get_violation(&self) -> std::cell::Ref<'_, Option<T>> {
        self.violation.borrow()
    }

    /// Returns `true` if a violation has been recorded.
    ///
    /// Equivalent to checking whether [`get_violation`](Self::get_violation) is `Some`.
    pub fn is_violated(&self) -> bool {
        self.violation.borrow().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_returns_guarded_when_not_in_block() {
        let guard = ReentryGuard::new(|_nested, prev| prev.or(Some("violated")));
        let token = guard.enter();
        assert!(token.is_some());
        assert!(!guard.is_violated());
    }

    #[test]
    fn guarded_drop_exits_block() {
        let guard = ReentryGuard::new(|_, prev| prev.or(Some("v")));
        {
            let _token = guard.enter().unwrap();
            // inside guarded block
        }
        // after drop we can enter again
        let token = guard.enter();
        assert!(token.is_some());
    }

    #[test]
    fn reentrant_enter_returns_none_and_records_violation() {
        let guard = ReentryGuard::new(|nested, prev| {
            assert!(nested);
            prev.or(Some("nested violation"))
        });
        let _token = guard.enter().unwrap();
        let inner = guard.enter();
        assert!(inner.is_none());
        assert!(guard.is_violated());
        assert_eq!(*guard.get_violation(), Some("nested violation"));
    }

    #[test]
    fn check_access_outside_guarded_does_nothing() {
        let guard = ReentryGuard::new(|_, _| Some("v"));
        guard.check_access();
        assert!(!guard.is_violated());
    }

    #[test]
    fn check_access_inside_guarded_records_violation() {
        let guard = ReentryGuard::new(|nested, prev| {
            assert!(!nested);
            prev.or(Some("access violation"))
        });
        let _token = guard.enter().unwrap();
        guard.check_access();
        assert!(guard.is_violated());
        assert_eq!(*guard.get_violation(), Some("access violation"));
    }

    #[test]
    fn second_violation_passes_previous_to_handler() {
        let guard: ReentryGuard<u32, _> = ReentryGuard::new(|_nested, prev| {
            Some(prev.map_or(1, |p| p + 1))
        });
        let _token = guard.enter().unwrap();
        guard.check_access(); // first violation → Some(1)
        guard.check_access(); // second violation → Some(2)
        assert_eq!(*guard.get_violation(), Some(2));
    }

    #[test]
    fn keep_first_violation_pattern() {
        let guard: ReentryGuard<&'static str, _> =
            ReentryGuard::new(|_, prev| prev.or(Some("first")));
        let _token = guard.enter().unwrap();
        guard.check_access();
        guard.check_access();
        assert_eq!(*guard.get_violation(), Some("first"));
    }

    #[test]
    fn fresh_enter_clears_violation() {
        let guard: ReentryGuard<u32, _> = ReentryGuard::new(|_, prev| Some(prev.unwrap_or(0) + 1));
        {
            let _token = guard.enter().unwrap();
            guard.check_access();
            assert!(guard.is_violated());
        }
        // re-enter: violation is cleared
        let _token = guard.enter().unwrap();
        assert!(!guard.is_violated());
    }

    #[test]
    fn is_violated_mirrors_get_violation_is_some() {
        let guard: ReentryGuard<i32, _> = ReentryGuard::new(|_, _| Some(42));
        let _token = guard.enter().unwrap();
        assert_eq!(guard.is_violated(), guard.get_violation().is_some());
        guard.check_access();
        assert_eq!(guard.is_violated(), guard.get_violation().is_some());
    }
}
