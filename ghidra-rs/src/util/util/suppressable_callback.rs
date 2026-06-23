use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    static STACKS: RefCell<HashMap<usize, Vec<Box<dyn Any>>>> = RefCell::new(HashMap::new());
}

/// A mechanism for preventing callback loops, stack overflows, and event storms.
///
/// Suppression is per-thread: a [`Suppression`] guard pushed on thread A does not
/// affect invocations on thread B.  This mirrors Java's `ThreadLocal`-backed
/// `SuppressableCallback`.
///
/// # Example
///
/// ```rust
/// use ghidra_rs::util::util::suppressable_callback::SuppressableCallback;
///
/// let cb: SuppressableCallback<()> = SuppressableCallback::new();
/// cb.invoke(|| {
///     let _guard = cb.suppress(());
///     // Recursive/re-entrant calls to cb.invoke are now suppressed on this thread.
///     cb.invoke(|| panic!("should not run"));
/// });
/// ```
pub struct SuppressableCallback<T: Any + 'static> {
    id: usize,
    // invariant over T so that downcasts from `Box<dyn Any>` are sound
    _phantom: PhantomData<*const T>,
}

// SAFETY: `SuppressableCallback` stores no T values itself; all values live in
// thread-local storage keyed by `id`.  Sharing the handle across threads is safe.
unsafe impl<T: Any + 'static> Send for SuppressableCallback<T> {}
unsafe impl<T: Any + 'static> Sync for SuppressableCallback<T> {}

/// RAII suppression handle returned by [`SuppressableCallback::suppress`].
///
/// The suppression remains active until this value is dropped.  Because it is
/// `!Send`, it can only be dropped on the thread that created it — matching the
/// compile-time guarantee that Java enforces at runtime.
pub struct Suppression<'a, T: Any + 'static> {
    cb: &'a SuppressableCallback<T>,
    // !Send: must be dropped on the creating thread
    _not_send: PhantomData<*const ()>,
}

impl<T: Any + 'static> Drop for Suppression<'_, T> {
    fn drop(&mut self) {
        STACKS.with(|stacks| {
            let mut map = stacks.borrow_mut();
            if let Some(stack) = map.get_mut(&self.cb.id) {
                stack.pop();
                if stack.is_empty() {
                    map.remove(&self.cb.id);
                }
            }
        });
    }
}

impl<T: Any + 'static> SuppressableCallback<T> {
    /// Creates a new `SuppressableCallback`.
    pub fn new() -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            _phantom: PhantomData,
        }
    }

    /// Suppresses this callback on the current thread, associating `value` with
    /// the suppression entry.  Returns a guard that lifts the suppression when
    /// dropped.
    pub fn suppress(&self, value: T) -> Suppression<'_, T> {
        STACKS.with(|stacks| {
            stacks.borrow_mut()
                .entry(self.id)
                .or_default()
                .push(Box::new(value));
        });
        Suppression { cb: self, _not_send: PhantomData }
    }

    /// Runs `callback` only if this callback is not currently suppressed on the
    /// current thread.
    pub fn invoke(&self, callback: impl FnOnce()) {
        if !self.is_suppressed() {
            callback();
        }
    }

    /// Runs `callback` returning its value, or returns `fallback` if suppressed.
    pub fn invoke_with_fallback<R>(&self, callback: impl FnOnce() -> R, fallback: R) -> R {
        if self.is_suppressed() { fallback } else { callback() }
    }

    fn is_suppressed(&self) -> bool {
        STACKS.with(|stacks| {
            stacks.borrow()
                .get(&self.id)
                .map(|v| !v.is_empty())
                .unwrap_or(false)
        })
    }
}

impl<T: Any + Clone + 'static> SuppressableCallback<T> {
    /// Always runs `callback` with the most-recently-pushed suppression value,
    /// or `None` when not suppressed.  The callback is responsible for deciding
    /// what action to take based on the value.
    pub fn invoke_with_top(&self, callback: impl FnOnce(Option<T>)) {
        let top = self.top_value();
        callback(top);
    }

    /// Like [`invoke_with_top`](Self::invoke_with_top) but returns the
    /// callback's result.
    pub fn invoke_with_top_returning<R>(&self, callback: impl FnOnce(Option<T>) -> R) -> R {
        callback(self.top_value())
    }

    /// Always runs `callback` with a snapshot of the full suppression stack
    /// (oldest entry first, most-recent entry last).  The callback is always
    /// invoked and decides what to do based on the stack contents.
    pub fn invoke_with_stack(&self, callback: impl FnOnce(&[T])) {
        let snapshot = self.stack_snapshot();
        callback(&snapshot);
    }

    /// Like [`invoke_with_stack`](Self::invoke_with_stack) but returns the
    /// callback's result.
    pub fn invoke_with_stack_returning<R>(&self, callback: impl FnOnce(&[T]) -> R) -> R {
        let snapshot = self.stack_snapshot();
        callback(&snapshot)
    }

    fn top_value(&self) -> Option<T> {
        STACKS.with(|stacks| {
            stacks.borrow()
                .get(&self.id)
                .and_then(|v| v.last())
                .and_then(|b| b.downcast_ref::<T>())
                .cloned()
        })
    }

    fn stack_snapshot(&self) -> Vec<T> {
        STACKS.with(|stacks| {
            stacks.borrow()
                .get(&self.id)
                .map(|v| {
                    v.iter()
                        .filter_map(|b| b.downcast_ref::<T>())
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        })
    }
}

impl<T: Any + 'static> Default for SuppressableCallback<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoke_runs_when_not_suppressed() {
        let cb: SuppressableCallback<()> = SuppressableCallback::new();
        let mut called = false;
        cb.invoke(|| called = true);
        assert!(called);
    }

    #[test]
    fn invoke_suppressed_does_not_run() {
        let cb: SuppressableCallback<()> = SuppressableCallback::new();
        let _s = cb.suppress(());
        let mut called = false;
        cb.invoke(|| called = true);
        assert!(!called);
    }

    #[test]
    fn suppression_drop_restores_invoke() {
        let cb: SuppressableCallback<()> = SuppressableCallback::new();
        {
            let _s = cb.suppress(());
            let mut called = false;
            cb.invoke(|| called = true);
            assert!(!called);
        }
        let mut called = false;
        cb.invoke(|| called = true);
        assert!(called);
    }

    #[test]
    fn nested_suppressions_require_all_dropped() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        let s1 = cb.suppress(1);
        let s2 = cb.suppress(2);
        cb.invoke(|| panic!("should not run"));
        drop(s2);
        cb.invoke(|| panic!("still suppressed"));
        drop(s1);
        let mut called = false;
        cb.invoke(|| called = true);
        assert!(called);
    }

    #[test]
    fn invoke_with_fallback_returns_fallback_when_suppressed() {
        let cb: SuppressableCallback<()> = SuppressableCallback::new();
        let _s = cb.suppress(());
        assert_eq!(cb.invoke_with_fallback(|| 42_i32, 0), 0);
    }

    #[test]
    fn invoke_with_fallback_runs_callback_when_not_suppressed() {
        let cb: SuppressableCallback<()> = SuppressableCallback::new();
        assert_eq!(cb.invoke_with_fallback(|| 42_i32, 0), 42);
    }

    #[test]
    fn invoke_with_top_none_when_not_suppressed() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        cb.invoke_with_top(|top| assert_eq!(top, None));
    }

    #[test]
    fn invoke_with_top_some_when_suppressed() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        let _s = cb.suppress(42);
        cb.invoke_with_top(|top| assert_eq!(top, Some(42)));
    }

    #[test]
    fn invoke_with_top_returns_most_recently_pushed() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        let _s1 = cb.suppress(1);
        let _s2 = cb.suppress(2);
        cb.invoke_with_top(|top| assert_eq!(top, Some(2)));
    }

    #[test]
    fn invoke_with_stack_empty_when_not_suppressed() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        cb.invoke_with_stack(|stack| assert!(stack.is_empty()));
    }

    #[test]
    fn invoke_with_stack_contains_pushed_values() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        let _s1 = cb.suppress(10);
        let _s2 = cb.suppress(20);
        cb.invoke_with_stack(|stack| {
            assert_eq!(stack.len(), 2);
            assert!(stack.contains(&10));
            assert!(stack.contains(&20));
        });
    }

    #[test]
    fn invoke_with_stack_returning_sums_values() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        let _s1 = cb.suppress(10);
        let _s2 = cb.suppress(20);
        let sum = cb.invoke_with_stack_returning(|stack| stack.iter().sum::<i32>());
        assert_eq!(sum, 30);
    }

    #[test]
    fn invoke_with_top_returning_works() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        let _s = cb.suppress(99);
        let result = cb.invoke_with_top_returning(|top| top.unwrap_or(0));
        assert_eq!(result, 99);
    }

    #[test]
    fn self_suppression_prevents_recursion() {
        let cb: SuppressableCallback<()> = SuppressableCallback::new();
        let mut count = 0_i32;
        cb.invoke(|| {
            count += 1;
            let _s = cb.suppress(());
            cb.invoke(|| count += 1); // suppressed; inner increment must not run
        });
        assert_eq!(count, 1);
    }

    #[test]
    fn different_instances_are_independent() {
        let cb1: SuppressableCallback<()> = SuppressableCallback::new();
        let cb2: SuppressableCallback<()> = SuppressableCallback::new();
        let _s = cb1.suppress(());
        let mut called = false;
        cb2.invoke(|| called = true);
        assert!(called);
    }

    #[test]
    fn invoke_with_top_always_called_even_when_not_suppressed() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        let mut called = false;
        cb.invoke_with_top(|top| {
            called = true;
            assert_eq!(top, None);
        });
        assert!(called);
    }

    #[test]
    fn invoke_with_stack_always_called_even_when_not_suppressed() {
        let cb: SuppressableCallback<i32> = SuppressableCallback::new();
        let mut called = false;
        cb.invoke_with_stack(|stack| {
            called = true;
            assert!(stack.is_empty());
        });
        assert!(called);
    }
}
