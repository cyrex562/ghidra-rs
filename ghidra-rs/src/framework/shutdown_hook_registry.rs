//! Port of `ghidra.framework.ShutdownHookRegistry`.

use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::framework::shutdown_priority::ShutdownPriority;
use crate::util::Callback;

/// Opaque handle to a hook registered via
/// [`ShutdownHookRegistry::add_shutdown_hook`], used to later unregister it with
/// [`ShutdownHookRegistry::remove_shutdown_hook`].
///
/// Port of `ghidra.framework.ShutdownHookRegistry.ShutdownHook`. The Java `TreeSet`
/// orders (and, since `TreeSet.remove` dispatches through `compareTo`, also *matches
/// for removal*) purely by priority; two hooks sharing a priority collide there, so
/// only one of them is ever added or removable. This handle instead carries a unique
/// id, so registering or removing one hook never affects another that shares its
/// priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownHook(u64);

struct HookEntry {
    id: u64,
    priority: i32,
    runnable: Callback,
}

static REGISTRY: OnceLock<Mutex<Vec<HookEntry>>> = OnceLock::new();
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn get_registry() -> &'static Mutex<Vec<HookEntry>> {
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// Registry of hooks that must run when the process exits.
///
/// Port of `ghidra.framework.ShutdownHookRegistry`. `Runtime.getRuntime().addShutdownHook`
/// is replaced with a libc `atexit` handler, which fires for both a normal return from
/// `main` and an explicit `std::process::exit`, mirroring the JVM's own limitation of
/// not running shutdown hooks when the process is killed outright (e.g. `kill -9`).
pub struct ShutdownHookRegistry;

impl ShutdownHookRegistry {
    /// Install a shutdown hook at the specified priority. If the hook has no specific
    /// priority or sensitivity to when it runs, prefer running it as regular cleanup
    /// code instead. Hooks with a lower priority value run first (see
    /// [`ShutdownPriority`]).
    pub fn add_shutdown_hook(r: Callback, priority: ShutdownPriority) -> ShutdownHook {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let entry = HookEntry {
            id,
            priority: priority.priority(),
            runnable: r,
        };

        {
            let mut hooks = get_registry().lock().unwrap();
            let pos = hooks.partition_point(|h| h.priority <= entry.priority);
            hooks.insert(pos, entry);
        }

        install_hook();

        ShutdownHook(id)
    }

    /// Remove a shutdown hook previously registered.
    pub fn remove_shutdown_hook(hook: ShutdownHook) {
        get_registry().lock().unwrap().retain(|h| h.id != hook.0);
    }
}

fn install_hook() {
    if HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        libc::atexit(run_registered_hooks);
    }
}

extern "C" fn run_registered_hooks() {
    notify_hooks();
}

fn notify_hooks() {
    let hooks = get_registry().lock().unwrap();
    for hook in hooks.iter() {
        let result = panic::catch_unwind(AssertUnwindSafe(|| (hook.runnable)()));
        if let Err(payload) = result {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "(unknown)".to_string()
            };
            tracing::error!("shutdown hook panicked: {msg}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Registry state is global, so serialize the tests that touch it.
    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn reset_registry() {
        get_registry().lock().unwrap().clear();
        // Prevent tests from ever registering a real `atexit` handler.
        HOOK_INSTALLED.store(true, Ordering::SeqCst);
    }

    #[test]
    fn test_add_shutdown_hook_returns_distinct_handles() {
        let _guard = TEST_GUARD.lock().unwrap();
        reset_registry();

        let a = ShutdownHookRegistry::add_shutdown_hook(Box::new(|| {}), ShutdownPriority::FIRST);
        let b = ShutdownHookRegistry::add_shutdown_hook(Box::new(|| {}), ShutdownPriority::LAST);

        assert_ne!(a, b);
    }

    #[test]
    fn test_notify_hooks_runs_in_priority_order() {
        let _guard = TEST_GUARD.lock().unwrap();
        reset_registry();

        let order = Arc::new(Mutex::new(Vec::new()));
        let o1 = Arc::clone(&order);
        let o2 = Arc::clone(&order);

        ShutdownHookRegistry::add_shutdown_hook(
            Box::new(move || o1.lock().unwrap().push("last")),
            ShutdownPriority::LAST,
        );
        ShutdownHookRegistry::add_shutdown_hook(
            Box::new(move || o2.lock().unwrap().push("first")),
            ShutdownPriority::FIRST,
        );

        notify_hooks();

        assert_eq!(*order.lock().unwrap(), vec!["first", "last"]);
    }

    #[test]
    fn test_remove_shutdown_hook_prevents_run() {
        let _guard = TEST_GUARD.lock().unwrap();
        reset_registry();

        let ran = Arc::new(Mutex::new(false));
        let ran_clone = Arc::clone(&ran);
        let hook = ShutdownHookRegistry::add_shutdown_hook(
            Box::new(move || *ran_clone.lock().unwrap() = true),
            ShutdownPriority::FIRST,
        );

        ShutdownHookRegistry::remove_shutdown_hook(hook);
        notify_hooks();

        assert!(!*ran.lock().unwrap());
    }

    #[test]
    fn test_other_hooks_still_run_after_a_panicking_hook() {
        let _guard = TEST_GUARD.lock().unwrap();
        reset_registry();

        let ran = Arc::new(Mutex::new(false));
        let ran_clone = Arc::clone(&ran);

        ShutdownHookRegistry::add_shutdown_hook(
            Box::new(|| panic!("boom")),
            ShutdownPriority::FIRST,
        );
        ShutdownHookRegistry::add_shutdown_hook(
            Box::new(move || *ran_clone.lock().unwrap() = true),
            ShutdownPriority::LAST,
        );

        notify_hooks();

        assert!(*ran.lock().unwrap());
    }

    #[test]
    fn test_install_hook_is_idempotent() {
        let _guard = TEST_GUARD.lock().unwrap();
        install_hook();
        install_hook();
    }
}
