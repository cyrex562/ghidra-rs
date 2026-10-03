//! Port of `ghidra.util.graph.KeyedObjectFactory` (deprecated since Ghidra 10.2).

use std::sync::Mutex;

/// Responsible for ensuring that no two vertices or edges have the same keys. One and only one
/// instance of `KeyedObjectFactory` may exist. In addition to ensuring that all vertices and
/// edges contained within any graph have distinct keys, `KeyedObjectFactory` provides methods for
/// obtaining the object that a `KeyedObject` refers to. More than one vertex may refer to the
/// same object. The object a `Vertex` refers to can not be changed. There is no method to return
/// the vertex referring to a specific object since in theory there can be a one-to-many
/// correspondence.
///
/// Port of `ghidra.util.graph.KeyedObjectFactory` (deprecated since Ghidra 10.2). Java models this
/// as a mutable-state singleton: a private constructor, a `static` `instance_` field holding the
/// one instance, and an instance-level `synchronized long keyCounter` field mutated by
/// [`get_next_available_key`](Self::get_next_available_key). Since the counter is genuinely
/// process-wide shared mutable state (that's the entire point of the class -- guaranteeing
/// distinct keys across every caller), this port keeps the counter behind a `static Mutex`
/// (mirroring the same convention already established for other ported singleton/global Java
/// state, e.g.
/// [`ShutdownHookRegistry`](crate::framework::shutdown_hook_registry::ShutdownHookRegistry)) and
/// reduces `KeyedObjectFactory` itself to a stateless, `Copy` handle type whose methods forward to
/// it, rather than a heap-allocated singleton object.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
#[derive(Debug, Clone, Copy)]
pub struct KeyedObjectFactory;

#[allow(deprecated)]
static KEY_COUNTER: Mutex<i64> = Mutex::new(0);

#[allow(deprecated)]
impl KeyedObjectFactory {
    /// The singleton instance of `KeyedObjectFactory`.
    ///
    /// Port of the public field `static public KeyedObjectFactory instance_`. Since
    /// [`KeyedObjectFactory`] here is a stateless, zero-sized handle (all real state lives in the
    /// shared [`KEY_COUNTER`], see the struct docs), a `const` serves the same purpose as Java's
    /// eagerly-constructed static field without needing lazy initialization.
    pub const INSTANCE: KeyedObjectFactory = KeyedObjectFactory;

    /// Returns singleton instance of `KeyedObjectFactory`.
    ///
    /// Port of `static public KeyedObjectFactory getInstance()`.
    pub fn get_instance() -> Self {
        Self::INSTANCE
    }

    /// Gets returns the next available key. The keys are given out based on a one up counter.
    ///
    /// Port of the package-private `synchronized long getNextAvailableKey()`. Java restricts this
    /// to the `ghidra.util.graph` package; `pub(crate)` is the closest equivalent this crate has.
    pub(crate) fn get_next_available_key(&self) -> i64 {
        let mut counter = KEY_COUNTER.lock().unwrap();
        let key = *counter;
        *counter += 1;
        key
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    // KeyedObjectFactory's backing counter is process-global, so serialize the tests that touch
    // it to avoid interference between them.
    static TEST_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn get_instance_returns_a_usable_handle() {
        let _guard = TEST_GUARD.lock().unwrap();
        let factory = KeyedObjectFactory::get_instance();
        let first = factory.get_next_available_key();
        let second = factory.get_next_available_key();
        assert_eq!(second, first + 1);
    }

    #[test]
    fn keys_increase_monotonically_by_one() {
        let _guard = TEST_GUARD.lock().unwrap();
        let factory = KeyedObjectFactory::INSTANCE;
        let a = factory.get_next_available_key();
        let b = factory.get_next_available_key();
        let c = factory.get_next_available_key();
        assert_eq!(b, a + 1);
        assert_eq!(c, b + 1);
    }

    #[test]
    fn every_handle_shares_the_same_counter() {
        let _guard = TEST_GUARD.lock().unwrap();
        // Mirrors Java's "one and only one instance may exist" -- every handle observes the same
        // underlying counter, since it's process-global rather than per-instance state.
        let a = KeyedObjectFactory::get_instance().get_next_available_key();
        let b = KeyedObjectFactory::INSTANCE.get_next_available_key();
        assert_eq!(b, a + 1);
    }
}
