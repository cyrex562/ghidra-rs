//! Port of `ghidra.framework.plugintool.PluginWithTransientState`.
//!
//! A plugin that can save and restore transient state as the tool switches between domain
//! objects (e.g. when the user tabs to a different program and back). Ported as an object-safe
//! generic trait, mirroring the Java generic interface `PluginWithTransientState<T>`; `T` is
//! usually a small value type (a Java `record` in the original).

/// Mirrors `ghidra.framework.plugintool.PluginWithTransientState<T>`.
pub trait PluginWithTransientState<T> {
    /// Returns an object containing the plugin's state, mirroring `getTransientState()`.
    fn get_transient_state(&self) -> T;

    /// Restores the transient state object previously returned by [`get_transient_state`],
    /// mirroring `restoreTransientState(T)`.
    ///
    /// [`get_transient_state`]: PluginWithTransientState::get_transient_state
    fn restore_transient_state(&mut self, state: T);

    /// Returns true if the plugin has been disposed, mirroring `isDisposed()`.
    fn is_disposed(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct CounterState {
        count: i32,
    }

    struct CounterPlugin {
        count: i32,
        disposed: bool,
    }

    impl PluginWithTransientState<CounterState> for CounterPlugin {
        fn get_transient_state(&self) -> CounterState {
            CounterState { count: self.count }
        }

        fn restore_transient_state(&mut self, state: CounterState) {
            self.count = state.count;
        }

        fn is_disposed(&self) -> bool {
            self.disposed
        }
    }

    #[test]
    fn transient_state_round_trips_through_trait_object() {
        let mut plugin: Box<dyn PluginWithTransientState<CounterState>> =
            Box::new(CounterPlugin { count: 5, disposed: false });

        let saved = plugin.get_transient_state();
        assert_eq!(saved, CounterState { count: 5 });

        plugin.restore_transient_state(CounterState { count: 42 });
        assert_eq!(plugin.get_transient_state(), CounterState { count: 42 });
        assert!(!plugin.is_disposed());
    }
}
