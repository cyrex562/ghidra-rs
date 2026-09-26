use super::jdi_cause::JdiCause;

/// Listener for state changes emitted by JDI.
pub trait JdiStateListener: Send + Sync {
    /// Called when JDI's state has changed.
    ///
    /// # Arguments
    ///
    /// * `state` - The new state
    /// * `cause` - The reason for the change
    fn state_changed(&self, state: i32, cause: &dyn JdiCause);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct StateCapture {
        state: Mutex<Option<i32>>,
        cause_recorded: Mutex<bool>,
    }

    impl StateCapture {
        fn new() -> Self {
            Self {
                state: Mutex::new(None),
                cause_recorded: Mutex::new(false),
            }
        }
    }

    impl JdiStateListener for StateCapture {
        fn state_changed(&self, state: i32, _cause: &dyn JdiCause) {
            *self.state.lock().unwrap() = Some(state);
            *self.cause_recorded.lock().unwrap() = true;
        }
    }

    #[test]
    fn listener_receives_state_change() {
        use crate::debug::dbg::jdi::manager::jdi_cause::Causes;

        let listener = StateCapture::new();
        listener.state_changed(42, &Causes::Unclaimed);

        assert_eq!(*listener.state.lock().unwrap(), Some(42));
        assert!(*listener.cause_recorded.lock().unwrap());
    }

    #[test]
    fn listener_as_trait_object() {
        use crate::debug::dbg::jdi::manager::jdi_cause::Causes;

        let listener = StateCapture::new();
        let trait_obj: &dyn JdiStateListener = &listener;

        trait_obj.state_changed(100, &Causes::Unclaimed);

        assert_eq!(*listener.state.lock().unwrap(), Some(100));
    }

    #[test]
    fn listener_accepts_different_states() {
        use crate::debug::dbg::jdi::manager::jdi_cause::Causes;

        let listener = StateCapture::new();

        listener.state_changed(1, &Causes::Unclaimed);
        assert_eq!(*listener.state.lock().unwrap(), Some(1));

        listener.state_changed(2, &Causes::Unclaimed);
        assert_eq!(*listener.state.lock().unwrap(), Some(2));

        listener.state_changed(99, &Causes::Unclaimed);
        assert_eq!(*listener.state.lock().unwrap(), Some(99));
    }

    #[test]
    fn listener_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StateCapture>();
    }
}
