/// Callback interface for animation framework clients.
///
/// Implementors receive periodic progress notifications over an animation cycle and a
/// final [`done`](SwingAnimationCallback::done) notification when the cycle completes.
///
/// Corresponds to `docking.util.SwingAnimationCallback`.
pub trait SwingAnimationCallback {
    /// Called repeatedly over the course of an animation cycle.
    ///
    /// `percent_complete` is a value in `[0.0, 1.0]` indicating how far through the
    /// cycle the animation currently is.
    fn progress(&mut self, percent_complete: f64);

    /// Called once when the entire animation cycle has finished, allowing finalization.
    fn done(&mut self);

    /// Returns the duration of this animation in milliseconds.
    ///
    /// Defaults to `1000 ms`. Override to change the cycle length.
    fn get_duration(&self) -> u32 {
        1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingCallback {
        progress_values: Vec<f64>,
        done_called: bool,
    }

    impl RecordingCallback {
        fn new() -> Self {
            Self { progress_values: Vec::new(), done_called: false }
        }
    }

    impl SwingAnimationCallback for RecordingCallback {
        fn progress(&mut self, percent_complete: f64) {
            self.progress_values.push(percent_complete);
        }

        fn done(&mut self) {
            self.done_called = true;
        }
    }

    #[test]
    fn default_duration_is_1000ms() {
        let cb = RecordingCallback::new();
        assert_eq!(cb.get_duration(), 1000);
    }

    #[test]
    fn custom_duration_overrides_default() {
        struct FastCallback;
        impl SwingAnimationCallback for FastCallback {
            fn progress(&mut self, _: f64) {}
            fn done(&mut self) {}
            fn get_duration(&self) -> u32 {
                250
            }
        }
        let cb = FastCallback;
        assert_eq!(cb.get_duration(), 250);
    }

    #[test]
    fn progress_receives_values() {
        let mut cb = RecordingCallback::new();
        cb.progress(0.0);
        cb.progress(0.5);
        cb.progress(1.0);
        assert_eq!(cb.progress_values, vec![0.0, 0.5, 1.0]);
    }

    #[test]
    fn done_marks_completion() {
        let mut cb = RecordingCallback::new();
        assert!(!cb.done_called);
        cb.done();
        assert!(cb.done_called);
    }

    #[test]
    fn trait_object_usable() {
        let mut cb = RecordingCallback::new();
        let dyn_cb: &mut dyn SwingAnimationCallback = &mut cb;
        dyn_cb.progress(0.25);
        dyn_cb.done();
        assert_eq!(cb.progress_values, vec![0.25]);
        assert!(cb.done_called);
    }
}
