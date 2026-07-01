use super::TimerCallback;

/// A timer that can be started and stopped, with configurable delay, initial delay, and repeat behavior.
///
/// Mirrors `generic.timer.GhidraTimer` from Ghidra. Provides a trait for timer implementations
/// that invoke a callback at specified intervals.
pub trait GhidraTimer {
    /// Starts the timer.
    fn start(&mut self);

    /// Stops the timer.
    fn stop(&mut self);

    /// Sets the delay (in milliseconds) for all callbacks after the first.
    fn set_delay(&mut self, delay: i32);

    /// Sets the delay (in milliseconds) for the first callback.
    fn set_initial_delay(&mut self, initial_delay: i32);

    /// Sets whether the timer repeats.
    ///
    /// If `true`, the timer will fire repeatedly. If `false`, it fires only once.
    fn set_repeats(&mut self, repeats: bool);

    /// Returns whether this timer is set to repeat.
    fn is_repeats(&self) -> bool;

    /// Returns whether the timer is currently running.
    fn is_running(&self) -> bool;

    /// Returns the delay (in milliseconds) for callbacks after the first.
    fn get_delay(&self) -> i32;

    /// Returns the delay (in milliseconds) for the first callback.
    fn get_initial_delay(&self) -> i32;

    /// Sets the callback to be invoked when the timer fires.
    fn set_timer_callback(&mut self, callback: Box<dyn TimerCallback>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTimer {
        delay: i32,
        initial_delay: i32,
        repeats: bool,
        running: bool,
        callback: Option<Box<dyn TimerCallback>>,
    }

    impl MockTimer {
        fn new() -> Self {
            Self {
                delay: 100,
                initial_delay: 100,
                repeats: true,
                running: false,
                callback: None,
            }
        }
    }

    impl GhidraTimer for MockTimer {
        fn start(&mut self) {
            self.running = true;
        }

        fn stop(&mut self) {
            self.running = false;
        }

        fn set_delay(&mut self, delay: i32) {
            self.delay = delay;
        }

        fn set_initial_delay(&mut self, initial_delay: i32) {
            self.initial_delay = initial_delay;
        }

        fn set_repeats(&mut self, repeats: bool) {
            self.repeats = repeats;
        }

        fn is_repeats(&self) -> bool {
            self.repeats
        }

        fn is_running(&self) -> bool {
            self.running
        }

        fn get_delay(&self) -> i32 {
            self.delay
        }

        fn get_initial_delay(&self) -> i32 {
            self.initial_delay
        }

        fn set_timer_callback(&mut self, callback: Box<dyn TimerCallback>) {
            self.callback = Some(callback);
        }
    }

    #[test]
    fn test_start_sets_running() {
        let mut timer = MockTimer::new();
        assert!(!timer.is_running());
        timer.start();
        assert!(timer.is_running());
    }

    #[test]
    fn test_stop_clears_running() {
        let mut timer = MockTimer::new();
        timer.start();
        assert!(timer.is_running());
        timer.stop();
        assert!(!timer.is_running());
    }

    #[test]
    fn test_set_delay() {
        let mut timer = MockTimer::new();
        assert_eq!(timer.get_delay(), 100);
        timer.set_delay(200);
        assert_eq!(timer.get_delay(), 200);
    }

    #[test]
    fn test_set_initial_delay() {
        let mut timer = MockTimer::new();
        assert_eq!(timer.get_initial_delay(), 100);
        timer.set_initial_delay(250);
        assert_eq!(timer.get_initial_delay(), 250);
    }

    #[test]
    fn test_set_repeats_true() {
        let mut timer = MockTimer::new();
        timer.set_repeats(true);
        assert!(timer.is_repeats());
    }

    #[test]
    fn test_set_repeats_false() {
        let mut timer = MockTimer::new();
        assert!(timer.is_repeats());
        timer.set_repeats(false);
        assert!(!timer.is_repeats());
    }

    #[test]
    fn test_default_values() {
        let timer = MockTimer::new();
        assert_eq!(timer.get_delay(), 100);
        assert_eq!(timer.get_initial_delay(), 100);
        assert!(timer.is_repeats());
        assert!(!timer.is_running());
    }

    #[test]
    fn test_set_timer_callback() {
        let mut timer = MockTimer::new();
        struct CountingCallback {
            count: usize,
        }
        impl TimerCallback for CountingCallback {
            fn timer_fired(&mut self) {
                self.count += 1;
            }
        }

        let callback = Box::new(CountingCallback { count: 0 });
        timer.set_timer_callback(callback);
        assert!(timer.callback.is_some());
    }
}
