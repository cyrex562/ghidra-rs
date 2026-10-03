//! Port of `ghidra.debug.api.progress.MonitorReceiver`.
//!
//! # Shape
//!
//! Java is an open `interface` (its in-repo implementor is `DefaultMonitorReceiver` in the
//! debugger's progress service), so this is a `trait` per `scripts/shape_rules.py`.
//!
//! All methods take `&self`, matching [`TaskMonitor`](crate::util::task::TaskMonitor): a receiver
//! is queried and cancelled from subscriber threads while the task drives the monitor, so the
//! implementation owns whatever synchronisation it needs.

/// A subscriber's view of a published task monitor.
///
/// Returned by [`ProgressService::get_all_monitors`](crate::app::services::ProgressService::get_all_monitors)
/// and passed to every [`ProgressListener`](super::ProgressListener) callback, it lets a
/// subscriber read a task's message and progress, and request cancellation.
pub trait MonitorReceiver {
    /// Get the current message for the monitor.
    fn get_message(&self) -> String;

    /// Check if the monitor indicates progress at all.
    ///
    /// If the task is indeterminate, then its [`get_maximum`](Self::get_maximum) and
    /// [`get_progress`](Self::get_progress) methods are meaningless.
    ///
    /// Returns true if indeterminate (no progress shown), false if determinate (progress shown).
    fn is_indeterminate(&self) -> bool;

    /// Get the maximum value of progress.
    ///
    /// The implication is that when [`get_progress`](Self::get_progress) returns the maximum,
    /// the task is complete.
    fn get_maximum(&self) -> i64;

    /// Get the progress value, if applicable.
    ///
    /// Returns the progress, or Java's `TaskMonitor.NO_PROGRESS_VALUE` (`-1`) if un-set or not
    /// applicable.
    fn get_progress(&self) -> i64;

    /// Check if the task can be cancelled.
    fn is_cancel_enabled(&self) -> bool;

    /// Request the task be cancelled.
    ///
    /// Note it is up to the client publishing the task to adhere to this request. In general,
    /// the computation should occasionally call
    /// [`TaskMonitor::check_cancelled`](crate::util::task::TaskMonitor::check_cancelled). In
    /// particular, the subscribing client *cannot* presume the task is cancelled purely by
    /// virtue of calling this method successfully. Instead, it should listen for
    /// [`ProgressListener::monitor_disposed`](super::ProgressListener::monitor_disposed).
    fn cancel(&self);

    /// Check if the task is cancelled.
    fn is_cancelled(&self) -> bool;

    /// Check if the monitor is still valid.
    ///
    /// A monitor becomes invalid when it is closed or cleaned.
    fn is_valid(&self) -> bool;

    /// Check if the monitor should be rendered with the progress value.
    ///
    /// Regardless of this value, the monitor will render a progress bar and a numeric
    /// percentage. If this is true (the default), it will also display
    /// "{progress} of {maximum}" in text.
    fn is_show_progress_value(&self) -> bool;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A receiver modelled on Java's `DefaultMonitorReceiver`: it reports a monitor's state, and
    /// `cancel` just latches the cancelled flag (idempotently).
    pub(crate) struct TestReceiver {
        pub message: String,
        pub indeterminate: bool,
        pub maximum: i64,
        pub progress: i64,
        pub cancel_enabled: bool,
        pub cancelled: Mutex<bool>,
        pub valid: bool,
        pub show_progress_value: bool,
    }

    impl Default for TestReceiver {
        fn default() -> Self {
            Self {
                message: String::new(),
                indeterminate: false,
                maximum: 0,
                // TaskMonitor.NO_PROGRESS_VALUE
                progress: -1,
                cancel_enabled: true,
                cancelled: Mutex::new(false),
                valid: true,
                show_progress_value: true,
            }
        }
    }

    impl MonitorReceiver for TestReceiver {
        fn get_message(&self) -> String {
            self.message.clone()
        }
        fn is_indeterminate(&self) -> bool {
            self.indeterminate
        }
        fn get_maximum(&self) -> i64 {
            self.maximum
        }
        fn get_progress(&self) -> i64 {
            self.progress
        }
        fn is_cancel_enabled(&self) -> bool {
            self.cancel_enabled
        }
        fn cancel(&self) {
            *self.cancelled.lock().unwrap() = true;
        }
        fn is_cancelled(&self) -> bool {
            *self.cancelled.lock().unwrap()
        }
        fn is_valid(&self) -> bool {
            self.valid
        }
        fn is_show_progress_value(&self) -> bool {
            self.show_progress_value
        }
    }

    #[test]
    fn unset_progress_reports_no_progress_value() {
        let r = TestReceiver::default();
        assert_eq!(r.get_progress(), -1);
        assert!(r.is_show_progress_value());
        assert!(r.is_valid());
    }

    #[test]
    fn cancel_is_a_request_through_a_trait_object() {
        let r = TestReceiver { maximum: 10, progress: 3, ..Default::default() };
        let dynr: &dyn MonitorReceiver = &r;
        assert!(!dynr.is_cancelled());
        dynr.cancel();
        assert!(dynr.is_cancelled());
        assert_eq!((dynr.get_progress(), dynr.get_maximum()), (3, 10));
    }

    #[test]
    fn cancel_is_idempotent() {
        let r = TestReceiver::default();
        r.cancel();
        r.cancel();
        assert!(r.is_cancelled());
        assert!(r.is_cancel_enabled());
    }
}
