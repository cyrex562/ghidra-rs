//! Port of `ghidra.debug.api.progress.ProgressListener`.
//!
//! # Shape
//!
//! Java is an open `interface` (implemented by the debugger console and progress service), so
//! this is a `trait` per `scripts/shape_rules.py`. The nested Java `enum Disposal` becomes the
//! sibling Rust enum [`Disposal`].
//!
//! Java's `Throwable error` parameter becomes a borrowed `std::error::Error` trait object, the
//! same error representation [`CloseableTaskMonitor::report_error`](super::CloseableTaskMonitor::report_error)
//! uses when a task reports the error in the first place.

use super::MonitorReceiver;

/// Describes how or why a task monitor was disposed.
///
/// Port of `ghidra.debug.api.progress.ProgressListener.Disposal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disposal {
    /// The monitor was properly closed.
    Closed,
    /// The monitor was *not* closed. Instead, it was cleaned by the garbage collector (in Rust:
    /// dropped without being closed).
    Cleaned,
}

/// A subscriber to task and progress events published through
/// [`ProgressService`](crate::app::services::ProgressService).
pub trait ProgressListener {
    /// A new task monitor has been created.
    ///
    /// The subscriber ought to display the monitor as soon as is reasonable. Optionally, a
    /// subscriber may apply a grace period, e.g., half a second, before displaying it, in case
    /// it is quickly disposed.
    fn monitor_created(&self, monitor: &dyn MonitorReceiver);

    /// A task monitor has been disposed, for the reason given by `disposal`.
    fn monitor_disposed(&self, monitor: &dyn MonitorReceiver, disposal: Disposal);

    /// A task has updated a monitor's message.
    fn message_updated(&self, monitor: &dyn MonitorReceiver, message: &str);

    /// A task has reported an error.
    fn error_reported(
        &self,
        monitor: &dyn MonitorReceiver,
        error: &(dyn std::error::Error + Send + Sync),
    );

    /// A task's progress has updated.
    ///
    /// Note the subscriber may need to use [`MonitorReceiver::get_maximum`] to properly update
    /// the display.
    fn progress_updated(&self, monitor: &dyn MonitorReceiver, progress: i64);

    /// Some other attribute has been updated:
    ///
    /// * cancelled
    /// * cancel enabled
    /// * indeterminate
    /// * maximum
    /// * show progress value in percent string
    fn attribute_updated(&self, monitor: &dyn MonitorReceiver);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::api::progress::monitor_receiver::tests::TestReceiver;
    use std::sync::Mutex;

    /// Records every event as a line, in the manner of the debugger console's listener.
    #[derive(Default)]
    struct RecordingListener {
        events: Mutex<Vec<String>>,
    }

    impl RecordingListener {
        fn push(&self, s: String) {
            self.events.lock().unwrap().push(s);
        }
    }

    impl ProgressListener for RecordingListener {
        fn monitor_created(&self, monitor: &dyn MonitorReceiver) {
            self.push(format!("created:{}", monitor.get_message()));
        }
        fn monitor_disposed(&self, _monitor: &dyn MonitorReceiver, disposal: Disposal) {
            self.push(format!("disposed:{disposal:?}"));
        }
        fn message_updated(&self, _monitor: &dyn MonitorReceiver, message: &str) {
            self.push(format!("message:{message}"));
        }
        fn error_reported(
            &self,
            _monitor: &dyn MonitorReceiver,
            error: &(dyn std::error::Error + Send + Sync),
        ) {
            self.push(format!("error:{error}"));
        }
        fn progress_updated(&self, monitor: &dyn MonitorReceiver, progress: i64) {
            self.push(format!("progress:{progress}/{}", monitor.get_maximum()));
        }
        fn attribute_updated(&self, monitor: &dyn MonitorReceiver) {
            self.push(format!("attr:cancelled={}", monitor.is_cancelled()));
        }
    }

    #[test]
    fn disposal_variants_are_distinct() {
        assert_ne!(Disposal::Closed, Disposal::Cleaned);
    }

    #[test]
    fn listener_receives_full_lifecycle_as_trait_object() {
        let recv = TestReceiver { message: "Loading".into(), maximum: 4, ..Default::default() };
        let rec = RecordingListener::default();
        let l: &dyn ProgressListener = &rec;

        l.monitor_created(&recv);
        l.message_updated(&recv, "Step 1");
        l.progress_updated(&recv, 2);
        recv.cancel();
        l.attribute_updated(&recv);
        let err = std::io::Error::new(std::io::ErrorKind::Other, "boom");
        l.error_reported(&recv, &err);
        l.monitor_disposed(&recv, Disposal::Closed);

        assert_eq!(
            *rec.events.lock().unwrap(),
            vec![
                "created:Loading",
                "message:Step 1",
                "progress:2/4",
                "attr:cancelled=true",
                "error:boom",
                "disposed:Closed",
            ]
        );
    }
}
