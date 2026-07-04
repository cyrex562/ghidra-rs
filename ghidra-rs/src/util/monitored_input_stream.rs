use std::io::{self, Read};

use crate::util::exception::IOCancelledException;
use crate::util::task::TaskMonitor;

const PROGRESS_INCREMENT: i64 = 32 * 1024;

/// Port of `ghidra.util.MonitoredInputStream`.
///
/// A [`Read`] wrapper that reports progress to a [`TaskMonitor`] as bytes are consumed and
/// allows the read operation to be cancelled via the monitor. Once the monitor is cancelled,
/// any subsequent read fails with an [`IOCancelledException`].
pub struct MonitoredInputStream<'a, R: Read> {
    inner: R,
    monitor: &'a dyn TaskMonitor,
    small_count: i64,
    count: i64,
    cleanup_on_cancel: bool,
}

impl<'a, R: Read> MonitoredInputStream<'a, R> {
    /// Creates a new instance, wrapping `inner` and reporting progress via `monitor`.
    pub fn new(inner: R, monitor: &'a dyn TaskMonitor) -> Self {
        Self {
            inner,
            monitor,
            small_count: 0,
            count: 0,
            cleanup_on_cancel: false,
        }
    }

    /// Get task monitor associated within this input stream.
    pub fn task_monitor(&self) -> &'a dyn TaskMonitor {
        self.monitor
    }

    /// Reset the current progress count to the specified value.
    pub fn set_progress(&mut self, progress: i64) {
        self.count = progress;
    }

    /// Convey to byte stream consumer if cleanup of any artifacts produced is recommended, when
    /// applicable, if [`IOCancelledException`] is thrown by this input stream.
    pub fn set_cleanup_on_cancel(mut self, enable: bool) -> Self {
        self.cleanup_on_cancel = enable;
        self
    }

    /// Determine if artifact cleanup is recommended when possible following cancellation
    /// of this input stream (i.e., [`IOCancelledException`] has been caught).
    pub fn cleanup_on_cancel(&self) -> bool {
        self.cleanup_on_cancel
    }
}

impl<'a, R: Read> Read for MonitoredInputStream<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.monitor.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Other, IOCancelledException::new()));
        }
        let n = self.inner.read(buf)?;
        self.small_count += n as i64;
        if self.small_count >= PROGRESS_INCREMENT {
            self.count += self.small_count;
            self.small_count = 0;
            self.monitor.set_progress(self.count);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

    struct RecordingMonitor {
        cancelled: AtomicBool,
        progress: AtomicI64,
    }

    impl RecordingMonitor {
        fn new() -> Self {
            Self {
                cancelled: AtomicBool::new(false),
                progress: AtomicI64::new(-1),
            }
        }
    }

    impl TaskMonitor for RecordingMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, value: i64) {
            self.progress.store(value, Ordering::SeqCst);
        }
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            self.progress.load(Ordering::SeqCst)
        }
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn reads_through_to_inner_stream() {
        let monitor = DummyMonitor;
        let data = vec![1u8, 2, 3, 4, 5];
        let mut stream = MonitoredInputStream::new(Cursor::new(data.clone()), &monitor);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn cancelled_monitor_fails_read() {
        let monitor = RecordingMonitor::new();
        monitor.cancel();
        let mut stream = MonitoredInputStream::new(Cursor::new(vec![1u8, 2, 3]), &monitor);
        let mut buf = [0u8; 3];
        let err = stream.read(&mut buf).unwrap_err();
        assert!(err.to_string().contains("IO cancelled by user"));
    }

    #[test]
    fn reports_progress_once_increment_reached() {
        let monitor = RecordingMonitor::new();
        let data = vec![0u8; PROGRESS_INCREMENT as usize + 10];
        let mut stream = MonitoredInputStream::new(Cursor::new(data), &monitor);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(monitor.get_progress(), PROGRESS_INCREMENT);
    }

    #[test]
    fn no_progress_reported_below_increment() {
        let monitor = RecordingMonitor::new();
        let data = vec![0u8; 10];
        let mut stream = MonitoredInputStream::new(Cursor::new(data), &monitor);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(monitor.get_progress(), -1);
    }

    #[test]
    fn set_progress_resets_count() {
        let monitor = DummyMonitor;
        let mut stream = MonitoredInputStream::new(Cursor::new(vec![1u8]), &monitor);
        stream.set_progress(42);
        assert_eq!(stream.count, 42);
    }

    #[test]
    fn task_monitor_accessor_returns_same_monitor() {
        let monitor = DummyMonitor;
        let stream = MonitoredInputStream::new(Cursor::new(vec![1u8]), &monitor);
        assert!(!stream.task_monitor().is_cancelled());
    }

    #[test]
    fn cleanup_on_cancel_defaults_to_false() {
        let monitor = DummyMonitor;
        let stream = MonitoredInputStream::new(Cursor::new(vec![1u8]), &monitor);
        assert!(!stream.cleanup_on_cancel());
    }

    #[test]
    fn cleanup_on_cancel_can_be_enabled() {
        let monitor = DummyMonitor;
        let stream = MonitoredInputStream::new(Cursor::new(vec![1u8]), &monitor)
            .set_cleanup_on_cancel(true);
        assert!(stream.cleanup_on_cancel());
    }

    #[test]
    fn small_reads_accumulate_progress_across_calls() {
        let monitor = RecordingMonitor::new();
        let half = (PROGRESS_INCREMENT / 2) as usize;
        let data = vec![0u8; half * 2 + 1];
        let mut stream = MonitoredInputStream::new(Cursor::new(data), &monitor);
        let mut buf = vec![0u8; half];
        let n1 = stream.read(&mut buf).unwrap();
        assert_eq!(n1, half);
        // Still below the increment threshold after the first read.
        assert_eq!(monitor.get_progress(), -1);
        let n2 = stream.read(&mut buf).unwrap();
        assert_eq!(n2, half);
        assert_eq!(monitor.get_progress(), PROGRESS_INCREMENT);
    }
}
