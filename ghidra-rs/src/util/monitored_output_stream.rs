use std::io::{self, Write};

use crate::util::exception::IOCancelledException;
use crate::util::task::TaskMonitor;

const PROGRESS_INCREMENT: i64 = 32 * 1024;

/// Port of `ghidra.util.MonitoredOutputStream`.
///
/// A [`Write`] wrapper that reports output progress to a [`TaskMonitor`] as bytes are written
/// and allows the operation to be cancelled via the monitor. Cancellation is only observed once
/// enough bytes have accumulated to reach the next progress increment, since that is the only
/// point at which the underlying stream reports progress.
pub struct MonitoredOutputStream<'a, W: Write> {
    inner: W,
    monitor: &'a dyn TaskMonitor,
    small_count: i64,
    count: i64,
}

impl<'a, W: Write> MonitoredOutputStream<'a, W> {
    /// Creates a new instance, wrapping `inner` and reporting progress via `monitor`.
    pub fn new(inner: W, monitor: &'a dyn TaskMonitor) -> Self {
        Self {
            inner,
            monitor,
            small_count: 0,
            count: 0,
        }
    }
}

impl<'a, W: Write> Write for MonitoredOutputStream<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.small_count += n as i64;
        if self.small_count >= PROGRESS_INCREMENT {
            if self.monitor.is_cancelled() {
                return Err(io::Error::new(io::ErrorKind::Other, IOCancelledException::new()));
            }
            self.count += self.small_count;
            self.small_count = 0;
            self.monitor.set_progress(self.count);
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;
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
    fn writes_through_to_inner_stream() {
        let monitor = DummyMonitor;
        let mut out = Vec::new();
        let mut stream = MonitoredOutputStream::new(&mut out, &monitor);
        stream.write_all(b"hello").unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn reports_progress_once_increment_reached() {
        let monitor = RecordingMonitor::new();
        let mut out = Vec::new();
        let mut stream = MonitoredOutputStream::new(&mut out, &monitor);
        let data = vec![0u8; PROGRESS_INCREMENT as usize + 10];
        stream.write_all(&data).unwrap();
        assert_eq!(monitor.get_progress(), PROGRESS_INCREMENT);
    }

    #[test]
    fn no_progress_reported_below_increment() {
        let monitor = RecordingMonitor::new();
        let mut out = Vec::new();
        let mut stream = MonitoredOutputStream::new(&mut out, &monitor);
        stream.write_all(&[0u8; 10]).unwrap();
        assert_eq!(monitor.get_progress(), -1);
    }

    #[test]
    fn cancelled_monitor_not_observed_until_increment_reached() {
        let monitor = RecordingMonitor::new();
        monitor.cancel();
        let mut out = Vec::new();
        let mut stream = MonitoredOutputStream::new(&mut out, &monitor);
        // Below the increment, the write succeeds even though the monitor is cancelled.
        stream.write_all(&[1u8, 2, 3]).unwrap();
        assert_eq!(out, vec![1u8, 2, 3]);
    }

    #[test]
    fn cancelled_monitor_fails_write_once_increment_reached() {
        let monitor = RecordingMonitor::new();
        monitor.cancel();
        let mut out = Vec::new();
        let mut stream = MonitoredOutputStream::new(&mut out, &monitor);
        let data = vec![0u8; PROGRESS_INCREMENT as usize];
        let err = stream.write(&data).unwrap_err();
        assert!(err.to_string().contains("IO cancelled by user"));
        // The bytes are still forwarded to the underlying stream before the cancellation check.
        assert_eq!(out.len(), PROGRESS_INCREMENT as usize);
    }

    #[test]
    fn small_writes_accumulate_progress_across_calls() {
        let monitor = RecordingMonitor::new();
        let mut out = Vec::new();
        let mut stream = MonitoredOutputStream::new(&mut out, &monitor);
        let half = vec![0u8; (PROGRESS_INCREMENT / 2) as usize];
        stream.write_all(&half).unwrap();
        assert_eq!(monitor.get_progress(), -1);
        stream.write_all(&half).unwrap();
        stream.write_all(&[0u8]).unwrap();
        assert_eq!(monitor.get_progress(), PROGRESS_INCREMENT + 1);
    }

    #[test]
    fn flush_forwards_to_inner_stream() {
        let monitor = DummyMonitor;
        let mut out = Vec::new();
        let mut stream = MonitoredOutputStream::new(&mut out, &monitor);
        stream.write_all(b"data").unwrap();
        stream.flush().unwrap();
        assert_eq!(out, b"data");
    }
}
