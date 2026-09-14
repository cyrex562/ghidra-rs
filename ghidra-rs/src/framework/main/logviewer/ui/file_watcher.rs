//! Port of `ghidra.framework.main.logviewer.ui.FileWatcher`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use crate::framework::main::logviewer::event::{EventType, FVEvent, FVEventListener};
use crate::util::timer::{GTimer, GTimerMonitor, StdGTimer};

/// Mirrors `FileWatcher.POLLING_INTERVAL_SEC`.
const POLLING_INTERVAL_SEC: i64 = 5;
/// Mirrors `FileWatcher.POLLING_DELAY_SEC`.
const POLLING_DELAY_SEC: i64 = 0;

/// Returns the file's last-modified time in milliseconds since the Unix epoch, or `0` if the
/// file does not exist or its metadata/modification time cannot be read.
///
/// Mirrors `File.lastModified()`, which likewise never throws and returns `0L` on any such
/// failure rather than propagating an error.
fn last_modified_millis(file: &Path) -> i64 {
    fs::metadata(file)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The pure decision logic of `FileWatcher.isFileUpdated(File)`, split out from the real
/// filesystem read ([`last_modified_millis`]) so it can be unit-tested without depending on
/// actual file-modification timestamps (whose OS-level resolution can be coarser than a test
/// wants to wait for).
///
/// If `timestamp` holds `-1` (the sentinel for "never checked yet"), this records `current` and
/// reports no update -- this is here to keep from popping up a notification immediately after
/// the file has been brought up. Otherwise, it reports an update (and records the new value)
/// exactly when `current` differs from the previously recorded timestamp.
fn is_file_updated_at(current: i64, timestamp: &AtomicI64) -> bool {
    let previous = timestamp.load(Ordering::SeqCst);
    if previous == -1 {
        timestamp.store(current, Ordering::SeqCst);
        return false;
    }
    if previous != current {
        timestamp.store(current, Ordering::SeqCst);
        return true;
    }
    false
}

/// The `FileWatcher` *watches* a single file and fires a change notification whenever the file
/// is modified. A couple notes:
///
/// 1. To keep from processing change events every time the file is modified, which may be too
///    frequent and cause processing issues, we use a simple polling mechanism.
///
/// 2. Changes in the file are identified by inspecting the last-modified timestamp.
///
/// 3. A `WatchService`-style mechanism is not used here since we cannot specify a polling rate.
///
/// Port of `ghidra.framework.main.logviewer.ui.FileWatcher`.
///
/// # Differences from Java
///
/// - Java's `Executors.newSingleThreadScheduledExecutor()` becomes a composed
///   [`GTimer`](crate::util::timer::GTimer) (defaulting to
///   [`StdGTimer`](crate::util::timer::StdGTimer) via [`FileWatcher::new`]), matching this
///   crate's established scheduling seam (see [`GTimer`]'s own docs). `FileWatcher::with_timer`
///   lets tests inject a deterministic timer.
/// - Java's `if (executor == null) return;` guard in `start()` protects against a field that, in
///   the real class, is set exactly once in the constructor and never nulled out afterward (no
///   `shutdown()`/setter exists) -- i.e. genuinely dead code in every real Ghidra build. This port
///   omits it rather than modeling an always-`Some` field as `Option`.
/// - Java's `run()` re-checks `future.isCancelled()` on every tick before doing any work, guarding
///   against the case where the executor had already dequeued a tick for execution at the moment
///   `cancel()` was called. [`StdGTimer`]'s own repeating-task loop already performs the
///   equivalent check (it tests its cancellation flag immediately before invoking the callback
///   each iteration -- see that type's docs), so this port does not duplicate the check inside the
///   scheduled closure itself; the observable behavior (no work happens on a tick after
///   [`FileWatcher::stop`]) is the same either way.
pub struct FileWatcher {
    timestamp: Arc<AtomicI64>,
    file: PathBuf,
    event_listener: Arc<FVEventListener>,
    timer: Box<dyn GTimer>,
    future: Mutex<Option<Box<dyn GTimerMonitor>>>,
}

impl FileWatcher {
    /// Constructor. Users must call [`FileWatcher::start`] to begin polling.
    ///
    /// Mirrors `FileWatcher(File, FVEventListener)`, using [`StdGTimer`] as the scheduling
    /// backend (see the module docs for why a `GTimer` stands in for Java's
    /// `ScheduledExecutorService`).
    pub fn new(file: PathBuf, event_listener: Arc<FVEventListener>) -> Self {
        Self::with_timer(file, event_listener, Box::new(StdGTimer))
    }

    /// As [`FileWatcher::new`], but with an injectable [`GTimer`] -- primarily for deterministic
    /// tests.
    pub fn with_timer(file: PathBuf, event_listener: Arc<FVEventListener>, timer: Box<dyn GTimer>) -> Self {
        FileWatcher {
            timestamp: Arc::new(AtomicI64::new(-1)),
            file,
            event_listener,
            timer,
            future: Mutex::new(None),
        }
    }

    /// Suspends the timer so it will no longer poll. This does not perform a shutdown, so the
    /// future may be scheduled again.
    ///
    /// Mirrors `FileWatcher.stop()`.
    ///
    /// # Panics
    /// If called before [`FileWatcher::start`], mirroring the Java method's `future.cancel(false)`
    /// throwing `NullPointerException` when `future` is still `null`.
    pub fn stop(&self) {
        let guard = self.future.lock().unwrap();
        let monitor = guard.as_ref().expect(
            "NullPointerException: future is null (mirrors Java's future.cancel(false) call in \
             stop() before start() has ever run)",
        );
        monitor.cancel();
    }

    /// Starts polling, or resumes polling if previously stopped.
    ///
    /// Mirrors `FileWatcher.start()`.
    pub fn start(&self) {
        let timestamp = Arc::clone(&self.timestamp);
        let file = self.file.clone();
        let event_listener = Arc::clone(&self.event_listener);

        let monitor = self.timer.schedule_repeating_runnable(
            POLLING_DELAY_SEC * 1000,
            POLLING_INTERVAL_SEC * 1000,
            Box::new(move || {
                if is_file_updated_at(last_modified_millis(&file), &timestamp) {
                    let update_evt = FVEvent::new(EventType::FileChanged, Box::new(()));
                    event_listener.send(&update_evt);
                }
            }),
        );
        *self.future.lock().unwrap() = Some(monitor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::time::Duration;

    /// A [`GTimer`] whose `schedule_repeating_runnable` invokes the callback synchronously,
    /// exactly once, and returns a monitor that just remembers whether it was cancelled --
    /// letting tests exercise [`FileWatcher::start`]/[`FileWatcher::stop`] deterministically
    /// without waiting on real wall-clock polling.
    struct ImmediateOnceTimer;

    struct RecordingMonitor {
        cancelled: std::sync::atomic::AtomicBool,
    }

    impl GTimerMonitor for RecordingMonitor {
        fn cancel(&self) -> bool {
            self.cancelled.store(true, Ordering::SeqCst);
            true
        }
        fn did_run(&self) -> bool {
            true
        }
        fn was_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
    }

    impl GTimer for ImmediateOnceTimer {
        fn schedule_runnable(
            &self,
            _delay_millis: i64,
            mut callback: crate::util::timer::GTimerCallback,
        ) -> Box<dyn GTimerMonitor> {
            callback();
            Box::new(RecordingMonitor { cancelled: std::sync::atomic::AtomicBool::new(false) })
        }

        fn schedule_repeating_runnable(
            &self,
            _delay_millis: i64,
            _period_millis: i64,
            mut callback: crate::util::timer::GTimerCallback,
        ) -> Box<dyn GTimerMonitor> {
            callback();
            Box::new(RecordingMonitor { cancelled: std::sync::atomic::AtomicBool::new(false) })
        }
    }

    fn unique_temp_file(tag: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!("ghidra_rs_file_watcher_test_{tag}_{n}.txt"));
        fs::write(&path, b"hello").unwrap();
        path
    }

    // ── is_file_updated_at (pure logic) ──────────────────────────────────

    #[test]
    fn first_check_is_never_an_update() {
        // Mirrors: "If the timestamp == -1, then this is the first time the timer has gone off,
        // so ignore it."
        let timestamp = AtomicI64::new(-1);
        assert!(!is_file_updated_at(1000, &timestamp));
        assert_eq!(timestamp.load(Ordering::SeqCst), 1000);
    }

    #[test]
    fn unchanged_mtime_is_not_an_update() {
        let timestamp = AtomicI64::new(1000);
        assert!(!is_file_updated_at(1000, &timestamp));
    }

    #[test]
    fn changed_mtime_is_an_update_and_records_the_new_value() {
        let timestamp = AtomicI64::new(1000);
        assert!(is_file_updated_at(2000, &timestamp));
        assert_eq!(timestamp.load(Ordering::SeqCst), 2000);

        // The next check against the same new value is no longer an update.
        assert!(!is_file_updated_at(2000, &timestamp));
    }

    // ── last_modified_millis (real filesystem access) ────────────────────

    #[test]
    fn last_modified_millis_of_a_missing_file_is_zero() {
        let missing = std::env::temp_dir().join("ghidra_rs_file_watcher_definitely_missing_xyz");
        assert_eq!(last_modified_millis(&missing), 0);
    }

    #[test]
    fn last_modified_millis_of_a_real_file_is_positive() {
        let path = unique_temp_file("mtime");
        assert!(last_modified_millis(&path) > 0);
        let _ = fs::remove_file(&path);
    }

    // ── start / stop wiring ───────────────────────────────────────────────

    #[test]
    fn start_with_a_freshly_written_file_does_not_fire_on_the_first_tick() {
        let path = unique_temp_file("first_tick");
        let listener = Arc::new(FVEventListener::new());
        let (tx, rx) = mpsc::channel::<EventType>();

        struct Recorder(mpsc::Sender<EventType>);
        impl crate::framework::main::logviewer::event::FVObserver for Recorder {
            fn update(&self, _source: &FVEventListener, evt: &FVEvent) {
                self.0.send(evt.event_type).unwrap();
            }
        }
        listener.add_observer(Arc::new(Recorder(tx)));

        let watcher = FileWatcher::with_timer(path.clone(), listener, Box::new(ImmediateOnceTimer));
        watcher.start();

        // First tick only records the baseline timestamp; no FILE_CHANGED event yet.
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn stop_cancels_the_scheduled_future() {
        let path = unique_temp_file("stop");
        let listener = Arc::new(FVEventListener::new());
        let watcher = FileWatcher::with_timer(path.clone(), listener, Box::new(ImmediateOnceTimer));

        watcher.start();
        watcher.stop();

        let guard = watcher.future.lock().unwrap();
        assert!(guard.as_ref().unwrap().was_cancelled());
        drop(guard);
        let _ = fs::remove_file(&path);
    }

    #[test]
    #[should_panic(expected = "NullPointerException")]
    fn stop_before_start_panics_like_javas_npe() {
        let path = unique_temp_file("stop_before_start");
        let listener = Arc::new(FVEventListener::new());
        let watcher = FileWatcher::new(path, listener);
        watcher.stop();
    }
}
