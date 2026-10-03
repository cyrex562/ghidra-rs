//! Corresponds to `ghidra.docking.spy.SpyEventRecorder`.

use crate::util::msg::Msg;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Records messages for later playback. This can be useful for tracking the order of
/// sequences/callbacks.
pub struct SpyEventRecorder {
    recorder_name: String,
    state: Mutex<RecorderState>,
    buffered: AtomicBool,
}

struct RecorderState {
    global_id: u64,
    events: Vec<SpyEvent>,
}

impl SpyEventRecorder {
    pub fn new(recorder_name: impl Into<String>) -> Self {
        SpyEventRecorder {
            recorder_name: recorder_name.into(),
            state: Mutex::new(RecorderState {
                global_id: 0,
                events: Vec::new(),
            }),
            buffered: AtomicBool::new(true),
        }
    }

    pub fn set_buffered(&self, buffered: bool) {
        self.buffered.store(buffered, Ordering::SeqCst);
    }

    /// Records the given message. Callable from multiple threads, as this method spies on
    /// events from things like tests and Swing.
    pub fn record(&self, message: impl Into<String>) {
        let mut state = self.state.lock().unwrap();
        state.global_id += 1;
        let event = SpyEvent {
            id: state.global_id,
            message: message.into(),
            time: SystemTime::now(),
        };

        if self.buffered.load(Ordering::SeqCst) {
            state.events.push(event);
        } else {
            // stderr intentional here for aesthetics
            eprintln!("{}", event.formatted(0));
        }
    }

    /// Records a message built from pre-formatted arguments (the Rust analog of the Java
    /// `record(String, Object...)` overload, which uses `String.format`).
    pub fn record_fmt(&self, args: fmt::Arguments) {
        self.record(fmt::format(args));
    }

    fn events_to_string(&self) -> String {
        let state = self.state.lock().unwrap();
        let size = state.events.len();
        let id_pad = size.to_string().len();

        let mut buffy = format!("Recorded Events - {}\n", self.recorder_name);
        for event in &state.events {
            buffy.push_str(&event.formatted(id_pad));
            buffy.push('\n');
        }
        buffy
    }

    pub fn dump_events(&self) {
        Msg::debug(&self.recorder_name, &self.events_to_string());
    }
}

impl fmt::Display for SpyEventRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.events_to_string())
    }
}

struct SpyEvent {
    id: u64,
    message: String,
    time: SystemTime,
}

impl SpyEvent {
    fn formatted(&self, id_pad: usize) -> String {
        let id_str = self.id.to_string();
        let delta = id_pad.saturating_sub(id_str.len());
        let pad = " ".repeat(delta);
        format!(
            "({}) {}{} {}",
            self.id,
            pad,
            format_time(self.time),
            self.message
        )
    }
}

/// Formats a time as `'T'HH:mm:ss:SSS`, matching the Java `FastDateFormat` pattern used by
/// the original recorder.
fn format_time(time: SystemTime) -> String {
    let millis_since_epoch = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let millis = millis_since_epoch % 1000;
    let total_secs = millis_since_epoch / 1000;
    let secs = total_secs % 60;
    let total_mins = total_secs / 60;
    let mins = total_mins % 60;
    let total_hours = total_mins / 60;
    let hours = total_hours % 24;

    format!("T{:02}:{:02}:{:02}:{:03}", hours, mins, secs, millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_recorder_has_no_events() {
        let recorder = SpyEventRecorder::new("test");
        let text = recorder.to_string();
        assert_eq!(text, "Recorded Events - test\n");
    }

    #[test]
    fn record_appends_buffered_events_in_order() {
        let recorder = SpyEventRecorder::new("test");
        recorder.record("first");
        recorder.record("second");

        let text = recorder.to_string();
        assert!(text.starts_with("Recorded Events - test\n"));
        let lines: Vec<&str> = text.lines().skip(1).collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("(1)"));
        assert!(lines[0].ends_with("first"));
        assert!(lines[1].contains("(2)"));
        assert!(lines[1].ends_with("second"));
    }

    #[test]
    fn record_fmt_formats_arguments_like_string_format() {
        let recorder = SpyEventRecorder::new("test");
        recorder.record_fmt(format_args!("value={}", 42));

        let text = recorder.to_string();
        assert!(text.contains("value=42"));
    }

    #[test]
    fn set_buffered_false_does_not_store_events() {
        let recorder = SpyEventRecorder::new("test");
        recorder.set_buffered(false);
        recorder.record("not stored");

        let text = recorder.to_string();
        assert_eq!(text, "Recorded Events - test\n");
    }

    #[test]
    fn global_id_increments_across_records() {
        let recorder = SpyEventRecorder::new("test");
        for _ in 0..12 {
            recorder.record("event");
        }

        let text = recorder.to_string();
        assert!(text.contains("(12) "));
    }

    #[test]
    fn format_time_produces_expected_pattern() {
        let time = UNIX_EPOCH + std::time::Duration::from_millis(3 * 3_600_000 + 4 * 60_000 + 5_000 + 6);
        assert_eq!(format_time(time), "T03:04:05:006");
    }
}
