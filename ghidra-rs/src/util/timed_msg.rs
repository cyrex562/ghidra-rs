use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::msg::Msg;

static LAST: OnceLock<Mutex<u64>> = OnceLock::new();

fn get_last() -> &'static Mutex<u64> {
    LAST.get_or_init(|| Mutex::new(0))
}

fn current_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn format_timed(last: &mut u64, now: u64, message: &str) -> String {
    if *last == 0 {
        *last = now;
        format!("(started) {}", message)
    } else {
        let lapsed = now.saturating_sub(*last);
        *last = now;
        format!("({} ms) {}", lapsed, message)
    }
}

/// Provides timestamped debug messaging with elapsed-time tracking.
///
/// The first call prefixes the message with `(started)`. Subsequent calls
/// prefix the message with the milliseconds elapsed since the previous call.
pub struct TimedMsg;

impl TimedMsg {
    /// Emits a debug message via [`Msg::debug`] with an elapsed-time prefix.
    pub fn debug(originator: &str, message: &str) {
        let formatted = {
            let mut last = get_last().lock().unwrap();
            format_timed(&mut last, current_millis(), message)
        };
        Msg::debug(originator, &formatted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_prefixes_started() {
        let mut last = 0u64;
        let result = format_timed(&mut last, 1000, "hello");
        assert_eq!(result, "(started) hello");
        assert_eq!(last, 1000);
    }

    #[test]
    fn second_call_shows_elapsed_ms() {
        let mut last = 0u64;
        format_timed(&mut last, 1000, "first");
        let result = format_timed(&mut last, 1250, "second");
        assert_eq!(result, "(250 ms) second");
        assert_eq!(last, 1250);
    }

    #[test]
    fn zero_elapsed_on_same_timestamp() {
        let mut last = 0u64;
        format_timed(&mut last, 5000, "first");
        let result = format_timed(&mut last, 5000, "same time");
        assert_eq!(result, "(0 ms) same time");
    }

    #[test]
    fn saturating_sub_handles_clock_skew() {
        let mut last = 0u64;
        format_timed(&mut last, 5000, "first");
        let result = format_timed(&mut last, 4000, "backward");
        assert_eq!(result, "(0 ms) backward");
    }
}
