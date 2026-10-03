//! Port of `ghidra.util.UniversalIdGenerator`.
//!
//! Generates process-wide unique [`UniversalID`]s. Each ID packs a millisecond timestamp, a
//! session ID derived from the generator's creation time, and a rolling instance counter into a
//! single `i64`, matching the Java implementation's bit layout (`(baseTime << 21) | (sessionID
//! << 5) | instanceCount`, with `instanceCount` rolling over every 32 IDs to force a fresh
//! timestamp/session read).
//!
//! Java's `nextID()` lazily self-initializes the generator (logging a warning) if
//! `initialize()` was never called; this port mirrors that lazy behavior via `OnceLock`, but
//! without the warning log (no `Msg`/logging seam is threaded through this module).

use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::universal_id::UniversalID;

fn current_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

struct GeneratorState {
    base_time: i64,
    session_id: i64,
    id_base: i64,
    /// Matches Java's `instanceCount = Integer.MAX_VALUE` initial value, which forces
    /// `get_next_id` to establish a fresh base time/id_base on the very first call.
    instance_count: i32,
}

impl GeneratorState {
    fn new() -> Self {
        let session_id = (current_time_millis() >> 4) & 0xffff;
        GeneratorState {
            base_time: 0,
            session_id,
            id_base: 0,
            instance_count: i32::MAX,
        }
    }

    fn get_next_id(&mut self) -> UniversalID {
        if self.instance_count >= 32 {
            self.base_time = self.new_base_time();
            self.id_base = (self.base_time << 21) | (self.session_id << 5);
            self.instance_count = 0;
        }
        let id = self.id_base + self.instance_count as i64;
        self.instance_count += 1;
        UniversalID::new(id)
    }

    fn new_base_time(&self) -> i64 {
        let new_time = current_time_millis();
        if new_time <= self.base_time {
            self.base_time + 1
        } else {
            new_time
        }
    }
}

static GENERATOR: OnceLock<Mutex<GeneratorState>> = OnceLock::new();

/// Returns the next process-wide unique ID, lazily initializing the generator if needed.
///
/// Port of `ghidra.util.UniversalIdGenerator.nextID()`.
pub fn next_id() -> UniversalID {
    let generator = GENERATOR.get_or_init(|| Mutex::new(GeneratorState::new()));
    generator.lock().unwrap().get_next_id()
}

/// Explicitly initializes the generator if it hasn't been already. Calling this is optional --
/// [`next_id`] self-initializes on first use -- but mirrors Java's public `initialize()` for
/// callers that want to establish the generator eagerly.
///
/// Port of `ghidra.util.UniversalIdGenerator.initialize()`.
pub fn initialize() {
    GENERATOR.get_or_init(|| Mutex::new(GeneratorState::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn next_id_returns_unique_values() {
        let mut seen = HashSet::new();
        for _ in 0..2000 {
            let id = next_id();
            assert!(seen.insert(id.value()), "duplicate id {}", id.value());
        }
    }

    #[test]
    fn next_id_is_monotonically_increasing_within_a_thread() {
        let mut last = next_id().value();
        for _ in 0..2000 {
            let current = next_id().value();
            assert!(
                current > last,
                "expected {current} > {last}"
            );
            last = current;
        }
    }

    #[test]
    fn initialize_is_idempotent_and_next_id_still_works() {
        initialize();
        initialize();
        let a = next_id();
        let b = next_id();
        assert_ne!(a, b);
    }
}
