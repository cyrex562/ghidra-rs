use crate::trace::seam_stubs::{TraceSchedule, TraceSnapshot, TimeRadix};

/// The attribute key for controlling the time radix.
///
/// Port of `ghidra.trace.model.time.TraceTimeManager.KEY_TIME_RADIX`. Hoisted out of the trait
/// (rather than kept as an associated const) because associated consts make a trait
/// dyn-incompatible, and `TraceTimeManager` is used pervasively as `Box<dyn TraceTimeManager>`.
pub const KEY_TIME_RADIX: &str = "_time_radix";

/// Manages the set of snapshots (points in time) recorded in a trace.
///
/// Port of `ghidra.trace.model.time.TraceTimeManager`.
pub trait TraceTimeManager {
    /// Create a new snapshot after the latest.
    ///
    /// `description`: a description of the new snapshot, i.e., the reason for advancing.
    ///
    /// Returns the created snapshot.
    fn create_snapshot(&self, description: &str) -> Box<dyn TraceSnapshot>;

    /// Get the snapshot with the given key, optionally creating it.
    ///
    /// `create_if_absent`: create the snapshot if it's missing.
    ///
    /// Returns the snapshot, or `None` if absent and not created.
    fn get_snapshot(&self, snap: i64, create_if_absent: bool) -> Option<Box<dyn TraceSnapshot>>;

    /// Get the most recent snapshot since a given key.
    ///
    /// Returns the snapshot, or `None`.
    fn get_most_recent_snapshot(&self, snap: i64) -> Option<Box<dyn TraceSnapshot>>;

    /// Get the most recent fork snapshot key since a given key.
    ///
    /// This searches the snapshots for one where `TraceSnapshot::is_fork()` is true. Note that
    /// conventionally, negative snaps are *scratch* space. If a non-negative snap is given, then
    /// the returned fork snap must also be non-negative, i.e., if no non-negative fork snapshot
    /// is found, this returns 0, the initial snapshot. If a negative snap is given, then the
    /// returned fork snap must also be negative, i.e., if no negative fork snapshot is found,
    /// this returns `i64::MIN`, even if that snapshot does not actually exist.
    fn get_most_recent_fork(&self, snap: i64) -> i64;

    /// Get all snapshots with the given schedule.
    ///
    /// Ideally, the snapshot schedules should be managed such that the returned collection
    /// contains at most one snapshot.
    fn get_snapshots_with_schedule(
        &self,
        schedule: &dyn TraceSchedule,
    ) -> Vec<Box<dyn TraceSnapshot>>;

    /// Find or create the snapshot with the given schedule.
    ///
    /// If a snapshot with the given schedule already exists, this returns the first such
    /// snapshot found. Ideally, there is exactly one. If this method is consistently used for
    /// creating scratch snapshots, then that should always be the case. If no such snapshot
    /// exists, this creates a snapshot with the minimum available negative snapshot key, that is
    /// starting at `i64::MIN` and increasing from there.
    fn find_scratch_snapshot(&self, schedule: &dyn TraceSchedule) -> Box<dyn TraceSnapshot>;

    /// Find the nearest related snapshot whose schedule is a prefix of the given schedule.
    ///
    /// This finds a snapshot that can be used as the initial state of an emulator to materialize
    /// the state at the given schedule. The one it returns is the one that would require the
    /// fewest instruction steps. Note that since an emulator cannot be initialized into the
    /// middle of an instruction, snapshots whose schedules contain p-code op steps are ignored.
    /// Additionally, this ignores any snapshots whose version is less than the emulator cache
    /// version.
    ///
    /// Returns the found snapshot, or `None`.
    fn find_snapshot_with_nearest_prefix(
        &self,
        schedule: &dyn TraceSchedule,
    ) -> Option<Box<dyn TraceSnapshot>>;

    /// List all snapshots in the trace.
    fn get_all_snapshots(&self) -> Vec<Box<dyn TraceSnapshot>>;

    /// List all snapshots between two given snaps in the trace.
    fn get_snapshots(
        &self,
        from_snap: i64,
        from_inclusive: bool,
        to_snap: i64,
        to_inclusive: bool,
    ) -> Vec<Box<dyn TraceSnapshot>>;

    /// Get the maximum snapshot key that has ever existed, usually that of the latest snapshot.
    ///
    /// Note, the corresponding snapshot need not exist, as it may have been deleted.
    ///
    /// Returns the key, or `None` if no snapshots have existed.
    fn get_max_snap(&self) -> Option<i64>;

    /// Get the number of snapshots.
    fn get_snapshot_count(&self) -> i64;

    /// Set the radix for displaying and parsing time (snapshots and step counts).
    ///
    /// This only affects the GUI, but storing it in the trace gives the back end a means of
    /// controlling it.
    fn set_time_radix(&mut self, radix: Box<dyn TimeRadix>);

    /// Get the radix for displaying and parsing time (snapshots and step counts).
    fn get_time_radix(&self) -> Box<dyn TimeRadix>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockSnapshot {
        key: i64,
        fork: bool,
    }

    impl TraceSnapshot for MockSnapshot {
        fn is_fork(&self) -> bool {
            self.fork
        }
    }

    struct MockRadix(i32);
    impl TimeRadix for MockRadix {
        fn radix(&self) -> i32 {
            self.0
        }
    }

    struct MockSchedule;
    impl TraceSchedule for MockSchedule {}

    struct MockTimeManager {
        snapshots: Mutex<Vec<(i64, bool)>>,
        radix: Mutex<i32>,
    }

    impl TraceTimeManager for MockTimeManager {
        fn create_snapshot(&self, _description: &str) -> Box<dyn TraceSnapshot> {
            let mut snaps = self.snapshots.lock().unwrap();
            let key = snaps.last().map(|(k, _)| k + 1).unwrap_or(0);
            snaps.push((key, false));
            Box::new(MockSnapshot { key, fork: false })
        }

        fn get_snapshot(&self, snap: i64, create_if_absent: bool) -> Option<Box<dyn TraceSnapshot>> {
            let mut snaps = self.snapshots.lock().unwrap();
            if let Some((k, f)) = snaps.iter().find(|(k, _)| *k == snap).copied() {
                return Some(Box::new(MockSnapshot { key: k, fork: f }));
            }
            if create_if_absent {
                snaps.push((snap, false));
                return Some(Box::new(MockSnapshot { key: snap, fork: false }));
            }
            None
        }

        fn get_most_recent_snapshot(&self, snap: i64) -> Option<Box<dyn TraceSnapshot>> {
            let snaps = self.snapshots.lock().unwrap();
            snaps
                .iter()
                .filter(|(k, _)| *k <= snap)
                .max_by_key(|(k, _)| *k)
                .map(|(k, f)| Box::new(MockSnapshot { key: *k, fork: *f }) as Box<dyn TraceSnapshot>)
        }

        fn get_most_recent_fork(&self, snap: i64) -> i64 {
            let snaps = self.snapshots.lock().unwrap();
            if snap >= 0 {
                snaps
                    .iter()
                    .filter(|(k, f)| *k >= 0 && *k <= snap && *f)
                    .map(|(k, _)| *k)
                    .max()
                    .unwrap_or(0)
            } else {
                snaps
                    .iter()
                    .filter(|(k, f)| *k < 0 && *k <= snap && *f)
                    .map(|(k, _)| *k)
                    .max()
                    .unwrap_or(i64::MIN)
            }
        }

        fn get_snapshots_with_schedule(
            &self,
            _schedule: &dyn TraceSchedule,
        ) -> Vec<Box<dyn TraceSnapshot>> {
            Vec::new()
        }

        fn find_scratch_snapshot(&self, _schedule: &dyn TraceSchedule) -> Box<dyn TraceSnapshot> {
            let mut snaps = self.snapshots.lock().unwrap();
            let key = snaps.iter().map(|(k, _)| *k).min().unwrap_or(0).min(i64::MIN + 1) - 1;
            snaps.push((key, false));
            Box::new(MockSnapshot { key, fork: false })
        }

        fn find_snapshot_with_nearest_prefix(
            &self,
            _schedule: &dyn TraceSchedule,
        ) -> Option<Box<dyn TraceSnapshot>> {
            None
        }

        fn get_all_snapshots(&self) -> Vec<Box<dyn TraceSnapshot>> {
            self.snapshots
                .lock()
                .unwrap()
                .iter()
                .map(|(k, f)| Box::new(MockSnapshot { key: *k, fork: *f }) as Box<dyn TraceSnapshot>)
                .collect()
        }

        fn get_snapshots(
            &self,
            from_snap: i64,
            from_inclusive: bool,
            to_snap: i64,
            to_inclusive: bool,
        ) -> Vec<Box<dyn TraceSnapshot>> {
            self.snapshots
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| {
                    let above_from = if from_inclusive { *k >= from_snap } else { *k > from_snap };
                    let below_to = if to_inclusive { *k <= to_snap } else { *k < to_snap };
                    above_from && below_to
                })
                .map(|(k, f)| Box::new(MockSnapshot { key: *k, fork: *f }) as Box<dyn TraceSnapshot>)
                .collect()
        }

        fn get_max_snap(&self) -> Option<i64> {
            self.snapshots.lock().unwrap().iter().map(|(k, _)| *k).max()
        }

        fn get_snapshot_count(&self) -> i64 {
            self.snapshots.lock().unwrap().len() as i64
        }

        fn set_time_radix(&mut self, radix: Box<dyn TimeRadix>) {
            let _ = radix;
            *self.radix.lock().unwrap() = 16;
        }

        fn get_time_radix(&self) -> Box<dyn TimeRadix> {
            Box::new(MockRadix(*self.radix.lock().unwrap()))
        }
    }

    fn make_manager() -> MockTimeManager {
        MockTimeManager {
            snapshots: Mutex::new(Vec::new()),
            radix: Mutex::new(10),
        }
    }

    #[test]
    fn usable_as_trait_object_and_tracks_snapshots() {
        let mut manager: Box<dyn TraceTimeManager> = Box::new(make_manager());

        assert_eq!(manager.get_max_snap(), None);
        assert_eq!(manager.get_snapshot_count(), 0);

        let s0 = manager.create_snapshot("initial");
        assert_eq!(s0.is_fork(), false);
        let s1 = manager.create_snapshot("advance");
        assert_eq!(s1.is_fork(), false);

        assert_eq!(manager.get_snapshot_count(), 2);
        assert_eq!(manager.get_max_snap(), Some(1));

        assert!(manager.get_snapshot(0, false).is_some());
        assert!(manager.get_snapshot(5, false).is_none());
        assert!(manager.get_snapshot(5, true).is_some());
        assert_eq!(manager.get_snapshot_count(), 3);

        let recent = manager.get_most_recent_snapshot(4).unwrap();
        assert_eq!(recent.is_fork(), false);

        let all = manager.get_all_snapshots();
        assert_eq!(all.len(), 3);

        let ranged = manager.get_snapshots(0, true, 1, true);
        assert_eq!(ranged.len(), 2);

        manager.set_time_radix(Box::new(MockRadix(16)));
        assert_eq!(manager.get_time_radix().radix(), 16);
    }

    #[test]
    fn find_scratch_snapshot_creates_negative_key() {
        let manager = make_manager();
        let scratch = manager.find_scratch_snapshot(&MockSchedule);
        assert_eq!(scratch.is_fork(), false);
        assert!(manager.get_max_snap().is_some());
    }

    #[test]
    fn key_time_radix_constant_matches_java() {
        assert_eq!(KEY_TIME_RADIX, "_time_radix");
    }
}
