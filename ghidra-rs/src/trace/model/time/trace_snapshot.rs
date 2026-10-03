//! Port of `ghidra.trace.model.time.TraceSnapshot`.

use std::sync::Arc;

use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::TraceSchedule;
use crate::trace::model::thread::TraceThread;

/// A "snapshot in time" in a trace.
///
/// This is not so much a snapshot as it is simply a marker in time. Each manager handles time on
/// its own, using the keys from these snapshots. Snapshot keys are called "snaps" for short.
/// While a snapshot need not exist for another manager to use its numeric key, it is proper
/// convention to create a snapshot before populating any other manager with corresponding
/// entries.
///
/// NOTE: There is a transitional phase here where some managers may still use "tick" instead of
/// "snap".
///
/// Port of `ghidra.trace.model.time.TraceSnapshot`. The sole in-repo implementor is
/// `ghidra.trace.database.time.DBTraceSnapshot`, itself not yet ported; its placeholder,
/// [`DBTraceSnapshot`](crate::trace::seam_stubs::DBTraceSnapshot), implements this trait.
pub trait TraceSnapshot: Send + Sync {
    /// Returns the trace that owns this snapshot.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Returns a key which orders the snapshot chronologically -- the database key.
    fn get_key(&self) -> i64;

    /// Returns the description of the snapshot.
    fn get_description(&self) -> String;

    /// Sets the human-consumable description of the snapshot.
    fn set_description(&self, description: &str);

    /// Returns the real creation time of this snapshot in milliseconds since the epoch.
    fn get_real_time(&self) -> i64;

    /// Sets the real creation time of this snapshot in milliseconds since Jan 1, 1970 12:00 AM
    /// (UTC).
    fn set_real_time(&self, millis_since_epoch: i64);

    /// If this snapshot was created because of an event, returns the thread that caused it.
    fn get_event_thread(&self) -> Option<Box<dyn TraceThread>>;

    /// If this snapshot was created because of an event, sets the thread that caused it.
    fn set_event_thread(&self, thread: Option<Box<dyn TraceThread>>);

    /// Returns the schedule, if applicable and known, relating this snapshot to a previous one.
    ///
    /// This information is not always known, or even applicable. If recording a single step,
    /// ideally, this is simply the previous snap plus one step of the event thread, e.g., for
    /// snap 6, the schedule would be "5:1". For an emulated machine cached in scratch space, this
    /// should be the schedule that would recover the same machine state.
    ///
    /// The object managers in the trace pay no heed to this schedule. In particular, when
    /// retrieving the "most-recent" information from a snapshot with a known schedule, the
    /// "previous snap" part of that schedule is *not* taken into account. In other words, the
    /// managers still interpret time linearly, even though this schedule field might imply
    /// built-in forking.
    fn get_schedule(&self) -> Option<Arc<dyn TraceSchedule>>;

    /// Returns the string representation of the schedule (possibly empty).
    fn get_schedule_string(&self) -> String;

    /// Checks whether this snapshot represents a fork.
    ///
    /// A snapshot is a fork if the snap immediately preceding it does not actually represent its
    /// immediately preceding snapshot in time. This is the case if the snapshot has a schedule
    /// whose initial snapshot is not the one immediately preceding it. NOTE: The (scratch)
    /// snapshot with the minimum key is *not* considered a fork.
    fn is_fork(&self) -> bool;

    /// Sets the schedule from some previous snapshot to this one.
    fn set_schedule(&self, schedule: Option<Arc<dyn TraceSchedule>>);

    /// Returns the snapshot's version, esp. when it represents a cache entry.
    fn get_version(&self) -> i64;

    /// Sets the snapshot's version, esp. when it represents a cache entry.
    fn set_version(&self, version: i64);

    /// Checks if a snapshot involves any steps of emulation.
    ///
    /// A scratch snapshot, i.e. whose key is negative, without a schedule set is considered
    /// inconsistent.
    ///
    /// `when_inconsistent`: the value to return for a scratch snapshot without a set schedule.
    fn is_snap_only(&self, when_inconsistent: bool) -> bool;

    /// For an emulated snapshot, checks if re-emulation is necessary to produce an up-to-date
    /// snapshot.
    ///
    /// For non-emulated snapshots, this always returns false. A non-emulated snapshot is a
    /// snapshot whose schedule includes no emulation steps. An emulation snapshot is stale when
    /// its version is less than the trace's emulator cache version. A scratch snapshot, i.e.
    /// whose key is negative, without a schedule set is considered inconsistent.
    ///
    /// `when_inconsistent`: the value to return for a scratch snapshot without a set schedule.
    fn is_stale(&self, when_inconsistent: bool) -> bool;

    /// Deletes this snapshot.
    ///
    /// This does not delete any entries in other managers associated with this snapshot. This
    /// simply deletes the marker and accompanying metadata. However, entries associated with
    /// deleted or otherwise non-existent snapshot keys may cause interesting behavior, especially
    /// for keys which exceed the latest snapshot key.
    fn delete(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::seam_stubs::{trace_schedule_snap, DBTraceSnapshot};

    #[test]
    fn dbtracesnapshot_matches_java_trace_snapshot_semantics() {
        let snap: Arc<DBTraceSnapshot> = Arc::new(DBTraceSnapshot::new(5));
        let snapshot: Arc<dyn TraceSnapshot> = snap;

        assert_eq!(snapshot.get_key(), 5);
        assert_eq!(snapshot.get_description(), "");
        assert_eq!(snapshot.get_schedule_string(), "");
        // No schedule, non-negative key: TraceSnapshot.isSnapOnly() is true regardless of
        // whenInconsistent.
        assert!(snapshot.is_snap_only(false));
        assert!(!snapshot.is_fork());

        snapshot.set_description("frame 5");
        assert_eq!(snapshot.get_description(), "frame 5");

        snapshot.set_real_time(1_700_000_000_000);
        assert_eq!(snapshot.get_real_time(), 1_700_000_000_000);

        // A schedule continuing from the immediately preceding snap (4) is not a fork.
        snapshot.set_schedule(Some(trace_schedule_snap(4)));
        assert!(!snapshot.is_fork());
        assert_eq!(snapshot.get_schedule_string(), "4");
        assert!(snapshot.is_snap_only(false));

        // A schedule that does NOT continue from the preceding snap makes this a fork.
        snapshot.set_schedule(Some(trace_schedule_snap(2)));
        assert!(snapshot.is_fork());

        snapshot.set_version(3);
        assert_eq!(snapshot.get_version(), 3);
    }

    #[test]
    fn scratch_snapshot_without_schedule_uses_when_inconsistent() {
        let snapshot: Arc<dyn TraceSnapshot> = Arc::new(DBTraceSnapshot::new(-1));
        assert!(snapshot.is_snap_only(true));
        assert!(!snapshot.is_snap_only(false));
    }
}
