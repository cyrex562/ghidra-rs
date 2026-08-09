//! Port of `ghidra.trace.database.time.DBTraceTimeManager`.
//!
//! The Java class is `DBTraceTimeManager implements TraceTimeManager, DBTraceManager`, both of
//! which are already-ported traits ([`TraceTimeManager`] and [`DBTraceManager`]), so this is a
//! concrete struct implementing them. It sits on a dependency cycle -- `DBTrace` hands it out
//! (`getTimeManager()`) and it reaches back into `DBTrace` for change notification -- which is cut
//! by keeping the trace behind the [`DBTrace`] placeholder rather than a concrete type.
//!
//! # Storage
//!
//! Java keeps its two tables in `DBCachedObjectStore`s obtained from `trace.getStoreFactory()`,
//! with a `DBCachedObjectIndex` over each one's indexed column:
//!
//! | Java field | role | here |
//! | --- | --- | --- |
//! | `snapshotStore` | `Snapshots` table, keyed by snap | `BTreeMap<i64, Arc<DBTraceSnapshot>>` |
//! | `snapshotsBySchedule` | index on the `Schedule` column | derived on demand (see below) |
//! | `forkStore` | `Forks` table | `BTreeMap<i64, DBTraceFork>` |
//! | `forksBySnap` | index on the `Snap` column | the same map -- it *is* keyed by snap |
//!
//! `DBCachedObjectStore` is not ported (and is itself only a navigable, long-keyed, write-through
//! cache over a DB table), so the maps stand in for it directly. Two consequences worth naming:
//!
//! - The by-schedule index is *derived* from the snapshots on each query rather than maintained
//!   incrementally. In Java the DB updates the index whenever the indexed column is written; here
//!   a snapshot's schedule can be rewritten through the snapshot itself, so recomputing keeps the
//!   view honest at the cost of a scan.
//! - `invalidateCache` becomes a no-op: there is no DB behind the map to re-read from, so
//!   dropping it would lose data rather than just a cache. See [`DBTraceTimeManager::invalidate_cache`].
//!
//! Java's `getMaxSnap()` returns `snapshotStore.getMaxKey()`, and its javadoc is explicit that the
//! corresponding snapshot "need not exist, as it may have been deleted" -- Ghidra's `Table` never
//! lowers its key counter. [`TimeState::max_key`] reproduces that: it only ever rises.
//!
//! # Locking
//!
//! Java's constructor is handed the domain object's shared `ReadWriteLock` and takes it around
//! every store access. Rust ties a lock to the data it guards, so that parameter becomes the
//! [`RwLock`] around [`TimeState`]; `LockHold.lock(lock.readLock())` maps to `state.read()` and
//! `lock.writeLock()` to `state.write()`. The one deliberate difference: the guard is released
//! *before* the `notifySnapshotXxx` callbacks run, since those call out into the trace, which may
//! call back in.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::db::util::error_handler::ErrorHandler;
use crate::trace::database::db_trace_manager::DBTraceManager;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::time::schedule::step::StepType;
use crate::trace::model::time::trace_time_manager::{TraceTimeManager, KEY_TIME_RADIX};
use crate::trace::seam_stubs::{
    time_radix_default, time_radix_from_str, trace_schedule_snap, DBTrace, DBTraceSnapshot,
    DBTraceThreadManager, TimeRadix, TraceChangeRecord, TraceSchedule, TraceSnapshot,
};

/// A snapshot key at which the trace's timeline forks, i.e. whose schedule does not simply
/// continue from the preceding snapshot.
///
/// Port of the nested class `DBTraceTimeManager.DBTraceFork`. In Java this is a
/// `DBAnnotatedObject` whose sole column is the snap; the annotations are the table/column
/// declarations, reproduced here as the [`TABLE_NAME`](DBTraceFork::TABLE_NAME) /
/// [`SNAP_COLUMN_NAME`](DBTraceFork::SNAP_COLUMN_NAME) constants. The Java `set(long)` exists only
/// to pair the field write with `update(SNAP_COLUMN)`; with no DB record behind it that is just an
/// assignment, so the field is public instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DBTraceFork {
    /// The forking snapshot's key. Mirrors the indexed `Snap` column.
    pub snap: i64,
}

impl DBTraceFork {
    /// Mirrors `DBTraceFork.TABLE_NAME`.
    pub const TABLE_NAME: &'static str = "Forks";
    /// Mirrors `DBTraceFork.SNAP_COLUMN_NAME`.
    pub const SNAP_COLUMN_NAME: &'static str = "Snap";
}

/// Which snapshot event a [`SnapshotChangeRecord`] carries.
///
/// Stands in for the `TraceEvents.SNAPSHOT_ADDED` / `_CHANGED` / `_DELETED` constants, which live
/// in the unported `TraceEvents`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotEvent {
    Added,
    Changed,
    Deleted,
}

/// Stands in for `new TraceChangeRecord<>(TraceEvents.SNAPSHOT_xxx, null, snapshot)`.
///
/// [`TraceChangeRecord`] is still a marker placeholder, so the trace cannot read anything back out
/// of this; it exists so the `setChanged` calls are made faithfully rather than dropped.
#[allow(dead_code)]
#[derive(Debug)]
struct SnapshotChangeRecord {
    event: SnapshotEvent,
    snapshot_key: i64,
}

impl TraceChangeRecord for SnapshotChangeRecord {}

/// The mutable, lock-guarded half of [`DBTraceTimeManager`]: the two tables and the snapshot
/// table's key counter.
#[derive(Default)]
struct TimeState {
    snapshots: BTreeMap<i64, Arc<DBTraceSnapshot>>,
    forks: BTreeMap<i64, DBTraceFork>,
    /// The largest key ever assigned in `snapshots`, never lowered by a delete. Mirrors
    /// Ghidra's `Table.getMaxKey()`.
    max_key: Option<i64>,
}

impl TimeState {
    /// Mirrors `snapshotStore.create(long)`.
    fn create(&mut self, key: i64) -> Arc<DBTraceSnapshot> {
        let snapshot = Arc::new(DBTraceSnapshot::new(key));
        self.snapshots.insert(key, Arc::clone(&snapshot));
        self.max_key = Some(self.max_key.map_or(key, |m| m.max(key)));
        snapshot
    }

    /// Mirrors `snapshotStore.create()`, which takes the table's next key.
    fn create_next(&mut self) -> Arc<DBTraceSnapshot> {
        self.create(self.max_key.map_or(0, |m| m + 1))
    }
}

/// The trace database's time manager: the snapshots (points in time) recorded in a trace, and the
/// subset of them at which the timeline forks.
///
/// Port of `ghidra.trace.database.time.DBTraceTimeManager`.
///
/// The inherent methods below mirror the Java class's own signatures, which are covariant on the
/// concrete `DBTraceSnapshot` where [`TraceTimeManager`] only promises `TraceSnapshot`; the
/// [`TraceTimeManager`] impl delegates to them and widens the result.
pub struct DBTraceTimeManager {
    trace: Arc<dyn DBTrace>,
    /// Mirrors the `threadManager` field. Java's `DBTraceSnapshot` uses it to resolve an event
    /// thread key; that part of the snapshot is not ported (see [`DBTraceSnapshot`]), so nothing
    /// reads this yet -- it is kept because the manager owns the reference.
    thread_manager: Option<Arc<dyn DBTraceThreadManager>>,
    state: RwLock<TimeState>,
}

impl DBTraceTimeManager {
    /// Create a time manager for `trace`.
    ///
    /// Mirrors `DBTraceTimeManager(DBHandle, OpenMode, ReadWriteLock, TaskMonitor, DBTrace,
    /// DBTraceThreadManager)`, minus the four parameters that exist only to open the two DB tables
    /// through `trace.getStoreFactory()`: with the tables standing in as in-memory maps (see the
    /// module docs) there is nothing for the handle, open mode, or monitor to do, and the lock
    /// moves inside. That also removes the Java `throws VersionException, IOException`, since
    /// neither can arise.
    pub fn new(
        trace: Arc<dyn DBTrace>,
        thread_manager: Option<Arc<dyn DBTraceThreadManager>>,
    ) -> Self {
        Self { trace, thread_manager, state: RwLock::new(TimeState::default()) }
    }

    /// The trace this manager belongs to. Mirrors the `trace` field, which `DBTraceSnapshot`
    /// reads as `manager.trace`.
    pub fn trace(&self) -> &Arc<dyn DBTrace> {
        &self.trace
    }

    /// The trace's thread manager. Mirrors the `threadManager` field.
    pub fn thread_manager(&self) -> Option<&Arc<dyn DBTraceThreadManager>> {
        self.thread_manager.as_ref()
    }

    /// Mirrors `notifySnapshotAdded(DBTraceSnapshot)`.
    fn notify_snapshot_added(&self, snapshot: &Arc<DBTraceSnapshot>) {
        self.trace.update_viewports_snapshot_added(&**snapshot);
        self.trace.set_changed(&SnapshotChangeRecord {
            event: SnapshotEvent::Added,
            snapshot_key: snapshot.get_key(),
        });
    }

    /// Mirrors `notifySnapshotChanged(DBTraceSnapshot)`.
    fn notify_snapshot_changed(&self, snapshot: &Arc<DBTraceSnapshot>) {
        self.trace.update_viewports_snapshot_changed(&**snapshot);
        self.trace.set_changed(&SnapshotChangeRecord {
            event: SnapshotEvent::Changed,
            snapshot_key: snapshot.get_key(),
        });
    }

    /// Mirrors `notifySnapshotDeleted(DBTraceSnapshot)`.
    fn notify_snapshot_deleted(&self, snapshot: &Arc<DBTraceSnapshot>) {
        self.trace.update_viewports_snapshot_deleted(&**snapshot);
        self.trace.set_changed(&SnapshotChangeRecord {
            event: SnapshotEvent::Deleted,
            snapshot_key: snapshot.get_key(),
        });
    }

    /// Milliseconds since the epoch, mirroring `System.currentTimeMillis()`.
    fn current_time_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// The fork-table half of `DBTraceSnapshot.setSchedule(TraceSchedule)`, plus the change
    /// notification.
    ///
    /// In Java the snapshot performs this itself, reaching back through `manager.forksBySnap` and
    /// `manager.forkStore`; here the fork table is this manager's private state, so the operation
    /// lives on the manager and [`DBTraceSnapshot::store_schedule`] handles only the snapshot's
    /// own columns. Passing `None` clears the schedule, mirroring `setSchedule(null)`.
    pub fn set_snapshot_schedule(
        &self,
        snapshot: &Arc<DBTraceSnapshot>,
        schedule: Option<Arc<dyn TraceSchedule>>,
    ) {
        {
            let mut state = self.state.write().unwrap();
            let key = snapshot.get_key();
            let is_fork = snapshot.store_schedule(schedule);
            match (state.forks.contains_key(&key), is_fork) {
                (true, false) => {
                    state.forks.remove(&key);
                }
                (false, true) => {
                    state.forks.insert(key, DBTraceFork { snap: key });
                }
                _ => {}
            }
        }
        self.notify_snapshot_changed(snapshot);
    }

    /// Create a new snapshot after the latest. Mirrors `createSnapshot(String)`.
    pub fn create_snapshot(&self, description: &str) -> Arc<DBTraceSnapshot> {
        let snapshot = {
            let mut state = self.state.write().unwrap();
            let snapshot = state.create_next();
            snapshot.set(Self::current_time_millis(), description);
            snapshot
        };
        if snapshot.get_key() == 0 {
            // Convention for first snap
            self.set_snapshot_schedule(&snapshot, Some(trace_schedule_snap(0)));
        }
        self.notify_snapshot_added(&snapshot);
        snapshot
    }

    /// Get the snapshot with the given key, optionally creating it. Mirrors `getSnapshot(long,
    /// boolean)`.
    pub fn get_snapshot(
        &self,
        snap: i64,
        create_if_absent: bool,
    ) -> Option<Arc<DBTraceSnapshot>> {
        if !create_if_absent {
            return self.state.read().unwrap().snapshots.get(&snap).cloned();
        }
        let (snapshot, created) = {
            let mut state = self.state.write().unwrap();
            match state.snapshots.get(&snap) {
                Some(existing) => (Arc::clone(existing), false),
                None => {
                    let snapshot = state.create(snap);
                    snapshot.set(Self::current_time_millis(), "");
                    (snapshot, true)
                }
            }
        };
        if created {
            if snapshot.get_key() == 0 {
                // Convention for first snap
                self.set_snapshot_schedule(&snapshot, Some(trace_schedule_snap(0)));
            }
            self.notify_snapshot_added(&snapshot);
        }
        Some(snapshot)
    }

    /// Get the most recent snapshot at or before `snap`. Mirrors `getMostRecentSnapshot(long)`.
    pub fn get_most_recent_snapshot(&self, snap: i64) -> Option<Arc<DBTraceSnapshot>> {
        let state = self.state.read().unwrap();
        state.snapshots.range(..=snap).next_back().map(|(_, s)| Arc::clone(s))
    }

    /// Get the most recent fork snapshot key at or before `snap`. Mirrors
    /// `getMostRecentFork(long)`, including its scratch-space convention: a non-negative query
    /// never yields a negative fork (it falls back to snap 0), and a negative query with no
    /// negative fork yields [`i64::MIN`].
    pub fn get_most_recent_fork(&self, snap: i64) -> i64 {
        let state = self.state.read().unwrap();
        let Some((&found_key, found_fork)) = state.forks.range(..=snap).next_back() else {
            return if snap < 0 { i64::MIN } else { 0 };
        };
        if found_key < 0 && snap >= 0 {
            return 0;
        }
        found_fork.snap
    }

    /// All snapshots whose schedule renders to the same string as `schedule`. Mirrors
    /// `getSnapshotsWithSchedule(TraceSchedule)`.
    pub fn get_snapshots_with_schedule(
        &self,
        schedule: &dyn TraceSchedule,
    ) -> Vec<Arc<DBTraceSnapshot>> {
        self.snapshots_with_schedule_string(&schedule.schedule_string())
    }

    /// The `snapshotsBySchedule.get(key)` lookup, on the already-rendered index key.
    fn snapshots_with_schedule_string(&self, key: &str) -> Vec<Arc<DBTraceSnapshot>> {
        let state = self.state.read().unwrap();
        state
            .snapshots
            .values()
            .filter(|s| s.get_schedule_string() == key)
            .map(Arc::clone)
            .collect()
    }

    /// The sorted, deduplicated keys of the `snapshotsBySchedule` index.
    fn schedule_index_keys(&self) -> Vec<String> {
        let state = self.state.read().unwrap();
        let mut keys: Vec<String> =
            state.snapshots.values().map(|s| s.get_schedule_string()).collect();
        keys.sort();
        keys.dedup();
        keys
    }

    /// Find or create the snapshot with the given schedule. Mirrors
    /// `findScratchSnapshot(TraceSchedule)`.
    pub fn find_scratch_snapshot(
        &self,
        schedule: Arc<dyn TraceSchedule>,
    ) -> Arc<DBTraceSnapshot> {
        let exist = self.get_snapshots_with_schedule(&*schedule);
        if let Some(first) = exist.into_iter().next() {
            return first;
        }
        /*
         * TODO: This could be more sophisticated.... Does it need to be, though? Ideally, we'd
         * only keep state around that has annotations, e.g., bookmarks and code units. That needs
         * a new query (latestStartSince) on those managers, though. It must find the latest start
         * tick since a given snap. We consider only start snaps because placed code units go
         * "from now on out".
         */
        let last = self.get_most_recent_snapshot(-1);
        let snap = last.map_or(i64::MIN, |l| l.get_key() + 1);
        let snapshot = self
            .get_snapshot(snap, true)
            .expect("get_snapshot with create_if_absent always yields a snapshot");
        self.set_snapshot_schedule(&snapshot, Some(schedule));
        snapshot
    }

    /// Mirrors `doGetValidSnapshotBySchedule(String, long)`: the first snapshot under the given
    /// index key whose version is at least `version`.
    fn do_get_valid_snapshot_by_schedule(
        &self,
        key: &str,
        version: i64,
    ) -> Option<Arc<DBTraceSnapshot>> {
        self.snapshots_with_schedule_string(key)
            .into_iter()
            .find(|s| s.get_version() >= version)
    }

    /// Mirrors `doFindNearest(TraceSchedule, long)`.
    ///
    /// One deviation: where Java recovers each candidate schedule by re-parsing the index key
    /// (`TraceSchedule.parse(key)`), this walks to the snapshot holding that key and reuses its
    /// schedule object. The key *is* `schedule.toString()` by construction, so the two agree --
    /// and the parser belongs to the unported `TraceSchedule`. Java's stated reason for parsing
    /// (deferring the record load behind the cheaper filters) does not apply to an in-memory map.
    fn do_find_nearest(
        &self,
        schedule: &dyn TraceSchedule,
        version: i64,
    ) -> Option<Arc<DBTraceSnapshot>> {
        // Base case
        if schedule.is_snap_only() {
            return self.get_snapshot(schedule.get_snap(), false); // may be None
        }

        // Inductive case
        let mut best: Option<Arc<DBTraceSnapshot>> = None;
        let dropped = schedule.drop_last_step();
        let str_dropped = dropped.schedule_string();
        let keys = self.schedule_index_keys();
        let mut i = keys.partition_point(|k| k.as_str() < str_dropped.as_str());
        while i < keys.len() {
            let key = keys[i].clone();
            i += 1;
            if !key.starts_with(&str_dropped) {
                break;
            }
            let Some(candidate) = self
                .snapshots_with_schedule_string(&key)
                .into_iter()
                .find_map(|s| s.get_schedule())
            else {
                continue;
            };
            // We're in a chunk of too-advanced (and probably unrelated) schedules
            if candidate.step_count() > schedule.step_count() {
                let candidate_trunc = candidate.truncate_to_steps(schedule.step_count());
                let candidate_step = candidate_trunc.last_step();
                let candidate_dropped = candidate_trunc.drop_last_step();
                // Hack the lexicographic indexing. Java formats the char after '{' resp. ';'.
                let extra = match candidate_step.get_type() {
                    StepType::Patch => {
                        format!("t{}-{}", candidate_step.get_thread_key(), '|')
                    }
                    _ => format!(
                        "{}{}",
                        candidate_step.to_string_radix(&time_radix_default()),
                        '<'
                    ),
                };
                let new_tail_key = if candidate_dropped.is_snap_only() {
                    format!("{}:{}", candidate_dropped.schedule_string(), extra)
                } else {
                    format!("{};{}", candidate_dropped.schedule_string(), extra)
                };
                i = keys.partition_point(|k| k.as_str() < new_tail_key.as_str());
                continue;
            }

            // We have a potential nearest. Must be related and less than, but better than best
            let cmp = candidate.compare_schedule(schedule);
            if !cmp.related() || cmp.compare_to() > 0 {
                continue;
            }
            if best
                .as_ref()
                .and_then(|b| b.get_schedule())
                .is_some_and(|s| s.compare_to(&*candidate) >= 0)
            {
                continue;
            }
            // Checking validity requires loading the record. Do this filter last.
            if let Some(valid) = self.do_get_valid_snapshot_by_schedule(&key, version) {
                best = Some(valid);
            }
        }

        if best.is_some() {
            return best;
        }

        self.do_find_nearest(&*dropped, version)
    }

    /// Find the nearest related snapshot whose schedule is a prefix of `schedule`. Mirrors
    /// `findSnapshotWithNearestPrefix(TraceSchedule)`.
    ///
    /// Because the index is lexicographic, [`Self::do_find_nearest`] has to hack a bit. Consider
    /// that 20 would come before 3 in the index. That said, all the steps leading up to the last
    /// would have to be equal for it to be a prefix, so no weird lexicographic stuff comes into
    /// play except in the final step. Even if the index were numeric, non-related schedules can
    /// appear between related ones, e.g. `0:t0-2, 0:t0-3;t1-1` when searching for `0:t0-4`.
    pub fn find_snapshot_with_nearest_prefix(
        &self,
        schedule: &dyn TraceSchedule,
    ) -> Option<Arc<DBTraceSnapshot>> {
        let version = self.trace.get_emulator_cache_version();
        let no_p_steps = schedule.drop_p_steps();
        let exists = self
            .get_snapshots_with_schedule(&*no_p_steps)
            .into_iter()
            .find(|s| s.get_version() >= version);
        if exists.is_some() {
            return exists;
        }
        self.do_find_nearest(&*no_p_steps, version)
    }

    /// All snapshots in the trace, in ascending key order. Mirrors `getAllSnapshots()`.
    pub fn get_all_snapshots(&self) -> Vec<Arc<DBTraceSnapshot>> {
        self.state.read().unwrap().snapshots.values().map(Arc::clone).collect()
    }

    /// All snapshots between two snaps. Mirrors `getSnapshots(long, boolean, long, boolean)`.
    pub fn get_snapshots(
        &self,
        from_snap: i64,
        from_inclusive: bool,
        to_snap: i64,
        to_inclusive: bool,
    ) -> Vec<Arc<DBTraceSnapshot>> {
        use std::ops::Bound;
        let from = if from_inclusive {
            Bound::Included(from_snap)
        } else {
            Bound::Excluded(from_snap)
        };
        let to = if to_inclusive { Bound::Included(to_snap) } else { Bound::Excluded(to_snap) };
        let state = self.state.read().unwrap();
        if !range_is_valid(from_snap, from_inclusive, to_snap, to_inclusive) {
            return Vec::new();
        }
        state.snapshots.range((from, to)).map(|(_, s)| Arc::clone(s)).collect()
    }

    /// The maximum snapshot key that has ever existed. Mirrors `getMaxSnap()`, i.e.
    /// `snapshotStore.getMaxKey()`: the key need not still be occupied.
    pub fn get_max_snap(&self) -> Option<i64> {
        self.state.read().unwrap().max_key
    }

    /// The number of snapshots. Mirrors `getSnapshotCount()`, i.e.
    /// `snapshotStore.getRecordCount()`.
    pub fn get_snapshot_count(&self) -> i64 {
        self.state.read().unwrap().snapshots.len() as i64
    }

    /// Remove `snapshot`, and the fork record for its snap if there is one. Mirrors
    /// `deleteSnapshot(DBTraceSnapshot)`.
    pub fn delete_snapshot(&self, snapshot: &Arc<DBTraceSnapshot>) {
        {
            let mut state = self.state.write().unwrap();
            let key = snapshot.get_key();
            let found_fork = state.forks.get(&key).copied();
            state.snapshots.remove(&key);
            if found_fork.is_some() {
                state.forks.remove(&key);
            }
        }
        self.notify_snapshot_deleted(snapshot);
    }

    /// Set the radix for displaying and parsing time. Mirrors `setTimeRadix(TimeRadix)`.
    ///
    /// # Panics
    /// Panics if the trace's object manager has no root object, mirroring the Java
    /// `IllegalStateException`.
    pub fn set_time_radix(&self, radix: &dyn TimeRadix) {
        let root = self
            .trace
            .get_object_manager()
            .get_root_object()
            .expect(
                "There must be a root object in the ObjectManager before setting the TimeRadix",
            );
        root.set_attribute(
            Lifespan::ALL,
            KEY_TIME_RADIX,
            Box::new(radix.radix_name().to_string()),
        );
    }

    /// Get the radix for displaying and parsing time, defaulting to `TimeRadix.DEFAULT` when the
    /// trace has no root object or no `_time_radix` attribute. Mirrors `getTimeRadix()`.
    pub fn get_time_radix(&self) -> Box<dyn TimeRadix> {
        let Some(root) = self.trace.get_object_manager().get_root_object() else {
            return Box::new(time_radix_default());
        };
        let Some(attribute) = root.get_attribute(0, KEY_TIME_RADIX) else {
            return Box::new(time_radix_default());
        };
        match attribute.get_value().downcast::<String>() {
            Ok(s) => Box::new(time_radix_from_str(&s)),
            Err(_) => Box::new(time_radix_default()),
        }
    }

    /// Mirrors `invalidateCache(boolean)`, which drops `snapshotStore`'s cache of DB records.
    ///
    /// A no-op here: with the store standing in as the storage itself (see the module docs), there
    /// is no record cache to drop and clearing the map would discard the snapshots outright.
    pub fn invalidate_cache(&self, all: bool) {
        let _ = all;
    }
}

/// Whether the bounds `getSnapshots` was handed describe a non-empty range, so that a reversed or
/// degenerate pair yields no snapshots instead of panicking the way `BTreeMap::range` does.
fn range_is_valid(from: i64, from_inclusive: bool, to: i64, to_inclusive: bool) -> bool {
    match from.cmp(&to) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Equal => from_inclusive && to_inclusive,
        std::cmp::Ordering::Greater => false,
    }
}

impl ErrorHandler for DBTraceTimeManager {
    /// Mirrors `dbError(IOException)`, which forwards to the trace.
    fn db_error(&self, e: std::io::Error) {
        self.trace.db_error(e);
    }
}

impl DBTraceManager for DBTraceTimeManager {
    fn invalidate_cache(&mut self, all: bool) {
        DBTraceTimeManager::invalidate_cache(self, all);
    }
}

impl TraceTimeManager for DBTraceTimeManager {
    fn create_snapshot(&self, description: &str) -> Box<dyn TraceSnapshot> {
        Box::new(DBTraceTimeManager::create_snapshot(self, description))
    }

    fn get_snapshot(&self, snap: i64, create_if_absent: bool) -> Option<Box<dyn TraceSnapshot>> {
        DBTraceTimeManager::get_snapshot(self, snap, create_if_absent)
            .map(|s| Box::new(s) as Box<dyn TraceSnapshot>)
    }

    fn get_most_recent_snapshot(&self, snap: i64) -> Option<Box<dyn TraceSnapshot>> {
        DBTraceTimeManager::get_most_recent_snapshot(self, snap)
            .map(|s| Box::new(s) as Box<dyn TraceSnapshot>)
    }

    fn get_most_recent_fork(&self, snap: i64) -> i64 {
        DBTraceTimeManager::get_most_recent_fork(self, snap)
    }

    fn get_snapshots_with_schedule(
        &self,
        schedule: &dyn TraceSchedule,
    ) -> Vec<Box<dyn TraceSnapshot>> {
        DBTraceTimeManager::get_snapshots_with_schedule(self, schedule)
            .into_iter()
            .map(|s| Box::new(s) as Box<dyn TraceSnapshot>)
            .collect()
    }

    fn find_scratch_snapshot(&self, schedule: &dyn TraceSchedule) -> Box<dyn TraceSnapshot> {
        // The trait hands out only a borrow, but the schedule is stored on the snapshot, so it
        // has to be recovered as an owned value. Every schedule reachable here renders to the
        // same index key as its snap-only or stepped original; when it is snap-only that is an
        // exact reconstruction.
        let owned: Arc<dyn TraceSchedule> = match self
            .get_snapshots_with_schedule(schedule)
            .into_iter()
            .find_map(|s| s.get_schedule())
        {
            Some(existing) => existing,
            None if schedule.is_snap_only() => trace_schedule_snap(schedule.get_snap()),
            None => panic!(
                "find_scratch_snapshot through &dyn TraceSchedule requires either an existing \
                 snapshot with this schedule or a snap-only schedule; call \
                 DBTraceTimeManager::find_scratch_snapshot with an Arc instead"
            ),
        };
        Box::new(DBTraceTimeManager::find_scratch_snapshot(self, owned))
    }

    fn find_snapshot_with_nearest_prefix(
        &self,
        schedule: &dyn TraceSchedule,
    ) -> Option<Box<dyn TraceSnapshot>> {
        DBTraceTimeManager::find_snapshot_with_nearest_prefix(self, schedule)
            .map(|s| Box::new(s) as Box<dyn TraceSnapshot>)
    }

    fn get_all_snapshots(&self) -> Vec<Box<dyn TraceSnapshot>> {
        DBTraceTimeManager::get_all_snapshots(self)
            .into_iter()
            .map(|s| Box::new(s) as Box<dyn TraceSnapshot>)
            .collect()
    }

    fn get_snapshots(
        &self,
        from_snap: i64,
        from_inclusive: bool,
        to_snap: i64,
        to_inclusive: bool,
    ) -> Vec<Box<dyn TraceSnapshot>> {
        DBTraceTimeManager::get_snapshots(self, from_snap, from_inclusive, to_snap, to_inclusive)
            .into_iter()
            .map(|s| Box::new(s) as Box<dyn TraceSnapshot>)
            .collect()
    }

    fn get_max_snap(&self) -> Option<i64> {
        DBTraceTimeManager::get_max_snap(self)
    }

    fn get_snapshot_count(&self) -> i64 {
        DBTraceTimeManager::get_snapshot_count(self)
    }

    fn set_time_radix(&mut self, radix: Box<dyn TimeRadix>) {
        DBTraceTimeManager::set_time_radix(self, &*radix);
    }

    fn get_time_radix(&self) -> Box<dyn TimeRadix> {
        DBTraceTimeManager::get_time_radix(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::model::target::trace_object_value::TraceObjectValue;
    use crate::trace::model::time::schedule::compare_result::CompareResult;
    use crate::trace::seam_stubs::{DBTraceObject, DBTraceObjectManager, TimeRadixKind};
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ---- a tick-only schedule, enough to drive doFindNearest ----

    /// A schedule of the form `snap:t0-a;t0-b`, i.e. a run of tick steps all on thread 0. That
    /// covers everything `doFindNearest` inspects without the unported `Sequence`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TickSchedule {
        snap: i64,
        steps: Vec<i64>,
    }

    impl TickSchedule {
        fn new(snap: i64, steps: &[i64]) -> Arc<dyn TraceSchedule> {
            Arc::new(TickSchedule { snap, steps: steps.to_vec() })
        }

        /// Models `Sequence.compareSeq`: equal prefixes are related, and a shorter final tick
        /// count is a prefix of a longer one (2 ticks is a prefix of 4 ticks).
        fn compare_seq(&self, that: &TickSchedule) -> CompareResult {
            let n = self.steps.len().min(that.steps.len());
            for i in 0..n {
                if self.steps[i] == that.steps[i] {
                    continue;
                }
                let less = self.steps[i] < that.steps[i];
                if less && i + 1 == self.steps.len() {
                    return CompareResult::RelLt;
                }
                if !less && i + 1 == that.steps.len() {
                    return CompareResult::RelGt;
                }
                return CompareResult::from_unrelated(if less { -1 } else { 1 });
            }
            match self.steps.len().cmp(&that.steps.len()) {
                std::cmp::Ordering::Less => CompareResult::RelLt,
                std::cmp::Ordering::Equal => CompareResult::Equals,
                std::cmp::Ordering::Greater => CompareResult::RelGt,
            }
        }
    }

    struct TickStep {
        count: i64,
    }

    impl crate::trace::model::time::schedule::step::Step for TickStep {
        fn to_string_radix(&self, _radix: &dyn TimeRadix) -> String {
            format!("t0-{}", self.count)
        }
        fn get_type(&self) -> StepType {
            StepType::Tick
        }
        fn is_nop(&self) -> bool {
            self.count == 0
        }
        fn get_thread_key(&self) -> i64 {
            0
        }
        fn get_tick_count(&self) -> i64 {
            self.count
        }
        fn get_skip_count(&self) -> i64 {
            0
        }
        fn get_patch_count(&self) -> i64 {
            0
        }
        fn coalesce_patches(
            &self,
            _language: &dyn crate::program::model::lang::Language,
            _steps: &mut Vec<Box<dyn crate::trace::model::time::schedule::step::Step>>,
        ) -> i64 {
            0
        }
        fn is_compatible(&self, _step: &dyn crate::trace::model::time::schedule::step::Step) -> bool {
            true
        }
        fn add_to(&mut self, _step: &dyn crate::trace::model::time::schedule::step::Step) {
            unimplemented!()
        }
        fn subtract(
            &self,
            _step: &dyn crate::trace::model::time::schedule::step::Step,
        ) -> Box<dyn crate::trace::model::time::schedule::step::Step> {
            unimplemented!()
        }
        fn clone_box(&self) -> Box<dyn crate::trace::model::time::schedule::step::Step> {
            Box::new(TickStep { count: self.count })
        }
        fn rewind(&mut self, _count: i64) -> i64 {
            unimplemented!()
        }
        fn compare_step(
            &self,
            _that: &dyn crate::trace::model::time::schedule::step::Step,
        ) -> CompareResult {
            unimplemented!()
        }
        fn execute(
            &self,
            _emu_thread: &dyn crate::pcode::emu::pcode_thread::ErasedPcodeThread,
            _stepper: &dyn crate::trace::model::time::schedule::stepper::Stepper,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            unimplemented!()
        }
    }

    impl TraceSchedule for TickSchedule {
        fn schedule_string(&self) -> String {
            if self.steps.is_empty() {
                return self.snap.to_string();
            }
            let steps: Vec<String> = self.steps.iter().map(|c| format!("t0-{c}")).collect();
            format!("{}:{}", self.snap, steps.join(";"))
        }

        fn is_snap_only(&self) -> bool {
            self.steps.is_empty()
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }

        fn step_count(&self) -> i32 {
            self.steps.len() as i32
        }

        fn drop_p_steps(&self) -> Arc<dyn TraceSchedule> {
            Arc::new(self.clone())
        }

        fn drop_last_step(&self) -> Arc<dyn TraceSchedule> {
            let mut steps = self.steps.clone();
            steps.pop();
            Arc::new(TickSchedule { snap: self.snap, steps })
        }

        fn truncate_to_steps(&self, count: i32) -> Arc<dyn TraceSchedule> {
            Arc::new(TickSchedule {
                snap: self.snap,
                steps: self.steps.iter().copied().take(count as usize).collect(),
            })
        }

        fn last_step(&self) -> Box<dyn crate::trace::model::time::schedule::step::Step> {
            Box::new(TickStep { count: *self.steps.last().expect("no steps") })
        }

        fn compare_schedule(&self, that: &dyn TraceSchedule) -> CompareResult {
            let by_snap = CompareResult::from_unrelated(match self.snap.cmp(&that.get_snap()) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            });
            if by_snap != CompareResult::Equals {
                return by_snap;
            }
            // Only ever compared against other TickSchedules (or the snap-only stand-in, which
            // this reconstructs as an empty step list).
            let other = TickSchedule {
                snap: that.get_snap(),
                steps: parse_tick_steps(&that.schedule_string()),
            };
            self.compare_seq(&other)
        }
    }

    fn parse_tick_steps(s: &str) -> Vec<i64> {
        match s.split_once(':') {
            None => Vec::new(),
            Some((_, steps)) => steps
                .split(';')
                .map(|st| st.trim_start_matches("t0-").parse().expect("tick step"))
                .collect(),
        }
    }

    // ---- a trace whose notifications and root object are observable ----

    #[derive(Default)]
    struct TraceLog {
        added: Vec<i64>,
        changed: Vec<i64>,
        deleted: Vec<i64>,
        set_changed: usize,
    }

    #[derive(Default)]
    struct MockRoot {
        attributes: Mutex<HashMap<String, String>>,
    }

    struct SharedRoot(Arc<MockRoot>);

    struct StringValue(String);

    impl TraceObjectValue for StringValue {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!()
        }
        fn get_parent(&self) -> Option<Box<dyn crate::trace::seam_stubs::TraceObject>> {
            None
        }
        fn get_entry_key(&self) -> String {
            KEY_TIME_RADIX.to_string()
        }
        fn get_canonical_path(&self) -> crate::trace::model::target::path::key_path::KeyPath {
            unimplemented!()
        }
        fn get_value(&self) -> Box<dyn std::any::Any + Send + Sync> {
            Box::new(self.0.clone())
        }
        fn get_child(&self) -> Box<dyn crate::trace::seam_stubs::TraceObject> {
            unimplemented!()
        }
        fn is_object(&self) -> bool {
            false
        }
        fn is_canonical(&self) -> bool {
            false
        }
        fn get_target_schema(&self) -> Box<dyn crate::trace::seam_stubs::TraceObjectSchema> {
            unimplemented!()
        }
        fn set_lifespan(&mut self, _lifespan: Lifespan) {
            unimplemented!()
        }
        fn set_lifespan_with_resolution(
            &mut self,
            _span: Lifespan,
            _resolution: crate::trace::seam_stubs::ConflictResolution,
        ) -> Result<(), crate::trace::model::target::duplicate_key_exception::DuplicateKeyException>
        {
            unimplemented!()
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::ALL
        }
        fn set_min_snap(&mut self, _min_snap: i64) {
            unimplemented!()
        }
        fn get_min_snap(&self) -> i64 {
            i64::MIN
        }
        fn set_max_snap(&mut self, _max_snap: i64) {
            unimplemented!()
        }
        fn get_max_snap(&self) -> i64 {
            i64::MAX
        }
        fn truncate_or_delete(
            &mut self,
            _span: Lifespan,
        ) -> crate::trace::model::target::trace_object_value::TruncateOrDelete {
            unimplemented!()
        }
        fn delete(&mut self) {
            unimplemented!()
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl DBTraceObject for SharedRoot {
        fn set_attribute(
            &self,
            _lifespan: Lifespan,
            name: &str,
            value: Box<dyn std::any::Any + Send + Sync>,
        ) -> Box<dyn TraceObjectValue> {
            let s = *value.downcast::<String>().expect("radix attribute is a String");
            self.0.attributes.lock().unwrap().insert(name.to_string(), s.clone());
            Box::new(StringValue(s))
        }

        fn get_attribute(&self, _snap: i64, name: &str) -> Option<Box<dyn TraceObjectValue>> {
            self.0
                .attributes
                .lock()
                .unwrap()
                .get(name)
                .map(|s| Box::new(StringValue(s.clone())) as Box<dyn TraceObjectValue>)
        }
    }

    struct MockObjectManager {
        root: Option<Arc<MockRoot>>,
    }

    impl DBTraceObjectManager for MockObjectManager {
        fn get_root_object(&self) -> Option<Box<dyn DBTraceObject>> {
            self.root
                .as_ref()
                .map(|r| Box::new(SharedRoot(Arc::clone(r))) as Box<dyn DBTraceObject>)
        }
    }

    #[derive(Default)]
    struct MockTrace {
        log: Mutex<TraceLog>,
        emulator_cache_version: i64,
        root: Option<Arc<MockRoot>>,
    }

    impl DBTrace for MockTrace {
        fn get_object_manager(&self) -> Box<dyn DBTraceObjectManager> {
            Box::new(MockObjectManager { root: self.root.as_ref().map(Arc::clone) })
        }

        fn set_changed(&self, _event: &dyn TraceChangeRecord) {
            self.log.lock().unwrap().set_changed += 1;
        }

        fn get_emulator_cache_version(&self) -> i64 {
            self.emulator_cache_version
        }

        fn update_viewports_snapshot_added(&self, snapshot: &dyn TraceSnapshot) {
            let _ = snapshot;
            // The trait only exposes isFork; the key is recorded by the manager-side helpers
            // below, which have the concrete snapshot.
            self.log.lock().unwrap().added.push(i64::from(snapshot.is_fork()));
        }

        fn update_viewports_snapshot_changed(&self, snapshot: &dyn TraceSnapshot) {
            self.log.lock().unwrap().changed.push(i64::from(snapshot.is_fork()));
        }

        fn update_viewports_snapshot_deleted(&self, snapshot: &dyn TraceSnapshot) {
            self.log.lock().unwrap().deleted.push(i64::from(snapshot.is_fork()));
        }
    }

    fn manager_with(trace: MockTrace) -> (DBTraceTimeManager, Arc<MockTrace>) {
        let trace = Arc::new(trace);
        (DBTraceTimeManager::new(Arc::clone(&trace) as Arc<dyn DBTrace>, None), trace)
    }

    fn manager() -> (DBTraceTimeManager, Arc<MockTrace>) {
        manager_with(MockTrace::default())
    }

    #[test]
    fn create_snapshot_numbers_from_zero_and_stamps_the_first_schedule() {
        let (mgr, trace) = manager();

        let s0 = mgr.create_snapshot("initial");
        let s1 = mgr.create_snapshot("advance");

        assert_eq!(s0.get_key(), 0);
        assert_eq!(s1.get_key(), 1);
        assert_eq!(s0.get_description(), "initial");
        // Convention for first snap: TraceSchedule.snap(0), which renders as "0".
        assert_eq!(s0.get_schedule_string(), "0");
        assert_eq!(s1.get_schedule_string(), "");
        // computeIsFork: snap 0's schedule starts at 0, which is not key - 1 == -1.
        assert!(s0.is_fork());
        assert!(!s1.is_fork());

        assert_eq!(mgr.get_snapshot_count(), 2);
        assert_eq!(mgr.get_max_snap(), Some(1));
        assert_eq!(trace.log.lock().unwrap().added.len(), 2);
    }

    #[test]
    fn get_max_snap_survives_deletion() {
        let (mgr, trace) = manager();
        mgr.create_snapshot("a");
        let s1 = mgr.create_snapshot("b");

        mgr.delete_snapshot(&s1);

        // Java: snapshotStore.getMaxKey(), which the table never lowers.
        assert_eq!(mgr.get_max_snap(), Some(1));
        assert_eq!(mgr.get_snapshot_count(), 1);
        assert!(mgr.get_snapshot(1, false).is_none());
        assert_eq!(trace.log.lock().unwrap().deleted.len(), 1);
        // The next create still takes maxKey + 1, not the freed slot.
        assert_eq!(mgr.create_snapshot("c").get_key(), 2);
    }

    #[test]
    fn get_most_recent_fork_honors_the_scratch_convention() {
        let (mgr, _trace) = manager();

        // No forks at all.
        assert_eq!(mgr.get_most_recent_fork(5), 0);
        assert_eq!(mgr.get_most_recent_fork(-5), i64::MIN);

        // A fork in scratch space only: a non-negative query must not see it.
        let scratch = mgr.get_snapshot(-10, true).unwrap();
        mgr.set_snapshot_schedule(&scratch, Some(TickSchedule::new(0, &[4])));
        assert!(scratch.is_fork());
        assert_eq!(mgr.get_most_recent_fork(5), 0);
        assert_eq!(mgr.get_most_recent_fork(-5), -10);
        assert_eq!(mgr.get_most_recent_fork(-20), i64::MIN);

        // A real fork at snap 3.
        let s3 = mgr.get_snapshot(3, true).unwrap();
        mgr.set_snapshot_schedule(&s3, Some(TickSchedule::new(0, &[7])));
        assert_eq!(mgr.get_most_recent_fork(5), 3);
        assert_eq!(mgr.get_most_recent_fork(2), 0);

        // Clearing the schedule drops the fork record again.
        mgr.set_snapshot_schedule(&s3, None);
        assert!(!s3.is_fork());
        assert_eq!(mgr.get_most_recent_fork(5), 0);
    }

    #[test]
    fn find_scratch_snapshot_allocates_downward_from_min_and_reuses() {
        let (mgr, _trace) = manager();
        mgr.create_snapshot("recorded"); // snap 0

        let schedule = TickSchedule::new(0, &[3]);
        let first = mgr.find_scratch_snapshot(Arc::clone(&schedule));
        assert_eq!(first.get_key(), i64::MIN);
        assert_eq!(first.get_schedule_string(), "0:t0-3");
        // computeIsFork is false at Long.MIN_VALUE, even with a schedule.
        assert!(!first.is_fork());

        // Same schedule -> same snapshot, no new allocation.
        let again = mgr.find_scratch_snapshot(Arc::clone(&schedule));
        assert_eq!(again.get_key(), i64::MIN);

        // A different schedule takes the next scratch snap up.
        let other = mgr.find_scratch_snapshot(TickSchedule::new(0, &[5]));
        assert_eq!(other.get_key(), i64::MIN + 1);
        assert_eq!(mgr.get_snapshot_count(), 3);
    }

    #[test]
    fn get_snapshots_respects_bound_inclusivity() {
        let (mgr, _trace) = manager();
        for _ in 0..5 {
            mgr.create_snapshot("s");
        }

        let keys = |v: Vec<Arc<DBTraceSnapshot>>| -> Vec<i64> {
            v.into_iter().map(|s| s.get_key()).collect()
        };

        assert_eq!(keys(mgr.get_snapshots(1, true, 3, true)), vec![1, 2, 3]);
        assert_eq!(keys(mgr.get_snapshots(1, false, 3, true)), vec![2, 3]);
        assert_eq!(keys(mgr.get_snapshots(1, true, 3, false)), vec![1, 2]);
        assert_eq!(keys(mgr.get_snapshots(1, false, 3, false)), vec![2]);
        assert_eq!(keys(mgr.get_all_snapshots()), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn find_snapshot_with_nearest_prefix_picks_the_longest_related_prefix() {
        let (mgr, _trace) = manager();
        mgr.create_snapshot("recorded"); // snap 0, schedule "0"

        // A scratch snapshot at 0:t0-2, and one too-advanced sibling at 0:t0-2;t0-3.
        let near = mgr.get_snapshot(10, true).unwrap();
        mgr.set_snapshot_schedule(&near, Some(TickSchedule::new(0, &[2])));
        let advanced = mgr.get_snapshot(11, true).unwrap();
        mgr.set_snapshot_schedule(&advanced, Some(TickSchedule::new(0, &[2, 3])));

        // 0:t0-2 is a related prefix of 0:t0-4 and beats the bare "0"; 0:t0-2;t0-3 is skipped as
        // too advanced.
        let found = mgr.find_snapshot_with_nearest_prefix(&*TickSchedule::new(0, &[4]));
        assert_eq!(found.map(|s| s.get_key()), Some(10));

        // An exact match short-circuits ahead of the prefix search.
        let exact = mgr.find_snapshot_with_nearest_prefix(&*TickSchedule::new(0, &[2]));
        assert_eq!(exact.map(|s| s.get_key()), Some(10));
    }

    #[test]
    fn find_snapshot_with_nearest_prefix_skips_stale_versions_but_not_the_base_case() {
        let (mgr, _trace) = manager_with(MockTrace { emulator_cache_version: 5, ..Default::default() });
        mgr.create_snapshot("recorded"); // snap 0, version 0

        let near = mgr.get_snapshot(10, true).unwrap();
        mgr.set_snapshot_schedule(&near, Some(TickSchedule::new(0, &[2])));
        near.set_version(1); // stale against the emulator cache version

        // Every candidate in the inductive case is filtered out by version, so the recursion
        // reaches the snap-only base case, which does not version-check at all.
        let found = mgr.find_snapshot_with_nearest_prefix(&*TickSchedule::new(0, &[4]));
        assert_eq!(found.map(|s| s.get_key()), Some(0));

        // Once the candidate is fresh enough, it wins again.
        near.set_version(5);
        let found = mgr.find_snapshot_with_nearest_prefix(&*TickSchedule::new(0, &[4]));
        assert_eq!(found.map(|s| s.get_key()), Some(10));
    }

    #[test]
    fn time_radix_round_trips_through_the_root_object() {
        let (mgr, _trace) = manager_with(MockTrace {
            root: Some(Arc::new(MockRoot::default())),
            ..Default::default()
        });

        // No attribute yet -> TimeRadix.DEFAULT, which is DEC.
        assert_eq!(mgr.get_time_radix().radix(), 10);
        assert_eq!(mgr.get_time_radix().radix_name(), "dec");

        mgr.set_time_radix(&TimeRadixKind::HexUpper);
        assert_eq!(mgr.get_time_radix().radix(), 16);
        assert_eq!(mgr.get_time_radix().radix_name(), "HEX");

        mgr.set_time_radix(&TimeRadixKind::HexLower);
        assert_eq!(mgr.get_time_radix().radix_name(), "hex");
    }

    #[test]
    fn time_radix_defaults_when_the_trace_has_no_root_object() {
        let (mgr, _trace) = manager();
        assert_eq!(mgr.get_time_radix().radix_name(), "dec");
    }

    #[test]
    #[should_panic(expected = "There must be a root object")]
    fn set_time_radix_requires_a_root_object() {
        let (mgr, _trace) = manager();
        mgr.set_time_radix(&TimeRadixKind::HexUpper);
    }

    #[test]
    fn usable_through_the_trace_time_manager_trait_object() {
        let (mgr, _trace) = manager();
        let mgr: Box<dyn TraceTimeManager> = Box::new(mgr);

        let s0 = mgr.create_snapshot("initial");
        assert!(s0.is_fork()); // snap 0 carries TraceSchedule.snap(0)
        assert_eq!(mgr.get_max_snap(), Some(0));
        assert_eq!(mgr.get_snapshot_count(), 1);
        assert!(mgr.get_snapshot(7, false).is_none());
        assert!(mgr.get_snapshot(7, true).is_some());
        assert_eq!(mgr.get_max_snap(), Some(7));
        assert_eq!(mgr.get_all_snapshots().len(), 2);
    }
}
