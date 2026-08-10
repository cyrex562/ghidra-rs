//! Minimal placeholder traits for core types that a ported trace-model interface references
//! before the real Rust port of that type exists yet. Each stub exposes only the members needed
//! by the interface(s) that currently reference it, and is expected to be replaced (or grown
//! into a supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for
//! provenance.

use std::any::TypeId;
use std::sync::Arc;

use crate::debug::api::tracermi::SchemaName;
use crate::trace::model::thread::TraceThread;
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::program::model::address::{
    Address, AddressFactory, AddressRange, AddressSet, AddressSetView, AddressSpace,
};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::{Language, Register};
use crate::program::model::mem::MemBuffer;
use crate::program::model::symbol::Namespace;
use crate::program::seam_stubs::RegisterValue as ProgramRegisterValue;
use crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace;
use crate::trace::database::target::db_trace_object_value::DBTraceObjectValue;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
use crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag;
use crate::trace::model::memory::trace_memory_region::TraceMemoryRegion;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::target::path::path_pattern::PathPattern;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::time::schedule::compare_result::CompareResult;
use crate::trace::model::time::schedule::step::Step;
use crate::trace::model::time::trace_snapshot::TraceSnapshot;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::util::trace_change_manager::TraceChangeManager;
use crate::trace::util::trace_change_record::TraceChangeRecord;
use crate::util::exception::DuplicateNameException;
use crate::util::lock_hold::Lock;
use crate::util::task::TaskMonitor;

/// Placeholder for `ghidra.trace.util.TraceEvent`, referenced by
/// [`TypedEventDispatcher`](crate::trace::util::typed_event_dispatcher::TypedEventDispatcher)
/// before the real (enum-like registry of `TraceEvent<T, U>` constants, e.g. in `TraceEvents`)
/// port is available. `TypedEventDispatcher` only ever needs an event's id to key its dispatch
/// tables, so that is the only member stubbed here.
pub trait TraceEvent: Send + Sync {
    /// Mirrors the inherited `EventType.getId()`.
    fn get_id(&self) -> i32;
}

/// Placeholder for `ghidra.trace.database.map.AbstractDBTracePropertyMap`, referenced by
/// [`TraceAddressPropertyManager`](crate::trace::model::property::trace_address_property_manager::TraceAddressPropertyManager)
/// and
/// [`DBTraceAddressPropertyManager`](crate::trace::database::property::db_trace_address_property_manager::DBTraceAddressPropertyManager)
/// before the real (generic, DB-record-backed) type is ported. Java's `Class<T> valueClass` /
/// `AbstractDBTracePropertyMap<T, ?>` erasure is represented the same way
/// [`TraceObjectValue::get_value`](crate::trace::model::target::trace_object_value::TraceObjectValue::get_value)'s
/// docs establish for an unconstrained type parameter on an object-safe trait: the map's value
/// type is carried at runtime as a [`TypeId`] rather than at the Rust type level, so a single
/// manager can hold differently-typed property maps simultaneously (mirroring
/// `propertyMapsByName: Map<String, AbstractDBTracePropertyMap<?, ?>>`). Only the one accessor
/// [`TraceAddressPropertyManager`](crate::trace::model::property::trace_address_property_manager::TraceAddressPropertyManager)'s
/// type-checking members need is stubbed here.
pub trait AbstractDBTracePropertyMap: Send + Sync {
    /// Mirrors `AbstractDBTracePropertyMap.getValueClass()`.
    fn get_value_class(&self) -> TypeId;
}

/// Placeholder for `ghidra.trace.model.bookmark.TraceBookmarkManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceBookmarkManager {}

/// Placeholder for `ghidra.trace.model.data.TraceBasedDataTypeManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported. Mirrors the
/// Java interface's `extends ProgramBasedDataTypeManager` (itself a `DataTypeManager`) so that
/// the placeholder stays substitutable for [`DataTypeManager`].
pub trait TraceBasedDataTypeManager: DataTypeManager {}

/// Placeholder for `ghidra.trace.model.context.TraceRegisterContextManager`, referenced by
/// [`Trace`](crate::trace::model::trace::Trace) before the real interface is ported.
pub trait TraceRegisterContextManager {}

/// Placeholder for `ghidra.trace.model.time.schedule.TraceSchedule`, referenced by
/// [`TraceTimeManager`](crate::trace::model::time::trace_time_manager::TraceTimeManager) before
/// the real port is available. `TraceTimeManager` only ever passes these around opaquely (as a
/// lookup/creation key), never inspecting them, so this is a marker trait.
///
/// Grown to add the members
/// [`DBTraceTimeManager`](crate::trace::database::time::db_trace_time_manager::DBTraceTimeManager)'s
/// `doFindNearest` prefix search actually inspects. Every one defaults to panicking, like
/// [`DBTrace`]'s grown members, so the existing marker (`impl TraceSchedule for MockSchedule {}`)
/// implementors keep compiling unchanged; the real port replaces every default.
pub trait TraceSchedule: Send + Sync {
    /// Mirrors `TraceSchedule.toString()`, i.e. `toString(TimeRadix.DEC)` -- the exact form
    /// `DBTraceSnapshot` stores in its indexed `Schedule` column, and therefore the key
    /// `DBTraceTimeManager`'s `snapshotsBySchedule` index is ordered by.
    fn schedule_string(&self) -> String {
        unimplemented!("TraceSchedule::schedule_string placeholder not overridden")
    }

    /// Mirrors `TraceSchedule.isSnapOnly()`.
    fn is_snap_only(&self) -> bool {
        unimplemented!("TraceSchedule::is_snap_only placeholder not overridden")
    }

    /// Mirrors `TraceSchedule.getSnap()`.
    fn get_snap(&self) -> i64 {
        unimplemented!("TraceSchedule::get_snap placeholder not overridden")
    }

    /// Mirrors `TraceSchedule.stepCount()`.
    fn step_count(&self) -> i32 {
        unimplemented!("TraceSchedule::step_count placeholder not overridden")
    }

    /// Mirrors `TraceSchedule.dropPSteps()`.
    fn drop_p_steps(&self) -> Arc<dyn TraceSchedule> {
        unimplemented!("TraceSchedule::drop_p_steps placeholder not overridden")
    }

    /// Mirrors `TraceSchedule.dropLastStep()`.
    fn drop_last_step(&self) -> Arc<dyn TraceSchedule> {
        unimplemented!("TraceSchedule::drop_last_step placeholder not overridden")
    }

    /// Mirrors `TraceSchedule.truncateToSteps(int)`.
    fn truncate_to_steps(&self, count: i32) -> Arc<dyn TraceSchedule> {
        let _ = count;
        unimplemented!("TraceSchedule::truncate_to_steps placeholder not overridden")
    }

    /// Mirrors `TraceSchedule.lastStep().step()`. The Java method returns a `StepAndKind` record
    /// pairing the step with which of the two sequences it came from; every caller ported so far
    /// immediately takes `.step()`, so only that half is stubbed.
    fn last_step(&self) -> Box<dyn Step> {
        unimplemented!("TraceSchedule::last_step placeholder not overridden")
    }

    /// Mirrors `TraceSchedule.compareSchedule(TraceSchedule)`.
    fn compare_schedule(&self, that: &dyn TraceSchedule) -> CompareResult {
        let _ = that;
        unimplemented!("TraceSchedule::compare_schedule placeholder not overridden")
    }

    /// Mirrors `TraceSchedule.compareTo(TraceSchedule)`, which Java derives from
    /// [`Self::compare_schedule`].
    fn compare_to(&self, that: &dyn TraceSchedule) -> i32 {
        self.compare_schedule(that).compare_to()
    }
}

/// Placeholder for the static factory `TraceSchedule.snap(long)`, which builds the snap-only
/// schedule for a given snapshot key (`new TraceSchedule(snap, Sequence.of(), Sequence.of())`).
///
/// Unlike [`patch_step_parse`] and friends this one is *implemented* rather than left panicking:
/// `DBTraceTimeManager.createSnapshot` stamps `TraceSchedule.snap(0)` onto the trace's first
/// snapshot, so a panicking stub would make the manager's most basic operation unusable. A
/// snap-only schedule has empty step sequences, which pins down every member
/// [`TraceSchedule`] declares without needing the unported `Sequence`/`Step` machinery: its
/// `toString` is just the snap rendered in the radix (`TimeRadix.DEC` here), its step count is
/// zero, and `compareSchedule` reduces to comparing snaps and then recognizing the empty
/// sequence as a prefix of any other.
pub fn trace_schedule_snap(snap: i64) -> Arc<dyn TraceSchedule> {
    Arc::new(SnapOnlySchedule { snap })
}

/// The concrete schedule [`trace_schedule_snap`] returns. Private: callers only ever see it as
/// `Arc<dyn TraceSchedule>`, and it disappears entirely once the real `TraceSchedule` is ported.
struct SnapOnlySchedule {
    snap: i64,
}

impl TraceSchedule for SnapOnlySchedule {
    fn schedule_string(&self) -> String {
        // `TraceSchedule.toString(radix)` with both sequences nop is just `radix.format(snap)`.
        self.snap.to_string()
    }

    fn is_snap_only(&self) -> bool {
        true
    }

    fn get_snap(&self) -> i64 {
        self.snap
    }

    fn step_count(&self) -> i32 {
        0
    }

    fn drop_p_steps(&self) -> Arc<dyn TraceSchedule> {
        Arc::new(SnapOnlySchedule { snap: self.snap })
    }

    fn compare_schedule(&self, that: &dyn TraceSchedule) -> CompareResult {
        // Schedules starting at different snaps are never related.
        let by_snap = CompareResult::from_unrelated(match self.snap.cmp(&that.get_snap()) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        });
        if by_snap != CompareResult::Equals {
            return by_snap;
        }
        // The empty sequence is a (related) prefix of every sequence.
        if that.step_count() > 0 {
            CompareResult::RelLt
        } else {
            CompareResult::Equals
        }
    }
}

/// Placeholder for the nested enum `ghidra.trace.model.time.schedule.TraceSchedule.TimeRadix`,
/// referenced by
/// [`TraceTimeManager`](crate::trace::model::time::trace_time_manager::TraceTimeManager) before
/// the real port is available. Mirrors the one member needed to make a round-trip
/// `set_time_radix`/`get_time_radix` observable: the radix's numeric value (Java's
/// `TimeRadix.getRadix()`).
///
/// Grown with [`Self::radix_name`], the enum's other public field, which
/// [`DBTraceTimeManager::set_time_radix`](crate::trace::database::time::db_trace_time_manager::DBTraceTimeManager::set_time_radix)
/// writes into the root object's `_time_radix` attribute.
pub trait TimeRadix: Send + Sync {
    /// Mirrors `TimeRadix.getRadix()`.
    fn radix(&self) -> i32;

    /// Mirrors the enum's `public final String name` field -- `"dec"`, `"HEX"`, or `"hex"` --
    /// the token `TimeRadix.fromStr` round-trips. Defaults to deriving the name from
    /// [`Self::radix`], which cannot tell `HEX_UPPER` from `HEX_LOWER`; upper-case implementors
    /// override it.
    fn radix_name(&self) -> &'static str {
        if self.radix() == 10 {
            "dec"
        } else {
            "hex"
        }
    }
}

/// The three constants of the Java enum `TraceSchedule.TimeRadix`, as a concrete stand-in usable
/// wherever a [`TimeRadix`] value (rather than an arbitrary implementor) is needed.
///
/// The enum's own name is already taken by the [`TimeRadix`] trait -- the shape earlier ports
/// picked, and the one `Step::to_string_radix` and friends take as `&dyn TimeRadix` -- so the
/// constants live under this separate name until the real port collapses the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRadixKind {
    /// Mirrors `TimeRadix.DEC` (`"dec"`, 10).
    Dec,
    /// Mirrors `TimeRadix.HEX_UPPER` (`"HEX"`, 16).
    HexUpper,
    /// Mirrors `TimeRadix.HEX_LOWER` (`"hex"`, 16).
    HexLower,
}

impl TimeRadix for TimeRadixKind {
    fn radix(&self) -> i32 {
        match self {
            TimeRadixKind::Dec => 10,
            TimeRadixKind::HexUpper | TimeRadixKind::HexLower => 16,
        }
    }

    fn radix_name(&self) -> &'static str {
        match self {
            TimeRadixKind::Dec => "dec",
            TimeRadixKind::HexUpper => "HEX",
            TimeRadixKind::HexLower => "hex",
        }
    }
}

/// Mirrors `TimeRadix.DEFAULT`, which is `DEC`.
pub fn time_radix_default() -> TimeRadixKind {
    TimeRadixKind::Dec
}

/// Mirrors `TimeRadix.fromStr(String)`, which falls back to [`time_radix_default`] on any
/// unrecognized token.
pub fn time_radix_from_str(s: &str) -> TimeRadixKind {
    match s {
        "dec" => TimeRadixKind::Dec,
        "HEX" => TimeRadixKind::HexUpper,
        "hex" => TimeRadixKind::HexLower,
        _ => time_radix_default(),
    }
}

/// Placeholder for `ghidra.trace.database.time.DBTraceSnapshot`, referenced by
/// [`DBTraceTimeManager`](crate::trace::database::time::db_trace_time_manager::DBTraceTimeManager)
/// before the real port is available.
///
/// A *struct* rather than the usual placeholder trait: the manager does not merely pass snapshots
/// around, it creates them (`snapshotStore.create()`), so there has to be something concrete to
/// create. What it needs is exactly the record `DBTraceSnapshot` persists -- key, real time,
/// description, schedule, version -- plus the derived `isFork` flag, so those fields are the
/// placeholder.
///
/// Two deliberate departures from the Java class, both because the parts left out belong to
/// types that are not ported:
///
/// - There is no back-reference to the owning manager. In Java every accessor takes
///   `manager.lock`, and `setSchedule` reaches into `manager.forkStore`; here the manager owns
///   both its lock and its fork table, so the fork bookkeeping lives in
///   [`DBTraceTimeManager::set_snapshot_schedule`](crate::trace::database::time::db_trace_time_manager::DBTraceTimeManager::set_snapshot_schedule)
///   and this type carries only per-snapshot state behind its own `Mutex`.
/// - `getEventThread`/`setEventThread` are omitted: they resolve a thread key through
///   `DBTraceThreadManager` and the root object's `TraceEventScope` schema, none of which is
///   ported. The stored `threadKey` column is likewise omitted, since nothing can read it yet.
pub struct DBTraceSnapshot {
    key: i64,
    data: std::sync::Mutex<DBTraceSnapshotData>,
}

struct DBTraceSnapshotData {
    real_time: i64,
    description: String,
    schedule: Option<Arc<dyn TraceSchedule>>,
    schedule_str: String,
    version: i64,
    is_fork: bool,
}

impl DBTraceSnapshot {
    /// A freshly created snapshot record, mirroring `fresh(true)`: no schedule, empty schedule
    /// string, not a fork.
    pub fn new(key: i64) -> Self {
        Self {
            key,
            data: std::sync::Mutex::new(DBTraceSnapshotData {
                real_time: 0,
                description: String::new(),
                schedule: None,
                schedule_str: String::new(),
                version: 0,
                is_fork: false,
            }),
        }
    }

    /// Mirrors `DBAnnotatedObject.getKey()`, the snapshot's snap.
    pub fn get_key(&self) -> i64 {
        self.key
    }

    /// Mirrors `DBTraceSnapshot.set(long, String)`.
    pub fn set(&self, real_time: i64, description: &str) {
        let mut data = self.data.lock().unwrap();
        data.real_time = real_time;
        data.description = description.to_string();
    }

    /// Mirrors `DBTraceSnapshot.getRealTime()`.
    pub fn get_real_time(&self) -> i64 {
        self.data.lock().unwrap().real_time
    }

    /// Mirrors `DBTraceSnapshot.getDescription()`.
    pub fn get_description(&self) -> String {
        self.data.lock().unwrap().description.clone()
    }

    /// Mirrors `DBTraceSnapshot.getSchedule()`.
    pub fn get_schedule(&self) -> Option<Arc<dyn TraceSchedule>> {
        self.data.lock().unwrap().schedule.clone()
    }

    /// Mirrors `DBTraceSnapshot.getScheduleString()`, the indexed `Schedule` column.
    pub fn get_schedule_string(&self) -> String {
        self.data.lock().unwrap().schedule_str.clone()
    }

    /// Mirrors `DBTraceSnapshot.getVersion()`.
    pub fn get_version(&self) -> i64 {
        self.data.lock().unwrap().version
    }

    /// Mirrors `DBTraceSnapshot.setVersion(long)`. The manager's change notification is *not*
    /// fired from here (see the type docs); callers that need it go through the manager.
    pub fn set_version(&self, version: i64) {
        self.data.lock().unwrap().version = version;
    }

    /// Mirrors `DBTraceSnapshot.isSnapOnly(boolean)`.
    pub fn is_snap_only(&self, when_inconsistent: bool) -> bool {
        let data = self.data.lock().unwrap();
        match &data.schedule {
            None if self.key < 0 => when_inconsistent,
            None => true,
            Some(schedule) => schedule.is_snap_only(),
        }
    }

    /// The schedule-column half of `DBTraceSnapshot.setSchedule(TraceSchedule)`: store the
    /// schedule and its string form, recompute `isFork`, and report the new flag so the manager
    /// can add or drop the matching fork record.
    ///
    /// Mirrors `computeIsFork()`: the snapshot at `Long.MIN_VALUE` is never a fork, nor is one
    /// without a schedule; otherwise it is a fork exactly when its schedule does not simply
    /// continue from the preceding snap.
    pub fn store_schedule(&self, schedule: Option<Arc<dyn TraceSchedule>>) -> bool {
        let mut data = self.data.lock().unwrap();
        data.schedule_str = match &schedule {
            None => String::new(),
            Some(s) => s.schedule_string(),
        };
        data.is_fork = match (&schedule, self.key) {
            (_, i64::MIN) => false,
            (None, _) => false,
            (Some(s), key) => s.get_snap() != key - 1,
        };
        data.schedule = schedule;
        data.is_fork
    }
}

impl TraceSnapshot for DBTraceSnapshot {
    /// `DBTraceSnapshot.getTrace()`: not implementable here, since this placeholder carries no
    /// back-reference to its owning trace (see the type's docs).
    fn get_trace(&self) -> Box<dyn Trace> {
        unimplemented!("DBTraceSnapshot::get_trace placeholder not overridden")
    }

    fn get_key(&self) -> i64 {
        self.key
    }

    fn get_description(&self) -> String {
        self.data.lock().unwrap().description.clone()
    }

    fn set_description(&self, description: &str) {
        self.data.lock().unwrap().description = description.to_string();
    }

    fn get_real_time(&self) -> i64 {
        self.data.lock().unwrap().real_time
    }

    fn set_real_time(&self, millis_since_epoch: i64) {
        self.data.lock().unwrap().real_time = millis_since_epoch;
    }

    /// `DBTraceSnapshot.getEventThread()`: not implementable here -- event-thread resolution
    /// needs `DBTraceThreadManager` and the root object's `TraceEventScope` schema, neither of
    /// which is ported (see the type's docs).
    fn get_event_thread(&self) -> Option<Box<dyn TraceThread>> {
        unimplemented!("DBTraceSnapshot::get_event_thread placeholder not overridden")
    }

    /// `DBTraceSnapshot.setEventThread(TraceThread)`: see [`Self::get_event_thread`].
    fn set_event_thread(&self, thread: Option<Box<dyn TraceThread>>) {
        let _ = thread;
        unimplemented!("DBTraceSnapshot::set_event_thread placeholder not overridden")
    }

    fn get_schedule(&self) -> Option<Arc<dyn TraceSchedule>> {
        self.data.lock().unwrap().schedule.clone()
    }

    fn get_schedule_string(&self) -> String {
        self.data.lock().unwrap().schedule_str.clone()
    }

    fn is_fork(&self) -> bool {
        self.data.lock().unwrap().is_fork
    }

    fn set_schedule(&self, schedule: Option<Arc<dyn TraceSchedule>>) {
        self.store_schedule(schedule);
    }

    fn get_version(&self) -> i64 {
        self.data.lock().unwrap().version
    }

    fn set_version(&self, version: i64) {
        self.data.lock().unwrap().version = version;
    }

    fn is_snap_only(&self, when_inconsistent: bool) -> bool {
        let data = self.data.lock().unwrap();
        match &data.schedule {
            None if self.key < 0 => when_inconsistent,
            None => true,
            Some(schedule) => schedule.is_snap_only(),
        }
    }

    /// `DBTraceSnapshot.isStale(boolean)`: not implementable here -- staleness is measured
    /// against the owning trace's emulator cache version, and this placeholder carries no
    /// back-reference to its trace (see [`Self::get_trace`]).
    fn is_stale(&self, when_inconsistent: bool) -> bool {
        let _ = when_inconsistent;
        unimplemented!("DBTraceSnapshot::is_stale placeholder not overridden")
    }

    /// `DBTraceSnapshot.delete()`: not implementable here -- deletion needs the owning manager's
    /// store, which this placeholder does not reference.
    fn delete(&self) {
        unimplemented!("DBTraceSnapshot::delete placeholder not overridden")
    }
}

impl TraceSnapshot for Arc<DBTraceSnapshot> {
    fn get_trace(&self) -> Box<dyn Trace> {
        (**self).get_trace()
    }

    fn get_key(&self) -> i64 {
        (**self).get_key()
    }

    fn get_description(&self) -> String {
        (**self).get_description()
    }

    fn set_description(&self, description: &str) {
        (**self).set_description(description)
    }

    fn get_real_time(&self) -> i64 {
        (**self).get_real_time()
    }

    fn set_real_time(&self, millis_since_epoch: i64) {
        (**self).set_real_time(millis_since_epoch)
    }

    fn get_event_thread(&self) -> Option<Box<dyn TraceThread>> {
        (**self).get_event_thread()
    }

    fn set_event_thread(&self, thread: Option<Box<dyn TraceThread>>) {
        (**self).set_event_thread(thread)
    }

    fn get_schedule(&self) -> Option<Arc<dyn TraceSchedule>> {
        (**self).get_schedule()
    }

    fn get_schedule_string(&self) -> String {
        (**self).get_schedule_string()
    }

    fn is_fork(&self) -> bool {
        (**self).is_fork()
    }

    fn set_schedule(&self, schedule: Option<Arc<dyn TraceSchedule>>) {
        (**self).set_schedule(schedule)
    }

    fn get_version(&self) -> i64 {
        (**self).get_version()
    }

    fn set_version(&self, version: i64) {
        (**self).set_version(version)
    }

    fn is_snap_only(&self, when_inconsistent: bool) -> bool {
        (**self).is_snap_only(when_inconsistent)
    }

    fn is_stale(&self, when_inconsistent: bool) -> bool {
        (**self).is_stale(when_inconsistent)
    }

    fn delete(&self) {
        (**self).delete()
    }
}

impl std::fmt::Debug for DBTraceSnapshot {
    /// Mirrors `DBTraceSnapshot.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = self.data.lock().unwrap();
        write!(
            f,
            "<DBTraceSnapshot key={}, realTime={}, schedule='{}', description='{}'>",
            self.key, data.real_time, data.schedule_str, data.description
        )
    }
}

/// Placeholder for `ghidra.trace.database.thread.DBTraceThreadManager`, referenced by
/// [`DBTraceTimeManager`](crate::trace::database::time::db_trace_time_manager::DBTraceTimeManager)
/// before the real port is available. `DBTraceTimeManager` only stores its thread manager (for
/// `DBTraceSnapshot`'s event-thread resolution, which is not ported -- see [`DBTraceSnapshot`]),
/// so only the two `DBTraceManager` members are stubbed.
pub trait DBTraceThreadManager: Send + Sync {
    /// Mirrors `DBTraceThreadManager.dbError(IOException)`.
    fn db_error(&self, e: std::io::Error) {
        panic!("database error: {e}")
    }

    /// Mirrors `DBTraceThreadManager.invalidateCache(boolean)`.
    fn invalidate_cache(&self, all: bool) {
        let _ = all;
        unimplemented!("DBTraceThreadManager::invalidate_cache placeholder not overridden")
    }
}

/// Placeholder for `ghidra.trace.model.TraceAddressSnapSpace`, referenced by
/// [`ImmutableTraceAddressSnapRange`](crate::trace::model::immutable_trace_address_snap_range::ImmutableTraceAddressSnapRange)
/// before the real (concrete, cached-singleton) implementation is ported. Only the method that
/// type needs: obtaining the canonical space for a given address space.
pub trait TraceAddressSnapSpace: Send + Sync {
    fn for_address_space(space: &std::sync::Arc<crate::program::model::address::AddressSpace>) -> Box<dyn TraceAddressSnapSpace>
    where
        Self: Sized;
}

/// Placeholder for `ghidra.util.database.ObjectKey`, referenced by
/// [`TraceUniqueObject`](crate::trace::model::trace_unique_object::TraceUniqueObject) before the
/// real port is available. Mirrors the Java type's identity contract: an immutable-hash opaque id
/// that is equatable and orderable against other keys.
pub trait ObjectKey: Send + Sync {
    fn equals(&self, obj: &dyn std::any::Any) -> bool;
    fn hash_code(&self) -> i32;
    fn compare_to(&self, that: &dyn ObjectKey) -> i32;
}

/// Placeholder for `ghidra.trace.model.bookmark.TraceBookmarkType`, referenced by
/// [`TraceBookmark`](crate::trace::model::bookmark::trace_bookmark::TraceBookmark) before the
/// real port is available. No members are parsed from the Java source yet.
pub trait TraceBookmarkType: Send + Sync {}

/// Placeholder for `ghidra.trace.model.memory.TraceOverlappedRegionException`, referenced by
/// [`TraceMemoryRegion`](crate::trace::model::memory::trace_memory_region::TraceMemoryRegion)
/// before the real port is available. Mirrors the two members
/// [`TraceMemoryRegion`]'s setters need: the detail message (inherited from Java's
/// `UsrException.getMessage()`) and the conflicting regions.
pub trait TraceOverlappedRegionException: Send + Sync {
    /// Mirrors `UsrException.getMessage()`, as inherited by `TraceOverlappedRegionException`.
    fn message(&self) -> &str;

    /// Mirrors `TraceOverlappedRegionException.getConflicts()`.
    fn get_conflicts(
        &self,
    ) -> Vec<Box<dyn crate::trace::model::memory::trace_memory_region::TraceMemoryRegion>>;
}

/// Placeholder for `ghidra.trace.model.target.schema.TraceObjectSchema`, referenced by
/// [`SchemaContext`](crate::trace::model::target::schema::schema_context::SchemaContext) and
/// [`DefaultSchemaContext`](crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext)
/// before the real port is available. Grown beyond an opaque marker to add the two members
/// `DefaultSchemaContext` needs: the name a schema is keyed by in a context, and its
/// `toString()` representation.
pub trait TraceObjectSchema: Send + Sync {
    /// The name this schema is registered under. Mirrors `TraceObjectSchema.getName()`.
    fn get_name(&self) -> SchemaName;

    /// Mirrors `TraceObjectSchema.toString()`.
    fn to_string(&self) -> String;

    /// Checks whether the given attribute key is hidden by this schema. Mirrors
    /// `TraceObjectSchema.isHidden(String)`, used by
    /// [`TraceObjectValue`](crate::trace::model::target::trace_object_value::TraceObjectValue)'s
    /// default `isHidden()`.
    ///
    /// The real Java default resolves this via a per-schema `Hidden` predicate not yet ported, so
    /// this placeholder defaults to "never hidden" until that machinery exists.
    fn is_hidden(&self, _name: &str) -> bool {
        false
    }

    /// Resolves an attribute name (or one of its aliases) to its canonical key. Mirrors
    /// `TraceObjectSchema.checkAliasedAttribute(String)`, used by
    /// [`TraceObjectValue`](crate::trace::model::target::trace_object_value::TraceObjectValue)'s
    /// default `hasEntryKey()`.
    ///
    /// The real Java default resolves this via an attribute-alias map not yet ported, so this
    /// placeholder defaults to identity (no aliasing).
    fn check_aliased_attribute(&self, name: &str) -> String {
        name.to_string()
    }

    /// Resolves the schema for a given child key (attribute or element). Mirrors
    /// `TraceObjectSchema.getChildSchema(String)`, used by
    /// [`TraceObjectValue`](crate::trace::model::target::trace_object_value::TraceObjectValue)'s
    /// default `getTargetSchema()`.
    ///
    /// The real Java default resolves this via the element/attribute schema maps not yet ported,
    /// so this placeholder defaults to the "ANY" primitive schema, mirroring
    /// `SchemaContext::get_schema`'s documented fallback for unresolved names.
    fn get_child_schema(&self, _key: &str) -> Box<dyn TraceObjectSchema> {
        struct FallbackAnySchema;
        impl TraceObjectSchema for FallbackAnySchema {
            fn get_name(&self) -> SchemaName {
                SchemaName::new("ANY")
            }

            fn to_string(&self) -> String {
                "ANY".to_string()
            }
        }
        Box::new(FallbackAnySchema)
    }

    /// Resolves the schema of the (possibly indirect) successor object at the given path from
    /// this schema. Mirrors `TraceObjectSchema.getSuccessorSchema(KeyPath)`, used by
    /// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)'s
    /// `getConventionalRegisterPath(AddressSpace, Register)` default.
    ///
    /// The real Java method walks the element/attribute schema maps (not yet ported) to resolve
    /// each path component, so this placeholder defaults to "unresolved" until that machinery
    /// exists.
    fn get_successor_schema(&self, _path: &KeyPath) -> Option<Box<dyn TraceObjectSchema>> {
        None
    }

    /// The trace interfaces this schema declares its objects provide. Mirrors
    /// `TraceObjectSchema.getInterfaces()`, used by
    /// [`TraceObject`](crate::trace::model::target::trace_object::TraceObject)'s default
    /// `isMethod()`.
    ///
    /// Java returns the interfaces' class tokens; this crate reifies the `@TraceObjectInfo`
    /// annotation those tokens are read through as [`TraceObjectInfo`], so that is the element
    /// type here. Defaults to "declares nothing" until the real schema port lands.
    fn get_interfaces(&self) -> Vec<TraceObjectInfo> {
        Vec::new()
    }

    /// Search this (root) schema for the unique path of an object suitable to provide the
    /// interface named `iface` in the context of the object at `seed`. Mirrors
    /// `TraceObjectSchema.searchForSuitable(Class, KeyPath)`, used by
    /// [`TraceObject`](crate::trace::model::target::trace_object::TraceObject)'s default
    /// `findSuitableInterface()`/`getExecutionState()`.
    ///
    /// The interface is named by its schema name rather than a class token, following the
    /// convention
    /// [`PrimitiveTraceObjectSchema`](crate::trace::model::target::schema::primitive_trace_object_schema)
    /// already uses for the `Class<?>` arguments of this same family of `searchFor*` methods.
    ///
    /// The real Java method walks the schema's ancestry and aggregate attributes (not yet
    /// ported), so this placeholder defaults to "not found".
    fn search_for_suitable(&self, _iface: &str, _seed: &KeyPath) -> Option<KeyPath> {
        None
    }

    /// As [`Self::search_for_suitable`], but searching for an object with the given schema rather
    /// than a given interface. Mirrors the
    /// `searchForSuitable(TraceObjectSchema, KeyPath)` overload, used by
    /// [`TraceObject`](crate::trace::model::target::trace_object::TraceObject)'s default
    /// `findSuitableSchema()`.
    fn search_for_suitable_schema(
        &self,
        _schema: &dyn TraceObjectSchema,
        _seed: &KeyPath,
    ) -> Option<KeyPath> {
        None
    }

    /// As [`Self::search_for_suitable`], but searching for the canonical *container* of `iface`.
    /// Mirrors `TraceObjectSchema.searchForSuitableContainer(Class, KeyPath)`, used by
    /// [`TraceObject`](crate::trace::model::target::trace_object::TraceObject)'s default
    /// `findSuitableContainerInterface()`.
    fn search_for_suitable_container(&self, _iface: &str, _seed: &KeyPath) -> Option<KeyPath> {
        None
    }

    /// Search this (root) schema for the register container(s) applicable to the object at
    /// `seed` at the given frame level. Mirrors
    /// `TraceObjectSchema.searchForRegisterContainer(int, KeyPath)`, used by
    /// [`TraceObject`](crate::trace::model::target::trace_object::TraceObject)'s default
    /// `findRegisterContainer()`.
    ///
    /// Java returns a `PathFilter` (in practice a `PathMatcher`) whose only use at that call site
    /// is enumerating its patterns. `PathMatcher` is not ported and this crate's
    /// [`PathFilter`](crate::trace::model::target::path::PathFilter) has no `getPatterns()`, so
    /// the patterns are returned directly. Defaults to "no candidates".
    fn search_for_register_container(
        &self,
        _frame_level: i32,
        _seed: &KeyPath,
    ) -> Vec<PathPattern> {
        Vec::new()
    }
}

/// Placeholder for the nested `ghidra.trace.model.Lifespan.LifeSet`, referenced by
/// [`TraceObject`] before the real port is available. Mirrors the one member
/// `DBTraceObjectInterface`'s default `isDeleted()` needs: whether the set of lifespans is empty.
pub trait LifeSet: Send + Sync {
    /// Mirrors `Span.SpanSet.isEmpty()`, as inherited by `LifeSet`.
    fn is_empty(&self) -> bool;
}

/// Placeholder for `ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema`,
/// referenced by
/// [`PrimitiveTraceObjectSchema`](crate::trace::model::target::schema::primitive_trace_object_schema::PrimitiveTraceObjectSchema)
/// before the real port is available. `PrimitiveTraceObjectSchema` only ever hands these back as
/// opaque values (`AttributeSchema.DEFAULT_ANY`/`DEFAULT_VOID`), never inspecting them, so this is
/// a marker trait rather than reproducing `getName`/`getSchema`/`isRequired`/`isFixed`/`getHidden`.
pub trait AttributeSchema: Send + Sync {}

/// Placeholder for `ghidra.trace.model.target.schema.SchemaBuilder`, referenced by
/// [`DefaultSchemaContext`](crate::trace::model::target::schema::default_schema_context::DefaultSchemaContext)
/// before the real port is available. `DefaultSchemaContext` only invokes `buildAndAdd()` on
/// builders it constructs, so that is the only member ported here.
pub trait SchemaBuilder: Send + Sync {
    /// Builds the schema and adds it to the context the builder was created from. Mirrors
    /// `SchemaBuilder.buildAndAdd()`.
    fn build_and_add(&self) -> Box<dyn TraceObjectSchema>;
}

/// Placeholder for `ghidra.trace.database.target.DBTraceObject`, referenced by
/// [`TraceObjectValueStorage`](crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage)
/// before the real port is available. `TraceObjectValueStorage` is a bare abstract interface (no
/// default methods), so it only ever passes this type around opaquely (as `getParent`'s return
/// and `getChildOrNull`'s return); no members are needed yet.
///
/// Grown again for
/// [`DBTraceObjectValue`](crate::trace::database::target::db_trace_object_value::DBTraceObjectValue),
/// which is the real port of the *other* half of the object/value cycle. Two changes:
///
/// - This is now declared `DBTraceObject: TraceObject`, which the Java class is
///   (`class DBTraceObject extends DBAnnotatedObject implements TraceObject,
///   DBTraceObjectInterface`). A value entry has to widen its parent and child to
///   [`TraceObjectValue`](crate::trace::model::target::trace_object_value::TraceObjectValue)'s
///   `Box<dyn TraceObject>`, which is only possible if the placeholder actually sits under
///   `TraceObject`. It also brings in `getCanonicalPath()`, which `DBTraceObjectValue`'s own
///   canonical-path computation is defined in terms of. It also supplies the `getAttribute` /
///   `setAttribute` pair
///   [`DBTraceTimeManager`](crate::trace::database::time::db_trace_time_manager::DBTraceTimeManager)'s
///   time-radix members use, which this placeholder previously declared itself.
/// - The package-private members `DBTraceObjectValue` calls on its parent and child are added
///   below. Each defaults to panicking rather than being required, so existing marker
///   implementors need only gain a `TraceObject` impl.
pub trait DBTraceObject: TraceObject {
    /// Mirrors `emitEvents(TraceChangeRecord<?, ?>)`, which forwards a change record to the
    /// object's trace (and to any interfaces the object implements, which may translate it).
    fn emit_events(&self, record: &TraceChangeRecord) {
        let _ = record;
        unimplemented!("DBTraceObject::emit_events placeholder not overridden")
    }

    /// Mirrors `notifyValueCreated(DBTraceObjectValue)`: a value entry whose *parent* is this
    /// object has just been added to the object's value cache.
    fn notify_value_created(&self, value: &DBTraceObjectValue) {
        let _ = value;
        unimplemented!("DBTraceObject::notify_value_created placeholder not overridden")
    }

    /// Mirrors `notifyValueDeleted(DBTraceObjectValue)`: the counterpart of
    /// [`Self::notify_value_created`].
    fn notify_value_deleted(&self, value: &DBTraceObjectValue) {
        let _ = value;
        unimplemented!("DBTraceObject::notify_value_deleted placeholder not overridden")
    }

    /// Mirrors `notifyParentValueCreated(DBTraceObjectValue)`: a value entry whose *child* is
    /// this object has just been added.
    fn notify_parent_value_created(&self, value: &DBTraceObjectValue) {
        let _ = value;
        unimplemented!("DBTraceObject::notify_parent_value_created placeholder not overridden")
    }

    /// Mirrors `notifyParentValueDeleted(DBTraceObjectValue)`: the counterpart of
    /// [`Self::notify_parent_value_created`].
    fn notify_parent_value_deleted(&self, value: &DBTraceObjectValue) {
        let _ = value;
        unimplemented!("DBTraceObject::notify_parent_value_deleted placeholder not overridden")
    }

    /// Mirrors `doCheckConflicts(Lifespan, String, Object)`, which throws `DuplicateKeyException`
    /// if setting `key` to `value` over `lifespan` would collide with an existing entry. The
    /// checked Java exception becomes an `Err`.
    fn do_check_conflicts(
        &self,
        lifespan: Lifespan,
        key: &str,
        value: &(dyn std::any::Any + Send + Sync),
    ) -> Result<(), crate::trace::model::target::duplicate_key_exception::DuplicateKeyException>
    {
        let _ = (lifespan, key, value);
        unimplemented!("DBTraceObject::do_check_conflicts placeholder not overridden")
    }

    /// Mirrors `doAdjust(Lifespan, String, Object)`, which shrinks `lifespan` to whatever part of
    /// it is free of conflicting entries (possibly to [`Lifespan::EMPTY`]).
    fn do_adjust(
        &self,
        lifespan: Lifespan,
        key: &str,
        value: &(dyn std::any::Any + Send + Sync),
    ) -> Lifespan {
        let _ = (lifespan, key, value);
        unimplemented!("DBTraceObject::do_adjust placeholder not overridden")
    }

    /// Mirrors `doCreateValue(Lifespan, String, Object)`, which creates and caches a new value
    /// entry under this object without any conflict resolution.
    fn do_create_value(
        &self,
        lifespan: Lifespan,
        key: &str,
        value: Box<dyn std::any::Any + Send + Sync>,
    ) -> Box<DBTraceObjectValue> {
        let _ = (lifespan, key, value);
        unimplemented!("DBTraceObject::do_create_value placeholder not overridden")
    }
}

/// Placeholder for `ghidra.trace.database.target.DBTraceObjectManager`, referenced by
/// [`TraceObjectValueStorage`](crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage)
/// before the real port is available. `TraceObjectValueStorage` only ever passes this type around
/// opaquely (as `getManager`'s return); no members are needed yet.
///
/// Grown to add the region-storage methods
/// [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)'s
/// region-management defaults need. The real Java methods are generic in a `Class<I extends
/// TraceObjectInterface>` reflection token (`getAllObjects(Class<I>)`, etc); every call site this
/// placeholder's consumer makes passes `TraceMemoryRegion.class`, so each is specialized directly
/// to [`TraceMemoryRegion`] rather than reproducing the generic/reflective shape. All default to
/// panicking, like [`DBTrace`]'s grown `get_object_manager`, so the existing marker
/// (`impl DBTraceObjectManager for T {}`) implementors keep compiling unchanged.
pub trait DBTraceObjectManager: Send + Sync {
    /// Mirrors `addMemoryRegion(String, Lifespan, AddressRange, Collection<TraceMemoryFlag>)`.
    fn add_memory_region(
        &self,
        _path: &str,
        _lifespan: Lifespan,
        _range: AddressRange,
        _flags: &[TraceMemoryFlag],
    ) -> Result<Box<dyn TraceMemoryRegion>, Box<dyn TraceOverlappedRegionException>> {
        unimplemented!("DBTraceObjectManager::add_memory_region placeholder not overridden")
    }

    /// Mirrors `getAllObjects(TraceMemoryRegion.class)`.
    fn get_all_regions(&self) -> Vec<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_all_regions placeholder not overridden")
    }

    /// Mirrors `getObjectByPath(long, String, TraceMemoryRegion.class)`.
    fn get_region_by_path(&self, _snap: i64, _path: &str) -> Option<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_region_by_path placeholder not overridden")
    }

    /// Mirrors `getObjectContaining(long, Address, TraceMemoryRegion.KEY_RANGE,
    /// TraceMemoryRegion.class)`.
    fn get_region_containing(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_region_containing placeholder not overridden")
    }

    /// Mirrors `getObjectsIntersecting(Lifespan, AddressRange, TraceMemoryRegion.KEY_RANGE,
    /// TraceMemoryRegion.class)`.
    fn get_regions_intersecting(
        &self,
        _lifespan: Lifespan,
        _range: &AddressRange,
    ) -> Vec<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_regions_intersecting placeholder not overridden")
    }

    /// Mirrors `getObjectsAtSnap(long, TraceMemoryRegion.class)`.
    fn get_regions_at_snap(&self, _snap: i64) -> Vec<Box<dyn TraceMemoryRegion>> {
        unimplemented!("DBTraceObjectManager::get_regions_at_snap placeholder not overridden")
    }

    /// Mirrors `getObjectsAddressSet(long, TraceMemoryRegion.KEY_RANGE, TraceMemoryRegion.class,
    /// Predicate<TraceMemoryRegion>)`.
    fn get_regions_address_set(
        &self,
        _snap: i64,
        _predicate: &dyn Fn(&dyn TraceMemoryRegion) -> bool,
    ) -> Box<dyn AddressSetView> {
        unimplemented!("DBTraceObjectManager::get_regions_address_set placeholder not overridden")
    }

    /// Mirrors `getRootObject()`, whose `null` return becomes `None`. Needed by
    /// [`DBTraceTimeManager`](crate::trace::database::time::db_trace_time_manager::DBTraceTimeManager)'s
    /// time-radix members, which store the radix as a root-object attribute.
    fn get_root_object(&self) -> Option<Box<dyn DBTraceObject>> {
        unimplemented!("DBTraceObjectManager::get_root_object placeholder not overridden")
    }

    /// Mirrors the package-private `trace` field, which
    /// [`DBTraceObjectValue`](crate::trace::database::target::db_trace_object_value::DBTraceObjectValue)
    /// reads as `manager.trace` to implement `getTrace()`.
    fn get_trace(&self) -> Box<dyn Trace> {
        unimplemented!("DBTraceObjectManager::get_trace placeholder not overridden")
    }
}

/// Placeholder for `ghidra.trace.database.target.TraceObjectValueQuery`, referenced by
/// [`DBTraceObjectValueRStarTree`](crate::trace::database::target::db_trace_object_value_r_star_tree::DBTraceObjectValueRStarTree)
/// before the real port is available. That trait's `DBTraceObjectValueMap::reduce` only ever
/// passes this type around opaquely (as the query to combine with any existing constraint); no
/// members are needed yet.
pub trait TraceObjectValueQuery: Send + Sync {}

/// Placeholder for `ghidra.trace.util.TraceRegisterUtils`, referenced by
/// [`TraceSpaceMixin`](crate::trace::util::trace_space_mixin::TraceSpaceMixin) before the real
/// port is available. Mirrors the Java class's static-method-only shape (see
/// [`ExtensionUtils`](crate::util::extensions::extension_utils::ExtensionUtils) for the same
/// static-class-to-`&self`-trait convention) as an object-safe trait, restricted to the two
/// static methods `TraceSpaceMixin`'s defaults call: `getThread(Trace, AddressSpace)` and
/// `getFrameLevel(Trace, AddressSpace)`.
///
/// Grown to add
/// [`TraceLabelSymbolView`](crate::trace::model::symbol::trace_label_symbol_view::TraceLabelSymbolView)'s
/// `requireByteBound(Register)` static check, used by its register-taking `add` default.
pub trait TraceRegisterUtils: Send + Sync {
    /// Mirrors `TraceRegisterUtils.getThread(Trace, AddressSpace)`.
    fn get_thread(&self, trace: &dyn Trace, space: &Arc<AddressSpace>) -> Box<dyn TraceThread>;

    /// Mirrors `TraceRegisterUtils.getFrameLevel(Trace, AddressSpace)`.
    fn get_frame_level(&self, trace: &dyn Trace, space: &Arc<AddressSpace>) -> i32;

    /// Get the register address space for the given thread and frame level, or `None` if it
    /// does not exist (and `create_if_absent` is false). Mirrors
    /// `TraceRegisterUtils.getRegisterAddressSpace(TraceThread, int, boolean)`, used by
    /// [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView)'s
    /// register-taking defaults.
    fn get_register_address_space(
        &self,
        thread: &dyn TraceThread,
        frame_level: i32,
        create_if_absent: bool,
    ) -> Option<Arc<AddressSpace>>;

    /// Mirrors `TraceRegisterUtils.requireByteBound(Register)`, which rejects a register that
    /// does not start and end on a byte boundary. Implemented directly against the ported
    /// [`Register`], since the check depends only on the register itself, not on any manager
    /// state.
    ///
    /// # Panics
    /// Panics if `register` is not byte-bound, mirroring the Java method's
    /// `IllegalArgumentException`.
    fn require_byte_bound(&self, register: &Register) {
        if register.least_significant_bit() % 8 != 0 || register.bit_length() % 8 != 0 {
            panic!("register {} is not byte-bound", register.name());
        }
    }

    /// Get the (byte-addressed) range a register occupies in its own address space. Mirrors the
    /// static `TraceRegisterUtils.rangeForRegister(Register)`, used by
    /// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)'s
    /// `getConventionalRegisterRange` default.
    ///
    /// Unlike this trait's other members, this one is implemented directly against the ported
    /// [`Register`] (its address and byte length), since the computation depends only on the
    /// register itself, not on any manager state.
    fn range_for_register(&self, register: &Register) -> AddressRange {
        let start = register.address().clone();
        let end = start.add_wrap((register.num_bytes() as i64) - 1);
        AddressRange::new(start, end)
    }

    /// Whether `register` starts and ends on a byte boundary. Mirrors the static
    /// `TraceRegisterUtils.isByteBound(Register)`, used by
    /// [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations)'s
    /// `setValue` default.
    ///
    /// Like [`Self::range_for_register`], this is implemented directly against the ported
    /// [`Register`]: the same check [`Self::require_byte_bound`] already makes, but as a predicate
    /// rather than a panic.
    fn is_byte_bound(&self, register: &Register) -> bool {
        register.least_significant_bit() % 8 == 0 && register.bit_length() % 8 == 0
    }

    /// Allocate a zeroed buffer sized to receive `register`'s bytes. Mirrors the static
    /// `TraceRegisterUtils.prepareBuffer(Register)`, used by
    /// [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations)'s
    /// `getValue`/`getViewValue` defaults, which fill it via `TraceMemoryOperations::get_bytes`/
    /// `get_view_bytes` before handing it to [`Self::finish_buffer`].
    ///
    /// The real Java method over-allocates to the base register's mask width and slices a
    /// byte-order-dependent window into it (see [`Self::finish_buffer`]'s docs for why that
    /// endianness handling has no home here yet); since callers only ever observe the buffer's
    /// length (`register.getNumBytes()`), a buffer of exactly that length is a faithful
    /// placeholder.
    fn prepare_buffer(&self, register: &Register) -> Vec<u8> {
        vec![0u8; register.num_bytes() as usize]
    }

    /// Extract the byte-ordered, mask-offset window of `value`'s bytes that corresponds to
    /// `register`. Mirrors the static `TraceRegisterUtils.bufferForValue(Register,
    /// RegisterValue)`, used by
    /// [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations)'s
    /// `setValue` default.
    ///
    /// Required rather than defaulted: the real computation reads `value`'s raw mask/value byte
    /// array (`RegisterValue.toBytes()`), which the
    /// [`RegisterValue`](crate::program::seam_stubs::RegisterValue) placeholder does not yet
    /// expose.
    fn buffer_for_value(&self, register: &Register, value: &dyn ProgramRegisterValue) -> Vec<u8>;

    /// Reconstruct a register value from a buffer previously filled via [`Self::prepare_buffer`].
    /// Mirrors the static `TraceRegisterUtils.finishBuffer(ByteBuffer, Register)`, used by
    /// [`InternalTraceMemoryOperations`](crate::trace::database::memory::internal_trace_memory_operations::InternalTraceMemoryOperations)'s
    /// `getValue`/`getViewValue` defaults.
    ///
    /// Required rather than defaulted: constructing a `RegisterValue` from raw bytes has no
    /// implementation to call through to on the
    /// [`RegisterValue`](crate::program::seam_stubs::RegisterValue) placeholder trait (it can only
    /// be built by a concrete type).
    fn finish_buffer(&self, buf: &[u8], register: &Register) -> Box<dyn ProgramRegisterValue>;
}

/// Placeholder for the nested `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery`,
/// referenced by
/// [`TraceAddressSnapRangePropertyMapOperations`](crate::trace::model::map::trace_address_snap_range_property_map_operations::TraceAddressSnapRangePropertyMapOperations)
/// before the real port is available. That trait only ever passes this type around opaquely (as
/// the `Q` type parameter of the `SpatialMap` supertrait it extends); no members are needed yet.
pub trait TraceAddressSnapRangeQuery: Send + Sync {}

/// Placeholder for `ghidra.trace.database.guest.DBTraceGuestPlatform.DBTraceGuestLanguage`,
/// referenced by
/// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)
/// before the real port is available. `InternalTracePlatform` only ever passes this type around
/// opaquely (as `getLanguageEntry()`'s return); no members are needed yet.
pub trait DBTraceGuestLanguage: Send + Sync {}

/// Placeholder for the nested
/// `ghidra.trace.database.data.DBTraceDataSettingsAdapter.DBTraceSettingsEntry`, referenced by
/// [`DBTraceDataSettingsOperations`](crate::trace::database::data::db_trace_data_settings_operations::DBTraceDataSettingsOperations)
/// before the real (DB-record-backed) type is ported. Mirrors the subset of members that
/// interface's default methods call: the lifespan and name accessors, plus the
/// `setLong`/`getLong`/`setString`/`getString`/`setValue`/`getValue` value accessors. The Java
/// class's `setBytes`/`getBytes` pair is not referenced by that interface (only reachable through
/// `setValue`/`getValue`, which already cover the `byte[]` case via
/// [`SettingsValue::Bytes`](crate::trace::database::data::db_trace_data_settings_operations::SettingsValue::Bytes)),
/// so it is omitted here.
pub trait DBTraceSettingsEntry: Send + Sync {
    /// Mirrors the record's `getLifespan()` (inherited from
    /// `AbstractDBTraceAddressSnapRangePropertyMapData`).
    fn get_lifespan(&self) -> Lifespan;

    /// Mirrors the `name` field's getter.
    fn name(&self) -> Option<String>;

    /// Mirrors `setName(String)`.
    fn set_name(&mut self, name: String);

    /// Mirrors `getLong()`.
    fn get_long(&self) -> Option<i64>;

    /// Mirrors `setLong(long)`.
    fn set_long(&mut self, value: i64);

    /// Mirrors `getString()`.
    fn get_string(&self) -> Option<String>;

    /// Mirrors `setString(String)`.
    fn set_string(&mut self, value: String);

    /// Mirrors `getValue()`.
    fn get_value(&self) -> crate::trace::database::data::db_trace_data_settings_operations::SettingsValue;

    /// Mirrors `setValue(Object)`.
    fn set_value(
        &mut self,
        value: crate::trace::database::data::db_trace_data_settings_operations::SettingsValue,
    );
}

/// Placeholder for the nested
/// `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData`,
/// referenced by
/// [`DBTraceAddressSnapRangePropertyMap`](crate::trace::database::map::db_trace_address_snap_range_property_map::DBTraceAddressSnapRangePropertyMap)
/// before the real port is available. That trait's `deleteData(DR)` only ever reads one field off
/// the record: the address space its backing range belongs to (`data.range.getAddressSpace()`),
/// used to pick which per-space delegate owns it.
pub trait AbstractDBTraceAddressSnapRangePropertyMapData: Send + Sync {
    /// The address space that this record's range belongs to. Mirrors
    /// `data.range.getAddressSpace()`.
    fn address_space(&self) -> Arc<AddressSpace>;
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceCodeUnitAdapter`, referenced (as a
/// supertrait) by
/// [`DBTraceDataAdapter`](crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter)
/// before the real port is available. In Java this interface overrides `TraceCodeUnit.getTrace()`
/// to covariantly narrow its return type from `Trace` to `DBTrace` (which implements
/// `ghidra.trace.util.TraceChangeManager`), letting `DBTraceDataAdapter`'s settings-change
/// defaults call `getTrace().setChanged(...)` directly. Rust has no covariant trait-method
/// override (see `TraceData`'s docs for the same issue), so this placeholder instead exposes the
/// change-notification sink those defaults need as its own accessor, rather than reproducing the
/// covariant `getTrace()`.
pub trait DBTraceCodeUnitAdapter: Send + Sync {
    /// Mirrors reaching the owning trace's `TraceChangeManager` through the covariant
    /// `getTrace()` override.
    fn trace_change_manager(&mut self) -> &mut dyn TraceChangeManager;
}

/// Placeholder for `ghidra.trace.util.DataAdapterFromDataType`, referenced (as a supertrait) by
/// [`DBTraceDataAdapter`](crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter)
/// before the real port is available. No members are parsed from the Java source yet.
pub trait DataAdapterFromDataType: Send + Sync {}

/// Placeholder for `ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace`,
/// referenced by
/// [`DBTraceAddressSnapRangePropertyMapTree`](crate::trace::database::map::db_trace_address_snap_range_property_map_tree::DBTraceAddressSnapRangePropertyMapTree)
/// before the real port is available. That trait's `getMapSpace()` returns this type opaquely to
/// callers; the one accessor it (and the tree's own node/data records) reach into is the backing
/// address space. Mirrors `DBTraceAddressSnapRangePropertyMapSpace.getAddressSpace()`.
pub trait DBTraceAddressSnapRangePropertyMapSpace<T>: Send + Sync {
    /// Mirrors `DBTraceAddressSnapRangePropertyMapSpace.getAddressSpace()`.
    fn address_space(&self) -> Arc<AddressSpace>;
}

/// Placeholder for `ghidra.util.database.spatial.DBTreeNodeRecord`, referenced by
/// [`DBTraceAddressSnapRangePropertyMapTree`](crate::trace::database::map::db_trace_address_snap_range_property_map_tree::DBTraceAddressSnapRangePropertyMapTree)
/// before the real port is available. That trait's `internalGetChildrenOf(DBTreeNodeRecord<?>)`
/// only ever type-tests and passes this type around opaquely; no members are needed yet.
pub trait DBTreeNodeRecord: Send + Sync {}

/// Placeholder for `ghidra.util.database.spatial.DBTreeRecord`, referenced by
/// [`DBTraceAddressSnapRangePropertyMapTree`](crate::trace::database::map::db_trace_address_snap_range_property_map_tree::DBTraceAddressSnapRangePropertyMapTree)
/// before the real port is available. That trait's `internalGetChildrenOf(DBTreeNodeRecord<?>)`
/// only ever returns this type opaquely to callers; no members are needed yet.
pub trait DBTreeRecord: Send + Sync {}

/// Placeholder for `ghidra.util.database.spatial.rect.Rectangle2DDirection`, referenced by
/// [`TraceReferenceOperations`](crate::trace::model::symbol::trace_reference_operations::TraceReferenceOperations)
/// before the real port is available. The Java type is an enum (`LEFTMOST`, `RIGHTMOST`,
/// `BOTTOMMOST`, `TOPMOST`) whose only public member is `isReversed()`; only that member is
/// stubbed here.
pub trait Rectangle2DDirection: Send + Sync {
    fn is_reversed(&self) -> bool;
}

/// Placeholder for `ghidra.trace.database.listing.AbstractBaseDBTraceCodeUnitsView<T>`,
/// referenced (as a supertrait) by
/// [`AbstractSingleDBTraceCodeUnitsView`](crate::trace::database::listing::abstract_single_db_trace_code_units_view::AbstractSingleDBTraceCodeUnitsView)
/// and (as the composed-view bound `M`) by
/// [`AbstractBaseDBTraceCodeUnitsMemoryView`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view::AbstractBaseDBTraceCodeUnitsMemoryView)
/// before the real port is available. Grown from a non-generic marker (just `getSpace()`) to
/// carry the Java class's `T extends DBTraceCodeUnitAdapter` type parameter, since
/// `AbstractBaseDBTraceCodeUnitsMemoryView`'s defaults call straight through to this view's own
/// per-space query methods (`getFloor`, `getAt`, the `get(...)` overloads, etc.) -- named here
/// to match the sibling overload-disambiguated names already established on
/// [`TraceBaseCodeUnitsView`](crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView)
/// (`get_in_range`, `get_address_set_view_within`, `covers_snap_range`, ...). Methods this stub's
/// original (narrower) consumer, [`AbstractSingleDBTraceCodeUnitsView`], doesn't need are still
/// included, since the real Java interface declares them regardless of which subtrait uses them.
pub trait AbstractBaseDBTraceCodeUnitsView<T> {
    /// The address space this view is bound to. Mirrors
    /// `AbstractBaseDBTraceCodeUnitsView.getSpace()` (equivalently, `getAddressSpace()`).
    fn get_space(&self) -> Arc<AddressSpace>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.size()`.
    fn size(&self) -> i32;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getFloor(long, Address)`.
    fn get_floor(&self, snap: i64, address: &Address) -> Option<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getContaining(long, Address)`.
    fn get_containing(&self, snap: i64, address: &Address) -> Option<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getAt(long, Address)`.
    fn get_at(&self, snap: i64, address: &Address) -> Option<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getCeiling(long, Address)`.
    fn get_ceiling(&self, snap: i64, address: &Address) -> Option<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.get(long, AddressRange, boolean)`. Named to
    /// match [`TraceBaseCodeUnitsView::get_in_range`].
    fn get_in_range(&self, snap: i64, range: &AddressRange, forward: bool) -> Vec<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getIntersecting(TraceAddressSnapRange)`.
    fn get_intersecting(&self, tasr: &dyn TraceAddressSnapRange) -> Vec<T>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getAddressSetView(long, AddressRange)`. Named to
    /// match [`TraceBaseCodeUnitsView::get_address_set_view_within`].
    fn get_address_set_view_within(&self, snap: i64, within: &AddressRange) -> Box<dyn AddressSetView>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.getAddressSetView(long)`.
    fn get_address_set_view(&self, snap: i64) -> Box<dyn AddressSetView>;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.containsAddress(long, Address)`.
    fn contains_address(&self, snap: i64, address: &Address) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.coversRange(Lifespan, AddressRange)`.
    fn covers_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.coversRange(TraceAddressSnapRange)`. Named to
    /// match [`TraceBaseCodeUnitsView::covers_snap_range`].
    fn covers_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.intersectsRange(Lifespan, AddressRange)`.
    fn intersects_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.intersectsRange(TraceAddressSnapRange)`. Named
    /// to match [`TraceBaseCodeUnitsView::intersects_snap_range`].
    fn intersects_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool;
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceCodeManager`, referenced by
/// [`AbstractBaseDBTraceCodeUnitsMemoryView`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view::AbstractBaseDBTraceCodeUnitsMemoryView)
/// before the real port is available. That trait's `manager` field accessor only ever reaches
/// these members (all inherited, in the real Java class, from
/// `AbstractDBTraceSpaceBasedManager<`[`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)`>`): the owning trace, the base language
/// (used to walk address spaces when stepping past a space boundary), the read/write locks, the
/// per-space lookup, and the active-space listing `size()` sums over.
pub trait DBTraceCodeManager: Send + Sync {
    /// Mirrors `AbstractDBTraceSpaceBasedManager.getTrace()`.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.getBaseLanguage()`.
    fn get_base_language(&self) -> Box<dyn Language>;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.lock.readLock()`.
    fn read_lock(&self) -> &dyn Lock;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.lock.writeLock()`.
    fn write_lock(&self) -> &dyn Lock;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.getForSpace(AddressSpace, boolean)`.
    fn get_for_space(
        &self,
        space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<Arc<dyn DBTraceCodeSpace>>;

    /// Mirrors `AbstractDBTraceSpaceBasedManager.getActiveSpaces()`.
    fn get_active_spaces(&self) -> Vec<Arc<dyn DBTraceCodeSpace>>;
}

/// Placeholder for `ghidra.trace.database.DBTrace`, referenced by
/// [`AbstractDBTraceCodeUnit`](crate::trace::database::listing::abstract_db_trace_code_unit::AbstractDBTraceCodeUnit)
/// before the real port is available. `AbstractDBTraceCodeUnit.getTrace()` only ever passes this
/// type around opaquely (returning `space.trace`, covariantly narrowed from the base `Trace`
/// interface -- see
/// [`DBTraceCodeSpace::get_trace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace::get_trace)'s
/// docs for that same narrowing); no members are needed yet. Not declared `: Trace`, since nothing
/// currently reachable through this placeholder needs any of `Trace`'s ~20 members, and requiring
/// them would force every implementor (including this module's own tests) to stub out that whole
/// surface for no benefit; the real port should implement both `Trace` and this trait, matching
/// Java's `DBTrace implements Trace`.
///
/// Grown to add the one member
/// [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)'s
/// region-management defaults need: reaching the trace's object manager, where regions are
/// actually stored (`trace.getObjectManager().addMemoryRegion(...)`, etc). Defaults to
/// panicking, like [`DBTraceOverlaySpaceAdapter`]'s grown members, so the existing marker
/// (`impl DBTrace for T {}`) implementors keep compiling unchanged.
pub trait DBTrace: Send + Sync {
    /// Mirrors `DBTrace.getObjectManager()`.
    fn get_object_manager(&self) -> Box<dyn DBTraceObjectManager> {
        unimplemented!("DBTrace::get_object_manager placeholder not overridden")
    }

    /// Mirrors `DBTrace.dbError(IOException)`, which wraps and rethrows. Panicking is the
    /// convention [`ErrorHandler`](crate::framework::db::util::error_handler::ErrorHandler)
    /// documents for that.
    fn db_error(&self, e: std::io::Error) {
        panic!("database error: {e}")
    }

    /// Mirrors `DBTrace.setChanged(TraceChangeRecord)`.
    fn set_changed(&self, event: &TraceChangeRecord) {
        let _ = event;
        unimplemented!("DBTrace::set_changed placeholder not overridden")
    }

    /// Mirrors `DBTrace.getEmulatorCacheVersion()`.
    fn get_emulator_cache_version(&self) -> i64 {
        unimplemented!("DBTrace::get_emulator_cache_version placeholder not overridden")
    }

    /// Mirrors `DBTrace.updateViewportsSnapshotAdded(TraceSnapshot)`.
    fn update_viewports_snapshot_added(&self, snapshot: &dyn TraceSnapshot) {
        let _ = snapshot;
        unimplemented!("DBTrace::update_viewports_snapshot_added placeholder not overridden")
    }

    /// Mirrors `DBTrace.updateViewportsSnapshotChanged(TraceSnapshot)`.
    fn update_viewports_snapshot_changed(&self, snapshot: &dyn TraceSnapshot) {
        let _ = snapshot;
        unimplemented!("DBTrace::update_viewports_snapshot_changed placeholder not overridden")
    }

    /// Mirrors `DBTrace.updateViewportsSnapshotDeleted(TraceSnapshot)`.
    fn update_viewports_snapshot_deleted(&self, snapshot: &dyn TraceSnapshot) {
        let _ = snapshot;
        unimplemented!("DBTrace::update_viewports_snapshot_deleted placeholder not overridden")
    }
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceCodeUnitsView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. `DBTraceCodeSpace` only ever stores and returns this type
/// opaquely (via its own `codeUnits()` accessor); no members are called on it, so this is a bare
/// marker.
pub trait DBTraceCodeUnitsView: Send + Sync {}

/// Placeholder for `ghidra.trace.database.listing.DBTraceDataView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. Same reasoning as [`DBTraceCodeUnitsView`]: only ever
/// stored and returned opaquely (via `data()`), so this is a bare marker.
pub trait DBTraceDataView: Send + Sync {}

/// Placeholder for `ghidra.trace.database.listing.DBTraceInstructionsView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. `DBTraceCodeSpace.invalidateCache()` is the only place that
/// calls a member on this field (`instructions.invalidateCache()`), so only that member is
/// stubbed.
pub trait DBTraceInstructionsView: Send + Sync {
    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.invalidateCache()`, called from
    /// `DBTraceCodeSpace.invalidateCache()`.
    fn invalidate_cache(&self);
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceDefinedDataView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. Same reasoning as [`DBTraceInstructionsView`]: only
/// `definedData.invalidateCache()` is called from `DBTraceCodeSpace.invalidateCache()`.
pub trait DBTraceDefinedDataView: Send + Sync {
    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.invalidateCache()`, called from
    /// `DBTraceCodeSpace.invalidateCache()`.
    fn invalidate_cache(&self);
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceUndefinedDataView`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. Same reasoning as [`DBTraceInstructionsView`]: only
/// `undefinedData.invalidateCache()` is called from `DBTraceCodeSpace.invalidateCache()`.
pub trait DBTraceUndefinedDataView: Send + Sync {
    /// Mirrors `AbstractBaseDBTraceCodeUnitsView.invalidateCache()`, called from
    /// `DBTraceCodeSpace.invalidateCache()`.
    fn invalidate_cache(&self);
}

/// Placeholder for `ghidra.trace.database.guest.DBTraceGuestPlatform`, referenced by
/// [`DBTraceCodeSpace`](crate::trace::database::listing::db_trace_code_space::DBTraceCodeSpace)
/// before the real port is available. `DBTraceCodeSpace.clearPlatform(...)` only ever compares
/// this type for reference equality (`instruction.platform != guest`) and passes it through
/// opaquely; no members are needed yet.
pub trait DBTraceGuestPlatform: Send + Sync {}

/// Placeholder for `ghidra.trace.database.DBTraceUtils`, referenced by
/// [`AbstractBaseDBTraceCodeUnitsMemoryView`](crate::trace::database::listing::abstract_base_db_trace_code_units_memory_view::AbstractBaseDBTraceCodeUnitsMemoryView)
/// before the real port is available. That (large, static-method-only) utility class is mirrored
/// here, like [`AddressCollectors`](crate::program::model::address::address_collectors::AddressCollectors),
/// as a unit struct with associated functions rather than a `&self`-taking trait, since none of
/// its methods are instance methods in the original. Only the one static method the memory view
/// needs is ported, with a real (not stubbed-out) body: both `AddressFactory::get_address_set`
/// and `AddressFactory::get_address_set_range` it composes are already-ported real APIs.
pub struct DBTraceUtils;

impl DBTraceUtils {
    /// Mirrors `DBTraceUtils.getAddressSet(AddressFactory, Address, boolean)`: the sub-range of
    /// `factory`'s full address set from `start` to the end of its space (`forward`) or from the
    /// beginning of its space to `start` (`!forward`).
    pub fn get_address_set(factory: &dyn AddressFactory, start: &Address, forward: bool) -> AddressSet {
        let all = factory.get_address_set();
        if forward {
            match all.max_address() {
                Some(max) => factory.get_address_set_range(start, &max),
                None => AddressSet::new(),
            }
        } else {
            match all.min_address() {
                Some(min) => factory.get_address_set_range(&min, start),
                None => AddressSet::new(),
            }
        }
    }
}


/// Placeholder for `ghidra.trace.database.listing.AbstractBaseDBTraceDefinedUnitsView`,
/// referenced by
/// [`DBTraceDefinedUnitsView`](crate::trace::database::listing::db_trace_defined_units_view::DBTraceDefinedUnitsView)
/// before the real port is available. The real Java class is a large abstract base (caching,
/// spatial-map queries, generic in `T extends AbstractDBTraceCodeUnit<T>`) that backs one "part"
/// (e.g. instructions, or defined data) of a composed view; `DBTraceDefinedUnitsView` only ever
/// calls three of its members -- on each part, to aggregate across all parts -- so only those are
/// stubbed here, with the same signatures as the overridden
/// [`TraceBaseCodeUnitsView`]/[`TraceBaseDefinedUnitsView`](crate::trace::model::listing::trace_base_defined_units_view::TraceBaseDefinedUnitsView)
/// methods they implement.
pub trait AbstractBaseDBTraceDefinedUnitsView: Send + Sync {
    /// Mirrors `AbstractBaseDBTraceDefinedUnitsView.coversRange(Lifespan, AddressRange)`.
    fn covers_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Mirrors `AbstractBaseDBTraceDefinedUnitsView.intersectsRange(Lifespan, AddressRange)`.
    fn intersects_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Mirrors the abstract `clear(Lifespan, AddressRange, boolean, TaskMonitor)` this part
    /// implements (declared on `TraceBaseDefinedUnitsView`).
    fn clear(
        &mut self,
        span: Lifespan,
        range: &AddressRange,
        clear_context: bool,
        monitor: &dyn crate::util::task::TaskMonitor,
    ) -> Result<(), crate::util::exception::CancelledException>;
}

/// Placeholder for `ghidra.trace.database.listing.DBTraceDefinedDataAdapter`, referenced (as a
/// supertrait) by
/// [`DBTraceData`](crate::trace::database::listing::db_trace_data::DBTraceData) before the real
/// port is available. Mirrors the Java interface's `extends DBTraceDataAdapter` (already ported)
/// plus the two members it adds beyond that supertrait's abstract surface: the abstract
/// `doGetComponentCache()` (a lazily-populated per-instance cache of
/// [`AbstractDBTraceDataComponent`](crate::trace::database::listing::abstract_db_trace_data_component::AbstractDBTraceDataComponent)s
/// that has no natural default body without access to instance storage) and the
/// `StringBuilder`-taking `getPathName(StringBuilder, boolean)` overload (ported as
/// `append_path_name`, taking the builder by mutable reference; distinct from the no-arg
/// `Data::get_path_name` this interface also inherits). The interface's remaining default
/// methods (`isDefined`, `getNumComponents`, `getComponent`, `getComponentAt`,
/// `getComponentContaining`, `getComponentsContaining`, `getPrimitiveAt`, `getComponent(int[])`,
/// and the covariantly-narrowed abstract `getRoot()`/`getParent()`) are either pure covariant
/// narrowings of already-inherited `Data` members or business logic layered over them (see
/// [`TraceData`](crate::trace::model::listing::trace_data::TraceData)'s docs for why Rust cannot
/// re-declare covariant overrides), so none are reproduced here.
pub trait DBTraceDefinedDataAdapter:
    crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter
{
    /// Mirrors the abstract `doGetComponentCache()`.
    fn do_get_component_cache(
        &self,
    ) -> Vec<Box<dyn crate::trace::database::listing::abstract_db_trace_data_component::AbstractDBTraceDataComponent>>;

    /// Mirrors the abstract `getPathName(StringBuilder, boolean)`, appending to `builder` in
    /// place of returning a new `StringBuilder`.
    fn append_path_name(&self, builder: &mut String, include_root_symbol: bool);
}

/// Placeholder for `ghidra.trace.database.address.DBTraceOverlaySpaceAdapter`, referenced by
/// [`AbstractDBTraceSymbol`](crate::trace::database::symbol::abstract_db_trace_symbol::AbstractDBTraceSymbol)
/// before the real port is available. That trait's `getOverlaySpaceAdapter()` (mirroring the
/// single-method `DecodesAddresses` interface it implements) only ever passes this type around
/// opaquely; no members are needed yet.
///
/// Grown to add the three overlay-address-space management methods
/// [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)'s
/// `create_overlay_address_space`/`get_or_create_overlay_address_space`/
/// `delete_overlay_address_space` defaults delegate straight through to (the `overlayAdapter`
/// field DBTraceMemoryManager's Java constructor is handed). All three default to panicking,
/// matching this module's other grown-but-not-yet-implemented placeholders (see
/// [`TracePlatform::get_trace`]'s docs for the same reasoning), so the existing marker
/// (`impl DBTraceOverlaySpaceAdapter for T {}`) implementor keeps compiling unchanged.
pub trait DBTraceOverlaySpaceAdapter: Send + Sync {
    /// Create a new address space with the given name based on `base`. Mirrors
    /// `createOverlayAddressSpace(String, AddressSpace)`.
    fn create_overlay_address_space(
        &self,
        _name: &str,
        _base: &Arc<AddressSpace>,
    ) -> Result<Arc<AddressSpace>, DuplicateNameException> {
        unimplemented!("DBTraceOverlaySpaceAdapter::create_overlay_address_space placeholder not overridden")
    }

    /// Get or create an overlay address space over `base`. Mirrors
    /// `getOrCreateOverlayAddressSpace(String, AddressSpace)`.
    fn get_or_create_overlay_address_space(
        &self,
        _name: &str,
        _base: &Arc<AddressSpace>,
    ) -> Option<Arc<AddressSpace>> {
        unimplemented!("DBTraceOverlaySpaceAdapter::get_or_create_overlay_address_space placeholder not overridden")
    }

    /// Delete the named overlay address space. Mirrors `deleteOverlayAddressSpace(String)`.
    fn delete_overlay_address_space(&self, _name: &str) {
        unimplemented!("DBTraceOverlaySpaceAdapter::delete_overlay_address_space placeholder not overridden")
    }
}

/// Placeholder for `ghidra.trace.database.program.DBTraceProgramView`, referenced by
/// [`AbstractDBTraceSymbol`](crate::trace::database::symbol::abstract_db_trace_symbol::AbstractDBTraceSymbol)
/// before the real port is available. That trait's `getProgram()` only ever passes this type
/// around opaquely; no members are needed yet.
pub trait DBTraceProgramView: Send + Sync {}

/// Placeholder for `ghidra.trace.database.symbol.DBTraceSymbolManager`, referenced by
/// [`DBTraceNamespaceSymbol`](crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol)
/// and
/// [`AbstractDBTraceSymbolSingleTypeViewBase`](crate::trace::database::symbol::abstract_db_trace_symbol_single_type_view::AbstractDBTraceSymbolSingleTypeViewBase)
/// before the real port is available. The Java class has ~20 members; only `getGlobalNamespace()`
/// (needed by `DBTraceNamespaceSymbol::checkCircular`), the `lock` field's `readLock()` (needed
/// by `AbstractDBTraceSymbolSingleTypeViewBase::get_children`/`get_children_named`), and
/// `assertIsMine(Namespace)` (same two callers) are modeled here.
pub trait DBTraceSymbolManager: Send + Sync {
    /// Mirrors `getGlobalNamespace()`.
    fn get_global_namespace(
        &self,
    ) -> std::sync::Arc<
        dyn crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol,
    >;

    /// Mirrors the `lock` field's `readLock()`, following the same convention as
    /// [`DBTraceCodeManager::read_lock`].
    fn read_lock(&self) -> &dyn Lock;

    /// Mirrors `assertIsMine(Namespace)`: confirms `ns` belongs to this manager's trace, or
    /// panics (`IllegalArgumentException` in Java) otherwise, returning the manager's own
    /// `DBTraceNamespaceSymbol` view of it.
    fn assert_is_mine(
        &self,
        ns: &dyn Namespace,
    ) -> std::sync::Arc<
        dyn crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol,
    >;
}

/// Placeholder for `ghidra.trace.database.memory.DBTraceMemorySpace`, referenced (as the
/// per-address-space delegate `M` of its
/// [`DBTraceDelegatingManager`](crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager))
/// by
/// [`DBTraceMemoryManager`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager)
/// before the real port is available.
///
/// The real Java class implements the full `InternalTraceMemoryOperations` surface (register
/// overloads and all) plus DB-tree bookkeeping (`checkStateMapIntegrity`, `paint`, `getDepth`,
/// ...). `DBTraceMemoryManager` only ever calls this trimmed set of members on it -- the
/// non-register `TraceMemoryOperations` primitives it delegates each per-space, plain-address
/// call to -- so only those are stubbed here, `&self`-receiver throughout since the manager's
/// `delegateXxx` helpers hand out this type by value (`Arc<dyn DBTraceMemorySpace>`), not by
/// exclusive reference.
pub trait DBTraceMemorySpace: Send + Sync {
    /// Mirrors `setState(long, AddressRange, TraceMemoryState)`.
    fn set_state(&self, snap: i64, range: &AddressRange, state: TraceMemoryState);

    /// Mirrors `getState(long, Address)`.
    fn get_state(&self, snap: i64, address: &Address) -> TraceMemoryState;

    /// Mirrors `getViewState(long, Address)`.
    fn get_view_state(&self, snap: i64, address: &Address) -> (i64, TraceMemoryState);

    /// Mirrors `getMostRecentStateEntry(long, Address)`.
    fn get_most_recent_state_entry(
        &self,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors `getViewMostRecentStateEntry(long, Address)`.
    fn get_view_most_recent_state_entry(
        &self,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors `getViewMostRecentStateEntry(long, AddressRange, Predicate<TraceMemoryState>)`.
    fn get_view_most_recent_state_entry_where(
        &self,
        snap: i64,
        range: &AddressRange,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors the two-argument `getAddressesWithState(long, Predicate<TraceMemoryState>)`.
    /// (The three-argument `getAddressesWithState(Lifespan, AddressSetView,
    /// Predicate<TraceMemoryState>)` and the lifespan-only two-argument overload are not modeled
    /// here; see
    /// [`DBTraceMemoryManager::get_addresses_with_state_in`](crate::trace::database::memory::db_trace_memory_manager::DBTraceMemoryManager::get_addresses_with_state_in)'s
    /// docs.)
    fn get_addresses_with_state(
        &self,
        snap: i64,
        predicate: &dyn Fn(TraceMemoryState) -> bool,
    ) -> Box<dyn AddressSetView>;

    /// Mirrors `getStates(long, AddressRange)`.
    fn get_states(
        &self,
        snap: i64,
        range: &AddressRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors `getMostRecentStates(TraceAddressSnapRange)`.
    fn get_most_recent_states(
        &self,
        within: &dyn TraceAddressSnapRange,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, TraceMemoryState)>;

    /// Mirrors `putBytes(long, Address, ByteBuffer)`.
    fn put_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Mirrors `getBytes(long, Address, ByteBuffer)`.
    fn get_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Mirrors `getViewBytes(long, Address, ByteBuffer)`.
    fn get_view_bytes(&self, snap: i64, start: &Address, buf: &mut [u8]) -> i32;

    /// Mirrors `removeBytes(long, Address, int)`.
    fn remove_bytes(&self, snap: i64, start: &Address, len: i32);

    /// Mirrors `findBytes(long, AddressRange, ByteBuffer, ByteBuffer, boolean, TaskMonitor)`.
    /// `mask` is `None` for Java's `null` ("match all bytes exactly").
    fn find_bytes(
        &self,
        snap: i64,
        range: &AddressRange,
        data: &[u8],
        mask: Option<&[u8]>,
        forward: bool,
        monitor: &dyn TaskMonitor,
    ) -> Option<Address>;

    /// Mirrors `getBufferAt(long, Address, ByteOrder)`. `big_endian` stands in for the Java
    /// `ByteOrder`, the same simplification
    /// [`MemBuffer::is_big_endian`](crate::program::model::mem::MemBuffer::is_big_endian) already
    /// established for byte-order parameters.
    fn get_buffer_at(&self, snap: i64, start: &Address, big_endian: bool) -> Box<dyn MemBuffer>;

    /// Mirrors `getSnapOfMostRecentChangeToBlock(long, Address)`.
    fn get_snap_of_most_recent_change_to_block(&self, snap: i64, address: &Address) -> Option<i64>;

    /// Mirrors `pack()`.
    fn pack(&self);
}

/// Placeholder for `ghidra.trace.database.context.DBTraceRegisterContextSpace`, referenced (as the
/// per-address-space delegate `M` of its
/// [`DBTraceDelegatingManager`](crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager))
/// by
/// [`DBTraceRegisterContextManager`](crate::trace::database::context::db_trace_register_context_manager::DBTraceRegisterContextManager)
/// before the real port is available.
///
/// The real Java class implements the model-level `TraceRegisterContextSpace` interface (already
/// ported as [`TraceRegisterContextSpace`](crate::trace::model::context::trace_register_context_space::TraceRegisterContextSpace),
/// whose mutating members take `&mut self`) plus DB-record-backed bookkeeping. This manager hands
/// the delegate out by value as `Arc<dyn DBTraceRegisterContextSpace>` (matching
/// [`DBTraceMemorySpace`]'s established convention for `Arc`-shared, lock-synchronized DB
/// delegates), so its members are `&self`-receiver throughout rather than reusing the `&mut self`
/// model trait. `get_value_with_default` is modeled on the concrete class's package-private
/// `getValueWithDefault(Language, Register, long, Address hostAddress, Address langAddress)`
/// helper (already resolved to a host address), which is what
/// `DBTraceRegisterContextManager.getValueWithDefault` actually calls -- not the model-level,
/// platform-taking overload -- since the manager itself is the one that maps guest to host and
/// resolves the language via `TracePlatform`.
pub trait DBTraceRegisterContextSpace: Send + Sync {
    /// The address space this register-context space is bound to. Mirrors
    /// `DBTraceRegisterContextSpace.getAddressSpace()`.
    fn get_address_space(&self) -> Arc<AddressSpace>;

    /// Mirrors `setValue(Language, RegisterValue, Lifespan, AddressRange)`.
    fn set_value(
        &self,
        language: &dyn Language,
        value: &dyn ProgramRegisterValue,
        lifespan: Lifespan,
        range: &AddressRange,
    );

    /// Mirrors `removeValue(Language, Register, Lifespan, AddressRange)`.
    fn remove_value(
        &self,
        language: &dyn Language,
        register: &Register,
        span: Lifespan,
        range: &AddressRange,
    );

    /// Mirrors `getValue(Language, Register, long, Address)`.
    fn get_value(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<Box<dyn ProgramRegisterValue>>;

    /// Mirrors `getEntry(Language, Register, long, Address)`.
    fn get_entry(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn ProgramRegisterValue>)>;

    /// Mirrors the package-private `getValueWithDefault(Language, Register, long, Address
    /// hostAddress, Address langAddress)` helper, called by
    /// `DBTraceRegisterContextManager.getValueWithDefault(TracePlatform, Register, long, Address)`
    /// after it has already mapped the guest address to `host_address` and resolved `language`
    /// from the platform.
    fn get_value_with_default(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        host_address: &Address,
        guest_address: &Address,
    ) -> Option<Box<dyn ProgramRegisterValue>>;

    /// Mirrors `getRegisterValueAddressRanges(Language, Register, long, AddressRange)`.
    fn get_register_value_address_ranges_within(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        within: &AddressRange,
    ) -> Box<dyn AddressSetView>;

    /// Mirrors the all-space overload `getRegisterValueAddressRanges(Language, Register, long)`.
    fn get_register_value_address_ranges(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
    ) -> Box<dyn AddressSetView>;

    /// Mirrors `hasRegisterValueInAddressRange(Language, Register, long, AddressRange)`.
    fn has_register_value_in_address_range(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        within: &AddressRange,
    ) -> bool;

    /// Mirrors the all-space overload `hasRegisterValue(Language, Register, long)`.
    fn has_register_value(&self, language: &dyn Language, register: &Register, snap: i64) -> bool;

    /// Mirrors `clear(Lifespan, AddressRange)`.
    fn clear(&self, span: Lifespan, range: &AddressRange);
}

/// Placeholder for the unported Java type `StepKind`, referenced by `Stepper`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait StepKind: Send + Sync {
    fn tick(&self, thread: &dyn ErasedPcodeThread);
    fn skip(&self, thread: &dyn ErasedPcodeThread);
}

/// Placeholder constructors for the unported Java types `PatchStep`, `SkipStep`, and `TickStep`,
/// referenced only by [`Step`]'s static factory methods (`Step::parse`, `Step::nop`).
///
/// Those Java methods are `static` (no receiver), so the usual "stub trait with instance
/// methods" shape doesn't fit: there is no instance to call `parse` on until one of these three
/// concrete types exists. Free functions mirroring the Java statics are the minimal placeholder
/// instead. Each panics until the real port lands; nothing in this crate calls them yet except
/// `Step::nop`/`Step::parse`, which are themselves not called by any ported code.
pub fn patch_step_parse(thread_key: i64, step_spec: &str) -> Box<dyn Step> {
    unimplemented!("PatchStep is not yet ported: parse({thread_key}, {step_spec:?})")
}

/// See [`patch_step_parse`]. Mirrors `SkipStep.parse(long, String, TimeRadix)`.
pub fn skip_step_parse(thread_key: i64, step_spec: &str, radix: &dyn TimeRadix) -> Box<dyn Step> {
    let _ = radix;
    unimplemented!("SkipStep is not yet ported: parse({thread_key}, {step_spec:?})")
}

/// See [`patch_step_parse`]. Mirrors `TickStep.parse(long, String, TimeRadix)`.
pub fn tick_step_parse(thread_key: i64, step_spec: &str, radix: &dyn TimeRadix) -> Box<dyn Step> {
    let _ = radix;
    unimplemented!("TickStep is not yet ported: parse({thread_key}, {step_spec:?})")
}

/// See [`patch_step_parse`]. Mirrors `new TickStep(long, long)`, used by `Step::nop`.
pub fn tick_step_new(thread_key: i64, tick_count: i64) -> Box<dyn Step> {
    unimplemented!("TickStep is not yet ported: new({thread_key}, {tick_count})")
}

