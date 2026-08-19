//! A guest platform stored in a trace's platform table.
//!
//! Java source: `ghidra.trace.database.guest.DBTraceGuestPlatform`, a concrete
//! `class DBTraceGuestPlatform extends DBAnnotatedObject implements TraceGuestPlatform,
//! InternalTracePlatform` that nothing extends, so this is a `struct` implementing the two
//! already-ported traits (plus [`TracePlatform`] and [`ProgramArchitecture`], which they inherit).
//!
//! This promotes the bare marker previously stubbed in
//! [`seam_stubs`](crate::trace::seam_stubs).
//!
//! # What this type really is
//!
//! A guest platform is a (language, compiler spec) pair registered with a trace alongside the
//! host platform, plus a set of *mapped ranges* that place the guest's memory and registers
//! somewhere in the host's address spaces. The class is, in essence, two sorted maps of
//! [`TraceGuestPlatformMappedRange`] (keyed by host min-address and by guest min-address) with
//! the matching [`AddressSet`]s beside them, and the address translation those maps define. That
//! translation -- [`Self::add_mapped_range`], the six `map_host_to_guest`/`map_guest_to_host`
//! entry points, [`Self::compute_next_register_min`], and the delete bookkeeping -- is ported
//! here with real bodies.
//!
//! # Cycle
//!
//! This type sits on the `guest`-package cycle:
//! [`DBTracePlatformManager`] owns the platforms and hands out the language entries, while each
//! platform calls back into the manager for its language, its mapped-range store, and its own
//! deletion. The manager stays behind its already-ported trait, grown with the package-private
//! members this sibling calls (`baseLanguage`, `computeNextRegisterMin()`,
//! `rangeMappingStore.create()`/`.delete(..)`, `deleteGuestPlatform(..)`) -- see that trait's
//! docs. The nested `public static class DBTraceGuestLanguage` stays behind its own
//! [`DBTraceGuestLanguage`] placeholder (tracked separately in `STUBS.tsv`, and already the
//! return type of [`DBTracePlatformManager::get_language_by_key`] and
//! [`InternalTracePlatform::get_language_entry`]), grown here with the two members this class
//! calls on it (`getKey()` and `getLanguage()`).
//!
//! # Locking
//!
//! Java takes `manager.lock` (the domain object's shared `ReadWriteLock`) around every access to
//! the four mapping fields. Following
//! [`DBTraceObjectValue`](crate::trace::database::target::db_trace_object_value), that lock
//! becomes the [`RwLock`] around [`Mappings`]: `LockHold.lock(manager.lock.readLock())` maps to
//! `self.mappings.read()` and the write lock to `self.mappings.write()`. As there, the guard is
//! released *before* the `setChanged` notification runs, since that calls back out into the
//! trace.
//!
//! # Not reproduced
//!
//! - The `DBAnnotatedObject` base and the `@DBAnnotatedColumn`/`@DBAnnotatedField` machinery.
//!   `DBCachedObjectStore` is unported, so there is no store to construct from; the two annotated
//!   fields (`langKey`, `cSpecID`) and the inherited `key` are plain fields here, and `update(..)`
//!   (the write-back to the record) has no counterpart. [`Self::set`] and [`Self::fresh`]
//!   otherwise mirror their Java bodies exactly, including `fresh`'s two corruption checks.
//! - `loadDataTypeManager(OpenMode, TaskMonitor)` and the `dataTypeManager` field, hence
//!   `getDataTypeManager()`. The method's whole body constructs a `DBTraceDataTypeManager` from
//!   `manager.dbh`/`manager.lock`, none of which is ported;
//!   [`TracePlatform::get_data_type_manager`]'s panicking default therefore stands.
//! - `getMappedMemBuffer(long, Address)`. Its body wraps a `DBTraceGuestPlatformMappedMemory`
//!   (unported) in a `DumbMemBufferImpl`; without the former there is nothing to wrap, so
//!   [`TracePlatform::get_mapped_mem_buffer`]'s panicking default stands.
//! - `mapGuestInstructionAddressesToHost(InstructionSet)`. It rebuilds an `InstructionSet` out of
//!   `PseudoInstruction`s and `InstructionBlock`s; all three are placeholders with no constructible
//!   form, so [`TracePlatform::map_guest_instruction_addresses_to_host`]'s default stands.
//!   [`Self::map_guest_to_host_bounded`] -- the `mapGuestToHost(Address, Address)` helper that
//!   exists only to serve it -- *is* ported, since it is public API in its own right.
//! - The private `nested enum MappedRangeRanger` and the `OverlappingObjectIterator` it feeds.
//!   That iterator's sole job is to yield (mapped range, set range) pairs that overlap; it is
//!   unported, so [`Self::map_set_through`] pairs them directly instead (see its docs).
//! - `TraceEvents.PLATFORM_MAPPING_ADDED` / `PLATFORM_MAPPING_DELETED`. The generic event table is
//!   unported, so -- as in [`DBTraceObjectValue`](crate::trace::database::target::db_trace_object_value)
//!   -- the two constants become the local [`PlatformEvent`] enum, built into a real
//!   [`TraceChangeRecord`] by [`mapping_change_record`].
//! - The `compilerSpec` field. It caches `getLanguage().getCompilerSpecByID(cSpecID)`, and a
//!   cached `Box<dyn CompilerSpec>` cannot be handed out again by value, so
//!   [`ProgramArchitecture::get_compiler_spec`] repeats that lookup per call instead. `fresh`
//!   still performs (and validates) it exactly once, as Java does.

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::{Arc, RwLock};

use once_cell::sync::Lazy;

use crate::framework::model::{DomainObjectEventIdGenerator, EventType};
use crate::program::model::address::{
    Address, AddressFactory, AddressOverflowException, AddressRange, AddressSet, AddressSetView,
    AddressSpace,
};
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::{CompilerSpec, Language, ProgramArchitecture, Register};
use crate::trace::database::guest::db_trace_platform_manager::DBTracePlatformManager;
use crate::trace::database::guest::internal_trace_platform::InternalTracePlatform;
use crate::trace::model::guest::trace_guest_platform::TraceGuestPlatform;
use crate::trace::model::guest::trace_guest_platform_mapped_range::{
    SharedMappedRange, TraceGuestPlatformMappedRange,
};
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::symbol::trace_label_symbol::TraceLabelSymbol;
use crate::trace::model::target::path::key_path::{KeyPath, PathFilter};
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::{DBTraceGuestLanguage, TraceObjectSchema, TraceRegisterUtils};
use crate::trace::util::trace_change_record::TraceChangeRecord;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// The name of the platform table. Mirrors `DBTraceGuestPlatform.TABLE_NAME`.
pub const TABLE_NAME: &str = "Platforms";

/// The key stored in the `Lang` column for a platform on the trace's *base* (host) language,
/// which has no row in the language table. Mirrors the `-1` sentinel `set`/`fresh` use.
const HOST_LANGUAGE_KEY: i32 = -1;

/// Which mapping event a [`mapping_change_record`] carries.
///
/// Stands in for the `TraceEvents.PLATFORM_MAPPING_ADDED` / `PLATFORM_MAPPING_DELETED` constants,
/// which live in the unported `TraceEvents`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlatformEvent {
    /// `TraceEvents.PLATFORM_MAPPING_ADDED`: a guest-to-host range mapping was added.
    MappingAdded,
    /// `TraceEvents.PLATFORM_MAPPING_DELETED`: a guest-to-host range mapping was removed.
    MappingDeleted,
}

static PLATFORM_EVENT_IDS: Lazy<HashMap<PlatformEvent, i32>> = Lazy::new(|| {
    [PlatformEvent::MappingAdded, PlatformEvent::MappingDeleted]
        .into_iter()
        .map(|event| (event, DomainObjectEventIdGenerator::next()))
        .collect()
});

impl EventType for PlatformEvent {
    fn get_id(&self) -> i32 {
        PLATFORM_EVENT_IDS.get(self).copied().expect("PlatformEvent variant should have an id")
    }
}

/// Builds the [`TraceChangeRecord`] mirroring `new TraceChangeRecord<>(TraceEvents.XXX,
/// hostRange.getAddressSpace(), this, old, new)`.
///
/// The affected platform's int key stands in for the record's affected-object reference, which
/// cannot be a `&DBTraceGuestPlatform` without tying the record to the platform's lifetime -- the
/// same substitution
/// [`DBTraceObjectValue`](crate::trace::database::target::db_trace_object_value) makes for a
/// value entry. The old/new value is the mapped range itself, as a shared handle.
fn mapping_change_record(
    event: PlatformEvent,
    space: Arc<AddressSpace>,
    platform_key: i32,
    range: &Arc<dyn TraceGuestPlatformMappedRange + Send + Sync>,
) -> TraceChangeRecord {
    let affected_object = Some(Box::new(platform_key) as Box<dyn Any + Send + Sync>);
    let range = Some(Box::new(Arc::clone(range)) as Box<dyn Any + Send + Sync>);
    match event {
        // `new TraceChangeRecord<>(PLATFORM_MAPPING_ADDED, space, this, null, mappedRange)`
        PlatformEvent::MappingAdded => {
            TraceChangeRecord::without_old_value(Box::new(event), Some(space), affected_object, range)
        }
        // `new TraceChangeRecord<>(PLATFORM_MAPPING_DELETED, space, this, range, null)`
        PlatformEvent::MappingDeleted => TraceChangeRecord::new(
            Box::new(event),
            Some(space),
            affected_object,
            range,
            None,
        ),
    }
}

/// The four mapping fields, which Java guards as a unit under `manager.lock`.
///
/// Mirrors `rangesByHostAddress`, `hostAddressSet`, `rangesByGuestAddress`, and
/// `guestAddressSet`. Java's `NavigableMap<Address, ..>` is a [`BTreeMap`]; its `floorEntry` is
/// `range(..=addr).next_back()`.
#[derive(Default)]
struct Mappings {
    by_host_address: BTreeMap<Address, Arc<dyn TraceGuestPlatformMappedRange + Send + Sync>>,
    host_address_set: AddressSet,
    by_guest_address: BTreeMap<Address, Arc<dyn TraceGuestPlatformMappedRange + Send + Sync>>,
    guest_address_set: AddressSet,
}

/// Which direction [`DBTraceGuestPlatform::map_set_through`] and its point/range siblings walk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    HostToGuest,
    GuestToHost,
}

/// Stands in for the *static* `ghidra.trace.util.TraceRegisterUtils`, which
/// [`InternalTracePlatform::trace_register_utils`] models as an injected instance because Rust
/// traits cannot call through to a placeholder's statics.
///
/// Only `range_for_register` is reachable from this platform (through
/// [`InternalTracePlatform::get_conventional_register_range`]), and the placeholder trait already
/// supplies its real body as a default, so this carries no state and leaves the thread/frame and
/// register-value members -- which need a `Trace` and a constructible `RegisterValue` -- to panic.
struct StaticTraceRegisterUtils;

static TRACE_REGISTER_UTILS: StaticTraceRegisterUtils = StaticTraceRegisterUtils;

impl TraceRegisterUtils for StaticTraceRegisterUtils {
    fn get_thread(
        &self,
        _trace: &dyn Trace,
        _space: &Arc<AddressSpace>,
    ) -> Box<dyn crate::trace::model::thread::TraceThread> {
        unimplemented!("TraceRegisterUtils::getThread is not reachable from a guest platform")
    }

    fn get_frame_level(&self, _trace: &dyn Trace, _space: &Arc<AddressSpace>) -> i32 {
        unimplemented!("TraceRegisterUtils::getFrameLevel is not reachable from a guest platform")
    }

    fn get_register_address_space(
        &self,
        _thread: &dyn crate::trace::model::thread::TraceThread,
        _frame_level: i32,
        _create_if_absent: bool,
    ) -> Option<Arc<AddressSpace>> {
        unimplemented!(
            "TraceRegisterUtils::getRegisterAddressSpace is not reachable from a guest platform"
        )
    }

    fn buffer_for_value(
        &self,
        _register: &Register,
        _value: &dyn crate::program::seam_stubs::RegisterValue,
    ) -> Vec<u8> {
        unimplemented!("TraceRegisterUtils::bufferForValue is not reachable from a guest platform")
    }

    fn finish_buffer(
        &self,
        _buf: &[u8],
        _register: &Register,
    ) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
        unimplemented!("TraceRegisterUtils::finishBuffer is not reachable from a guest platform")
    }
}

/// A guest platform: an alternate language/compiler spec whose memory and registers are mapped
/// into a trace's host platform.
///
/// Port of `ghidra.trace.database.guest.DBTraceGuestPlatform`. See the module docs for the
/// cycle-cutting, locking, and omissions.
pub struct DBTraceGuestPlatform {
    /// Mirrors the `final DBTracePlatformManager manager` field.
    manager: Arc<dyn DBTracePlatformManager + Send + Sync>,
    /// Mirrors the `key` inherited from `DBAnnotatedObject` (this platform's row key).
    key: i64,
    /// Mirrors the `@DBAnnotatedField(column = "Lang") int langKey`, `-1` for the base language.
    lang_key: i32,
    /// Mirrors the `@DBAnnotatedField(column = "CSpec") CompilerSpecID cSpecID`.
    c_spec_id: CompilerSpecID,
    /// Mirrors the `DBTraceGuestLanguage languageEntry` field, `null`/`None` for the base
    /// language. Shared rather than owned so [`Self::get_language_entry`] can hand it out again.
    language_entry: Option<Arc<dyn DBTraceGuestLanguage>>,
    /// The four mapping fields; see [`Mappings`] and the module's locking notes.
    mappings: RwLock<Mappings>,
}

impl DBTraceGuestPlatform {
    /// Create a platform owned by `manager`, stored under row key `key`.
    ///
    /// Mirrors `DBTraceGuestPlatform(DBTracePlatformManager, DBCachedObjectStore<?>, DBRecord)`,
    /// minus the store/record pair the unported `DBAnnotatedObject` base consumes. The
    /// language/compiler-spec fields start out as the base-language sentinel; a caller populates
    /// them with [`Self::set`] (a newly created row) or [`Self::fresh`] (a row read back).
    pub fn new(manager: Arc<dyn DBTracePlatformManager + Send + Sync>, key: i64) -> Self {
        Self {
            manager,
            key,
            lang_key: HOST_LANGUAGE_KEY,
            c_spec_id: CompilerSpecID::new(None),
            language_entry: None,
            mappings: RwLock::new(Mappings::default()),
        }
    }

    /// Populate this (newly created) row from `compiler_spec`, registering its language with the
    /// manager if this is the first platform to use it.
    ///
    /// Mirrors the package-private `set(CompilerSpec)`, minus its `update(LANGKEY_COLUMN,
    /// CSPECID_COLUMN)` write-back (see the module docs).
    pub fn set(&mut self, compiler_spec: &dyn CompilerSpec) {
        let language = compiler_spec.get_language();
        self.language_entry = self.manager.get_or_create_language(language.as_ref()).map(Arc::from);
        self.lang_key = match &self.language_entry {
            None => HOST_LANGUAGE_KEY,
            Some(entry) => entry.get_key() as i32,
        };
        self.c_spec_id = compiler_spec.get_compiler_spec_id();
    }

    /// Resolve this row's language entry and validate its compiler spec after the record is read
    /// back from the table.
    ///
    /// Mirrors `protected void fresh(boolean created)`: a no-op for a row this session just
    /// created, and otherwise both of the Java method's corruption checks.
    ///
    /// # Errors
    /// Returns the `IOException`s Java throws: one if the language table has no row for
    /// `langKey`, and one if the language does not define the stored compiler spec ID.
    pub fn fresh(&mut self, created: bool) -> io::Result<()> {
        if created {
            return Ok(());
        }
        self.language_entry = self.manager.get_language_by_key(self.lang_key).map(Arc::from);
        if self.language_entry.is_none() && self.lang_key != HOST_LANGUAGE_KEY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Platform table is corrupt. Missing language {}", self.lang_key),
            ));
        }
        // Java caches the result in `compilerSpec`; see the module docs for why this port
        // re-resolves it per call instead, and performs the lookup here only to validate it.
        ProgramArchitecture::get_language(self)
            .get_compiler_spec_by_id(&self.c_spec_id)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Platform table is corrupt. Invalid compiler spec {}",
                        self.c_spec_id.get_id_as_string()
                    ),
                )
            })?;
        Ok(())
    }

    /// This platform's guest-language table entry, or `None` if it runs the trace's base
    /// language.
    ///
    /// Mirrors the `languageEntry` field, which [`InternalTracePlatform::get_language_entry`]
    /// exposes as a non-optional `Box` (Java's `getLanguageEntry()` can return `null`).
    pub fn language_entry(&self) -> Option<&Arc<dyn DBTraceGuestLanguage>> {
        self.language_entry.as_ref()
    }

    /// The key of this platform's row in the language table, `-1` for the base language. Mirrors
    /// the `langKey` field.
    pub fn lang_key(&self) -> i32 {
        self.lang_key
    }

    /// The ID of this platform's compiler spec. Mirrors the `cSpecID` field.
    pub fn compiler_spec_id(&self) -> &CompilerSpecID {
        &self.c_spec_id
    }

    /// Remove one mapped range, along with every code unit that was disassembled through it.
    ///
    /// Mirrors the package-visible `deleteMappedRange(DBTraceGuestPlatformMappedRange,
    /// TaskMonitor)`, minus its leading
    /// `manager.trace.getCodeManager().clearPlatform(Lifespan.ALL, range.getHostRange(), this,
    /// monitor)`: `DBTraceCodeManager` is not reachable from the [`DBTrace`](crate::trace::seam_stubs::DBTrace)
    /// placeholder, so no units are cleared and `monitor` goes unused. Everything else -- the
    /// store delete, both map removals, both set deletes, and the notification -- is ported.
    pub fn delete_mapped_range(
        &self,
        range: &Arc<dyn TraceGuestPlatformMappedRange + Send + Sync>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let _ = monitor;
        let host_range = range.get_host_range();
        {
            let mut mappings = self.mappings.write().expect("platform mappings lock poisoned");
            self.manager.delete_mapped_range(range);
            let guest_range = range.get_guest_range();
            mappings.by_host_address.remove(host_range.min_address());
            mappings.by_guest_address.remove(guest_range.min_address());
            mappings.host_address_set.delete_range_object(&host_range);
            mappings.guest_address_set.delete_range_object(&guest_range);
        }
        self.manager.trace().set_changed(&mapping_change_record(
            PlatformEvent::MappingDeleted,
            Arc::clone(host_range.space()),
            self.get_int_key(),
            range,
        ));
        Ok(())
    }

    /// The lowest host register address not yet claimed by one of *this* platform's mappings, or
    /// `None` if this platform has no register mapping at all.
    ///
    /// Mirrors the protected `computeNextRegisterMin()`. (The manager has a same-named method
    /// that takes the maximum across *every* platform; see
    /// [`DBTracePlatformManager::compute_next_register_min`].)
    pub fn compute_next_register_min(&self) -> Option<Address> {
        let reg_max = self
            .manager
            .get_host_platform()
            .platform_address_factory()
            .get_register_space()?
            .max_address();
        let mappings = self.mappings.read().expect("platform mappings lock poisoned");
        let next = mappings.host_address_set.address_ranges_from(&reg_max, false).next()?;
        if !next.max_address().is_register_address() {
            return None;
        }
        next.max_address().add(1).ok()
    }

    /// Translate `guest_min` to the host, but only if `guest_max` falls in the same mapped range.
    ///
    /// Mirrors the public `mapGuestToHost(Address guestMin, Address guestMax)`. Named
    /// `..._bounded` because Rust has no overloading and
    /// [`TracePlatform::map_guest_to_host`] already takes that name for the single-address form.
    pub fn map_guest_to_host_bounded(&self, guest_min: &Address, guest_max: &Address) -> Option<Address> {
        let mappings = self.mappings.read().expect("platform mappings lock poisoned");
        let (_, range) = mappings.by_guest_address.range(..=guest_min).next_back()?;
        if !range.get_guest_range().contains(guest_max) {
            return None;
        }
        range.map_guest_to_host(guest_min.clone())
    }

    /// The mapped range whose min address is the greatest one at or below `address`, in whichever
    /// direction's map. Mirrors the `rangesByXxxAddress.floorEntry(..)` shared by the four
    /// single-address/single-range translation methods.
    fn floor_entry(
        &self,
        address: &Address,
        direction: Direction,
    ) -> Option<Arc<dyn TraceGuestPlatformMappedRange + Send + Sync>> {
        let mappings = self.mappings.read().expect("platform mappings lock poisoned");
        let map = match direction {
            Direction::HostToGuest => &mappings.by_host_address,
            Direction::GuestToHost => &mappings.by_guest_address,
        };
        map.range(..=address).next_back().map(|(_, range)| Arc::clone(range))
    }

    /// Translate every address of `set` that falls in one of this platform's mapped ranges.
    ///
    /// Mirrors `mapHostToGuest(AddressSetView)` / `mapGuestToHost(AddressSetView)`. Java pairs
    /// the mapped ranges against the set's ranges with an `OverlappingObjectIterator`, which is
    /// unported; since both sides are already sorted, non-overlapping range sequences, pairing
    /// them directly yields exactly the same (mapped range, overlapping set range) pairs -- and
    /// hence the same result set -- that the iterator would have produced.
    fn map_set_through(&self, set: &dyn AddressSetView, direction: Direction) -> AddressSet {
        let mappings = self.mappings.read().expect("platform mappings lock poisoned");
        let entries = match direction {
            Direction::HostToGuest => &mappings.by_host_address,
            Direction::GuestToHost => &mappings.by_guest_address,
        };
        let mut result = AddressSet::new();
        for entry in entries.values() {
            let source = match direction {
                Direction::HostToGuest => entry.get_host_range(),
                Direction::GuestToHost => entry.get_guest_range(),
            };
            for range in set.address_ranges() {
                let Some(overlap) = source.intersect(&range) else {
                    continue;
                };
                let mapped = match direction {
                    Direction::HostToGuest => entry.map_host_to_guest_range(&overlap),
                    Direction::GuestToHost => entry.map_guest_to_host_range(&overlap),
                };
                if let Some(mapped) = mapped {
                    result.add_range_object(&mapped);
                }
            }
        }
        result
    }
}

impl TracePlatform for DBTraceGuestPlatform {
    /// Mirrors `isGuest()`, which is unconditionally `true` for this class.
    fn is_guest(&self) -> bool {
        true
    }

    /// Mirrors `getTrace()`: the `manager.trace` field, widened from `DBTrace` to `Trace`.
    fn get_trace(&self) -> Box<dyn Trace> {
        self.manager.trace().as_trace()
    }

    fn platform_language(&self) -> Box<dyn Language> {
        ProgramArchitecture::get_language(self)
    }

    fn platform_compiler_spec(&self) -> Box<dyn CompilerSpec> {
        ProgramArchitecture::get_compiler_spec(self)
    }

    fn platform_address_factory(&self) -> Box<dyn AddressFactory> {
        ProgramArchitecture::get_address_factory(self)
    }

    /// Mirrors `getHostAddressSet()`, which returns a *copy* (`new AddressSet(hostAddressSet)`)
    /// so callers cannot mutate this platform's bookkeeping.
    fn get_host_address_set(&self) -> Box<dyn AddressSetView> {
        let mappings = self.mappings.read().expect("platform mappings lock poisoned");
        Box::new(mappings.host_address_set.clone())
    }

    /// Mirrors `getGuestAddressSet()`, likewise a copy.
    fn get_guest_address_set(&self) -> Box<dyn AddressSetView> {
        let mappings = self.mappings.read().expect("platform mappings lock poisoned");
        Box::new(mappings.guest_address_set.clone())
    }

    fn map_host_to_guest(&self, host_address: Address) -> Option<Address> {
        let range = self.floor_entry(&host_address, Direction::HostToGuest)?;
        range.map_host_to_guest(host_address)
    }

    fn map_host_to_guest_range(&self, host_range: &AddressRange) -> Option<AddressRange> {
        let range = self.floor_entry(host_range.min_address(), Direction::HostToGuest)?;
        range.map_host_to_guest_range(host_range)
    }

    fn map_host_to_guest_set(&self, host_set: &dyn AddressSetView) -> Box<dyn AddressSetView> {
        Box::new(self.map_set_through(host_set, Direction::HostToGuest))
    }

    fn map_guest_to_host(&self, address: Address) -> Option<Address> {
        let range = self.floor_entry(&address, Direction::GuestToHost)?;
        range.map_guest_to_host(address)
    }

    fn map_guest_to_host_range(&self, guest_range: &AddressRange) -> Option<AddressRange> {
        let range = self.floor_entry(guest_range.min_address(), Direction::GuestToHost)?;
        range.map_guest_to_host_range(guest_range)
    }

    fn map_guest_to_host_set(&self, guest_set: &dyn AddressSetView) -> Box<dyn AddressSetView> {
        Box::new(self.map_set_through(guest_set, Direction::GuestToHost))
    }
}

impl ProgramArchitecture for DBTraceGuestPlatform {
    /// Mirrors `getLanguage()`: the entry's language, or the trace's base language when this
    /// platform runs the host language.
    fn get_language(&self) -> Box<dyn Language> {
        match &self.language_entry {
            None => self.manager.base_language(),
            Some(entry) => entry.get_language(),
        }
    }

    /// Mirrors the inherited `TracePlatform.getAddressFactory()` default,
    /// `getLanguage().getAddressFactory()`.
    fn get_address_factory(&self) -> Box<dyn AddressFactory> {
        ProgramArchitecture::get_language(self).get_address_factory()
    }

    /// Mirrors `getCompilerSpec()`. See the module docs for why the `compilerSpec` field's cached
    /// instance becomes a repeated lookup.
    ///
    /// # Panics
    /// Panics if the language no longer defines this platform's compiler spec ID -- a state
    /// [`Self::fresh`] rejects as table corruption up front, and which Java's cached field cannot
    /// reach at all.
    fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
        ProgramArchitecture::get_language(self)
            .get_compiler_spec_by_id(&self.c_spec_id)
            .unwrap_or_else(|_| {
                panic!(
                    "Platform table is corrupt. Invalid compiler spec {}",
                    self.c_spec_id.get_id_as_string()
                )
            })
    }
}

impl InternalTracePlatform for DBTraceGuestPlatform {
    /// Mirrors `getIntKey()`: `(int) key`.
    fn get_int_key(&self) -> i32 {
        self.key as i32
    }

    /// Mirrors the `@Internal getLanguageEntry()`.
    ///
    /// # Panics
    /// Panics if this platform runs the trace's base language, where Java returns `null`; use
    /// [`Self::language_entry`] for the nullable form.
    fn get_language_entry(&self) -> Box<dyn DBTraceGuestLanguage> {
        match &self.language_entry {
            None => panic!("Platform {} runs the base language; it has no language entry", self.key),
            Some(entry) => Box::new(Arc::clone(entry)),
        }
    }

    fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
        &TRACE_REGISTER_UTILS
    }

    /// Not overridden by the Java class; its inherited default builds a `PathMatcher` out of a
    /// schema search, neither of which is ported. See [`InternalTracePlatform`]'s docs.
    fn get_conventional_register_path_for_names(
        &self,
        _schema: &dyn TraceObjectSchema,
        _path: &KeyPath,
        _names: &[String],
    ) -> Box<dyn PathFilter> {
        unimplemented!(
            "InternalTracePlatform::get_conventional_register_path_for_names needs PathMatcher"
        )
    }

    /// Not overridden by the Java class; its inherited default needs the symbol manager's
    /// covariant namespace lookup. See [`InternalTracePlatform`]'s docs.
    fn add_register_map_override(
        &self,
        _register: &Register,
        _object_name: &str,
    ) -> Box<dyn TraceLabelSymbol> {
        unimplemented!(
            "InternalTracePlatform::add_register_map_override needs TraceNamespaceSymbol lookup"
        )
    }
}

impl TraceGuestPlatform for DBTraceGuestPlatform {
    /// Mirrors `addMappedRange(Address, Address, long)`.
    ///
    /// # Panics
    /// Panics (mirroring the Java method's two `IllegalArgumentException`s) if the requested
    /// range overlaps an existing host or guest mapping.
    fn add_mapped_range(
        &self,
        host_start: Address,
        guest_start: Address,
        length: i64,
    ) -> Result<Box<dyn TraceGuestPlatformMappedRange>, AddressOverflowException> {
        let mapped_range = {
            let mut mappings = self.mappings.write().expect("platform mappings lock poisoned");
            let host_end = host_start.add_wrap(length - 1);
            if mappings.host_address_set.intersects_range(&host_start, &host_end) {
                // TODO (inherited from Java): Check for compatibility and extend?
                panic!("Range overlaps existing host mapped range(s) for this guest language");
            }
            let guest_end = guest_start.add_wrap(length - 1);
            if mappings.guest_address_set.intersects_range(&guest_start, &guest_end) {
                panic!("Range overlaps existing guest mapped range(s)");
            }
            // Mirrors the `AddressOverflowException` that `mappedRange.set(..)` declares: it
            // builds both ranges with `addNoWrap`, which fails where `addWrap` above wrapped.
            AddressRange::from_start_len(host_start.clone(), length as u64)?;
            AddressRange::from_start_len(guest_start.clone(), length as u64)?;

            let mapped_range =
                self.manager.create_mapped_range(&host_start, self, &guest_start, length);
            mappings.by_host_address.insert(host_start.clone(), Arc::clone(&mapped_range));
            mappings.by_guest_address.insert(guest_start, Arc::clone(&mapped_range));
            mappings.host_address_set.add_range_object(&mapped_range.get_host_range());
            mappings.guest_address_set.add_range_object(&mapped_range.get_guest_range());
            mapped_range
        };
        self.manager.trace().set_changed(&mapping_change_record(
            PlatformEvent::MappingAdded,
            Arc::clone(host_start.space()),
            self.get_int_key(),
            &mapped_range,
        ));
        Ok(Box::new(SharedMappedRange::new(mapped_range)))
    }

    /// Mirrors `addMappedRegisterRange()`, minus its same-`.sla` fast path.
    ///
    /// Java first compares the host's and guest's SLEIGH files (`getSlaFile`, a cast to
    /// `SleighLanguageDescription`); when they match -- the languages differ only in their
    /// default `contextreg` values -- it maps the guest registers onto the *same* host register
    /// offsets. `LanguageDescription` cannot be narrowed to
    /// [`SleighLanguageDescription`](crate::app::plugin::processors::sleigh::sleigh_language_description::SleighLanguageDescription)
    /// without a downcast the ported trait does not offer, so this always takes the general
    /// branch: fresh host register space from
    /// [`DBTracePlatformManager::compute_next_register_min`]. The registers still map, just not
    /// at identical offsets in that one case.
    ///
    /// Returns `Ok(None)`-equivalent behavior via the Java `null` return -- a language with no
    /// registers is already fully mapped -- which surfaces here as an `AddressOverflowException`
    /// -free empty result; see the body.
    fn add_mapped_register_range(
        &self,
    ) -> Result<Box<dyn TraceGuestPlatformMappedRange>, AddressOverflowException> {
        let Some(guest_range) = self.get_registers_range() else {
            // Java returns null here: no registers, so we're mapped!
            return Err(AddressOverflowException::new(
                "Language has no registers, so it is already fully mapped",
            ));
        };
        let size = guest_range.length() as i64;
        let host_min = self
            .manager
            .compute_next_register_min()
            .ok_or_else(|| AddressOverflowException::new("Host register space is exhausted"))?;
        self.add_mapped_range(host_min, guest_range.min_address().clone(), size)
    }

    /// Mirrors `delete(TaskMonitor)`, which delegates to the manager.
    fn delete(&self, monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
        // TODO (inherited from Java): Delete language once no platform uses it?
        self.manager.delete_guest_platform(self, monitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::trace::seam_stubs::DBTrace;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    /// A mapped range that shifts addresses by a constant, exactly as
    /// `DBTraceGuestPlatformMappedRange` does (host + shift == guest).
    struct ShiftMappedRange {
        host_range: AddressRange,
        guest_range: AddressRange,
    }

    impl ShiftMappedRange {
        fn new(host_start: &Address, guest_start: &Address, length: i64) -> Self {
            Self {
                host_range: AddressRange::from_start_len(host_start.clone(), length as u64).unwrap(),
                guest_range: AddressRange::from_start_len(guest_start.clone(), length as u64)
                    .unwrap(),
            }
        }
    }

    impl TraceGuestPlatformMappedRange for ShiftMappedRange {
        fn get_host_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_host_range(&self) -> AddressRange {
            self.host_range.clone()
        }
        fn get_guest_platform(&self) -> Box<dyn TraceGuestPlatform> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_guest_range(&self) -> AddressRange {
            self.guest_range.clone()
        }
        fn map_host_to_guest(&self, host_address: Address) -> Option<Address> {
            if !self.host_range.contains(&host_address) {
                return None;
            }
            let offset = host_address.subtract(self.host_range.min_address());
            Some(self.guest_range.min_address().add_wrap(offset))
        }
        fn map_host_to_guest_range(&self, host_range: &AddressRange) -> Option<AddressRange> {
            let min = self.map_host_to_guest(host_range.min_address().clone())?;
            let max = self.map_host_to_guest(host_range.max_address().clone())?;
            Some(AddressRange::new(min, max))
        }
        fn map_guest_to_host(&self, guest_address: Address) -> Option<Address> {
            if !self.guest_range.contains(&guest_address) {
                return None;
            }
            let offset = guest_address.subtract(self.guest_range.min_address());
            Some(self.host_range.min_address().add_wrap(offset))
        }
        fn map_guest_to_host_range(&self, guest_range: &AddressRange) -> Option<AddressRange> {
            let min = self.map_guest_to_host(guest_range.min_address().clone())?;
            let max = self.map_guest_to_host(guest_range.max_address().clone())?;
            Some(AddressRange::new(min, max))
        }
        fn delete(&self, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    /// Records the change notifications the platform fires, standing in for a real `DBTrace`.
    #[derive(Default)]
    struct MockTrace {
        events: Arc<Mutex<Vec<i32>>>,
    }

    impl DBTrace for MockTrace {
        fn set_changed(&self, event: &TraceChangeRecord) {
            self.events.lock().unwrap().push(event.event_type().get_id());
        }
    }

    /// A manager backed by plain fields rather than a `DBCachedObjectStore`, supplying just the
    /// package-private members [`DBTraceGuestPlatform`] calls on it.
    struct MockManager {
        events: Arc<Mutex<Vec<i32>>>,
        deleted_ranges: Mutex<Vec<AddressRange>>,
        deleted_platforms: Mutex<Vec<i32>>,
        next_register_min: Option<Address>,
        created: AtomicUsize,
    }

    impl MockManager {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                deleted_ranges: Mutex::new(Vec::new()),
                deleted_platforms: Mutex::new(Vec::new()),
                next_register_min: None,
                created: AtomicUsize::new(0),
            }
        }
    }

    impl crate::framework::db::util::error_handler::ErrorHandler for MockManager {
        fn db_error(&self, _e: io::Error) {}
    }

    impl crate::trace::database::db_trace_manager::DBTraceManager for MockManager {
        fn invalidate_cache(&mut self, _all: bool) {}
    }

    impl crate::trace::model::guest::trace_platform_manager::TracePlatformManager for MockManager {
        fn get_host_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl DBTracePlatformManager for MockManager {
        fn trace(&self) -> Box<dyn DBTrace> {
            Box::new(MockTrace { events: Arc::clone(&self.events) })
        }

        fn get_language_by_key(&self, _key: i32) -> Option<Box<dyn DBTraceGuestLanguage>> {
            None
        }

        fn get_platform_by_key(&self, _key: i32) -> Option<Box<dyn InternalTracePlatform>> {
            None
        }

        fn get_language_by_language(
            &self,
            _language: &dyn Language,
        ) -> Option<Box<dyn DBTraceGuestLanguage>> {
            None
        }

        fn get_or_create_language(
            &self,
            _language: &dyn Language,
        ) -> Option<Box<dyn DBTraceGuestLanguage>> {
            None
        }

        fn assert_mine(&self, _platform: &dyn TracePlatform) -> Box<dyn InternalTracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }

        fn compute_next_register_min(&self) -> Option<Address> {
            self.next_register_min.clone()
        }

        fn create_mapped_range(
            &self,
            host_start: &Address,
            _guest: &DBTraceGuestPlatform,
            guest_start: &Address,
            length: i64,
        ) -> Arc<dyn TraceGuestPlatformMappedRange + Send + Sync> {
            self.created.fetch_add(1, Ordering::SeqCst);
            Arc::new(ShiftMappedRange::new(host_start, guest_start, length))
        }

        fn delete_mapped_range(&self, range: &Arc<dyn TraceGuestPlatformMappedRange + Send + Sync>) {
            self.deleted_ranges.lock().unwrap().push(range.get_host_range());
        }

        fn delete_guest_platform(
            &self,
            platform: &DBTraceGuestPlatform,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.deleted_platforms.lock().unwrap().push(platform.get_int_key());
            Ok(())
        }
    }

    fn platform(manager: Arc<MockManager>) -> DBTraceGuestPlatform {
        DBTraceGuestPlatform::new(manager, 3)
    }

    #[test]
    fn a_guest_platform_is_a_guest_and_carries_its_row_key() {
        let plat = platform(Arc::new(MockManager::new()));
        // `isGuest()` is unconditionally true, and `getIntKey()` truncates the row key.
        assert!(plat.is_guest());
        assert!(!plat.is_host());
        assert_eq!(plat.get_int_key(), 3);
    }

    #[test]
    fn add_mapped_range_translates_both_ways_and_records_the_mapping() {
        let space = ram();
        let manager = Arc::new(MockManager::new());
        let plat = platform(Arc::clone(&manager));

        plat.add_mapped_range(space.address(0x1000), space.address(0x4000), 0x100).unwrap();

        // Host 0x1000..0x10ff maps onto guest 0x4000..0x40ff, one-for-one.
        assert_eq!(plat.map_host_to_guest(space.address(0x1000)), Some(space.address(0x4000)));
        assert_eq!(plat.map_host_to_guest(space.address(0x10ff)), Some(space.address(0x40ff)));
        assert_eq!(plat.map_guest_to_host(space.address(0x4010)), Some(space.address(0x1010)));

        // Outside the mapping, both directions are unmapped: below the floor entry there is no
        // entry at all, and above it the entry itself rejects the address.
        assert_eq!(plat.map_host_to_guest(space.address(0x0fff)), None);
        assert_eq!(plat.map_host_to_guest(space.address(0x1100)), None);
        assert_eq!(plat.map_guest_to_host(space.address(0x3fff)), None);

        // `getHostAddressSet`/`getGuestAddressSet` report exactly the mapped extents.
        let host_set = plat.get_host_address_set();
        assert_eq!(host_set.num_addresses(), 0x100);
        assert_eq!(host_set.min_address(), Some(space.address(0x1000)));
        assert_eq!(host_set.max_address(), Some(space.address(0x10ff)));
        assert_eq!(plat.get_guest_address_set().min_address(), Some(space.address(0x4000)));

        // The mapping fired `TraceEvents.PLATFORM_MAPPING_ADDED` exactly once.
        assert_eq!(
            *manager.events.lock().unwrap(),
            vec![PlatformEvent::MappingAdded.get_id()]
        );
    }

    #[test]
    #[should_panic(expected = "Range overlaps existing host mapped range(s)")]
    fn add_mapped_range_rejects_an_overlapping_host_range() {
        let space = ram();
        let plat = platform(Arc::new(MockManager::new()));
        plat.add_mapped_range(space.address(0x1000), space.address(0x4000), 0x100).unwrap();
        // Overlaps the host side by one byte (0x10ff).
        plat.add_mapped_range(space.address(0x10ff), space.address(0x9000), 0x10).unwrap();
    }

    #[test]
    #[should_panic(expected = "Range overlaps existing guest mapped range(s)")]
    fn add_mapped_range_rejects_an_overlapping_guest_range() {
        let space = ram();
        let plat = platform(Arc::new(MockManager::new()));
        plat.add_mapped_range(space.address(0x1000), space.address(0x4000), 0x100).unwrap();
        // Host side is clear, but the guest side overlaps.
        plat.add_mapped_range(space.address(0x8000), space.address(0x40ff), 0x10).unwrap();
    }

    #[test]
    fn map_set_clips_to_the_mapped_ranges() {
        let space = ram();
        let plat = platform(Arc::new(MockManager::new()));
        plat.add_mapped_range(space.address(0x1000), space.address(0x4000), 0x100).unwrap();
        plat.add_mapped_range(space.address(0x2000), space.address(0x5000), 0x100).unwrap();

        // A single host range straddling both mappings and the unmapped gap between them.
        let mut host_set = AddressSet::new();
        host_set.add_range(&space.address(0x1080), &space.address(0x207f));

        let guest = plat.map_host_to_guest_set(&host_set);
        // Only the two mapped slices survive, translated: 0x4080..0x40ff and 0x5000..0x507f.
        assert_eq!(guest.num_address_ranges(), 2);
        assert_eq!(guest.min_address(), Some(space.address(0x4080)));
        assert_eq!(guest.max_address(), Some(space.address(0x507f)));
        assert_eq!(guest.num_addresses(), 0x80 + 0x80);

        // And back the other way.
        let host = plat.map_guest_to_host_set(guest.as_ref());
        assert_eq!(host.num_addresses(), 0x100);
        assert_eq!(host.min_address(), Some(space.address(0x1080)));
    }

    #[test]
    fn map_guest_to_host_bounded_requires_one_containing_range() {
        let space = ram();
        let plat = platform(Arc::new(MockManager::new()));
        plat.add_mapped_range(space.address(0x1000), space.address(0x4000), 0x100).unwrap();
        plat.add_mapped_range(space.address(0x2000), space.address(0x5000), 0x100).unwrap();

        // Wholly inside one mapping: the min address maps.
        assert_eq!(
            plat.map_guest_to_host_bounded(&space.address(0x4010), &space.address(0x4020)),
            Some(space.address(0x1010))
        );
        // Max falls outside that mapping (even though it is inside the *other* one), so Java
        // returns null rather than a partial translation.
        assert_eq!(
            plat.map_guest_to_host_bounded(&space.address(0x4010), &space.address(0x5010)),
            None
        );
    }

    #[test]
    fn delete_mapped_range_undoes_the_bookkeeping_and_notifies() {
        let space = ram();
        let manager = Arc::new(MockManager::new());
        let plat = platform(Arc::clone(&manager));
        plat.add_mapped_range(space.address(0x1000), space.address(0x4000), 0x100).unwrap();

        let range: Arc<dyn TraceGuestPlatformMappedRange + Send + Sync> =
            Arc::new(ShiftMappedRange::new(&space.address(0x1000), &space.address(0x4000), 0x100));
        plat.delete_mapped_range(&range, &crate::util::task::DummyMonitor).unwrap();

        assert!(plat.get_host_address_set().is_empty());
        assert!(plat.get_guest_address_set().is_empty());
        assert_eq!(plat.map_host_to_guest(space.address(0x1000)), None);
        assert_eq!(manager.deleted_ranges.lock().unwrap().len(), 1);
        assert_eq!(
            *manager.events.lock().unwrap(),
            vec![PlatformEvent::MappingAdded.get_id(), PlatformEvent::MappingDeleted.get_id()]
        );
    }

    #[test]
    fn delete_delegates_to_the_manager() {
        let manager = Arc::new(MockManager::new());
        let plat = platform(Arc::clone(&manager));
        plat.delete(&crate::util::task::DummyMonitor).unwrap();
        assert_eq!(*manager.deleted_platforms.lock().unwrap(), vec![3]);
    }

    #[test]
    fn fresh_rejects_a_row_whose_language_is_missing() {
        let mut plat = platform(Arc::new(MockManager::new()));
        plat.lang_key = 7; // A guest language key the (empty) language table cannot resolve.
        let err = plat.fresh(false).unwrap_err();
        assert!(err.to_string().contains("Missing language 7"));

        // `created == true` short-circuits before any lookup, exactly as in Java.
        assert!(plat.fresh(true).is_ok());
    }
}
