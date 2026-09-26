//! Port of `ghidra.trace.util.TraceEvents`.
//!
//! Java declares `TraceEvents` as a constant-interface (91 `public static final` fields, no
//! abstract methods of its own) whose values are literally the enum constants nested inside
//! [`TraceEvent`](crate::trace::util::trace_event::TraceEvent)'s Java source (e.g.
//! `TraceObjectEvent.OBJECT_CREATED`, `TraceBookmarkEvent.BOOKMARK_ADDED`, ...) -- 53 distinct
//! tiny nested enum types, one `<T, U>` pairing apiece, exposed here unqualified for convenience.
//! `TraceEvent`'s own port already established that every consumer erases `<T, U>` to `dyn Any`
//! (see its doc comment), so nothing here needs 53 separate Rust types to preserve compile-time
//! `T`/`U` safety Java never actually used past this file. Instead, mirroring
//! [`ProgramEvent`](crate::program::util::program_event::ProgramEvent)'s identical situation (one
//! flat Java-enum-like interface's worth of ids), all 91 constants become variants of one flat
//! [`TraceEventKind`] enum, each assigned a unique id via [`DomainObjectEventIdGenerator`] exactly
//! once (Java assigns one per nested-enum constant at class-init time; this does the same via a
//! lazily-initialized table, so id assignment order matches declaration order here).
//!
//! Per the shape rule for this file (a Java constant-interface with no type of its own), no
//! `struct`/`enum TraceEvents` is emitted -- only the `pub const` bindings below, one per Java
//! field, so callers can `use` this module and reference `OBJECT_CREATED` etc. unqualified exactly
//! as a Java class that `implements TraceEvents` would.

use once_cell::sync::Lazy;
use std::collections::HashMap;

use crate::framework::model::{DomainObjectEventIdGenerator, EventType};
use crate::program::model::listing::comment_type::CommentType;
use crate::trace::util::trace_event::TraceEvent;

/// The concrete trace-event identities backing every `pub const` below.
///
/// Port of the 53 nested enum types declared inside `ghidra.trace.util.TraceEvent` (see the
/// module doc comment for why they collapse into one flat enum here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceEventKind {
    ObjectCreated,
    ObjectLifeChanged,
    ObjectDeleted,
    ValueCreated,
    ValueLifespanChanged,
    ValueDeleted,
    BookmarkTypeAdded,
    BookmarkAdded,
    BookmarkChanged,
    BookmarkLifespanChanged,
    BookmarkDeleted,
    BreakpointAdded,
    BreakpointChanged,
    BreakpointLifespanChanged,
    BreakpointDeleted,
    TypeCategoryAdded,
    TypeCategoryMoved,
    TypeCategoryRenamed,
    TypeCategoryDeleted,
    CodeAdded,
    CodeLifespanChanged,
    CodeRemoved,
    CodeFragmentChanged,
    CodeDataTypeReplaced,
    CodeDataSettingsChanged,
    PlateCommentChanged,
    PreCommentChanged,
    PostCommentChanged,
    EolCommentChanged,
    RepeatableCommentChanged,
    CompositeDataAdded,
    CompositeDataLifespanChanged,
    CompositeDataRemoved,
    DataTypeAdded,
    DataTypeReplaced,
    DataTypeChanged,
    DataTypeMoved,
    DataTypeRenamed,
    DataTypeDeleted,
    InstructionFlowOverrideChanged,
    InstructionFallThroughOverrideChanged,
    InstructionLengthOverrideChanged,
    BytesChanged,
    RegionAdded,
    RegionChanged,
    RegionLifespanChanged,
    RegionDeleted,
    OverlayAdded,
    OverlayDeleted,
    BytesStateChanged,
    ModuleAdded,
    ModuleChanged,
    ModuleLifespanChanged,
    ModuleDeleted,
    SectionAdded,
    SectionChanged,
    SectionDeleted,
    ReferenceAdded,
    ReferenceLifespanChanged,
    ReferencePrimaryChanged,
    ReferenceDeleted,
    StackAdded,
    StackChanged,
    StackDeleted,
    MappingAdded,
    MappingDeleted,
    SourceTypeArchiveAdded,
    SourceTypeArchiveChanged,
    SourceTypeArchiveDeleted,
    SymbolAdded,
    SymbolSourceChanged,
    SymbolPrimaryChanged,
    SymbolRenamed,
    SymbolParentChanged,
    SymbolAssociationAdded,
    SymbolAssociationRemoved,
    SymbolAddressChanged,
    SymbolLifespanChanged,
    SymbolChanged,
    SymbolDeleted,
    ThreadAdded,
    ThreadChanged,
    ThreadLifespanChanged,
    ThreadDeleted,
    SnapshotAdded,
    SnapshotChanged,
    SnapshotDeleted,
    PlatformAdded,
    PlatformDeleted,
    PlatformMappingAdded,
    PlatformMappingDeleted,
}

/// All 91 variants, in the same order Java's class-init would assign ids to the corresponding
/// nested-enum constants (declaration order in `TraceEvents.java`).
const ALL_KINDS: [TraceEventKind; 91] = [
    TraceEventKind::ObjectCreated,
    TraceEventKind::ObjectLifeChanged,
    TraceEventKind::ObjectDeleted,
    TraceEventKind::ValueCreated,
    TraceEventKind::ValueLifespanChanged,
    TraceEventKind::ValueDeleted,
    TraceEventKind::BookmarkTypeAdded,
    TraceEventKind::BookmarkAdded,
    TraceEventKind::BookmarkChanged,
    TraceEventKind::BookmarkLifespanChanged,
    TraceEventKind::BookmarkDeleted,
    TraceEventKind::BreakpointAdded,
    TraceEventKind::BreakpointChanged,
    TraceEventKind::BreakpointLifespanChanged,
    TraceEventKind::BreakpointDeleted,
    TraceEventKind::TypeCategoryAdded,
    TraceEventKind::TypeCategoryMoved,
    TraceEventKind::TypeCategoryRenamed,
    TraceEventKind::TypeCategoryDeleted,
    TraceEventKind::CodeAdded,
    TraceEventKind::CodeLifespanChanged,
    TraceEventKind::CodeRemoved,
    TraceEventKind::CodeFragmentChanged,
    TraceEventKind::CodeDataTypeReplaced,
    TraceEventKind::CodeDataSettingsChanged,
    TraceEventKind::PlateCommentChanged,
    TraceEventKind::PreCommentChanged,
    TraceEventKind::PostCommentChanged,
    TraceEventKind::EolCommentChanged,
    TraceEventKind::RepeatableCommentChanged,
    TraceEventKind::CompositeDataAdded,
    TraceEventKind::CompositeDataLifespanChanged,
    TraceEventKind::CompositeDataRemoved,
    TraceEventKind::DataTypeAdded,
    TraceEventKind::DataTypeReplaced,
    TraceEventKind::DataTypeChanged,
    TraceEventKind::DataTypeMoved,
    TraceEventKind::DataTypeRenamed,
    TraceEventKind::DataTypeDeleted,
    TraceEventKind::InstructionFlowOverrideChanged,
    TraceEventKind::InstructionFallThroughOverrideChanged,
    TraceEventKind::InstructionLengthOverrideChanged,
    TraceEventKind::BytesChanged,
    TraceEventKind::RegionAdded,
    TraceEventKind::RegionChanged,
    TraceEventKind::RegionLifespanChanged,
    TraceEventKind::RegionDeleted,
    TraceEventKind::OverlayAdded,
    TraceEventKind::OverlayDeleted,
    TraceEventKind::BytesStateChanged,
    TraceEventKind::ModuleAdded,
    TraceEventKind::ModuleChanged,
    TraceEventKind::ModuleLifespanChanged,
    TraceEventKind::ModuleDeleted,
    TraceEventKind::SectionAdded,
    TraceEventKind::SectionChanged,
    TraceEventKind::SectionDeleted,
    TraceEventKind::ReferenceAdded,
    TraceEventKind::ReferenceLifespanChanged,
    TraceEventKind::ReferencePrimaryChanged,
    TraceEventKind::ReferenceDeleted,
    TraceEventKind::StackAdded,
    TraceEventKind::StackChanged,
    TraceEventKind::StackDeleted,
    TraceEventKind::MappingAdded,
    TraceEventKind::MappingDeleted,
    TraceEventKind::SourceTypeArchiveAdded,
    TraceEventKind::SourceTypeArchiveChanged,
    TraceEventKind::SourceTypeArchiveDeleted,
    TraceEventKind::SymbolAdded,
    TraceEventKind::SymbolSourceChanged,
    TraceEventKind::SymbolPrimaryChanged,
    TraceEventKind::SymbolRenamed,
    TraceEventKind::SymbolParentChanged,
    TraceEventKind::SymbolAssociationAdded,
    TraceEventKind::SymbolAssociationRemoved,
    TraceEventKind::SymbolAddressChanged,
    TraceEventKind::SymbolLifespanChanged,
    TraceEventKind::SymbolChanged,
    TraceEventKind::SymbolDeleted,
    TraceEventKind::ThreadAdded,
    TraceEventKind::ThreadChanged,
    TraceEventKind::ThreadLifespanChanged,
    TraceEventKind::ThreadDeleted,
    TraceEventKind::SnapshotAdded,
    TraceEventKind::SnapshotChanged,
    TraceEventKind::SnapshotDeleted,
    TraceEventKind::PlatformAdded,
    TraceEventKind::PlatformDeleted,
    TraceEventKind::PlatformMappingAdded,
    TraceEventKind::PlatformMappingDeleted,
];

static EVENT_IDS: Lazy<HashMap<TraceEventKind, i32>> = Lazy::new(|| {
    let mut map = HashMap::with_capacity(ALL_KINDS.len());
    for kind in ALL_KINDS.iter() {
        map.insert(*kind, DomainObjectEventIdGenerator::next());
    }
    map
});

impl EventType for TraceEventKind {
    fn get_id(&self) -> i32 {
        EVENT_IDS
            .get(self)
            .copied()
            .expect("TraceEventKind variant should have an id")
    }
}

impl TraceEvent for TraceEventKind {}

/// A [`TraceObject`](crate::trace::model::target::TraceObject) was created, but not yet inserted.
pub const OBJECT_CREATED: TraceEventKind = TraceEventKind::ObjectCreated;
/// An object's life changed: one of its canonical parents was created, deleted, or had its
/// lifespan change.
pub const OBJECT_LIFE_CHANGED: TraceEventKind = TraceEventKind::ObjectLifeChanged;
/// A `TraceObject` was deleted.
pub const OBJECT_DELETED: TraceEventKind = TraceEventKind::ObjectDeleted;
/// A `TraceObjectValue` was created.
pub const VALUE_CREATED: TraceEventKind = TraceEventKind::ValueCreated;
/// A `TraceObjectValue`'s lifespan changed.
pub const VALUE_LIFESPAN_CHANGED: TraceEventKind = TraceEventKind::ValueLifespanChanged;
/// A `TraceObjectValue` was deleted.
pub const VALUE_DELETED: TraceEventKind = TraceEventKind::ValueDeleted;
/// A `TraceBookmarkType` was added.
pub const BOOKMARK_TYPE_ADDED: TraceEventKind = TraceEventKind::BookmarkTypeAdded;
/// A `TraceBookmark` was added.
pub const BOOKMARK_ADDED: TraceEventKind = TraceEventKind::BookmarkAdded;
/// A `TraceBookmark` was changed.
pub const BOOKMARK_CHANGED: TraceEventKind = TraceEventKind::BookmarkChanged;
/// A `TraceBookmark`'s lifespan was changed.
pub const BOOKMARK_LIFESPAN_CHANGED: TraceEventKind = TraceEventKind::BookmarkLifespanChanged;
/// A `TraceBookmark` was deleted.
pub const BOOKMARK_DELETED: TraceEventKind = TraceEventKind::BookmarkDeleted;
/// A `TraceBreakpointLocation` was added.
pub const BREAKPOINT_ADDED: TraceEventKind = TraceEventKind::BreakpointAdded;
/// A `TraceBreakpointLocation` was changed.
pub const BREAKPOINT_CHANGED: TraceEventKind = TraceEventKind::BreakpointChanged;
/// A `TraceBreakpointLocation`'s lifespan was changed.
pub const BREAKPOINT_LIFESPAN_CHANGED: TraceEventKind = TraceEventKind::BreakpointLifespanChanged;
/// A `TraceBreakpointLocation` was deleted.
pub const BREAKPOINT_DELETED: TraceEventKind = TraceEventKind::BreakpointDeleted;
/// A `Category` was added. The `long` is the category id.
pub const TYPE_CATEGORY_ADDED: TraceEventKind = TraceEventKind::TypeCategoryAdded;
/// A `Category` was moved. The `long` is the category id.
pub const TYPE_CATEGORY_MOVED: TraceEventKind = TraceEventKind::TypeCategoryMoved;
/// A `Category` was renamed. The `long` is the category id.
pub const TYPE_CATEGORY_RENAMED: TraceEventKind = TraceEventKind::TypeCategoryRenamed;
/// A `Category` was deleted. The `long` is the category id.
pub const TYPE_CATEGORY_DELETED: TraceEventKind = TraceEventKind::TypeCategoryDeleted;
/// One or more `TraceCodeUnit`s were added. May be a single unit or a whole block; only the
/// first unit in the block is given in the record.
pub const CODE_ADDED: TraceEventKind = TraceEventKind::CodeAdded;
/// A `TraceCodeUnit`'s lifespan changed.
pub const CODE_LIFESPAN_CHANGED: TraceEventKind = TraceEventKind::CodeLifespanChanged;
/// One or more `TraceCodeUnit`s were removed. May be a single unit or a whole block; only the
/// first unit in the block is given, if it is given at all.
pub const CODE_REMOVED: TraceEventKind = TraceEventKind::CodeRemoved;
/// A `ProgramFragment` was changed.
pub const CODE_FRAGMENT_CHANGED: TraceEventKind = TraceEventKind::CodeFragmentChanged;
/// One or more `TraceData`'s `DataType` was replaced. The type's id is given in the record.
pub const CODE_DATA_TYPE_REPLACED: TraceEventKind = TraceEventKind::CodeDataTypeReplaced;
/// One or more `TraceData`'s `Settings` was changed.
pub const CODE_DATA_SETTINGS_CHANGED: TraceEventKind = TraceEventKind::CodeDataSettingsChanged;
/// A plate comment was changed.
pub const PLATE_COMMENT_CHANGED: TraceEventKind = TraceEventKind::PlateCommentChanged;
/// A pre comment was changed.
pub const PRE_COMMENT_CHANGED: TraceEventKind = TraceEventKind::PreCommentChanged;
/// A post comment was changed.
pub const POST_COMMENT_CHANGED: TraceEventKind = TraceEventKind::PostCommentChanged;
/// An end-of-line comment was changed.
pub const EOL_COMMENT_CHANGED: TraceEventKind = TraceEventKind::EolCommentChanged;
/// A repeatable comment was changed.
pub const REPEATABLE_COMMENT_CHANGED: TraceEventKind = TraceEventKind::RepeatableCommentChanged;
/// A `TraceData` of `Composite` type was added.
pub const COMPOSITE_DATA_ADDED: TraceEventKind = TraceEventKind::CompositeDataAdded;
/// The lifespan of a `TraceData` of `Composite` type was changed.
pub const COMPOSITE_DATA_LIFESPAN_CHANGED: TraceEventKind =
    TraceEventKind::CompositeDataLifespanChanged;
/// A `TraceData` of `Composite` type was removed.
pub const COMPOSITE_DATA_REMOVED: TraceEventKind = TraceEventKind::CompositeDataRemoved;
/// A `DataType` was added.
pub const DATA_TYPE_ADDED: TraceEventKind = TraceEventKind::DataTypeAdded;
/// A `DataType` was replaced.
pub const DATA_TYPE_REPLACED: TraceEventKind = TraceEventKind::DataTypeReplaced;
/// A `DataType` was changed.
pub const DATA_TYPE_CHANGED: TraceEventKind = TraceEventKind::DataTypeChanged;
/// A `DataType` was moved.
pub const DATA_TYPE_MOVED: TraceEventKind = TraceEventKind::DataTypeMoved;
/// A `DataType` was renamed.
pub const DATA_TYPE_RENAMED: TraceEventKind = TraceEventKind::DataTypeRenamed;
/// A `DataType` was deleted.
pub const DATA_TYPE_DELETED: TraceEventKind = TraceEventKind::DataTypeDeleted;
/// A `TraceInstruction`'s flow override was changed.
pub const INSTRUCTION_FLOW_OVERRIDE_CHANGED: TraceEventKind =
    TraceEventKind::InstructionFlowOverrideChanged;
/// A `TraceInstruction`'s fall-through override was changed.
pub const INSTRUCTION_FALL_THROUGH_OVERRIDE_CHANGED: TraceEventKind =
    TraceEventKind::InstructionFallThroughOverrideChanged;
/// A `TraceInstruction`'s length override was changed.
pub const INSTRUCTION_LENGTH_OVERRIDE_CHANGED: TraceEventKind =
    TraceEventKind::InstructionLengthOverrideChanged;
/// The trace's memory or register values were changed. Note the given byte arrays may be larger
/// than the actual change.
pub const BYTES_CHANGED: TraceEventKind = TraceEventKind::BytesChanged;
/// A `TraceMemoryRegion` was added.
pub const REGION_ADDED: TraceEventKind = TraceEventKind::RegionAdded;
/// A `TraceMemoryRegion` was changed.
pub const REGION_CHANGED: TraceEventKind = TraceEventKind::RegionChanged;
/// A `TraceMemoryRegion`'s lifespan was changed.
pub const REGION_LIFESPAN_CHANGED: TraceEventKind = TraceEventKind::RegionLifespanChanged;
/// A `TraceMemoryRegion` was deleted.
pub const REGION_DELETED: TraceEventKind = TraceEventKind::RegionDeleted;
/// An overlay `AddressSpace` was added.
pub const OVERLAY_ADDED: TraceEventKind = TraceEventKind::OverlayAdded;
/// An overlay `AddressSpace` was deleted.
pub const OVERLAY_DELETED: TraceEventKind = TraceEventKind::OverlayDeleted;
/// The cache state of memory or register values was changed.
pub const BYTES_STATE_CHANGED: TraceEventKind = TraceEventKind::BytesStateChanged;
/// A `TraceModule` was added.
pub const MODULE_ADDED: TraceEventKind = TraceEventKind::ModuleAdded;
/// A `TraceModule` was changed.
pub const MODULE_CHANGED: TraceEventKind = TraceEventKind::ModuleChanged;
/// A `TraceModule`'s lifespan was changed.
pub const MODULE_LIFESPAN_CHANGED: TraceEventKind = TraceEventKind::ModuleLifespanChanged;
/// A `TraceModule` was deleted.
pub const MODULE_DELETED: TraceEventKind = TraceEventKind::ModuleDeleted;
/// A `TraceSection` was added.
pub const SECTION_ADDED: TraceEventKind = TraceEventKind::SectionAdded;
/// A `TraceSection` was changed.
pub const SECTION_CHANGED: TraceEventKind = TraceEventKind::SectionChanged;
/// A `TraceSection` was deleted.
pub const SECTION_DELETED: TraceEventKind = TraceEventKind::SectionDeleted;
/// A `TraceReference` was added.
pub const REFERENCE_ADDED: TraceEventKind = TraceEventKind::ReferenceAdded;
/// A `TraceReference`'s lifespan was changed.
pub const REFERENCE_LIFESPAN_CHANGED: TraceEventKind = TraceEventKind::ReferenceLifespanChanged;
/// A `TraceReference` was promoted to or demoted from primary.
pub const REFERENCE_PRIMARY_CHANGED: TraceEventKind = TraceEventKind::ReferencePrimaryChanged;
/// A `TraceReference` was deleted.
pub const REFERENCE_DELETED: TraceEventKind = TraceEventKind::ReferenceDeleted;
/// A `TraceStack` was added.
pub const STACK_ADDED: TraceEventKind = TraceEventKind::StackAdded;
/// A `TraceStack` was changed. The "new value" in the record is the min snap of the change; the
/// "old value" is always 0.
pub const STACK_CHANGED: TraceEventKind = TraceEventKind::StackChanged;
/// A `TraceStack` was deleted.
pub const STACK_DELETED: TraceEventKind = TraceEventKind::StackDeleted;
/// A `TraceStaticMapping` was added.
pub const MAPPING_ADDED: TraceEventKind = TraceEventKind::MappingAdded;
/// A `TraceStaticMapping` was deleted.
pub const MAPPING_DELETED: TraceEventKind = TraceEventKind::MappingDeleted;
/// A source data type archive was added.
pub const SOURCE_TYPE_ARCHIVE_ADDED: TraceEventKind = TraceEventKind::SourceTypeArchiveAdded;
/// A source data type archive was changed.
pub const SOURCE_TYPE_ARCHIVE_CHANGED: TraceEventKind = TraceEventKind::SourceTypeArchiveChanged;
/// A source data type archive was deleted.
pub const SOURCE_TYPE_ARCHIVE_DELETED: TraceEventKind = TraceEventKind::SourceTypeArchiveDeleted;
/// A `TraceSymbol` was added.
pub const SYMBOL_ADDED: TraceEventKind = TraceEventKind::SymbolAdded;
/// A `TraceSymbol`'s source type changed.
pub const SYMBOL_SOURCE_CHANGED: TraceEventKind = TraceEventKind::SymbolSourceChanged;
/// A `TraceSymbol` was promoted to or demoted from primary.
pub const SYMBOL_PRIMARY_CHANGED: TraceEventKind = TraceEventKind::SymbolPrimaryChanged;
/// A `TraceSymbol` was renamed.
pub const SYMBOL_RENAMED: TraceEventKind = TraceEventKind::SymbolRenamed;
/// A `TraceSymbol`'s parent namespace changed.
pub const SYMBOL_PARENT_CHANGED: TraceEventKind = TraceEventKind::SymbolParentChanged;
/// A `TraceSymbol` was associated with a `TraceReference`.
pub const SYMBOL_ASSOCIATION_ADDED: TraceEventKind = TraceEventKind::SymbolAssociationAdded;
/// A `TraceSymbol` was dissociated from a `TraceReference`.
pub const SYMBOL_ASSOCIATION_REMOVED: TraceEventKind = TraceEventKind::SymbolAssociationRemoved;
/// A `TraceSymbol`'s address changed.
pub const SYMBOL_ADDRESS_CHANGED: TraceEventKind = TraceEventKind::SymbolAddressChanged;
/// A `TraceSymbol`'s lifespan changed.
pub const SYMBOL_LIFESPAN_CHANGED: TraceEventKind = TraceEventKind::SymbolLifespanChanged;
/// A `TraceSymbol` was changed in a way not captured by the other `SYMBOL_` events.
pub const SYMBOL_CHANGED: TraceEventKind = TraceEventKind::SymbolChanged;
/// A `TraceSymbol` was deleted.
pub const SYMBOL_DELETED: TraceEventKind = TraceEventKind::SymbolDeleted;
/// A `TraceThread` was added.
pub const THREAD_ADDED: TraceEventKind = TraceEventKind::ThreadAdded;
/// A `TraceThread` was changed.
pub const THREAD_CHANGED: TraceEventKind = TraceEventKind::ThreadChanged;
/// A `TraceThread`'s lifespan was changed.
pub const THREAD_LIFESPAN_CHANGED: TraceEventKind = TraceEventKind::ThreadLifespanChanged;
/// A `TraceThread` was deleted.
pub const THREAD_DELETED: TraceEventKind = TraceEventKind::ThreadDeleted;
/// A `TraceSnapshot` was added.
pub const SNAPSHOT_ADDED: TraceEventKind = TraceEventKind::SnapshotAdded;
/// A `TraceSnapshot` was changed.
pub const SNAPSHOT_CHANGED: TraceEventKind = TraceEventKind::SnapshotChanged;
/// A `TraceSnapshot` was deleted.
pub const SNAPSHOT_DELETED: TraceEventKind = TraceEventKind::SnapshotDeleted;
/// A `TraceGuestPlatform` was added.
pub const PLATFORM_ADDED: TraceEventKind = TraceEventKind::PlatformAdded;
/// A `TraceGuestPlatform` was deleted.
pub const PLATFORM_DELETED: TraceEventKind = TraceEventKind::PlatformDeleted;
/// A `TraceGuestPlatformMappedRange` was added.
pub const PLATFORM_MAPPING_ADDED: TraceEventKind = TraceEventKind::PlatformMappingAdded;
/// A `TraceGuestPlatformMappedRange` was deleted.
pub const PLATFORM_MAPPING_DELETED: TraceEventKind = TraceEventKind::PlatformMappingDeleted;

/// Get the comment change event for the given comment type.
///
/// Port of `TraceEvents.byCommentType(CommentType)`.
pub fn by_comment_type(comment_type: CommentType) -> TraceEventKind {
    match comment_type {
        CommentType::Plate => PLATE_COMMENT_CHANGED,
        CommentType::Pre => PRE_COMMENT_CHANGED,
        CommentType::Post => POST_COMMENT_CHANGED,
        CommentType::Eol => EOL_COMMENT_CHANGED,
        CommentType::Repeatable => REPEATABLE_COMMENT_CHANGED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_91_constants_have_unique_ids() {
        let ids: std::collections::HashSet<i32> = ALL_KINDS.iter().map(|k| k.get_id()).collect();
        assert_eq!(ids.len(), ALL_KINDS.len());
    }

    #[test]
    fn get_id_is_stable_across_calls() {
        assert_eq!(OBJECT_CREATED.get_id(), OBJECT_CREATED.get_id());
    }

    #[test]
    fn distinct_constants_have_distinct_ids() {
        assert_ne!(OBJECT_CREATED.get_id(), OBJECT_DELETED.get_id());
        assert_ne!(BOOKMARK_ADDED.get_id(), BOOKMARK_CHANGED.get_id());
    }

    #[test]
    fn by_comment_type_matches_java_switch() {
        assert_eq!(by_comment_type(CommentType::Plate), PLATE_COMMENT_CHANGED);
        assert_eq!(by_comment_type(CommentType::Pre), PRE_COMMENT_CHANGED);
        assert_eq!(by_comment_type(CommentType::Post), POST_COMMENT_CHANGED);
        assert_eq!(by_comment_type(CommentType::Eol), EOL_COMMENT_CHANGED);
        assert_eq!(
            by_comment_type(CommentType::Repeatable),
            REPEATABLE_COMMENT_CHANGED
        );
    }

    #[test]
    fn trace_event_kind_is_usable_as_dyn_trace_event() {
        let event: &dyn TraceEvent = &OBJECT_CREATED;
        assert_eq!(event.get_id(), OBJECT_CREATED.get_id());
    }
}
