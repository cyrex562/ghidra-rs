use crate::framework::model::{DomainObjectEventIdGenerator, EventType};
use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Event types for Program changes.
///
/// Each variant represents a specific type of change that can occur to a Program.
/// Implements the EventType trait to provide unique, compact ids for efficient
/// event filtering via bit sets.
///
/// Port of `ghidra.program.util.ProgramEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramEvent {
    MemoryBlockAdded,
    MemoryBlockRemoved,
    MemoryBlockChanged,
    MemoryBlockMoved,
    MemoryBlockSplit,
    MemoryBlocksJoined,
    MemoryBytesChanged,

    ImageBaseChanged,

    CodeAdded,
    CodeRemoved,
    CodeReplaced,

    CodeUnitPropertyChanged,
    CodeUnitPropertyAllRemoved,
    CodeUnitPropertyRangeRemoved,

    SymbolAdded,
    SymbolRemoved,
    SymbolSourceChanged,
    SymbolAnchorFlagChanged,
    SymbolPrimaryStateChanged,
    SymbolRenamed,
    SymbolScopeChanged,
    SymbolAssociationAdded,
    SymbolAssociationRemoved,
    SymbolDataChanged,
    SymbolAddressChanged,

    ExternalEntryAdded,
    ExternalEntryRemoved,

    ExternalNameAdded,
    ExternalNameRemoved,
    ExternalNameChanged,
    ExternalReferenceAdded,
    ExternalReferenceRemoved,

    ReferenceAdded,
    ReferenceRemoved,
    ReferenceTypeChanged,
    RefernceePrimarySet,
    ReferencePrimaryRemoved,

    EquateAdded,
    EquateRemoved,
    EquateReferenceAdded,
    EquateReferenceRemoved,
    EquateRenamed,

    ProgramTreeCreated,
    ProgramTreeRemoved,
    ProgramTreeRenamed,
    GroupAdded,
    GroupRemoved,
    GroupRenamed,
    GroupCommentChanged,
    GroupAliasChanged,
    GroupReparented,
    ModuleReordered,
    FragmentMoved,
    FragmentChanged,

    CommentChanged,

    DataTypeCategoryAdded,
    DataTypeCategoryRemoved,
    DataTypeCategoryRenamed,
    DataTypeCategoryMoved,
    DataTypeAdded,
    DataTypeRemoved,
    DataTypeRenamed,
    DataTypeMoved,
    DataTypeChanged,
    DataTypeSettingChanged,
    DataTypeReplaced,
    SourceArchiveAdded,
    SourceArchiveChanged,

    BookmarkTypeAdded,
    BookmarkTypeRemoved,
    BookmarkAdded,
    BookmarkRemoved,
    BookmarkChanged,

    LanguageChanged,
    RegisterValuesChanged,
    OverlaySpaceAdded,
    OverlaySpaceRemoved,
    OverlaySpaceRenamed,

    FunctionTagCreated,
    FunctionTagChanged,
    FunctionTagDeleted,
    FunctionTagApplied,
    FunctionTagUnapplied,

    FunctionAdded,
    FunctionRemoved,
    FunctionBodyChanged,
    FunctionChanged,

    VariableReferenceAdded,
    VariableReferenceRemoved,

    FallthroughChanged,
    FlowOverrideChanged,
    LengthOverrideChanged,

    AddressPropertyMapAdded,
    AddressPropertyMapRemoved,
    AddressPropertyMapChanged,

    IntPropertyMapAdded,
    IntPropertyMapRemoved,
    IntPropertyMapChanged,

    CodeUnitUserDataChanged,
    UserDataChanged,

    RelocationAdded,

    SourceFileAdded,
    SourceFileRemoved,
    SourceMapChanged,
}

static EVENT_IDS: Lazy<HashMap<ProgramEvent, i32>> = Lazy::new(|| {
    let mut map = HashMap::new();
    let events = [
        ProgramEvent::MemoryBlockAdded,
        ProgramEvent::MemoryBlockRemoved,
        ProgramEvent::MemoryBlockChanged,
        ProgramEvent::MemoryBlockMoved,
        ProgramEvent::MemoryBlockSplit,
        ProgramEvent::MemoryBlocksJoined,
        ProgramEvent::MemoryBytesChanged,
        ProgramEvent::ImageBaseChanged,
        ProgramEvent::CodeAdded,
        ProgramEvent::CodeRemoved,
        ProgramEvent::CodeReplaced,
        ProgramEvent::CodeUnitPropertyChanged,
        ProgramEvent::CodeUnitPropertyAllRemoved,
        ProgramEvent::CodeUnitPropertyRangeRemoved,
        ProgramEvent::SymbolAdded,
        ProgramEvent::SymbolRemoved,
        ProgramEvent::SymbolSourceChanged,
        ProgramEvent::SymbolAnchorFlagChanged,
        ProgramEvent::SymbolPrimaryStateChanged,
        ProgramEvent::SymbolRenamed,
        ProgramEvent::SymbolScopeChanged,
        ProgramEvent::SymbolAssociationAdded,
        ProgramEvent::SymbolAssociationRemoved,
        ProgramEvent::SymbolDataChanged,
        ProgramEvent::SymbolAddressChanged,
        ProgramEvent::ExternalEntryAdded,
        ProgramEvent::ExternalEntryRemoved,
        ProgramEvent::ExternalNameAdded,
        ProgramEvent::ExternalNameRemoved,
        ProgramEvent::ExternalNameChanged,
        ProgramEvent::ExternalReferenceAdded,
        ProgramEvent::ExternalReferenceRemoved,
        ProgramEvent::ReferenceAdded,
        ProgramEvent::ReferenceRemoved,
        ProgramEvent::ReferenceTypeChanged,
        ProgramEvent::RefernceePrimarySet,
        ProgramEvent::ReferencePrimaryRemoved,
        ProgramEvent::EquateAdded,
        ProgramEvent::EquateRemoved,
        ProgramEvent::EquateReferenceAdded,
        ProgramEvent::EquateReferenceRemoved,
        ProgramEvent::EquateRenamed,
        ProgramEvent::ProgramTreeCreated,
        ProgramEvent::ProgramTreeRemoved,
        ProgramEvent::ProgramTreeRenamed,
        ProgramEvent::GroupAdded,
        ProgramEvent::GroupRemoved,
        ProgramEvent::GroupRenamed,
        ProgramEvent::GroupCommentChanged,
        ProgramEvent::GroupAliasChanged,
        ProgramEvent::GroupReparented,
        ProgramEvent::ModuleReordered,
        ProgramEvent::FragmentMoved,
        ProgramEvent::FragmentChanged,
        ProgramEvent::CommentChanged,
        ProgramEvent::DataTypeCategoryAdded,
        ProgramEvent::DataTypeCategoryRemoved,
        ProgramEvent::DataTypeCategoryRenamed,
        ProgramEvent::DataTypeCategoryMoved,
        ProgramEvent::DataTypeAdded,
        ProgramEvent::DataTypeRemoved,
        ProgramEvent::DataTypeRenamed,
        ProgramEvent::DataTypeMoved,
        ProgramEvent::DataTypeChanged,
        ProgramEvent::DataTypeSettingChanged,
        ProgramEvent::DataTypeReplaced,
        ProgramEvent::SourceArchiveAdded,
        ProgramEvent::SourceArchiveChanged,
        ProgramEvent::BookmarkTypeAdded,
        ProgramEvent::BookmarkTypeRemoved,
        ProgramEvent::BookmarkAdded,
        ProgramEvent::BookmarkRemoved,
        ProgramEvent::BookmarkChanged,
        ProgramEvent::LanguageChanged,
        ProgramEvent::RegisterValuesChanged,
        ProgramEvent::OverlaySpaceAdded,
        ProgramEvent::OverlaySpaceRemoved,
        ProgramEvent::OverlaySpaceRenamed,
        ProgramEvent::FunctionTagCreated,
        ProgramEvent::FunctionTagChanged,
        ProgramEvent::FunctionTagDeleted,
        ProgramEvent::FunctionTagApplied,
        ProgramEvent::FunctionTagUnapplied,
        ProgramEvent::FunctionAdded,
        ProgramEvent::FunctionRemoved,
        ProgramEvent::FunctionBodyChanged,
        ProgramEvent::FunctionChanged,
        ProgramEvent::VariableReferenceAdded,
        ProgramEvent::VariableReferenceRemoved,
        ProgramEvent::FallthroughChanged,
        ProgramEvent::FlowOverrideChanged,
        ProgramEvent::LengthOverrideChanged,
        ProgramEvent::AddressPropertyMapAdded,
        ProgramEvent::AddressPropertyMapRemoved,
        ProgramEvent::AddressPropertyMapChanged,
        ProgramEvent::IntPropertyMapAdded,
        ProgramEvent::IntPropertyMapRemoved,
        ProgramEvent::IntPropertyMapChanged,
        ProgramEvent::CodeUnitUserDataChanged,
        ProgramEvent::UserDataChanged,
        ProgramEvent::RelocationAdded,
        ProgramEvent::SourceFileAdded,
        ProgramEvent::SourceFileRemoved,
        ProgramEvent::SourceMapChanged,
    ];

    for event in events.iter() {
        map.insert(*event, DomainObjectEventIdGenerator::next());
    }
    map
});

impl EventType for ProgramEvent {
    fn get_id(&self) -> i32 {
        EVENT_IDS
            .get(self)
            .copied()
            .expect("ProgramEvent variant should have an id")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_events_have_unique_ids() {
        let mut ids = vec![];
        let events = [
            ProgramEvent::MemoryBlockAdded,
            ProgramEvent::MemoryBlockRemoved,
            ProgramEvent::MemoryBlockChanged,
            ProgramEvent::MemoryBlockMoved,
            ProgramEvent::MemoryBlockSplit,
            ProgramEvent::MemoryBlocksJoined,
            ProgramEvent::MemoryBytesChanged,
            ProgramEvent::ImageBaseChanged,
            ProgramEvent::CodeAdded,
            ProgramEvent::CodeRemoved,
            ProgramEvent::CodeReplaced,
            ProgramEvent::CodeUnitPropertyChanged,
            ProgramEvent::CodeUnitPropertyAllRemoved,
            ProgramEvent::CodeUnitPropertyRangeRemoved,
            ProgramEvent::SymbolAdded,
            ProgramEvent::SymbolRemoved,
            ProgramEvent::SymbolSourceChanged,
            ProgramEvent::SymbolAnchorFlagChanged,
            ProgramEvent::SymbolPrimaryStateChanged,
            ProgramEvent::SymbolRenamed,
            ProgramEvent::SymbolScopeChanged,
            ProgramEvent::SymbolAssociationAdded,
            ProgramEvent::SymbolAssociationRemoved,
            ProgramEvent::SymbolDataChanged,
            ProgramEvent::SymbolAddressChanged,
            ProgramEvent::ExternalEntryAdded,
            ProgramEvent::ExternalEntryRemoved,
            ProgramEvent::ExternalNameAdded,
            ProgramEvent::ExternalNameRemoved,
            ProgramEvent::ExternalNameChanged,
            ProgramEvent::ExternalReferenceAdded,
            ProgramEvent::ExternalReferenceRemoved,
            ProgramEvent::ReferenceAdded,
            ProgramEvent::ReferenceRemoved,
            ProgramEvent::ReferenceTypeChanged,
            ProgramEvent::RefernceePrimarySet,
            ProgramEvent::ReferencePrimaryRemoved,
            ProgramEvent::EquateAdded,
            ProgramEvent::EquateRemoved,
            ProgramEvent::EquateReferenceAdded,
            ProgramEvent::EquateReferenceRemoved,
            ProgramEvent::EquateRenamed,
            ProgramEvent::ProgramTreeCreated,
            ProgramEvent::ProgramTreeRemoved,
            ProgramEvent::ProgramTreeRenamed,
            ProgramEvent::GroupAdded,
            ProgramEvent::GroupRemoved,
            ProgramEvent::GroupRenamed,
            ProgramEvent::GroupCommentChanged,
            ProgramEvent::GroupAliasChanged,
            ProgramEvent::GroupReparented,
            ProgramEvent::ModuleReordered,
            ProgramEvent::FragmentMoved,
            ProgramEvent::FragmentChanged,
            ProgramEvent::CommentChanged,
            ProgramEvent::DataTypeCategoryAdded,
            ProgramEvent::DataTypeCategoryRemoved,
            ProgramEvent::DataTypeCategoryRenamed,
            ProgramEvent::DataTypeCategoryMoved,
            ProgramEvent::DataTypeAdded,
            ProgramEvent::DataTypeRemoved,
            ProgramEvent::DataTypeRenamed,
            ProgramEvent::DataTypeMoved,
            ProgramEvent::DataTypeChanged,
            ProgramEvent::DataTypeSettingChanged,
            ProgramEvent::DataTypeReplaced,
            ProgramEvent::SourceArchiveAdded,
            ProgramEvent::SourceArchiveChanged,
            ProgramEvent::BookmarkTypeAdded,
            ProgramEvent::BookmarkTypeRemoved,
            ProgramEvent::BookmarkAdded,
            ProgramEvent::BookmarkRemoved,
            ProgramEvent::BookmarkChanged,
            ProgramEvent::LanguageChanged,
            ProgramEvent::RegisterValuesChanged,
            ProgramEvent::OverlaySpaceAdded,
            ProgramEvent::OverlaySpaceRemoved,
            ProgramEvent::OverlaySpaceRenamed,
            ProgramEvent::FunctionTagCreated,
            ProgramEvent::FunctionTagChanged,
            ProgramEvent::FunctionTagDeleted,
            ProgramEvent::FunctionTagApplied,
            ProgramEvent::FunctionTagUnapplied,
            ProgramEvent::FunctionAdded,
            ProgramEvent::FunctionRemoved,
            ProgramEvent::FunctionBodyChanged,
            ProgramEvent::FunctionChanged,
            ProgramEvent::VariableReferenceAdded,
            ProgramEvent::VariableReferenceRemoved,
            ProgramEvent::FallthroughChanged,
            ProgramEvent::FlowOverrideChanged,
            ProgramEvent::LengthOverrideChanged,
            ProgramEvent::AddressPropertyMapAdded,
            ProgramEvent::AddressPropertyMapRemoved,
            ProgramEvent::AddressPropertyMapChanged,
            ProgramEvent::IntPropertyMapAdded,
            ProgramEvent::IntPropertyMapRemoved,
            ProgramEvent::IntPropertyMapChanged,
            ProgramEvent::CodeUnitUserDataChanged,
            ProgramEvent::UserDataChanged,
            ProgramEvent::RelocationAdded,
            ProgramEvent::SourceFileAdded,
            ProgramEvent::SourceFileRemoved,
            ProgramEvent::SourceMapChanged,
        ];

        for event in events.iter() {
            ids.push(event.get_id());
        }

        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();

        assert_eq!(ids.len(), sorted.len(), "All event ids should be unique");
        assert_eq!(ids.len(), 104, "Should have 104 events");
    }

    #[test]
    fn event_ids_are_positive() {
        let events = [
            ProgramEvent::MemoryBlockAdded,
            ProgramEvent::CodeAdded,
            ProgramEvent::SymbolAdded,
        ];

        for event in events.iter() {
            assert!(event.get_id() > 0, "Event id should be positive");
        }
    }

    #[test]
    fn same_event_has_consistent_id() {
        let event = ProgramEvent::MemoryBlockAdded;
        let id1 = event.get_id();
        let id2 = event.get_id();
        assert_eq!(id1, id2, "Same event should always return same id");
    }

    #[test]
    fn different_events_have_different_ids() {
        let event1 = ProgramEvent::MemoryBlockAdded;
        let event2 = ProgramEvent::MemoryBlockRemoved;
        assert_ne!(
            event1.get_id(),
            event2.get_id(),
            "Different events should have different ids"
        );
    }
}
