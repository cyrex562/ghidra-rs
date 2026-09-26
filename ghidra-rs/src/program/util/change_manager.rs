//! The ChangeManager interface. Defines event types and the methods used to generate an
//! event within a Program.
//!
//! Port of `ghidra.program.util.ChangeManager`. Java's overloaded `setChanged` and
//! `setObjChanged` methods are each given a distinct Rust name, since Rust traits cannot
//! overload on parameter type alone.

use std::any::Any;

use crate::program::model::address::Address;
use crate::program::model::lang::Register;
use crate::program::util::{FunctionChangeType, ProgramEvent};

/// Interface to define event types and the method to generate an event within a Program.
pub trait ChangeManager {
    /// Marks the state of a Program as having changed and generates the event of the
    /// specified type. Any or all parameters may be `None`.
    ///
    /// # Arguments
    /// * `event_type` - the event type
    /// * `old_value` - original value or an object that is related to the event
    /// * `new_value` - new value or an object that is related to the event
    fn set_changed(
        &mut self,
        event_type: ProgramEvent,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );

    /// Notifies that register values have changed over the indicated address range.
    ///
    /// # Arguments
    /// * `register` - register value which was modified (`None` indicates all registers
    ///   affected or unknown)
    /// * `start` - the start address for the range where values changed
    /// * `end` - the end address (inclusive) for the range where values changed
    fn set_register_values_changed(&mut self, register: Option<&Register>, start: &Address, end: &Address);

    /// Marks the state of a Program as having changed and generates the event of the
    /// specified type over an address range. Any or all parameters may be `None`.
    ///
    /// # Arguments
    /// * `event_type` - the event type
    /// * `start` - starting address that is affected by the event
    /// * `end` - ending address that is affected by the event
    /// * `old_value` - original value or an object that is related to the event
    /// * `new_value` - new value or an object that is related to the event
    fn set_changed_range(
        &mut self,
        event_type: ProgramEvent,
        start: &Address,
        end: &Address,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );

    /// Marks the state of a Program as having changed and generates the event of the
    /// specified type. Any or all parameters may be `None`.
    ///
    /// # Arguments
    /// * `event_type` - the event type
    /// * `affected` - object that is the subject of the event
    /// * `old_value` - original value or an object that is related to the event
    /// * `new_value` - new value or an object that is related to the event
    fn set_obj_changed(
        &mut self,
        event_type: ProgramEvent,
        affected: Option<Box<dyn Any + Send + Sync>>,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );

    /// Marks the state of a Program as having changed and generates the event of the
    /// specified type, associated with a particular address. Any or all parameters may be
    /// `None`.
    ///
    /// # Arguments
    /// * `event_type` - the event type
    /// * `addr` - program address affected
    /// * `affected` - object that is the subject of the event
    /// * `old_value` - original value or an object that is related to the event
    /// * `new_value` - new value or an object that is related to the event
    fn set_obj_changed_at(
        &mut self,
        event_type: ProgramEvent,
        addr: Option<&Address>,
        affected: Option<Box<dyn Any + Send + Sync>>,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );

    /// Marks the state of a Program as having changed and generates the
    /// `CodeUnitPropertyChanged` event.
    ///
    /// # Arguments
    /// * `property_name` - name of property for the range that changed
    /// * `code_unit_addr` - address of the code unit with the property change
    /// * `old_value` - old value for the property
    /// * `new_value` - new value for the property
    fn set_property_changed(
        &mut self,
        property_name: &str,
        code_unit_addr: &Address,
        old_value: Option<Box<dyn Any + Send + Sync>>,
        new_value: Option<Box<dyn Any + Send + Sync>>,
    );

    /// Marks the state of the Program as having changed and generates the
    /// `CodeUnitPropertyRangeRemoved` event.
    ///
    /// # Arguments
    /// * `property_name` - name of property for the range being removed
    /// * `start` - start address of the range
    /// * `end` - end address of the range
    fn set_property_range_removed(&mut self, property_name: &str, start: &Address, end: &Address);
}

////////////////////////////////////////////////////////////////////////////
//
//                           Deprecated event ids
//
////////////////////////////////////////////////////////////////////////////

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEMORY_BLOCK_ADDED: ProgramEvent = ProgramEvent::MemoryBlockAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEMORY_BLOCK_REMOVED: ProgramEvent = ProgramEvent::MemoryBlockRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEMORY_BLOCK_CHANGED: ProgramEvent = ProgramEvent::MemoryBlockChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEMORY_BLOCK_MOVED: ProgramEvent = ProgramEvent::MemoryBlockMoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEMORY_BLOCK_SPLIT: ProgramEvent = ProgramEvent::MemoryBlockSplit;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEMORY_BLOCKS_JOINED: ProgramEvent = ProgramEvent::MemoryBlocksJoined;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEMORY_BYTES_CHANGED: ProgramEvent = ProgramEvent::MemoryBytesChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_IMAGE_BASE_CHANGED: ProgramEvent = ProgramEvent::ImageBaseChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CODE_ADDED: ProgramEvent = ProgramEvent::CodeAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CODE_REMOVED: ProgramEvent = ProgramEvent::CodeRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CODE_MOVED: ProgramEvent = ProgramEvent::FragmentChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CODE_REPLACED: ProgramEvent = ProgramEvent::CodeReplaced;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CODE_UNIT_PROPERTY_CHANGED: ProgramEvent = ProgramEvent::CodeUnitPropertyChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED: ProgramEvent = ProgramEvent::CodeUnitPropertyAllRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED: ProgramEvent = ProgramEvent::CodeUnitPropertyRangeRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_ADDED: ProgramEvent = ProgramEvent::SymbolAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_REMOVED: ProgramEvent = ProgramEvent::SymbolRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_SOURCE_CHANGED: ProgramEvent = ProgramEvent::SymbolSourceChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_ANCHORED_FLAG_CHANGED: ProgramEvent = ProgramEvent::SymbolAnchorFlagChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_SET_AS_PRIMARY: ProgramEvent = ProgramEvent::SymbolPrimaryStateChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_RENAMED: ProgramEvent = ProgramEvent::SymbolRenamed;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EXTERNAL_ENTRY_POINT_ADDED: ProgramEvent = ProgramEvent::ExternalEntryAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EXTERNAL_ENTRY_POINT_REMOVED: ProgramEvent = ProgramEvent::ExternalEntryRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_SCOPE_CHANGED: ProgramEvent = ProgramEvent::SymbolScopeChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_ASSOCIATION_ADDED: ProgramEvent = ProgramEvent::SymbolAssociationAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_ASSOCIATION_REMOVED: ProgramEvent = ProgramEvent::SymbolAssociationRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_DATA_CHANGED: ProgramEvent = ProgramEvent::SymbolDataChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SYMBOL_ADDRESS_CHANGED: ProgramEvent = ProgramEvent::SymbolAddressChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEM_REFERENCE_ADDED: ProgramEvent = ProgramEvent::ReferenceAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEM_REFERENCE_REMOVED: ProgramEvent = ProgramEvent::ReferenceRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEM_REF_TYPE_CHANGED: ProgramEvent = ProgramEvent::ReferenceTypeChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEM_REF_PRIMARY_SET: ProgramEvent = ProgramEvent::RefernceePrimarySet;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MEM_REF_PRIMARY_REMOVED: ProgramEvent = ProgramEvent::ReferencePrimaryRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EXTERNAL_NAME_ADDED: ProgramEvent = ProgramEvent::ExternalNameAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EXTERNAL_NAME_REMOVED: ProgramEvent = ProgramEvent::ExternalNameRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EXTERNAL_NAME_CHANGED: ProgramEvent = ProgramEvent::ExternalNameChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EQUATE_ADDED: ProgramEvent = ProgramEvent::EquateAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EQUATE_REMOVED: ProgramEvent = ProgramEvent::EquateRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EQUATE_REFERENCE_ADDED: ProgramEvent = ProgramEvent::EquateReferenceAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EQUATE_REFERENCE_REMOVED: ProgramEvent = ProgramEvent::EquateReferenceRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EQUATE_RENAMED: ProgramEvent = ProgramEvent::EquateRenamed;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_GROUP_ADDED: ProgramEvent = ProgramEvent::GroupAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_GROUP_REMOVED: ProgramEvent = ProgramEvent::GroupRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_GROUP_RENAMED: ProgramEvent = ProgramEvent::GroupRenamed;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_GROUP_COMMENT_CHANGED: ProgramEvent = ProgramEvent::GroupCommentChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_GROUP_ALIAS_CHANGED: ProgramEvent = ProgramEvent::GroupAliasChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_MODULE_REORDERED: ProgramEvent = ProgramEvent::ModuleReordered;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FRAGMENT_MOVED: ProgramEvent = ProgramEvent::FragmentMoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_GROUP_REPARENTED: ProgramEvent = ProgramEvent::GroupReparented;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EOL_COMMENT_CHANGED: ProgramEvent = ProgramEvent::CommentChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_PRE_COMMENT_CHANGED: ProgramEvent = ProgramEvent::CommentChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_POST_COMMENT_CHANGED: ProgramEvent = ProgramEvent::CommentChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_PLATE_COMMENT_CHANGED: ProgramEvent = ProgramEvent::CommentChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_REPEATABLE_COMMENT_CHANGED: ProgramEvent = ProgramEvent::CommentChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CATEGORY_ADDED: ProgramEvent = ProgramEvent::DataTypeCategoryAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CATEGORY_REMOVED: ProgramEvent = ProgramEvent::DataTypeCategoryRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CATEGORY_RENAMED: ProgramEvent = ProgramEvent::DataTypeCategoryRenamed;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CATEGORY_MOVED: ProgramEvent = ProgramEvent::DataTypeCategoryMoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_ADDED: ProgramEvent = ProgramEvent::DataTypeAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_REMOVED: ProgramEvent = ProgramEvent::DataTypeRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_RENAMED: ProgramEvent = ProgramEvent::DataTypeRenamed;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_MOVED: ProgramEvent = ProgramEvent::DataTypeMoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_CHANGED: ProgramEvent = ProgramEvent::DataTypeChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_SETTING_CHANGED: ProgramEvent = ProgramEvent::DataTypeSettingChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_DATA_TYPE_REPLACED: ProgramEvent = ProgramEvent::DataTypeReplaced;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SOURCE_ARCHIVE_ADDED: ProgramEvent = ProgramEvent::SourceArchiveAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_SOURCE_ARCHIVE_CHANGED: ProgramEvent = ProgramEvent::SourceArchiveChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_BOOKMARK_TYPE_ADDED: ProgramEvent = ProgramEvent::BookmarkTypeAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_BOOKMARK_TYPE_REMOVED: ProgramEvent = ProgramEvent::BookmarkTypeRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_BOOKMARK_ADDED: ProgramEvent = ProgramEvent::BookmarkAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_BOOKMARK_REMOVED: ProgramEvent = ProgramEvent::BookmarkRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_BOOKMARK_CHANGED: ProgramEvent = ProgramEvent::BookmarkChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_LANGUAGE_CHANGED: ProgramEvent = ProgramEvent::LanguageChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_REGISTER_VALUES_CHANGED: ProgramEvent = ProgramEvent::RegisterValuesChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_OVERLAY_SPACE_ADDED: ProgramEvent = ProgramEvent::OverlaySpaceAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_OVERLAY_SPACE_REMOVED: ProgramEvent = ProgramEvent::OverlaySpaceRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_OVERLAY_SPACE_RENAMED: ProgramEvent = ProgramEvent::OverlaySpaceRenamed;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_TREE_CREATED: ProgramEvent = ProgramEvent::ProgramTreeCreated;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_TREE_REMOVED: ProgramEvent = ProgramEvent::ProgramTreeRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_TREE_RENAMED: ProgramEvent = ProgramEvent::ProgramTreeRenamed;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FUNCTION_TAG_CHANGED: ProgramEvent = ProgramEvent::FunctionTagChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FUNCTION_TAG_CREATED: ProgramEvent = ProgramEvent::FunctionTagCreated;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FUNCTION_TAG_DELETED: ProgramEvent = ProgramEvent::FunctionTagDeleted;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FUNCTION_ADDED: ProgramEvent = ProgramEvent::FunctionTagApplied;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FUNCTION_REMOVED: ProgramEvent = ProgramEvent::FunctionTagUnapplied;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FUNCTION_CHANGED: ProgramEvent = ProgramEvent::FunctionChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_VARIABLE_REFERENCE_ADDED: ProgramEvent = ProgramEvent::VariableReferenceAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_VARIABLE_REFERENCE_REMOVED: ProgramEvent = ProgramEvent::VariableReferenceRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FUNCTION_BODY_CHANGED: ProgramEvent = ProgramEvent::FunctionBodyChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use FunctionChangeType directly")]
pub const FUNCTION_CHANGED_PURGE: FunctionChangeType = FunctionChangeType::PurgeChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use FunctionChangeType directly")]
pub const FUNCTION_CHANGED_INLINE: FunctionChangeType = FunctionChangeType::InlineChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use FunctionChangeType directly")]
pub const FUNCTION_CHANGED_NORETURN: FunctionChangeType = FunctionChangeType::NoReturnChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use FunctionChangeType directly")]
pub const FUNCTION_CHANGED_CALL_FIXUP: FunctionChangeType = FunctionChangeType::CallFixupChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use FunctionChangeType directly")]
pub const FUNCTION_CHANGED_RETURN: FunctionChangeType = FunctionChangeType::ReturnTypeChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use FunctionChangeType directly")]
pub const FUNCTION_CHANGED_PARAMETERS: FunctionChangeType = FunctionChangeType::ParametersChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use FunctionChangeType directly")]
pub const FUNCTION_CHANGED_THUNK: FunctionChangeType = FunctionChangeType::ThunkChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EXTERNAL_REFERENCE_ADDED: ProgramEvent = ProgramEvent::ExternalReferenceAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_EXTERNAL_REFERENCE_REMOVED: ProgramEvent = ProgramEvent::ExternalReferenceRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FALLTHROUGH_CHANGED: ProgramEvent = ProgramEvent::FallthroughChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_FLOWOVERRIDE_CHANGED: ProgramEvent = ProgramEvent::FlowOverrideChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_LENGTH_OVERRIDE_CHANGED: ProgramEvent = ProgramEvent::LengthOverrideChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_ADDRESS_SET_PROPERTY_MAP_ADDED: ProgramEvent = ProgramEvent::AddressPropertyMapAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_ADDRESS_SET_PROPERTY_MAP_REMOVED: ProgramEvent = ProgramEvent::AddressPropertyMapRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED: ProgramEvent = ProgramEvent::AddressPropertyMapChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED: ProgramEvent = ProgramEvent::IntPropertyMapAdded;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED: ProgramEvent = ProgramEvent::IntPropertyMapRemoved;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED: ProgramEvent = ProgramEvent::IntPropertyMapChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_CODE_UNIT_USER_DATA_CHANGED: ProgramEvent = ProgramEvent::CodeUnitUserDataChanged;

#[deprecated(since = "0.1.0", note = "Event type enums have replaced numeric constants; use ProgramEvent directly")]
pub const DOCR_USER_DATA_CHANGED: ProgramEvent = ProgramEvent::UserDataChanged;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct RecordingChangeManager {
        events: Vec<ProgramEvent>,
        register_range: Option<(Address, Address)>,
        property_removed_range: Option<(String, Address, Address)>,
    }

    impl RecordingChangeManager {
        fn new() -> Self {
            Self {
                events: Vec::new(),
                register_range: None,
                property_removed_range: None,
            }
        }
    }

    impl ChangeManager for RecordingChangeManager {
        fn set_changed(
            &mut self,
            event_type: ProgramEvent,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.events.push(event_type);
        }

        fn set_register_values_changed(
            &mut self,
            _register: Option<&Register>,
            start: &Address,
            end: &Address,
        ) {
            self.register_range = Some((start.clone(), end.clone()));
        }

        fn set_changed_range(
            &mut self,
            event_type: ProgramEvent,
            _start: &Address,
            _end: &Address,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.events.push(event_type);
        }

        fn set_obj_changed(
            &mut self,
            event_type: ProgramEvent,
            _affected: Option<Box<dyn Any + Send + Sync>>,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.events.push(event_type);
        }

        fn set_obj_changed_at(
            &mut self,
            event_type: ProgramEvent,
            _addr: Option<&Address>,
            _affected: Option<Box<dyn Any + Send + Sync>>,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.events.push(event_type);
        }

        fn set_property_changed(
            &mut self,
            _property_name: &str,
            _code_unit_addr: &Address,
            _old_value: Option<Box<dyn Any + Send + Sync>>,
            _new_value: Option<Box<dyn Any + Send + Sync>>,
        ) {
            self.events.push(ProgramEvent::CodeUnitPropertyChanged);
        }

        fn set_property_range_removed(&mut self, property_name: &str, start: &Address, end: &Address) {
            self.property_removed_range = Some((property_name.to_string(), start.clone(), end.clone()));
        }
    }

    #[test]
    fn set_changed_records_event_type() {
        let mut mgr = RecordingChangeManager::new();
        mgr.set_changed(ProgramEvent::SymbolRenamed, None, None);
        assert_eq!(mgr.events, vec![ProgramEvent::SymbolRenamed]);
    }

    #[test]
    fn set_changed_accepts_object_payloads() {
        let mut mgr = RecordingChangeManager::new();
        let old: Box<dyn Any + Send + Sync> = Box::new("old".to_string());
        let new: Box<dyn Any + Send + Sync> = Box::new("new".to_string());
        mgr.set_changed(ProgramEvent::DataTypeChanged, Some(old), Some(new));
        assert_eq!(mgr.events, vec![ProgramEvent::DataTypeChanged]);
    }

    #[test]
    fn set_register_values_changed_records_range() {
        let mut mgr = RecordingChangeManager::new();
        let start = addr(0x1000);
        let end = addr(0x2000);
        mgr.set_register_values_changed(None, &start, &end);
        assert_eq!(mgr.register_range, Some((start, end)));
    }

    #[test]
    fn set_changed_range_records_event_type() {
        let mut mgr = RecordingChangeManager::new();
        let start = addr(0x1000);
        let end = addr(0x2000);
        mgr.set_changed_range(ProgramEvent::CodeAdded, &start, &end, None, None);
        assert_eq!(mgr.events, vec![ProgramEvent::CodeAdded]);
    }

    #[test]
    fn set_obj_changed_records_event_type() {
        let mut mgr = RecordingChangeManager::new();
        mgr.set_obj_changed(ProgramEvent::BookmarkAdded, None, None, None);
        assert_eq!(mgr.events, vec![ProgramEvent::BookmarkAdded]);
    }

    #[test]
    fn set_obj_changed_at_records_event_type() {
        let mut mgr = RecordingChangeManager::new();
        let a = addr(0x4000);
        mgr.set_obj_changed_at(ProgramEvent::FunctionChanged, Some(&a), None, None, None);
        assert_eq!(mgr.events, vec![ProgramEvent::FunctionChanged]);
    }

    #[test]
    fn set_property_changed_records_property_event() {
        let mut mgr = RecordingChangeManager::new();
        let a = addr(0x8000);
        mgr.set_property_changed("comment", &a, None, None);
        assert_eq!(mgr.events, vec![ProgramEvent::CodeUnitPropertyChanged]);
    }

    #[test]
    fn set_property_range_removed_records_range() {
        let mut mgr = RecordingChangeManager::new();
        let start = addr(0x1000);
        let end = addr(0x2000);
        mgr.set_property_range_removed("comment", &start, &end);
        assert_eq!(
            mgr.property_removed_range,
            Some(("comment".to_string(), start, end))
        );
    }

    #[test]
    fn deprecated_program_event_constants_reference_correct_events() {
        assert_eq!(DOCR_MEMORY_BLOCK_ADDED, ProgramEvent::MemoryBlockAdded);
        assert_eq!(DOCR_MEMORY_BLOCK_REMOVED, ProgramEvent::MemoryBlockRemoved);
        assert_eq!(DOCR_MEMORY_BLOCK_CHANGED, ProgramEvent::MemoryBlockChanged);
        assert_eq!(DOCR_MEMORY_BLOCK_MOVED, ProgramEvent::MemoryBlockMoved);
        assert_eq!(DOCR_MEMORY_BLOCK_SPLIT, ProgramEvent::MemoryBlockSplit);
        assert_eq!(DOCR_MEMORY_BLOCKS_JOINED, ProgramEvent::MemoryBlocksJoined);
        assert_eq!(DOCR_MEMORY_BYTES_CHANGED, ProgramEvent::MemoryBytesChanged);
        assert_eq!(DOCR_IMAGE_BASE_CHANGED, ProgramEvent::ImageBaseChanged);
        assert_eq!(DOCR_CODE_ADDED, ProgramEvent::CodeAdded);
        assert_eq!(DOCR_CODE_REMOVED, ProgramEvent::CodeRemoved);
        assert_eq!(DOCR_CODE_MOVED, ProgramEvent::FragmentChanged);
        assert_eq!(DOCR_CODE_REPLACED, ProgramEvent::CodeReplaced);
        assert_eq!(DOCR_CODE_UNIT_PROPERTY_CHANGED, ProgramEvent::CodeUnitPropertyChanged);
        assert_eq!(
            DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED,
            ProgramEvent::CodeUnitPropertyAllRemoved
        );
        assert_eq!(
            DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED,
            ProgramEvent::CodeUnitPropertyRangeRemoved
        );
        assert_eq!(DOCR_SYMBOL_ADDED, ProgramEvent::SymbolAdded);
        assert_eq!(DOCR_SYMBOL_REMOVED, ProgramEvent::SymbolRemoved);
        assert_eq!(DOCR_SYMBOL_SOURCE_CHANGED, ProgramEvent::SymbolSourceChanged);
        assert_eq!(DOCR_SYMBOL_ANCHORED_FLAG_CHANGED, ProgramEvent::SymbolAnchorFlagChanged);
        assert_eq!(DOCR_SYMBOL_SET_AS_PRIMARY, ProgramEvent::SymbolPrimaryStateChanged);
        assert_eq!(DOCR_SYMBOL_RENAMED, ProgramEvent::SymbolRenamed);
        assert_eq!(DOCR_EXTERNAL_ENTRY_POINT_ADDED, ProgramEvent::ExternalEntryAdded);
        assert_eq!(DOCR_EXTERNAL_ENTRY_POINT_REMOVED, ProgramEvent::ExternalEntryRemoved);
        assert_eq!(DOCR_SYMBOL_SCOPE_CHANGED, ProgramEvent::SymbolScopeChanged);
        assert_eq!(DOCR_SYMBOL_ASSOCIATION_ADDED, ProgramEvent::SymbolAssociationAdded);
        assert_eq!(DOCR_SYMBOL_ASSOCIATION_REMOVED, ProgramEvent::SymbolAssociationRemoved);
        assert_eq!(DOCR_SYMBOL_DATA_CHANGED, ProgramEvent::SymbolDataChanged);
        assert_eq!(DOCR_SYMBOL_ADDRESS_CHANGED, ProgramEvent::SymbolAddressChanged);
        assert_eq!(DOCR_MEM_REFERENCE_ADDED, ProgramEvent::ReferenceAdded);
        assert_eq!(DOCR_MEM_REFERENCE_REMOVED, ProgramEvent::ReferenceRemoved);
        assert_eq!(DOCR_MEM_REF_TYPE_CHANGED, ProgramEvent::ReferenceTypeChanged);
        assert_eq!(DOCR_MEM_REF_PRIMARY_SET, ProgramEvent::RefernceePrimarySet);
        assert_eq!(DOCR_MEM_REF_PRIMARY_REMOVED, ProgramEvent::ReferencePrimaryRemoved);
        assert_eq!(DOCR_EXTERNAL_NAME_ADDED, ProgramEvent::ExternalNameAdded);
        assert_eq!(DOCR_EXTERNAL_NAME_REMOVED, ProgramEvent::ExternalNameRemoved);
        assert_eq!(DOCR_EXTERNAL_NAME_CHANGED, ProgramEvent::ExternalNameChanged);
        assert_eq!(DOCR_EQUATE_ADDED, ProgramEvent::EquateAdded);
        assert_eq!(DOCR_EQUATE_REMOVED, ProgramEvent::EquateRemoved);
        assert_eq!(DOCR_EQUATE_REFERENCE_ADDED, ProgramEvent::EquateReferenceAdded);
        assert_eq!(DOCR_EQUATE_REFERENCE_REMOVED, ProgramEvent::EquateReferenceRemoved);
        assert_eq!(DOCR_EQUATE_RENAMED, ProgramEvent::EquateRenamed);
        assert_eq!(DOCR_GROUP_ADDED, ProgramEvent::GroupAdded);
        assert_eq!(DOCR_GROUP_REMOVED, ProgramEvent::GroupRemoved);
        assert_eq!(DOCR_GROUP_RENAMED, ProgramEvent::GroupRenamed);
        assert_eq!(DOCR_GROUP_COMMENT_CHANGED, ProgramEvent::GroupCommentChanged);
        assert_eq!(DOCR_GROUP_ALIAS_CHANGED, ProgramEvent::GroupAliasChanged);
        assert_eq!(DOCR_MODULE_REORDERED, ProgramEvent::ModuleReordered);
        assert_eq!(DOCR_FRAGMENT_MOVED, ProgramEvent::FragmentMoved);
        assert_eq!(DOCR_GROUP_REPARENTED, ProgramEvent::GroupReparented);
        assert_eq!(DOCR_EOL_COMMENT_CHANGED, ProgramEvent::CommentChanged);
        assert_eq!(DOCR_PRE_COMMENT_CHANGED, ProgramEvent::CommentChanged);
        assert_eq!(DOCR_POST_COMMENT_CHANGED, ProgramEvent::CommentChanged);
        assert_eq!(DOCR_PLATE_COMMENT_CHANGED, ProgramEvent::CommentChanged);
        assert_eq!(DOCR_REPEATABLE_COMMENT_CHANGED, ProgramEvent::CommentChanged);
        assert_eq!(DOCR_CATEGORY_ADDED, ProgramEvent::DataTypeCategoryAdded);
        assert_eq!(DOCR_CATEGORY_REMOVED, ProgramEvent::DataTypeCategoryRemoved);
        assert_eq!(DOCR_CATEGORY_RENAMED, ProgramEvent::DataTypeCategoryRenamed);
        assert_eq!(DOCR_CATEGORY_MOVED, ProgramEvent::DataTypeCategoryMoved);
        assert_eq!(DOCR_DATA_TYPE_ADDED, ProgramEvent::DataTypeAdded);
        assert_eq!(DOCR_DATA_TYPE_REMOVED, ProgramEvent::DataTypeRemoved);
        assert_eq!(DOCR_DATA_TYPE_RENAMED, ProgramEvent::DataTypeRenamed);
        assert_eq!(DOCR_DATA_TYPE_MOVED, ProgramEvent::DataTypeMoved);
        assert_eq!(DOCR_DATA_TYPE_CHANGED, ProgramEvent::DataTypeChanged);
        assert_eq!(DOCR_DATA_TYPE_SETTING_CHANGED, ProgramEvent::DataTypeSettingChanged);
        assert_eq!(DOCR_DATA_TYPE_REPLACED, ProgramEvent::DataTypeReplaced);
        assert_eq!(DOCR_SOURCE_ARCHIVE_ADDED, ProgramEvent::SourceArchiveAdded);
        assert_eq!(DOCR_SOURCE_ARCHIVE_CHANGED, ProgramEvent::SourceArchiveChanged);
        assert_eq!(DOCR_BOOKMARK_TYPE_ADDED, ProgramEvent::BookmarkTypeAdded);
        assert_eq!(DOCR_BOOKMARK_TYPE_REMOVED, ProgramEvent::BookmarkTypeRemoved);
        assert_eq!(DOCR_BOOKMARK_ADDED, ProgramEvent::BookmarkAdded);
        assert_eq!(DOCR_BOOKMARK_REMOVED, ProgramEvent::BookmarkRemoved);
        assert_eq!(DOCR_BOOKMARK_CHANGED, ProgramEvent::BookmarkChanged);
        assert_eq!(DOCR_LANGUAGE_CHANGED, ProgramEvent::LanguageChanged);
        assert_eq!(DOCR_REGISTER_VALUES_CHANGED, ProgramEvent::RegisterValuesChanged);
        assert_eq!(DOCR_OVERLAY_SPACE_ADDED, ProgramEvent::OverlaySpaceAdded);
        assert_eq!(DOCR_OVERLAY_SPACE_REMOVED, ProgramEvent::OverlaySpaceRemoved);
        assert_eq!(DOCR_OVERLAY_SPACE_RENAMED, ProgramEvent::OverlaySpaceRenamed);
        assert_eq!(DOCR_TREE_CREATED, ProgramEvent::ProgramTreeCreated);
        assert_eq!(DOCR_TREE_REMOVED, ProgramEvent::ProgramTreeRemoved);
        assert_eq!(DOCR_TREE_RENAMED, ProgramEvent::ProgramTreeRenamed);
        assert_eq!(DOCR_FUNCTION_TAG_CHANGED, ProgramEvent::FunctionTagChanged);
        assert_eq!(DOCR_FUNCTION_TAG_CREATED, ProgramEvent::FunctionTagCreated);
        assert_eq!(DOCR_FUNCTION_TAG_DELETED, ProgramEvent::FunctionTagDeleted);
        assert_eq!(DOCR_FUNCTION_ADDED, ProgramEvent::FunctionTagApplied);
        assert_eq!(DOCR_FUNCTION_REMOVED, ProgramEvent::FunctionTagUnapplied);
        assert_eq!(DOCR_FUNCTION_CHANGED, ProgramEvent::FunctionChanged);
        assert_eq!(DOCR_VARIABLE_REFERENCE_ADDED, ProgramEvent::VariableReferenceAdded);
        assert_eq!(DOCR_VARIABLE_REFERENCE_REMOVED, ProgramEvent::VariableReferenceRemoved);
        assert_eq!(DOCR_FUNCTION_BODY_CHANGED, ProgramEvent::FunctionBodyChanged);
        assert_eq!(DOCR_EXTERNAL_REFERENCE_ADDED, ProgramEvent::ExternalReferenceAdded);
        assert_eq!(DOCR_EXTERNAL_REFERENCE_REMOVED, ProgramEvent::ExternalReferenceRemoved);
        assert_eq!(DOCR_FALLTHROUGH_CHANGED, ProgramEvent::FallthroughChanged);
        assert_eq!(DOCR_FLOWOVERRIDE_CHANGED, ProgramEvent::FlowOverrideChanged);
        assert_eq!(DOCR_LENGTH_OVERRIDE_CHANGED, ProgramEvent::LengthOverrideChanged);
        assert_eq!(DOCR_ADDRESS_SET_PROPERTY_MAP_ADDED, ProgramEvent::AddressPropertyMapAdded);
        assert_eq!(DOCR_ADDRESS_SET_PROPERTY_MAP_REMOVED, ProgramEvent::AddressPropertyMapRemoved);
        assert_eq!(DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, ProgramEvent::AddressPropertyMapChanged);
        assert_eq!(DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED, ProgramEvent::IntPropertyMapAdded);
        assert_eq!(DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED, ProgramEvent::IntPropertyMapRemoved);
        assert_eq!(DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED, ProgramEvent::IntPropertyMapChanged);
        assert_eq!(DOCR_CODE_UNIT_USER_DATA_CHANGED, ProgramEvent::CodeUnitUserDataChanged);
        assert_eq!(DOCR_USER_DATA_CHANGED, ProgramEvent::UserDataChanged);
    }

    #[test]
    fn deprecated_function_change_type_constants_reference_correct_types() {
        assert_eq!(FUNCTION_CHANGED_PURGE, FunctionChangeType::PurgeChanged);
        assert_eq!(FUNCTION_CHANGED_INLINE, FunctionChangeType::InlineChanged);
        assert_eq!(FUNCTION_CHANGED_NORETURN, FunctionChangeType::NoReturnChanged);
        assert_eq!(FUNCTION_CHANGED_CALL_FIXUP, FunctionChangeType::CallFixupChanged);
        assert_eq!(FUNCTION_CHANGED_RETURN, FunctionChangeType::ReturnTypeChanged);
        assert_eq!(FUNCTION_CHANGED_PARAMETERS, FunctionChangeType::ParametersChanged);
        assert_eq!(FUNCTION_CHANGED_THUNK, FunctionChangeType::ThunkChanged);
    }
}
