use crate::program::model::data::data_type::DataType;

/// Indicates the conflict resolution policy which should be applied when any conflict is
/// encountered.
///
/// Port of `ghidra.program.model.data.DataTypeConflictHandler.ConflictResolutionPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictResolutionPolicy {
    RenameAndAdd,
    UseExisting,
    ReplaceExisting,
    ReplaceEmptyStructsOrRenameAndAdd,
}

impl ConflictResolutionPolicy {
    /// Returns the handler associated with this policy.
    pub fn get_handler(self) -> &'static dyn DataTypeConflictHandler {
        match self {
            ConflictResolutionPolicy::RenameAndAdd => &DEFAULT_HANDLER,
            ConflictResolutionPolicy::UseExisting => &KEEP_HANDLER,
            ConflictResolutionPolicy::ReplaceExisting => &REPLACE_HANDLER,
            ConflictResolutionPolicy::ReplaceEmptyStructsOrRenameAndAdd => {
                &REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER
            }
        }
    }
}

/// Indicates the resolution which should be applied to a specific conflict.
///
/// Port of `ghidra.program.model.data.DataTypeConflictHandler.ConflictResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictResult {
    RenameAndAdd,
    UseExisting,
    ReplaceExisting,
}

/// Provides the `DataTypeManager` with a handler that is used to provide a disposition when a
/// datatype conflict is detected during `DataTypeManager::resolve` processing.
///
/// Port of `ghidra.program.model.data.DataTypeConflictHandler`.
///
/// Known Issue: resolve processing identifies a conflict on an outer datatype (e.g., Structure)
/// before a resolve conflict decision has been made on its referenced datatypes. Depending upon
/// the conflict handler used, this can result in duplicate conflict types once the full
/// resolution is completed (see GP-3632).
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that declared no
/// methods, referenced only as a parameter type by
/// [`Category`](crate::program::model::data::category::Category) and
/// [`DataTypeManager`](crate::program::model::data::data_type_manager::DataTypeManager).
///
/// Every method is given a default (mirroring [`DEFAULT_HANDLER`]'s `resolve_conflict`
/// behavior, `false` for `should_update`, and [`KEEP_HANDLER`] as a conservative,
/// non-mutating `get_subsequent_handler`) so that the existing bare
/// `impl DataTypeConflictHandler for MockDataTypeConflictHandler {}` in
/// `DataTypeManager`'s tests keeps compiling unmodified.
pub trait DataTypeConflictHandler {
    /// Callback to handle conflicts in a datatype manager when new datatypes are added that
    /// have the same name as an existing datatype. The implementer of this interface should do
    /// one of the following:
    /// - return `RenameAndAdd` - the existing datatype is kept and the added datatype will be
    ///   renamed with a `.conflict` suffix (may throw exception if the datatypes are not
    ///   compatible)
    /// - return `UseExisting` - the added datatype will be ignored and the existing dataType
    ///   will be used
    /// - return `ReplaceExisting` - the existing datatype will be replaced by the added datatype
    fn resolve_conflict(
        &self,
        added_data_type: &dyn DataType,
        existing_data_type: &dyn DataType,
    ) -> ConflictResult {
        let _ = (added_data_type, existing_data_type);
        ConflictResult::RenameAndAdd
    }

    /// Callback invoked when an associated dataType is being resolved and its local version of
    /// the dataType is different from the source archive's dataType. Returns `true` if the local
    /// version should be updated to the archive's version of the dataType. Otherwise, the local
    /// dataType will be used (without updating) in the resolve operation.
    fn should_update(&self, source_data_type: &dyn DataType, local_data_type: &dyn DataType) -> bool {
        let _ = (source_data_type, local_data_type);
        false
    }

    /// Returns the appropriate handler for recursive resolve calls.
    fn get_subsequent_handler(&self) -> &'static dyn DataTypeConflictHandler {
        &KEEP_HANDLER
    }
}

pub struct DefaultHandlerImpl;

impl DataTypeConflictHandler for DefaultHandlerImpl {
    fn resolve_conflict(
        &self,
        _added_data_type: &dyn DataType,
        _existing_data_type: &dyn DataType,
    ) -> ConflictResult {
        ConflictResult::RenameAndAdd
    }

    fn should_update(&self, _source_data_type: &dyn DataType, _local_data_type: &dyn DataType) -> bool {
        true // TODO: uncertain this is appropriate
    }

    fn get_subsequent_handler(&self) -> &'static dyn DataTypeConflictHandler {
        &DEFAULT_SUBSEQUENT_HANDLER
    }
}

/// The default conflict handler: renames the added datatype with a `.conflict` suffix.
pub static DEFAULT_HANDLER: DefaultHandlerImpl = DefaultHandlerImpl;

struct DefaultSubsequentHandlerImpl;

impl DataTypeConflictHandler for DefaultSubsequentHandlerImpl {
    fn resolve_conflict(
        &self,
        added_data_type: &dyn DataType,
        existing_data_type: &dyn DataType,
    ) -> ConflictResult {
        DEFAULT_HANDLER.resolve_conflict(added_data_type, existing_data_type)
    }

    fn should_update(&self, _source_data_type: &dyn DataType, _local_data_type: &dyn DataType) -> bool {
        false
    }

    fn get_subsequent_handler(&self) -> &'static dyn DataTypeConflictHandler {
        &DEFAULT_SUBSEQUENT_HANDLER
    }
}

static DEFAULT_SUBSEQUENT_HANDLER: DefaultSubsequentHandlerImpl = DefaultSubsequentHandlerImpl;

pub struct ReplaceHandlerImpl;

impl DataTypeConflictHandler for ReplaceHandlerImpl {
    fn resolve_conflict(
        &self,
        _added_data_type: &dyn DataType,
        _existing_data_type: &dyn DataType,
    ) -> ConflictResult {
        ConflictResult::ReplaceExisting
    }

    fn should_update(&self, _source_data_type: &dyn DataType, _local_data_type: &dyn DataType) -> bool {
        true
    }

    fn get_subsequent_handler(&self) -> &'static dyn DataTypeConflictHandler {
        &SUBSEQUENT_REPLACE_HANDLER
    }
}

/// Replaces the existing datatype with the added datatype.
pub static REPLACE_HANDLER: ReplaceHandlerImpl = ReplaceHandlerImpl;

struct SubsequentReplaceHandlerImpl;

impl DataTypeConflictHandler for SubsequentReplaceHandlerImpl {
    fn resolve_conflict(
        &self,
        added_data_type: &dyn DataType,
        existing_data_type: &dyn DataType,
    ) -> ConflictResult {
        REPLACE_HANDLER.resolve_conflict(added_data_type, existing_data_type)
    }

    fn should_update(&self, _source_data_type: &dyn DataType, _local_data_type: &dyn DataType) -> bool {
        false
    }

    fn get_subsequent_handler(&self) -> &'static dyn DataTypeConflictHandler {
        &SUBSEQUENT_REPLACE_HANDLER
    }
}

static SUBSEQUENT_REPLACE_HANDLER: SubsequentReplaceHandlerImpl = SubsequentReplaceHandlerImpl;

pub struct KeepHandlerImpl;

impl DataTypeConflictHandler for KeepHandlerImpl {
    fn resolve_conflict(
        &self,
        _added_data_type: &dyn DataType,
        _existing_data_type: &dyn DataType,
    ) -> ConflictResult {
        ConflictResult::UseExisting
    }

    fn should_update(&self, _source_data_type: &dyn DataType, _local_data_type: &dyn DataType) -> bool {
        false
    }

    fn get_subsequent_handler(&self) -> &'static dyn DataTypeConflictHandler {
        &KEEP_HANDLER
    }
}

/// Keeps the existing datatype; the added datatype is not added.
pub static KEEP_HANDLER: KeepHandlerImpl = KeepHandlerImpl;

pub struct ReplaceEmptyStructsOrRenameAndAddHandlerImpl;

impl ReplaceEmptyStructsOrRenameAndAddHandlerImpl {
    fn resolve_conflict_replace_empty(
        &self,
        added_data_type: &dyn DataType,
        existing_data_type: &dyn DataType,
    ) -> ConflictResult {
        if added_data_type.is_not_yet_defined() {
            return ConflictResult::UseExisting;
        }
        if existing_data_type.is_not_yet_defined() {
            return ConflictResult::ReplaceExisting;
        }
        ConflictResult::RenameAndAdd
    }
}

impl DataTypeConflictHandler for ReplaceEmptyStructsOrRenameAndAddHandlerImpl {
    fn resolve_conflict(
        &self,
        added_data_type: &dyn DataType,
        existing_data_type: &dyn DataType,
    ) -> ConflictResult {
        if added_data_type.is_structure() {
            if existing_data_type.is_structure() {
                return self.resolve_conflict_replace_empty(added_data_type, existing_data_type);
            }
        } else if added_data_type.is_union() && existing_data_type.is_union() {
            return self.resolve_conflict_replace_empty(added_data_type, existing_data_type);
        }
        ConflictResult::RenameAndAdd
    }

    fn should_update(&self, _source_data_type: &dyn DataType, _local_data_type: &dyn DataType) -> bool {
        false
    }

    fn get_subsequent_handler(&self) -> &'static dyn DataTypeConflictHandler {
        &REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER
    }
}

/// This conflict handler behaves similar to [`DEFAULT_HANDLER`] with the difference being that
/// an empty composite (see [`DataType::is_not_yet_defined`]) will be replaced by a similar
/// non-empty composite type. Alignment (e.g., packing) is not considered when determining
/// conflict resolution.
///
/// Unlike [`DEFAULT_HANDLER`], follow-on dependency datatype resolutions will retain the same
/// conflict resolution strategy.
pub static REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER: ReplaceEmptyStructsOrRenameAndAddHandlerImpl =
    ReplaceEmptyStructsOrRenameAndAddHandlerImpl;

pub(crate) struct BuiltInManagerHandlerImpl;

impl DataTypeConflictHandler for BuiltInManagerHandlerImpl {
    fn resolve_conflict(
        &self,
        _added_data_type: &dyn DataType,
        _existing_data_type: &dyn DataType,
    ) -> ConflictResult {
        panic!("Built-in data-types may not be substantially changed while Ghidra is running");
    }

    fn should_update(&self, _source_data_type: &dyn DataType, _local_data_type: &dyn DataType) -> bool {
        false
    }

    fn get_subsequent_handler(&self) -> &'static dyn DataTypeConflictHandler {
        &BUILT_IN_MANAGER_HANDLER
    }
}

pub(crate) static BUILT_IN_MANAGER_HANDLER: BuiltInManagerHandlerImpl = BuiltInManagerHandlerImpl;

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType {
        not_yet_defined: bool,
        structure: bool,
        union: bool,
    }

    impl MockDataType {
        fn plain() -> Self {
            MockDataType { not_yet_defined: false, structure: false, union: false }
        }

        fn structure(not_yet_defined: bool) -> Self {
            MockDataType { not_yet_defined, structure: true, union: false }
        }

        fn union(not_yet_defined: bool) -> Self {
            MockDataType { not_yet_defined, structure: false, union: true }
        }
    }

    impl DataType for MockDataType {
        fn is_not_yet_defined(&self) -> bool {
            self.not_yet_defined
        }

        fn is_structure(&self) -> bool {
            self.structure
        }

        fn is_union(&self) -> bool {
            self.union
        }
    }

    #[test]
    fn default_handler_renames_and_adds() {
        let added = MockDataType::plain();
        let existing = MockDataType::plain();
        assert_eq!(
            DEFAULT_HANDLER.resolve_conflict(&added, &existing),
            ConflictResult::RenameAndAdd
        );
        assert!(DEFAULT_HANDLER.should_update(&added, &existing));
    }

    #[test]
    fn default_handler_subsequent_handler_never_updates() {
        let added = MockDataType::plain();
        let existing = MockDataType::plain();
        let subsequent = DEFAULT_HANDLER.get_subsequent_handler();
        assert_eq!(
            subsequent.resolve_conflict(&added, &existing),
            ConflictResult::RenameAndAdd
        );
        assert!(!subsequent.should_update(&added, &existing));
        assert!(std::ptr::eq(
            subsequent.get_subsequent_handler() as *const dyn DataTypeConflictHandler as *const (),
            subsequent as *const dyn DataTypeConflictHandler as *const ()
        ));
    }

    #[test]
    fn replace_handler_replaces_existing() {
        let added = MockDataType::plain();
        let existing = MockDataType::plain();
        assert_eq!(
            REPLACE_HANDLER.resolve_conflict(&added, &existing),
            ConflictResult::ReplaceExisting
        );
        assert!(REPLACE_HANDLER.should_update(&added, &existing));
    }

    #[test]
    fn replace_handler_subsequent_handler_never_updates() {
        let added = MockDataType::plain();
        let existing = MockDataType::plain();
        let subsequent = REPLACE_HANDLER.get_subsequent_handler();
        assert_eq!(
            subsequent.resolve_conflict(&added, &existing),
            ConflictResult::ReplaceExisting
        );
        assert!(!subsequent.should_update(&added, &existing));
    }

    #[test]
    fn keep_handler_uses_existing() {
        let added = MockDataType::plain();
        let existing = MockDataType::plain();
        assert_eq!(
            KEEP_HANDLER.resolve_conflict(&added, &existing),
            ConflictResult::UseExisting
        );
        assert!(!KEEP_HANDLER.should_update(&added, &existing));
    }

    #[test]
    fn replace_empty_structs_handler_keeps_non_structure_non_union_rename_and_add() {
        let added = MockDataType::plain();
        let existing = MockDataType::plain();
        assert_eq!(
            REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER.resolve_conflict(&added, &existing),
            ConflictResult::RenameAndAdd
        );
    }

    #[test]
    fn replace_empty_structs_handler_prefers_added_when_added_empty() {
        let added = MockDataType::structure(true);
        let existing = MockDataType::structure(false);
        assert_eq!(
            REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER.resolve_conflict(&added, &existing),
            ConflictResult::UseExisting
        );
    }

    #[test]
    fn replace_empty_structs_handler_replaces_when_existing_empty() {
        let added = MockDataType::structure(false);
        let existing = MockDataType::structure(true);
        assert_eq!(
            REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER.resolve_conflict(&added, &existing),
            ConflictResult::ReplaceExisting
        );
    }

    #[test]
    fn replace_empty_structs_handler_renames_when_both_defined() {
        let added = MockDataType::structure(false);
        let existing = MockDataType::structure(false);
        assert_eq!(
            REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER.resolve_conflict(&added, &existing),
            ConflictResult::RenameAndAdd
        );
    }

    #[test]
    fn replace_empty_structs_handler_handles_unions() {
        let added = MockDataType::union(true);
        let existing = MockDataType::union(false);
        assert_eq!(
            REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER.resolve_conflict(&added, &existing),
            ConflictResult::UseExisting
        );
    }

    #[test]
    fn replace_empty_structs_handler_renames_when_kinds_differ() {
        let added = MockDataType::structure(true);
        let existing = MockDataType::union(true);
        assert_eq!(
            REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER.resolve_conflict(&added, &existing),
            ConflictResult::RenameAndAdd
        );
    }

    #[test]
    #[should_panic(expected = "Built-in data-types may not be substantially changed")]
    fn built_in_manager_handler_panics_on_resolve() {
        let added = MockDataType::plain();
        let existing = MockDataType::plain();
        BUILT_IN_MANAGER_HANDLER.resolve_conflict(&added, &existing);
    }

    #[test]
    fn conflict_resolution_policy_returns_matching_handler() {
        let added = MockDataType::plain();
        let existing = MockDataType::plain();
        assert_eq!(
            ConflictResolutionPolicy::RenameAndAdd.get_handler().resolve_conflict(&added, &existing),
            ConflictResult::RenameAndAdd
        );
        assert_eq!(
            ConflictResolutionPolicy::UseExisting.get_handler().resolve_conflict(&added, &existing),
            ConflictResult::UseExisting
        );
        assert_eq!(
            ConflictResolutionPolicy::ReplaceExisting.get_handler().resolve_conflict(&added, &existing),
            ConflictResult::ReplaceExisting
        );
        assert_eq!(
            ConflictResolutionPolicy::ReplaceEmptyStructsOrRenameAndAdd
                .get_handler()
                .resolve_conflict(&added, &existing),
            ConflictResult::RenameAndAdd
        );
    }

    struct MockDataTypeConflictHandler;
    impl DataTypeConflictHandler for MockDataTypeConflictHandler {}

    #[test]
    fn bare_impl_uses_defaults() {
        let handler = MockDataTypeConflictHandler;
        let added = MockDataType::plain();
        let existing = MockDataType::plain();
        assert_eq!(
            handler.resolve_conflict(&added, &existing),
            ConflictResult::RenameAndAdd
        );
        assert!(!handler.should_update(&added, &existing));
        assert!(std::ptr::eq(
            handler.get_subsequent_handler() as *const dyn DataTypeConflictHandler as *const (),
            &KEEP_HANDLER as *const KeepHandlerImpl as *const ()
        ));
    }
}
