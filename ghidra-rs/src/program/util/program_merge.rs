//! Merges the differences between two programs from an "origin" program into a "result"
//! program.
//!
//! Port of `ghidra.program.util.ProgramMerge`. `ProgramMerge` was selected as a dependency-cycle
//! cut-point, so it is ported here as a trait rather than a concrete struct: its public API
//! (constructors excepted, see below) becomes [`ProgramMerge`], letting callers depend on
//! `Box<dyn ProgramMerge>`/`Arc<dyn ProgramMerge>` without pulling in a concrete merge
//! implementation (and, transitively, the `SymbolMerge`/`FunctionMerge` helpers and the
//! `AddressTranslator` a concrete implementation would hold).
//!
//! Not ported here:
//! - Both constructors (`ProgramMerge(Program, Program)` and
//!   `ProgramMerge(AddressTranslator)`), which are construction-time details for a concrete
//!   implementation, not part of the dynamic-dispatch surface this trait exists to cut the cycle
//!   for (the same convention already followed by
//!   [`UnsupportedMapDB`](crate::program::database::properties::UnsupportedMapDB) and
//!   [`RangeMapAdapter`](crate::program::util::RangeMapAdapter)).
//! - Package-private methods (`clearMessages`, the `AddressSetView`-only overload of
//!   `mergeProgramContext`, the `Address`-only overload of `mergeEquates`,
//!   `reApplyDuplicateEquates`/`getDuplicateEquatesInfo`/`clearDuplicateEquates`, the 5-argument
//!   overload of `mergeLabels`, `reApplyDuplicateSymbols`/`getDuplicateSymbolsInfo`/
//!   `clearDuplicateSymbols`, and `mergeBookmarks`) and all `private` helper methods: none of
//!   these are reachable outside the class, so they carry no dynamic-dispatch obligation.
//! - The package-private static `overlapsOtherFunctions` helpers and the commented-out/`FIXME`
//!   methods already dead in the Java source (`replaceExternalDataType`,
//!   `mergeFunctionParameterOffset`, `replaceStackRange`).
//!
//! `ProgramMerge`'s "one for one translator" precondition checks
//! (`originToResultTranslator.isOneForOneTranslator()`) throw Java's unchecked
//! `UnsupportedOperationException`; per this crate's convention for unchecked exceptions (see
//! [`FunctionManager`](crate::program::model::listing::function_manager::FunctionManager)),
//! implementations of the affected methods below should panic rather than return a checked
//! error.

use std::sync::Arc;

use thiserror::Error;

use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::listing::{Function, FunctionTag, Program, Variable};
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::symbol::{Namespace, Reference, SymbolTable, SymbolType};
use crate::program::model::listing::CommentType;
use crate::framework::store::LockException;
use crate::util::exception::{CancelledException, DuplicateNameException, InvalidInputException};
use crate::util::task::TaskMonitor;

/// Suffix attached to a symbol/function/variable name, followed by a one-up number, to create a
/// new unique name when a merge conflict occurs.
///
/// Port of `ProgramMerge.SYMBOL_CONFLICT_SUFFIX`.
pub const SYMBOL_CONFLICT_SUFFIX: &str = "_conflict";

/// Combines the checked exceptions declared on `ProgramMerge.mergeBytes`/`mergeCodeUnits`.
#[derive(Error, Debug, PartialEq)]
pub enum MemoryMergeError {
    #[error(transparent)]
    Memory(#[from] MemoryAccessException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Combines the checked exceptions declared on `ProgramMerge.replaceFunctionParameterName`/
/// `replaceFunctionVariableName`.
#[derive(Error, Debug, PartialEq)]
pub enum FunctionMemberRenameError {
    #[error(transparent)]
    DuplicateName(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// Merges the differences between two programs from an origin program into a result program.
///
/// Port of `ghidra.program.util.ProgramMerge`. See the module docs for what was intentionally
/// left out of this trait.
pub trait ProgramMerge {
    /// Gets the result program. Merge changes are applied to this program.
    fn get_result_program(&self) -> Arc<dyn Program>;

    /// Gets the origin program, used for obtaining things to merge into the result program.
    fn get_origin_program(&self) -> Arc<dyn Program>;

    /// True if there is a current error message.
    fn has_error_message(&self) -> bool;

    /// True if there is a current informational message.
    fn has_info_message(&self) -> bool;

    /// Gets the error messages resulting from the last merge/replace call. Errors describe things
    /// that prevented something from being merged.
    fn get_error_message(&self) -> String;

    /// Gets the informational messages resulting from the last merge/replace call. These
    /// describe non-critical changes that were necessary during the merge (e.g. a symbol given a
    /// conflict-suffixed name).
    fn get_info_message(&self) -> String;

    /// Clears the current error message.
    fn clear_error_message(&mut self);

    /// Clears the current informational message.
    fn clear_info_message(&mut self);

    /// Merges byte differences within `origin_address_set` into the result program.
    ///
    /// Any instructions at the equivalent byte addresses in the result program get cleared and
    /// re-created (dropping existing references) if `overwrite_instructions` is set.
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `UnsupportedOperationException`) if
    /// this merge's translator is not a "one for one translator".
    fn merge_bytes(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        overwrite_instructions: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MemoryMergeError>;

    /// Merges all instructions and/or data in `origin_address_set` from the origin program into
    /// the result program. `byte_diffs` indicates addresses (derived from the origin program)
    /// where the bytes differ between the two programs; `merge_data_bytes` controls whether
    /// differing bytes are copied when merging `Data`.
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `UnsupportedOperationException`) if
    /// this merge's translator is not a "one for one translator".
    fn merge_code_units(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        byte_diffs: &dyn AddressSetView,
        merge_data_bytes: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MemoryMergeError>;

    /// Merges the equate differences in `origin_address_set` into the result program.
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `UnsupportedOperationException`) if
    /// this merge's translator is not a "one for one translator".
    fn merge_equates(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Replaces the current equate (if any) in the result program, at `origin_address`/`op_index`
    /// for the given scalar `value`, with the origin program's equate.
    fn merge_equate(&mut self, origin_address: &Address, op_index: i32, value: i64);

    /// Replaces all references in the result program for `origin_address_set` with those from the
    /// origin program (equivalent to calling
    /// [`replace_references_filtered`](Self::replace_references_filtered) with
    /// `only_keep_defaults = false`).
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `UnsupportedOperationException`) if
    /// this merge's translator is not a "one for one translator".
    fn replace_references(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Replaces all references in the result program for `origin_address_set` with those from the
    /// origin program. If `only_keep_defaults` is true, only the origin program's default
    /// references are used to replace what's in the result program.
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `UnsupportedOperationException`) if
    /// this merge's translator is not a "one for one translator".
    fn replace_references_filtered(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        only_keep_defaults: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Merges the references in `origin_address_set` from the origin program into the result
    /// program, preserving any non-default references already present in the result program.
    /// Fallthrough references are never merged (they are handled by code unit merging).
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `UnsupportedOperationException`) if
    /// this merge's translator is not a "one for one translator".
    fn merge_references(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        only_keep_defaults: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Replaces all references in the result program for the code unit at `origin_address`'s
    /// `operand_index` with those from the origin program.
    fn replace_references_at_operand(&mut self, origin_address: &Address, operand_index: i32);

    /// Replaces `result_ref` (if any) with a reference equivalent to `origin_ref` (if any).
    /// Returns the resulting reference in the result program, or `None` if the reference was
    /// removed by the replace.
    fn replace_reference(
        &mut self,
        result_ref: Option<&dyn Reference>,
        origin_ref: Option<&dyn Reference>,
    ) -> Option<Box<dyn Reference>>;

    /// As [`replace_reference`](Self::replace_reference), but associates the resulting reference
    /// with the symbol whose ID is `to_symbol_id` in the result program.
    fn replace_reference_with_symbol(
        &mut self,
        result_ref: Option<&dyn Reference>,
        origin_ref: Option<&dyn Reference>,
        to_symbol_id: i64,
    ) -> Option<Box<dyn Reference>>;

    /// Creates a reference in the result program equivalent to `origin_ref`. If `to_symbol_id`
    /// resolves to a symbol in the result program, the reference is associated with it. If
    /// `origin_ref` is an external reference and `replace_ext_loc` is set, the associated external
    /// location is replaced with the one from `origin_ref` as well. Returns the created
    /// reference, or `None` if none was created.
    fn add_reference(
        &mut self,
        origin_ref: Option<&dyn Reference>,
        to_symbol_id: i64,
        replace_ext_loc: bool,
    ) -> Option<Box<dyn Reference>>;

    /// Replaces all fallthroughs in the result program for `origin_address_set` with those from
    /// the origin program, where they differ.
    fn replace_fall_throughs(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Merges/replaces comments of the given `comment_type` (a
    /// [`ProgramMergeFilter`](crate::program::util::ProgramMergeFilter) comment-type constant:
    /// `PLATE_COMMENTS`, `PRE_COMMENTS`, `EOL_COMMENTS`, `REPEATABLE_COMMENTS`, or
    /// `POST_COMMENTS`) wherever they occur in `origin_address_set`. `both = true` merges both
    /// programs' comments; `both = false` replaces the result program's comment with the origin
    /// program's.
    fn merge_comment(
        &mut self,
        origin_address_set: &AddressSet,
        comment_type: u32,
        both: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Merges/replaces comments of the given `comment_type` wherever they occur in
    /// `origin_address_set`, from the origin program into the result program. `setting` is a
    /// [`ProgramMergeFilter`](crate::program::util::ProgramMergeFilter) merge setting
    /// (`IGNORE`/`REPLACE`/`MERGE`); any other value is a no-op.
    fn merge_comment_type(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        comment_type: u32,
        setting: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Merges the comment of the given type in the result program with the comment in the origin
    /// program at `origin_address`.
    fn merge_comments(&mut self, comment_type: CommentType, origin_address: &Address);

    /// Replaces the comment of the given type in the result program with the comment in the
    /// origin program at `origin_address`.
    fn replace_comment(&mut self, comment_type: CommentType, origin_address: &Address);

    /// Merges/replaces function tags of the origin program into the result program within
    /// `origin_address_set`. `setting` is a
    /// [`ProgramMergeFilter`](crate::program::util::ProgramMergeFilter) merge setting
    /// (`IGNORE`/`REPLACE`/`MERGE`; any other value is a no-op). When merging, `discard_tags` are
    /// removed from the merged result and `keep_tags` are ensured to be present.
    fn apply_function_tag_changes(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        setting: i32,
        discard_tags: &[Box<dyn FunctionTag>],
        keep_tags: &[Box<dyn FunctionTag>],
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Merges all symbols and aliases in `origin_address_set` from the origin program into the
    /// result program (equivalent to the package-private 5-argument overload with
    /// `replace_primary = true` and `replace_function = true`). `setting` is the current merge
    /// label setting.
    fn merge_labels(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        setting: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Replaces all symbols and aliases in `origin_address_set` in the result program with those
    /// from the origin program. `replace_function` indicates the function symbol should also be
    /// replaced.
    fn replace_labels(
        &mut self,
        origin_address_set: &AddressSet,
        replace_function: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Replaces function names and namespaces within `origin_address_set` with those from the
    /// origin program.
    fn replace_function_names(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Merges function differences within `addr_set`: removes result-program functions that have
    /// no counterpart in the origin program, then replaces the rest from the origin program.
    fn merge_functions(
        &mut self,
        addr_set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Completely replaces any function at `entry` (an address in the result program) with the
    /// function, if any, at the equivalent address in the origin program. Returns the function
    /// that was created in the result program, or `None` if none was created (call
    /// [`get_error_message`](Self::get_error_message) to check for a failure in that case).
    fn merge_function(
        &mut self,
        entry: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Arc<dyn Function>>, CancelledException>;

    /// Replaces the return type/storage of the function in the result program with that of the
    /// function in the origin program at `entry2` (an origin-program address).
    fn merge_function_return(&mut self, entry2: &Address);

    /// Replaces the name of the function in the result program with the name of the function in
    /// the origin program at `entry2` (an origin-program address).
    fn merge_function_name(&mut self, entry2: &Address, monitor: &dyn TaskMonitor);

    /// Changes the result function's signature source to match the origin function's signature
    /// source, at `origin_entry_point` (an origin-program address).
    fn replace_function_signature_source(&mut self, origin_entry_point: &Address, monitor: &dyn TaskMonitor);

    /// Replaces the return address offset of the function in the result program with that of the
    /// function in the origin program at `entry2` (an origin-program address).
    fn merge_function_return_address_offset(&mut self, entry2: &Address, monitor: &dyn TaskMonitor);

    /// Replaces the local size of the function in the result program with that of the function in
    /// the origin program at `entry2` (an origin-program address).
    fn merge_function_local_size(&mut self, entry2: &Address, monitor: &dyn TaskMonitor);

    /// Replaces the stack purge size of the function in the result program with that of the
    /// function in the origin program at `entry2` (an origin-program address).
    fn merge_function_stack_purge_size(&mut self, entry2: &Address, monitor: &dyn TaskMonitor);

    /// Changes whether the function at `entry2` (an address in the result program) has var-args,
    /// if it doesn't match the function at the same entry point in the origin program.
    fn replace_function_var_args(&mut self, entry2: &Address, monitor: &dyn TaskMonitor);

    /// Changes the calling convention of the function at `origin_entry_point` (an origin-program
    /// address) in the result program, if it doesn't match the origin program's function.
    fn replace_function_calling_convention(&mut self, origin_entry_point: &Address, monitor: &dyn TaskMonitor);

    /// Changes whether the function at `origin_entry_point` (an origin-program address) is inline
    /// in the result program, if it doesn't match the origin program's function.
    fn replace_function_inline_flag(&mut self, origin_entry_point: &Address, monitor: &dyn TaskMonitor);

    /// Changes the "does not return" flag of the function at `origin_entry_point` (an
    /// origin-program address) in the result program, if it doesn't match the origin program's
    /// function.
    fn replace_function_no_return_flag(&mut self, origin_entry_point: &Address, monitor: &dyn TaskMonitor);

    /// Changes the "custom variable storage" flag of the function at `origin_entry_point` (an
    /// origin-program address) in the result program, if it doesn't match the origin program's
    /// function.
    fn replace_function_custom_storage_flag(&mut self, origin_entry_point: &Address, monitor: &dyn TaskMonitor);

    /// Replaces the parameters (and return type/storage, and custom-storage use) of the function
    /// at `origin_entry_point` (an origin-program address) in the result program with those of
    /// the origin program's function.
    fn replace_function_parameters(&mut self, origin_entry_point: &Address, monitor: &dyn TaskMonitor);

    /// As [`replace_function_parameters`](Self::replace_function_parameters), but operating
    /// directly on a target/source function pair rather than looking them up by address.
    fn replace_function_parameters_between(&mut self, to_func: Arc<dyn Function>, from_func: Arc<dyn Function>);

    /// Replaces the external result function `to_function` with `from_function`. Does not create
    /// or place the function in its parent namespace; that must be done separately. Returns the
    /// new function created in the result program, or `None` if none was created (call
    /// [`get_error_message`](Self::get_error_message) to check for a failure in that case).
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `UnsupportedOperationException`) if
    /// this merge's translator is not a "one for one translator". Implementations should also
    /// panic (standing in for Java's `IllegalArgumentException`) if either function is not
    /// external.
    fn replace_external_function(
        &mut self,
        to_function: Arc<dyn Function>,
        from_function: Arc<dyn Function>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Arc<dyn Function>>, CancelledException>;

    /// Replaces the name of the `ordinal`-th parameter of the function at `origin_entry_point` (an
    /// origin-program address) in the result program with the name from the origin program.
    fn replace_function_parameter_name(
        &mut self,
        origin_entry_point: &Address,
        ordinal: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), FunctionMemberRenameError>;

    /// Replaces the data type of the `ordinal`-th parameter of the function at
    /// `origin_entry_point` (an origin-program address) in the result program with the data type
    /// from the origin program.
    fn replace_function_parameter_data_type(&mut self, origin_entry_point: &Address, ordinal: i32, monitor: &dyn TaskMonitor);

    /// Replaces the comment of the `ordinal`-th parameter of the function at `origin_entry_point`
    /// (an origin-program address) in the result program with the comment from the origin
    /// program.
    fn replace_function_parameter_comment(&mut self, origin_entry_point: &Address, ordinal: i32, monitor: &dyn TaskMonitor);

    /// Replaces the local variable in the result program's function at `origin_entry_point` (an
    /// origin-program address) equivalent to `var` with the matching variable from the origin
    /// program's function.
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `IllegalArgumentException`) if `var`
    /// is a parameter; use [`replace_function_parameter_name`](Self::replace_function_parameter_name)
    /// and its siblings for parameters instead.
    fn replace_function_variable(&mut self, origin_entry_point: &Address, var: &dyn Variable, monitor: &dyn TaskMonitor);

    /// Replaces the function variables/parameters (matched from `var_list`) in the result
    /// program's function at `origin_entry_point` (an origin-program address) with those from the
    /// origin program's function.
    fn replace_variables(
        &mut self,
        origin_entry_point: &Address,
        var_list: &[Box<dyn Variable>],
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Replaces the name of the result program's variable equivalent to `var` with the name of the
    /// matching variable in the origin program. Delegates to
    /// [`replace_function_parameter_name`](Self::replace_function_parameter_name) if `var` is a
    /// parameter.
    fn replace_function_variable_name(
        &mut self,
        origin_entry_point: &Address,
        var: &dyn Variable,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), FunctionMemberRenameError>;

    /// Replaces the data type of the result program's variable equivalent to `var` with the data
    /// type of the matching variable in the origin program. Delegates to
    /// [`replace_function_parameter_data_type`](Self::replace_function_parameter_data_type) if
    /// `var` is a parameter.
    fn replace_function_variable_data_type(&mut self, origin_entry_point: &Address, var: &dyn Variable, monitor: &dyn TaskMonitor);

    /// Replaces the comment of the result program's variable equivalent to `var` with the comment
    /// of the matching variable in the origin program. Delegates to
    /// [`replace_function_parameter_comment`](Self::replace_function_parameter_comment) if `var`
    /// is a parameter.
    fn replace_function_variable_comment(&mut self, origin_entry_point: &Address, var: &dyn Variable, monitor: &dyn TaskMonitor);

    /// Merges the bookmark of the given `bookmark_type`/`category` from the origin program into
    /// the result program at the address equivalent to `origin_address`, without affecting other
    /// bookmarks at that address.
    fn merge_bookmark(
        &mut self,
        origin_address: &Address,
        bookmark_type: &str,
        category: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Merges user-defined property differences within `origin_address_set` from the origin
    /// program into the result program.
    ///
    /// # Panics
    /// Implementations should panic (standing in for Java's `UnsupportedOperationException`) if
    /// this merge's translator is not a "one for one translator".
    fn merge_properties(
        &mut self,
        origin_address_set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Replaces the user-defined property named `user_property_name` from the specified origin
    /// address in the origin program into the equivalent result address in the result program.
    /// The result program must already have a code unit at the equivalent address.
    fn merge_user_property(&mut self, user_property_name: &str, origin_address: &Address);

    /// Merges the source map information from `origin_addrs` in the origin program into the
    /// result program. `settings` are the merge settings for this feature.
    fn apply_source_map_differences(
        &mut self,
        origin_addrs: &AddressSet,
        settings: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), LockException>;
}

/// Create a name that is unique for `symbol_type`-typed symbols in `namespace1` and, if given,
/// `namespace2`.
///
/// Port of both overloads of the static `ProgramMerge.getUniqueName` helper: passing `None` for
/// `namespace2` corresponds to the single-namespace overload. `symbol_table` is used to detect
/// name collisions; on a collision, [`SYMBOL_CONFLICT_SUFFIX`] plus a one-up counter is appended
/// until a free name is found.
///
/// Unlike the Java original's private `isUniqueSymbolName` helper (which also checks whether any
/// non-duplicate-allowing symbol with `name` exists anywhere in the namespace, not just at
/// `address`), this only checks for a colliding symbol at `address` itself: a namespace-wide "all
/// symbols with this name" query isn't available yet on [`SymbolTable`]. It also does not
/// replicate the Java method's external-address short-circuit (`address.isExternalAddress()`),
/// since no equivalent check exists yet on [`Address`]. Both should be tightened once
/// `SymbolTable` grows the relevant query.
pub fn get_unique_name(
    symbol_table: &dyn SymbolTable,
    name: &str,
    address: &Address,
    namespace1: &dyn Namespace,
    namespace2: Option<&dyn Namespace>,
    symbol_type: SymbolType,
) -> String {
    let mut candidate = name.to_string();
    for i in 1..i32::MAX {
        let ok1 = is_unique_symbol_name(symbol_table, namespace1, &candidate, address, symbol_type);
        let ok2 = namespace2
            .map(|ns| is_unique_symbol_name(symbol_table, ns, &candidate, address, symbol_type))
            .unwrap_or(true);
        if ok1 && ok2 {
            return candidate;
        }
        candidate = format!("{name}{SYMBOL_CONFLICT_SUFFIX}{i}");
    }
    candidate
}

fn is_unique_symbol_name(
    symbol_table: &dyn SymbolTable,
    namespace: &dyn Namespace,
    name: &str,
    address: &Address,
    symbol_type: SymbolType,
) -> bool {
    let namespace_id = namespace.get_symbol().get_id();
    let colliding = symbol_table
        .get_symbols(address)
        .unwrap_or_default()
        .into_iter()
        .any(|symbol| {
            symbol.get_name() == name
                && symbol
                    .get_parent_namespace()
                    .map(|ns| ns.get_symbol().get_id())
                    .unwrap_or(-1)
                    == namespace_id
        });
    if colliding {
        return false;
    }
    // Java's `isUniqueSymbolName` also fails if any non-duplicate-allowing symbol exists
    // anywhere in the namespace with this name; that whole-namespace query isn't available yet
    // (see the doc comment on `get_unique_name`), so only the same-address collision above is
    // checked.
    let _ = symbol_type;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{Symbol, SymbolType};
    use crate::program::model::symbol::SourceType;
    use crate::util::task::DummyMonitor;
    use std::cell::RefCell;
    use std::io;
    use std::sync::Arc;

    fn ram_address(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    /// Minimal mock proving [`ProgramMerge`] is object-safe and that a merge operation actually
    /// mutates accumulated state (error/info messages) rather than just returning defaults.
    struct MockProgramMerge {
        result_program: Arc<dyn Program>,
        origin_program: Arc<dyn Program>,
        error_msg: RefCell<String>,
        info_msg: RefCell<String>,
        one_for_one: bool,
    }

    struct MockProgram(&'static str);
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    impl MockProgramMerge {
        fn new(one_for_one: bool) -> Self {
            MockProgramMerge {
                result_program: Arc::new(MockProgram("result")),
                origin_program: Arc::new(MockProgram("origin")),
                error_msg: RefCell::new(String::new()),
                info_msg: RefCell::new(String::new()),
                one_for_one,
            }
        }
    }

    impl ProgramMerge for MockProgramMerge {
        fn get_result_program(&self) -> Arc<dyn Program> {
            self.result_program.clone()
        }

        fn get_origin_program(&self) -> Arc<dyn Program> {
            self.origin_program.clone()
        }

        fn has_error_message(&self) -> bool {
            !self.error_msg.borrow().is_empty()
        }

        fn has_info_message(&self) -> bool {
            !self.info_msg.borrow().is_empty()
        }

        fn get_error_message(&self) -> String {
            self.error_msg.borrow().clone()
        }

        fn get_info_message(&self) -> String {
            self.info_msg.borrow().clone()
        }

        fn clear_error_message(&mut self) {
            self.error_msg.borrow_mut().clear();
        }

        fn clear_info_message(&mut self) {
            self.info_msg.borrow_mut().clear();
        }

        fn merge_bytes(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            _overwrite_instructions: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), MemoryMergeError> {
            if !self.one_for_one {
                panic!("not a one for one translator");
            }
            Ok(())
        }

        fn merge_code_units(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            _byte_diffs: &dyn AddressSetView,
            _merge_data_bytes: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), MemoryMergeError> {
            Ok(())
        }

        fn merge_equates(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_equate(&mut self, _origin_address: &Address, _op_index: i32, _value: i64) {}

        fn replace_references(
            &mut self,
            origin_address_set: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.replace_references_filtered(origin_address_set, false, monitor)
        }

        fn replace_references_filtered(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            _only_keep_defaults: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_references(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            _only_keep_defaults: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn replace_references_at_operand(&mut self, _origin_address: &Address, _operand_index: i32) {}

        fn replace_reference(
            &mut self,
            _result_ref: Option<&dyn Reference>,
            _origin_ref: Option<&dyn Reference>,
        ) -> Option<Box<dyn Reference>> {
            None
        }

        fn replace_reference_with_symbol(
            &mut self,
            _result_ref: Option<&dyn Reference>,
            _origin_ref: Option<&dyn Reference>,
            _to_symbol_id: i64,
        ) -> Option<Box<dyn Reference>> {
            None
        }

        fn add_reference(
            &mut self,
            _origin_ref: Option<&dyn Reference>,
            _to_symbol_id: i64,
            _replace_ext_loc: bool,
        ) -> Option<Box<dyn Reference>> {
            None
        }

        fn replace_fall_throughs(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_comment(
            &mut self,
            _origin_address_set: &AddressSet,
            _comment_type: u32,
            _both: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_comment_type(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            _comment_type: u32,
            _setting: i32,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_comments(&mut self, _comment_type: CommentType, _origin_address: &Address) {}

        fn replace_comment(&mut self, _comment_type: CommentType, _origin_address: &Address) {}

        fn apply_function_tag_changes(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            _setting: i32,
            _discard_tags: &[Box<dyn FunctionTag>],
            _keep_tags: &[Box<dyn FunctionTag>],
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_labels(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            _setting: i32,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn replace_labels(
            &mut self,
            _origin_address_set: &AddressSet,
            _replace_function: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn replace_function_names(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_functions(
            &mut self,
            _addr_set: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_function(
            &mut self,
            _entry: &Address,
            monitor: &dyn TaskMonitor,
        ) -> Result<Option<Arc<dyn Function>>, CancelledException> {
            monitor.check_cancelled()?;
            self.error_msg.borrow_mut().push_str("no function to merge\n");
            Ok(None)
        }

        fn merge_function_return(&mut self, _entry2: &Address) {}

        fn merge_function_name(&mut self, _entry2: &Address, _monitor: &dyn TaskMonitor) {}

        fn replace_function_signature_source(&mut self, _origin_entry_point: &Address, _monitor: &dyn TaskMonitor) {}

        fn merge_function_return_address_offset(&mut self, _entry2: &Address, _monitor: &dyn TaskMonitor) {}

        fn merge_function_local_size(&mut self, _entry2: &Address, _monitor: &dyn TaskMonitor) {}

        fn merge_function_stack_purge_size(&mut self, _entry2: &Address, _monitor: &dyn TaskMonitor) {}

        fn replace_function_var_args(&mut self, _entry2: &Address, _monitor: &dyn TaskMonitor) {}

        fn replace_function_calling_convention(&mut self, _origin_entry_point: &Address, _monitor: &dyn TaskMonitor) {}

        fn replace_function_inline_flag(&mut self, _origin_entry_point: &Address, _monitor: &dyn TaskMonitor) {}

        fn replace_function_no_return_flag(&mut self, _origin_entry_point: &Address, _monitor: &dyn TaskMonitor) {}

        fn replace_function_custom_storage_flag(&mut self, _origin_entry_point: &Address, _monitor: &dyn TaskMonitor) {}

        fn replace_function_parameters(&mut self, _origin_entry_point: &Address, _monitor: &dyn TaskMonitor) {}

        fn replace_function_parameters_between(&mut self, _to_func: Arc<dyn Function>, _from_func: Arc<dyn Function>) {}

        fn replace_external_function(
            &mut self,
            _to_function: Arc<dyn Function>,
            _from_function: Arc<dyn Function>,
            monitor: &dyn TaskMonitor,
        ) -> Result<Option<Arc<dyn Function>>, CancelledException> {
            monitor.check_cancelled()?;
            Ok(None)
        }

        fn replace_function_parameter_name(
            &mut self,
            _origin_entry_point: &Address,
            _ordinal: i32,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), FunctionMemberRenameError> {
            Ok(())
        }

        fn replace_function_parameter_data_type(&mut self, _origin_entry_point: &Address, _ordinal: i32, _monitor: &dyn TaskMonitor) {}

        fn replace_function_parameter_comment(&mut self, _origin_entry_point: &Address, _ordinal: i32, _monitor: &dyn TaskMonitor) {}

        fn replace_function_variable(&mut self, _origin_entry_point: &Address, var: &dyn Variable, _monitor: &dyn TaskMonitor) {
            let _ = var;
        }

        fn replace_variables(
            &mut self,
            _origin_entry_point: &Address,
            _var_list: &[Box<dyn Variable>],
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn replace_function_variable_name(
            &mut self,
            _origin_entry_point: &Address,
            _var: &dyn Variable,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), FunctionMemberRenameError> {
            Ok(())
        }

        fn replace_function_variable_data_type(&mut self, _origin_entry_point: &Address, _var: &dyn Variable, _monitor: &dyn TaskMonitor) {}

        fn replace_function_variable_comment(&mut self, _origin_entry_point: &Address, _var: &dyn Variable, _monitor: &dyn TaskMonitor) {}

        fn merge_bookmark(
            &mut self,
            _origin_address: &Address,
            _bookmark_type: &str,
            _category: &str,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_properties(
            &mut self,
            _origin_address_set: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn merge_user_property(&mut self, _user_property_name: &str, _origin_address: &Address) {}

        fn apply_source_map_differences(
            &mut self,
            _origin_addrs: &AddressSet,
            _settings: i32,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), LockException> {
            Ok(())
        }
    }

    #[test]
    fn merge_function_records_info_when_nothing_to_merge() {
        let mut merge: Box<dyn ProgramMerge> = Box::new(MockProgramMerge::new(true));
        assert!(!merge.has_error_message());

        let monitor = DummyMonitor;
        let result = merge.merge_function(&ram_address(0x400000), &monitor).unwrap();

        assert!(result.is_none());
        assert!(merge.has_error_message());
        assert_eq!(merge.get_error_message(), "no function to merge\n");

        merge.clear_error_message();
        assert!(!merge.has_error_message());
    }

    #[test]
    #[should_panic(expected = "not a one for one translator")]
    fn merge_bytes_panics_when_not_one_for_one() {
        let mut merge = MockProgramMerge::new(false);
        let monitor = DummyMonitor;
        let addr_set = AddressSet::new();
        let _ = merge.merge_bytes(&addr_set, false, &monitor);
    }

    struct MockSymbol {
        id: i64,
        name: &'static str,
        namespace_id: Option<i64>,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            ram_address(0x1000)
        }
        fn get_name(&self) -> &str {
            self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            self.namespace_id.unwrap_or(0)
        }
    }

    struct MockNamespace {
        symbol_id: i64,
    }

    impl crate::program::model::symbol::Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol {
                id: self.symbol_id,
                name: "ns",
                namespace_id: None,
            })
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
    }

    struct MockSymbolTable {
        symbols_at_address: Vec<Arc<dyn Symbol>>,
    }

    impl SymbolTable for MockSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!()
        }

        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }

        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self.symbols_at_address.clone())
        }
    }

    #[test]
    fn get_unique_name_appends_conflict_suffix_on_collision() {
        let ns = MockNamespace { symbol_id: 7 };
        let existing = MockSymbol {
            id: 1,
            name: "foo",
            namespace_id: Some(7),
        };
        // Wire the mock symbol's parent namespace id to match `ns` via a wrapper, since
        // `MockSymbol` itself always reports `get_parent_namespace() == None` (the trait
        // default); route through a thin adapter instead.
        struct WithNamespace(MockSymbol, Arc<dyn crate::program::model::symbol::Namespace>);
        impl Symbol for WithNamespace {
            fn get_address(&self) -> Address {
                self.0.get_address()
            }
            fn get_name(&self) -> &str {
                self.0.get_name()
            }
            fn get_symbol_type(&self) -> SymbolType {
                self.0.get_symbol_type()
            }
            fn get_source(&self) -> SourceType {
                self.0.get_source()
            }
            fn is_primary(&self) -> bool {
                self.0.is_primary()
            }
            fn get_id(&self) -> i64 {
                self.0.get_id()
            }
            fn get_parent_id(&self) -> i64 {
                self.0.get_parent_id()
            }
            fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
                Some(self.1.clone())
            }
        }

        let ns_arc: Arc<dyn crate::program::model::symbol::Namespace> = Arc::new(MockNamespace { symbol_id: 7 });
        let table = MockSymbolTable {
            symbols_at_address: vec![Arc::new(WithNamespace(existing, ns_arc))],
        };

        let name = get_unique_name(
            &table,
            "foo",
            &ram_address(0x1000),
            &ns,
            None,
            SymbolType::Label,
        );

        assert_eq!(name, "foo_conflict1");
    }
}
