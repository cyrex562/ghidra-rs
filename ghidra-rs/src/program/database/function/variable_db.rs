//! Port of `ghidra.program.database.function.VariableDB`, promoted to a trait mirroring
//! [`VariableImpl`](crate::program::model::listing::variable_impl::VariableImpl) (a `pub trait Foo:
//! Variable` with `foo_*`-prefixed default methods) rather than
//! [`FunctionDb`](crate::program::database::function::FunctionDb)'s bare-cut-point shape, since
//! `VariableDB` (unlike `FunctionDB`) is not itself constructed *by* one of its own dependencies --
//! it is composed by exactly the sibling classes this port is landing alongside it
//! ([`LocalVariableDb`](crate::program::database::function::LocalVariableDb),
//! [`ParameterDb`](crate::program::database::function::ParameterDb), and later
//! `ReturnParameterDB`, which `extends ParameterDB` rather than `VariableDB` directly and so mostly
//! bypasses this trait).
//!
//! `VariableDB implements Variable`, modeled here as `pub trait VariableDb: Variable` exactly like
//! `VariableImpl`. The `symbol`/`function` fields are exposed as required accessors
//! ([`VariableDb::symbol`]/[`VariableDb::function`]), and the lazily-cached `storage` field (used
//! both to memoize `symbol.getVariableStorage()` and to persist storage set directly via
//! `setDynamicStorage`/`setStorageAndDataType`, bypassing the symbol) is exposed as
//! [`VariableDb::cached_storage`]/[`VariableDb::set_cached_storage`], mirroring
//! [`VariableImpl::stored_variable_storage`]'s identical accessor shape for the analogous field.
//!
//! ## What got a real default, and what didn't
//!
//! Every read-only `Variable` method `VariableDB` implements is ported as a real, faithful
//! `variable_db_*`-prefixed default method: [`is_valid`](VariableDb::variable_db_is_valid),
//! [`get_program`](VariableDb::variable_db_get_program),
//! [`get_data_type`](VariableDb::variable_db_get_data_type),
//! [`get_name`](VariableDb::variable_db_get_name),
//! [`get_comment`](VariableDb::variable_db_get_comment),
//! [`get_symbol`](VariableDb::variable_db_get_symbol),
//! [`get_source`](VariableDb::variable_db_get_source),
//! [`has_assigned_storage`](VariableDb::variable_db_has_assigned_storage),
//! [`get_variable_storage`](VariableDb::variable_db_get_variable_storage) (with the real lazy-cache
//! semantics), the varnode/register/stack/memory/unique/compound accessors, and
//! [`is_equivalent`](VariableDb::variable_db_is_equivalent)/[`compare_to`](VariableDb::variable_db_compare_to).
//! These all reach `self.get_data_type()`/`self.get_variable_storage()`/`self.get_first_use_offset()`
//! etc. through the `Variable` supertrait bound, which gives exactly the virtual-dispatch behavior
//! Java relies on (e.g. `ParameterDB`'s forced-indirect `getDataType()` override is honored
//! automatically by `variable_db_is_valid`, with no need to thread the resolved data type through
//! as a parameter).
//!
//! [`variable_db_set_name`](VariableDb::variable_db_set_name) and
//! [`variable_db_set_storage_and_data_type`](VariableDb::variable_db_set_storage_and_data_type)
//! (the package-private `setStorageAndDataType`) also get real defaults: neither Java method
//! touches `functionMgr`/locking, only `symbol`/`function.hasCustomVariableStorage()` (a `&self`
//! `Function` method), so [`VariableSymbolDb::rename`](crate::program::seam_stubs::VariableSymbolDb::rename)/
//! [`VariableSymbolDb::set_variable_storage_and_data_type`](crate::program::seam_stubs::VariableSymbolDb::set_variable_storage_and_data_type)
//! (both `&self`, added to that seam by this port for exactly this purpose) are enough.
//!
//! [`variable_db_set_comment`](VariableDb::variable_db_set_comment),
//! [`variable_db_set_data_type_with_storage`](VariableDb::variable_db_set_data_type_with_storage),
//! and [`variable_db_set_data_type_aligned`](VariableDb::variable_db_set_data_type_aligned) are left
//! as *required* methods with no default body, following the precedent set by
//! [`GhidraClassDb::set_parent_namespace`](crate::program::database::symbol::GhidraClassDb::set_parent_namespace):
//! their Java bodies call `FunctionDB.functionChanged`/`dataTypeChanged`/`updateParametersAndReturn`/
//! `updateSignatureSourceAfterVariableChange`, all `&mut self` methods on the already-landed
//! [`FunctionDb`] trait, which cannot be reached from a `&self` default method through the shared
//! `Arc<dyn FunctionDb>` this trait holds (the same "shared `Arc`, but the supertrait wants `&mut
//! self`" friction `GhidraClassDb` already documents for `Symbol::set_namespace`). Each required
//! method's doc comment reproduces the exact Java algorithm so a concrete implementor -- one that
//! holds its `FunctionDb` behind real interior mutability -- can complete it faithfully.
//! [`variable_db_set_data_type`](VariableDb::variable_db_set_data_type) (the two-argument overload)
//! *does* get a default, since its Java body is a pure one-line forward to the four-argument
//! `setDataType(type, true, false, source)` overload.
//!
//! [`variable_db_get_function`](VariableDb::variable_db_get_function) is also required, for a
//! related but distinct reason: `Variable::get_function` must return `Box<dyn Function>`, but this
//! trait only ever holds the owning function behind a shared `Arc<dyn FunctionDb>` -- `dyn Function`
//! has no `Clone`, so there is no portable way to manufacture an owned `Box` from a shared
//! reference. This mirrors
//! [`AutoParameterImpl::stored_function`](crate::program::model::listing::auto_parameter_impl::AutoParameterImpl::stored_function),
//! which required the identical accessor for the identical reason.
//!
//! [`variable_db_set_dynamic_storage`](VariableDb::variable_db_set_dynamic_storage) defaults to a
//! panic, standing in for `VariableDB.setDynamicStorage`'s unconditional
//! `UnsupportedOperationException` -- [`ParameterDb`](crate::program::database::function::ParameterDb)
//! overrides it with a real body.
//!
//! ## Left out of this port
//! - `equals`/`hashCode`/`toString`: no `Object` identity contract to satisfy in Rust (matching
//!   [`FunctionDb`]'s identical note); [`Variable::is_equivalent`] already fills the role `equals`
//!   played for value comparison.
//! - The package-private constructor: a concrete implementor's own constructor supplies
//!   `symbol`/`function` directly.
//! - The commented-out, dead `flushVariableStorage()` method (already commented out in the Java
//!   source).

use std::cmp::Ordering;
use std::sync::Arc;

use crate::program::database::function::FunctionDb;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
use crate::program::model::listing::variable_storage::{UnassignedStorage, VariableStorage};
use crate::program::model::listing::{Function, Program, Variable};
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::{SourceType, Symbol};
use crate::program::seam_stubs::VariableSymbolDb;
use crate::util::exception::InvalidInputException;

/// Database implementation of a [`Variable`].
///
/// Port of `ghidra.program.database.function.VariableDB` (see the module docs for the
/// default-vs-required method split and everything intentionally left out).
pub trait VariableDb: Variable {
    /// Backing storage for the `symbol` field.
    fn symbol(&self) -> Arc<dyn VariableSymbolDb>;

    /// Backing storage for the `function` field (`VariableDB.function`; `functionMgr` is reached
    /// via [`FunctionDb::function_manager`] rather than being cached separately here).
    fn function(&self) -> Arc<dyn FunctionDb>;

    /// Backing storage for the lazily-cached `storage` field. `None` means "not yet cached; fall
    /// back to `symbol.getVariableStorage()`".
    fn cached_storage(&self) -> Option<Box<dyn VariableStorage>>;

    /// Update the cached storage value.
    fn set_cached_storage(&self, storage: Option<Box<dyn VariableStorage>>);

    /// Default body for the protected `VariableDB.isVoidAllowed()` extension point. `false` for
    /// `LocalVariableDB`/`ParameterDB`; not overridden by either.
    fn variable_db_is_void_allowed(&self) -> bool {
        false
    }

    /// Default body for [`Variable::is_valid`]. Port of the `final` `VariableDB.isValid()`.
    fn variable_db_is_valid(&self) -> bool {
        let storage = self.variable_db_get_variable_storage();
        let dt = self.get_data_type();
        if dt.is_void_type() {
            return self.variable_db_is_void_allowed() && storage.is_void_storage();
        }
        if dt.get_length() <= 0 || !storage.is_valid() {
            return false;
        }
        storage.size() >= dt.get_length()
    }

    /// Default body for [`Variable::get_program`]. Port of `VariableDB.getProgram()`.
    fn variable_db_get_program(&self) -> Arc<dyn Program> {
        self.function().get_program()
    }

    /// Default body for [`Variable::get_data_type`]. Port of `VariableDB.getDataType()`.
    fn variable_db_get_data_type(&self) -> Box<dyn DataType> {
        self.symbol().variable_data_type()
    }

    /// Default body for [`Variable::get_length`]. Port of `VariableDB.getLength()`.
    fn variable_db_get_length(&self) -> i32 {
        self.get_data_type().get_length()
    }

    /// Default body for [`Variable::get_name`]. Port of `VariableDB.getName()`.
    fn variable_db_get_name(&self) -> Option<String> {
        Some(self.symbol().get_name().to_string())
    }

    /// Default body for [`Variable::set_name`]. Port of `VariableDB.setName(String, SourceType)`.
    fn variable_db_set_name(
        &self,
        name: &str,
        source: SourceType,
    ) -> Result<(), SetVariableNameError> {
        self.symbol().rename(name, source)
    }

    /// Default body for [`Variable::get_comment`]. Port of `VariableDB.getComment()`.
    fn variable_db_get_comment(&self) -> Option<String> {
        self.symbol().variable_symbol_comment()
    }

    /// Required body for [`Variable::set_comment`]. Port of `VariableDB.setComment(String)`:
    /// ```java
    /// public void setComment(String comment) {
    ///     symbol.setSymbolComment(comment);
    ///     functionMgr.functionChanged(function, null);
    /// }
    /// ```
    /// Left required (see module docs): a concrete implementor should call
    /// `self.symbol().set_variable_symbol_comment(comment)` followed by notifying its
    /// `FunctionDb` of the change (`FunctionDb::function_changed(None)`), which requires `&mut
    /// dyn FunctionDb` this trait cannot obtain from a shared `Arc` in a `&self` default method.
    fn variable_db_set_comment(&self, comment: Option<String>);

    /// Default body for [`Variable::get_function`]. Required (see module docs): `dyn Function` has
    /// no `Clone`, so there is no portable way to manufacture a `Box<dyn Function>` from the
    /// shared `Arc<dyn FunctionDb>` returned by [`VariableDb::function`].
    fn variable_db_get_function(&self) -> Option<Box<dyn Function>>;

    /// Default body for [`Variable::get_symbol`]. Port of `VariableDB.getSymbol()`.
    fn variable_db_get_symbol(&self) -> Option<Arc<dyn Symbol>> {
        Some(self.symbol())
    }

    /// Default body for [`Variable::get_source`]. Port of `VariableDB.getSource()`.
    fn variable_db_get_source(&self) -> SourceType {
        self.symbol().get_source()
    }

    /// Default body for [`Variable::has_assigned_storage`]. Port of
    /// `VariableDB.hasAssignedStorage()`.
    fn variable_db_has_assigned_storage(&self) -> bool {
        !self.symbol().variable_storage().is_unassigned_storage()
    }

    /// Default body for [`Variable::get_variable_storage`] (returning the storage directly rather
    /// than `Option`-wrapped, for use by this trait's other default methods). Port of
    /// `VariableDB.getVariableStorage()`'s lazy-cache semantics: once assigned (here, or via
    /// [`VariableDb::variable_db_set_storage_and_data_type`]/`ParameterDb::set_dynamic_storage`),
    /// the cached value is returned on every subsequent call rather than re-deriving it from the
    /// symbol.
    fn variable_db_get_variable_storage(&self) -> Box<dyn VariableStorage> {
        if let Some(cached) = self.cached_storage() {
            return cached;
        }
        let fresh = self.symbol().variable_storage();
        let for_cache = duplicate_storage(fresh.as_ref());
        self.set_cached_storage(Some(for_cache));
        fresh
    }

    /// Default body for [`Variable::get_first_storage_varnode`]. Port of
    /// `VariableDB.getFirstStorageVarnode()`.
    fn variable_db_get_first_storage_varnode(&self) -> Option<Varnode> {
        self.variable_db_get_variable_storage().get_first_varnode()
    }

    /// Default body for [`Variable::get_last_storage_varnode`]. Port of
    /// `VariableDB.getLastStorageVarnode()`.
    fn variable_db_get_last_storage_varnode(&self) -> Option<Varnode> {
        self.variable_db_get_variable_storage().get_last_varnode()
    }

    /// Default body for [`Variable::is_stack_variable`]. Port of `VariableDB.isStackVariable()`.
    fn variable_db_is_stack_variable(&self) -> bool {
        self.variable_db_get_variable_storage().is_stack_storage()
    }

    /// Default body for [`Variable::has_stack_storage`]. Port of `VariableDB.hasStackStorage()`.
    fn variable_db_has_stack_storage(&self) -> bool {
        self.variable_db_get_variable_storage().has_stack_storage()
    }

    /// Default body for [`Variable::is_register_variable`]. Port of
    /// `VariableDB.isRegisterVariable()`.
    fn variable_db_is_register_variable(&self) -> bool {
        self.variable_db_get_variable_storage().is_register_storage()
    }

    /// Default body for [`Variable::get_register`]. Port of `VariableDB.getRegister()`.
    fn variable_db_get_register(&self) -> Option<RegisterRef> {
        self.variable_db_get_variable_storage().get_register()
    }

    /// Default body for [`Variable::get_registers`]. Port of `VariableDB.getRegisters()`.
    fn variable_db_get_registers(&self) -> Option<Vec<RegisterRef>> {
        self.variable_db_get_variable_storage().get_registers()
    }

    /// Default body for [`Variable::get_min_address`]. Port of `VariableDB.getMinAddress()`.
    fn variable_db_get_min_address(&self) -> Option<Address> {
        self.variable_db_get_variable_storage().get_min_address()
    }

    /// Default body for [`Variable::get_stack_offset`]. Port of `VariableDB.getStackOffset()`.
    fn variable_db_get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
        Ok(self.variable_db_get_variable_storage().get_stack_offset())
    }

    /// Default body for [`Variable::is_memory_variable`]. Port of `VariableDB.isMemoryVariable()`.
    fn variable_db_is_memory_variable(&self) -> bool {
        self.variable_db_get_variable_storage().is_memory_storage()
    }

    /// Default body for [`Variable::is_unique_variable`]. Port of `VariableDB.isUniqueVariable()`
    /// (`variableStorage.isHashStorage()` in Java).
    fn variable_db_is_unique_variable(&self) -> bool {
        self.variable_db_get_variable_storage().is_hash_storage()
    }

    /// Default body for [`Variable::is_compound_variable`]. Port of
    /// `VariableDB.isCompoundVariable()`.
    fn variable_db_is_compound_variable(&self) -> bool {
        self.variable_db_get_variable_storage().is_compound_storage()
    }

    /// Required body for the package-private `VariableDB.setDynamicStorage(VariableStorage)`,
    /// standing in for its unconditional `throw new UnsupportedOperationException()`.
    /// [`ParameterDb`](crate::program::database::function::ParameterDb) overrides this with a real
    /// body.
    ///
    /// # Panics
    /// Always, unless overridden.
    fn variable_db_set_dynamic_storage(&self, _storage: Box<dyn VariableStorage>) {
        panic!("setDynamicStorage is not supported for this variable");
    }

    /// Default body for the package-private
    /// `VariableDB.setStorageAndDataType(VariableStorage, DataType)`.
    fn variable_db_set_storage_and_data_type(
        &self,
        new_storage: Box<dyn VariableStorage>,
        data_type: Box<dyn DataType>,
    ) {
        let new_storage: Box<dyn VariableStorage> =
            if self.is_parameter() && !self.function().has_custom_variable_storage() {
                Box::new(UnassignedStorage)
            } else {
                new_storage
            };
        let storage_for_symbol = duplicate_storage(new_storage.as_ref());
        self.symbol()
            .set_variable_storage_and_data_type(storage_for_symbol, data_type);
        self.set_cached_storage(Some(new_storage));
    }

    /// Required body for [`Variable::set_data_type_with_storage`]. Port of
    /// `VariableDB.setDataType(DataType, VariableStorage, boolean, SourceType)`:
    /// ```java
    /// public void setDataType(DataType type, VariableStorage newStorage, boolean force,
    ///         SourceType source) throws InvalidInputException, VariableSizeException {
    ///     try (Closeable c = functionMgr.lock.write()) {
    ///         function.startUpdate();
    ///         function.checkDeleted();
    ///         if ((this instanceof Parameter) && !function.hasCustomVariableStorage()) {
    ///             newStorage = VariableStorage.UNASSIGNED_STORAGE;
    ///         }
    ///         type = VariableUtilities.checkDataType(type, false, getLength(), function.getProgram());
    ///         if (!(this instanceof Parameter) || function.hasCustomVariableStorage()) {
    ///             newStorage = VariableUtilities.checkStorage(function, newStorage, type, force);
    ///             VariableUtilities.checkVariableConflict(function, this, newStorage, force);
    ///             setStorageAndDataType(newStorage, type);
    ///         }
    ///         else {
    ///             setStorageAndDataType(newStorage, type);
    ///             function.updateParametersAndReturn();
    ///         }
    ///         if (this instanceof Parameter) {
    ///             function.updateSignatureSourceAfterVariableChange(source, type);
    ///         }
    ///         function.dataTypeChanged(this);
    ///     }
    ///     finally {
    ///         function.endUpdate();
    ///     }
    /// }
    /// ```
    /// Left required (see module docs): reaches `function.updateParametersAndReturn()`/
    /// `updateSignatureSourceAfterVariableChange`/`dataTypeChanged`, all `&mut self` methods on
    /// [`FunctionDb`] unreachable from a `&self` default through a shared `Arc`. A concrete
    /// implementor should use
    /// [`VariableDb::variable_db_set_storage_and_data_type`] for the `setStorageAndDataType` call
    /// and [`crate::program::model::listing::variable_utilities::VariableUtilities`]'s
    /// `check_data_type`/`check_storage_for_function`/`check_variable_conflict` for the
    /// `VariableUtilities` calls (`function.startUpdate`/`checkDeleted`/`endUpdate` and the
    /// `functionMgr.lock` are implementation details of the concrete `FunctionDb`, already omitted
    /// from that trait's own port -- see its module docs).
    fn variable_db_set_data_type_with_storage(
        &self,
        data_type: Box<dyn DataType>,
        new_storage: Box<dyn VariableStorage>,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException>;

    /// Required body for [`Variable::set_data_type_aligned`]. Port of
    /// `VariableDB.setDataType(DataType, boolean, boolean, SourceType)`, the `alignStack` overload
    /// that resizes existing storage in place (via `VariableUtilities.resizeStorage`) rather than
    /// accepting an explicit replacement storage. Left required for the same reason as
    /// [`VariableDb::variable_db_set_data_type_with_storage`] (see its doc and the module docs).
    fn variable_db_set_data_type_aligned(
        &self,
        data_type: Box<dyn DataType>,
        align_stack: bool,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException>;

    /// Default body for [`Variable::set_data_type`]. Port of
    /// `VariableDB.setDataType(DataType, SourceType)`, a pure forward to the `alignStack` overload.
    fn variable_db_set_data_type(
        &self,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_db_set_data_type_aligned(data_type, true, false, source)
    }

    /// Default body for [`Variable::is_equivalent`]. Port of `VariableDB.isEquivalent(Variable)`
    /// (identity comparison, meaningless in Rust, is dropped -- see [`FunctionDb`]'s identical
    /// note about `equals`/`hashCode`).
    fn variable_db_is_equivalent(&self, other: &dyn Variable) -> bool {
        if other.is_parameter() != self.is_parameter() {
            return false;
        }
        if let (Some(mine), Some(theirs)) = (self.parameter_ordinal(), other.parameter_ordinal()) {
            if mine != theirs {
                return false;
            }
        }

        let other_function = other.get_function();
        let self_has_custom = self.function().has_custom_variable_storage();
        // Java: `otherFunction == null || otherFunction.hasCustomVariableStorage()`.
        let other_has_custom = other_function
            .as_ref()
            .map(|f| f.has_custom_variable_storage())
            .unwrap_or(true);
        if self_has_custom || other_has_custom {
            let mine = self.variable_db_get_variable_storage();
            let theirs = other.get_variable_storage();
            let storage_eq = match theirs {
                Some(theirs) => mine.storage_equals(theirs.as_ref()),
                None => false,
            };
            if !storage_eq {
                return false;
            }
        }

        if self.get_first_use_offset() != other.get_first_use_offset() {
            return false;
        }

        crate::program::model::data::parameter_definition_impl::is_same_or_equivalent_data_type(
            self.get_data_type().as_ref(),
            other.get_data_type().as_ref(),
        )
    }

    /// Default body for [`Variable::compare_to`]. Port of `VariableDB.compareTo(Variable)`'s
    /// delegation to `VariableUtilities.compare(this, otherVar)`, duplicated locally rather than
    /// calling that trait method directly: `self` here is `&Self` where `Self: VariableDb` (a
    /// dyn-unsized receiver inside a default method), which cannot be reborrowed as `&dyn Variable`
    /// without a concrete, `Sized` type -- exactly the friction
    /// [`VariableImpl::variable_impl_compare_to`](crate::program::model::listing::variable_impl::VariableImpl::variable_impl_compare_to)
    /// already documents and works around the same way.
    fn variable_db_compare_to(&self, other: &dyn Variable) -> Ordering {
        if let (Some(o1), Some(o2)) = (self.parameter_ordinal(), other.parameter_ordinal()) {
            return o1.cmp(&o2);
        }

        let self_precedence = variable_db_precedence(
            self.is_memory_variable(),
            self.is_register_variable(),
            self.is_stack_variable(),
            self.is_unique_variable(),
            self.is_compound_variable(),
            self.is_parameter(),
        );
        let other_precedence = variable_db_precedence(
            other.is_memory_variable(),
            other.is_register_variable(),
            other.is_stack_variable(),
            other.is_unique_variable(),
            other.is_compound_variable(),
            other.is_parameter(),
        );
        let precedence_diff = self_precedence - other_precedence;
        if precedence_diff != 0 {
            return precedence_diff.cmp(&0);
        }

        if self.is_stack_variable() && other.is_stack_variable() {
            if let (Ok(o1), Ok(o2)) = (self.get_stack_offset(), other.get_stack_offset()) {
                let diff = o2 - o1;
                if diff != 0 {
                    return diff.cmp(&0);
                }
            }
        }

        let fu1 = self.get_first_use_offset();
        let fu2 = other.get_first_use_offset();
        if fu1 != fu2 {
            if fu1 == 0 {
                return Ordering::Less;
            }
            if fu2 == 0 {
                return Ordering::Greater;
            }
            return fu1.cmp(&fu2);
        }

        let mine = self
            .get_variable_storage()
            .map(|s| s.get_varnodes())
            .unwrap_or_default();
        let theirs = other
            .get_variable_storage()
            .map(|s| s.get_varnodes())
            .unwrap_or_default();
        variable_db_compare_varnode_lists(&mine, &theirs)
    }
}

/// Duplicate a `Box<dyn VariableStorage>`, preserving special sentinel identity
/// (bad/unassigned/void storage) that a generic [`VariableStorage::with_varnodes`] rebuild would
/// otherwise lose: those singletons carry an empty varnode list, so blindly rebuilding via
/// `with_varnodes(s.get_varnodes())` would silently turn them into a non-sentinel, merely-empty
/// [`crate::program::seam_stubs::VarnodeListStorage`]. Not a port of any specific Java method
/// (Java's object identity makes this a non-issue there).
fn duplicate_storage(s: &dyn VariableStorage) -> Box<dyn VariableStorage> {
    if s.is_unassigned_storage() {
        Box::new(UnassignedStorage)
    } else if s.is_bad_storage() {
        Box::new(crate::program::model::listing::variable_storage::BadStorage)
    } else if s.is_void_storage() {
        Box::new(crate::program::model::listing::variable_storage::VoidStorage)
    } else {
        s.with_varnodes(s.get_varnodes())
    }
}

/// Precedence used by [`VariableDb::variable_db_compare_to`], mirroring
/// [`VariableUtilities::get_precedence`](crate::program::model::listing::variable_utilities::VariableUtilities::get_precedence)
/// (duplicated locally; see that default method's doc for why `self` cannot be passed directly).
fn variable_db_precedence(
    is_memory: bool,
    is_register: bool,
    is_stack: bool,
    is_unique: bool,
    is_compound: bool,
    is_parameter: bool,
) -> i32 {
    let mut precedence = if is_memory {
        15
    } else if is_register {
        13
    } else if is_stack {
        14
    } else if is_unique {
        16
    } else if is_compound {
        11
    } else {
        0
    };
    if is_parameter {
        precedence -= 10;
    }
    precedence
}

/// Compare storage varnode lists lexicographically by (space, offset, size), mirroring
/// [`variable_utilities::compare_varnode_lists`](crate::program::model::listing::variable_utilities)
/// (duplicated locally since that helper is private to its module).
fn variable_db_compare_varnode_lists(a: &[Varnode], b: &[Varnode]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        let key_x = (x.get_space_id(), x.get_offset(), x.get_size());
        let key_y = (y.get_space_id(), y.get_offset(), y.get_size());
        let ord = key_x.cmp(&key_y);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::database::function::FunctionManagerDb;
    use crate::program::model::address::AddressSetView;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::PrototypeModel;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{
        FunctionSignature, FunctionTag, Parameter, Program, StackFrame, VariableFilter,
    };
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{ExternalLocation, Namespace, SymbolType};
    use crate::program::seam_stubs::VariableSymbolDb;
    use crate::util::task::TaskMonitor;

    #[derive(Clone)]
    struct MockDataType {
        length: i32,
        void_type: bool,
    }

    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_void_type(&self) -> bool {
            self.void_type
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.length == dt.get_length() && self.void_type == dt.is_void_type()
        }
        fn get_name(&self) -> String {
            if self.void_type {
                "void".to_string()
            } else {
                "int".to_string()
            }
        }
    }

    fn ram_space() -> Arc<crate::program::model::address::AddressSpace> {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn stack_space() -> Arc<crate::program::model::address::AddressSpace> {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    fn mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram)
    }

    /// Minimal [`VariableSymbolDb`] backing a [`MockVariableDb`], holding just enough state to
    /// exercise [`VariableDb`]'s default methods. [`Symbol`]/[`VariableSymbolDb`] require `Send +
    /// Sync`, so interior mutability is via [`std::sync::Mutex`]/[`std::sync::atomic::AtomicI32`]
    /// rather than [`RefCell`] (`Box<dyn VariableStorage>` itself is not `Send`, so the varnode
    /// list is cached instead and re-wrapped into fresh storage on each read).
    struct MockSymbol {
        name: Mutex<String>,
        data_type: MockDataType,
        storage: Mutex<Option<Vec<Varnode>>>,
        comment: Mutex<Option<String>>,
        first_use_offset: std::sync::atomic::AtomicI32,
        ordinal: std::sync::atomic::AtomicI32,
        source: SourceType,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            ram_space().address(0)
        }
        fn get_name(&self) -> &str {
            // `Symbol::get_name` returns `&str` tied to `&self`, which a `Mutex<String>` cannot
            // hand out directly; leak a fresh copy for test purposes (see other `Box::leak` test
            // uses elsewhere in this crate, e.g. `assembly_resolution.rs`).
            Box::leak(self.name.lock().unwrap().clone().into_boxed_str())
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::LocalVar
        }
        fn get_source(&self) -> SourceType {
            self.source
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    impl VariableSymbolDb for MockSymbol {
        fn variable_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type.clone())
        }
        fn variable_storage(&self) -> Box<dyn VariableStorage> {
            match self.storage.lock().unwrap().clone() {
                Some(varnodes) => Box::new(crate::program::seam_stubs::VarnodeListStorage(varnodes)),
                None => Box::new(UnassignedStorage),
            }
        }
        fn set_variable_storage_and_data_type(
            &self,
            storage: Box<dyn VariableStorage>,
            _data_type: Box<dyn DataType>,
        ) {
            *self.storage.lock().unwrap() = Some(storage.get_varnodes());
        }
        fn variable_first_use_offset(&self) -> i32 {
            self.first_use_offset.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn set_variable_first_use_offset(&self, first_use_offset: i32) {
            self.first_use_offset.store(first_use_offset, std::sync::atomic::Ordering::SeqCst);
        }
        fn variable_ordinal(&self) -> i32 {
            self.ordinal.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn set_variable_ordinal(&self, ordinal: i32) {
            self.ordinal.store(ordinal, std::sync::atomic::Ordering::SeqCst);
        }
        fn variable_symbol_comment(&self) -> Option<String> {
            self.comment.lock().unwrap().clone()
        }
        fn set_variable_symbol_comment(&self, comment: Option<String>) {
            *self.comment.lock().unwrap() = comment;
        }
        fn rename(
            &self,
            name: &str,
            _source: SourceType,
        ) -> Result<(), SetVariableNameError> {
            *self.name.lock().unwrap() = name.to_string();
            Ok(())
        }
    }

    /// Minimal no-op [`FunctionDb`] used only so [`MockVariableDb::function`] has something to
    /// return; no test below exercises a required (`&mut self`-needing) method through it.
    struct MockFunctionDb {
        custom_storage: bool,
        state: crate::program::database::db_object::DbObjectState,
    }

    impl Namespace for MockFunctionDb {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunctionDb {
        fn get_name(&self) -> String {
            "mock_func".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            Ok(())
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            mock_program()
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}
        fn get_entry_point(&self) -> Address {
            ram_space().address(0)
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn set_return_type(
            &mut self,
            _dt: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_return(
            &mut self,
            _dt: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            String::new()
        }
        fn get_signature_source(&self) -> SourceType {
            SourceType::Default
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            false
        }
        fn remove_tag(&mut self, _name: &str) {}
        fn set_stack_purge_size(&mut self, _purge_size: i32) {}
        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not exercised by this smoke test")
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::function::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            Ok(())
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::function::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            Ok(())
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            None
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn Parameter>, InvalidInputException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parameter_count(&self) -> i32 {
            0
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {}
        fn set_body(
            &mut self,
            _new_body: &dyn AddressSetView,
        ) -> Result<(), crate::program::database::OverlappingFunctionException> {
            Ok(())
        }
        fn has_var_args(&self) -> bool {
            false
        }
        fn set_var_args(&mut self, _has_var_args: bool) {}
        fn is_inline(&self) -> bool {
            false
        }
        fn set_inline(&mut self, _is_inline: bool) {}
        fn has_no_return(&self) -> bool {
            false
        }
        fn set_no_return(&mut self, _has_no_return: bool) {}
        fn has_custom_variable_storage(&self) -> bool {
            self.custom_storage
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}
        fn get_calling_convention(&self) -> Option<Arc<PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            String::new()
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn is_thunk(&self) -> bool {
            false
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }
        fn is_external(&self) -> bool {
            false
        }
        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
            None
        }
        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl DbObject for MockFunctionDb {
        fn state(&self) -> &DbObjectState {
            &self.state
        }
        fn refresh(&self, _record: Option<&crate::framework::db::DBRecord>) -> bool {
            true
        }
    }

    impl FunctionDb for MockFunctionDb {
        fn set_validation_enabled(&mut self, _enabled: bool) {}
        fn function_manager(&self) -> Arc<dyn FunctionManagerDb> {
            unimplemented!("not exercised by this smoke test")
        }
        fn do_delete_variable(&mut self, _symbol: &dyn VariableSymbolDb) {}
        fn get_variable(&self, _symbol: &dyn VariableSymbolDb) -> Option<Box<dyn Variable>> {
            None
        }
        fn set_return_storage_and_data_type(
            &mut self,
            _storage: Option<Box<dyn VariableStorage>>,
            _data_type: Box<dyn DataType>,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn get_return_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4, void_type: false })
        }
        fn get_return_storage(&self, _has_custom_storage: bool) -> Box<dyn VariableStorage> {
            Box::new(UnassignedStorage)
        }
        fn deserialize_storage(&self, _serialized: Option<&str>) -> Box<dyn VariableStorage> {
            Box::new(UnassignedStorage)
        }
        fn get_stored_signature_source(&self) -> SourceType {
            SourceType::Default
        }
        fn set_local_size(&mut self, _size: i32) {}
        fn get_return_address_offset(&self) -> i32 {
            0
        }
        fn set_return_address_offset(&mut self, _offset: i32) {}
        fn create_class_struct_if_needed(&mut self) {}
        fn data_type_changed(&mut self, _var: &dyn Variable) {}
        fn function_changed(&mut self, _change_type: Option<crate::program::util::FunctionChangeType>) {}
        fn invalidate_frame(&mut self) {}
        fn update_parameters_and_return(&mut self) {}
    }

    /// Minimal [`VariableDb`] implementor used to exercise its default methods.
    struct MockVariableDb {
        symbol: Arc<MockSymbol>,
        function: Arc<MockFunctionDb>,
        cache: RefCell<Option<Box<dyn VariableStorage>>>,
        is_parameter: bool,
        parameter_ordinal: Option<i32>,
        first_use_offset: i32,
    }

    impl VariableDb for MockVariableDb {
        fn symbol(&self) -> Arc<dyn VariableSymbolDb> {
            self.symbol.clone()
        }
        fn function(&self) -> Arc<dyn FunctionDb> {
            self.function.clone()
        }
        fn cached_storage(&self) -> Option<Box<dyn VariableStorage>> {
            self.cache
                .borrow()
                .as_ref()
                .map(|s| duplicate_storage(s.as_ref()))
        }
        fn set_cached_storage(&self, storage: Option<Box<dyn VariableStorage>>) {
            *self.cache.borrow_mut() = storage;
        }
        fn variable_db_set_comment(&self, comment: Option<String>) {
            self.symbol.set_variable_symbol_comment(comment);
        }
        fn variable_db_get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn variable_db_set_data_type_with_storage(
            &self,
            data_type: Box<dyn DataType>,
            new_storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_db_set_storage_and_data_type(new_storage, data_type);
            Ok(())
        }
        fn variable_db_set_data_type_aligned(
            &self,
            data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            let storage = self.variable_db_get_variable_storage();
            self.variable_db_set_storage_and_data_type(storage, data_type);
            Ok(())
        }
    }

    impl Variable for MockVariableDb {
        fn get_data_type(&self) -> Box<dyn DataType> {
            self.variable_db_get_data_type()
        }
        fn set_data_type_with_storage(
            &mut self,
            data_type: Box<dyn DataType>,
            storage: Box<dyn VariableStorage>,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_db_set_data_type_with_storage(data_type, storage, force, source)
        }
        fn set_data_type(
            &mut self,
            data_type: Box<dyn DataType>,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_db_set_data_type(data_type, source)
        }
        fn set_data_type_aligned(
            &mut self,
            data_type: Box<dyn DataType>,
            align_stack: bool,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_db_set_data_type_aligned(data_type, align_stack, force, source)
        }
        fn get_name(&self) -> Option<String> {
            self.variable_db_get_name()
        }
        fn get_length(&self) -> i32 {
            self.variable_db_get_length()
        }
        fn is_valid(&self) -> bool {
            self.variable_db_is_valid()
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            self.variable_db_get_function()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.variable_db_get_program()
        }
        fn get_source(&self) -> SourceType {
            self.variable_db_get_source()
        }
        fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetVariableNameError> {
            self.variable_db_set_name(name, source)
        }
        fn get_comment(&self) -> Option<String> {
            self.variable_db_get_comment()
        }
        fn set_comment(&mut self, comment: Option<String>) {
            self.variable_db_set_comment(comment)
        }
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            Some(self.variable_db_get_variable_storage())
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            self.variable_db_get_first_storage_varnode()
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            self.variable_db_get_last_storage_varnode()
        }
        fn is_stack_variable(&self) -> bool {
            self.variable_db_is_stack_variable()
        }
        fn has_stack_storage(&self) -> bool {
            self.variable_db_has_stack_storage()
        }
        fn is_register_variable(&self) -> bool {
            self.variable_db_is_register_variable()
        }
        fn get_register(&self) -> Option<RegisterRef> {
            self.variable_db_get_register()
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            self.variable_db_get_registers()
        }
        fn get_min_address(&self) -> Option<Address> {
            self.variable_db_get_min_address()
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            self.variable_db_get_stack_offset()
        }
        fn is_memory_variable(&self) -> bool {
            self.variable_db_is_memory_variable()
        }
        fn is_unique_variable(&self) -> bool {
            self.variable_db_is_unique_variable()
        }
        fn is_compound_variable(&self) -> bool {
            self.variable_db_is_compound_variable()
        }
        fn has_assigned_storage(&self) -> bool {
            self.variable_db_has_assigned_storage()
        }
        fn get_first_use_offset(&self) -> i32 {
            self.first_use_offset
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            self.variable_db_get_symbol()
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.variable_db_is_equivalent(variable)
        }
        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.variable_db_compare_to(other)
        }
        fn is_parameter(&self) -> bool {
            self.is_parameter
        }
        fn parameter_ordinal(&self) -> Option<i32> {
            self.parameter_ordinal
        }
    }

    fn mock_local_var(name: &str, storage: Option<Box<dyn VariableStorage>>) -> MockVariableDb {
        MockVariableDb {
            symbol: Arc::new(MockSymbol {
                name: Mutex::new(name.to_string()),
                data_type: MockDataType { length: 4, void_type: false },
                storage: Mutex::new(storage.map(|s| s.get_varnodes())),
                comment: Mutex::new(None),
                first_use_offset: std::sync::atomic::AtomicI32::new(0),
                ordinal: std::sync::atomic::AtomicI32::new(0),
                source: SourceType::UserDefined,
            }),
            function: Arc::new(MockFunctionDb {
                custom_storage: false,
                state: crate::program::database::db_object::DbObjectState::new(1),
            }),
            cache: RefCell::new(None),
            is_parameter: false,
            parameter_ordinal: None,
            first_use_offset: 0,
        }
    }

    fn register_storage() -> Box<dyn VariableStorage> {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let reg_space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        Box::new(crate::program::seam_stubs::VarnodeListStorage(vec![Varnode::new(
            reg_space.address(0x10),
            4,
        )]))
    }

    #[test]
    fn is_valid_checks_length_and_storage_size() {
        let var = mock_local_var("local_1", Some(register_storage()));
        assert!(var.is_valid());

        let mut bad_dt_var = mock_local_var("local_2", Some(register_storage()));
        bad_dt_var.symbol = Arc::new(MockSymbol {
            name: Mutex::new("local_2".to_string()),
            data_type: MockDataType { length: 0, void_type: false },
            storage: Mutex::new(Some(register_storage().get_varnodes())),
            comment: Mutex::new(None),
            first_use_offset: std::sync::atomic::AtomicI32::new(0),
            ordinal: std::sync::atomic::AtomicI32::new(0),
            source: SourceType::UserDefined,
        });
        assert!(!bad_dt_var.is_valid());
    }

    #[test]
    fn get_variable_storage_caches_after_first_lookup() {
        let var = mock_local_var("local_1", Some(register_storage()));
        let first = var.variable_db_get_variable_storage();
        assert!(first.is_register_storage());
        // Mutate the symbol directly; the cached value should now win.
        *var.symbol.storage.lock().unwrap() = None;
        let second = var.variable_db_get_variable_storage();
        assert!(second.is_register_storage(), "cached storage should persist");
    }

    #[test]
    fn set_storage_and_data_type_updates_symbol_and_cache() {
        let var = mock_local_var("local_1", None);
        var.variable_db_set_storage_and_data_type(
            register_storage(),
            Box::new(MockDataType { length: 4, void_type: false }),
        );
        assert!(var.variable_db_get_variable_storage().is_register_storage());
        assert!(var.symbol.variable_storage().is_register_storage());
    }

    #[test]
    fn set_storage_and_data_type_forces_unassigned_for_parameter_without_custom_storage() {
        let mut var = mock_local_var("param_1", None);
        var.is_parameter = true;
        var.parameter_ordinal = Some(0);
        var.variable_db_set_storage_and_data_type(
            register_storage(),
            Box::new(MockDataType { length: 4, void_type: false }),
        );
        assert!(var.variable_db_get_variable_storage().is_unassigned_storage());
    }

    #[test]
    fn set_dynamic_storage_panics_by_default() {
        let var = mock_local_var("local_1", None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            var.variable_db_set_dynamic_storage(register_storage());
        }));
        assert!(result.is_err());
    }

    #[test]
    fn set_name_delegates_to_symbol_rename() {
        let mut var = mock_local_var("local_1", None);
        Variable::set_name(&mut var, "renamed", SourceType::UserDefined).unwrap();
        assert_eq!(var.get_name(), Some("renamed".to_string()));
    }

    #[test]
    fn is_equivalent_compares_ordinal_storage_offset_and_data_type() {
        let a = mock_local_var("a", Some(register_storage()));
        let b = mock_local_var("b", Some(register_storage()));
        assert!(a.is_equivalent(&b), "same storage/offset/data type should be equivalent");

        let mut c = mock_local_var("c", Some(register_storage()));
        c.is_parameter = true;
        c.parameter_ordinal = Some(0);
        assert!(!a.is_equivalent(&c), "parameter-ness mismatch must not be equivalent");
    }

    #[test]
    fn compare_to_orders_parameters_by_ordinal() {
        let mut p0 = mock_local_var("p0", Some(register_storage()));
        p0.is_parameter = true;
        p0.parameter_ordinal = Some(0);
        let mut p1 = mock_local_var("p1", Some(register_storage()));
        p1.is_parameter = true;
        p1.parameter_ordinal = Some(1);
        assert_eq!(p0.compare_to(&p1), Ordering::Less);
        assert_eq!(p1.compare_to(&p0), Ordering::Greater);
    }

    #[test]
    fn compare_to_falls_back_to_first_use_offset() {
        let mut early = mock_local_var("early", Some(stack_storage()));
        early.first_use_offset = 0;
        let mut later = mock_local_var("later", Some(stack_storage()));
        later.first_use_offset = 8;
        assert_eq!(early.compare_to(&later), Ordering::Less);
    }

    fn stack_storage() -> Box<dyn VariableStorage> {
        Box::new(crate::program::seam_stubs::VarnodeListStorage(vec![Varnode::new(
            stack_space().address(0x8),
            4,
        )]))
    }

    #[test]
    fn get_stack_offset_reports_underlying_storage_offset() {
        let var = mock_local_var("stack_var", Some(stack_storage()));
        assert_eq!(var.get_stack_offset(), Ok(8));
        assert!(var.is_stack_variable());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let var: Box<dyn Variable> = Box::new(mock_local_var("boxed", Some(register_storage())));
        assert!(var.is_valid());
    }
}
