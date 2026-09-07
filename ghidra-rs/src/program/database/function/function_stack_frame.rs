//! Port of `ghidra.program.database.function.FunctionStackFrame`, mirroring
//! [`crate::util::stack_frame_impl::StackFrameImpl`]'s shape (a `pub trait Foo: StackFrame` with
//! `stored_*` backing-field accessors and `function_stack_frame_*`-prefixed default methods a
//! concrete implementor's `impl StackFrame for Foo` delegates to) rather than
//! [`FunctionDb`]'s bare-cut-point shape, since `FunctionStackFrame` (unlike `FunctionDB`) is not
//! itself a cycle cut-point -- it is a leaf class *composed by* the already-ported [`FunctionDb`]
//! (`Function.getStackFrame()` constructs `new FunctionStackFrame(this)`).
//!
//! `FunctionStackFrame implements StackFrame` and holds four fields: `variables` (a lazily
//! computed, offset-sorted cache of this function's compound-or-simple stack variables),
//! `function` (the owning `FunctionDB`), `stackGrowsNegative` (cached alongside `variables`), and
//! `invalid` (the cache-staleness flag). These are exposed as required accessors
//! ([`FunctionStackFrame::stored_function`],
//! [`FunctionStackFrame::cached_variables`]/[`FunctionStackFrame::set_cached_variables`],
//! [`FunctionStackFrame::cached_grows_negative`]/[`FunctionStackFrame::set_cached_grows_negative`],
//! [`FunctionStackFrame::cached_invalid`]/[`FunctionStackFrame::set_cached_invalid`]), mirroring
//! [`crate::program::database::function::VariableDb`]'s `cached_storage`/`set_cached_storage`
//! shape for its own lazily-cached field. The `Lock functionMgr.lock` field is not modeled: no
//! sibling class in this package (`VariableDb`, `ParameterDb`, `ReturnParameterDb`) models
//! `FunctionManagerDB`'s lock either, since this port has no concurrent-access story yet for the
//! database layer.
//!
//! ## What got a real default, and what didn't
//!
//! [`checkIsValid`](FunctionStackFrame::function_stack_frame_check_is_valid),
//! [`checkDeleted`](FunctionStackFrame::function_stack_frame_check_deleted), and
//! `setInvalid` (as [`FunctionStackFrame::function_stack_frame_set_invalid`]) all get real
//! defaults: none of them touch `FunctionDB` through anything but its already-`&self`
//! [`Function::is_deleted`]/[`Function::get_program`]/[`Function::get_variables_filtered`], so a
//! shared `Arc<dyn FunctionDb>` is enough. Likewise every read-only query --
//! [`getStackVariables`](FunctionStackFrame::function_stack_frame_get_stack_variables),
//! [`getLocals`](FunctionStackFrame::function_stack_frame_get_locals),
//! [`getParameters`](FunctionStackFrame::function_stack_frame_get_parameters),
//! [`getFrameSize`](FunctionStackFrame::function_stack_frame_get_frame_size),
//! [`getLocalSize`](FunctionStackFrame::function_stack_frame_get_local_size),
//! [`growsNegative`](FunctionStackFrame::function_stack_frame_grows_negative),
//! [`getParameterSize`](FunctionStackFrame::function_stack_frame_get_parameter_size),
//! the package-private `getParameterCount`
//! (as [`FunctionStackFrame::function_stack_frame_get_parameter_count`]),
//! [`getParameterOffset`](FunctionStackFrame::function_stack_frame_get_parameter_offset),
//! [`getReturnAddressOffset`](FunctionStackFrame::function_stack_frame_get_return_address_offset)
//! (`FunctionDb::get_return_address_offset` is `&self`),
//! [`getVariableContaining`](FunctionStackFrame::function_stack_frame_get_variable_containing),
//! [`isParameterOffset`](FunctionStackFrame::function_stack_frame_is_parameter_offset), and
//! `equals` (as [`FunctionStackFrame::function_stack_frame_eq`]) -- get real, faithful
//! `function_stack_frame_*` defaults. `getVariableContaining`'s binary search reuses the
//! already-ported [`StackVariableComparator`]/[`StackVariableOperand`], exactly mirroring
//! [`crate::util::stack_frame_impl::StackFrameImpl::stack_frame_impl_get_variable_containing`].
//! `getParameterOffset`/`getLocalSize`/`getParameterSize`/`isParameterOffset`/`equals` all
//! ultimately need `VariableUtilities.getBaseStackParamOffset(function)`; since
//! [`VariableUtilities`] is itself a bare-default-method cut-point trait (any `impl
//! VariableUtilities for Foo {}` is a complete, working instance), these defaults take a `&dyn
//! VariableUtilities` parameter rather than a stored field, mirroring
//! [`crate::util::stack_frame_impl::compute_stack_frame_impl_fields`]'s identical choice for the
//! same helper.
//!
//! [`createVariable`](FunctionStackFrame::function_stack_frame_create_variable),
//! [`clearVariable`](FunctionStackFrame::function_stack_frame_clear_variable),
//! `setLocalSize` (as [`FunctionStackFrame::function_stack_frame_set_local_size`]), and
//! `setReturnAddressOffset` (as
//! [`FunctionStackFrame::function_stack_frame_set_return_address_offset`]) are left as *required*
//! methods with no default body, following the precedent set by
//! [`VariableDb`](crate::program::database::function::VariableDb)'s own module docs: their Java
//! bodies call `FunctionDB.insertParameter`/`addLocalVariable`/`setCustomVariableStorage`/
//! `removeVariable`/`setLocalSize`/`setReturnAddressOffset`, all `&mut self` methods on
//! [`Function`]/[`FunctionDb`] unreachable from a `&self` default method through the shared
//! `Arc<dyn FunctionDb>` [`FunctionStackFrame::stored_function`] returns. Each required method's
//! doc comment reproduces the exact Java algorithm so a concrete implementor -- one that holds its
//! `FunctionDb` behind real interior mutability -- can complete it faithfully.
//! [`getFunction`](FunctionStackFrame::function_stack_frame_get_function) is required too, for the
//! same `Box<dyn Function>`-from-a-shared-reference reason
//! [`VariableDb::variable_db_get_function`](crate::program::database::function::VariableDb::variable_db_get_function)
//! documents: `dyn Function` has no `Clone`, so there is no portable way to manufacture an owned
//! `Box` from `stored_function()`'s `Arc<dyn FunctionDb>`.
//!
//! ## Left out of this port
//! - The package-private constructor (`FunctionStackFrame(FunctionDB)`): a concrete implementor's
//!   own constructor supplies `stored_function` and initializes the cache fields (`invalid =
//!   true`, `stackGrowsNegative` from the compiler spec) directly, mirroring how
//!   [`compute_stack_frame_impl_fields`](crate::util::stack_frame_impl::compute_stack_frame_impl_fields)
//!   is a free function a concrete `StackFrameImpl` constructor calls rather than a trait method.
//! - `equals`/`hashCode`: no `Object` identity contract to satisfy in Rust (matching every other
//!   `*Db` module's identical note); [`function_stack_frame_eq`](FunctionStackFrame::function_stack_frame_eq)
//!   fills the role `equals` played for value comparison, using [`crate::program::model::listing::Variable::is_equivalent`]
//!   rather than Java's `Variable.equals` per-element, exactly as
//!   [`crate::util::stack_frame_impl::StackFrameImpl::stack_frame_impl_eq`] already does.
//! - Several large blocks of dead, already-commented-out code in the Java source
//!   (`getNegativeSize`/`getPositiveSize`/`getNegativeCount`/`getPositiveCount` and the
//!   commented-out `setParameterOffset` override) are not ported, matching their absence from the
//!   live Java class.

use std::sync::Arc;

use crate::program::database::function::FunctionDb;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::{
    CompoundStackVariableFilter, CreateStackVariableError, Function, StackFrame,
    StackVariableComparator, StackVariableOperand, Variable, VariableUtilities,
    UNKNOWN_PARAM_OFFSET,
};
use crate::program::model::symbol::SourceType;

/// Database implementation of a [`StackFrame`] backed by a [`FunctionDb`].
///
/// Port of `ghidra.program.database.function.FunctionStackFrame` (see the module docs for the
/// default-vs-required method split and everything intentionally left out).
pub trait FunctionStackFrame: StackFrame {
    /// Backing storage for the `function` field.
    fn stored_function(&self) -> Arc<dyn FunctionDb>;

    /// Backing storage for the `invalid` field (cache-staleness flag; `true` means
    /// [`cached_variables`](Self::cached_variables)/[`cached_grows_negative`](Self::cached_grows_negative)
    /// must be recomputed before use).
    fn cached_invalid(&self) -> bool;

    /// Update the backing storage for the `invalid` field.
    fn set_cached_invalid(&self, invalid: bool);

    /// Backing storage for the `stackGrowsNegative` field.
    fn cached_grows_negative(&self) -> bool;

    /// Update the backing storage for the `stackGrowsNegative` field.
    fn set_cached_grows_negative(&self, grows_negative: bool);

    /// Backing storage for the `variables` field: this function's compound-or-simple stack
    /// variables (per [`CompoundStackVariableFilter`]), kept sorted ascending by stack offset
    /// (mirroring the invariant Java's binary-search-based queries require of the array field).
    fn cached_variables(&self) -> Vec<Box<dyn Variable>>;

    /// Update the backing storage for the `variables` field.
    fn set_cached_variables(&self, variables: Vec<Box<dyn Variable>>);

    /// Default body for the package-private `FunctionStackFrame.checkIsValid()`: if the function
    /// has been deleted, returns `false`; otherwise, if the cache is stale, recomputes
    /// [`cached_grows_negative`](Self::cached_grows_negative) from the function's compiler spec
    /// and [`cached_variables`](Self::cached_variables) from
    /// [`Function::get_variables_filtered`] (sorted via [`StackVariableComparator`]), then returns
    /// `true`.
    fn function_stack_frame_check_is_valid(&self) -> bool {
        let function = self.stored_function();
        if Function::is_deleted(function.as_ref()) {
            return false;
        }
        if self.cached_invalid() {
            let grows_negative = function
                .get_program()
                .get_compiler_spec()
                .map(|cs| cs.stack_grows_negative())
                .unwrap_or(false);
            self.set_cached_grows_negative(grows_negative);

            let mut variables =
                function.get_variables_filtered(Some(&CompoundStackVariableFilter));
            variables.sort_by(|a, b| {
                StackVariableComparator::compare(
                    &StackVariableOperand::Variable(a.as_ref()),
                    &StackVariableOperand::Variable(b.as_ref()),
                )
            });
            self.set_cached_variables(variables);
            self.set_cached_invalid(false);
        }
        true
    }

    /// Default body for the package-private `FunctionStackFrame.checkDeleted()`.
    ///
    /// # Panics
    /// Panics if the underlying function has been deleted, standing in for Java's
    /// `ConcurrentModificationException("Object has been deleted.")`.
    fn function_stack_frame_check_deleted(&self) {
        if !self.function_stack_frame_check_is_valid() {
            panic!("Object has been deleted.");
        }
    }

    /// Default body for the package-private `FunctionStackFrame.setInvalid()`.
    fn function_stack_frame_set_invalid(&self) {
        self.set_cached_invalid(true);
    }

    /// Required body for [`StackFrame::get_function`]. Required (see module docs): `dyn Function`
    /// has no `Clone`, so there is no portable way to manufacture a `Box<dyn Function>` from the
    /// shared `Arc<dyn FunctionDb>` returned by [`FunctionStackFrame::stored_function`].
    fn function_stack_frame_get_function(&self) -> Option<Box<dyn Function>>;

    /// Required body for [`StackFrame::create_variable`]. Port of
    /// `FunctionStackFrame.createVariable(String, int, DataType, SourceType)`:
    /// ```java
    /// public Variable createVariable(String name, int offset, DataType dataType, SourceType source) {
    ///     checkDeleted();
    ///     if (dataType != null) {
    ///         dataType = dataType.clone(function.getProgram().getDataTypeManager());
    ///     }
    ///     Variable var = new LocalVariableImpl(name, dataType, offset, function.getProgram());
    ///     if (isParameterOffset(offset)) {
    ///         // Determine ordinal insertion point
    ///         int ordinal = function.getParameterCount();
    ///         Parameter[] params = getParameters();
    ///         if (stackGrowsNegative) {
    ///             for (int i = params.length - 1; i >= 0; i--) {
    ///                 if (offset <= params[i].getLastStorageVarnode().getOffset()) {
    ///                     ordinal = params[i].getOrdinal();
    ///                 }
    ///             }
    ///         }
    ///         else {
    ///             for (Parameter param : params) {
    ///                 if (offset >= param.getLastStorageVarnode().getOffset()) {
    ///                     ordinal = param.getOrdinal();
    ///                 }
    ///             }
    ///         }
    ///         var = function.insertParameter(ordinal, var, source);
    ///     }
    ///     else {
    ///         var = function.addLocalVariable(var, source);
    ///     }
    ///     if ((var instanceof Parameter) && !function.hasCustomVariableStorage() &&
    ///         (!var.isStackVariable() || var.getStackOffset() != offset)) {
    ///         function.setCustomVariableStorage(true);
    ///         VariableStorage storage = new VariableStorage(function.getProgram(), offset, var.getLength());
    ///         var.setDataType(var.getDataType(), storage, true, source);
    ///     }
    ///     return var;
    /// }
    /// ```
    /// **WARNING!** (preserved from the Java doc): stack parameters will be created even if the
    /// calling convention does not specify stack inputs, and use of this method to add parameters
    /// may force the function to use custom variable storage.
    ///
    /// Left required (see module docs): every branch above ultimately calls
    /// `Function::insert_parameter`/`add_local_variable`/`set_custom_variable_storage`, all `&mut
    /// self`, unreachable from a `&self` default through the shared `Arc<dyn FunctionDb>`
    /// [`FunctionStackFrame::stored_function`] returns.
    fn function_stack_frame_create_variable(
        &mut self,
        name: &str,
        offset: i32,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<Box<dyn Variable>, CreateStackVariableError>;

    /// Default body for [`StackFrame::get_stack_variables`]. Port of
    /// `FunctionStackFrame.getStackVariables()` (the Java body defensively copies the `variables`
    /// array; [`cached_variables`](Self::cached_variables) is expected to hand back an
    /// independently owned `Vec` on every call, so no further copy is needed here).
    fn function_stack_frame_get_stack_variables(&self) -> Vec<Box<dyn Variable>> {
        self.function_stack_frame_check_is_valid();
        self.cached_variables()
    }

    /// Default body for [`StackFrame::get_locals`]. Port of `FunctionStackFrame.getLocals()`.
    fn function_stack_frame_get_locals(&self) -> Vec<Box<dyn Variable>> {
        self.function_stack_frame_check_is_valid();
        self.cached_variables()
            .into_iter()
            .filter(|v| !v.is_parameter())
            .collect()
    }

    /// Default body for [`StackFrame::get_parameters`]. Port of
    /// `FunctionStackFrame.getParameters()`.
    fn function_stack_frame_get_parameters(&self) -> Vec<Box<dyn Variable>> {
        self.function_stack_frame_check_is_valid();
        self.cached_variables()
            .into_iter()
            .filter(|v| v.is_parameter())
            .collect()
    }

    /// Default body for [`StackFrame::get_frame_size`]. Port of
    /// `FunctionStackFrame.getFrameSize()`.
    fn function_stack_frame_get_frame_size(&self, variable_utilities: &dyn VariableUtilities) -> i32 {
        self.function_stack_frame_get_parameter_size(variable_utilities)
            + self.function_stack_frame_get_local_size(variable_utilities)
    }

    /// Default body for [`StackFrame::get_local_size`]. Port of
    /// `FunctionStackFrame.getLocalSize()`.
    fn function_stack_frame_get_local_size(&self, variable_utilities: &dyn VariableUtilities) -> i32 {
        self.function_stack_frame_check_is_valid();

        let base_offset = variable_utilities
            .get_base_stack_param_offset(self.stored_function().as_ref())
            .unwrap_or(0);
        let variables = self.cached_variables();

        if self.cached_grows_negative() {
            if let Some(first) = variables.first() {
                if !first.is_parameter() {
                    let mut offset = first
                        .get_last_storage_varnode()
                        .map(|v| v.get_offset() as i32)
                        .unwrap_or(0);
                    if offset > 0 {
                        offset = 0;
                    }
                    return base_offset - offset;
                }
            }
            return base_offset;
        }

        let last = match variables.last() {
            None => return -base_offset,
            Some(v) => v,
        };
        if !last.is_parameter() {
            if let Some(stack_varnode) = last.get_last_storage_varnode() {
                let len = stack_varnode.get_size();
                let mut offset = stack_varnode.get_offset() as i32;
                if offset < 0 {
                    offset = 0;
                }
                return offset - base_offset + len;
            }
        }
        -base_offset
    }

    /// Default body for [`StackFrame::grows_negative`]. Port of
    /// `FunctionStackFrame.growsNegative()`.
    fn function_stack_frame_grows_negative(&self) -> bool {
        self.cached_grows_negative()
    }

    /// Required body for [`StackFrame::set_local_size`]. Port of
    /// `FunctionStackFrame.setLocalSize(int)` (`function.setLocalSize(size);`; the Java doc notes
    /// this "has no real affect"). Left required (see module docs):
    /// [`FunctionDb::set_local_size`] is `&mut self`, unreachable from a `&self` default through
    /// the shared `Arc<dyn FunctionDb>` [`FunctionStackFrame::stored_function`] returns.
    fn function_stack_frame_set_local_size(&mut self, size: i32);

    /// Default body for [`StackFrame::get_parameter_size`]. Port of
    /// `FunctionStackFrame.getParameterSize()`.
    fn function_stack_frame_get_parameter_size(
        &self,
        variable_utilities: &dyn VariableUtilities,
    ) -> i32 {
        self.function_stack_frame_check_is_valid();

        let base_offset = variable_utilities
            .get_base_stack_param_offset(self.stored_function().as_ref())
            .unwrap_or(0);
        let variables = self.cached_variables();

        if self.cached_grows_negative() {
            let last = match variables.last() {
                None => return 0,
                Some(v) => v,
            };
            if last.is_parameter() {
                if let Some(stack_varnode) = last.get_last_storage_varnode() {
                    let len = stack_varnode.get_size();
                    let stack_offset = stack_varnode.get_offset() as i32;
                    return stack_offset - base_offset + len;
                }
            }
            return 0;
        }

        if let Some(first) = variables.first() {
            if first.is_parameter() {
                if let Some(stack_varnode) = first.get_last_storage_varnode() {
                    let stack_offset = stack_varnode.get_offset() as i32;
                    return base_offset - stack_offset;
                }
            }
        }
        0
    }

    /// Default body for the package-private `FunctionStackFrame.getParameterCount()`: the number
    /// of parameters which occupy stack storage.
    fn function_stack_frame_get_parameter_count(&self) -> i32 {
        self.function_stack_frame_check_is_valid();
        self.cached_variables()
            .iter()
            .filter(|v| v.is_parameter())
            .count() as i32
    }

    /// Required body for [`StackFrame::clear_variable`]. Port of
    /// `FunctionStackFrame.clearVariable(int)`:
    /// ```java
    /// public void clearVariable(int offset) {
    ///     checkDeleted();
    ///     Variable var = getVariableContaining(offset);
    ///     if (var != null) {
    ///         if (!function.hasCustomVariableStorage()) {
    ///             function.setCustomVariableStorage(true);
    ///         }
    ///         function.removeVariable(var);
    ///     }
    /// }
    /// ```
    /// **WARNING!** (preserved from the Java doc): removing stack parameters from the stack frame
    /// will enable custom storage.
    ///
    /// Left required (see module docs): `Function::set_custom_variable_storage`/`remove_variable`
    /// are both `&mut self`, unreachable from a `&self` default through the shared `Arc<dyn
    /// FunctionDb>` [`FunctionStackFrame::stored_function`] returns.
    fn function_stack_frame_clear_variable(&mut self, offset: i32);

    /// Default body for [`StackFrame::get_parameter_offset`]. Port of
    /// `FunctionStackFrame.getParameterOffset()`.
    fn function_stack_frame_get_parameter_offset(
        &self,
        variable_utilities: &dyn VariableUtilities,
    ) -> i32 {
        variable_utilities
            .get_base_stack_param_offset(self.stored_function().as_ref())
            .unwrap_or(UNKNOWN_PARAM_OFFSET)
    }

    /// Default body for [`StackFrame::get_return_address_offset`]. Port of
    /// `FunctionStackFrame.getReturnAddressOffset()` (`FunctionDb::get_return_address_offset` is
    /// `&self`, so no `&mut`-reachability problem applies here).
    fn function_stack_frame_get_return_address_offset(&self) -> i32 {
        self.stored_function().get_return_address_offset()
    }

    /// Required body for [`StackFrame::set_return_address_offset`]. Port of
    /// `FunctionStackFrame.setReturnAddressOffset(int)` (`function.setReturnAddressOffset(offset);`).
    /// Left required (see module docs): [`FunctionDb::set_return_address_offset`] is `&mut self`,
    /// unreachable from a `&self` default through the shared `Arc<dyn FunctionDb>`
    /// [`FunctionStackFrame::stored_function`] returns.
    fn function_stack_frame_set_return_address_offset(&mut self, offset: i32);

    /// Default body for [`StackFrame::get_variable_containing`]. Port of
    /// `FunctionStackFrame.getVariableContaining(int)`.
    fn function_stack_frame_get_variable_containing(&self, offset: i32) -> Option<Box<dyn Variable>> {
        self.function_stack_frame_check_is_valid();
        let mut variables = self.cached_variables();
        let key = StackVariableOperand::Offset(offset);
        let search = variables.binary_search_by(|v| {
            StackVariableComparator::compare(&StackVariableOperand::Variable(v.as_ref()), &key)
        });
        let index = match search {
            Ok(i) => return Some(variables.remove(i)),
            Err(insertion_point) => {
                if insertion_point == 0 {
                    return None;
                }
                insertion_point - 1
            }
        };
        let var = &variables[index];
        let stack_varnode = var.get_last_storage_varnode()?;
        if stack_varnode.get_offset() as i32 + stack_varnode.get_size() > offset {
            return Some(variables.remove(index));
        }
        None
    }

    /// Default body for [`StackFrame::is_parameter_offset`]. Port of
    /// `FunctionStackFrame.isParameterOffset(int)`.
    fn function_stack_frame_is_parameter_offset(
        &self,
        offset: i32,
        variable_utilities: &dyn VariableUtilities,
    ) -> bool {
        let base_offset = match variable_utilities
            .get_base_stack_param_offset(self.stored_function().as_ref())
        {
            Some(v) => v,
            None => return false,
        };
        let grows_negative = self.cached_grows_negative();
        (grows_negative && offset >= base_offset) || (!grows_negative && offset < base_offset)
    }

    /// Compares `self` and `other` the way `FunctionStackFrame.equals` does: by local size,
    /// parameter offset, return address offset, and the stack variables themselves (approximated
    /// via [`crate::program::model::listing::Variable::is_equivalent`] rather than Java's
    /// `Variable.equals`, since Rust trait objects have no structural equality to fall back on --
    /// mirroring [`crate::util::stack_frame_impl::StackFrameImpl::stack_frame_impl_eq`]'s identical
    /// choice). Port of `FunctionStackFrame.equals(Object)`.
    fn function_stack_frame_eq(
        &self,
        other: &dyn StackFrame,
        variable_utilities: &dyn VariableUtilities,
    ) -> bool {
        self.function_stack_frame_check_is_valid();
        if self.function_stack_frame_get_local_size(variable_utilities) != other.get_local_size()
            || self.function_stack_frame_get_parameter_offset(variable_utilities)
                != other.get_parameter_offset()
            || self.function_stack_frame_get_return_address_offset()
                != other.get_return_address_offset()
        {
            return false;
        }
        let my_vars = self.cached_variables();
        let other_vars = other.get_stack_variables();
        if my_vars.len() != other_vars.len() {
            return false;
        }
        my_vars
            .iter()
            .zip(other_vars.iter())
            .all(|(a, b)| a.is_equivalent(b.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::Mutex;

    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::database::function::FunctionManagerDb;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::PrototypeModel;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::variable::UnsupportedOperationError;
    use crate::program::model::listing::variable_storage::{UnassignedStorage, VariableStorage};
    use crate::program::model::listing::{
        FunctionSignature, FunctionTag, Parameter, Program, VariableFilter,
    };
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{ExternalLocation, Namespace, Symbol};
    use crate::program::seam_stubs::VariableSymbolDb;
    use crate::util::exception::{DuplicateNameException, InvalidInputException};
    use crate::util::task::TaskMonitor;

    fn stack_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
    }

    fn stack_addr(offset: i32) -> Address {
        Address::new(stack_space(), offset as i64)
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    #[derive(Clone)]
    struct MockVariable {
        name: String,
        offset: i32,
        length: i32,
        is_param: bool,
    }

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type_aligned(
            &mut self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_name(&self) -> Option<String> {
            Some(self.name.clone())
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn set_name(
            &mut self,
            name: &str,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
            self.name = name.to_string();
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            Some(Varnode::new(stack_addr(self.offset), self.length))
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            Some(Varnode::new(stack_addr(self.offset), self.length))
        }
        fn is_stack_variable(&self) -> bool {
            true
        }
        fn has_stack_storage(&self) -> bool {
            true
        }
        fn is_register_variable(&self) -> bool {
            false
        }
        fn get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            Some(stack_addr(self.offset))
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            Ok(self.offset)
        }
        fn is_memory_variable(&self) -> bool {
            false
        }
        fn is_unique_variable(&self) -> bool {
            false
        }
        fn is_compound_variable(&self) -> bool {
            false
        }
        fn has_assigned_storage(&self) -> bool {
            true
        }
        fn get_first_use_offset(&self) -> i32 {
            0
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
                && self.offset == variable.get_stack_offset().unwrap_or(i32::MIN)
        }
        fn compare_to(&self, other: &dyn Variable) -> std::cmp::Ordering {
            self.offset.cmp(&other.get_stack_offset().unwrap_or(0))
        }
        fn is_parameter(&self) -> bool {
            self.is_param
        }
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

    /// A minimal, always-default [`PrototypeModel`] whose only override is
    /// `getStackParameterOffset()`, letting [`VariableUtilities::get_base_stack_param_offset`]
    /// resolve a deterministic parameter start offset without needing a full `CompilerSpec` mock.
    struct TestConvention(i64);
    impl PrototypeModel for TestConvention {
        fn get_stack_parameter_offset(&self) -> Option<i64> {
            Some(self.0)
        }
    }

    struct TestVariableUtilities;
    impl VariableUtilities for TestVariableUtilities {}

    /// Minimal [`FunctionDb`] backing the stack frame under test. `variables` stands in for the
    /// full set of the function's compound-or-simple stack variables that
    /// [`Function::get_variables_filtered`] would return; the frame's own cache is populated from
    /// this via [`function_stack_frame_check_is_valid`](FunctionStackFrame::function_stack_frame_check_is_valid).
    struct MockFunctionDb {
        state: DbObjectState,
        // `FunctionDb: DbObject: Send + Sync`, so this mock's interior mutability must be
        // thread-safe (unlike `MockFunctionStackFrame`'s own `Cell`/`RefCell` fields below, which
        // face no such bound).
        deleted: AtomicBool,
        variables: Mutex<Vec<MockVariable>>,
        return_address_offset: AtomicI32,
        stack_param_offset: Option<i64>,
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
            Arc::new(MockProgram)
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
            stack_addr(0)
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
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
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
            self.variables.lock().unwrap().iter().filter(|v| v.is_param).count() as i32
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
            self.variables
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .map(|v| Box::new(v) as Box<dyn Variable>)
                .collect()
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
            false
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            self.stack_param_offset.map(|o| Box::new(TestConvention(o)) as Box<dyn PrototypeModel>)
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
            self.deleted.load(Ordering::SeqCst)
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
            Box::new(MockDataType)
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
            self.return_address_offset.load(Ordering::SeqCst)
        }
        fn set_return_address_offset(&mut self, offset: i32) {
            self.return_address_offset.store(offset, Ordering::SeqCst);
        }
        fn create_class_struct_if_needed(&mut self) {}
        fn data_type_changed(&mut self, _var: &dyn Variable) {}
        fn function_changed(&mut self, _change_type: Option<crate::program::util::FunctionChangeType>) {}
        fn invalidate_frame(&mut self) {}
        fn update_parameters_and_return(&mut self) {}
    }

    /// A [`FunctionStackFrame`] implementor backed by plain `Cell`/`RefCell` fields, mirroring
    /// `MockStackFrameImpl` in the sibling `stack_frame_impl` module. Every [`StackFrame`] method
    /// delegates to its `function_stack_frame_*` counterpart.
    struct MockFunctionStackFrame {
        function: Arc<MockFunctionDb>,
        invalid: Cell<bool>,
        grows_negative: Cell<bool>,
        variables: RefCell<Vec<MockVariable>>,
    }

    impl FunctionStackFrame for MockFunctionStackFrame {
        fn stored_function(&self) -> Arc<dyn FunctionDb> {
            self.function.clone()
        }
        fn cached_invalid(&self) -> bool {
            self.invalid.get()
        }
        fn set_cached_invalid(&self, invalid: bool) {
            self.invalid.set(invalid);
        }
        fn cached_grows_negative(&self) -> bool {
            self.grows_negative.get()
        }
        fn set_cached_grows_negative(&self, grows_negative: bool) {
            self.grows_negative.set(grows_negative);
        }
        fn cached_variables(&self) -> Vec<Box<dyn Variable>> {
            self.variables
                .borrow()
                .iter()
                .cloned()
                .map(|v| Box::new(v) as Box<dyn Variable>)
                .collect()
        }
        fn set_cached_variables(&self, variables: Vec<Box<dyn Variable>>) {
            // The trait contract only requires each stored entry to be independently
            // reconstructible; this mock re-derives `MockVariable`s from the (offset, length,
            // is_parameter) triple exposed by `Variable` itself, exactly mirroring how
            // `stack_frame_impl`'s tests store a `Vec<MockVariable>` rather than the trait
            // objects directly.
            let rebuilt: Vec<MockVariable> = variables
                .iter()
                .map(|v| MockVariable {
                    name: v.get_name().unwrap_or_default(),
                    offset: v.get_stack_offset().unwrap_or(0),
                    length: v.get_length(),
                    is_param: v.is_parameter(),
                })
                .collect();
            *self.variables.borrow_mut() = rebuilt;
        }

        fn function_stack_frame_get_function(&self) -> Option<Box<dyn Function>> {
            None
        }

        fn function_stack_frame_create_variable(
            &mut self,
            name: &str,
            offset: i32,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, CreateStackVariableError> {
            if self.function.variables.lock().unwrap().iter().any(|v| v.name == name) {
                return Err(CreateStackVariableError::Duplicate(DuplicateNameException(
                    name.to_string(),
                )));
            }
            let is_param =
                self.function_stack_frame_is_parameter_offset(offset, &TestVariableUtilities);
            let var = MockVariable { name: name.to_string(), offset, length: 4, is_param };
            self.function.variables.lock().unwrap().push(var.clone());
            self.set_cached_invalid(true);
            Ok(Box::new(var))
        }

        fn function_stack_frame_set_local_size(&mut self, _size: i32) {
            // Matches the Java doc's own note that this setter "has no real affect".
        }

        fn function_stack_frame_clear_variable(&mut self, offset: i32) {
            self.function.variables.lock().unwrap().retain(|v| v.offset != offset);
            self.set_cached_invalid(true);
        }

        fn function_stack_frame_set_return_address_offset(&mut self, offset: i32) {
            self.function.return_address_offset.store(offset, Ordering::SeqCst);
        }
    }

    impl StackFrame for MockFunctionStackFrame {
        fn get_function(&self) -> Option<Box<dyn Function>> {
            self.function_stack_frame_get_function()
        }
        fn get_frame_size(&self) -> i32 {
            self.function_stack_frame_get_frame_size(&TestVariableUtilities)
        }
        fn get_local_size(&self) -> i32 {
            self.function_stack_frame_get_local_size(&TestVariableUtilities)
        }
        fn get_parameter_size(&self) -> i32 {
            self.function_stack_frame_get_parameter_size(&TestVariableUtilities)
        }
        fn get_parameter_offset(&self) -> i32 {
            self.function_stack_frame_get_parameter_offset(&TestVariableUtilities)
        }
        fn is_parameter_offset(&self, offset: i32) -> bool {
            self.function_stack_frame_is_parameter_offset(offset, &TestVariableUtilities)
        }
        fn set_local_size(&mut self, size: i32) {
            self.function_stack_frame_set_local_size(size)
        }
        fn set_return_address_offset(&mut self, offset: i32) {
            self.function_stack_frame_set_return_address_offset(offset)
        }
        fn get_return_address_offset(&self) -> i32 {
            self.function_stack_frame_get_return_address_offset()
        }
        fn get_variable_containing(&self, offset: i32) -> Option<Box<dyn Variable>> {
            self.function_stack_frame_get_variable_containing(offset)
        }
        fn create_variable(
            &mut self,
            name: &str,
            offset: i32,
            data_type: Box<dyn DataType>,
            source: SourceType,
        ) -> Result<Box<dyn Variable>, CreateStackVariableError> {
            self.function_stack_frame_create_variable(name, offset, data_type, source)
        }
        fn clear_variable(&mut self, offset: i32) {
            self.function_stack_frame_clear_variable(offset)
        }
        fn get_stack_variables(&self) -> Vec<Box<dyn Variable>> {
            self.function_stack_frame_get_stack_variables()
        }
        fn get_parameters(&self) -> Vec<Box<dyn Variable>> {
            self.function_stack_frame_get_parameters()
        }
        fn get_locals(&self) -> Vec<Box<dyn Variable>> {
            self.function_stack_frame_get_locals()
        }
        fn grows_negative(&self) -> bool {
            self.function_stack_frame_grows_negative()
        }
    }

    /// Negative-growth frame matching the "Negative Growth" example in `StackFrame`'s own class
    /// docs (and reused by `stack_frame_impl`'s tests): two locals at -8/-4, two parameters at
    /// 8/12, parameter offset 8.
    fn negative_growth_vars() -> Vec<MockVariable> {
        vec![
            MockVariable { name: "local2".to_string(), offset: -8, length: 4, is_param: false },
            MockVariable { name: "local1".to_string(), offset: -4, length: 4, is_param: false },
            MockVariable { name: "param1".to_string(), offset: 8, length: 4, is_param: true },
            MockVariable { name: "param2".to_string(), offset: 12, length: 4, is_param: true },
        ]
    }

    /// A frame whose cache is already populated (`invalid = false`), so reads exercise the real
    /// `function_stack_frame_*` query algorithms directly without going through
    /// [`function_stack_frame_check_is_valid`](FunctionStackFrame::function_stack_frame_check_is_valid)'s
    /// compiler-spec-driven recompute (this mock's `MockProgram` has no compiler spec to consult,
    /// so a recompute would always collapse `grows_negative` to `false` -- see
    /// [`check_is_valid_populates_cache_from_function_and_sorts_by_offset`] for that fallback path
    /// tested on its own). The backing `function.variables` is seeded with the same four
    /// variables so that mutator tests (`create_variable`/`clear_variable`), which invalidate the
    /// cache and force a real recompute, still observe a consistent variable set afterward.
    fn negative_growth_frame() -> MockFunctionStackFrame {
        let function = Arc::new(MockFunctionDb {
            state: DbObjectState::new(1),
            deleted: AtomicBool::new(false),
            variables: Mutex::new(negative_growth_vars()),
            return_address_offset: AtomicI32::new(4),
            stack_param_offset: Some(8),
        });
        MockFunctionStackFrame {
            function,
            invalid: Cell::new(false),
            grows_negative: Cell::new(true),
            variables: RefCell::new(negative_growth_vars()),
        }
    }

    /// A frame with a deliberately stale (`invalid = true`) cache, for tests that exercise
    /// [`function_stack_frame_check_is_valid`](FunctionStackFrame::function_stack_frame_check_is_valid)'s
    /// real recompute path.
    fn fresh_invalid_frame(variables: Vec<MockVariable>) -> MockFunctionStackFrame {
        let function = Arc::new(MockFunctionDb {
            state: DbObjectState::new(1),
            deleted: AtomicBool::new(false),
            variables: Mutex::new(variables),
            return_address_offset: AtomicI32::new(0),
            stack_param_offset: Some(8),
        });
        MockFunctionStackFrame {
            function,
            invalid: Cell::new(true),
            grows_negative: Cell::new(true),
            variables: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn check_is_valid_populates_cache_from_function_and_sorts_by_offset() {
        // Deliberately scrambled order, to prove the recompute path re-sorts by offset rather
        // than trusting `Function::get_variables_filtered`'s return order.
        let scrambled = vec![
            MockVariable { name: "param2".to_string(), offset: 12, length: 4, is_param: true },
            MockVariable { name: "local2".to_string(), offset: -8, length: 4, is_param: false },
            MockVariable { name: "param1".to_string(), offset: 8, length: 4, is_param: true },
            MockVariable { name: "local1".to_string(), offset: -4, length: 4, is_param: false },
        ];
        let frame = fresh_invalid_frame(scrambled);
        assert!(frame.cached_invalid());
        assert!(frame.function_stack_frame_check_is_valid());
        assert!(!frame.cached_invalid());
        // `MockProgram` has no compiler spec to consult, so the recompute falls back to `false`
        // exactly as `VariableUtilities`/`StackFrameImpl`'s own fallback tests already establish.
        assert!(!frame.cached_grows_negative());
        let names: Vec<String> = frame
            .cached_variables()
            .iter()
            .map(|v| v.get_name().unwrap())
            .collect();
        assert_eq!(names, vec!["local2", "local1", "param1", "param2"]);
    }

    #[test]
    fn check_is_valid_returns_false_once_function_is_deleted() {
        let frame = negative_growth_frame();
        assert!(frame.function_stack_frame_check_is_valid());
        frame.function.deleted.store(true, Ordering::SeqCst);
        assert!(!frame.function_stack_frame_check_is_valid());
    }

    #[test]
    #[should_panic(expected = "Object has been deleted.")]
    fn check_deleted_panics_once_function_is_deleted() {
        let frame = negative_growth_frame();
        frame.function.deleted.store(true, Ordering::SeqCst);
        frame.function_stack_frame_check_deleted();
    }

    #[test]
    fn set_invalid_forces_a_recompute_on_next_check() {
        let frame = negative_growth_frame();
        assert!(frame.function_stack_frame_check_is_valid());
        frame.function_stack_frame_set_invalid();
        assert!(frame.cached_invalid());
        assert!(frame.function_stack_frame_check_is_valid());
        assert!(!frame.cached_invalid());
    }

    #[test]
    fn locals_and_parameters_partition_by_is_parameter() {
        let frame = negative_growth_frame();
        let locals = frame.get_locals();
        assert_eq!(
            locals.iter().map(|v| v.get_name().unwrap()).collect::<Vec<_>>(),
            vec!["local2", "local1"]
        );
        let params = frame.get_parameters();
        assert_eq!(
            params.iter().map(|v| v.get_name().unwrap()).collect::<Vec<_>>(),
            vec!["param1", "param2"]
        );
    }

    #[test]
    fn frame_size_local_size_and_parameter_size_match_java_worked_example() {
        let frame = negative_growth_frame();
        // getLocalSize(): variables[0] is local2 (not a Parameter) at offset -8, which is not >
        // 0, so offset stays -8; baseOffset(8) - (-8) = 16. Unlike `StackFrameImpl`'s simpler
        // "distance from zero" formula, `FunctionStackFrame`'s local size is measured from the
        // parameter offset down through the lowest local (i.e. it also covers the return-address
        // save area between true locals and true parameters).
        assert_eq!(frame.get_local_size(), 16);
        // getParameterSize(): variables[last] is param2 (a Parameter) at offset 12, length 4;
        // stackOffset(12) - baseOffset(8) + len(4) = 8.
        assert_eq!(frame.get_parameter_size(), 8);
        assert_eq!(frame.get_frame_size(), 24);
        assert_eq!(frame.function_stack_frame_get_parameter_count(), 2);
    }

    #[test]
    fn parameter_offset_and_is_parameter_offset_use_calling_convention() {
        let frame = negative_growth_frame();
        assert_eq!(frame.get_parameter_offset(), 8);
        assert!(frame.is_parameter_offset(8));
        assert!(frame.is_parameter_offset(12));
        assert!(!frame.is_parameter_offset(-4));
        assert!(!frame.is_parameter_offset(0));
    }

    #[test]
    fn parameter_offset_falls_back_to_unknown_when_no_convention_available() {
        let function = Arc::new(MockFunctionDb {
            state: DbObjectState::new(1),
            deleted: AtomicBool::new(false),
            variables: Mutex::new(Vec::new()),
            return_address_offset: AtomicI32::new(0),
            stack_param_offset: None,
        });
        let frame = MockFunctionStackFrame {
            function,
            invalid: Cell::new(true),
            grows_negative: Cell::new(false),
            variables: RefCell::new(Vec::new()),
        };
        assert_eq!(frame.get_parameter_offset(), UNKNOWN_PARAM_OFFSET);
        assert!(!frame.is_parameter_offset(4));
    }

    #[test]
    fn grows_negative_reports_cached_direction_without_forcing_a_recompute() {
        // `invalid = true` with a *stale* `grows_negative = true` cached value: if
        // `growsNegative()` incorrectly called `checkIsValid()` first, the fallback recompute
        // (no compiler spec available) would flip this to `false` and clear the invalid flag.
        let frame = fresh_invalid_frame(Vec::new());
        assert!(frame.cached_invalid());
        assert!(frame.cached_grows_negative());
        assert!(frame.grows_negative());
        assert!(frame.cached_invalid(), "growsNegative must not call checkIsValid");
        assert!(frame.cached_grows_negative(), "growsNegative must not force a recompute");
    }

    #[test]
    fn get_return_address_offset_reads_through_to_the_function() {
        let frame = negative_growth_frame();
        assert_eq!(frame.get_return_address_offset(), 4);
    }

    #[test]
    fn get_variable_containing_finds_covering_and_exact_matches() {
        let frame = negative_growth_frame();
        assert_eq!(
            frame.get_variable_containing(-8).unwrap().get_name(),
            Some("local2".to_string())
        );
        // Falls within local2's [-8, -4) range.
        assert_eq!(
            frame.get_variable_containing(-6).unwrap().get_name(),
            Some("local2".to_string())
        );
        // Falls within param2's [12, 16) range.
        assert_eq!(
            frame.get_variable_containing(13).unwrap().get_name(),
            Some("param2".to_string())
        );
        // Before every variable, and strictly between local1's end and param1's start.
        assert!(frame.get_variable_containing(-100).is_none());
        assert!(frame.get_variable_containing(0).is_none());
    }

    #[test]
    fn create_variable_rejects_duplicate_name_and_invalidates_cache_on_success() {
        let mut frame = negative_growth_frame();
        assert!(frame.function_stack_frame_check_is_valid());

        let created = frame
            .create_variable("local_1", -20, Box::new(MockDataType), SourceType::UserDefined)
            .unwrap();
        assert_eq!(created.get_name(), Some("local_1".to_string()));
        // The mock's own bookkeeping marks the cache stale after a successful create; the next
        // read recomputes from the (now four-plus-one) function-level variable list.
        assert!(frame.cached_invalid());
        assert_eq!(frame.get_stack_variables().len(), 5);

        let dup_err = match frame.create_variable(
            "local_1",
            -24,
            Box::new(MockDataType),
            SourceType::UserDefined,
        ) {
            Err(e) => e,
            Ok(_) => panic!("expected duplicate name error"),
        };
        assert!(matches!(dup_err, CreateStackVariableError::Duplicate(_)));
    }

    #[test]
    fn clear_variable_removes_it_and_invalidates_cache() {
        let mut frame = negative_growth_frame();
        assert!(frame.function_stack_frame_check_is_valid());
        assert_eq!(frame.get_stack_variables().len(), 4);

        frame.clear_variable(-8);
        assert!(frame.cached_invalid());
        let remaining: Vec<String> = frame
            .get_stack_variables()
            .iter()
            .map(|v| v.get_name().unwrap())
            .collect();
        assert_eq!(remaining, vec!["local1", "param1", "param2"]);
    }

    #[test]
    fn set_return_address_offset_updates_the_function() {
        let mut frame = negative_growth_frame();
        frame.set_return_address_offset(99);
        assert_eq!(frame.get_return_address_offset(), 99);
    }

    #[test]
    fn set_local_size_is_a_no_op_matching_the_java_doc() {
        let mut frame = negative_growth_frame();
        let before = frame.get_local_size();
        frame.set_local_size(1234);
        assert_eq!(frame.get_local_size(), before);
    }

    #[test]
    fn equals_compares_by_size_offsets_and_variables() {
        let a = negative_growth_frame();
        let b = negative_growth_frame();
        assert!(a.function_stack_frame_eq(&b, &TestVariableUtilities));

        let c = negative_growth_frame();
        c.function.return_address_offset.store(999, Ordering::SeqCst);
        assert!(!a.function_stack_frame_eq(&c, &TestVariableUtilities));
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let frame: Box<dyn StackFrame> = Box::new(negative_growth_frame());
        assert_eq!(frame.get_return_address_offset(), 4);
        assert_eq!(frame.get_stack_variables().len(), 4);
    }
}
