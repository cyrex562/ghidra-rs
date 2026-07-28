//! Port of `ghidra.util.StackFrameImpl`, promoted to a trait because it was selected as a
//! dependency-cycle cut-point.
//!
//! The Java class is a concrete, deliberately "deficient" [`StackFrame`] implementation (per its
//! own class javadoc, "only used by the `UndefinedFunction` implementation"): the parameter
//! start offset and stack-growth direction are fixed at construction time from the owning
//! [`Function`], and every mutator (`createVariable`/`setLocalSize`/`setReturnAddressOffset`/
//! `clearVariable`) unconditionally throws `UnsupportedOperationException`. What remains is a
//! pure read-only view over a `variables` list, a `localSize` field, and a `returnStart` field.
//!
//! Following the same `stored_*`-accessor / `<TypeName>_*`-defaulted-method convention as
//! [`UndefinedFunction`](crate::util::undefined_function::UndefinedFunction), the backing fields
//! (`function`, `paramStart`, `growsNegative`, `localSize`, `returnStart`, `variables`) are
//! exposed via required `stored_*` accessors, and every method body `StackFrameImpl.java` gives a
//! real algorithm to is exposed here as a defaulted `stack_frame_impl_*` method. A concrete
//! implementor is expected to implement [`StackFrame`] itself, delegating each method body to its
//! `stack_frame_impl_*` counterpart, exactly as `MockStackFrameImpl` does in this module's tests.
//! Unlike [`UndefinedFunction`], this trait does not need `Self: StackFrame` (or any supertrait)
//! since every default body is self-contained in terms of the `stored_*` accessors.
//!
//! The constructor's field derivation (`growsNegative = function.getProgram().getCompilerSpec()
//! .stackGrowsNegative()`, `paramStart = VariableUtilities.getBaseStackParamOffset(function)`) is
//! ported as the free function [`compute_stack_frame_impl_fields`], mirroring how
//! [`crate::util::undefined_function::check_entry_is_memory_address`] ports
//! `UndefinedFunction`'s own constructor validation as a free function a concrete implementor's
//! constructor is expected to call (a trait cannot construct "a new `Self`" generically). Where
//! Java would NPE if `getCompilerSpec()` returned `null`, this free function instead falls back to
//! `false`, matching the `Option`-returning style [`UndefinedFunction::undefined_function_get_calling_convention`]
//! already uses for the same `Program::get_compiler_spec` call.
//!
//! Several query methods (`getVariableContaining`, `getNegativeVariables`, `getPositiveVariables`,
//! `getNegativeCount`, `getPositiveCount`) mutate the `variables` field in place as a side effect,
//! lazily pruning entries whose data type has been deleted. Since this trait's accessors take
//! `&self`, that pruning cannot be persisted back to storage here; instead, [`stack_frame_impl_live_variables`](StackFrameImpl::stack_frame_impl_live_variables)
//! filters deleted entries out of a fresh copy of [`stored_variables`](StackFrameImpl::stored_variables)
//! before every method that would otherwise prune them, which is observationally equivalent for
//! every caller (the pruning is otherwise unobservable performance bookkeeping). `getStackVariables`/
//! `getAllVariables` do **not** prune deleted entries in Java, so [`stack_frame_impl_get_stack_variables`](StackFrameImpl::stack_frame_impl_get_stack_variables)
//! reads `stored_variables()` directly. Note also that `getNegativeVariables`'s and
//! `getNegativeCount`'s break conditions differ by one comparison operator in the original Java
//! (`start > getParameterOffset()` vs. `start >= paramStart`); that discrepancy is preserved
//! faithfully here rather than unified.
//!
//! `variableChanged(LocalVariableImpl)` is not ported: it is package-private (not part of the
//! `StackFrame` interface), unreferenced by anything else in this port, and `LocalVariableImpl`
//! itself is not yet ported, so there is nothing for a stub to usefully stand in for.
//!
//! `getVariableContaining`'s binary search reuses the already-ported
//! [`StackVariableComparator`]/[`StackVariableOperand`] rather than needing a new placeholder.

use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::CompilerSpec;
use crate::program::model::listing::{
    CreateStackVariableError, Function, StackVariableComparator, StackVariableOperand, Variable,
    VariableUtilities, UNKNOWN_PARAM_OFFSET,
};
use crate::program::model::symbol::SourceType;
use crate::util::exception::InvalidInputException;

/// Stands in for the `StackFrameImpl(Function)` constructor body, computing the stack-growth
/// direction and parameter start offset a concrete implementor should store alongside `function`
/// itself. See the module docs for how this deviates from Java's NPE-on-missing-compiler-spec
/// behavior.
pub fn compute_stack_frame_impl_fields(
    function: &dyn Function,
    variable_utilities: &dyn VariableUtilities,
) -> (bool, i32) {
    let grows_negative = function
        .get_program()
        .get_compiler_spec()
        .map(|cs| cs.stack_grows_negative())
        .unwrap_or(false);
    let param_start = variable_utilities
        .get_base_stack_param_offset(function)
        .unwrap_or(UNKNOWN_PARAM_OFFSET);
    (grows_negative, param_start)
}

/// Field-backed default implementation of the [`StackFrame`](crate::program::model::listing::StackFrame)
/// overrides `StackFrameImpl` gives real bodies to. See the module docs for the `stored_*`
/// accessor / `stack_frame_impl_*` method-naming convention.
///
/// Port of `ghidra.util.StackFrameImpl`.
pub trait StackFrameImpl {
    /// Backing storage for the `function` field.
    fn stored_function(&self) -> Box<dyn Function>;

    /// Backing storage for the `paramStart` field.
    fn stored_param_start(&self) -> i32;

    /// Backing storage for the `growsNegative` field.
    fn stored_grows_negative(&self) -> bool;

    /// Backing storage for the `localSize` field (0 until `setLocalSize` succeeds -- which, in
    /// this deficient implementation, never happens).
    fn stored_local_size(&self) -> i32;

    /// Backing storage for the `returnStart` field (0 until `setReturnAddressOffset` succeeds --
    /// which, in this deficient implementation, never happens).
    fn stored_return_start(&self) -> i32;

    /// Backing storage for the `variables` field: all defined stack variables, kept sorted
    /// ascending by stack offset (mirroring the invariant Java's binary-search-based queries
    /// require of the `ArrayList<Variable>` field).
    fn stored_variables(&self) -> Vec<Box<dyn Variable>>;

    /// [`stored_variables`](Self::stored_variables) with deleted-data-type entries filtered out.
    /// See the module docs for why filtering stands in for Java's in-place pruning.
    fn stack_frame_impl_live_variables(&self) -> Vec<Box<dyn Variable>> {
        self.stored_variables()
            .into_iter()
            .filter(|v| !v.get_data_type().is_deleted())
            .collect()
    }

    /// Default body for `StackFrame::get_function`. Port of `StackFrameImpl.getFunction`
    /// (inherited accessor for the `function` field).
    fn stack_frame_impl_get_function(&self) -> Option<Box<dyn Function>> {
        Some(self.stored_function())
    }

    /// Default body for `StackFrame::get_stack_variables`. Port of
    /// `StackFrameImpl.getStackVariables` (delegates to the private `getAllVariables`, which does
    /// *not* prune deleted entries).
    fn stack_frame_impl_get_stack_variables(&self) -> Vec<Box<dyn Variable>> {
        self.stored_variables()
    }

    /// Default body for `StackFrame::get_locals`. Port of `StackFrameImpl.getLocals`.
    fn stack_frame_impl_get_locals(&self) -> Vec<Box<dyn Variable>> {
        if self.stack_frame_impl_get_parameter_offset() >= 0 {
            self.stack_frame_impl_negative_variables()
        } else {
            self.stack_frame_impl_positive_variables()
        }
    }

    /// Default body for `StackFrame::get_parameters`. Port of `StackFrameImpl.getParameters`.
    fn stack_frame_impl_get_parameters(&self) -> Vec<Box<dyn Variable>> {
        if self.stack_frame_impl_get_parameter_offset() >= 0 {
            self.stack_frame_impl_positive_variables()
        } else {
            self.stack_frame_impl_negative_variables()
        }
    }

    /// Default body for `StackFrame::get_frame_size`. Port of `StackFrameImpl.getFrameSize`.
    fn stack_frame_impl_get_frame_size(&self) -> i32 {
        let mut size = self.stack_frame_impl_get_local_size();
        size += if self.stored_grows_negative() {
            self.stack_frame_impl_positive_size()
        } else {
            self.stack_frame_impl_negative_size()
        };
        size
    }

    /// Default body for `StackFrame::get_local_size`. Port of `StackFrameImpl.getLocalSize`.
    fn stack_frame_impl_get_local_size(&self) -> i32 {
        let local_size = self.stored_local_size();
        if local_size > 0 {
            return local_size;
        }
        if self.stored_grows_negative() {
            self.stack_frame_impl_negative_size()
        } else {
            self.stack_frame_impl_positive_size()
        }
    }

    /// Default body for `StackFrame::grows_negative`. Port of `StackFrameImpl.growsNegative`.
    fn stack_frame_impl_grows_negative(&self) -> bool {
        self.stored_grows_negative()
    }

    /// Default body for `StackFrame::set_local_size`: unconditionally rejected. Port of
    /// `StackFrameImpl.setLocalSize`.
    fn stack_frame_impl_set_local_size(&mut self, size: i32) {
        let _ = size;
        panic!("StackFrameImpl may not be modified: setLocalSize is not supported")
    }

    /// Default body for `StackFrame::get_parameter_size`. Port of
    /// `StackFrameImpl.getParameterSize`.
    fn stack_frame_impl_get_parameter_size(&self) -> i32 {
        if self.stored_grows_negative() {
            self.stack_frame_impl_positive_size() - self.stack_frame_impl_get_parameter_offset()
        } else {
            self.stack_frame_impl_negative_size() + self.stack_frame_impl_get_parameter_offset()
        }
    }

    /// Default body for the (non-interface) public method `StackFrameImpl.getParameterCount`.
    fn stack_frame_impl_get_parameter_count(&self) -> i32 {
        if self.stored_grows_negative() {
            self.stack_frame_impl_positive_count()
        } else {
            self.stack_frame_impl_negative_count()
        }
    }

    /// Default body for `StackFrame::clear_variable`: unconditionally rejected. Port of
    /// `StackFrameImpl.clearVariable`.
    fn stack_frame_impl_clear_variable(&mut self, offset: i32) {
        let _ = offset;
        panic!("StackFrameImpl may not be modified: clearVariable is not supported")
    }

    /// Default body for `StackFrame::get_parameter_offset`. Port of
    /// `StackFrameImpl.getParameterOffset` (inherited accessor for the `paramStart` field).
    fn stack_frame_impl_get_parameter_offset(&self) -> i32 {
        self.stored_param_start()
    }

    /// Default body for `StackFrame::is_parameter_offset`. Port of
    /// `StackFrameImpl.isParameterOffset`.
    fn stack_frame_impl_is_parameter_offset(&self, offset: i32) -> bool {
        let param_start = self.stored_param_start();
        let grows_negative = self.stored_grows_negative();
        (grows_negative && offset >= param_start) || (!grows_negative && offset < param_start)
    }

    /// Default body for `StackFrame::get_return_address_offset`. Port of
    /// `StackFrameImpl.getReturnAddressOffset` (inherited accessor for the `returnStart` field).
    fn stack_frame_impl_get_return_address_offset(&self) -> i32 {
        self.stored_return_start()
    }

    /// Default body for `StackFrame::set_return_address_offset`: unconditionally rejected. Port
    /// of `StackFrameImpl.setReturnAddressOffset`.
    fn stack_frame_impl_set_return_address_offset(&mut self, offset: i32) {
        let _ = offset;
        panic!("StackFrameImpl may not be modified: setReturnAddressOffset is not supported")
    }

    /// Default body for `StackFrame::create_variable`: unconditionally rejected. Port of
    /// `StackFrameImpl.createVariable`.
    fn stack_frame_impl_create_variable(
        &self,
        name: &str,
        offset: i32,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<Box<dyn Variable>, CreateStackVariableError> {
        let _ = (name, offset, data_type, source);
        Err(InvalidInputException::with_message(
            "StackFrameImpl may not be modified: createVariable is not supported",
        )
        .into())
    }

    /// Default body for `StackFrame::get_variable_containing`. Port of
    /// `StackFrameImpl.getVariableContaining`. See the module docs for why a matched-but-deleted
    /// entry is filtered out up front instead of removed from storage on the way through.
    fn stack_frame_impl_get_variable_containing(&self, offset: i32) -> Option<Box<dyn Variable>> {
        let mut variables = self.stack_frame_impl_live_variables();
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
        let stack_offset = var.get_stack_offset().unwrap_or(0);
        if stack_offset + var.get_length() > offset {
            return Some(variables.remove(index));
        }
        None
    }

    /// Size of the negative portion of the stack. Port of the private
    /// `StackFrameImpl.getNegativeSize`.
    fn stack_frame_impl_negative_size(&self) -> i32 {
        let param_start = self.stack_frame_impl_get_parameter_offset();
        let variables = self.stored_variables();
        let first = match variables.first() {
            None => return if self.stored_grows_negative() { 0 } else { -param_start },
            Some(v) => v,
        };
        let stack_offset = first.get_stack_offset().unwrap_or(0);
        if stack_offset >= 0 {
            return if self.stored_grows_negative() { 0 } else { -param_start };
        }
        -stack_offset
    }

    /// Size of the positive portion of the stack (including 0). Port of the private
    /// `StackFrameImpl.getPositiveSize`.
    fn stack_frame_impl_positive_size(&self) -> i32 {
        let param_start = self.stack_frame_impl_get_parameter_offset();
        let variables = self.stored_variables();
        let last = match variables.last() {
            None => return if self.stored_grows_negative() { param_start } else { 0 },
            Some(v) => v,
        };
        let stack_offset = last.get_stack_offset().unwrap_or(0);
        if stack_offset < 0 {
            return if self.stored_grows_negative() { param_start } else { 0 };
        }
        stack_offset + last.get_length()
    }

    /// All stack variables in the negative portion of the stack, ordered from least negative to
    /// most negative (mirrors Java's `-1` to `-n` ordering). Excludes any variables at or before
    /// the parameter offset if it is itself negative. Port of the private
    /// `StackFrameImpl.getNegativeVariables`.
    fn stack_frame_impl_negative_variables(&self) -> Vec<Box<dyn Variable>> {
        let param_start = self.stack_frame_impl_get_parameter_offset();
        let mut variables = self.stack_frame_impl_live_variables();
        let mut split = 0;
        for var in &variables {
            let start = var.get_stack_offset().unwrap_or(0);
            if start >= 0 || start > param_start {
                break;
            }
            split += 1;
        }
        let mut negatives: Vec<Box<dyn Variable>> = variables.drain(0..split).collect();
        negatives.reverse();
        negatives
    }

    /// All stack variables in the positive portion of the stack, in ascending offset order.
    /// Excludes any variables before the parameter offset if it is itself positive. Port of the
    /// private `StackFrameImpl.getPositiveVariables`.
    fn stack_frame_impl_positive_variables(&self) -> Vec<Box<dyn Variable>> {
        let param_start = self.stored_param_start();
        let variables = self.stack_frame_impl_live_variables();
        let mut split = variables.len();
        for (i, var) in variables.iter().enumerate() {
            let start = var.get_stack_offset().unwrap_or(0);
            if start >= 0 && start >= param_start {
                split = i;
                break;
            }
        }
        variables.into_iter().skip(split).collect()
    }

    /// Count of stack variables in the negative portion of the frame. Port of the private
    /// `StackFrameImpl.getNegativeCount` -- note its break condition (`start >= paramStart`)
    /// differs by one comparison operator from [`stack_frame_impl_negative_variables`](Self::stack_frame_impl_negative_variables)'s
    /// (`start > getParameterOffset()`); see the module docs.
    fn stack_frame_impl_negative_count(&self) -> i32 {
        let param_start = self.stored_param_start();
        let variables = self.stack_frame_impl_live_variables();
        let mut count = 0;
        for var in &variables {
            let start = var.get_stack_offset().unwrap_or(0);
            if start >= 0 || start >= param_start {
                break;
            }
            count += 1;
        }
        count
    }

    /// Count of stack variables in the positive portion of the frame. Port of the private
    /// `StackFrameImpl.getPositiveCount`.
    fn stack_frame_impl_positive_count(&self) -> i32 {
        self.stack_frame_impl_positive_variables().len() as i32
    }

    /// Compares `self` and `other` the way `StackFrameImpl.equals` does: by local size, parameter
    /// offset, return address offset, and the stack variables themselves (approximated via
    /// [`Variable::is_equivalent`] rather than Java's `Variable.equals`, since Rust trait objects
    /// have no structural equality to fall back on). Port of `StackFrameImpl.equals`.
    fn stack_frame_impl_eq(&self, other: &dyn crate::program::model::listing::StackFrame) -> bool {
        let my_vars = self.stored_variables();
        let other_vars = other.get_stack_variables();
        if self.stack_frame_impl_get_local_size() != other.get_local_size()
            || self.stored_param_start() != other.get_parameter_offset()
            || self.stored_return_start() != other.get_return_address_offset()
            || my_vars.len() != other_vars.len()
        {
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
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::variable::UnsupportedOperationError;
    use crate::program::model::listing::{Program, StackFrame};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{Namespace, Symbol};
    use std::sync::Arc;

    fn mock_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
    }

    fn stack_addr(offset: i32) -> Address {
        Address::new(mock_space(), offset as i64)
    }

    struct MockDataType {
        deleted: bool,
    }
    impl DataType for MockDataType {
        fn is_deleted(&self) -> bool {
            self.deleted
        }
    }

    #[derive(Clone)]
    struct MockVariable {
        name: String,
        offset: i32,
        length: i32,
        deleted: bool,
    }

    impl Variable for MockVariable {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { deleted: self.deleted })
        }
        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn crate::program::seam_stubs::VariableStorage>,
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
        fn get_variable_storage(&self) -> Option<Box<dyn crate::program::seam_stubs::VariableStorage>> {
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
            self.get_name() == variable.get_name() && self.offset == variable.get_stack_offset().unwrap_or(i32::MIN)
        }
        fn compare_to(&self, other: &dyn Variable) -> std::cmp::Ordering {
            self.offset.cmp(&other.get_stack_offset().unwrap_or(0))
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

    /// Minimal `Function` mock: only `get_program`/`get_calling_convention` are exercised (by
    /// [`compute_stack_frame_impl_fields`]); everything else is unused by this module's tests.
    struct MockFunction;
    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            unimplemented!("not needed for this smoke test")
        }
    }
    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "mock_function".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_call_fixup(&self) -> Option<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_comment(&self) -> Option<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_repeatable_comment(&self) -> Option<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_entry_point(&self) -> Address {
            unimplemented!("not needed for this smoke test")
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn crate::program::seam_stubs::VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_signature_formal(
            &self,
            _formal_signature: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn get_signature_source(&self) -> SourceType {
            unimplemented!("not needed for this smoke test")
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_stack_purge_size(&self) -> i32 {
            unimplemented!("not needed for this smoke test")
        }
        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn remove_tag(&mut self, _name: &str) {
            unimplemented!("not needed for this smoke test")
        }
        fn set_stack_purge_size(&mut self, _purge_size: i32) {
            unimplemented!("not needed for this smoke test")
        }
        fn is_stack_purge_size_valid(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!("not needed for this smoke test")
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {
            unimplemented!("not needed for this smoke test")
        }
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parameter_count(&self) -> i32 {
            unimplemented!("not needed for this smoke test")
        }
        fn get_auto_parameter_count(&self) -> i32 {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            unimplemented!("not needed for this smoke test")
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {
            unimplemented!("not needed for this smoke test")
        }
        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn has_var_args(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn set_var_args(&mut self, _has_var_args: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn is_inline(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn set_inline(&mut self, _is_inline: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn has_no_return(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn set_no_return(&mut self, _has_no_return: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn has_custom_variable_storage(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_thunk(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_external(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_calling_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_called_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            unimplemented!("not needed for this smoke test")
        }
        fn promote_local_user_labels_to_global(&mut self) {
            unimplemented!("not needed for this smoke test")
        }
        fn is_deleted(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
    }

    struct TestVariableUtilities;
    impl VariableUtilities for TestVariableUtilities {}

    /// A `StackFrameImpl` implementor backed by plain struct fields, sorted ascending by offset
    /// as Java's `variables` `ArrayList` invariant requires. Every `StackFrame` method delegates
    /// to its `stack_frame_impl_*` counterpart, mirroring `MockUndefinedFunction` in the sibling
    /// `undefined_function` module.
    struct MockStackFrameImpl {
        param_start: i32,
        grows_negative: bool,
        local_size: i32,
        return_start: i32,
        variables: Vec<MockVariable>,
    }

    impl StackFrameImpl for MockStackFrameImpl {
        fn stored_function(&self) -> Box<dyn Function> {
            Box::new(MockFunction)
        }
        fn stored_param_start(&self) -> i32 {
            self.param_start
        }
        fn stored_grows_negative(&self) -> bool {
            self.grows_negative
        }
        fn stored_local_size(&self) -> i32 {
            self.local_size
        }
        fn stored_return_start(&self) -> i32 {
            self.return_start
        }
        fn stored_variables(&self) -> Vec<Box<dyn Variable>> {
            self.variables
                .iter()
                .cloned()
                .map(|v| Box::new(v) as Box<dyn Variable>)
                .collect()
        }
    }

    impl StackFrame for MockStackFrameImpl {
        fn get_function(&self) -> Option<Box<dyn Function>> {
            self.stack_frame_impl_get_function()
        }
        fn get_frame_size(&self) -> i32 {
            self.stack_frame_impl_get_frame_size()
        }
        fn get_local_size(&self) -> i32 {
            self.stack_frame_impl_get_local_size()
        }
        fn get_parameter_size(&self) -> i32 {
            self.stack_frame_impl_get_parameter_size()
        }
        fn get_parameter_offset(&self) -> i32 {
            self.stack_frame_impl_get_parameter_offset()
        }
        fn is_parameter_offset(&self, offset: i32) -> bool {
            self.stack_frame_impl_is_parameter_offset(offset)
        }
        fn set_local_size(&mut self, size: i32) {
            self.stack_frame_impl_set_local_size(size)
        }
        fn set_return_address_offset(&mut self, offset: i32) {
            self.stack_frame_impl_set_return_address_offset(offset)
        }
        fn get_return_address_offset(&self) -> i32 {
            self.stack_frame_impl_get_return_address_offset()
        }
        fn get_variable_containing(&self, offset: i32) -> Option<Box<dyn Variable>> {
            self.stack_frame_impl_get_variable_containing(offset)
        }
        fn create_variable(
            &mut self,
            name: &str,
            offset: i32,
            data_type: Box<dyn DataType>,
            source: SourceType,
        ) -> Result<Box<dyn Variable>, CreateStackVariableError> {
            self.stack_frame_impl_create_variable(name, offset, data_type, source)
        }
        fn clear_variable(&mut self, offset: i32) {
            self.stack_frame_impl_clear_variable(offset)
        }
        fn get_stack_variables(&self) -> Vec<Box<dyn Variable>> {
            self.stack_frame_impl_get_stack_variables()
        }
        fn get_parameters(&self) -> Vec<Box<dyn Variable>> {
            self.stack_frame_impl_get_parameters()
        }
        fn get_locals(&self) -> Vec<Box<dyn Variable>> {
            self.stack_frame_impl_get_locals()
        }
        fn grows_negative(&self) -> bool {
            self.stack_frame_impl_grows_negative()
        }
    }

    /// Negative-growth frame matching the "Negative Growth" example in `StackFrame`'s own class
    /// docs: two locals at -8/-4, two parameters at 8/12, parameter offset 8.
    fn negative_growth_frame() -> MockStackFrameImpl {
        MockStackFrameImpl {
            param_start: 8,
            grows_negative: true,
            local_size: 0,
            return_start: 4,
            variables: vec![
                MockVariable { name: "local2".to_string(), offset: -8, length: 4, deleted: false },
                MockVariable { name: "local1".to_string(), offset: -4, length: 4, deleted: false },
                MockVariable { name: "param1".to_string(), offset: 8, length: 4, deleted: false },
                MockVariable { name: "param2".to_string(), offset: 12, length: 4, deleted: false },
            ],
        }
    }

    #[test]
    fn locals_and_parameters_partition_by_parameter_offset() {
        let frame = negative_growth_frame();
        let locals = frame.stack_frame_impl_get_locals();
        assert_eq!(
            locals.iter().map(|v| v.get_name().unwrap()).collect::<Vec<_>>(),
            vec!["local1", "local2"]
        );
        let params = frame.stack_frame_impl_get_parameters();
        assert_eq!(
            params.iter().map(|v| v.get_name().unwrap()).collect::<Vec<_>>(),
            vec!["param1", "param2"]
        );
    }

    #[test]
    fn frame_size_and_parameter_size_match_java_worked_example() {
        let frame = negative_growth_frame();
        assert_eq!(frame.stack_frame_impl_get_local_size(), 8);
        assert_eq!(frame.stack_frame_impl_get_frame_size(), 24);
        assert_eq!(frame.stack_frame_impl_get_parameter_size(), 8);
        assert_eq!(frame.stack_frame_impl_get_parameter_count(), 2);
    }

    #[test]
    fn is_parameter_offset_respects_growth_direction() {
        let frame = negative_growth_frame();
        assert!(frame.stack_frame_impl_is_parameter_offset(8));
        assert!(!frame.stack_frame_impl_is_parameter_offset(-4));
    }

    #[test]
    fn get_variable_containing_finds_covering_and_exact_matches() {
        let frame = negative_growth_frame();
        // Exact match.
        assert_eq!(
            frame.stack_frame_impl_get_variable_containing(-8).unwrap().get_name(),
            Some("local2".to_string())
        );
        // Falls within local2's [-8, -4) range.
        assert_eq!(
            frame.stack_frame_impl_get_variable_containing(-6).unwrap().get_name(),
            Some("local2".to_string())
        );
        // Before every variable.
        assert!(frame.stack_frame_impl_get_variable_containing(-100).is_none());
    }

    #[test]
    fn get_variable_containing_skips_deleted_entries() {
        let mut frame = negative_growth_frame();
        frame.variables[3].deleted = true; // param2 @ 12..16
        assert!(frame.stack_frame_impl_get_variable_containing(13).is_none());
        // Deleted entries are also excluded from the live parameter list.
        let params = frame.stack_frame_impl_get_parameters();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].get_name(), Some("param1".to_string()));
        // ...but still show up via the raw, unfiltered accessor.
        assert_eq!(frame.stack_frame_impl_get_stack_variables().len(), 4);
    }

    #[test]
    fn mutators_are_rejected() {
        let mut frame = negative_growth_frame();
        assert!(
            frame
                .stack_frame_impl_create_variable("x", 0, Box::new(MockDataType { deleted: false }), SourceType::UserDefined)
                .is_err()
        );
    }

    #[test]
    #[should_panic(expected = "setLocalSize")]
    fn set_local_size_panics() {
        let mut frame = negative_growth_frame();
        frame.stack_frame_impl_set_local_size(4);
    }

    #[test]
    fn equals_compares_by_size_offsets_and_variables() {
        let a = negative_growth_frame();
        let b = negative_growth_frame();
        assert!(a.stack_frame_impl_eq(&b));

        let mut c = negative_growth_frame();
        c.return_start = 999;
        assert!(!a.stack_frame_impl_eq(&c));
    }

    #[test]
    fn compute_fields_uses_compiler_spec_and_variable_utilities() {
        let (grows_negative, param_start) =
            compute_stack_frame_impl_fields(&MockFunction, &TestVariableUtilities);
        // MockFunction's program has no compiler spec, and its calling convention resolves to
        // `None`, so both fall back to their documented defaults.
        assert!(!grows_negative);
        assert_eq!(param_start, UNKNOWN_PARAM_OFFSET);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let frame: Box<dyn StackFrame> = Box::new(negative_growth_frame());
        assert_eq!(frame.get_return_address_offset(), 4);
        assert_eq!(frame.get_stack_variables().len(), 4);
    }
}
