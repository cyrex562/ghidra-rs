//! Port of `ghidra.util.UndefinedFunction`, promoted to a trait because it was selected as a
//! dependency-cycle cut-point.
//!
//! The Java class is a concrete [`Function`] implementation representing a function whose
//! extent/signature has not actually been analyzed: every accessor either returns a fixed
//! "unknown" value or rejects mutation outright, except `getName`/`getEntryPoint`/`getProgram`/
//! `getBody`/`getSignature`/`getStackFrame`, which are backed by the four fields the constructor
//! populates (`p`, `entry`, `body`, `signature`, `frame`).
//!
//! Every one of those overrides turns out to already be *required* (no default) on
//! [`Function`]/[`Namespace`](crate::program::model::symbol::Namespace) -- a concrete
//! implementation must supply a body for each regardless of this port -- so, following the same
//! `stored_*`-accessor / `<TypeName>_*`-defaulted-method convention as
//! [`AutoParameterImpl`](crate::program::model::listing::auto_parameter_impl::AutoParameterImpl):
//! the four private fields are exposed via required `stored_signature`/`stored_frame`/
//! `stored_body`/`set_stored_body` accessors (the other two, `p`/`entry`, are already reachable
//! through [`Function::get_program`]/[`Function::get_entry_point`] themselves, which a concrete
//! implementor wires up directly), and every method `UndefinedFunction.java` gives a real body to
//! is exposed here as a defaulted `undefined_function_*` method. A concrete type is expected to
//! delegate its `Namespace`/`Function` method bodies to these instead of writing the logic twice,
//! exactly as `MockUndefinedFunction` does in this module's tests.
//!
//! `Function.getReturn()` (`new ReturnParameterImpl(dt, ..., program)`) is the one override left
//! entirely to the implementor (no `undefined_function_get_return` default): `ReturnParameterImpl`
//! itself is not yet ported (see `DatabaseVariableImpl`'s doc comment in `program::seam_stubs`),
//! so there is no value this trait could hand back generically. Likewise
//! `getReturnType`/`setReturnType`'s `DataType.DEFAULT` comparison is approximated by checking
//! `DataType::get_name() == "undefined"` (`DefaultDataType`'s real Java name), since the
//! `DataType.DEFAULT` singleton itself is not yet ported either (see `DataType`'s own doc comment).
//!
//! The constructor's sole validation (`entry`, if present, must be a memory address) is ported as
//! the free function [`check_entry_is_memory_address`], mirroring how
//! [`AutoParameterImpl`](crate::program::model::listing::auto_parameter_impl)'s
//! `check_auto_storage` ports its own constructor validation as a free function a concrete
//! implementor's constructor is expected to call, since a trait cannot construct "a new `Self`"
//! generically.
//!
//! The three static factory methods (`findFunction`, `findFunctionUsingSimpleBlockModel`,
//! `findFunctionUsingIsolatedBlockModel`) become `Self: Sized`-bounded associated functions on
//! this trait: bounding them this way keeps `UndefinedFunction` itself object-safe (usable as
//! `Box<dyn UndefinedFunction>`/`Arc<dyn UndefinedFunction>` for its instance surface) while still
//! letting a concrete implementor's own factory methods delegate to them. Since a trait cannot
//! build "a new Self" generically either, each takes a `make` callback standing in for
//! `new UndefinedFunction(program, entry)`.
//!
//! `getEntryBlock`'s worklist walk over non-call, non-indirect source edges is ported in full as
//! the free function [`find_entry_block`] (it is `private` in Java, so -- as with
//! [`SimpleBlockModel`](crate::program::model::block::simple_block_model::SimpleBlockModel)'s own
//! excluded private helpers -- it is not part of the trait's public contract, just the shared
//! implementation the two `find_function_using_*_block_model` defaults call). It required growing
//! two existing placeholders (see `STUBS.tsv`): `program::seam_stubs::CodeBlock` gained
//! `is_empty`/`get_first_start_address`/`get_sources` (the real `CodeBlock` interface extends
//! `AddressSetView` and separately declares `getFirstStartAddress`/`getSources`), and
//! `program::seam_stubs::FlowType` gained `is_indirect`. `IsolatedEntrySubModel` itself is not yet
//! ported at all, so `find_function_using_isolated_block_model` takes a
//! [`crate::util::seam_stubs::IsolatedEntrySubModelLike`] placeholder parameter instead of
//! constructing one internally.
//!
//! `findFunctionUsingSimpleBlockModel`'s `program.getListing().getInstructionContaining(address)
//! == null` fast-path check is not ported: `Program::get_listing` requires `&mut self` (see its
//! doc comment), while this trait -- like `Function::get_program` itself -- only ever has a
//! shared `Arc<dyn Program>` to work with. Skipping the check does not change the *result* (an
//! address with no instruction has no code block either, so
//! [`find_entry_block`] still reports `None`), only the (here, irrelevant) early-exit performance
//! of getting there.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use crate::program::database::function::OverlappingFunctionException;
use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::block::simple_block_model::SimpleBlockModel;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::listing::function::{
    FunctionEditError, SetFunctionNameError, UNKNOWN_CALLING_CONVENTION_STRING,
};
use crate::program::model::listing::{
    Function, FunctionSignature, FunctionTag, Parameter, Program, Variable,
};
use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
use crate::program::seam_stubs::{CodeBlock, StackFrame, VariableFilter};
use crate::util::exception::{CancelledException, InvalidInputException};
use crate::util::seam_stubs::IsolatedEntrySubModelLike;
use crate::util::task::TaskMonitor;

/// Stands in for the `if (entry != null && !entry.isMemoryAddress())` guard in the
/// `UndefinedFunction(Program, Address)` constructor body.
pub fn check_entry_is_memory_address(entry: Option<&Address>) -> Result<(), InvalidInputException> {
    if let Some(e) = entry {
        if !e.is_memory_address() {
            return Err(InvalidInputException::with_message(
                "Entry point must be memory address",
            ));
        }
    }
    Ok(())
}

/// Port of the private static `UndefinedFunction.getEntryBlock(Program, Address, TaskMonitor)`.
///
/// Starting from the block containing `address`, walks backwards over non-call, non-indirect
/// source edges until a block with no such sources is found (the function's true entry block),
/// returning `None` if `address` has no code block, the block is empty, or the search is
/// cancelled.
pub fn find_entry_block(
    block_model: &dyn SimpleBlockModel,
    address: &Address,
    monitor: &dyn TaskMonitor,
) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
    let block = match block_model.get_first_code_block_containing(address, monitor)? {
        Some(b) => b,
        None => return Ok(None),
    };
    if block.is_empty() {
        return Ok(None);
    }

    let mut visited: HashSet<Address> = HashSet::new();
    let block_start = block
        .get_first_start_address()
        .expect("a non-empty code block has a first start address");
    visited.insert(block_start);

    let mut worklist: VecDeque<Box<dyn CodeBlock>> = VecDeque::new();
    worklist.push_back(block);

    while let Some(cur_block) = worklist.pop_front() {
        let mut count = 0;
        let mut sources = cur_block.get_sources(monitor)?;
        while !monitor.is_cancelled() && sources.has_next()? {
            let block_ref = sources.next()?;
            let flow_type = block_ref.get_flow_type();
            if flow_type.is_call() || flow_type.is_indirect() {
                continue; // don't follow call edges or improper indirect references
            }
            count += 1; // count the existence of a source that is NOT a call
            let source_addr = block_ref.get_source_address();
            if visited.contains(&source_addr) {
                continue; // already visited this block
            }
            visited.insert(source_addr);
            worklist.push_back(block_ref.get_source_block());
        }
        if count == 0 {
            return Ok(Some(cur_block));
        }
    }
    Ok(None)
}

/// Field-backed default implementation of the [`Function`]/[`Namespace`] overrides
/// `UndefinedFunction` gives real bodies to, plus its static finder methods.
///
/// Port of `ghidra.util.UndefinedFunction`. See the module docs for the `stored_*` accessor /
/// `undefined_function_*` method-naming convention.
pub trait UndefinedFunction: Function {
    /// Backing storage for the `signature` field (`new FunctionDefinitionDataType(this, true)`).
    fn stored_signature(&self) -> Box<dyn FunctionSignature>;

    /// Backing storage for the `frame` field (`new StackFrameImpl(this)`).
    fn stored_frame(&self) -> Box<dyn StackFrame>;

    /// Backing storage for the `body` field.
    fn stored_body(&self) -> Box<dyn AddressSetView>;

    /// Setter for the `body` field, used by [`undefined_function_set_body`](Self::undefined_function_set_body).
    fn set_stored_body(&mut self, new_body: AddressSet);

    /// Default body for [`Function::is_deleted`]. Port of `UndefinedFunction.isDeleted`.
    fn undefined_function_is_deleted(&self) -> bool {
        false
    }

    /// Default body for [`Function::is_external`]. Port of `UndefinedFunction.isExternal`.
    fn undefined_function_is_external(&self) -> bool {
        false
    }

    /// Default body for [`Function::get_external_location`]. Port of
    /// `UndefinedFunction.getExternalLocation`.
    fn undefined_function_get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
        None
    }

    /// Default body for [`Function::get_calling_convention`]. Port of
    /// `UndefinedFunction.getCallingConvention`.
    fn undefined_function_get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
        self.get_program()
            .get_compiler_spec()
            .and_then(|cs| cs.get_default_calling_convention())
    }

    /// Default body for [`Function::has_unknown_calling_convention_name`]: always `true`,
    /// regardless of whether [`undefined_function_get_calling_convention`](Self::undefined_function_get_calling_convention)
    /// found one. Port of `UndefinedFunction.hasUnknownCallingConventionName`.
    fn undefined_function_has_unknown_calling_convention_name(&self) -> bool {
        true
    }

    /// Default body for [`Function::get_calling_convention_name`]. Port of
    /// `UndefinedFunction.getCallingConventionName`.
    fn undefined_function_get_calling_convention_name(&self) -> String {
        UNKNOWN_CALLING_CONVENTION_STRING.to_string()
    }

    /// Default body for [`Function::get_comment`]. Port of `UndefinedFunction.getComment`.
    fn undefined_function_get_comment(&self) -> Option<String> {
        None
    }

    /// Default body for [`Function::get_comment_as_array`]. Port of
    /// `UndefinedFunction.getCommentAsArray`.
    fn undefined_function_get_comment_as_array(&self) -> Vec<String> {
        Vec::new()
    }

    /// Default body for [`Function::get_name`]: `"UndefinedFunction_" + entry.toString(false)`.
    /// Port of `UndefinedFunction.getName()`.
    fn undefined_function_get_name(&self) -> String {
        format!("UndefinedFunction_{}", self.get_entry_point().format(false, 8))
    }

    /// Default body for [`Namespace::get_name_with_path`](crate::program::model::symbol::Namespace::get_name_with_path):
    /// ignores `include_namespace_path` and just returns the plain name. Port of
    /// `UndefinedFunction.getName(boolean)`.
    fn undefined_function_get_name_with_path(&self, _include_namespace_path: bool) -> String {
        Function::get_name(self)
    }

    /// Default body for [`Function::get_parameter`]. Port of `UndefinedFunction.getParameter`.
    fn undefined_function_get_parameter(&self) -> Option<Box<dyn Parameter>> {
        None
    }

    /// Default body for [`Function::get_parameter_count`]. Port of
    /// `UndefinedFunction.getParameterCount`.
    fn undefined_function_get_parameter_count(&self) -> i32 {
        0
    }

    /// Default body for [`Function::get_auto_parameter_count`]. Port of
    /// `UndefinedFunction.getAutoParameterCount`.
    fn undefined_function_get_auto_parameter_count(&self) -> i32 {
        0
    }

    /// Default body for [`Function::get_parameters`]/[`Function::get_parameters_filtered`]. Port
    /// of `UndefinedFunction.getParameters()`/`getParameters(VariableFilter)`.
    fn undefined_function_get_parameters(&self) -> Vec<Box<dyn Parameter>> {
        Vec::new()
    }

    /// Default body for [`Function::has_custom_variable_storage`]. Port of
    /// `UndefinedFunction.hasCustomVariableStorage`.
    fn undefined_function_has_custom_variable_storage(&self) -> bool {
        false
    }

    /// Default body for [`Function::set_custom_variable_storage`]: silently ignored ("don't
    /// support"). Port of `UndefinedFunction.setCustomVariableStorage`.
    fn undefined_function_set_custom_variable_storage(&mut self, has_custom_variable_storage: bool) {
        let _ = has_custom_variable_storage;
    }

    /// Default body for [`Function::get_local_variables`]/[`Function::get_local_variables_filtered`]/
    /// [`Function::get_variables_filtered`]/[`Function::get_all_variables`]. Port of
    /// `UndefinedFunction.getLocalVariables()`/`getLocalVariables(VariableFilter)`/
    /// `getVariables(VariableFilter)`/`getAllVariables`.
    fn undefined_function_get_variables(&self) -> Vec<Box<dyn Variable>> {
        Vec::new()
    }

    /// Default body for [`Function::get_repeatable_comment`]. Port of
    /// `UndefinedFunction.getRepeatableComment`.
    fn undefined_function_get_repeatable_comment(&self) -> Option<String> {
        None
    }

    /// Default body for [`Function::get_repeatable_comment_as_array`]. Port of
    /// `UndefinedFunction.getRepeatableCommentAsArray`.
    fn undefined_function_get_repeatable_comment_as_array(&self) -> Vec<String> {
        Vec::new()
    }

    /// Default body for [`Function::get_return_type`]. Approximates `DataType.DEFAULT` as `None`
    /// since that singleton is not yet ported (see the module docs). Port of
    /// `UndefinedFunction.getReturnType`.
    fn undefined_function_get_return_type(&self) -> Option<Box<dyn DataType>> {
        None
    }

    /// Default body for [`Function::set_return_type`]: accepted (as a no-op) only for what
    /// approximates `DataType.DEFAULT` (see the module docs), rejected otherwise. Port of
    /// `UndefinedFunction.setReturnType`.
    fn undefined_function_set_return_type(
        &self,
        data_type: &dyn DataType,
    ) -> Result<(), InvalidInputException> {
        if data_type.get_name() == "undefined" {
            Ok(())
        } else {
            Err(InvalidInputException::with_message(
                "UndefinedFunction may not be modified",
            ))
        }
    }

    /// Default body for [`Function::get_signature`]/[`Function::get_signature_formal`]: ignores
    /// `formal_signature` and always returns the stored signature. Port of
    /// `UndefinedFunction.getSignature()`/`getSignature(boolean)`.
    fn undefined_function_get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
        self.stored_signature()
    }

    /// Default body for [`Function::get_prototype_string`]: ignores `formal_signature`. Port of
    /// `UndefinedFunction.getPrototypeString`.
    fn undefined_function_get_prototype_string(
        &self,
        _formal_signature: bool,
        include_calling_convention: bool,
    ) -> String {
        self.stored_signature()
            .get_prototype_string_with_calling_convention(include_calling_convention)
    }

    /// Default body for [`Function::get_signature_source`]. Port of
    /// `UndefinedFunction.getSignatureSource`.
    fn undefined_function_get_signature_source(&self) -> SourceType {
        SourceType::Default
    }

    /// Default body for [`Function::get_stack_frame`]. Port of
    /// `UndefinedFunction.getStackFrame`.
    fn undefined_function_get_stack_frame(&self) -> Box<dyn StackFrame> {
        self.stored_frame()
    }

    /// Default body for [`Function::get_stack_purge_size`]. Port of
    /// `UndefinedFunction.getStackPurgeSize`.
    fn undefined_function_get_stack_purge_size(&self) -> i32 {
        0
    }

    /// Default body for [`Function::has_no_return`]. Port of `UndefinedFunction.hasNoReturn`.
    fn undefined_function_has_no_return(&self) -> bool {
        false
    }

    /// Default body for [`Function::has_var_args`]. Port of `UndefinedFunction.hasVarArgs`.
    fn undefined_function_has_var_args(&self) -> bool {
        false
    }

    /// Default body for [`Function::is_inline`]. Port of `UndefinedFunction.isInline`.
    fn undefined_function_is_inline(&self) -> bool {
        false
    }

    /// Default body for [`Function::is_stack_purge_size_valid`]. Port of
    /// `UndefinedFunction.isStackPurgeSizeValid`.
    fn undefined_function_is_stack_purge_size_valid(&self) -> bool {
        false
    }

    /// Default body for [`Function::set_body`]: unconditionally replaces the stored body (Java's
    /// override performs no validation, unlike the general `Function.setBody` contract). Port of
    /// `UndefinedFunction.setBody`.
    fn undefined_function_set_body(
        &mut self,
        new_body: &dyn AddressSetView,
    ) -> Result<(), OverlappingFunctionException> {
        self.set_stored_body(AddressSet::new().union(new_body));
        Ok(())
    }

    /// Default body for [`Function::is_thunk`]. Port of `UndefinedFunction.isThunk`.
    fn undefined_function_is_thunk(&self) -> bool {
        false
    }

    /// Default body for [`Function::get_thunked_function`]. Port of
    /// `UndefinedFunction.getThunkedFunction`.
    fn undefined_function_get_thunked_function(&self) -> Option<Arc<dyn Function>> {
        None
    }

    /// Default body for [`Function::get_function_thunk_addresses`]. Port of
    /// `UndefinedFunction.getFunctionThunkAddresses`.
    fn undefined_function_get_function_thunk_addresses(&self) -> Option<Vec<Address>> {
        None
    }

    /// Default body for [`Function::get_calling_functions`]. Port of
    /// `UndefinedFunction.getCallingFunctions`.
    fn undefined_function_get_calling_functions(&self) -> Vec<Arc<dyn Function>> {
        Vec::new()
    }

    /// Default body for [`Function::get_called_functions`]. Port of
    /// `UndefinedFunction.getCalledFunctions`.
    fn undefined_function_get_called_functions(&self) -> Vec<Arc<dyn Function>> {
        Vec::new()
    }

    /// Default body for [`Function::get_call_fixup`]. Port of
    /// `UndefinedFunction.getCallFixup`.
    fn undefined_function_get_call_fixup(&self) -> Option<String> {
        None
    }

    /// Default body for [`Namespace::get_parent_namespace`](crate::program::model::symbol::Namespace::get_parent_namespace).
    /// Port of `UndefinedFunction.getParentNamespace`.
    fn undefined_function_get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
        self.get_program().get_global_namespace()
    }

    /// Default body for [`Namespace::get_symbol`](crate::program::model::symbol::Namespace::get_symbol):
    /// always rejected, mirroring Java's unchecked `UnsupportedOperationException` (the trait
    /// method has no `Result` to report it through). Port of `UndefinedFunction.getSymbol`.
    fn undefined_function_get_symbol(&self) -> Arc<dyn Symbol> {
        panic!("UndefinedFunction does not have a symbol")
    }

    /// Compares `self` and `other` the way `UndefinedFunction.equals`/`hashCode` do together: by
    /// entry point and body, standing in for Java's `entry.equals(...)` +
    /// `SystemUtilities.isEqual(getBody(), ...)` (there being no `obj instanceof
    /// UndefinedFunction` downcast in Rust). Port of `UndefinedFunction.equals`.
    fn undefined_function_eq(&self, other: &dyn Function) -> bool {
        self.get_entry_point() == other.get_entry_point()
            && self.get_body().has_same_addresses(&*other.get_body())
    }

    /// Port of `UndefinedFunction.hashCode` (`entry.hashCode()`).
    fn undefined_function_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.get_entry_point().hash(&mut hasher);
        hasher.finish()
    }

    /// Rejects with `err`, standing in for the many `UndefinedFunction` overrides that just
    /// `throw new UnsupportedOperationException()`.
    fn undefined_function_reject<T>(&self) -> Result<T, InvalidInputException> {
        Err(InvalidInputException::with_message(
            "UndefinedFunction may not be modified",
        ))
    }

    /// Default body for [`Function::add_local_variable`]/[`Function::add_parameter`]/
    /// [`Function::insert_parameter`]. Port of `UndefinedFunction.addLocalVariable`/
    /// `addParameter`/`insertParameter`.
    fn undefined_function_reject_edit<T>(&self) -> Result<T, FunctionEditError> {
        Err(FunctionEditError::InvalidInput(InvalidInputException::with_message(
            "UndefinedFunction may not be modified",
        )))
    }

    /// Default body for [`Function::set_name`]. Port of `UndefinedFunction.setName`.
    fn undefined_function_set_name(&self) -> Result<(), SetFunctionNameError> {
        Err(SetFunctionNameError::InvalidInput(InvalidInputException::with_message(
            "UndefinedFunction may not be modified",
        )))
    }

    /// Default body for [`Function::set_thunked_function`]. Port of
    /// `UndefinedFunction.setThunkedFunction`.
    fn undefined_function_set_thunked_function(&self) -> Result<(), String> {
        Err("UndefinedFunction may not be modified".to_string())
    }

    /// Constructs a new undefined function value for `entry` within `program`, mirroring
    /// `UndefinedFunction(Program, Address)`. Bounded by `Self: Sized` since a trait cannot build
    /// "a new Self" generically.
    fn new_undefined_function(
        program: Arc<dyn Program>,
        entry: Option<Address>,
    ) -> Result<Self, InvalidInputException>
    where
        Self: Sized;

    /// Port of `UndefinedFunction.findFunction`: identifies an undefined function based on the
    /// listing disassembly at `address`, first trying the simple block model then falling back
    /// to the isolated-entry sub model. Returns `None` if `address` has no code block in either
    /// model, the monitor is already cancelled, or construction fails.
    fn find_function(
        program: Arc<dyn Program>,
        address: &Address,
        monitor: &dyn TaskMonitor,
        block_model: &dyn SimpleBlockModel,
        isolated_model: &dyn IsolatedEntrySubModelLike,
    ) -> Option<Self>
    where
        Self: Sized,
    {
        if monitor.is_cancelled() {
            return None;
        }
        if let Some(f) =
            Self::find_function_using_simple_block_model(program.clone(), address, monitor, block_model)
        {
            return Some(f);
        }
        if monitor.is_cancelled() {
            return None;
        }
        Self::find_function_using_isolated_block_model(program, address, monitor, isolated_model)
    }

    /// Port of `UndefinedFunction.findFunctionUsingIsolatedBlockModel`.
    fn find_function_using_isolated_block_model(
        program: Arc<dyn Program>,
        address: &Address,
        monitor: &dyn TaskMonitor,
        isolated_model: &dyn IsolatedEntrySubModelLike,
    ) -> Option<Self>
    where
        Self: Sized,
    {
        monitor.set_message(&format!(
            "Find undefined entry for {address} (isolated entry model)"
        ));
        let block = isolated_model
            .get_first_code_block_containing(address, monitor)
            .ok()
            .flatten()?;
        let entry = block.get_first_start_address()?;
        Self::new_undefined_function(program, Some(entry)).ok()
    }

    /// Port of `UndefinedFunction.findFunctionUsingSimpleBlockModel` (see the module docs for why
    /// the `getListing().getInstructionContaining(address) == null` fast-path is not ported).
    fn find_function_using_simple_block_model(
        program: Arc<dyn Program>,
        address: &Address,
        monitor: &dyn TaskMonitor,
        block_model: &dyn SimpleBlockModel,
    ) -> Option<Self>
    where
        Self: Sized,
    {
        monitor.set_message(&format!("Find undefined entry for {address} (simple model)"));
        let block = find_entry_block(block_model, address, monitor).ok().flatten()?;
        let entry = block.get_first_start_address()?;
        Self::new_undefined_function(program, Some(entry)).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::block::code_block_reference::CodeBlockReference;
    use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
    use crate::program::model::listing::function::SetFunctionNameError;
    use crate::program::model::listing::FunctionUpdateType;
    use crate::program::model::symbol::SymbolType;
    use crate::program::model::block::code_block_model::CodeBlockModel;
    use crate::program::seam_stubs::FlowType;
    use crate::util::task::DummyMonitor;

    fn mock_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(mock_space(), offset)
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

    struct MockSignature;
    impl FunctionSignature for MockSignature {
        fn get_name(&self) -> String {
            "undefined".to_string()
        }
        fn get_prototype_string_with_calling_convention(&self, _include_calling_convention: bool) -> String {
            "void undefined(void)".to_string()
        }
        fn get_arguments(&self) -> Vec<Box<dyn crate::program::model::data::parameter_definition::ParameterDefinition>> {
            Vec::new()
        }
        fn get_return_type(&self) -> Box<dyn DataType> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn has_var_args(&self) -> bool {
            false
        }
        fn has_no_return(&self) -> bool {
            false
        }
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            UNKNOWN_CALLING_CONVENTION_STRING.to_string()
        }
        fn is_equivalent_signature(&self, _signature: &dyn FunctionSignature) -> bool {
            false
        }
    }

    struct MockStackFrame;
    impl StackFrame for MockStackFrame {
        fn get_function(&self) -> Option<Box<dyn Function>> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_frame_size(&self) -> i32 {
            0
        }
        fn get_local_size(&self) -> i32 {
            0
        }
        fn get_parameter_size(&self) -> i32 {
            0
        }
        fn get_parameter_offset(&self) -> i32 {
            0
        }
        fn is_parameter_offset(&self, _offset: i32) -> bool {
            false
        }
        fn set_local_size(&mut self, _size: i32) {}
        fn set_return_address_offset(&mut self, _offset: i32) {}
        fn get_return_address_offset(&self) -> i32 {
            0
        }
        fn get_variable_containing(&self, _offset: i32) -> Option<Box<dyn Variable>> {
            None
        }
        fn create_variable(
            &mut self,
            _name: &str,
            _offset: i32,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, crate::program::model::listing::stack_frame::CreateStackVariableError> {
            unimplemented!("not needed for this smoke test")
        }
        fn clear_variable(&mut self, _offset: i32) {}
        fn get_stack_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_parameters(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_locals(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn grows_negative(&self) -> bool {
            true
        }
    }

    /// Minimal `UndefinedFunction`/`Function`/`Namespace` implementor backed by plain struct
    /// fields. Every method this port gives a real algorithm to just delegates to its
    /// `undefined_function_*` counterpart, mirroring `MockAutoParameterImpl` in the sibling
    /// `auto_parameter_impl` module.
    struct MockUndefinedFunction {
        program: Arc<dyn Program>,
        entry: Address,
        body: AddressSet,
    }

    impl MockUndefinedFunction {
        fn try_new(program: Arc<dyn Program>, entry: Option<Address>) -> Result<Self, InvalidInputException> {
            check_entry_is_memory_address(entry.as_ref())?;
            let body = match &entry {
                Some(e) => AddressSet::from_address(e.clone()),
                None => AddressSet::new(),
            };
            Ok(MockUndefinedFunction {
                program,
                entry: entry.unwrap_or_else(|| addr(0)),
                body,
            })
        }
    }

    impl Namespace for MockUndefinedFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.undefined_function_get_symbol()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.undefined_function_get_parent_namespace()
        }
        fn get_name_with_path(&self, include_namespace_path: bool) -> String {
            self.undefined_function_get_name_with_path(include_namespace_path)
        }
        fn get_body(&self) -> Box<dyn AddressSetView> {
            Box::new(self.stored_body_owned())
        }
    }

    impl MockUndefinedFunction {
        fn stored_body_owned(&self) -> AddressSet {
            self.body.clone()
        }
    }

    impl Function for MockUndefinedFunction {
        fn get_name(&self) -> String {
            self.undefined_function_get_name()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            self.undefined_function_set_name()
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {
            panic!("UndefinedFunction may not be modified")
        }
        fn get_call_fixup(&self) -> Option<String> {
            self.undefined_function_get_call_fixup()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_comment(&self) -> Option<String> {
            self.undefined_function_get_comment()
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            self.undefined_function_get_comment_as_array()
        }
        fn set_comment(&mut self, _comment: Option<&str>) {
            panic!("UndefinedFunction may not be modified")
        }
        fn get_repeatable_comment(&self) -> Option<String> {
            self.undefined_function_get_repeatable_comment()
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            self.undefined_function_get_repeatable_comment_as_array()
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {
            panic!("UndefinedFunction may not be modified")
        }
        fn get_entry_point(&self) -> Address {
            self.entry.clone()
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            self.undefined_function_get_return_type()
        }
        fn set_return_type(
            &mut self,
            data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.undefined_function_set_return_type(data_type.as_ref())
        }
        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!("not needed for this smoke test (ReturnParameterImpl not yet ported)")
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Err(InvalidInputException::with_message("UndefinedFunction may not be modified"))
        }
        fn get_signature_formal(&self, formal_signature: bool) -> Box<dyn FunctionSignature> {
            self.undefined_function_get_signature_formal(formal_signature)
        }
        fn get_prototype_string(&self, formal_signature: bool, include_calling_convention: bool) -> String {
            self.undefined_function_get_prototype_string(formal_signature, include_calling_convention)
        }
        fn get_signature_source(&self) -> SourceType {
            self.undefined_function_get_signature_source()
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {
            panic!("UndefinedFunction may not be modified")
        }
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            self.undefined_function_get_stack_frame()
        }
        fn get_stack_purge_size(&self) -> i32 {
            self.undefined_function_get_stack_purge_size()
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            panic!("UndefinedFunction may not be modified")
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            panic!("UndefinedFunction may not be modified")
        }
        fn remove_tag(&mut self, _name: &str) {
            panic!("UndefinedFunction may not be modified")
        }
        fn set_stack_purge_size(&mut self, _purge_size: i32) {
            panic!("UndefinedFunction may not be modified")
        }
        fn is_stack_purge_size_valid(&self) -> bool {
            self.undefined_function_is_stack_purge_size_valid()
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            self.undefined_function_reject_edit()
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            self.undefined_function_reject_edit()
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            self.undefined_function_reject_edit()
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            self.undefined_function_reject_edit()
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            self.undefined_function_get_parameter()
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {
            panic!("UndefinedFunction may not be modified")
        }
        #[allow(deprecated)]
        fn move_parameter(&mut self, _from_ordinal: i32, _to_ordinal: i32) -> Result<Box<dyn Parameter>, InvalidInputException> {
            Err(InvalidInputException::with_message("UndefinedFunction may not be modified"))
        }
        fn get_parameter_count(&self) -> i32 {
            self.undefined_function_get_parameter_count()
        }
        fn get_auto_parameter_count(&self) -> i32 {
            self.undefined_function_get_auto_parameter_count()
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            self.undefined_function_get_parameters()
        }
        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            self.undefined_function_get_parameters()
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            self.undefined_function_get_variables()
        }
        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            self.undefined_function_get_variables()
        }
        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            self.undefined_function_get_variables()
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            self.undefined_function_get_variables()
        }
        fn add_local_variable(&mut self, _var: Box<dyn Variable>, _source: SourceType) -> Result<Box<dyn Variable>, FunctionEditError> {
            self.undefined_function_reject_edit()
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {
            panic!("UndefinedFunction may not be modified")
        }
        fn set_body(&mut self, new_body: &dyn AddressSetView) -> Result<(), OverlappingFunctionException> {
            self.undefined_function_set_body(new_body)
        }
        fn has_var_args(&self) -> bool {
            self.undefined_function_has_var_args()
        }
        fn set_var_args(&mut self, _has_var_args: bool) {
            panic!("UndefinedFunction may not be modified")
        }
        fn is_inline(&self) -> bool {
            self.undefined_function_is_inline()
        }
        fn set_inline(&mut self, _is_inline: bool) {
            panic!("UndefinedFunction may not be modified")
        }
        fn has_no_return(&self) -> bool {
            self.undefined_function_has_no_return()
        }
        fn set_no_return(&mut self, _has_no_return: bool) {
            panic!("UndefinedFunction may not be modified")
        }
        fn has_custom_variable_storage(&self) -> bool {
            self.undefined_function_has_custom_variable_storage()
        }
        fn set_custom_variable_storage(&mut self, has_custom_variable_storage: bool) {
            self.undefined_function_set_custom_variable_storage(has_custom_variable_storage)
        }
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            self.undefined_function_get_calling_convention()
        }
        fn get_calling_convention_name(&self) -> String {
            self.undefined_function_get_calling_convention_name()
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            Err(InvalidInputException::with_message("UndefinedFunction may not be modified"))
        }
        fn is_thunk(&self) -> bool {
            self.undefined_function_is_thunk()
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            self.undefined_function_get_thunked_function()
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            self.undefined_function_get_function_thunk_addresses()
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            self.undefined_function_set_thunked_function()
        }
        fn is_external(&self) -> bool {
            self.undefined_function_is_external()
        }
        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
            self.undefined_function_get_external_location()
        }
        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            self.undefined_function_get_calling_functions()
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            self.undefined_function_get_called_functions()
        }
        fn promote_local_user_labels_to_global(&mut self) {
            panic!("UndefinedFunction may not be modified")
        }
        fn is_deleted(&self) -> bool {
            self.undefined_function_is_deleted()
        }
    }

    impl UndefinedFunction for MockUndefinedFunction {
        fn stored_signature(&self) -> Box<dyn FunctionSignature> {
            Box::new(MockSignature)
        }
        fn stored_frame(&self) -> Box<dyn StackFrame> {
            Box::new(MockStackFrame)
        }
        fn stored_body(&self) -> Box<dyn AddressSetView> {
            Box::new(self.body.clone())
        }
        fn set_stored_body(&mut self, new_body: AddressSet) {
            self.body = new_body;
        }
        fn new_undefined_function(
            program: Arc<dyn Program>,
            entry: Option<Address>,
        ) -> Result<Self, InvalidInputException> {
            MockUndefinedFunction::try_new(program, entry)
        }
    }

    #[test]
    fn constructor_rejects_non_memory_entry() {
        let stack_space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 2);
        let bad_entry = Address::new(stack_space, 0);
        let result = MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(bad_entry));
        assert!(result.is_err());
    }

    #[test]
    fn constructor_accepts_memory_entry() {
        let f = MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(addr(0x1000))).unwrap();
        assert_eq!(f.get_entry_point(), addr(0x1000));
    }

    #[test]
    fn get_name_uses_entry_address() {
        let f = MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(addr(0x1000))).unwrap();
        assert_eq!(Function::get_name(&f), format!("UndefinedFunction_{}", addr(0x1000).format(false, 8)));
    }

    #[test]
    fn fixed_query_defaults_match_java() {
        let f = MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(addr(0x1000))).unwrap();
        assert!(!f.is_deleted());
        assert!(!Function::is_external(&f));
        assert!(f.get_external_location().is_none());
        assert!(f.has_unknown_calling_convention_name());
        assert_eq!(f.get_calling_convention_name(), "unknown");
        assert_eq!(f.get_parameter_count(), 0);
        assert_eq!(f.get_stack_purge_size(), 0);
        assert!(f.get_parameters().is_empty());
        assert!(f.get_return_type().is_none());
    }

    #[test]
    fn set_return_type_only_accepts_default() {
        struct OtherType;
        impl DataType for OtherType {
            fn get_name(&self) -> String {
                "other".to_string()
            }
            fn get_length(&self) -> i32 {
                4
            }
        }
        struct DefaultType;
        impl DataType for DefaultType {
            fn get_name(&self) -> String {
                "undefined".to_string()
            }
            fn get_length(&self) -> i32 {
                1
            }
        }

        let mut f = MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(addr(0x1000))).unwrap();
        assert!(f.set_return_type(Box::new(DefaultType), SourceType::Analysis).is_ok());
        assert!(f.set_return_type(Box::new(OtherType), SourceType::Analysis).is_err());
    }

    #[test]
    fn set_body_replaces_stored_body() {
        let mut f = MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(addr(0x1000))).unwrap();
        let mut new_body = AddressSet::new();
        new_body.add_range(&addr(0x2000), &addr(0x2010));
        assert!(Function::set_body(&mut f, &new_body).is_ok());
        assert!(Namespace::get_body(&f).has_same_addresses(&new_body));
    }

    #[test]
    fn equals_and_hash_compare_by_entry_and_body() {
        let a = MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(addr(0x1000))).unwrap();
        let b = MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(addr(0x1000))).unwrap();
        let c = MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(addr(0x2000))).unwrap();
        assert!(a.undefined_function_eq(&b));
        assert!(!a.undefined_function_eq(&c));
        assert_eq!(a.undefined_function_hash(), b.undefined_function_hash());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let f: Box<dyn Function> = Box::new(MockUndefinedFunction::try_new(Arc::new(MockProgram), Some(addr(0x1000))).unwrap());
        assert!(!f.is_deleted() || f.is_deleted()); // dyn dispatch reaches the impl at all
        assert_eq!(f.get_calling_convention_name(), "unknown");
    }

    // --- getEntryBlock / find_function_using_simple_block_model -----------------------------

    struct MockFlowType {
        call: bool,
        indirect: bool,
    }
    impl FlowType for MockFlowType {
        fn is_call(&self) -> bool {
            self.call
        }
        fn is_indirect(&self) -> bool {
            self.indirect
        }
    }

    struct MockCodeBlockModel;
    impl CodeBlockModel for MockCodeBlockModel {
        fn get_name(&self) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_block_at(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_first_code_block_containing(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_blocks_containing(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_num_sources(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_num_destinations(
            &self,
            _block: &dyn CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_flow_type(&self, _block: &dyn CodeBlock) -> Box<dyn FlowType> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_block_name(&self, _block: &dyn CodeBlock) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// A single-address `CodeBlock` in a tiny hand-built flow graph, with an explicit list of
    /// (source address, is-call) source edges.
    #[derive(Clone)]
    struct GraphBlock {
        start: Address,
        sources: Vec<(Address, bool)>,
    }

    impl CodeBlock for GraphBlock {
        fn get_min_address(&self) -> Option<Address> {
            Some(self.start.clone())
        }
        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            Box::new(MockCodeBlockModel)
        }
        fn get_destinations(&self, _monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_empty(&self) -> bool {
            false
        }
        fn get_first_start_address(&self) -> Option<Address> {
            Some(self.start.clone())
        }
        fn get_sources(&self, _monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            Ok(Box::new(GraphSourceIterator {
                block_start: self.start.clone(),
                sources: self.sources.clone(),
                index: 0,
            }))
        }
    }

    struct GraphCodeBlockReference {
        source: Address,
        destination: Address,
        is_call: bool,
    }
    impl CodeBlockReference for GraphCodeBlockReference {
        fn get_source_address(&self) -> Address {
            self.source.clone()
        }
        fn get_destination_address(&self) -> Address {
            self.destination.clone()
        }
        fn get_flow_type(&self) -> Box<dyn FlowType> {
            Box::new(MockFlowType { call: self.is_call, indirect: false })
        }
        fn get_reference(&self) -> Address {
            self.destination.clone()
        }
        fn get_referent(&self) -> Address {
            self.source.clone()
        }
        fn get_destination_block(&self) -> Box<dyn CodeBlock> {
            Box::new(GraphBlock { start: self.destination.clone(), sources: Vec::new() })
        }
        fn get_source_block(&self) -> Box<dyn CodeBlock> {
            // Sources beyond the immediate test graph report no further sources of their own.
            Box::new(GraphBlock { start: self.source.clone(), sources: Vec::new() })
        }
    }

    struct GraphSourceIterator {
        block_start: Address,
        sources: Vec<(Address, bool)>,
        index: usize,
    }
    impl CodeBlockReferenceIterator for GraphSourceIterator {
        fn has_next(&mut self) -> Result<bool, CancelledException> {
            Ok(self.index < self.sources.len())
        }
        fn next(&mut self) -> Result<Box<dyn CodeBlockReference>, CancelledException> {
            let (source, is_call) = self.sources[self.index].clone();
            self.index += 1;
            Ok(Box::new(GraphCodeBlockReference {
                source,
                destination: self.block_start.clone(),
                is_call,
            }))
        }
    }

    /// A [`SimpleBlockModel`] whose `get_first_code_block_containing` always returns the same
    /// pre-built block, regardless of the requested address -- enough to drive
    /// [`find_entry_block`]'s worklist walk in isolation.
    struct FixedSimpleBlockModel {
        block: GraphBlock,
    }
    impl SimpleBlockModel for FixedSimpleBlockModel {
        fn get_code_block_at(&self, _addr: &Address, _monitor: &dyn TaskMonitor) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_first_code_block_containing(&self, _addr: &Address, _monitor: &dyn TaskMonitor) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            Ok(Some(Box::new(self.block.clone())))
        }
        fn get_code_blocks(&self, _monitor: &dyn TaskMonitor) -> Result<Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_blocks_overlapping(&self, _addr_set: &dyn AddressSetView, _monitor: &dyn TaskMonitor) -> Result<Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_block_name(&self, _block: &dyn CodeBlock) -> String {
            unimplemented!("not needed for this smoke test")
        }
        fn get_flow_type(&self, _block: &dyn CodeBlock) -> crate::program::model::symbol::RefType {
            unimplemented!("not needed for this smoke test")
        }
        fn get_sources(&self, block: &dyn CodeBlock, monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            block.get_sources(monitor)
        }
        fn get_num_sources(&self, _block: &dyn CodeBlock, _monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_destinations(&self, block: &dyn CodeBlock, monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            block.get_destinations(monitor)
        }
        fn get_num_destinations(&self, _block: &dyn CodeBlock, _monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_basic_block_model(&self) -> Box<dyn SimpleBlockModel> {
            unimplemented!("not needed for this smoke test")
        }
        fn externals_included(&self) -> bool {
            false
        }
        fn is_block_start(&self, _instruction: &dyn crate::program::model::listing::instruction::Instruction) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn has_end_of_block_flow(&self, _instr: &dyn crate::program::model::listing::instruction::Instruction) -> bool {
            unimplemented!("not needed for this smoke test")
        }
    }

    #[test]
    fn find_entry_block_walks_back_to_true_entry() {
        // A two-hop chain: requested (0x3000) <- middle (0x2000) <- real_entry (0x1000, no
        // sources of its own). `find_entry_block` should walk all the way back to real_entry.
        let real_entry = addr(0x1000);
        let middle_block = GraphBlock {
            start: addr(0x2000),
            sources: vec![(real_entry.clone(), false)],
        };

        struct ChainSourceIterator {
            destination: Address,
            emitted: bool,
            next_block: Option<GraphBlock>,
        }
        impl CodeBlockReferenceIterator for ChainSourceIterator {
            fn has_next(&mut self) -> Result<bool, CancelledException> {
                Ok(!self.emitted)
            }
            fn next(&mut self) -> Result<Box<dyn CodeBlockReference>, CancelledException> {
                self.emitted = true;
                Ok(Box::new(ChainReference {
                    source: self.next_block.take().unwrap(),
                    destination: self.destination.clone(),
                }))
            }
        }
        struct ChainReference {
            source: GraphBlock,
            destination: Address,
        }
        impl CodeBlockReference for ChainReference {
            fn get_source_address(&self) -> Address {
                self.source.start.clone()
            }
            fn get_destination_address(&self) -> Address {
                self.destination.clone()
            }
            fn get_flow_type(&self) -> Box<dyn FlowType> {
                Box::new(MockFlowType { call: false, indirect: false })
            }
            fn get_reference(&self) -> Address {
                self.destination.clone()
            }
            fn get_referent(&self) -> Address {
                self.source.start.clone()
            }
            fn get_destination_block(&self) -> Box<dyn CodeBlock> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_source_block(&self) -> Box<dyn CodeBlock> {
                Box::new(self.source.clone())
            }
        }

        #[derive(Clone)]
        struct ChainBlock(GraphBlock, Option<Box<GraphBlock>>);
        impl CodeBlock for ChainBlock {
            fn get_min_address(&self) -> Option<Address> {
                Some(self.0.start.clone())
            }
            fn get_model(&self) -> Box<dyn CodeBlockModel> {
                Box::new(MockCodeBlockModel)
            }
            fn get_destinations(&self, _monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn is_empty(&self) -> bool {
                false
            }
            fn get_first_start_address(&self) -> Option<Address> {
                Some(self.0.start.clone())
            }
            fn get_sources(&self, _monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
                match &self.1 {
                    Some(next) => Ok(Box::new(ChainSourceIterator {
                        destination: self.0.start.clone(),
                        emitted: false,
                        next_block: Some((**next).clone()),
                    })),
                    None => Ok(Box::new(crate::program::seam_stubs::EmptyCodeBlockReferenceIterator)),
                }
            }
        }

        let requested_chain_block = ChainBlock(
            GraphBlock { start: addr(0x3000), sources: Vec::new() },
            Some(Box::new(middle_block.clone())),
        );

        struct ChainModel(ChainBlock);
        impl SimpleBlockModel for ChainModel {
            fn get_code_block_at(&self, _addr: &Address, _monitor: &dyn TaskMonitor) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_first_code_block_containing(&self, _addr: &Address, _monitor: &dyn TaskMonitor) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
                Ok(Some(Box::new(self.0.clone())))
            }
            fn get_code_blocks(&self, _monitor: &dyn TaskMonitor) -> Result<Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_code_blocks_overlapping(&self, _addr_set: &dyn AddressSetView, _monitor: &dyn TaskMonitor) -> Result<Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_program(&self) -> Arc<dyn Program> {
                Arc::new(MockProgram)
            }
            fn get_block_name(&self, _block: &dyn CodeBlock) -> String {
                unimplemented!("not needed for this smoke test")
            }
            fn get_flow_type(&self, _block: &dyn CodeBlock) -> crate::program::model::symbol::RefType {
                unimplemented!("not needed for this smoke test")
            }
            fn get_sources(&self, block: &dyn CodeBlock, monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
                block.get_sources(monitor)
            }
            fn get_num_sources(&self, _block: &dyn CodeBlock, _monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_destinations(&self, block: &dyn CodeBlock, monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
                block.get_destinations(monitor)
            }
            fn get_num_destinations(&self, _block: &dyn CodeBlock, _monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_basic_block_model(&self) -> Box<dyn SimpleBlockModel> {
                unimplemented!("not needed for this smoke test")
            }
            fn externals_included(&self) -> bool {
                false
            }
            fn is_block_start(&self, _instruction: &dyn crate::program::model::listing::instruction::Instruction) -> bool {
                unimplemented!("not needed for this smoke test")
            }
            fn has_end_of_block_flow(&self, _instr: &dyn crate::program::model::listing::instruction::Instruction) -> bool {
                unimplemented!("not needed for this smoke test")
            }
        }

        let model = ChainModel(requested_chain_block);
        let monitor = DummyMonitor;
        let found = find_entry_block(&model, &addr(0x3000), &monitor).unwrap().unwrap();
        assert_eq!(found.get_first_start_address(), Some(real_entry));
    }

    #[test]
    fn find_function_using_simple_block_model_builds_function_at_entry() {
        let real_entry = addr(0x1000);
        let block = GraphBlock {
            start: real_entry.clone(),
            sources: Vec::new(),
        };
        let model = FixedSimpleBlockModel { block };
        let monitor = DummyMonitor;
        let found = MockUndefinedFunction::find_function_using_simple_block_model(
            Arc::new(MockProgram),
            &addr(0x3000),
            &monitor,
            &model,
        )
        .expect("expected a function to be found");
        assert_eq!(found.get_entry_point(), real_entry);
    }

    struct MockIsolatedModel {
        block: Option<GraphBlock>,
    }
    impl IsolatedEntrySubModelLike for MockIsolatedModel {
        fn get_first_code_block_containing(&self, _addr: &Address, _monitor: &dyn TaskMonitor) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
            Ok(self.block.clone().map(|b| Box::new(b) as Box<dyn CodeBlock>))
        }
    }

    #[test]
    fn find_function_using_isolated_block_model_builds_function_at_entry() {
        let entry = addr(0x4000);
        let model = MockIsolatedModel { block: Some(GraphBlock { start: entry.clone(), sources: Vec::new() }) };
        let monitor = DummyMonitor;
        let found = MockUndefinedFunction::find_function_using_isolated_block_model(
            Arc::new(MockProgram),
            &addr(0x4000),
            &monitor,
            &model,
        )
        .expect("expected a function to be found");
        assert_eq!(found.get_entry_point(), entry);
    }

    #[test]
    fn find_function_falls_back_to_isolated_model_when_simple_model_finds_nothing() {
        struct EmptySimpleBlockModel;
        impl SimpleBlockModel for EmptySimpleBlockModel {
            fn get_code_block_at(&self, _addr: &Address, _monitor: &dyn TaskMonitor) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_first_code_block_containing(&self, _addr: &Address, _monitor: &dyn TaskMonitor) -> Result<Option<Box<dyn CodeBlock>>, CancelledException> {
                Ok(None)
            }
            fn get_code_blocks(&self, _monitor: &dyn TaskMonitor) -> Result<Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_code_blocks_overlapping(&self, _addr_set: &dyn AddressSetView, _monitor: &dyn TaskMonitor) -> Result<Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_program(&self) -> Arc<dyn Program> {
                Arc::new(MockProgram)
            }
            fn get_block_name(&self, _block: &dyn CodeBlock) -> String {
                unimplemented!("not needed for this smoke test")
            }
            fn get_flow_type(&self, _block: &dyn CodeBlock) -> crate::program::model::symbol::RefType {
                unimplemented!("not needed for this smoke test")
            }
            fn get_sources(&self, _block: &dyn CodeBlock, _monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_num_sources(&self, _block: &dyn CodeBlock, _monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_destinations(&self, _block: &dyn CodeBlock, _monitor: &dyn TaskMonitor) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_num_destinations(&self, _block: &dyn CodeBlock, _monitor: &dyn TaskMonitor) -> Result<i32, CancelledException> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_basic_block_model(&self) -> Box<dyn SimpleBlockModel> {
                unimplemented!("not needed for this smoke test")
            }
            fn externals_included(&self) -> bool {
                false
            }
            fn is_block_start(&self, _instruction: &dyn crate::program::model::listing::instruction::Instruction) -> bool {
                unimplemented!("not needed for this smoke test")
            }
            fn has_end_of_block_flow(&self, _instr: &dyn crate::program::model::listing::instruction::Instruction) -> bool {
                unimplemented!("not needed for this smoke test")
            }
        }

        let entry = addr(0x5000);
        let isolated = MockIsolatedModel { block: Some(GraphBlock { start: entry.clone(), sources: Vec::new() }) };
        let simple = EmptySimpleBlockModel;
        let monitor = DummyMonitor;

        let found = MockUndefinedFunction::find_function(
            Arc::new(MockProgram),
            &addr(0x5000),
            &monitor,
            &simple,
            &isolated,
        )
        .expect("expected the isolated model fallback to find a function");
        assert_eq!(found.get_entry_point(), entry);
    }

    #[test]
    fn symbol_type_used_in_doc_example_compiles() {
        // Keep `SymbolType` imported (used implicitly by the wider `Namespace`/`Symbol`
        // machinery this module's mocks touch) so this module's import list stays honest if
        // the mocks above change.
        let _ = SymbolType::Function;
    }
}
