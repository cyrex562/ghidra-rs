//! Port of `ghidra.program.model.listing.ReturnParameterImpl`.
//!
//! The Java class is a tiny, concrete `ReturnParameterImpl extends ParameterImpl`, representing a
//! function's return value: it always has ordinal [`RETURN_ORDINAL`] and name [`RETURN_NAME`],
//! and it overrides `isVoidAllowed()` to `true` (a return value, unlike an ordinary parameter, may
//! legitimately have the `void` datatype). Every constructor forwards to `ParameterImpl`'s own
//! private nine-argument constructor with `name = RETURN_NAME`, `ordinal = RETURN_ORDINAL`, and
//! `sourceType = null`.
//!
//! Following the same "composition via trait delegation" shape as
//! [`LocalVariableImpl`](crate::program::model::listing::local_variable_impl::LocalVariableImpl)
//! and the production
//! [`MemoryParameter`](crate::app::cmd::function::add_memory_parameter_command) --
//! [`ParameterImpl`](crate::program::model::listing::parameter_impl::ParameterImpl) and
//! [`VariableImpl`](crate::program::model::listing::variable_impl::VariableImpl) are traits, not
//! structs, so there is no `base` field to hold; this concrete type stores the plain fields their
//! `stored_*` accessors read/write and implements `Variable`/`VariableImpl`/`ParameterImpl`/
//! [`Parameter`] by delegating each method to its `variable_impl_*`/`parameter_impl_*`
//! counterpart.
//!
//! `name` is still a real, mutable `Option<String>` field initialized to `Some(RETURN_NAME)`
//! rather than a hardcoded constant getter: Java's `ReturnParameterImpl` does not override
//! `setName`/`getName` (only `isVoidAllowed`), so -- exactly as in Java -- a caller can still
//! change the name via the inherited `Variable.setName`/`VariableImpl.setName`. `ordinal`, by
//! contrast, has no setter anywhere on the `Parameter`/`ParameterImpl` surface reachable from this
//! type, so [`ParameterImpl::stored_ordinal`] is hardcoded to return [`RETURN_ORDINAL`] rather
//! than growing a field nothing can ever legitimately change.
//!
//! ## Constructor collapsing
//!
//! The seven public Java constructors collapse onto six `new_*` functions plus one
//! `new_from_parameter`, mirroring [`LocalVariableImpl`]'s identical collapsing of `VariableImpl`'s
//! storage-kind constructor family:
//!
//! - [`new_from_parameter`](ReturnParameterImpl::new_from_parameter) -- `ReturnParameterImpl(Parameter,
//!   Program)`. See the note below on `VariableStorage.clone(Program)`.
//! - [`new`](ReturnParameterImpl::new) -- `ReturnParameterImpl(DataType, Program)` (no storage).
//! - [`new_stack`](ReturnParameterImpl::new_stack) -- `ReturnParameterImpl(DataType, int, Program)`.
//! - [`new_register`](ReturnParameterImpl::new_register) -- `ReturnParameterImpl(DataType, Register,
//!   Program)`.
//! - [`new_storage_addr`](ReturnParameterImpl::new_storage_addr) -- `ReturnParameterImpl(DataType,
//!   Address, Program)`.
//! - [`new_with_storage`](ReturnParameterImpl::new_with_storage) -- both `ReturnParameterImpl(DataType,
//!   VariableStorage, Program)` and `ReturnParameterImpl(DataType, VariableStorage, boolean,
//!   Program)` (`force` defaults to `false` in Java when omitted; callers here just pass it
//!   explicitly).
//!
//! Every Java constructor passes a literal `null` `sourceType` down to `ParameterImpl`/
//! `VariableImpl`'s constructor. As documented on [`LocalVariableImpl`], passing
//! [`SourceType::UserDefined`] explicitly is behaviorally identical to Java's `null` here (`<RETURN>`
//! never matches `ParameterImpl.hasDefaultName()`'s `"param_N"` pattern, so
//! `hasDefaultName() ? DEFAULT : sourceType` always keeps whatever was passed in, and
//! `VariableImpl.getSource()` maps a stored `null` back to `USER_DEFINED` at read time anyway).
//!
//! ## `VariableStorage.clone(Program)` has no generic trait-level equivalent
//!
//! `new_from_parameter` ports `param.getVariableStorage().clone(program)`. Java's
//! `VariableStorage.clone(ProgramArchitecture)` re-homes a storage's varnodes to a new program's
//! address spaces; only the concrete
//! [`VariableStorageImpl::clone_for_architecture`](crate::program::model::listing::variable_storage::VariableStorageImpl::clone_for_architecture)
//! provides this, not the general `dyn VariableStorage` trait every other storage kind
//! (`VarnodeListStorage`, the auto-storage singletons, etc.) also implements. Since this port
//! (like [`VariableImpl::init_fields`] itself, at its own `check_storage`-duplication call site)
//! only ever holds storage behind `dyn VariableStorage`, `new_from_parameter` instead rebuilds the
//! source parameter's storage via `with_varnodes(get_varnodes())` -- identical behavior for any
//! storage that does not carry program-architecture-specific state (true of every storage kind
//! constructible through this port today), but not a real cross-architecture re-home for a
//! genuine `VariableStorageImpl`.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::parameter::{RETURN_NAME, RETURN_ORDINAL};
use crate::program::model::listing::parameter_impl::ParameterImpl;
use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
use crate::program::model::listing::variable_impl::{init_fields, VariableImpl};
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::{AutoParameterType, Function, Parameter, Program, Variable};
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::SourceType;
use crate::program::seam_stubs::share_data_type;
use crate::util::exception::InvalidInputException;

/// Concrete, in-memory (non-database-backed) representation of a function's return value.
///
/// Port of `ghidra.program.model.listing.ReturnParameterImpl`. See the module docs for the
/// constructor-collapsing convention and the `VariableStorage.clone(Program)` deviation.
pub struct ReturnParameterImpl {
    name: Option<String>,
    data_type: Arc<dyn DataType>,
    comment: Option<String>,
    source_type: SourceType,
    storage: Option<Box<dyn VariableStorage>>,
    program: Arc<dyn Program>,
}

/// Manual `Debug` impl: `data_type`/`program`/`storage` are `dyn` trait objects
/// (`DataType`/`Program`/`VariableStorage`) that do not themselves require `Debug`, so
/// `#[derive(Debug)]` is not available here. Only the plain fields are shown.
impl std::fmt::Debug for ReturnParameterImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReturnParameterImpl")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("source_type", &self.source_type)
            .finish_non_exhaustive()
    }
}

impl ReturnParameterImpl {
    /// Backs every public constructor. Port of the private nine-argument `ParameterImpl`
    /// constructor as called by every `ReturnParameterImpl` overload (`name = RETURN_NAME`,
    /// `ordinal = RETURN_ORDINAL`, `sourceType = null`, always).
    #[allow(clippy::too_many_arguments)]
    fn with_fields(
        data_type: Box<dyn DataType>,
        storage: Option<Box<dyn VariableStorage>>,
        storage_addr: Option<Address>,
        stack_offset: Option<i32>,
        register: Option<RegisterRef>,
        force: bool,
        program: Arc<dyn Program>,
    ) -> Result<Self, InvalidInputException> {
        let fields = init_fields(
            Some(RETURN_NAME.to_string()),
            data_type,
            storage,
            storage_addr,
            stack_offset,
            register,
            force,
            program.as_ref(),
            SourceType::UserDefined,
            true,  // void_allowed: ReturnParameterImpl.isVoidAllowed() is always true
            false, // has_default_name: RETURN_NAME never matches "param_N"
        )?;
        Ok(ReturnParameterImpl {
            name: fields.name,
            data_type: Arc::from(fields.data_type),
            comment: None,
            source_type: fields.source_type,
            storage: Some(fields.variable_storage),
            program,
        })
    }

    /// Construct a return parameter from another, copying its datatype and storage.
    ///
    /// Port of `ReturnParameterImpl(Parameter, Program)`. See the module docs for why this
    /// rebuilds `param`'s storage via `with_varnodes(get_varnodes())` rather than a true
    /// `VariableStorage.clone(Program)` re-home.
    pub fn new_from_parameter(
        param: &dyn Parameter,
        program: Arc<dyn Program>,
    ) -> Result<Self, InvalidInputException> {
        let data_type = param.get_data_type();
        let storage = param
            .get_variable_storage()
            .map(|s| s.with_varnodes(s.get_varnodes()));
        Self::with_fields(data_type, storage, None, None, None, false, program)
    }

    /// Construct a return parameter which has no specific storage specified.
    ///
    /// Port of `ReturnParameterImpl(DataType, Program)`.
    pub fn new(data_type: Box<dyn DataType>, program: Arc<dyn Program>) -> Result<Self, InvalidInputException> {
        Self::with_fields(data_type, None, None, None, None, false, program)
    }

    /// Construct a return parameter at the specified stack offset.
    ///
    /// Port of `ReturnParameterImpl(DataType, int, Program)`.
    pub fn new_stack(
        data_type: Box<dyn DataType>,
        stack_offset: i32,
        program: Arc<dyn Program>,
    ) -> Result<Self, InvalidInputException> {
        Self::with_fields(data_type, None, None, Some(stack_offset), None, false, program)
    }

    /// Construct a return parameter using the specified register.
    ///
    /// Port of `ReturnParameterImpl(DataType, Register, Program)`.
    pub fn new_register(
        data_type: Box<dyn DataType>,
        register: RegisterRef,
        program: Arc<dyn Program>,
    ) -> Result<Self, InvalidInputException> {
        Self::with_fields(data_type, None, None, None, Some(register), false, program)
    }

    /// Construct a return parameter with a single varnode at the specified address.
    ///
    /// Port of `ReturnParameterImpl(DataType, Address, Program)`.
    pub fn new_storage_addr(
        data_type: Box<dyn DataType>,
        storage_addr: Address,
        program: Arc<dyn Program>,
    ) -> Result<Self, InvalidInputException> {
        Self::with_fields(data_type, None, Some(storage_addr), None, None, false, program)
    }

    /// Construct a return parameter with one or more associated storage elements.
    ///
    /// Port of `ReturnParameterImpl(DataType, VariableStorage, Program)` /
    /// `ReturnParameterImpl(DataType, VariableStorage, boolean, Program)` (collapsed; see the
    /// module docs).
    pub fn new_with_storage(
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        force: bool,
        program: Arc<dyn Program>,
    ) -> Result<Self, InvalidInputException> {
        Self::with_fields(data_type, Some(storage), None, None, None, force, program)
    }
}

impl VariableImpl for ReturnParameterImpl {
    /// Port of `ParameterImpl.hasDefaultName` as inherited by `ReturnParameterImpl` (not
    /// overridden). Always evaluates to `false` in practice since `<RETURN>` never matches the
    /// `"param_N"` default-name pattern, but this delegates to the real algorithm (rather than
    /// hardcoding `false`) so it stays correct if `name` is ever changed via `set_name`.
    fn has_default_name(&self) -> bool {
        self.parameter_impl_has_default_name()
    }

    /// Port of `ReturnParameterImpl.isVoidAllowed` (always `true`).
    fn is_void_allowed(&self) -> bool {
        true
    }

    fn stored_name(&self) -> Option<String> {
        self.name.clone()
    }

    fn set_stored_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    fn stored_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }

    fn set_stored_data_type(&mut self, data_type: Box<dyn DataType>) {
        self.data_type = Arc::from(data_type);
    }

    fn stored_comment(&self) -> Option<String> {
        self.comment.clone()
    }

    fn set_stored_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    fn stored_source_type(&self) -> SourceType {
        self.source_type
    }

    fn set_stored_source_type(&mut self, source_type: SourceType) {
        self.source_type = source_type;
    }

    fn stored_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
        self.storage
            .as_ref()
            .map(|s| s.with_varnodes(s.get_varnodes()))
    }

    fn set_stored_variable_storage(&mut self, storage: Option<Box<dyn VariableStorage>>) {
        self.storage = storage;
    }
}

impl ParameterImpl for ReturnParameterImpl {
    /// `ordinal` has no setter anywhere on the reachable `Parameter`/`ParameterImpl` surface (see
    /// the module docs), so this is hardcoded to [`RETURN_ORDINAL`] rather than backed by a field.
    fn stored_ordinal(&self) -> i32 {
        RETURN_ORDINAL
    }
}

impl Variable for ReturnParameterImpl {
    fn get_data_type(&self) -> Box<dyn DataType> {
        self.parameter_impl_get_data_type()
    }

    fn set_data_type_with_storage(
        &mut self,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type_with_storage(data_type, storage, force, source)
    }

    fn set_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type(data_type, source)
    }

    fn set_data_type_aligned(
        &mut self,
        data_type: Box<dyn DataType>,
        align_stack: bool,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type_aligned(data_type, align_stack, force, source)
    }

    fn get_name(&self) -> Option<String> {
        self.variable_impl_get_name()
    }

    fn get_length(&self) -> i32 {
        self.variable_impl_get_length()
    }

    fn is_valid(&self) -> bool {
        self.variable_impl_is_valid()
    }

    fn get_function(&self) -> Option<Box<dyn Function>> {
        self.variable_impl_get_function()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    fn get_source(&self) -> SourceType {
        self.variable_impl_get_source()
    }

    fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetVariableNameError> {
        self.variable_impl_set_name(name, source)
    }

    fn get_comment(&self) -> Option<String> {
        self.variable_impl_get_comment()
    }

    fn set_comment(&mut self, comment: Option<String>) {
        self.variable_impl_set_comment(comment)
    }

    fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
        self.variable_impl_get_variable_storage()
    }

    fn get_first_storage_varnode(&self) -> Option<Varnode> {
        self.variable_impl_get_first_storage_varnode()
    }

    fn get_last_storage_varnode(&self) -> Option<Varnode> {
        self.variable_impl_get_last_storage_varnode()
    }

    fn is_stack_variable(&self) -> bool {
        self.variable_impl_is_stack_variable()
    }

    fn has_stack_storage(&self) -> bool {
        self.variable_impl_has_stack_storage()
    }

    fn is_register_variable(&self) -> bool {
        self.variable_impl_is_register_variable()
    }

    fn get_register(&self) -> Option<RegisterRef> {
        self.variable_impl_get_register()
    }

    fn get_registers(&self) -> Option<Vec<RegisterRef>> {
        self.variable_impl_get_registers()
    }

    fn get_min_address(&self) -> Option<Address> {
        self.variable_impl_get_min_address()
    }

    fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
        self.variable_impl_get_stack_offset()
    }

    fn is_memory_variable(&self) -> bool {
        self.variable_impl_is_memory_variable()
    }

    fn is_unique_variable(&self) -> bool {
        self.variable_impl_is_unique_variable()
    }

    fn is_compound_variable(&self) -> bool {
        self.variable_impl_is_compound_variable()
    }

    fn has_assigned_storage(&self) -> bool {
        self.variable_impl_has_assigned_storage()
    }

    /// Port of `ParameterImpl.getFirstUseOffset` (`final`, always `0`), inherited unchanged.
    fn get_first_use_offset(&self) -> i32 {
        self.parameter_impl_get_first_use_offset()
    }

    fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
        None
    }

    fn is_equivalent(&self, variable: &dyn Variable) -> bool {
        self.variable_impl_is_equivalent(variable)
    }

    fn compare_to(&self, other: &dyn Variable) -> Ordering {
        self.variable_impl_compare_to(other)
    }

    fn is_parameter(&self) -> bool {
        true
    }

    fn is_auto_parameter(&self) -> bool {
        self.parameter_impl_is_auto_parameter()
    }

    fn parameter_ordinal(&self) -> Option<i32> {
        Some(self.stored_ordinal())
    }
}

impl Parameter for ReturnParameterImpl {
    fn get_ordinal(&self) -> i32 {
        self.parameter_impl_get_ordinal()
    }

    fn is_auto_parameter(&self) -> bool {
        self.parameter_impl_is_auto_parameter()
    }

    fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
        self.parameter_impl_get_auto_parameter_type()
    }

    fn is_forced_indirect(&self) -> bool {
        self.parameter_impl_is_forced_indirect()
    }

    fn get_formal_data_type(&self) -> Box<dyn DataType> {
        self.parameter_impl_get_formal_data_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::seam_stubs::VarnodeListStorage;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockDataType {
        length: i32,
        is_void: bool,
    }

    impl MockDataType {
        fn sized(length: i32) -> Self {
            MockDataType {
                length,
                is_void: false,
            }
        }

        fn void() -> Self {
            MockDataType {
                length: 0,
                is_void: true,
            }
        }
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            if self.is_void {
                "void".to_string()
            } else {
                format!("mock{}", self.length)
            }
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_void_type(&self) -> bool {
            self.is_void
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.length == dt.get_length() && self.is_void == dt.is_void_type()
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

    fn mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram)
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn new_uses_return_name_and_ordinal() {
        let ret = ReturnParameterImpl::new(Box::new(MockDataType::void()), mock_program()).unwrap();
        assert_eq!(Variable::get_name(&ret), Some(RETURN_NAME.to_string()));
        assert_eq!(Parameter::get_ordinal(&ret), RETURN_ORDINAL);
        assert_eq!(ret.parameter_ordinal(), Some(RETURN_ORDINAL));
        assert!(ret.is_parameter());
    }

    #[test]
    fn new_allows_void_data_type_matching_is_void_allowed_override() {
        // ReturnParameterImpl.isVoidAllowed() returns true (unlike ParameterImpl's inherited
        // `false`), so a void-typed return with no storage must be valid.
        let ret = ReturnParameterImpl::new(Box::new(MockDataType::void()), mock_program()).unwrap();
        assert!(ret.is_valid());
        assert!(ret.get_data_type().is_void_type());
    }

    #[test]
    fn new_storage_addr_builds_memory_return_value() {
        let addr = ram_space().address(0x4000);
        let ret = ReturnParameterImpl::new_storage_addr(
            Box::new(MockDataType::sized(4)),
            addr.clone(),
            mock_program(),
        )
        .unwrap();
        assert!(ret.is_memory_variable());
        assert_eq!(ret.get_min_address(), Some(addr));
        assert_eq!(ret.get_length(), 4);
    }

    #[test]
    fn get_first_use_offset_is_always_zero() {
        let ret = ReturnParameterImpl::new(Box::new(MockDataType::void()), mock_program()).unwrap();
        assert_eq!(ret.get_first_use_offset(), 0);
    }

    #[test]
    fn has_default_name_is_always_false_for_return_name() {
        // "<RETURN>" never matches ParameterImpl's "param_N" default-name pattern, unlike an
        // actual default-named ordinary parameter.
        let ret = ReturnParameterImpl::new(Box::new(MockDataType::void()), mock_program()).unwrap();
        assert!(!ret.has_default_name());
    }

    #[test]
    fn new_from_parameter_copies_data_type_and_storage() {
        use crate::program::model::listing::parameter_impl::ParameterImpl as ParameterImplTrait;

        struct SourceParam {
            data_type: MockDataType,
            storage: Box<dyn VariableStorage>,
            program: Arc<dyn Program>,
        }
        impl VariableImpl for SourceParam {
            fn stored_name(&self) -> Option<String> {
                Some("count".to_string())
            }
            fn set_stored_name(&mut self, _name: Option<String>) {}
            fn stored_data_type(&self) -> Box<dyn DataType> {
                Box::new(self.data_type)
            }
            fn set_stored_data_type(&mut self, _data_type: Box<dyn DataType>) {}
            fn stored_comment(&self) -> Option<String> {
                None
            }
            fn set_stored_comment(&mut self, _comment: Option<String>) {}
            fn stored_source_type(&self) -> SourceType {
                SourceType::UserDefined
            }
            fn set_stored_source_type(&mut self, _source_type: SourceType) {}
            fn stored_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
                Some(self.storage.with_varnodes(self.storage.get_varnodes()))
            }
            fn set_stored_variable_storage(&mut self, _storage: Option<Box<dyn VariableStorage>>) {}
        }
        impl ParameterImplTrait for SourceParam {
            fn stored_ordinal(&self) -> i32 {
                0
            }
        }
        impl Variable for SourceParam {
            fn get_data_type(&self) -> Box<dyn DataType> {
                self.parameter_impl_get_data_type()
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
                self.variable_impl_get_name()
            }
            fn get_length(&self) -> i32 {
                self.variable_impl_get_length()
            }
            fn is_valid(&self) -> bool {
                self.variable_impl_is_valid()
            }
            fn get_function(&self) -> Option<Box<dyn Function>> {
                None
            }
            fn get_program(&self) -> Arc<dyn Program> {
                self.program.clone()
            }
            fn get_source(&self) -> SourceType {
                self.variable_impl_get_source()
            }
            fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
                Ok(())
            }
            fn get_comment(&self) -> Option<String> {
                None
            }
            fn set_comment(&mut self, _comment: Option<String>) {}
            fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
                self.variable_impl_get_variable_storage()
            }
            fn get_first_storage_varnode(&self) -> Option<Varnode> {
                self.variable_impl_get_first_storage_varnode()
            }
            fn get_last_storage_varnode(&self) -> Option<Varnode> {
                self.variable_impl_get_last_storage_varnode()
            }
            fn is_stack_variable(&self) -> bool {
                self.variable_impl_is_stack_variable()
            }
            fn has_stack_storage(&self) -> bool {
                self.variable_impl_has_stack_storage()
            }
            fn is_register_variable(&self) -> bool {
                self.variable_impl_is_register_variable()
            }
            fn get_register(&self) -> Option<RegisterRef> {
                None
            }
            fn get_registers(&self) -> Option<Vec<RegisterRef>> {
                None
            }
            fn get_min_address(&self) -> Option<Address> {
                self.variable_impl_get_min_address()
            }
            fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
                self.variable_impl_get_stack_offset()
            }
            fn is_memory_variable(&self) -> bool {
                self.variable_impl_is_memory_variable()
            }
            fn is_unique_variable(&self) -> bool {
                false
            }
            fn is_compound_variable(&self) -> bool {
                false
            }
            fn has_assigned_storage(&self) -> bool {
                self.variable_impl_has_assigned_storage()
            }
            fn get_first_use_offset(&self) -> i32 {
                0
            }
            fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
                None
            }
            fn is_equivalent(&self, other: &dyn Variable) -> bool {
                self.variable_impl_is_equivalent(other)
            }
            fn compare_to(&self, other: &dyn Variable) -> Ordering {
                self.variable_impl_compare_to(other)
            }
            fn is_parameter(&self) -> bool {
                true
            }
            fn parameter_ordinal(&self) -> Option<i32> {
                Some(0)
            }
        }
        impl Parameter for SourceParam {
            fn get_ordinal(&self) -> i32 {
                0
            }
            fn is_auto_parameter(&self) -> bool {
                false
            }
            fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
                None
            }
            fn is_forced_indirect(&self) -> bool {
                false
            }
            fn get_formal_data_type(&self) -> Box<dyn DataType> {
                self.parameter_impl_get_formal_data_type()
            }
        }

        let addr = ram_space().address(0x5000);
        let source = SourceParam {
            data_type: MockDataType::sized(8),
            storage: Box::new(VarnodeListStorage(vec![Varnode::new(addr.clone(), 8)])),
            program: mock_program(),
        };
        let ret = ReturnParameterImpl::new_from_parameter(&source, mock_program()).unwrap();
        assert_eq!(ret.get_length(), 8);
        assert_eq!(ret.get_min_address(), Some(addr));
        assert_eq!(Variable::get_name(&ret), Some(RETURN_NAME.to_string()));
        assert_eq!(Parameter::get_ordinal(&ret), RETURN_ORDINAL);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let ret: Box<dyn Parameter> =
            Box::new(ReturnParameterImpl::new(Box::new(MockDataType::void()), mock_program()).unwrap());
        assert_eq!(ret.get_ordinal(), RETURN_ORDINAL);
    }
}
