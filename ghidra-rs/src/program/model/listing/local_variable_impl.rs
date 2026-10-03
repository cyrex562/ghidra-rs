//! Port of `ghidra.program.model.listing.LocalVariableImpl`.
//!
//! The Java class is a small, concrete `LocalVariableImpl extends VariableImpl implements
//! LocalVariable`, adding exactly one field (`firstUseOffset`) and two accessors
//! (`getFirstUseOffset`/`setFirstUseOffset`) on top of the already-ported
//! [`VariableImpl`](crate::program::model::listing::variable_impl::VariableImpl) trait. Since
//! that trait already carries the entire field-backed `Variable` algorithm behind its
//! `stored_*`/`variable_impl_*` convention, this port follows the same "composition via trait
//! delegation" shape already established by
//! [`MemoryParameter`](crate::app::cmd::function::add_memory_parameter_command) (a production,
//! non-test `VariableImpl` implementor) rather than inventing a `base: VariableImpl` field --
//! `VariableImpl` is a trait, not a struct, so there is nothing to hold "by value"; a concrete
//! type instead stores the plain fields the trait's `stored_*` accessors read/write and
//! implements `Variable`/`VariableImpl`/[`LocalVariable`] by delegating each method to its
//! `variable_impl_*` counterpart, exactly like `MemoryParameter` and the sibling
//! `MockVariableImpl`/`MockParameterImpl` test doubles do.
//!
//! `data_type` is stored as an `Arc<dyn DataType>` (not `Box`) and handed back through
//! [`share_data_type`], and `storage` is rebuilt via `with_varnodes(get_varnodes())` on every
//! read -- both mirroring `MemoryParameter`'s identical workaround for `dyn DataType`/
//! `dyn VariableStorage` having no `Clone` bound.
//!
//! ## Constructor collapsing
//!
//! Java declares nine public constructor overloads plus one private nine-argument delegate
//! (`LocalVariableImpl(String, int, DataType, VariableStorage, Address, Integer, Register,
//! boolean, Program, SourceType)`, mirroring `VariableImpl`'s own private constructor). Exactly
//! one of `storage`/`storageAddr`/`stackOffset`/`register` may be given (the rest `null`), so --
//! following [`VariableImpl::init_fields`]'s own collapsing precedent -- the overloads collapse
//! onto four `new_*` constructors here, one per storage kind:
//!
//! - [`new_stack`](LocalVariableImpl::new_stack) -- the two `(name, dataType, stackOffset,
//!   program[, sourceType])` overloads (`firstUseOffset` is always `0` for these).
//! - [`new_register`](LocalVariableImpl::new_register) -- the two `(name, firstUseOffset,
//!   dataType, register, program[, sourceType])` overloads.
//! - [`new_storage_addr`](LocalVariableImpl::new_storage_addr) -- the two `(name, firstUseOffset,
//!   dataType, storageAddr, program[, sourceType])` overloads.
//! - [`new_with_storage`](LocalVariableImpl::new_with_storage) -- the three `(name,
//!   firstUseOffset, dataType, storage[, force], program[, sourceType])` overloads (`force`
//!   defaults to `false` in Java when omitted; callers here just pass it explicitly).
//!
//! Every Java overload that omits `sourceType` passes a literal `null` down to the private
//! constructor. `VariableImpl.getSource()` maps that `null` back to `SourceType.USER_DEFINED` at
//! read time (`sourceType != null ? sourceType : SourceType.USER_DEFINED`), and
//! `LocalVariableImpl` never overrides `hasDefaultName()` (so it stays `false`, meaning the
//! private constructor's `hasDefaultName() ? DEFAULT : sourceType` assignment always keeps
//! whatever was passed in). Passing [`SourceType::UserDefined`] explicitly for those collapsed
//! overloads is therefore behaviorally identical to Java's `null`, just resolved eagerly instead
//! of at `getSource()` time (Rust's `SourceType` has no null variant to defer to).
//!
//! ## Faithful quirk: `setFirstUseOffset` does not re-validate stack placement
//!
//! The private constructor validates `hasStackStorage() && firstUseOffset != 0` and throws
//! `InvalidInputException` (lines 220-222 of the Java source). `setFirstUseOffset(int)` (lines
//! 230-234), however, performs **no such check** -- it unconditionally stores the new offset and
//! returns `true`. This means a stack-based `LocalVariableImpl` can be constructed with
//! `firstUseOffset == 0` and then have that invariant broken through `setFirstUseOffset`, with no
//! error reported. This port reproduces that asymmetry exactly (see
//! `set_first_use_offset_does_not_revalidate_stack_placement_quirk` below) rather than "fixing"
//! it to match the constructor's stricter check.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
use crate::program::model::listing::variable_impl::{init_fields, VariableImpl};
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::{Function, LocalVariable, Program, Variable};
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::SourceType;
use crate::program::seam_stubs::share_data_type;
use crate::util::exception::InvalidInputException;

/// Concrete, in-memory (non-database-backed) local variable.
///
/// Port of `ghidra.program.model.listing.LocalVariableImpl`. See the module docs for the
/// constructor-collapsing convention and the one faithfully-reproduced quirk.
pub struct LocalVariableImpl {
    name: Option<String>,
    data_type: Arc<dyn DataType>,
    comment: Option<String>,
    source_type: SourceType,
    storage: Option<Box<dyn VariableStorage>>,
    program: Arc<dyn Program>,
    first_use_offset: i32,
}

/// Manual `Debug` impl: `data_type`/`program`/`storage` are `dyn` trait objects
/// (`DataType`/`Program`/`VariableStorage`) that do not themselves require `Debug`, so
/// `#[derive(Debug)]` is not available here. Only the plain fields are shown.
impl std::fmt::Debug for LocalVariableImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalVariableImpl")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("source_type", &self.source_type)
            .field("first_use_offset", &self.first_use_offset)
            .finish_non_exhaustive()
    }
}

impl LocalVariableImpl {
    /// Backs every public constructor. Port of the private nine-argument
    /// `LocalVariableImpl(String, int, DataType, VariableStorage, Address, Integer, Register,
    /// boolean, Program, SourceType)`.
    #[allow(clippy::too_many_arguments)]
    fn with_fields(
        name: Option<String>,
        first_use_offset: i32,
        data_type: Box<dyn DataType>,
        storage: Option<Box<dyn VariableStorage>>,
        storage_addr: Option<Address>,
        stack_offset: Option<i32>,
        register: Option<RegisterRef>,
        force: bool,
        program: Arc<dyn Program>,
        source_type: SourceType,
    ) -> Result<Self, InvalidInputException> {
        let fields = init_fields(
            name,
            data_type,
            storage,
            storage_addr,
            stack_offset,
            register,
            force,
            program.as_ref(),
            source_type,
            false, // void_allowed: LocalVariableImpl never overrides isVoidAllowed()
            false, // has_default_name: LocalVariableImpl never overrides hasDefaultName()
        )?;
        let result = LocalVariableImpl {
            name: fields.name,
            data_type: Arc::from(fields.data_type),
            comment: None,
            source_type: fields.source_type,
            storage: Some(fields.variable_storage),
            program,
            first_use_offset,
        };
        // Port of the constructor-only check (lines 220-222 of the Java source): a stack-based
        // variable's firstUseOffset must be 0. Note `setFirstUseOffset` below deliberately does
        // NOT re-run this check; see the module docs.
        if result.variable_impl_has_stack_storage() && first_use_offset != 0 {
            return Err(InvalidInputException::with_message(
                "Stack-based variable must have firstUseOffset of 0",
            ));
        }
        Ok(result)
    }

    /// Construct a stack variable at the specified stack offset with a first-use offset of 0.
    ///
    /// Port of `LocalVariableImpl(String, DataType, int, Program)` /
    /// `LocalVariableImpl(String, DataType, int, Program, SourceType)` (collapsed; see the
    /// module docs).
    pub fn new_stack(
        name: Option<&str>,
        data_type: Box<dyn DataType>,
        stack_offset: i32,
        program: Arc<dyn Program>,
        source_type: SourceType,
    ) -> Result<Self, InvalidInputException> {
        Self::with_fields(
            name.map(str::to_string),
            0,
            data_type,
            None,
            None,
            Some(stack_offset),
            None,
            false,
            program,
            source_type,
        )
    }

    /// Construct a register variable with the specified register storage.
    ///
    /// Port of `LocalVariableImpl(String, int, DataType, Register, Program)` /
    /// `LocalVariableImpl(String, int, DataType, Register, Program, SourceType)` (collapsed; see
    /// the module docs).
    pub fn new_register(
        name: Option<&str>,
        first_use_offset: i32,
        data_type: Box<dyn DataType>,
        register: RegisterRef,
        program: Arc<dyn Program>,
        source_type: SourceType,
    ) -> Result<Self, InvalidInputException> {
        Self::with_fields(
            name.map(str::to_string),
            first_use_offset,
            data_type,
            None,
            None,
            None,
            Some(register),
            false,
            program,
            source_type,
        )
    }

    /// Construct a variable with a single storage element at the specified address.
    ///
    /// Port of `LocalVariableImpl(String, int, DataType, Address, Program)` /
    /// `LocalVariableImpl(String, int, DataType, Address, Program, SourceType)` (collapsed; see
    /// the module docs).
    pub fn new_storage_addr(
        name: Option<&str>,
        first_use_offset: i32,
        data_type: Box<dyn DataType>,
        storage_addr: Address,
        program: Arc<dyn Program>,
        source_type: SourceType,
    ) -> Result<Self, InvalidInputException> {
        Self::with_fields(
            name.map(str::to_string),
            first_use_offset,
            data_type,
            None,
            Some(storage_addr),
            None,
            None,
            false,
            program,
            source_type,
        )
    }

    /// Construct a variable with one or more associated storage elements.
    ///
    /// Port of `LocalVariableImpl(String, int, DataType, VariableStorage, Program)` /
    /// `LocalVariableImpl(String, int, DataType, VariableStorage, boolean, Program)` /
    /// `LocalVariableImpl(String, int, DataType, VariableStorage, boolean, Program, SourceType)`
    /// (collapsed; see the module docs).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_storage(
        name: Option<&str>,
        first_use_offset: i32,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        force: bool,
        program: Arc<dyn Program>,
        source_type: SourceType,
    ) -> Result<Self, InvalidInputException> {
        Self::with_fields(
            name.map(str::to_string),
            first_use_offset,
            data_type,
            Some(storage),
            None,
            None,
            None,
            force,
            program,
            source_type,
        )
    }
}

impl VariableImpl for LocalVariableImpl {
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

impl LocalVariable for LocalVariableImpl {
    /// Port of `LocalVariableImpl.setFirstUseOffset(int)`. See the module docs: this
    /// deliberately does not re-validate stack placement the way the constructor does.
    fn set_first_use_offset(&mut self, first_use_offset: i32) -> bool {
        self.first_use_offset = first_use_offset;
        true
    }
}

impl Variable for LocalVariableImpl {
    fn get_data_type(&self) -> Box<dyn DataType> {
        self.variable_impl_get_data_type()
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

    /// Port of `LocalVariableImpl.getFirstUseOffset()` (`final`).
    fn get_first_use_offset(&self) -> i32 {
        self.first_use_offset
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::Register;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockDataType {
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            format!("mock{}", self.length)
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.length == dt.get_length()
        }
    }

    struct MockProgram {
        address_factory: Arc<dyn AddressFactory>,
    }

    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.address_factory.clone())
        }
    }

    /// [`DefaultAddressFactory`] deliberately panics if constructed with a `Stack`-typed space
    /// (`validate_space` in `factory.rs`, matching the real address factory never registering the
    /// stack space as an ordinary memory space). This minimal hand-rolled [`AddressFactory`]
    /// mirrors the identical `MockAddressFactory` in
    /// `variable_storage.rs`'s own test module: only [`AddressFactory::get_stack_space`] (the one
    /// method `compute_storage`'s stack-offset branch actually calls) is real; every other method
    /// is either a trivial forward or left `unimplemented!()` since no test below exercises it.
    struct MockAddressFactory {
        ram_space: Arc<AddressSpace>,
        stack_space: Arc<AddressSpace>,
    }

    impl AddressFactory for MockAddressFactory {
        fn get_address(&self, _addr_string: &str) -> Option<Address> {
            None
        }
        fn get_all_addresses_case(&self, _addr_string: &str, _case_sensitive: bool) -> Vec<Address> {
            Vec::new()
        }
        fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
            Some(self.ram_space.clone())
        }
        fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            vec![self.ram_space.clone(), self.stack_space.clone()]
        }
        fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>> {
            self.get_address_spaces().into_iter().find(|s| s.name() == name)
        }
        fn get_address_space_by_id(&self, id: i32) -> Option<Arc<AddressSpace>> {
            self.get_address_spaces().into_iter().find(|s| s.space_id() == id)
        }
        fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.get_address_spaces()
        }
        fn get_num_address_spaces(&self) -> usize {
            2
        }
        fn is_valid_address(&self, _address: &Address) -> bool {
            true
        }
        fn get_index(&self, _address: &Address) -> i64 {
            0
        }
        fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
            space.clone()
        }
        fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.get_address_spaces()
        }
        fn address(&self, _space_id: i32, _offset: i64) -> Option<Address> {
            None
        }
        fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
            Some(self.stack_space.clone())
        }
        fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_address(&self, _offset: i64) -> Option<Address> {
            None
        }
        fn get_address_set_range(&self, min: &Address, max: &Address) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::from_start_end(min.clone(), max.clone())
        }
        fn get_address_set(&self) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn old_get_address_from_long(&self, _value: i64) -> Option<Address> {
            None
        }
        fn has_multiple_memory_spaces(&self) -> bool {
            false
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn stack_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
    }

    fn mock_program_with_stack() -> Arc<dyn Program> {
        let factory = MockAddressFactory {
            ram_space: ram_space(),
            stack_space: stack_space(),
        };
        Arc::new(MockProgram {
            address_factory: Arc::new(factory),
        })
    }

    fn mock_program_no_stack() -> Arc<dyn Program> {
        let factory = DefaultAddressFactory::new(vec![ram_space()]);
        Arc::new(MockProgram {
            address_factory: Arc::new(factory),
        })
    }

    #[test]
    fn new_stack_builds_valid_stack_variable_with_zero_first_use_offset() {
        let program = mock_program_with_stack();
        let var = LocalVariableImpl::new_stack(
            Some("local_1"),
            Box::new(MockDataType { length: 4 }),
            -8,
            program,
            SourceType::UserDefined,
        )
        .unwrap();
        assert_eq!(var.get_name(), Some("local_1".to_string()));
        assert!(var.is_stack_variable());
        assert_eq!(var.get_first_use_offset(), 0);
        assert_eq!(var.get_stack_offset().unwrap(), -8);
        assert!(var.is_valid());
    }

    #[test]
    fn new_stack_rejects_nonzero_first_use_offset_via_direct_construction() {
        // LocalVariableImpl's private ctor takes an explicit firstUseOffset even for stack
        // variables; `new_stack` always passes 0 (matching the two Java overloads it collapses),
        // but `with_fields` (the private ctor port) itself must still reject a nonzero one.
        let program = mock_program_with_stack();
        let result = LocalVariableImpl::with_fields(
            Some("local_1".to_string()),
            4,
            Box::new(MockDataType { length: 4 }),
            None,
            None,
            Some(-8),
            None,
            false,
            program,
            SourceType::UserDefined,
        );
        // `LocalVariableImpl` has no `Debug` impl (it holds `dyn` trait-object fields), so
        // `Result::unwrap_err` (which requires `T: Debug`) is not usable here; match instead.
        match result {
            Ok(_) => panic!("expected an error for stack variable with nonzero firstUseOffset"),
            Err(e) => assert!(e.to_string().contains("firstUseOffset")),
        }
    }

    #[test]
    fn set_first_use_offset_does_not_revalidate_stack_placement_quirk() {
        // Faithful reproduction of LocalVariableImpl.java lines 230-234: setFirstUseOffset has no
        // hasStackStorage()/firstUseOffset==0 guard, unlike the constructor (lines 220-222).
        let program = mock_program_with_stack();
        let mut var = LocalVariableImpl::new_stack(
            Some("local_1"),
            Box::new(MockDataType { length: 4 }),
            -8,
            program,
            SourceType::UserDefined,
        )
        .unwrap();
        assert_eq!(var.get_first_use_offset(), 0);
        // This would be rejected if constructed directly with a nonzero offset, but the setter
        // performs no such check.
        assert!(var.set_first_use_offset(16));
        assert_eq!(var.get_first_use_offset(), 16);
        assert!(var.is_stack_variable(), "storage is unaffected by the setter");
    }

    #[test]
    fn new_register_builds_register_variable() {
        let reg_space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let reg = Register::new("r0", "General register 0", reg_space.address(0), 4, false, 0);
        let program = mock_program_no_stack();
        let var = LocalVariableImpl::new_register(
            Some("local_reg"),
            0,
            Box::new(MockDataType { length: 4 }),
            reg,
            program,
            SourceType::UserDefined,
        )
        .unwrap();
        assert!(var.is_register_variable());
        assert_eq!(var.get_length(), 4);
    }

    #[test]
    fn new_storage_addr_builds_memory_variable() {
        let program = mock_program_no_stack();
        let addr = ram_space().address(0x1000);
        let var = LocalVariableImpl::new_storage_addr(
            Some("local_mem"),
            0,
            Box::new(MockDataType { length: 4 }),
            addr.clone(),
            program,
            SourceType::UserDefined,
        )
        .unwrap();
        assert!(var.is_memory_variable());
        assert_eq!(var.get_min_address(), Some(addr));
    }

    #[test]
    fn new_with_storage_rejects_nonzero_first_use_offset_for_stack_storage() {
        use crate::program::seam_stubs::VarnodeListStorage;

        let program = mock_program_with_stack();
        let stack_addr = stack_space().address(-4);
        let storage = Box::new(VarnodeListStorage(vec![Varnode::new(stack_addr, 4)]));
        let result = LocalVariableImpl::new_with_storage(
            Some("local_1"),
            4, // nonzero first-use offset with stack storage should be rejected
            Box::new(MockDataType { length: 4 }),
            storage,
            false,
            program,
            SourceType::UserDefined,
        );
        assert!(result.is_err());
    }

    #[test]
    fn get_source_defaults_to_user_defined_matching_javas_null_source_type_fallback() {
        let program = mock_program_no_stack();
        let var = LocalVariableImpl::new_storage_addr(
            Some("local_1"),
            0,
            Box::new(MockDataType { length: 4 }),
            ram_space().address(0x2000),
            program,
            SourceType::UserDefined,
        )
        .unwrap();
        assert_eq!(var.get_source(), SourceType::UserDefined);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let program = mock_program_no_stack();
        let var: Box<dyn LocalVariable> = Box::new(
            LocalVariableImpl::new_storage_addr(
                Some("local_1"),
                0,
                Box::new(MockDataType { length: 4 }),
                ram_space().address(0x3000),
                program,
                SourceType::UserDefined,
            )
            .unwrap(),
        );
        assert_eq!(var.get_name(), Some("local_1".to_string()));
    }
}
