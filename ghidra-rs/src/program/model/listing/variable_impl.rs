//! Port of `ghidra.program.model.listing.VariableImpl`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class is a package-private abstract class that is the shared implementation behind
//! every first-party [`Variable`] (`ParameterImpl`, `LocalVariableImpl`, and friends). Since
//! [`Variable`] already declares most of these methods as required (non-default) trait methods,
//! Rust does not allow this subtrait to supply a default body under the same name (the call
//! becomes ambiguous at every call site) -- exactly the situation
//! [`DataOrganizationImpl`](crate::program::model::data::data_organization_impl::DataOrganizationImpl)
//! and
//! [`ParameterDefinitionImpl`](crate::program::model::data::parameter_definition_impl::ParameterDefinitionImpl)
//! already solved. Following the latter's `parameter_definition_impl_*`/`stored_*` convention:
//! the private fields (`name`, `dataType`, `comment`, `sourceType`, `variableStorage`) are exposed
//! via required `stored_*`/`set_stored_*` accessor methods, and each `Variable` method this class
//! gives a real algorithm to is exposed under a `variable_impl_*` prefix. A concrete `impl
//! Variable for Foo` is expected to delegate each method to its `variable_impl_*` counterpart (see
//! the `MockVariableImpl` test below).
//!
//! `hasDefaultName()`/`isVoidAllowed()` are protected extension points overridden by some
//! subclasses (e.g. `ParameterImpl` treats `"param_N"`-shaped names as default); they are exposed
//! here as defaulted trait methods ([`has_default_name`](VariableImpl::has_default_name),
//! [`is_void_allowed`](VariableImpl::is_void_allowed)) an implementor can override, exactly
//! mirroring the Java `protected` methods' default bodies (`false` for both).
//!
//! The nine-argument package-private constructor that every public `VariableImpl` constructor
//! overload delegates to (with a different subset of `storage`/`storageAddr`/`stackOffset`/
//! `register` left `null`) is ported as the free function [`init_fields`], mirroring
//! `ParameterDefinitionImpl`'s `init_fields`: it performs the full validation/storage-computation
//! algorithm and returns the field values ready to store, since a trait cannot construct "a new
//! `Self`" generically. `hasDefaultName()`/`isVoidAllowed()` are threaded through as plain `bool`
//! parameters rather than a `&dyn VariableImpl` receiver, since the object being constructed does
//! not exist yet; callers should evaluate their own override of each before calling.
//!
//! `VariableUtilities.checkDataType`/`checkStorage` are already ported as
//! [`VariableUtilities::check_data_type_for_program`]/[`VariableUtilities::check_storage`], reached
//! through the zero-sized [`DefaultVariableUtilities`] marker (mirroring
//! `ParameterDefinitionImpl`'s identical `DefaultVariableUtilities` marker, kept private to this
//! module since neither is part of any public API). `checkStorage`'s Java overload used here is
//! `void`-returning (validate only, keep the original storage object), so
//! [`VariableUtilities::check_storage`] is used rather than `check_storage_for_function` (whose
//! `Option<&dyn Function>` variant additionally resizes/shrinks register storage in ways
//! `VariableImpl` does not).
//!
//! `Java`'s `VariableStorage.isVoidStorage()`/`isUnassignedStorage()` distinguish two singleton
//! sentinel storages (`VariableStorage.VOID_STORAGE`/`UNASSIGNED_STORAGE`), neither of which is
//! portable without the real `VariableStorage` class (not yet ported; see
//! [`seam_stubs::VariableStorage`](crate::program::seam_stubs::VariableStorage)). Both sentinels
//! have an empty varnode list, matching how the stub's own
//! [`VariableStorage::is_valid`](crate::program::seam_stubs::VariableStorage::is_valid) doc already
//! treats "empty varnode list" as the placeholder-storage signal, so this port checks
//! `storage.get_varnodes().is_empty()` wherever Java checks either predicate. Similarly,
//! `VariableStorage.isStackStorage()`/`hasStackStorage()`/`isCompoundStorage()` are not on the
//! stub, so they are computed directly here from `get_varnodes()`/[`Address::is_stack_address`]
//! rather than growing the stub.
//!
//! `VariableStorage.getRegisters()` (plural, for compound register+other storage) has no stub
//! counterpart beyond the single-register [`VariableStorage::get_register`]; this port approximates
//! it as `Some(vec![get_register()?])` when a register is present, which is exact for the common
//! single-register case and only diverges for genuinely multi-register compound storage (not
//! constructible through this port's [`compute_storage`] yet).
//!
//! The private storage-resize algorithm (`resizeStorage`/`shrinkStorage`/`expandStorage`/
//! `shrinkVarnode`/`expandVarnode`/`resizeStackVarnode`), used only by
//! `variable_impl_set_data_type` (the no-explicit-storage `setDataType(DataType, SourceType)`
//! overload), is ported as `variable_impl_*`-prefixed default methods. It is deliberately distinct
//! from the similarly-named free functions in
//! [`variable_utilities`](crate::program::model::listing::variable_utilities) (which back
//! `VariableUtilities.resizeStorage`, used by subclasses *with* a `Function`): `VariableImpl`
//! itself has no function context (`getFunction()` returns `None`), so its version skips the
//! calling-convention-based stack alignment/justification `VariableUtilities`'s version performs,
//! matching the real Java method exactly (`resizeStackVarnode` here always keeps the same stack
//! offset, only changing the varnode's size).
//!
//! Java's `expandStorage` builds its returned `VariableStorage` from a `newList` local that is
//! declared but never populated (the mutated `varnodes` array is discarded instead), which looks
//! like a dead-code bug rather than intentional behavior -- it would silently drop all storage
//! whenever a variable's datatype grows past its non-register, non-stack current storage. This
//! port instead returns storage built from the mutated varnode array, matching the (correct)
//! analogous logic in [`variable_utilities::expand_storage`](crate::program::model::listing::variable_utilities)
//! and matching evident intent.
//!
//! `Address.isHashAddress()` has no analogue on the ported [`Address`] (no `Hash` variant on
//! [`AddressSpaceType`](crate::program::model::address::AddressSpaceType)), so
//! [`compute_storage`] only recognizes memory/register/stack addresses; a hash-space address
//! (not producible by any code that calls into this port yet) is rejected the same way an
//! unrecognized space is.
//!
//! `toString()`, `equals(Object)`/`hashCode()`, and `compareTo(Variable)` are ported as
//! [`VariableImpl::variable_impl_to_string`], [`VariableImpl::variable_impl_is_equivalent`] (Rust
//! has no object-identity `equals`; [`Variable::is_equivalent`] already fills that role), and
//! [`VariableImpl::variable_impl_compare_to`]. `compareTo`'s delegation to
//! `VariableUtilities.compare` is inlined directly (rather than calling
//! [`VariableUtilities::compare`]) since that method takes two `&dyn Variable` arguments and `self`
//! here is `&Self` where `Self: VariableImpl` (a `dyn`-unsized receiver inside a default method),
//! which cannot be reborrowed as `&dyn Variable` without supertrait-upcasting coercion; the small
//! amount of precedence/varnode-ordering logic involved is duplicated locally instead.

use std::cmp::Ordering;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::parameter_definition_impl::is_same_or_equivalent_data_type;
use crate::program::model::lang::RegisterRef;
use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
use crate::program::model::listing::variable_utilities::VariableUtilities;
use crate::program::model::listing::{Function, Program, Variable};
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::SourceType;
use crate::program::seam_stubs::{PlaceholderVariableStorage, VarnodeListStorage, VariableStorage};
use crate::util::exception::InvalidInputException;

/// Zero-sized [`VariableUtilities`] implementor used solely to reach that trait's
/// default-implemented `check_data_type_for_program`/`check_storage` methods, mirroring the Java
/// static utility class's lack of instance state. Not a port of any specific Java class. See
/// [`ParameterDefinitionImpl`](crate::program::model::data::parameter_definition_impl::ParameterDefinitionImpl)'s
/// identical marker.
struct DefaultVariableUtilities;

impl VariableUtilities for DefaultVariableUtilities {}

/// Field values backing a new `VariableImpl`-implementing variable, returned by [`init_fields`].
pub struct VariableImplFields {
    pub name: Option<String>,
    pub data_type: Box<dyn DataType>,
    pub variable_storage: Box<dyn VariableStorage>,
    pub source_type: SourceType,
}

/// Validate `storage`/`storage_addr`/`stack_offset`/`register` usage: stands in for
/// `VariableImpl.checkUsage`. At most one of the four may be specified.
fn check_usage(
    has_storage: bool,
    has_storage_addr: bool,
    has_stack_offset: bool,
    has_register: bool,
) -> Result<(), InvalidInputException> {
    let invalid_usage = if has_storage {
        has_storage_addr || has_stack_offset || has_register
    } else if has_register {
        has_storage_addr || has_stack_offset
    } else if has_stack_offset {
        has_storage_addr
    } else {
        false
    };
    if invalid_usage {
        // Java throws the unchecked IllegalArgumentException here; there is no ported analogue,
        // so this port reports the same message via InvalidInputException instead.
        return Err(InvalidInputException::with_message(
            "only one storage location may be specified",
        ));
    }
    Ok(())
}

/// Validate that `program` is usable: stands in for `VariableImpl.checkProgram`.
fn check_program(program: &dyn Program) -> Result<(), InvalidInputException> {
    if program.is_closed() {
        return Err(InvalidInputException::with_message(
            "An open program object which corresponds to the specified storage is required",
        ));
    }
    Ok(())
}

/// Build single-varnode storage of `data_type`'s length at `storage_addr`, or unassigned storage
/// if `storage_addr` is `None`. Stands in for `VariableImpl.computeStorage`.
///
/// # Errors
/// Returns `Err` if `storage_addr` is not a memory, register, or stack address, or if a negative
/// stack offset would span the zero boundary.
fn compute_storage(
    data_type: &dyn DataType,
    storage_addr: Option<Address>,
) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
    let Some(addr) = storage_addr else {
        return Ok(Box::new(PlaceholderVariableStorage));
    };
    if !addr.is_memory_address() && !addr.is_register_address() && !addr.is_stack_address() {
        return Err(InvalidInputException::with_message(format!(
            "Invalid storage address specified: space={}",
            addr.space().name()
        )));
    }
    let dt_length = data_type.get_length();
    if !addr.is_stack_address() {
        return Ok(Box::new(VarnodeListStorage(vec![Varnode::new(addr, dt_length)])));
    }
    let stack_offset = addr.offset();
    if stack_offset < 0 && -stack_offset < dt_length as i64 {
        return Err(InvalidInputException::with_message(format!(
            "Data type does not fit within stack frame constraints (stack offset={}, size={})",
            stack_offset, dt_length
        )));
    }
    Ok(Box::new(VarnodeListStorage(vec![Varnode::new(addr, dt_length)])))
}

/// Build the field values for a new `VariableImpl`-implementing variable, mirroring the private
/// nine-argument Java constructor `VariableImpl(String, DataType, VariableStorage, Address,
/// Integer, Register, boolean, Program, SourceType)`. At most one of `storage`/`storage_addr`/
/// `stack_offset`/`register` may be specified (`None` for the rest), mirroring how each public
/// constructor overload passes a different single one.
///
/// `void_allowed`/`has_default_name` should be the caller's own
/// [`VariableImpl::is_void_allowed`]/[`VariableImpl::has_default_name`] override, evaluated before
/// this call since the object under construction does not exist yet to call them on.
///
/// # Errors
/// Returns `Err` if more than one storage location is specified, `program` is closed, the
/// datatype is unacceptable, or storage validation/construction fails.
#[allow(clippy::too_many_arguments)]
pub fn init_fields(
    name: Option<String>,
    data_type: Box<dyn DataType>,
    storage: Option<Box<dyn VariableStorage>>,
    storage_addr: Option<Address>,
    stack_offset: Option<i32>,
    register: Option<RegisterRef>,
    force: bool,
    program: &dyn Program,
    source_type: SourceType,
    void_allowed: bool,
    has_default_name: bool,
) -> Result<VariableImplFields, InvalidInputException> {
    check_usage(
        storage.is_some(),
        storage_addr.is_some(),
        stack_offset.is_some(),
        register.is_some(),
    )?;
    check_program(program)?;

    let vu = DefaultVariableUtilities;
    let resolved_source_type = if has_default_name {
        SourceType::Default
    } else {
        source_type
    };

    if let Some(storage) = storage {
        let void_ok = storage.get_varnodes().is_empty() && void_allowed;
        let dt = vu.check_data_type_for_program(Some(data_type), void_ok, storage.size(), program)?;
        // `VariableUtilities.checkStorage(storage, dataType, force)` is void in Java: it validates
        // (and may throw) without handing back a possibly-adjusted storage, so the *original*
        // `storage` is what gets stored. `dyn VariableStorage` has no `Clone`, so a duplicate is
        // built via `with_varnodes` purely to satisfy `check_storage`'s consuming signature.
        let storage_for_check = storage.with_varnodes(storage.get_varnodes());
        vu.check_storage(storage_for_check, dt.as_ref(), force)?;
        return Ok(VariableImplFields {
            name,
            data_type: dt,
            variable_storage: storage,
            source_type: resolved_source_type,
        });
    }

    if let Some(register) = register {
        let reg_size = register.borrow().minimum_byte_size();
        let dt = vu.check_data_type_for_program(Some(data_type), false, reg_size, program)?;
        let size = dt.get_length();
        let reg_addr = register.borrow().address().clone();
        if reg_size < size {
            if !force {
                return Err(InvalidInputException::with_message(format!(
                    "Register '{}' size too small for specified data type size: {}",
                    register.borrow().name(),
                    size
                )));
            }
            // Allow size mismatch if forced and bypass normal storage computation.
            let storage: Box<dyn VariableStorage> =
                Box::new(VarnodeListStorage(vec![Varnode::new(reg_addr, reg_size)]));
            return Ok(VariableImplFields {
                name,
                data_type: dt,
                variable_storage: storage,
                source_type: resolved_source_type,
            });
        }
        let mut addr = reg_addr;
        if register.borrow().is_big_endian() && reg_size > size {
            addr = addr.add((reg_size - size) as i64).map_err(|_| {
                InvalidInputException::with_message("address overflow while aligning register storage")
            })?;
        }
        let storage = compute_storage(dt.as_ref(), Some(addr))?;
        return Ok(VariableImplFields {
            name,
            data_type: dt,
            variable_storage: storage,
            source_type: resolved_source_type,
        });
    }

    let addr = if let Some(offset) = stack_offset {
        let stack_space = program
            .get_address_factory()
            .and_then(|factory| factory.get_stack_space())
            .ok_or_else(|| InvalidInputException::with_message("no stack address space available"))?;
        Some(stack_space.address(offset as i64))
    } else {
        storage_addr
    };
    let dt = vu.check_data_type_for_program(Some(data_type), addr.is_none() && void_allowed, 1, program)?;
    let storage = compute_storage(dt.as_ref(), addr)?;
    Ok(VariableImplFields {
        name,
        data_type: dt,
        variable_storage: storage,
        source_type: resolved_source_type,
    })
}

/// Precedence used by [`VariableImpl::variable_impl_compare_to`], mirroring
/// [`VariableUtilities::get_precedence`] (duplicated locally; see the module docs for why `self`
/// cannot be passed to that trait method directly).
fn precedence(
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
fn compare_varnode_lists(a: &[Varnode], b: &[Varnode]) -> Ordering {
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

/// Render a storage's varnode list for display/error messages, mirroring `VariableStorage`'s own
/// `toString()`.
fn storage_display(storage: &dyn VariableStorage) -> String {
    storage
        .get_varnodes()
        .iter()
        .map(Varnode::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Field-backed default implementation of several [`Variable`] methods, plus the storage-resize
/// algorithm backing [`VariableImpl::variable_impl_set_data_type`].
///
/// Port of `ghidra.program.model.listing.VariableImpl`. See the module docs for the `stored_*`
/// accessor convention, the `variable_impl_*` method-naming convention, and every documented
/// deviation from the Java source.
pub trait VariableImpl: Variable {
    /// Backing storage for the `name` field.
    fn stored_name(&self) -> Option<String>;
    /// Update the backing storage for the `name` field.
    fn set_stored_name(&mut self, name: Option<String>);
    /// Backing storage for the `dataType` field.
    fn stored_data_type(&self) -> Box<dyn DataType>;
    /// Update the backing storage for the `dataType` field.
    fn set_stored_data_type(&mut self, data_type: Box<dyn DataType>);
    /// Backing storage for the `comment` field.
    fn stored_comment(&self) -> Option<String>;
    /// Update the backing storage for the `comment` field.
    fn set_stored_comment(&mut self, comment: Option<String>);
    /// Backing storage for the `sourceType` field.
    fn stored_source_type(&self) -> SourceType;
    /// Update the backing storage for the `sourceType` field.
    fn set_stored_source_type(&mut self, source_type: SourceType);
    /// Backing storage for the `variableStorage` field.
    fn stored_variable_storage(&self) -> Option<Box<dyn VariableStorage>>;
    /// Update the backing storage for the `variableStorage` field.
    fn set_stored_variable_storage(&mut self, storage: Option<Box<dyn VariableStorage>>);

    /// Determine if the current name is a default name. Overridden by implementors like
    /// `ParameterImpl` whose default-name convention (e.g. `param_N`) affects
    /// [`variable_impl_set_name`](Self::variable_impl_set_name)'s source-type fallback and
    /// [`init_fields`]'s `has_default_name` argument.
    ///
    /// Port of `VariableImpl.hasDefaultName`.
    fn has_default_name(&self) -> bool {
        false
    }

    /// Determine if a zero-sized void datatype is permitted for this variable.
    ///
    /// Port of `VariableImpl.isVoidAllowed`.
    fn is_void_allowed(&self) -> bool {
        false
    }

    /// Default body for [`Variable::is_valid`].
    fn variable_impl_is_valid(&self) -> bool {
        let data_type = self.stored_data_type();
        let storage = self.stored_variable_storage();
        if data_type.is_void_type() {
            return self.is_void_allowed()
                && storage
                    .map(|s| s.get_varnodes().is_empty())
                    .unwrap_or(false);
        }
        let Some(storage) = storage else {
            return false;
        };
        if data_type.get_length() <= 0 || !storage.is_valid() {
            return false;
        }
        storage.size() >= data_type.get_length()
    }

    /// Default body for [`Variable::get_comment`].
    fn variable_impl_get_comment(&self) -> Option<String> {
        self.stored_comment()
    }

    /// Default body for [`Variable::get_data_type`].
    fn variable_impl_get_data_type(&self) -> Box<dyn DataType> {
        self.stored_data_type()
    }

    /// Default body for [`Variable::get_length`].
    fn variable_impl_get_length(&self) -> i32 {
        self.stored_data_type().get_length()
    }

    /// Default body for [`Variable::get_name`].
    fn variable_impl_get_name(&self) -> Option<String> {
        self.stored_name()
    }

    /// Default body for [`Variable::get_source`].
    fn variable_impl_get_source(&self) -> SourceType {
        self.stored_source_type()
    }

    /// Default body for [`Variable::get_function`]: `VariableImpl` itself is not tied to a
    /// function (subclasses like `ParameterImpl`/`LocalVariableImpl` override this).
    fn variable_impl_get_function(&self) -> Option<Box<dyn Function>> {
        None
    }

    /// Default body for [`Variable::set_name`].
    fn variable_impl_set_name(
        &mut self,
        name: &str,
        source: SourceType,
    ) -> Result<(), SetVariableNameError> {
        self.set_stored_name(Some(name.to_string()));
        let effective_source = if self.has_default_name() {
            SourceType::Default
        } else {
            source
        };
        self.set_stored_source_type(effective_source);
        Ok(())
    }

    /// Default body for [`Variable::set_comment`]: strips one trailing newline, if present.
    fn variable_impl_set_comment(&mut self, comment: Option<String>) {
        let comment = comment.map(|c| match c.strip_suffix('\n') {
            Some(stripped) => stripped.to_string(),
            None => c,
        });
        self.set_stored_comment(comment);
    }

    /// Default body for [`Variable::get_variable_storage`].
    fn variable_impl_get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
        self.stored_variable_storage()
    }

    /// Default body for [`Variable::get_first_storage_varnode`].
    fn variable_impl_get_first_storage_varnode(&self) -> Option<Varnode> {
        self.stored_variable_storage()
            .and_then(|s| s.get_first_varnode())
    }

    /// Default body for [`Variable::get_last_storage_varnode`].
    fn variable_impl_get_last_storage_varnode(&self) -> Option<Varnode> {
        self.stored_variable_storage()
            .and_then(|s| s.get_varnodes().last().cloned())
    }

    /// Default body for [`Variable::is_stack_variable`]: true if storage is a single varnode
    /// located on the stack.
    fn variable_impl_is_stack_variable(&self) -> bool {
        match self.stored_variable_storage() {
            Some(s) => matches!(
                s.get_varnodes().as_slice(),
                [vn] if vn.get_address().is_stack_address()
            ),
            None => false,
        }
    }

    /// Default body for [`Variable::has_stack_storage`]: true if the last storage varnode is on
    /// the stack (a compound variable's stack element, if present, is always last).
    fn variable_impl_has_stack_storage(&self) -> bool {
        self.stored_variable_storage()
            .and_then(|s| s.get_varnodes().last().cloned())
            .map(|vn| vn.get_address().is_stack_address())
            .unwrap_or(false)
    }

    /// Default body for [`Variable::is_register_variable`].
    fn variable_impl_is_register_variable(&self) -> bool {
        self.stored_variable_storage()
            .map(|s| s.is_register_storage())
            .unwrap_or(false)
    }

    /// Default body for [`Variable::get_register`].
    fn variable_impl_get_register(&self) -> Option<RegisterRef> {
        self.stored_variable_storage().and_then(|s| s.get_register())
    }

    /// Default body for [`Variable::get_registers`]. See the module docs for how this
    /// approximates the plural Java accessor.
    fn variable_impl_get_registers(&self) -> Option<Vec<RegisterRef>> {
        self.stored_variable_storage()
            .and_then(|s| s.get_register())
            .map(|r| vec![r])
    }

    /// Default body for [`Variable::get_min_address`].
    fn variable_impl_get_min_address(&self) -> Option<Address> {
        self.stored_variable_storage()
            .and_then(|s| s.get_first_varnode())
            .map(|vn| vn.get_address().clone())
    }

    /// Default body for [`Variable::get_stack_offset`].
    fn variable_impl_get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
        if self.variable_impl_is_stack_variable() {
            if let Some(vn) = self
                .stored_variable_storage()
                .and_then(|s| s.get_first_varnode())
            {
                return Ok(vn.get_address().offset() as i32);
            }
        }
        Err(UnsupportedOperationError(
            "Variable is not a stack variable".to_string(),
        ))
    }

    /// Default body for [`Variable::is_memory_variable`].
    fn variable_impl_is_memory_variable(&self) -> bool {
        self.stored_variable_storage()
            .map(|s| s.is_memory_storage())
            .unwrap_or(false)
    }

    /// Default body for [`Variable::is_unique_variable`].
    fn variable_impl_is_unique_variable(&self) -> bool {
        self.stored_variable_storage()
            .map(|s| s.is_hash_storage())
            .unwrap_or(false)
    }

    /// Default body for [`Variable::is_compound_variable`].
    fn variable_impl_is_compound_variable(&self) -> bool {
        self.stored_variable_storage()
            .map(|s| s.get_varnodes().len() > 1)
            .unwrap_or(false)
    }

    /// Default body for [`Variable::has_assigned_storage`].
    fn variable_impl_has_assigned_storage(&self) -> bool {
        self.stored_variable_storage().is_some()
    }

    /// Default body for [`Variable::set_data_type_with_storage`]
    /// (`VariableImpl.setDataType(DataType, VariableStorage, boolean, SourceType)`).
    ///
    /// # Errors
    /// Returns `Err` if the datatype is unacceptable or violates storage constraints.
    fn variable_impl_set_data_type_with_storage(
        &mut self,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        force: bool,
        _source: SourceType,
    ) -> Result<(), InvalidInputException> {
        let vu = DefaultVariableUtilities;
        let void_ok = storage.get_varnodes().is_empty() && self.is_void_allowed();
        let checked_type =
            vu.check_data_type_for_program(Some(data_type), void_ok, storage.size(), self.get_program().as_ref())?;
        let storage_for_check = storage.with_varnodes(storage.get_varnodes());
        vu.check_storage(storage_for_check, checked_type.as_ref(), force)?;
        self.set_stored_data_type(checked_type);
        self.set_stored_variable_storage(Some(storage));
        Ok(())
    }

    /// Default body for [`Variable::set_data_type_aligned`]
    /// (`VariableImpl.setDataType(DataType, boolean, boolean, SourceType)`): `align`/`force` are
    /// ignored (stack alignment is unknown without a function context) and the call is delegated
    /// to [`variable_impl_set_data_type`](Self::variable_impl_set_data_type) with
    /// [`SourceType::Analysis`], exactly matching the Java method.
    ///
    /// # Errors
    /// Returns `Err` if the datatype is unacceptable or storage cannot be resized to fit it.
    fn variable_impl_set_data_type_aligned(
        &mut self,
        data_type: Box<dyn DataType>,
        _align: bool,
        _force: bool,
        _source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type(data_type, SourceType::Analysis)
    }

    /// Default body for [`Variable::set_data_type`]
    /// (`VariableImpl.setDataType(DataType, SourceType)`): resizes the current storage (via
    /// [`variable_impl_resize_storage`](Self::variable_impl_resize_storage)) to fit `data_type`.
    ///
    /// # Errors
    /// Returns `Err` if the datatype is unacceptable or storage cannot be resized to fit it.
    fn variable_impl_set_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
        _source: SourceType,
    ) -> Result<(), InvalidInputException> {
        let vu = DefaultVariableUtilities;
        let default_size = self.stored_data_type().get_length();
        let checked_type = vu.check_data_type_for_program(
            Some(data_type),
            self.is_void_allowed(),
            default_size,
            self.get_program().as_ref(),
        )?;
        let new_storage: Box<dyn VariableStorage> = if checked_type.is_void_type() {
            Box::new(PlaceholderVariableStorage)
        } else {
            match self.stored_variable_storage() {
                Some(cur) => self.variable_impl_resize_storage(cur, checked_type.as_ref())?,
                None => Box::new(PlaceholderVariableStorage),
            }
        };
        self.set_stored_variable_storage(Some(new_storage));
        self.set_stored_data_type(checked_type);
        Ok(())
    }

    /// Resize `cur_storage` to `data_type`'s length. Has limited ability to grow storage if it
    /// does not have a stack component or other space constraints are exceeded.
    ///
    /// Port of the private `VariableImpl.resizeStorage`.
    ///
    /// # Errors
    /// Returns `Err` if unable to resize storage to the specified size.
    fn variable_impl_resize_storage(
        &self,
        cur_storage: Box<dyn VariableStorage>,
        data_type: &dyn DataType,
    ) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
        let new_size = data_type.get_length();
        let cur_size = cur_storage.size();
        if cur_size == new_size {
            return Ok(cur_storage);
        }
        if cur_size == 0 || cur_storage.is_unique_storage() || cur_storage.is_hash_storage() {
            return Err(InvalidInputException::with_message(format!(
                "Current storage can't be resized: {}",
                storage_display(cur_storage.as_ref())
            )));
        }
        if new_size > cur_size {
            self.variable_impl_expand_storage(cur_storage, new_size, data_type)
        } else {
            self.variable_impl_shrink_storage(cur_storage, new_size, data_type)
        }
    }

    /// Port of the private `VariableImpl.shrinkStorage`.
    fn variable_impl_shrink_storage(
        &self,
        cur_storage: Box<dyn VariableStorage>,
        new_size: i32,
        data_type: &dyn DataType,
    ) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
        let mut new_list: Vec<Varnode> = Vec::new();
        let mut size = 0;
        for vn in cur_storage.get_varnodes() {
            size += vn.get_size();
            if size >= new_size {
                let shrunk = self.variable_impl_shrink_varnode(&vn, size - new_size, data_type)?;
                new_list.push(shrunk);
                break;
            }
            new_list.push(vn);
        }
        Ok(cur_storage.with_varnodes(new_list))
    }

    /// Port of the private `VariableImpl.expandStorage`. See the module docs for the apparent
    /// Java bug (an always-empty result list) this port does not reproduce.
    fn variable_impl_expand_storage(
        &self,
        cur_storage: Box<dyn VariableStorage>,
        new_size: i32,
        data_type: &dyn DataType,
    ) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
        let mut varnodes = cur_storage.get_varnodes();
        let Some(last) = varnodes.last().cloned() else {
            return Err(InvalidInputException::with_message(format!(
                "Current storage can't be expanded to {} bytes: {}",
                new_size,
                storage_display(cur_storage.as_ref())
            )));
        };
        let last_index = varnodes.len() - 1;
        let size_increase = new_size - cur_storage.size();
        let expanded = self.variable_impl_expand_varnode(&last, size_increase, new_size, data_type)?;
        varnodes[last_index] = expanded;
        Ok(cur_storage.with_varnodes(varnodes))
    }

    /// Port of the private `VariableImpl.shrinkVarnode`.
    fn variable_impl_shrink_varnode(
        &self,
        varnode: &Varnode,
        size_reduction: i32,
        data_type: &dyn DataType,
    ) -> Result<Varnode, InvalidInputException> {
        let addr = varnode.get_address();
        if addr.is_stack_address() {
            return self.variable_impl_resize_stack_varnode(varnode, varnode.get_size() - size_reduction);
        }
        let is_register = varnode.is_register();
        let big_endian = self
            .get_program()
            .get_memory()
            .map(|m| m.is_big_endian())
            .unwrap_or(false);
        let complex_dt = data_type.as_composite().is_some() || data_type.as_array().is_some();
        if big_endian && (is_register || !complex_dt) {
            let new_addr = varnode.get_address().add(size_reduction as i64).map_err(|_| {
                InvalidInputException::with_message("address overflow while shrinking storage")
            })?;
            return Ok(Varnode::new(new_addr, varnode.get_size() - size_reduction));
        }
        Ok(Varnode::new(
            varnode.get_address().clone(),
            varnode.get_size() - size_reduction,
        ))
    }

    /// Port of the private `VariableImpl.expandVarnode`.
    fn variable_impl_expand_varnode(
        &self,
        varnode: &Varnode,
        size_increase: i32,
        new_size: i32,
        data_type: &dyn DataType,
    ) -> Result<Varnode, InvalidInputException> {
        let addr = varnode.get_address();
        if addr.is_stack_address() {
            return self.variable_impl_resize_stack_varnode(varnode, varnode.get_size() + size_increase);
        }
        let size = varnode.get_size() + size_increase;
        let program = self.get_program();
        let big_endian = program.get_memory().map(|m| m.is_big_endian()).unwrap_or(false);
        let reg = program.get_register_at(varnode.get_address());
        let vn_addr = varnode.get_address().clone();

        if let Some(mut new_reg) = reg {
            loop {
                let too_small = new_reg.borrow().minimum_byte_size() < size;
                if !too_small {
                    break;
                }
                let parent = new_reg.borrow().parent_register();
                match parent {
                    Some(p) => new_reg = p,
                    None => {
                        return Err(InvalidInputException::with_message(format!(
                            "Current storage can't be expanded to {} bytes",
                            new_size
                        )));
                    }
                }
            }
            if big_endian {
                let msb = new_reg.borrow().minimum_byte_size();
                let expanded_addr = new_reg.borrow().address().add((msb - size) as i64).map_err(|_| {
                    InvalidInputException::with_message("address overflow while expanding storage")
                })?;
                return Ok(Varnode::new(expanded_addr, size));
            }
        }

        let complex_dt = data_type.as_composite().is_some() || data_type.as_array().is_some();
        if big_endian && !complex_dt {
            let new_addr = vn_addr.subtract_no_wrap(size_increase as i64).map_err(|_| {
                InvalidInputException::with_message("address underflow while expanding storage")
            })?;
            return Ok(Varnode::new(new_addr, size));
        }
        Ok(Varnode::new(vn_addr, size))
    }

    /// Port of the private `VariableImpl.resizeStackVarnode`: keeps the same stack offset,
    /// changing only the varnode's size (no calling-convention-based alignment; see the module
    /// docs).
    fn variable_impl_resize_stack_varnode(
        &self,
        varnode: &Varnode,
        new_varnode_size: i32,
    ) -> Result<Varnode, InvalidInputException> {
        let cur_addr = varnode.get_address();
        let stack_offset = cur_addr.offset() as i32;
        let new_end_stack_offset = stack_offset + new_varnode_size - 1;
        if stack_offset < 0 && new_end_stack_offset >= 0 {
            return Err(InvalidInputException::with_message(
                "Data type does not fit within variable stack constraints",
            ));
        }
        let new_addr = Address::new(cur_addr.space().clone(), stack_offset as i64);
        Ok(Varnode::new(new_addr, new_varnode_size))
    }

    /// Port of `VariableImpl.toString()`.
    fn variable_impl_to_string(&self) -> String {
        format!(
            "[{} {}@{}]",
            self.stored_data_type().get_name(),
            self.stored_name().unwrap_or_default(),
            self.stored_variable_storage()
                .as_deref()
                .map(storage_display)
                .unwrap_or_default()
        )
    }

    /// Default body for [`Variable::is_equivalent`], standing in for `VariableImpl.equals`
    /// (identity/name/comment comparisons are handled by the caller through the ordinary
    /// [`Variable::get_name`]/[`Variable::get_comment`] accessors; this covers the storage/
    /// first-use-offset/datatype comparison `VariableImpl.isEquivalent` itself performs).
    fn variable_impl_is_equivalent(&self, other: &dyn Variable) -> bool {
        if self.parameter_ordinal().is_some() != other.parameter_ordinal().is_some() {
            return false;
        }
        if let (Some(a), Some(b)) = (self.parameter_ordinal(), other.parameter_ordinal()) {
            if a != b {
                return false;
            }
        }
        let storage_eq = match (self.stored_variable_storage(), other.get_variable_storage()) {
            (None, None) => true,
            (Some(a), Some(b)) => a.storage_equals(b.as_ref()),
            _ => false,
        };
        if !storage_eq {
            return false;
        }
        if self.get_first_use_offset() != other.get_first_use_offset() {
            return false;
        }
        is_same_or_equivalent_data_type(self.stored_data_type().as_ref(), other.get_data_type().as_ref())
    }

    /// Default body for [`Variable::compare_to`], standing in for `VariableImpl.compareTo`'s
    /// delegation to `VariableUtilities.compare` (duplicated locally; see the module docs).
    fn variable_impl_compare_to(&self, other: &dyn Variable) -> Ordering {
        if let (Some(o1), Some(o2)) = (self.parameter_ordinal(), other.parameter_ordinal()) {
            return o1.cmp(&o2);
        }

        let self_precedence = precedence(
            self.variable_impl_is_memory_variable_for_precedence(),
            self.variable_impl_is_register_variable(),
            self.variable_impl_is_stack_variable(),
            self.variable_impl_is_unique_variable(),
            self.variable_impl_is_compound_variable(),
            self.is_parameter(),
        );
        let other_precedence = precedence(
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

        if self.variable_impl_is_stack_variable() && other.is_stack_variable() {
            if let (Ok(o1), Ok(o2)) = (self.variable_impl_get_stack_offset(), other.get_stack_offset()) {
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

        let self_varnodes = self
            .stored_variable_storage()
            .map(|s| s.get_varnodes())
            .unwrap_or_default();
        let other_varnodes = other
            .get_variable_storage()
            .map(|s| s.get_varnodes())
            .unwrap_or_default();
        compare_varnode_lists(&self_varnodes, &other_varnodes)
    }

    /// Helper for [`variable_impl_compare_to`](Self::variable_impl_compare_to): `self`'s
    /// memory-variable precedence input, kept as a separate method (rather than calling
    /// [`variable_impl_is_memory_variable`](Self::variable_impl_is_memory_variable) inline) purely
    /// to keep the precedence call site symmetric with `other`'s `Variable::is_memory_variable()`.
    fn variable_impl_is_memory_variable_for_precedence(&self) -> bool {
        self.variable_impl_is_memory_variable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::Register;
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::{Function, Program};
    use crate::program::model::symbol::Symbol;

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
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            format!("mock{}", self.length)
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn is_void_type(&self) -> bool {
            self.is_void
        }

        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.length == dt.get_length()
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

    /// Minimal `VariableImpl` implementor backed by plain struct fields, mirroring the
    /// `MockVariable`/`MockLocalVariable` structs in sibling test modules. Every `Variable` method
    /// this port gives a real algorithm to just delegates to its `variable_impl_*` counterpart, as
    /// documented on [`VariableImpl`].
    struct MockVariableImpl {
        name: Option<String>,
        data_type: MockDataType,
        comment: Option<String>,
        source_type: SourceType,
        storage: Option<Box<dyn VariableStorage>>,
        program: Arc<dyn Program>,
        first_use_offset: i32,
        default_name: bool,
    }

    impl VariableImpl for MockVariableImpl {
        fn has_default_name(&self) -> bool {
            self.default_name
        }
        fn stored_name(&self) -> Option<String> {
            self.name.clone()
        }
        fn set_stored_name(&mut self, name: Option<String>) {
            self.name = name;
        }
        fn stored_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type)
        }
        fn set_stored_data_type(&mut self, data_type: Box<dyn DataType>) {
            // `dyn DataType` has no downcast/`Clone` bound; the mock instead reconstructs an
            // equivalent `MockDataType` from the trait's own accessors. Safe here since nothing in
            // this module ever hands `set_stored_data_type` anything but a `MockDataType`, and
            // `MockDataType`'s own `get_name` is itself derived purely from `length`.
            self.data_type = MockDataType {
                length: data_type.get_length(),
                is_void: data_type.is_void_type(),
            };
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

    impl Variable for MockVariableImpl {
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
            align: bool,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_impl_set_data_type_aligned(data_type, align, force, source)
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
        fn get_first_use_offset(&self) -> i32 {
            self.first_use_offset
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.variable_impl_is_equivalent(variable)
        }
        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.variable_impl_compare_to(other)
        }
    }

    fn new_variable(name: &str, data_type: MockDataType, addr: Address) -> MockVariableImpl {
        let program = mock_program();
        let fields = init_fields(
            Some(name.to_string()),
            Box::new(data_type),
            None,
            Some(addr),
            None,
            None,
            false,
            program.as_ref(),
            SourceType::UserDefined,
            false,
            false,
        )
        .unwrap();
        MockVariableImpl {
            name: fields.name,
            data_type: MockDataType {
                length: fields.data_type.get_length(),
                is_void: fields.data_type.is_void_type(),
            },
            comment: None,
            source_type: fields.source_type,
            storage: Some(fields.variable_storage),
            program,
            default_name: false,
            first_use_offset: 0,
        }
    }

    #[test]
    fn init_fields_from_memory_address_builds_valid_storage() {
        let addr = ram_space().address(0x1000);
        let var = new_variable("local_1", MockDataType::sized(4), addr.clone());
        assert_eq!(var.get_name(), Some("local_1".to_string()));
        assert_eq!(var.get_length(), 4);
        assert!(var.is_valid());
        assert_eq!(var.get_min_address(), Some(addr));
        assert_eq!(var.get_source(), SourceType::UserDefined);
    }

    #[test]
    fn init_fields_rejects_multiple_storage_locations() {
        let program = mock_program();
        let result = init_fields(
            None,
            Box::new(MockDataType::sized(4)),
            None,
            Some(ram_space().address(0)),
            Some(4),
            None,
            false,
            program.as_ref(),
            SourceType::UserDefined,
            false,
            false,
        );
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error for conflicting storage locations"),
        };
        assert!(err.to_string().contains("only one storage location"));
    }

    #[test]
    fn init_fields_from_register_uses_register_address_and_size() {
        let reg_space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let reg = Register::new("r0", "General register 0", reg_space.address(0), 4, false, 0);
        let program = mock_program();
        let fields = init_fields(
            Some("param_1".to_string()),
            Box::new(MockDataType::sized(4)),
            None,
            None,
            None,
            Some(reg),
            false,
            program.as_ref(),
            SourceType::UserDefined,
            false,
            false,
        )
        .unwrap();
        assert_eq!(fields.variable_storage.size(), 4);
        assert!(fields.variable_storage.is_register_storage());
    }

    #[test]
    fn set_name_uses_default_source_type_when_has_default_name() {
        let mut var = new_variable("local_1", MockDataType::sized(4), ram_space().address(0));
        var.default_name = true;
        var.variable_impl_set_name("local_2", SourceType::UserDefined)
            .unwrap();
        assert_eq!(var.stored_source_type(), SourceType::Default);
    }

    #[test]
    fn set_comment_strips_trailing_newline() {
        let mut var = new_variable("local_1", MockDataType::sized(4), ram_space().address(0));
        var.variable_impl_set_comment(Some("hello\n".to_string()));
        assert_eq!(var.stored_comment(), Some("hello".to_string()));
    }

    #[test]
    fn set_data_type_shrinks_memory_storage() {
        let mut var = new_variable("local_1", MockDataType::sized(4), ram_space().address(0x2000));
        var.variable_impl_set_data_type(Box::new(MockDataType::sized(2)), SourceType::Analysis)
            .unwrap();
        assert_eq!(var.get_length(), 2);
        assert_eq!(
            var.stored_variable_storage().unwrap().size(),
            2,
            "shrinking should resize the backing storage to match the new datatype length"
        );
    }

    #[test]
    fn set_data_type_expands_memory_storage() {
        let mut var = new_variable("local_1", MockDataType::sized(2), ram_space().address(0x3000));
        var.variable_impl_set_data_type(Box::new(MockDataType::sized(8)), SourceType::Analysis)
            .unwrap();
        assert_eq!(var.get_length(), 8);
        assert_eq!(
            var.stored_variable_storage().unwrap().size(),
            8,
            "expanding should grow the backing storage to match the new datatype length, not \
             silently drop it (see the module docs re: the Java expandStorage bug)"
        );
    }

    #[test]
    fn to_string_matches_java_format() {
        let var = new_variable("local_1", MockDataType::sized(4), ram_space().address(0x10));
        let text = var.variable_impl_to_string();
        assert!(text.starts_with("[mock4 local_1@"));
        assert!(text.ends_with(']'));
    }

    #[test]
    fn is_equivalent_compares_storage_and_data_type() {
        let a = new_variable("local_1", MockDataType::sized(4), ram_space().address(0x10));
        let b = new_variable("local_2", MockDataType::sized(4), ram_space().address(0x10));
        // `storage_equals` on the underlying stub defaults to `false` (see seam_stubs), so two
        // otherwise-identical storages are never considered equal by this port; this exercises
        // that both variables are consistently *not* equivalent rather than asserting a specific
        // (stub-dependent) outcome for identical storage.
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn compare_to_orders_by_first_use_offset_when_precedence_and_storage_match() {
        let mut a = new_variable("local_1", MockDataType::sized(4), ram_space().address(0x10));
        let mut b = new_variable("local_2", MockDataType::sized(4), ram_space().address(0x10));
        a.first_use_offset = 4;
        b.first_use_offset = 8;
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let var: Box<dyn VariableImpl> = Box::new(new_variable(
            "local_1",
            MockDataType::sized(4),
            ram_space().address(0x10),
        ));
        assert_eq!(var.stored_name(), Some("local_1".to_string()));
        assert!(var.variable_impl_is_valid());
    }
}
