//! Port of `ghidra.program.model.data.DataUtilities`.
//!
//! The Java class is a `private`-constructor static-method utility (it cannot be instantiated).
//! It was selected as a dependency-cycle cut-point, so -- mirroring
//! [`VariableUtilities`](crate::program::model::listing::variable_utilities::VariableUtilities)
//! -- it is ported here as a Rust trait with default-implemented methods instead of free
//! functions: callers depend on `&dyn DataUtilities` (a trait-object seam) rather than importing
//! this module's concrete machinery directly, which is what breaks the cycle. A bare `impl
//! DataUtilities for Foo {}` is enough to use every method, since every method has a real default
//! implementation. The private helper methods that back the public API have no receiver of their
//! own in Java and are ported as ordinary module-private free functions, exactly as
//! `VariableUtilities` already does for its own `variable_varnodes` helper.
//!
//! A handful of accessors this port needs did not previously exist on already-ported real traits;
//! they were grown as defaulted methods (so existing implementors keep compiling), following the
//! established `instanceof`-standin convention used throughout this crate:
//! - [`DataType::as_typedef`](crate::program::model::data::data_type::DataType::as_typedef) --
//!   `instanceof TypeDef`, by-reference (like the pre-existing `as_pointer`/`as_dynamic`).
//! - [`CodeUnit::as_data`](crate::program::model::listing::code_unit::CodeUnit::as_data) --
//!   `instanceof Data`, needed while walking a mixed instruction/data code-unit sequence.
//! - [`Reference::as_external_reference`](crate::program::model::symbol::reference::Reference::as_external_reference)
//!   -- `instanceof ExternalReference`.
//! - [`Program::get_memory`](crate::program::model::listing::Program::get_memory),
//!   [`Memory::get_block`](crate::program::model::mem::Memory::get_block), and
//!   [`MemoryBlock::contains`](crate::program::model::mem::MemoryBlock::contains).
//!
//! `Undefined.isUndefined(DataType)` (see
//! [`undefined::is_undefined`](crate::program::model::data::undefined::is_undefined)) takes
//! ownership of a `Box<dyn DataType>`, but every call site in this port only ever holds a
//! borrowed `&dyn DataType` that is still needed afterward (e.g. `isDefaultData`'s `dt` parameter,
//! which is checked for undefined-ness and then, if that fails, inspected further as a
//! typedef/pointer). Rather than force an ownership transfer that Java's reference semantics never
//! required, this port re-implements the identical check as [`is_undefined_ref`] using the
//! by-reference [`DataType::as_array`] downcast in place of the owned-only
//! [`DataType::into_array`] that `undefined::is_undefined` itself relies on.
//!
//! `ghidra.program.model.mem.DumbMemBufferImpl` (used by the private `getDtInstance`) is not yet
//! ported; a minimal placeholder lives in `seam_stubs.rs` (see `STUBS.tsv`).
//!
//! A few spots need one owned `DataType` handle to alias another (e.g. `ptr.newPointer(ptr)`,
//! which passes the same pointer object as both receiver and argument to build a "pointer to
//! itself"). Since `dyn DataType` has no `Clone`, this port threads the relevant value through as
//! an `Arc<dyn DataType>` and uses the existing
//! [`share_data_type`](crate::program::seam_stubs::share_data_type) helper (already used
//! elsewhere in this crate for exactly this purpose) to hand out an aliasing `Box<dyn DataType>`
//! handle. [`DataUtilities::reconcile_applied_data_type`]'s `originalDataType` parameter is
//! therefore `Arc<dyn DataType>` rather than `&dyn DataType`.
//!
//! `newType.equals(existingType)` in the private `isExistingNonDynamicType` relies on Java's
//! default `Object.equals` (reference identity) for `DataType` implementations that don't override
//! it. No general identity comparison is available for `dyn DataType` in this port, so
//! [`DataType::is_equivalent`] (already used earlier in the same call chain for the analogous
//! `newType.isEquivalent(existingType)` check) is used as the closest available structural
//! stand-in; this is a deliberate, documented divergence.
//!
//! `reconcileAppliedDataType`'s final branch constructs `new PointerDataType(newDataType)` to wrap
//! a bare `FunctionDefinition` (or typedef thereof) in a pointer. As documented on
//! [`PointerDataType`](crate::program::model::data::pointer_data_type::PointerDataType) itself,
//! this port has no way to construct a concrete `PointerDataType` generically (there is no
//! `Self: Default`/factory bound, and this branch is reached specifically when no `Pointer`
//! instance is otherwise available to ask for one). Mirroring
//! [`DataTypeInstance`](crate::program::model::data::data_type_instance)'s own documented
//! divergence for the identical underlying limitation, this branch returns `newDataType`
//! unwrapped rather than a pointer to it.
//!
//! Several methods (`getDataAtLocation`, `getDataAtAddress`, `getMaxAddressOfUndefinedRange`,
//! `isUndefinedData`, `getNextNonUndefinedDataAfter`, `isUndefinedRange`) assume in Java that
//! `program.getListing()`/`program.getMemory()` are always non-null, and would throw an unchecked
//! `NullPointerException` if that assumption were ever violated. This port instead treats a
//! missing `Listing`/`Memory` as "nothing found" (`None`/`false`), trading Java's crash for a safe
//! fallback consistent with each method's `Option`/`bool` contract.
//!
//! `getDataAtLocation` needs a `&mut dyn Listing` reached through the `Arc<dyn Program>` handed
//! back by [`ProgramLocation::get_program`], which this crate's `Program::get_listing` cannot
//! reach through a shared reference. Mirroring the established
//! [`FunctionMatchSet::get_length_in_a`](crate::app::plugin::match::function_match_set::FunctionMatchSet::get_length_in_a)
//! precedent for the same architectural constraint, this port uses `Arc::get_mut`, returning
//! `None` if the program `Arc` is currently shared.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_instance::{
    get_data_type_instance, get_data_type_instance_at, DataTypeInstance,
};
use crate::program::model::data::pointer::Pointer;
use crate::program::model::listing::{CodeUnit, Data, Listing, Program};
use crate::program::model::symbol::{Reference, ReferenceManager};
use crate::program::seam_stubs::{share_data_type, DumbMemBufferImpl};
use crate::program::model::mem::MemBuffer;
use crate::program::util::{CodeUnitInsertionException, ProgramLocation};
use crate::util::exception::AssertException;

/// `ClearDataMode` specifies how conflicting data should be cleared when creating/re-creating
/// data.
///
/// Port of `ghidra.program.model.data.DataUtilities.ClearDataMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearDataMode {
    /// Ensure that data will fit before clearing a single code unit at the specified data
    /// address.
    CheckForSpace,
    /// Always clear a single code unit at the data address regardless of the ability for the
    /// desired data-type to fit.
    ClearSingleData,
    /// Clear all conflicting Undefined Data provided new data will fit within memory and not
    /// conflict with an instruction or other defined data.
    ClearAllUndefinedConflictData,
    /// Clear all Default Data provided new data will fit within memory and not conflict with an
    /// instruction or other defined data.
    ClearAllDefaultConflictData,
    /// Clear all conflicting data provided new data will fit within memory and not conflict with
    /// an instruction.
    ClearAllConflictData,
}

/// Static helper methods for working with `Data`/`DataType` creation, lookup, and undefined-range
/// queries.
///
/// Port of `ghidra.program.model.data.DataUtilities`. See the module docs for what was ported,
/// grown, and deliberately diverged from.
pub trait DataUtilities {
    /// Determine if the specified name is a valid data-type name.
    fn is_valid_data_type_name(&self, name: &str) -> bool {
        if name.trim().is_empty() {
            return false;
        }
        !name.chars().any(|c| c.is_control())
    }

    /// Create data where existing data may already exist. Pointer datatype stacking will not be
    /// performed.
    ///
    /// `addr` is the data address (offcut data address only allowed if `clear_mode ==
    /// ClearDataMode::ClearAllConflictData`). `length` is used only for a Dynamic `new_type` which
    /// has `Dynamic::can_specify_length() == true`.
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if data creation failed.
    fn create_data(
        &self,
        program: &mut dyn Program,
        addr: &Address,
        new_type: Box<dyn DataType>,
        length: i32,
        clear_mode: ClearDataMode,
    ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
        self.create_data_with_stack_pointers(program, addr, new_type, length, false, clear_mode)
    }

    /// Create data where existing data may already exist.
    ///
    /// `stack_pointers` is as described on [`DataUtilities::reconcile_applied_data_type`].
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if data creation failed.
    fn create_data_with_stack_pointers(
        &self,
        program: &mut dyn Program,
        addr: &Address,
        new_type: Box<dyn DataType>,
        length: i32,
        stack_pointers: bool,
        clear_mode: ClearDataMode,
    ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
        let mut new_type = new_type;
        let mut stack_pointers = stack_pointers;

        let data = {
            let listing = program.get_listing().ok_or_else(|| no_data_at(addr))?;
            get_data(addr, clear_mode, listing)?
        };

        let mut existing_length = addr.space().unit_size();
        let existing_type: Arc<dyn DataType> = Arc::from(data.get_data_type());
        let mut ext_ref: Option<Arc<dyn Reference>> = None;

        if !is_parent_data(data.as_ref(), addr) {
            if !stack_pointers && is_data_clearing_denied(existing_type.as_ref(), clear_mode) {
                return Err(no_data_at(addr));
            }

            existing_length = data.get_length();

            if data.is_defined() {
                if stack_pointers && new_type.is_pointer() {
                    if let Some(existing_ptr) = existing_type.as_pointer() {
                        if is_default_pointer(new_type.as_ref()) {
                            let ptr_arg = share_data_type(&existing_type);
                            new_type = existing_ptr.new_pointer(ptr_arg);
                        }
                        stack_pointers = false;
                    }
                }
                if new_type.is_equivalent(existing_type.as_ref()) {
                    return Ok(data);
                }
            }

            ext_ref = get_external_pointer_reference(
                addr,
                new_type.is_pointer(),
                stack_pointers,
                program.get_reference_manager(),
                existing_type.is_pointer(),
            );
        }

        if let Some(dtm) = program.get_data_type_manager() {
            new_type = new_type.clone_data_type(dtm.as_ref());
        }
        new_type = self.reconcile_applied_data_type(existing_type.clone(), new_type, stack_pointers);

        if is_existing_non_dynamic_type(new_type.as_ref(), existing_type.as_ref()) {
            return Ok(data);
        }

        let new_type_is_pointer = new_type.is_pointer();
        let display_name = new_type.get_display_name();
        let dti = get_dt_instance(program, addr, new_type, length).ok_or_else(|| {
            CodeUnitInsertionException::new(format!("Could not create DataType {display_name}"))
        })?;

        if stack_pointers && existing_type.is_pointer() && new_type_is_pointer {
            if let Some(listing) = program.get_listing() {
                listing.clear_code_units(addr, addr, false);
            }
        }

        let dti_length = dti.get_length();
        let create_result = {
            let new_data_type = dti.get_data_type();
            let listing = program.get_listing().ok_or_else(|| no_data_at(addr))?;
            listing.create_data_sized(addr.clone(), new_data_type, dti_length)
        };

        let new_data = match create_result {
            Ok(d) => d,
            Err(_) => {
                if clear_mode == ClearDataMode::ClearSingleData {
                    if let Some(listing) = program.get_listing() {
                        listing.clear_code_units(addr, addr, false);
                    }
                } else {
                    check_enough_space(program, addr, existing_length, dti.as_ref(), clear_mode)?;
                }
                let new_data_type = dti.get_data_type();
                let listing = program.get_listing().ok_or_else(|| no_data_at(addr))?;
                listing.create_data_sized(addr.clone(), new_data_type, dti_length)?
            }
        };

        restore_reference(new_type_is_pointer, program.get_reference_manager(), ext_ref);

        Ok(new_data)
    }

    /// Determine the final data-type which should be applied based upon a user applied type of
    /// `new_data_type` on an existing `original_data_type`. Pointer conversion is performed when
    /// appropriate, otherwise `new_data_type` is returned unchanged.
    ///
    /// If `new_data_type` is a `FunctionDefinition`, or Typedef to a `FunctionDefinition`, it
    /// will either be stacked with the existing pointer if enabled/applicable, or will be
    /// converted to a pointer since `FunctionDefinition`s may only be used in the form of a
    /// pointer (see the module docs for a documented divergence here).
    ///
    /// Note that `original_data_type` and `new_data_type` should be actual applied types (i.e.,
    /// do not strip typedefs, pointers, arrays, etc).
    ///
    /// If `stack_pointers` is true:
    /// - If `new_data_type` is a default pointer and `original_data_type` is a pointer, the new
    ///   pointer will wrap the existing pointer thus increasing its "depth" (e.g., `int *` would
    ///   become `int **` when a default pointer is applied). If `original_data_type` is not a
    ///   pointer, `new_data_type` is returned unchanged.
    /// - If `original_data_type` is any type of pointer, the supplied `new_data_type` will
    ///   replace the pointer's base type (e.g., `int *` would become `db *` when `new_data_type`
    ///   is `ByteDataType`).
    ///
    /// If `stack_pointers` is false, only required transformations will be applied (e.g. a
    /// `FunctionDefinitionDataType` is transformed to a pointer before being applied).
    fn reconcile_applied_data_type(
        &self,
        original_data_type: Arc<dyn DataType>,
        new_data_type: Box<dyn DataType>,
        stack_pointers: bool,
    ) -> Box<dyn DataType> {
        if new_data_type.is_default_data_type() {
            return new_data_type;
        }

        let original_ptr = original_data_type.as_pointer();

        if stack_pointers && new_data_type.is_pointer() {
            if let Some(ptr) = original_ptr {
                if is_default_pointer(new_data_type.as_ref()) {
                    let ptr_arg = share_data_type(&original_data_type);
                    return ptr.new_pointer(ptr_arg);
                }
                return new_data_type;
            }
        } else if stack_pointers {
            if let Some(ptr) = original_ptr {
                return stack_pointers_onto(ptr, new_data_type);
            }
        } else if is_function_definition_or_typedef_thereof(new_data_type.as_ref()) {
            // Java wraps this in `new PointerDataType(newDataType)`; see the module docs for why
            // that construction is unmodeled here.
            return new_data_type;
        }

        new_data_type
    }

    /// Get the data for the given address; if the code unit at the address is an instruction,
    /// return `None`.
    ///
    /// `loc` provides the address and subcomponent within the data at the address.
    fn get_data_at_location(&self, loc: &dyn ProgramLocation) -> Option<Box<dyn Data>> {
        let mut program = loc.get_program();
        let listing = Arc::get_mut(&mut program)?.get_listing()?;
        let data_containing = listing.get_data_containing(&loc.get_address())?;
        let path = loc.get_component_path().unwrap_or(&[]);
        data_containing.get_component_by_path(path)
    }

    /// Get the data for the given address.
    ///
    /// This will return `Some` if and only if there is data that starts at the given address.
    fn get_data_at_address(
        &self,
        program: &mut dyn Program,
        address: Option<&Address>,
    ) -> Option<Arc<dyn Data>> {
        let address = address?;
        program.get_listing()?.get_data_at(address)
    }

    /// Get the maximum address of an undefined data range starting at `addr`. Both undefined
    /// code units and defined data which have an Undefined data type are included in the range.
    ///
    /// `addr` is the address where this will start checking for Undefined data; it can be offcut
    /// into an Undefined Data.
    ///
    /// Returns the end of the undefined range, or `None` if `addr` does not correspond to an
    /// undefined location.
    fn get_max_address_of_undefined_range(
        &self,
        program: &mut dyn Program,
        addr: &Address,
    ) -> Option<Address> {
        let data = program.get_listing()?.get_data_containing(addr)?;
        if !is_undefined_ref(data.get_data_type().as_ref()) {
            return None;
        }
        let mut end_of_range_address = data.get_max_address();

        let block = program.get_memory()?.get_block(addr)?;
        let limit_address = block.get_end();

        let mut cu: Option<Arc<dyn CodeUnit>> = Some(data.clone() as Arc<dyn CodeUnit>);
        while let Some(current) = cu.clone() {
            if mnemonic_address(current.as_ref()) > limit_address {
                end_of_range_address = limit_address.clone();
                break;
            }
            let still_undefined = current
                .as_data()
                .map(|d| is_undefined_ref(d.get_data_type().as_ref()))
                .unwrap_or(false);
            if !still_undefined {
                end_of_range_address = current.get_min_address().previous().ok()?;
                break;
            }
            end_of_range_address = current.get_max_address();
            cu = program
                .get_listing()
                .and_then(|l| l.get_defined_code_unit_after(&end_of_range_address));
        }
        if cu.is_none() {
            end_of_range_address = limit_address;
        }

        Some(end_of_range_address)
    }

    /// Determine if the specified `addr` corresponds to an undefined data location, where both
    /// undefined code units and defined data which has an Undefined data type is considered to
    /// be undefined.
    fn is_undefined_data(&self, program: &mut dyn Program, addr: &Address) -> bool {
        match program.get_listing().and_then(|l| l.get_data_at(addr)) {
            Some(data) => is_undefined_ref(data.get_data_type().as_ref()),
            None => false,
        }
    }

    /// Get the next defined data that comes after the address indicated by `addr` and that is no
    /// more than `max_addr`, and that is not a sized undefined data type.
    fn get_next_non_undefined_data_after(
        &self,
        program: &mut dyn Program,
        addr: &Address,
        max_addr: &Address,
    ) -> Option<Arc<dyn Data>> {
        let mut current_address = addr.clone();
        let mut data = program.get_listing()?.get_defined_data_after(&current_address);
        while let Some(d) = &data {
            if !is_undefined_ref(d.get_data_type().as_ref()) || current_address > *max_addr {
                break;
            }
            current_address = d.get_max_address();
            data = program.get_listing()?.get_defined_data_after(&current_address);
        }
        match data {
            Some(d) if mnemonic_address(d.as_ref()) > *max_addr => None,
            other => other,
        }
    }

    /// Finds the first conflicting address in the given address range.
    ///
    /// `ignore_undefined_data`: true if the search should ignore Undefined data as a potential
    /// conflict, or false if Undefined data should trigger conflicts.
    ///
    /// Returns the address of the first conflict in the range, or `None` if there were no
    /// conflicts.
    ///
    /// Java scans this range via `Listing.getDefinedData(AddressSetView, boolean)`/
    /// `Listing.getInstructions(AddressSetView, boolean)`. This port instead walks the range with
    /// `get_defined_data_at`/`get_defined_data_after` and `get_instruction_at`/
    /// `get_instruction_after` (mirroring the bounded-scan idiom already used by
    /// [`DataUtilities::get_next_non_undefined_data_after`]), since `Listing`'s
    /// `AddressSetView`-scoped iterators currently return the placeholder
    /// `seam_stubs::DataIterator`/`seam_stubs::InstructionIterator` types, which have no item
    /// accessor yet.
    fn find_first_conflicting_address(
        &self,
        program: &mut dyn Program,
        addr: &Address,
        length: i32,
        ignore_undefined_data: bool,
    ) -> Option<Address> {
        let end = addr.add((length - 1) as i64).ok()?;

        let data_addr = {
            let listing = program.get_listing()?;
            first_defined_data_start_in_range(listing, addr, &end, ignore_undefined_data)
        };
        let instruction_addr = {
            let listing = program.get_listing()?;
            first_instruction_start_in_range(listing, addr, &end)
        };

        match (data_addr, instruction_addr) {
            (None, None) => None,
            (None, Some(i)) => Some(i),
            (Some(d), None) => Some(d),
            (Some(d), Some(i)) => Some(if d < i { d } else { i }),
        }
    }

    /// Determine if there is only undefined data from `start_address` to `end_address`. Both
    /// addresses must be in the same defined block of memory.
    ///
    /// `end_address` must be greater than or equal to `start_address` and must be in the same
    /// memory block as `start_address`, otherwise `false` is returned.
    fn is_undefined_range(
        &self,
        program: &mut dyn Program,
        start_address: &Address,
        end_address: &Address,
    ) -> bool {
        let Some(block) = program.get_memory().and_then(|m| m.get_block(start_address)) else {
            return false;
        };
        if !block.contains(end_address) {
            return false;
        }
        if start_address > end_address {
            return false;
        }

        let Some(data) = program
            .get_listing()
            .and_then(|l| l.get_data_containing(start_address))
        else {
            return false;
        };
        if !is_undefined_ref(data.get_data_type().as_ref()) {
            return false;
        }

        let mut max_address = data.get_max_address();
        while &max_address < end_address {
            let Some(code_unit) = program
                .get_listing()
                .and_then(|l| l.get_defined_code_unit_after(&max_address))
            else {
                return true;
            };
            let min_address = code_unit.get_min_address();
            if &min_address > end_address {
                return true;
            }
            let still_undefined = code_unit
                .as_data()
                .map(|d| is_undefined_ref(d.get_data_type().as_ref()))
                .unwrap_or(false);
            if !still_undefined {
                return false;
            }
            max_address = code_unit.get_max_address();
        }
        true
    }
}

/// Returns the mnemonic (start) address of `cu`, i.e. `MemBuffer.getAddress()` as inherited by
/// `CodeUnit`. `CodeUnit` itself separately declares an operand-indexed `getAddress(int)`
/// overload (see [`CodeUnit::get_address`]), so this is reached via a fully-qualified call to
/// disambiguate from that unrelated method of the same name.
fn mnemonic_address(cu: &dyn CodeUnit) -> Address {
    MemBuffer::get_address(cu)
}

/// Mirrors `Undefined.isUndefined(DataType)`'s logic using the by-reference
/// [`DataType::as_array`] downcast rather than the owned-only [`DataType::into_array`] that
/// [`undefined::is_undefined`](crate::program::model::data::undefined::is_undefined) itself uses
/// -- see the module docs for why.
fn is_undefined_ref(dt: &dyn DataType) -> bool {
    if dt.is_default_data_type() || dt.is_undefined_type() {
        return true;
    }
    match dt.as_array() {
        Some(array) => {
            let base_type = array.get_data_type();
            base_type.is_undefined_type() || base_type.is_default_data_type()
        }
        None => false,
    }
}

/// Returns true if `ptr`'s referenced datatype is unset or the `DEFAULT` datatype.
///
/// Shared by [`is_default_data`] and [`is_default_pointer`], which both perform this exact check
/// (`ptrDt == null || ptrDt == DataType.DEFAULT` in Java).
fn pointer_targets_default(ptr: &dyn Pointer) -> bool {
    match ptr.get_data_type() {
        None => true,
        Some(inner) => inner.is_default_data_type(),
    }
}

/// Port of the private `DataUtilities.isDefaultPointer(DataType)`.
fn is_default_pointer(dt: &dyn DataType) -> bool {
    match dt.as_pointer() {
        Some(ptr) => pointer_targets_default(ptr),
        None => false,
    }
}

/// Port of the private `DataUtilities.isDefaultData(DataType)`; see [`ClearDataMode::ClearAllDefaultConflictData`].
fn is_default_data(dt: &dyn DataType) -> bool {
    if is_undefined_ref(dt) {
        return true;
    }

    let base_holder = match dt.as_typedef() {
        Some(td) => {
            if !td.is_auto_named() {
                return false;
            }
            Some(td.get_data_type())
        }
        None => None,
    };
    let dt: &dyn DataType = base_holder.as_deref().unwrap_or(dt);

    match dt.as_pointer() {
        Some(ptr) => pointer_targets_default(ptr),
        None => false,
    }
}

/// Port of the private `DataUtilities.isDataClearingDenied(DataType, ClearDataMode)`.
fn is_data_clearing_denied(dt: &dyn DataType, clear_mode: ClearDataMode) -> bool {
    if clear_mode == ClearDataMode::ClearAllUndefinedConflictData && !is_undefined_ref(dt) {
        return true;
    }
    if clear_mode == ClearDataMode::ClearAllDefaultConflictData && !is_default_data(dt) {
        return true;
    }
    false
}

/// Port of the private `DataUtilities.isParentData(Data, Address)`.
fn is_parent_data(data: &dyn Data, addr: &Address) -> bool {
    mnemonic_address(data) != *addr
}

/// Port of the private `DataUtilities.getData(Address, ClearDataMode, Listing)`.
fn get_data(
    addr: &Address,
    clear_mode: ClearDataMode,
    listing: &mut dyn Listing,
) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
    if let Some(data) = listing.get_data_at(addr) {
        return Ok(data);
    }

    let mut data = None;
    if matches!(
        clear_mode,
        ClearDataMode::ClearAllConflictData
            | ClearDataMode::ClearAllUndefinedConflictData
            | ClearDataMode::ClearAllDefaultConflictData
    ) {
        if let Some(containing) = listing.get_data_containing(addr) {
            if !is_data_clearing_denied(containing.get_data_type().as_ref(), clear_mode) {
                data = Some(containing);
            }
        }
    }

    data.ok_or_else(|| no_data_at(addr))
}

/// Port of the private `DataUtilities.getDtInstance(Program, Address, DataType, int, DataType)`.
/// The `realType` parameter is recomputed internally from `new_type` rather than threaded through
/// separately, avoiding a borrow that would otherwise outlive `new_type` being moved into the
/// `DataTypeInstance` factory calls below.
fn get_dt_instance(
    program: &mut dyn Program,
    addr: &Address,
    new_type: Box<dyn DataType>,
    length: i32,
) -> Option<Box<dyn DataTypeInstance>> {
    let base_holder = if new_type.is_typedef() {
        new_type.typedef_base_data_type()
    } else {
        None
    };
    let can_specify_length = base_holder
        .as_deref()
        .unwrap_or(new_type.as_ref())
        .as_dynamic()
        .map(|d| d.can_specify_length())
        .unwrap_or(false);

    let buf = DumbMemBufferImpl::new(program.get_memory(), addr.clone());

    if length > 0 && can_specify_length {
        get_data_type_instance_at(Some(new_type), &buf, length, false)
    } else {
        get_data_type_instance(Some(new_type), &buf, false)
    }
}

/// Port of the private `DataUtilities.isExistingNonDynamicType(DataType, DataType, DataType)`.
/// See the module docs for the `newType.equals(existingType)` -> `is_equivalent` divergence.
fn is_existing_non_dynamic_type(new_type: &dyn DataType, existing_type: &dyn DataType) -> bool {
    let base_holder = if new_type.is_typedef() {
        new_type.typedef_base_data_type()
    } else {
        None
    };
    let real_type: &dyn DataType = base_holder.as_deref().unwrap_or(new_type);

    if real_type.is_dynamic_type() || real_type.is_factory_type() {
        return false;
    }

    new_type.is_equivalent(existing_type)
}

/// Port of the private `DataUtilities.restoreReference(DataType, ReferenceManager, Reference)`.
fn restore_reference(
    new_type_is_pointer: bool,
    ref_mgr: Option<&mut dyn ReferenceManager>,
    ext_ref: Option<Arc<dyn Reference>>,
) {
    let Some(ext_ref) = ext_ref else {
        return;
    };
    if !new_type_is_pointer {
        return;
    }
    let Some(ref_mgr) = ref_mgr else {
        return;
    };
    let Some(external) = ext_ref.as_external_reference() else {
        return;
    };

    let ext_loc = Arc::from(external.get_external_location());
    let from_address = ext_ref.from_address();
    let source = ext_ref.source();
    let ref_type = ext_ref.reference_type();
    if let Err(e) =
        ref_mgr.add_external_reference_for_location(from_address, 0, ext_loc, source, ref_type)
    {
        // Java: `throw new AssertException(e)` -- this can only happen if the extLoc/fromAddress
        // we just read back off `ext_ref` were somehow invalid, which should never occur.
        panic!("{}", AssertException::with_cause(e));
    }
}

/// Port of the private `DataUtilities.getExternalPointerReference(Address, DataType, boolean,
/// ReferenceManager, DataType)`.
fn get_external_pointer_reference(
    addr: &Address,
    new_type_is_pointer: bool,
    stack_pointers: bool,
    ref_mgr: Option<&mut dyn ReferenceManager>,
    existing_type_is_pointer: bool,
) -> Option<Arc<dyn Reference>> {
    if !((stack_pointers || new_type_is_pointer) && existing_type_is_pointer) {
        return None;
    }
    let ref_mgr = ref_mgr?;
    ref_mgr
        .get_references_from(addr.clone())
        .into_iter()
        .find(|r| r.operand_index() == 0 && r.is_external_reference())
}

/// Port of the private `DataUtilities.checkEnoughSpace(Program, Address, int, DataTypeInstance,
/// ClearDataMode)`.
fn check_enough_space(
    program: &mut dyn Program,
    addr: &Address,
    existing_data_len: i32,
    dti: &dyn DataTypeInstance,
    clear_mode: ClearDataMode,
) -> Result<(), CodeUnitInsertionException> {
    let not_enough_space = || {
        CodeUnitInsertionException::new(format!(
            "Not enough space to create DataType {}",
            dti.get_data_type().get_display_name()
        ))
    };

    let end = addr
        .add_no_wrap((existing_data_len - 1) as i64)
        .map_err(|_| not_enough_space())?;
    let new_end = addr
        .add_no_wrap((dti.get_length() - 1) as i64)
        .map_err(|_| not_enough_space())?;

    let listing = program.get_listing().ok_or_else(|| no_data_at(addr))?;

    if let Some(instr) = listing.get_instruction_after(&end) {
        if instr.get_min_address() <= new_end {
            return Err(not_enough_space());
        }
    }

    let defined_data = listing.get_defined_data_after(&end);
    let defined_data = match defined_data {
        Some(d) if d.get_min_address() <= new_end => d,
        _ => {
            listing.clear_code_units(addr, addr, false);
            return Ok(());
        }
    };

    let clearing_allowed = matches!(
        clear_mode,
        ClearDataMode::ClearAllUndefinedConflictData | ClearDataMode::ClearAllDefaultConflictData
    ) && !is_data_clearing_denied(defined_data.get_data_type().as_ref(), clear_mode);

    if clearing_allowed {
        check_for_defined_data(dti, listing, &new_end, &defined_data.get_max_address(), clear_mode)?;
    } else if clear_mode != ClearDataMode::ClearAllConflictData {
        return Err(not_enough_space());
    }

    listing.clear_code_units(addr, &new_end, false);
    Ok(())
}

/// Port of the private `DataUtilities.checkForDefinedData(DataTypeInstance, Listing, Address,
/// Address, ClearDataMode)`.
fn check_for_defined_data(
    dti: &dyn DataTypeInstance,
    listing: &mut dyn Listing,
    address: &Address,
    end: &Address,
    clear_mode: ClearDataMode,
) -> Result<(), CodeUnitInsertionException> {
    let mut end = end.clone();
    while end <= *address {
        let Some(defined_data) = listing.get_defined_data_after(&end) else {
            return Ok(());
        };
        if defined_data.get_min_address() > *address {
            return Ok(());
        }
        if is_data_clearing_denied(defined_data.get_data_type().as_ref(), clear_mode) {
            return Err(CodeUnitInsertionException::new(format!(
                "Not enough space to create DataType {}",
                dti.get_data_type().get_display_name()
            )));
        }
        end = defined_data.get_max_address();
    }
    Ok(())
}

/// Port of the private `DataUtilities.stackPointers(Pointer, DataType)`, renamed to avoid
/// clashing with the `stack_pointers` parameter/local used throughout this module.
fn stack_pointers_onto(pointer: &dyn Pointer, data_type: Box<dyn DataType>) -> Box<dyn DataType> {
    match pointer.get_data_type() {
        Some(inner) => match inner.as_pointer() {
            Some(inner_ptr) => {
                let replaced = stack_pointers_onto(inner_ptr, data_type);
                pointer.new_pointer(replaced)
            }
            None => pointer.new_pointer(data_type),
        },
        None => pointer.new_pointer(data_type),
    }
}

/// Shared by [`DataUtilities::reconcile_applied_data_type`]; port of the inline `newDataType
/// instanceof FunctionDefinition || (newDataType instanceof TypeDef && ((TypeDef)
/// newDataType).getBaseDataType() instanceof FunctionDefinition)` check.
fn is_function_definition_or_typedef_thereof(dt: &dyn DataType) -> bool {
    if dt.is_function_definition_type() {
        return true;
    }
    if dt.is_typedef() {
        if let Some(base) = dt.typedef_base_data_type() {
            return base.is_function_definition_type();
        }
    }
    false
}

/// Shared "Could not create Data at address {addr}" `CodeUnitInsertionException`, used at every
/// call site that mirrors a null-`Listing`/null-`Data` guard in the Java source.
fn no_data_at(addr: &Address) -> CodeUnitInsertionException {
    CodeUnitInsertionException::new(format!("Could not create Data at address {addr}"))
}

/// Finds the start address of the first defined Data in `[addr, end]`, skipping past leading
/// Undefined data when `ignore_undefined_data` is set. Used by
/// [`DataUtilities::find_first_conflicting_address`]; see that method's docs for why this
/// bounded-scan reimplementation is needed in place of `Listing::get_defined_data_in`.
fn first_defined_data_start_in_range(
    listing: &mut dyn Listing,
    addr: &Address,
    end: &Address,
    ignore_undefined_data: bool,
) -> Option<Address> {
    let mut candidate = listing
        .get_defined_data_at(addr)
        .or_else(|| listing.get_defined_data_after(addr));
    while let Some(d) = candidate {
        let start = d.get_min_address();
        if start > *end {
            return None;
        }
        if !ignore_undefined_data || !is_undefined_ref(d.get_data_type().as_ref()) {
            return Some(start);
        }
        candidate = listing.get_defined_data_after(&d.get_max_address());
    }
    None
}

/// Finds the start address of the first Instruction in `[addr, end]`. Used by
/// [`DataUtilities::find_first_conflicting_address`]; see that method's docs for why this
/// bounded-scan reimplementation is needed in place of `Listing::get_instructions_in`.
fn first_instruction_start_in_range(
    listing: &mut dyn Listing,
    addr: &Address,
    end: &Address,
) -> Option<Address> {
    let candidate = listing
        .get_instruction_at(addr)
        .or_else(|| listing.get_instruction_after(addr))?;
    let start = candidate.get_min_address();
    (start <= *end).then_some(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType {
        name: String,
        length: i32,
        is_control_undefined: bool,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_undefined_type(&self) -> bool {
            self.is_control_undefined
        }
        fn clone_data_type(
            &self,
            _dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager,
        ) -> Box<dyn DataType> {
            Box::new(MockDataType {
                name: self.name.clone(),
                length: self.length,
                is_control_undefined: self.is_control_undefined,
            })
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.name
        }
    }

    /// Smoke test proving `DataUtilities` is object-safe via a bare blanket impl (every method
    /// has a default body), mirroring `VariableUtilities`'s own smoke test.
    struct Util;
    impl DataUtilities for Util {}

    #[test]
    fn usable_as_trait_object() {
        let util: &dyn DataUtilities = &Util;
        assert!(util.is_valid_data_type_name("byte"));
    }

    #[test]
    fn is_valid_data_type_name_rejects_blank_and_control() {
        let util = Util;
        assert!(!util.is_valid_data_type_name(""));
        assert!(!util.is_valid_data_type_name("   "));
        assert!(!util.is_valid_data_type_name("bad\u{0007}name"));
        assert!(util.is_valid_data_type_name("my_type_1"));
    }

    #[test]
    fn reconcile_applied_data_type_passes_through_default() {
        struct DefaultLike;
        impl DataType for DefaultLike {
            fn is_default_data_type(&self) -> bool {
                true
            }
        }

        let util = Util;
        let original: Arc<dyn DataType> = Arc::new(MockDataType {
            name: "orig".into(),
            length: 4,
            is_control_undefined: false,
        });
        let result = util.reconcile_applied_data_type(original, Box::new(DefaultLike), false);
        assert!(result.is_default_data_type());
    }

    #[test]
    fn reconcile_applied_data_type_returns_unchanged_when_not_stacking() {
        let util = Util;
        let original: Arc<dyn DataType> = Arc::new(MockDataType {
            name: "orig".into(),
            length: 4,
            is_control_undefined: false,
        });
        let new_dt = Box::new(MockDataType {
            name: "new".into(),
            length: 2,
            is_control_undefined: false,
        });
        let result = util.reconcile_applied_data_type(original, new_dt, false);
        assert_eq!(result.get_name(), "new");
    }

    #[test]
    fn is_undefined_ref_detects_undefined_type() {
        let dt = MockDataType {
            name: "undefined1".into(),
            length: 1,
            is_control_undefined: true,
        };
        assert!(is_undefined_ref(&dt));
    }

    #[test]
    fn is_undefined_ref_false_for_defined_type() {
        let dt = MockDataType {
            name: "int".into(),
            length: 4,
            is_control_undefined: false,
        };
        assert!(!is_undefined_ref(&dt));
    }

    #[test]
    fn is_data_clearing_denied_matches_clear_mode() {
        let undefined = MockDataType {
            name: "undefined1".into(),
            length: 1,
            is_control_undefined: true,
        };
        let defined = MockDataType {
            name: "int".into(),
            length: 4,
            is_control_undefined: false,
        };
        assert!(!is_data_clearing_denied(
            &undefined,
            ClearDataMode::ClearAllUndefinedConflictData
        ));
        assert!(is_data_clearing_denied(
            &defined,
            ClearDataMode::ClearAllUndefinedConflictData
        ));
        assert!(!is_data_clearing_denied(
            &defined,
            ClearDataMode::ClearAllConflictData
        ));
    }
}
