//! Port of `ghidra.program.model.data.UnionDataType`: the in-memory (non-database-backed)
//! `Union` implementation.
//!
//! [`UnionDataType`] is a concrete struct whose `Composite`/`Union`/`DataType` trait impls
//! delegate to the inherent `union_data_type_*` methods, which port the Java bodies one for one.
//! A union has no offset-based layout: every component sits at offset 0, the list index equals
//! the ordinal, and the union's length is the largest (bitfield-allocation-adjusted) component
//! length, aligned up when packing is enabled.
//!
//! Divergences from Java follow the same build-then-share convention as
//! [`StructureDataType`](super::structure_data_type::StructureDataType): no parent tracking or
//! change notification, the associated manager is recorded only as its data organization (so
//! inserted types are not `clone(dataMgr)`-rebound), data type identity is compared by path, and
//! `BadDataType` is represented by the local [`BadDataTypeStandIn`] until it is ported.

use crate::program::model::data::bit_field_data_type::{
    check_base_data_type, get_effective_bit_size, get_minimum_storage_size_no_offset, is_valid_base_data_type,
    BitFieldDataType,
};
use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::composite_alignment_helper;
use crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl;
use crate::program::model::data::built_in::shared_default_organization;
use crate::program::model::data::composite_internal::{
    stored_minimum_alignment_of, stored_packing_value_of, CompositeInternal, DEFAULT_ALIGNMENT, NO_PACKING,
};
use crate::program::model::data::undefined1_data_type::Undefined1DataType;
use crate::program::seam_stubs::share_data_type;
use crate::util::universal_id_generator::next_id;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::{DataType, SetDataTypeNameError, UnsupportedOperationError};
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_component_impl::DataTypeComponentImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::internal_data_type_component::InternalDataTypeComponent;
use crate::program::model::data::packing_type::PackingType;
use crate::program::model::data::alignment_type::AlignmentType;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::data::union::Union;
use crate::program::model::data::union_internal::UnionInternal;
use crate::program::model::mem::MemBuffer;
use crate::docking::settings::settings::Settings;
use crate::util::exception::DuplicateNameException;
use crate::util::UniversalID;
use std::collections::HashSet;
use std::sync::Arc;

/// Port of the relevant cases of `DataTypeUtilities.isSecondPartOfFirst(DataType, DataType)`, used
/// by [`union_data_type_check_ancestry`]. A near-duplicate of
/// [`structure_data_type::is_part_of_data_type_by_ref`](super::structure_data_type), which exists
/// separately in each module rather than being shared (it is a small private helper, not part of
/// either module's public surface) -- see that sibling's own doc comment for the identical
/// `Array`-case caveat (conservatively treated as "not part of").
fn is_part_of_data_type_by_ref(data_type: &dyn DataType, target: &dyn DataType) -> bool {
    if data_type.is_pointer() || target.is_pointer() {
        return false;
    }
    if crate::program::model::data::composite_internal::is_same_data_type_identity(data_type, target) {
        return true;
    }
    if data_type.is_typedef() {
        return match data_type.typedef_base_data_type() {
            Some(inner) => is_part_of_data_type_by_ref(inner.as_ref(), target),
            None => false,
        };
    }
    match data_type.as_composite() {
        Some(composite) => composite
            .get_defined_components()
            .into_iter()
            .any(|dtc| is_part_of_data_type_by_ref(dtc.get_data_type().as_ref(), target)),
        None => false,
    }
}

/// Port of `DataTypeComponentImpl.isUndefined()`'s test applied to a not-yet-wrapped data type
/// (`(dataType instanceof Dynamic dynamic) && dynamic.canSpecifyLength()`), used in place of
/// `dtc.isUndefined()` where only the data type is at hand. Identical to
/// [`structure_data_type::is_dynamic_with_specifiable_length`](super::structure_data_type), kept
/// as its own private copy for the same reason as [`is_part_of_data_type_by_ref`] above.
fn is_dynamic_with_specifiable_length(data_type: &dyn DataType) -> bool {
    data_type
        .as_dynamic()
        .map(|d| d.can_specify_length())
        .unwrap_or(false)
}

/// Port of the private `DataTypeUtilities.checkValidReplacementDataType(DataType)`, used by
/// [`check_valid_replacement`]. See
/// [`structure_data_type::check_valid_replacement_data_type`](super::structure_data_type)'s
/// identical sibling copy for why this isn't shared (small private helper, duplicated per-module
/// like [`is_part_of_data_type_by_ref`] above) and for the `DataTypeDB` early-return this crate
/// cannot yet recognize generically.
fn check_valid_replacement_data_type(data_type: &dyn DataType) -> Result<(), String> {
    if data_type.is_void_type() {
        return Err("IllegalArgumentException: Replacement data type may not be 'void' data type".to_string());
    }
    if data_type.is_default_data_type() {
        return Err(
            "IllegalArgumentException: Replacement data type may not be 'default' undefined data type".to_string(),
        );
    }
    if data_type.is_bit_field_type() {
        return Err(format!(
            "IllegalArgumentException: Replacement data type may not be a bitfield: {}",
            data_type.get_name()
        ));
    }
    if data_type.is_factory_type() {
        return Err(format!(
            "IllegalArgumentException: Replacement data type may not be a Factory data type: {}",
            data_type.get_name()
        ));
    }
    if data_type.is_dynamic_type() {
        return Err(format!(
            "IllegalArgumentException: Replacement data type may not be a Dynamic data type: {}",
            data_type.get_name()
        ));
    }
    Ok(())
}

/// Port of the private `DataTypeUtilities.checkForInvalidFunctionDefinitionReplacement(DataType,
/// DataType)`, used by [`check_valid_replacement`].
fn check_for_invalid_function_definition_replacement(
    replaced_dt: &dyn DataType,
    replacement_dt: &dyn DataType,
) -> Result<(), String> {
    let replaced_base_owned;
    let replaced_base: &dyn DataType = if replaced_dt.is_typedef() {
        replaced_base_owned = replaced_dt.typedef_base_data_type();
        replaced_base_owned.as_deref().unwrap_or(replaced_dt)
    } else {
        replaced_dt
    };
    let replacement_base_owned;
    let replacement_base: &dyn DataType = if replacement_dt.is_typedef() {
        replacement_base_owned = replacement_dt.typedef_base_data_type();
        replacement_base_owned.as_deref().unwrap_or(replacement_dt)
    } else {
        replacement_dt
    };

    if replaced_base.is_function_definition_type() {
        if !replacement_base.is_function_definition_type() {
            return Err(format!(
                "IllegalArgumentException: Existing function definition \"{}\" may not be replaced with \"{}\"",
                replaced_dt.get_name(),
                replacement_dt.get_name()
            ));
        }
    } else if replacement_base.is_function_definition_type() {
        return Err(format!(
            "IllegalArgumentException: Existing data type \"{}\" may not be replaced with function definition \"{}\"",
            replaced_dt.get_name(),
            replacement_dt.get_name()
        ));
    }
    Ok(())
}

/// Port of `DataTypeUtilities.checkValidReplacement(DataType, DataType)`, used by
/// [`UnionDataType::union_data_type_data_type_replaced`] ahead of (and, matching Java, unguarded
/// by the same try/catch as) the validate/clone/check-ancestry sequence that follows it.
fn check_valid_replacement(replaced_dt: &dyn DataType, replacement_dt: &dyn DataType) -> Result<(), String> {
    check_valid_replacement_data_type(replaced_dt)?;
    check_valid_replacement_data_type(replacement_dt)?;
    check_for_invalid_function_definition_replacement(replaced_dt, replacement_dt)
}

/// Local stand-in for Ghidra's `BadDataType.dataType` singleton, used by
/// [`UnionDataType::union_data_type_data_type_deleted`]. See
/// [`structure_data_type::BadDataTypeStandIn`](super::structure_data_type)'s identical sibling
/// copy (same reasoning: [`BadDataType`](super::bad_data_type::BadDataType) has no ready-made
/// concrete singleton in this crate) for why this minimal local type is enough -- a union
/// component's length is never resized on substitution (unlike a structure's, there is no offset
/// bookkeeping to preserve), so even this stand-in's exact `getLength()` value is immaterial here.
#[derive(Debug, Clone, Copy)]
struct BadDataTypeStandIn;

impl DataType for BadDataTypeStandIn {
    fn get_name(&self) -> String {
        "-BAD-".to_string()
    }
    fn get_length(&self) -> i32 {
        -1
    }
    fn get_description(&self) -> String {
        "** Bad Data Type **".to_string()
    }
}

fn bad_data_type_stand_in() -> Box<dyn DataType> {
    Box::new(BadDataTypeStandIn)
}


/// Basic (in-memory, non-database-backed) implementation of the union data type.
///
/// Port of `ghidra.program.model.data.UnionDataType`. See the module-level documentation for what
/// was ported, defaulted, and intentionally omitted (a work in progress; see the "porting
/// progress" note there).
///
/// NOTE: Implementation is not thread safe (matches the Java class's documented contract).
impl UnionDataType {
    /// The private `unionLength` field.
    fn stored_union_length(&self) -> i32 {
        self.union_length
    }

    /// Sets the private `unionLength` field.
    fn set_stored_union_length(&mut self, length: i32) {
        self.union_length = length;
    }

    /// The private `unionAlignment` field (`<= 0` when not yet computed).
    fn stored_union_alignment(&self) -> i32 {
        self.union_alignment
    }

    /// Sets the private `unionAlignment` field.
    fn set_stored_union_alignment(&mut self, alignment: i32) {
        self.union_alignment = alignment;
    }

    /// The private `components` field (`List<DataTypeComponentImpl>`), in ordinal order.
    fn components(&self) -> &Vec<DataTypeComponentImpl> {
        &self.components
    }

    /// Mutable access to the private `components` field.
    fn components_mut(&mut self) -> &mut Vec<DataTypeComponentImpl> {
        &mut self.components
    }

    /// Port of `UnionDataType.isZeroLength()`. Exposed under a distinct name since
    /// [`DataType::is_zero_length`] already provides a (placeholder) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn union_data_type_is_zero_length(&self) -> bool {
        self.stored_union_length() == 0
    }

    /// Port of `UnionDataType.getLength()`: a zero-length union reports a length of 1 since a
    /// defined data unit cannot have zero length. Exposed under a distinct name since
    /// [`DataType::get_length`] already provides a (placeholder) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn length(&self) -> i32 {
        let len = self.stored_union_length();
        if len == 0 {
            1
        } else {
            len
        }
    }

    /// Port of `UnionDataType.hasLanguageDependantLength()`: always `true` ("Assume any component
    /// may have a language-dependent length"). Exposed under a distinct name since
    /// [`CompositeDataTypeImpl::composite_impl_has_language_dependant_length`] is required
    /// (abstract in Java too) with no default of its own; a concrete implementation should
    /// delegate its answer to this.
    fn union_data_type_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Port of `UnionDataType.getRepresentation(MemBuffer, Settings, int)`. Exposed under a
    /// distinct name since [`DataType::get_representation`] already provides a (placeholder)
    /// default. A concrete `impl DataType for ...` should delegate to this.
    fn representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        if self.composite_impl_is_not_yet_defined() {
            "<Empty-Union>".to_string()
        } else {
            String::new()
        }
    }

    /// Port of `UnionDataType.getDefaultLabelPrefix()`. Exposed under a distinct name since
    /// [`DataType::get_default_label_prefix`] already provides a (placeholder, `None`) default. A
    /// concrete `impl DataType for ...` should delegate to this.
    fn default_label_prefix(&self) -> Option<String> {
        Some(format!("UNION_{}", self.get_name()))
    }

    /// Port of `UnionDataType.getNumComponents()`. Exposed under a distinct name since
    /// [`Composite::get_num_components`](crate::program::model::data::composite::Composite::get_num_components)
    /// already provides a (placeholder) default. A concrete `impl Composite for ...` should
    /// delegate to this.
    fn union_data_type_get_num_components(&self) -> i32 {
        self.components().len() as i32
    }

    /// Port of `UnionDataType.getNumDefinedComponents()`: identical to
    /// [`union_data_type_get_num_components`] in Java too (a union has no undefined filler
    /// components). Exposed under a distinct name since
    /// [`Composite::get_num_defined_components`](crate::program::model::data::composite::Composite::get_num_defined_components)
    /// already provides a (placeholder) default.
    fn union_data_type_get_num_defined_components(&self) -> i32 {
        self.union_data_type_get_num_components()
    }

    /// Port of `UnionDataType.getComponent(int)`: direct indexing, since a union's component list
    /// index always equals its ordinal (unlike [`StructureDataType`](super::structure_data_type::StructureDataType),
    /// no undefined filler synthesis or offset search is needed). Exposed under a distinct name
    /// since [`Composite::get_component`](crate::program::model::data::composite::Composite::get_component)
    /// already provides a (placeholder) default.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn union_data_type_get_component(&self, ordinal: i32) -> Result<DataTypeComponentImpl, String> {
        if ordinal < 0 || ordinal as usize >= self.components().len() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        Ok(self.components()[ordinal as usize].snapshot())
    }

    /// Port of `UnionDataType.getComponents()`/`getDefinedComponents()` (identical bodies in
    /// Java: `getDefinedComponents() { return getComponents(); }`). Exposed under a distinct name
    /// since [`Composite::get_components`](crate::program::model::data::composite::Composite::get_components)/
    /// [`Composite::get_defined_components`](crate::program::model::data::composite::Composite::get_defined_components)
    /// already provide (placeholder) defaults. A concrete `impl Composite for ...` should
    /// delegate both `get_components`/`get_defined_components` to this single method.
    fn union_data_type_get_components(&self) -> Vec<DataTypeComponentImpl> {
        self.components().iter().map(|dtc| dtc.snapshot()).collect()
    }

    /// Port of `DataTypeUtilities.checkAncestry(DataType, DataType)`, called as
    /// `checkAncestry(this, componentDataType)` throughout this trait's `add`/`insert`/
    /// `insertBitField`/`replaceWith` methods. Rejects `component_data_type` if adding it to this
    /// union would create a cyclic composite.
    ///
    /// # Errors
    /// Returns `Err` if `component_data_type` has this union within it (mirrors
    /// `DataTypeDependencyException`).
    fn union_data_type_check_ancestry(&self, component_data_type: &dyn DataType) -> Result<(), String> {
        if is_part_of_data_type_by_ref(component_data_type, self) {
            return Err(format!(
                "DataTypeDependencyException: Data type {} has {} within it.",
                component_data_type.get_display_name(),
                self.get_display_name()
            ));
        }
        Ok(())
    }

    /// Port of the private `UnionDataType.adjustBitField(DataType)`: normalizes a `BitFieldDataType`
    /// component so it always starts at bit-0 (lsb) of byte-0 for little-endian, or bit-7 (msb)
    /// of byte-0 for big-endian -- both aligned and non-packed unions use this same adjustment
    /// ("non-packed must force bitfield placement at byte offset 0"). Non-bitfield data types
    /// pass through unchanged.
    fn union_data_type_adjust_bit_field(&self, data_type: Box<dyn DataType>) -> Box<dyn DataType> {
        if !data_type.is_bit_field_type() {
            return data_type;
        }
        let extracted = {
            let bitfield = match data_type.as_bit_field_data_type() {
                Some(bf) => bf,
                None => return data_type,
            };
            (
                bitfield.get_base_data_type(),
                bitfield.get_declared_bit_size(),
                bitfield.get_bit_size(),
                bitfield.get_bit_offset(),
            )
        };
        let (base_data_type, declared_bit_size, existing_effective_bit_size, existing_bit_offset) = extracted;

        let effective_bit_size = get_effective_bit_size(declared_bit_size, base_data_type.get_length());

        let big_endian = self.get_data_organization().is_big_endian();
        let storage_bit_offset = if big_endian {
            if declared_bit_size == 0 {
                7
            } else {
                let storage_size = get_minimum_storage_size_no_offset(effective_bit_size);
                8 * storage_size - effective_bit_size
            }
        } else {
            0
        };

        if effective_bit_size != existing_effective_bit_size || storage_bit_offset != existing_bit_offset {
            match BitFieldDataType::new(base_data_type, effective_bit_size, storage_bit_offset) {
                Ok(new_bitfield) => Box::new(new_bitfield),
                // unexpected since deriving from existing bitfield; ignore and use existing bitfield
                Err(_) => data_type,
            }
        } else {
            data_type
        }
    }

    /// Port of the private `UnionDataType.shiftOrdinals(int, int)`, specialized to Union's
    /// always-`+1`/`-1` call sites (Java's general `deltaOrdinal` parameter is kept for fidelity
    /// even though every real caller below only ever passes `1` or `-1`).
    fn union_data_type_shift_ordinals(&mut self, ordinal: i32, delta_ordinal: i32) {
        for dtc in self.components_mut().iter_mut().skip(ordinal as usize) {
            dtc.set_ordinal(dtc.get_ordinal() + delta_ordinal);
        }
    }

    /// Port of the private `UnionDataType.doAdd(DataType, int, String, String)`. See the module
    /// docs for what is skipped (`dataType.clone(dataMgr)`, `data_type.addParent(self)`).
    ///
    /// # Errors
    /// Returns `Err` if a positive length cannot be determined for the specified data type
    /// (mirrors `IllegalArgumentException`), or if `data_type` would create a cyclic composite
    /// (mirrors `DataTypeDependencyException`).
    fn union_data_type_do_add(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        let data_type = self.composite_impl_validate_data_type(data_type)?;
        let data_type = self.union_data_type_adjust_bit_field(data_type);
        // dataType.clone(dataMgr): skipped, see module docs.
        self.union_data_type_check_ancestry(data_type.as_ref())?;

        let dynamic_specifiable = is_dynamic_with_specifiable_length(data_type.as_ref());
        let length = self.composite_impl_preferred_component_length_default(
            data_type.as_ref(),
            dynamic_specifiable,
            length,
        )?;

        let ordinal = self.components().len() as i32;
        let dtc = DataTypeComponentImpl::new(data_type, None, length, ordinal, 0, component_name, comment);
        // data_type.addParent(this): skipped, see module docs.
        self.components_mut().push(dtc);
        Ok(self.components().last().expect("just pushed").snapshot())
    }

    /// Port of `UnionDataType.add(DataType, int, String, String)`.
    ///
    /// # Errors
    /// See [`union_data_type_do_add`](UnionDataType::union_data_type_do_add).
    fn union_data_type_add(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        let old_alignment = self.union_data_type_alignment();
        let dtc = self.union_data_type_do_add(data_type, length, component_name, comment)?;
        if !self.union_data_type_repack(true)
            && self.is_packing_enabled()
            && old_alignment != self.union_data_type_alignment()
        {
            // notifyAlignmentChanged(): no-op, see module docs.
        }
        Ok(dtc)
    }

    /// Port of `UnionDataType.insert(int, DataType, int, String, String)`. See the module docs
    /// for what is skipped (`dataType.clone(dataMgr)`, `data_type.addParent(self)`). Unlike Java
    /// (which lets `components.add(ordinal, dtc)` throw `IndexOutOfBoundsException` only after
    /// doing all the validation/adjustment work), the ordinal bounds check happens first here --
    /// an intentional reordering with no externally observable difference beyond avoiding
    /// wasted work on an already-doomed call.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds, a positive length cannot be determined for
    /// the specified data type (mirrors `IndexOutOfBoundsException`/`IllegalArgumentException`),
    /// or `data_type` would create a cyclic composite (mirrors `DataTypeDependencyException`).
    fn union_data_type_insert(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        if ordinal < 0 || ordinal as usize > self.components().len() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }

        let data_type = self.composite_impl_validate_data_type(data_type)?;
        let old_alignment = self.union_data_type_alignment();
        let data_type = self.union_data_type_adjust_bit_field(data_type);
        // dataType.clone(dataMgr): skipped, see module docs.
        self.union_data_type_check_ancestry(data_type.as_ref())?;

        let dynamic_specifiable = is_dynamic_with_specifiable_length(data_type.as_ref());
        let length = self.composite_impl_preferred_component_length_default(
            data_type.as_ref(),
            dynamic_specifiable,
            length,
        )?;

        let dtc = DataTypeComponentImpl::new(data_type, None, length, ordinal, 0, component_name, comment);
        // data_type.addParent(this): skipped, see module docs.
        self.union_data_type_shift_ordinals(ordinal, 1);
        self.components_mut().insert(ordinal as usize, dtc);

        if !self.union_data_type_repack(true)
            && self.is_packing_enabled()
            && old_alignment != self.union_data_type_alignment()
        {
            // notifyAlignmentChanged(): no-op, see module docs.
        }
        Ok(self.components()[ordinal as usize].snapshot())
    }

    /// Port of `UnionDataType.addBitField(DataType, int, String, String)`.
    ///
    /// # Errors
    /// See [`union_data_type_insert_bit_field`](UnionDataType::union_data_type_insert_bit_field).
    fn union_data_type_add_bit_field(
        &mut self,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        let ordinal = self.components().len() as i32;
        self.union_data_type_insert_bit_field(ordinal, base_data_type, bit_size, component_name, comment)
    }

    /// Port of `UnionDataType.insertBitField(int, DataType, int, String, String)`. See the module
    /// docs for what is skipped (`baseDataType.clone(dataMgr)`).
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`), if
    /// `base_data_type` is not a valid bitfield base type (mirrors `InvalidDataTypeException`),
    /// or if a positive length cannot be determined (mirrors `IllegalArgumentException`).
    fn union_data_type_insert_bit_field(
        &mut self,
        ordinal: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        if ordinal < 0 || ordinal as usize > self.components().len() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        check_base_data_type(base_data_type.as_ref())
            .map_err(|e| format!("InvalidDataTypeException: {}", e.message()))?;
        // baseDataType.clone(dataMgr): skipped, see module docs.
        let bit_field_dt = BitFieldDataType::new_at_offset_zero(base_data_type, bit_size)
            .map_err(|e| format!("InvalidDataTypeException: {}", e.message()))?;
        let storage_size = bit_field_dt.get_storage_size();
        self.union_data_type_insert(ordinal, Box::new(bit_field_dt), storage_size, component_name, comment)
    }

    /// Port of the private `UnionDataType.getBitFieldAllocation(BitFieldDataType)`: the number of
    /// bytes a bitfield component contributes to the union's overall packed length, per the
    /// target compiler's bitfield packing convention.
    fn union_data_type_get_bit_field_allocation(&self, bitfield: &BitFieldDataType) -> i32 {
        let bit_field_packing = *self.get_data_organization().get_bit_field_packing();
        if bit_field_packing.use_ms_convention() {
            return bitfield.get_base_type_size();
        }
        if bitfield.get_bit_size() == 0 {
            return 0;
        }
        let mut length = bitfield.get_base_type_size();
        let packing = self.stored_packing_value();
        if packing > 0 && length > packing {
            length = crate::program::model::data::data_organization_impl::get_least_common_multiple(
                bitfield.get_storage_size(),
                packing,
            );
        }
        length
    }

    /// Port of `UnionDataType.getAlignment()`. Exposed under a distinct name since
    /// [`CompositeDataTypeImpl::composite_impl_alignment`] is required (abstract in Java too)
    /// with no default of its own; a concrete implementation should delegate its answer to this.
    ///
    /// Java's `getAlignment()` lazily computes **and caches** into the private `unionAlignment`
    /// field (`if (unionAlignment > 0) return unionAlignment; ...`). The required
    /// `composite_impl_alignment` this delta answers is declared `&self`-only, so it cannot write
    /// that cache itself; this method therefore only *reads* the cache (returning it immediately
    /// when positive, exactly like Java) and leaves *writing* it to
    /// [`union_data_type_repack`](UnionDataType::union_data_type_repack) (an `&mut self` method,
    /// which resets the field to a sentinel and stores the freshly computed value -- matching
    /// Java's `repack(boolean)` body exactly). Net effect: identical values to Java, just
    /// recomputed (harmlessly) more often before the first `repack` runs.
    fn union_data_type_alignment(&self) -> i32 {
        let cached = self.stored_union_alignment();
        if cached > 0 {
            return cached;
        }
        if self.is_packing_enabled() {
            let data_organization = self.get_data_organization();
            composite_alignment_helper::get_alignment(data_organization.as_ref(), self)
        } else {
            self.composite_impl_non_packed_alignment()
        }
    }

    /// Port of `UnionDataType.repack(boolean)`. Returns `true` if a layout change was detected.
    /// Unlike [`StructureDataType::structure_data_type_pack`](super::structure_data_type::StructureDataType::structure_data_type_pack),
    /// no `AlignedStructurePacker`-style helper trait is needed here: Java's `Union.repack` body
    /// is entirely self-contained (`unionLength = max over components of (bitfield-adjusted)
    /// length`, then aligned up via `DataOrganizationImpl.getAlignedOffset` when packing is
    /// enabled).
    fn union_data_type_repack(&mut self, notify: bool) -> bool {
        let old_length = self.stored_union_length();
        let old_alignment = self.union_data_type_alignment();

        let packing_enabled = self.is_packing_enabled();
        let mut new_length = 0i32;
        for dtc in self.components() {
            let mut length = dtc.get_length();
            if packing_enabled && dtc.is_bit_field_component() {
                let dt = dtc.get_data_type();
                if let Some(bitfield) = dt.as_bit_field_data_type() {
                    length = self.union_data_type_get_bit_field_allocation(bitfield);
                }
            }
            new_length = new_length.max(length);
        }
        self.set_stored_union_length(new_length);

        // force recompute of unionAlignment, matching Java's `unionAlignment = -1; getAlignment();`
        self.set_stored_union_alignment(-1);
        let new_alignment = self.union_data_type_alignment();
        self.set_stored_union_alignment(new_alignment);

        if packing_enabled {
            new_length = crate::program::model::data::data_organization_impl::get_aligned_offset(new_alignment, new_length);
            self.set_stored_union_length(new_length);
        }

        let changed = old_length != new_length || old_alignment != new_alignment;

        if changed && notify {
            // notifySizeChanged()/notifyAlignmentChanged(): no-op, see module docs.
        }
        changed
    }

    /// Port of `UnionDataType.isEquivalent(DataType)`. Java's `instanceof UnionInternal` test is
    /// [`DataType::as_union`]; the other union's stored packing/minimum alignment are recovered
    /// from its public API ([`stored_packing_value_of`]/[`stored_minimum_alignment_of`]).
    fn union_data_type_is_equivalent(&self, dt: &dyn DataType) -> bool {
        if std::ptr::addr_eq(dt as *const dyn DataType, self as *const Self) {
            return true;
        }
        let Some(other) = dt.as_union() else {
            return false;
        };
        if self.stored_packing_value() != stored_packing_value_of(other)
            || self.stored_minimum_alignment_value() != stored_minimum_alignment_of(other)
        {
            // rely on component match instead of checking length since dynamic component sizes
            // could affect length
            return false;
        }
        let other_components = other.get_components();
        if self.components().len() != other_components.len() {
            return false;
        }
        let packed = self.is_packing_enabled();
        self.components()
            .iter()
            .zip(other_components.iter())
            .all(|(mine, theirs)| mine.is_equivalent_within(theirs.as_ref(), packed))
    }

    /// Port of `UnionDataType.replaceWith(DataType)`: replaces this union's components with
    /// those of `dt` (which must be a union), including its packing and alignment settings.
    ///
    /// # Errors
    /// Returns `Err` if `dt` is not a union (Java's bare `IllegalArgumentException`) or a
    /// component data type would create a cyclic composite.
    fn union_data_type_replace_with(&mut self, dt: &dyn DataType) -> Result<(), String> {
        let Some(other) = dt.as_union() else {
            return Err("IllegalArgumentException".to_string());
        };
        self.components_mut().clear();
        self.set_stored_union_alignment(-1);

        self.set_stored_packing_value_raw(stored_packing_value_of(other));
        self.set_stored_minimum_alignment_value(stored_minimum_alignment_of(other));

        for dtc in other.get_components() {
            let dt = dtc.get_data_type();
            self.union_data_type_do_add(dt, dtc.get_length(), dtc.get_field_name(), dtc.get_comment())?;
        }

        self.union_data_type_repack(false);
        Ok(())
    }

    /// Port of `UnionDataType.delete(int)`.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn union_data_type_delete(&mut self, ordinal: i32) -> Result<(), String> {
        if ordinal < 0 || ordinal as usize >= self.components().len() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        let old_alignment = self.union_data_type_alignment();
        let removed = self.components_mut().remove(ordinal as usize);
        let _ = removed; // dtc.getDataType().removeParent(this): skipped, see module docs.
        self.union_data_type_shift_ordinals(ordinal, -1);

        if !self.union_data_type_repack(true)
            && self.is_packing_enabled()
            && old_alignment != self.union_data_type_alignment()
        {
            // notifyAlignmentChanged(): no-op, see module docs.
        }
        Ok(())
    }

    /// Port of `UnionDataType.delete(Set<Integer>)`.
    fn union_data_type_delete_set(&mut self, ordinals: &HashSet<i32>) -> Result<(), String> {
        if ordinals.is_empty() {
            return Ok(());
        }
        if ordinals.len() == 1 {
            let ordinal = *ordinals.iter().next().expect("len() == 1");
            return self.union_data_type_delete(ordinal);
        }

        let old_alignment = self.union_data_type_alignment();

        let old_components = std::mem::take(self.components_mut());
        let mut new_components = Vec::with_capacity(old_components.len());
        let mut new_length = 0i32;
        let mut ordinal_adjustment = 0i32;
        for mut dtc in old_components {
            let ordinal = dtc.get_ordinal();
            if ordinals.contains(&ordinal) {
                ordinal_adjustment -= 1;
                // dtc.getDataType().removeParent(this): skipped, see module docs.
            } else {
                if ordinal_adjustment != 0 {
                    dtc.set_ordinal(dtc.get_ordinal() + ordinal_adjustment);
                }
                new_length = new_length.max(dtc.get_length());
                new_components.push(dtc);
            }
        }
        *self.components_mut() = new_components;

        if self.is_packing_enabled() {
            if !self.union_data_type_repack(true) && old_alignment != self.union_data_type_alignment() {
                // notifyAlignmentChanged(): no-op, see module docs.
            }
        } else if self.stored_union_length() != new_length {
            self.set_stored_union_length(new_length);
            // notifySizeChanged(): no-op, see module docs.
        }
        Ok(())
    }

    /// Port of `UnionDataType.dataTypeSizeChanged(DataType)`: resize every component whose data
    /// type matches `dt`, then repack (falling back to a bare "must assume alignment changed"
    /// notification-shaped no-op when packing is enabled but `repack` itself reports no change --
    /// matching Java's `!repack(true) && isPackingEnabled()` guard).
    ///
    /// # Errors
    /// Returns `Err` if a positive preferred length cannot be determined for `dt` at some matching
    /// component (mirrors `IllegalArgumentException`, propagated unguarded exactly as Java leaves
    /// it uncaught).
    fn union_data_type_data_type_size_changed(&mut self, dt: &dyn DataType) -> Result<(), String> {
        if dt.is_bit_field_type() {
            return Ok(());
        }
        let target_path = dt.get_data_type_path();
        let is_dynamic = is_dynamic_with_specifiable_length(dt);
        let mut changed = false;
        let n = self.components().len();
        for i in 0..n {
            if self.components()[i].get_data_type().get_data_type_path() == target_path {
                let old_len = self.components()[i].get_length();
                let length = self.composite_impl_preferred_component_length_default(dt, is_dynamic, old_len)?;
                if length != old_len {
                    self.components_mut()[i].set_length(length);
                    changed = true;
                }
            }
        }
        if changed {
            let repacked = self.union_data_type_repack(true);
            if !repacked && self.is_packing_enabled() {
                // notifyAlignmentChanged(): no-op, see module docs.
            }
        }
        Ok(())
    }

    /// Port of `UnionDataType.dataTypeAlignmentChanged(DataType)`: only a packing-enabled union's
    /// layout can depend on a component's alignment, so this is a no-op otherwise.
    fn union_data_type_data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        if !self.is_packing_enabled() {
            return;
        }
        if dt.is_bit_field_type() {
            return;
        }
        let target_path = dt.get_data_type_path();
        let has_possible_change = self
            .components()
            .iter()
            .any(|dtc| dtc.get_data_type().get_data_type_path() == target_path);
        if has_possible_change {
            let repacked = self.union_data_type_repack(true);
            if !repacked && self.is_packing_enabled() {
                // notifyAlignmentChanged(): no-op, see module docs.
            }
        }
    }

    /// Port of the protected `CompositeDataTypeImpl.updateBitFieldDataType(DataTypeComponentImpl,
    /// DataType, DataType)`, specialized to operate directly on this union's own
    /// `Vec<DataTypeComponentImpl>` storage. See
    /// [`StructureDataType::structure_data_type_update_bit_field_data_type`](super::structure_data_type::StructureDataType::structure_data_type_update_bit_field_data_type)'s
    /// identical sibling copy for why this bypasses the object-unsafe
    /// [`CompositeDataTypeImpl::composite_impl_update_bit_field_data_type`] (still stubbed at
    /// `Ok(false)`) and for the `Arc`-based `new_dt` shape.
    ///
    /// # Errors
    /// Returns `Err` if the component at `index` is not actually a bit-field component (mirrors
    /// the Java `AssertException`), or if reconstructing the bitfield around the new base type
    /// fails (also mirrors an `AssertException`).
    fn union_data_type_update_bit_field_data_type(
        &mut self,
        index: usize,
        old_dt: &dyn DataType,
        new_dt: Option<&Arc<dyn DataType>>,
    ) -> Result<bool, String> {
        if !self.components()[index].is_bit_field_component() {
            return Err("AssertException: expected bitfield component".to_string());
        }
        let Some(new_dt) = new_dt else {
            return Ok(false);
        };
        if !is_valid_base_data_type(new_dt.as_ref()) {
            return Ok(false);
        }
        let (base_path, declared_bit_size, bit_offset, bit_size) = {
            let dt = self.components()[index].get_data_type();
            let bitfield = dt
                .as_bit_field_data_type()
                .expect("is_bit_field_component() implies as_bit_field_data_type() returns Some");
            (
                bitfield.get_base_data_type().get_data_type_path(),
                bitfield.get_declared_bit_size(),
                bitfield.get_bit_offset(),
                bitfield.get_bit_size(),
            )
        };
        if base_path != old_dt.get_data_type_path() {
            return Ok(false);
        }
        let max_bit_size = 8 * new_dt.get_length();
        if bit_size > max_bit_size {
            return Ok(false);
        }
        let new_bitfield =
            BitFieldDataType::new(crate::program::seam_stubs::share_data_type(new_dt), declared_bit_size, bit_offset)
                .map_err(|e| format!("AssertException: {}", e.message()))?;
        self.components_mut()[index].set_data_type(Box::new(new_bitfield));
        // oldDt.removeParent(this)/newDt.addParent(this): no-op, see module docs.
        Ok(true)
    }

    /// Port of `UnionDataType.dataTypeDeleted(DataType)`. See the module docs for what is skipped:
    /// the bitfield-base-type-deleted "revert to primitive type" case (same reason
    /// [`StructureDataType::structure_data_type_data_type_deleted`](super::structure_data_type::StructureDataType::structure_data_type_data_type_deleted)
    /// skips it: `BitFieldDataType.getPrimitiveBaseDataType()` is not yet ported).
    fn union_data_type_data_type_deleted(&mut self, dt: &dyn DataType) {
        let target_path = dt.get_data_type_path();
        let mut changed = false;
        let n = self.components().len();
        for i in (0..n).rev() {
            if self.components()[i].is_bit_field_component() {
                // Do not allow bitfield to be destroyed: if its base type is removed, revert to
                // the primitive integer type.
                let primitive = {
                    let bitfield = self.components()[i]
                        .data_type_arc()
                        .as_bit_field_data_type()
                        .expect("is_bit_field_component() implies a BitFieldDataType");
                    (bitfield.referenced_base_data_type().get_data_type_path() == target_path)
                        .then(|| bitfield.get_primitive_base_data_type())
                };
                if let Some(primitive) = primitive {
                    if let Ok(true) = self.union_data_type_update_bit_field_data_type(i, dt, Some(&primitive)) {
                        changed = true;
                    }
                }
            } else if self.components()[i].get_data_type().get_data_type_path() == target_path {
                self.components_mut()[i].set_data_type(bad_data_type_stand_in());
                changed = true;
            }
        }
        if changed && self.is_packing_enabled() {
            let repacked = self.union_data_type_repack(true);
            if !repacked {
                // notifyAlignmentChanged(): no-op, see module docs.
            }
        }
    }

    /// Port of `UnionDataType.dataTypeReplaced(DataType, DataType)`. Exposed taking an owned
    /// `new_dt: Box<dyn DataType>` for the identical reason
    /// [`StructureDataType::structure_data_type_data_type_replaced`](super::structure_data_type::StructureDataType::structure_data_type_data_type_replaced)'s
    /// own doc comment gives (needs to *store* the replacement, which a borrowed `&dyn DataType`
    /// cannot generically be turned into without a `Clone` bound on [`DataType`]); like that
    /// sibling, `UnionDataType` therefore leaves `DataType::data_type_replaced` at its
    /// inherited placeholder default.
    ///
    /// NOTE: matches Java verbatim on one subtle point -- the non-bitfield branch's replacement
    /// *length* (`getPreferredComponentLength(newDt, dtc.getLength())`) is derived from the
    /// original `new_dt` parameter, not from `replacement_dt` (the post-validation/ancestry-checked
    /// value actually stored into the component just after). This looks like a latent quirk in the
    /// original Java (see `UnionDataType.dataTypeReplaced`'s own body), ported as-is per this
    /// crate's faithful-porting policy rather than "fixed".
    ///
    /// See the module docs for what is skipped (`dataType.clone(dataMgr)`, parent-notification
    /// wiring).
    ///
    /// # Errors
    /// Returns `Err` if `old_dt`/`new_dt` fail `DataTypeUtilities.checkValidReplacement`'s checks
    /// (mirrors `IllegalArgumentException`, and matching Java, *not* subject to the fallback the
    /// validate/ancestry-check sequence below gets), or if
    /// [`union_data_type_update_bit_field_data_type`](UnionDataType::union_data_type_update_bit_field_data_type)
    /// fails for some matching bitfield component, or if the preferred-length computation for the
    /// original `new_dt` fails for some matching non-bitfield component.
    fn union_data_type_data_type_replaced(
        &mut self,
        old_dt: &dyn DataType,
        new_dt: Box<dyn DataType>,
    ) -> Result<(), String> {
        check_valid_replacement(old_dt, new_dt.as_ref())?;

        let new_dt_arc: Arc<dyn DataType> = Arc::from(new_dt);

        let replacement_dt: Box<dyn DataType> = {
            let candidate = crate::program::seam_stubs::share_data_type(&new_dt_arc);
            let validated = self.composite_impl_validate_data_type(candidate);
            // replacementDt.clone(dataMgr): skipped, see module docs.
            let checked = validated.and_then(|dt| {
                self.union_data_type_check_ancestry(dt.as_ref())?;
                Ok(dt)
            });
            match checked {
                Ok(dt) => dt,
                Err(_) => share_data_type(&Undefined1DataType::data_type()),
            }
        };
        let replacement_arc: Arc<dyn DataType> = Arc::from(replacement_dt);

        let old_path = old_dt.get_data_type_path();
        let mut changed = false;
        let n = self.components().len();
        for i in (0..n).rev() {
            if self.components()[i].is_bit_field_component() {
                if self.union_data_type_update_bit_field_data_type(i, old_dt, Some(&replacement_arc))? {
                    changed = true;
                }
            } else if self.components()[i].get_data_type().get_data_type_path() == old_path {
                let old_len = self.components()[i].get_length();
                let is_dynamic_new = is_dynamic_with_specifiable_length(new_dt_arc.as_ref());
                let len = self.composite_impl_preferred_component_length_default(
                    new_dt_arc.as_ref(),
                    is_dynamic_new,
                    old_len,
                )?;
                // oldDt.removeParent(this)/replacementDt.addParent(this): no-op, see module docs.
                self.components_mut()[i].set_length(len);
                self.components_mut()[i].set_data_type(crate::program::seam_stubs::share_data_type(&replacement_arc));
                self.components_mut()[i].invalidate_settings();
                changed = true;
            }
        }
        if changed {
            self.union_data_type_repack(false);
            // notifySizeChanged(): no-op, see module docs.
        }
        Ok(())
    }
}

/// Port of `DataUtilities.isValidDataTypeName(String)`'s check as applied by the
/// `GenericDataType` constructor chain (`UnionDataType`'s Java superclass), used by
/// [`UnionDataType::new_in_category`]. See
/// [`structure_data_type`](super::structure_data_type)'s identical local duplicate for why this
/// isn't shared from `composite_data_type_impl::check_valid_name` (private to its own module, and
/// used for a different, checked-exception-returning call site).
fn is_valid_union_name(name: &str) -> bool {
    !name.trim().is_empty() && !name.chars().any(|c| c.is_control())
}

/// Basic in-memory (non-database-backed) implementation of a union data type.
///
/// Port of `ghidra.program.model.data.UnionDataType`. Follows the same build-then-share
/// convention as [`StructureDataType`](super::structure_data_type::StructureDataType): an owned
/// value edited through `&mut self`; components handed out carry a parent snapshot; the
/// associated manager is recorded only as its data organization.
pub struct UnionDataType {
    category_path: CategoryPath,
    name: String,
    description: Option<String>,
    data_organization: Option<Arc<DataOrganizationImpl>>,
    minimum_alignment_value: i32,
    packing_value: i32,
    union_length: i32,
    union_alignment: i32,
    components: Vec<DataTypeComponentImpl>,
    universal_id: UniversalID,
    source_archive_id: Option<UniversalID>,
    last_change_time: i64,
    last_change_time_in_source_archive: i64,
}

/// Transitional name for [`UnionDataType`].
#[deprecated(note = "renamed to UnionDataType")]
pub type UnionDataTypeImpl = UnionDataType;

impl Clone for UnionDataType {
    /// A value copy with the same identity, sharing component data types with the original.
    fn clone(&self) -> Self {
        UnionDataType {
            category_path: self.category_path.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            data_organization: self.data_organization.clone(),
            minimum_alignment_value: self.minimum_alignment_value,
            packing_value: self.packing_value,
            union_length: self.union_length,
            union_alignment: self.union_alignment,
            components: self.components.iter().map(DataTypeComponentImpl::snapshot).collect(),
            universal_id: self.universal_id,
            source_archive_id: self.source_archive_id,
            last_change_time: self.last_change_time,
            last_change_time_in_source_archive: self.last_change_time_in_source_archive,
        }
    }
}

impl std::fmt::Debug for UnionDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::program::model::data::composite_internal::to_string(self))
    }
}

impl UnionDataType {
    /// Construct a new empty union with the given name. The root category is used.
    ///
    /// Port of `UnionDataType(String)`.
    ///
    /// # Panics
    /// Panics (Java: `IllegalArgumentException`) if `name` is not a valid data-type name.
    pub fn new(name: impl Into<String>) -> Self {
        Self::new_in_category(ROOT.clone(), name)
    }

    /// Construct a new empty union with the given name within the specified category.
    ///
    /// Port of `UnionDataType(CategoryPath, String)`.
    ///
    /// # Panics
    /// See [`new`](Self::new).
    pub fn new_in_category(category_path: CategoryPath, name: impl Into<String>) -> Self {
        Self::with_manager(category_path, name, None)
    }

    /// Port of `UnionDataType(CategoryPath, String, DataTypeManager)`: the manager's data
    /// organization governs packing, alignment and endianness.
    ///
    /// # Panics
    /// See [`new`](Self::new).
    pub fn with_manager(category_path: CategoryPath, name: impl Into<String>, dtm: Option<&dyn DataTypeManager>) -> Self {
        let name = name.into();
        if !is_valid_union_name(&name) {
            panic!("IllegalArgumentException: Invalid DataType name: {name}");
        }
        UnionDataType {
            category_path,
            name,
            description: None,
            data_organization: dtm.map(|dtm| dtm.get_data_organization()),
            minimum_alignment_value: DEFAULT_ALIGNMENT,
            packing_value: NO_PACKING,
            union_length: 0,
            union_alignment: 0,
            components: Vec::new(),
            universal_id: next_id(),
            source_archive_id: None,
            last_change_time: 0,
            last_change_time_in_source_archive: 0,
        }
    }

    /// Construct a new empty union with an explicit archive identity.
    ///
    /// Port of the constructor taking `universalID`/`sourceArchive`/`lastChangeTime`/
    /// `lastChangeTimeInSourceArchive`/`dtm`. `source_archive` is tracked only by ID.
    ///
    /// # Panics
    /// See [`new`](Self::new).
    #[allow(clippy::too_many_arguments)]
    pub fn with_archive_identity(
        category_path: CategoryPath,
        name: impl Into<String>,
        universal_id: UniversalID,
        source_archive: Option<&dyn SourceArchive>,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
        dtm: Option<&dyn DataTypeManager>,
    ) -> Self {
        let mut u = Self::with_manager(category_path, name, dtm);
        u.universal_id = universal_id;
        u.source_archive_id = source_archive.map(|a| a.source_archive_id());
        u.last_change_time = last_change_time;
        u.last_change_time_in_source_archive = last_change_time_in_source_archive;
        u
    }

    /// Port of `UnionDataType.replaceWith(DataType)` returning the error Java throws.
    ///
    /// # Errors
    /// See [`DataType::replace_with`].
    pub fn try_replace_with(&mut self, data_type: &dyn DataType) -> Result<(), String> {
        self.union_data_type_replace_with(data_type)
    }

    /// Port of `UnionDataType.dataTypeReplaced(DataType, DataType)` with an owned replacement.
    ///
    /// # Errors
    /// Returns `Err` if `old_dt`/`new_dt` fail `DataTypeUtilities.checkValidReplacement`.
    pub fn replace_data_type(&mut self, old_dt: &dyn DataType, new_dt: Arc<dyn DataType>) -> Result<(), String> {
        self.union_data_type_data_type_replaced(old_dt, share_data_type(&new_dt))
    }

    /// A snapshot of this union, used as the parent of the components handed out by one call.
    fn parent_snapshot(&self) -> Arc<dyn CompositeDataTypeImpl> {
        Arc::new(self.clone())
    }

    /// A component handed out through the public API, with this union as its parent.
    fn handed_out(&self, dtc: DataTypeComponentImpl) -> Box<dyn DataTypeComponent> {
        Box::new(dtc.with_parent(Some(self.parent_snapshot())))
    }

    /// Several components handed out by one call, sharing one parent snapshot.
    fn handed_out_all(&self, components: Vec<DataTypeComponentImpl>) -> Vec<Box<dyn DataTypeComponent>> {
        let parent = self.parent_snapshot();
        components
            .into_iter()
            .map(|dtc| Box::new(dtc.with_parent(Some(parent.clone()))) as Box<dyn DataTypeComponent>)
            .collect()
    }
}

impl DataType for UnionDataType {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn set_name(&mut self, name: &str) -> Result<(), SetDataTypeNameError> {
        self.composite_impl_set_name(name)?;
        Ok(())
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        self.category_path = path;
        Ok(())
    }

    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        self.data_organization.clone().unwrap_or_else(shared_default_organization)
    }

    fn get_mnemonic(&self, settings: &dyn Settings) -> String {
        self.composite_impl_mnemonic(settings)
    }

    fn get_length(&self) -> i32 {
        UnionDataType::length(self)
    }

    /// Java `CompositeDataTypeImpl.getAlignedLength()` is final and returns `getLength()`.
    fn get_aligned_length(&self) -> i32 {
        UnionDataType::length(self)
    }

    fn get_universal_id(&self) -> UniversalID {
        self.universal_id
    }

    fn get_last_change_time(&self) -> i64 {
        self.last_change_time
    }

    fn set_last_change_time(&mut self, last_change_time: i64) {
        self.last_change_time = last_change_time;
    }

    fn get_last_change_time_in_source_archive(&self) -> i64 {
        self.last_change_time_in_source_archive
    }

    fn set_last_change_time_in_source_archive(&mut self, last_change_time_in_source_archive: i64) {
        self.last_change_time_in_source_archive = last_change_time_in_source_archive;
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        self.union_data_type_is_equivalent(dt)
    }

    /// Port of `UnionDataType.replaceWith(DataType)`.
    ///
    /// # Panics
    /// Panics (Java throws `IllegalArgumentException`) if `data_type` is not a union or contains
    /// this union; [`UnionDataType::try_replace_with`] returns the error instead.
    fn replace_with(&mut self, data_type: &dyn DataType) {
        if let Err(e) = self.union_data_type_replace_with(data_type) {
            panic!("{e}");
        }
    }

    fn runtime_class(&self) -> Option<std::any::TypeId> {
        Some(std::any::TypeId::of::<UnionDataType>())
    }

    fn as_composite_mut(&mut self) -> Option<&mut dyn Composite> {
        Some(self)
    }

    fn is_zero_length(&self) -> bool {
        self.union_data_type_is_zero_length()
    }

    fn has_language_dependant_length(&self) -> bool {
        self.union_data_type_has_language_dependant_length()
    }

    fn get_alignment(&self) -> i32 {
        self.composite_impl_alignment()
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        UnionDataType::representation(self, buf, settings, length)
    }

    fn get_default_label_prefix(&self) -> Option<String> {
        UnionDataType::default_label_prefix(self)
    }

    fn get_description(&self) -> String {
        self.composite_impl_description()
    }

    fn set_description(&mut self, description: &str) -> Result<(), UnsupportedOperationError> {
        self.composite_impl_set_description(Some(description));
        Ok(())
    }

    fn is_not_yet_defined(&self) -> bool {
        self.composite_impl_is_not_yet_defined()
    }

    fn is_union(&self) -> bool {
        true
    }

    fn as_composite(&self) -> Option<&dyn Composite> {
        Some(self)
    }

    fn as_union(&self) -> Option<&dyn crate::program::model::data::union::Union> {
        Some(self)
    }

    /// Stands in for `(Composite) this` where the caller needs to *consume* ownership rather
    /// than merely borrow (see [`DataType::into_composite`]'s own doc comment). Added for
    /// [`DataTypeWriter`](crate::program::model::data::data_type_writer::DataTypeWriter)'s port
    /// of `doWrite`, which needs to convert an owned `Box<dyn DataType>` known (via
    /// [`as_union`](Self::as_union)) to be a `Union` into an owned `Box<dyn Composite>` for its
    /// dependency-graph bookkeeping, without cloning the underlying data.
    fn into_composite(self: Box<Self>) -> Option<Box<dyn Composite>> {
        Some(self)
    }

    /// Port of `CompositeDataTypeImpl.copy(DataTypeManager)` as inherited by `UnionDataType`:
    /// constructs a brand-new `UnionDataType` (new identity, no source archive) and
    /// repopulates it from `self` via
    /// [`union_data_type_replace_with`](UnionDataType::union_data_type_replace_with).
    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let mut copy = UnionDataType::with_manager(self.get_category_path(), self.get_name(), Some(dtm));
        copy.composite_impl_set_description(Some(&self.get_description()));
        copy.union_data_type_replace_with(self)
            .expect("replaceWith from a well-formed UnionDataType cannot fail");
        Box::new(copy)
    }

    /// Port of `UnionDataType.clone(DataTypeManager)`: like [`copy_data_type`](Self::copy_data_type)
    /// but preserves this union's archive identity on the clone. Java short-circuits and returns
    /// `this` when `dataMgr == dataMgr`; since `dataMgr` is not tracked here at all (see the
    /// struct docs), that identity check can never apply and this always produces a fresh clone.
    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(self.clone_union_impl(Some(dtm)))
    }

    /// Port of `UnionDataType.dataTypeSizeChanged(DataType)`. See
    /// [`union_data_type_data_type_size_changed`](UnionDataType::union_data_type_data_type_size_changed)'s
    /// own doc comment for the ported algorithm; a genuinely invalid preferred length (mirroring
    /// Java's uncaught `IllegalArgumentException`) is treated here as "nothing to do" rather than
    /// panicking, since this override's signature has no `Result` to propagate through.
    fn data_type_size_changed(&mut self, dt: &dyn DataType) {
        let _ = self.union_data_type_data_type_size_changed(dt);
    }

    /// Port of `UnionDataType.dataTypeAlignmentChanged(DataType)`.
    fn data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        self.union_data_type_data_type_alignment_changed(dt);
    }

    /// Port of `UnionDataType.dataTypeDeleted(DataType)`. See
    /// [`union_data_type_data_type_deleted`](UnionDataType::union_data_type_data_type_deleted)'s
    /// own doc comment for what is skipped (the bitfield-base-type-deleted revert case).
    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        self.union_data_type_data_type_deleted(dt);
    }

    // `data_type_replaced` is intentionally left at its inherited placeholder default: see
    // `union_data_type_data_type_replaced`'s own doc comment for why it cannot be reached
    // generically from this override's borrowed `new_dt: &dyn DataType`.
}

impl UnionDataType {
    /// Shared body for [`DataType::clone_data_type`] and [`Union::clone_union`] (which differ only
    /// in return type: `Box<dyn DataType>` vs `Box<dyn Union>`).
    fn clone_union_impl(&self, dtm: Option<&dyn DataTypeManager>) -> UnionDataType {
        let mut clone = UnionDataType::with_archive_identity(
            self.get_category_path(),
            self.get_name(),
            self.universal_id,
            None,
            self.last_change_time,
            self.last_change_time_in_source_archive,
            dtm,
        );
        clone.source_archive_id = self.source_archive_id;
        clone.composite_impl_set_description(Some(&self.get_description()));
        clone
            .union_data_type_replace_with(self)
            .expect("replaceWith from a well-formed UnionDataType cannot fail");
        clone
    }
}

impl Composite for UnionDataType {
    fn get_num_components(&self) -> i32 {
        self.union_data_type_get_num_components()
    }

    fn get_num_defined_components(&self) -> i32 {
        self.union_data_type_get_num_defined_components()
    }

    fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_data_type_get_component(ordinal)
            .map(|c| self.handed_out(c))
    }

    fn get_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        self.handed_out_all(self.union_data_type_get_components())
    }

    fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        self.handed_out_all(self.union_data_type_get_components())
    }

    fn add(&mut self, data_type: Box<dyn DataType>) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_add(data_type)
    }

    fn add_with_length(&mut self, data_type: Box<dyn DataType>, length: i32) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_add_with_length(data_type, length)
    }

    fn add_with_name(
        &mut self,
        data_type: Box<dyn DataType>,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_add_with_name(data_type, component_name, comment)
    }

    fn add_with_length_and_name(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_add_with_length_and_name(data_type, length, component_name, comment)
    }

    fn add_bit_field(
        &mut self,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_data_type_add_bit_field(base_data_type, bit_size, component_name, comment)
            .map(|c| self.handed_out(c))
    }

    fn insert(&mut self, ordinal: i32, data_type: Box<dyn DataType>) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_insert(ordinal, data_type)
    }

    fn insert_with_length(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_insert_with_length(ordinal, data_type, length)
    }

    fn insert_with_length_and_name(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.composite_impl_insert_with_length_and_name(ordinal, data_type, length, component_name, comment)
    }

    fn delete(&mut self, ordinal: i32) -> Result<(), String> {
        self.union_data_type_delete(ordinal)
    }

    fn delete_set(&mut self, ordinals: &HashSet<i32>) -> Result<(), String> {
        self.union_data_type_delete_set(ordinals)
    }

    fn is_part_of(&self, data_type: &dyn DataType) -> bool {
        self.composite_impl_is_part_of(data_type)
    }

    fn repack(&mut self) {
        self.composite_impl_repack();
    }

    fn get_packing_type(&self) -> PackingType {
        self.composite_impl_packing_type()
    }

    fn set_packing_enabled(&mut self, enabled: bool) {
        self.composite_impl_set_packing_enabled(enabled);
    }

    fn set_to_default_packing(&mut self) {
        self.composite_impl_set_to_default_packing();
    }

    fn get_explicit_packing_value(&self) -> i32 {
        self.composite_impl_explicit_packing_value()
    }

    fn set_explicit_packing_value(&mut self, packing_value: i32) -> Result<(), String> {
        self.composite_impl_set_explicit_packing_value(packing_value)
    }

    fn pack(&mut self, packing_value: i32) -> Result<(), String> {
        self.composite_impl_set_explicit_packing_value(packing_value)
    }

    fn get_alignment_type(&self) -> AlignmentType {
        self.composite_impl_alignment_type()
    }

    fn set_to_default_aligned(&mut self) {
        self.composite_impl_set_to_default_aligned();
    }

    fn set_to_machine_aligned(&mut self) {
        self.composite_impl_set_to_machine_aligned();
    }

    fn get_explicit_minimum_alignment(&self) -> i32 {
        self.composite_impl_explicit_minimum_alignment()
    }

    fn set_explicit_minimum_alignment(&mut self, minimum_alignment: i32) -> Result<(), String> {
        self.composite_impl_set_explicit_minimum_alignment(minimum_alignment)
    }
}

impl CompositeInternal for UnionDataType {
    fn get_stored_packing_value(&self) -> i32 {
        self.composite_impl_stored_packing_value()
    }

    fn get_stored_minimum_alignment(&self) -> i32 {
        self.composite_impl_stored_minimum_alignment()
    }
}

impl Union for UnionDataType {
    fn clone_union(&self, dtm: &dyn DataTypeManager) -> Box<dyn Union> {
        Box::new(self.clone_union_impl(Some(dtm)))
    }

    fn insert_bit_field(
        &mut self,
        ordinal: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_data_type_insert_bit_field(ordinal, base_data_type, bit_size, component_name, comment)
            .map(|c| self.handed_out(c))
    }
}

impl UnionInternal for UnionDataType {}

impl CompositeDataTypeImpl for UnionDataType {
    fn stored_description(&self) -> String {
        self.description.clone().unwrap_or_default()
    }

    fn set_stored_description(&mut self, description: String) {
        self.description = if description.is_empty() { None } else { Some(description) };
    }

    fn stored_minimum_alignment_value(&self) -> i32 {
        self.minimum_alignment_value
    }

    fn set_stored_minimum_alignment_value(&mut self, minimum_alignment: i32) {
        self.minimum_alignment_value = minimum_alignment;
    }

    fn stored_packing_value(&self) -> i32 {
        self.packing_value
    }

    fn set_stored_packing_value_raw(&mut self, packing: i32) {
        self.packing_value = packing;
    }

    fn set_stored_name(&mut self, name: String) {
        self.name = name;
    }

    fn composite_impl_has_language_dependant_length(&self) -> bool {
        self.union_data_type_has_language_dependant_length()
    }

    fn repack_with_notify(&mut self, notify: bool) -> bool {
        self.union_data_type_repack(notify)
    }

    fn composite_impl_alignment(&self) -> i32 {
        self.union_data_type_alignment()
    }

    fn for_each_defined_component(&self, consumer: &mut dyn FnMut(&dyn DataTypeComponent)) {
        for dtc in &self.components {
            consumer(dtc);
        }
    }

    fn composite_impl_add_with_length_and_name(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_data_type_add(data_type, length, field_name, comment)
            .map(|c| self.handed_out(c))
    }

    fn composite_impl_insert_with_length_and_name(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_data_type_insert(ordinal, data_type, length, field_name, comment)
            .map(|c| self.handed_out(c))
    }

    /// Port of `CompositeDataTypeImpl.validateDataType(DataType)`: in a union `DataType.DEFAULT`
    /// always becomes `Undefined1DataType`; factory types and types without a positive length are
    /// rejected.
    fn composite_impl_validate_data_type(&self, data_type: Box<dyn DataType>) -> Result<Box<dyn DataType>, String> {
        if data_type.is_default_data_type() {
            return Ok(share_data_type(&Undefined1DataType::data_type()));
        }
        if let Some(dynamic) = data_type.as_dynamic() {
            if !dynamic.can_specify_length() {
                return Err(format!(
                    "IllegalArgumentException: The \"{}\" data type is not allowed in a composite data type.",
                    data_type.get_name()
                ));
            }
        } else if data_type.is_factory_type() || data_type.get_length() <= 0 {
            return Err(format!(
                "IllegalArgumentException: The \"{}\" data type is not allowed in a composite data type.",
                data_type.get_name()
            ));
        }
        Ok(data_type)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::composite_internal::CompositeInternal;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::packing_type::PackingType;

    fn sample() -> UnionDataType {
        UnionDataType::new("MyUnion")
    }

    fn byte_data_type(name: &str, length: i32) -> Box<dyn DataType> {
        struct SimpleDataType {
            name: String,
            length: i32,
        }
        impl DataType for SimpleDataType {
            fn get_name(&self) -> String {
                self.name.clone()
            }
            fn get_length(&self) -> i32 {
                self.length
            }
            fn get_alignment(&self) -> i32 {
                self.length.max(1)
            }
            fn is_equivalent(&self, dt: &dyn DataType) -> bool {
                self.name == dt.get_name() && self.length == dt.get_length()
            }
        }
        Box::new(SimpleDataType {
            name: name.to_string(),
            length,
        })
    }

    /// Valid bitfield base type (unlike [`byte_data_type`], which does not report
    /// `is_integer_type()`): a minimal signed integer stand-in accepted by
    /// [`check_base_data_type`].
    fn int_data_type(name: &str, length: i32) -> Box<dyn DataType> {
        struct IntDataType {
            name: String,
            length: i32,
        }
        impl DataType for IntDataType {
            fn get_name(&self) -> String {
                self.name.clone()
            }
            fn get_length(&self) -> i32 {
                self.length
            }
            fn get_alignment(&self) -> i32 {
                self.length
            }
            fn is_integer_type(&self) -> bool {
                true
            }
            fn is_signed_integer_type(&self) -> bool {
                true
            }
        }
        Box::new(IntDataType {
            name: name.to_string(),
            length,
        })
    }

    #[test]
    fn zero_length_union_reports_length_one_and_empty_representation() {
        let u = sample();
        assert!(u.union_data_type_is_zero_length());
        assert_eq!(u.length(), 1);
        assert_eq!(u.representation(&MockBuf, &MockSettings, 0), "<Empty-Union>");
    }

    #[test]
    fn defined_union_reports_stored_length_and_blank_representation() {
        let mut u = sample();
        u.set_stored_union_length(4);
        u.components_mut().push(DataTypeComponentImpl::new(byte_data_type("dword", 4), None, 4, 0, 0, None, None));
        assert!(!u.union_data_type_is_zero_length());
        assert_eq!(u.length(), 4);
        assert_eq!(u.representation(&MockBuf, &MockSettings, 4), "");
    }

    #[test]
    fn has_language_dependant_length_is_always_true() {
        let u = sample();
        assert!(u.union_data_type_has_language_dependant_length());
    }

    #[test]
    fn default_label_prefix_uses_union_prefixed_name() {
        let u = sample();
        assert_eq!(u.default_label_prefix(), Some("UNION_MyUnion".to_string()));
    }

    #[test]
    fn get_component_rejects_out_of_bounds_ordinal() {
        let u = sample();
        assert!(u.union_data_type_get_component(0).is_err());
    }

    #[test]
    fn get_component_and_get_components_reflect_manually_seeded_state() {
        let mut u = sample();
        u.components_mut().push(DataTypeComponentImpl::new(byte_data_type("byte", 1), None, 1, 0, 0, None, None));
        u.components_mut().push(DataTypeComponentImpl::new(byte_data_type("dword", 4), None, 4, 1, 0, None, None));

        assert_eq!(u.union_data_type_get_num_components(), 2);
        assert_eq!(u.union_data_type_get_num_defined_components(), 2);

        let c0 = u.union_data_type_get_component(0).unwrap();
        assert_eq!(c0.get_data_type_name(), "byte");
        assert_eq!(c0.get_offset(), 0);

        let all = u.union_data_type_get_components();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].get_data_type_name(), "dword");
    }

    #[test]
    fn check_ancestry_rejects_cyclic_component() {
        let u = sample();
        let dyn_self: &dyn DataType = &u as &dyn DataType;
        assert!(is_part_of_data_type_by_ref(dyn_self, dyn_self));
        let result = u.union_data_type_check_ancestry(dyn_self);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DataTypeDependencyException"));
    }

    #[test]
    fn check_ancestry_accepts_non_cyclic_component() {
        let u = sample();
        let dt = byte_data_type("byte", 1);
        assert!(u.union_data_type_check_ancestry(dt.as_ref()).is_ok());
    }

    #[test]
    fn non_packed_alignment_defaults_to_one() {
        let u = sample();
        assert_eq!(u.union_data_type_alignment(), 1);
    }

    #[test]
    fn repack_non_packed_recomputes_length_from_max_component() {
        let mut u = sample();
        u.components_mut().push(DataTypeComponentImpl::new(byte_data_type("byte", 1), None, 1, 0, 0, None, None));
        u.components_mut().push(DataTypeComponentImpl::new(byte_data_type("dword", 4), None, 4, 1, 0, None, None));
        let changed = u.union_data_type_repack(false);
        assert!(changed);
        assert_eq!(u.length(), 4);
        // repacking again with no changes should report no change
        assert!(!u.union_data_type_repack(false));
    }

    #[test]
    fn repack_packed_aligns_length_and_computes_positive_alignment() {
        let mut u = sample();
        u.packing_value = crate::program::model::data::composite_internal::DEFAULT_PACKING;
        u.components_mut().push(DataTypeComponentImpl::new(byte_data_type("dword", 4), None, 4, 0, 0, None, None));
        let changed = u.union_data_type_repack(false);
        assert!(changed);
        assert_eq!(u.length(), 4);
        assert!(u.union_data_type_alignment() > 0);
    }

    #[test]
    fn add_appends_component_at_offset_zero_and_grows_to_max_length() {
        let mut u = sample();
        let dtc1 = u.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        assert_eq!(dtc1.get_ordinal(), 0);
        assert_eq!(dtc1.get_offset(), 0);
        assert_eq!(u.length(), 1);

        let dtc2 = u
            .union_data_type_add(byte_data_type("dword", 4), -1, Some("field2".to_string()), None)
            .unwrap();
        assert_eq!(dtc2.get_ordinal(), 1);
        assert_eq!(dtc2.get_offset(), 0);
        assert_eq!(u.length(), 4);
        assert_eq!(u.union_data_type_get_num_components(), 2);
        assert_eq!(u.union_data_type_get_num_defined_components(), 2);
    }

    #[test]
    fn insert_shifts_existing_ordinals_and_keeps_offset_zero() {
        let mut u = sample();
        u.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        u.union_data_type_add(byte_data_type("word", 2), -1, None, None).unwrap();

        let inserted = u
            .union_data_type_insert(1, byte_data_type("dword", 4), -1, None, None)
            .unwrap();
        assert_eq!(inserted.get_ordinal(), 1);
        assert_eq!(inserted.get_offset(), 0);

        // the component that used to be at ordinal 1 shifted to ordinal 2
        assert_eq!(u.union_data_type_get_component(2).unwrap().get_data_type_name(), "word");
        assert_eq!(u.length(), 4);
    }

    #[test]
    fn insert_at_num_components_behaves_like_add() {
        let mut u = sample();
        u.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        let inserted = u
            .union_data_type_insert(1, byte_data_type("dword", 4), -1, None, None)
            .unwrap();
        assert_eq!(inserted.get_ordinal(), 1);
        assert_eq!(u.union_data_type_get_num_components(), 2);
    }

    #[test]
    fn insert_rejects_out_of_bounds_ordinal() {
        let mut u = sample();
        let result = u.union_data_type_insert(5, byte_data_type("byte", 1), -1, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn add_bit_field_appends_bitfield_component() {
        let mut u = sample();
        let dtc = u
            .union_data_type_add_bit_field(int_data_type("int", 4), 3, Some("flag".to_string()), None)
            .unwrap();
        assert_eq!(dtc.get_ordinal(), 0);
        assert_eq!(dtc.get_offset(), 0);
        assert!(dtc.is_bit_field_component());
        assert_eq!(u.union_data_type_get_num_components(), 1);
    }

    #[test]
    fn add_bit_field_rejects_invalid_base_type() {
        let mut u = sample();
        let result = u.union_data_type_add_bit_field(byte_data_type("byte", 1), 3, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn insert_bit_field_rejects_out_of_bounds_ordinal() {
        let mut u = sample();
        let result = u.union_data_type_insert_bit_field(5, int_data_type("int", 4), 3, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn union_trait_insert_bit_field_delegates_to_union_data_type_insert_bit_field() {
        let mut u = sample();
        let dyn_union: &mut dyn crate::program::model::data::union::Union = &mut u;
        let result = dyn_union.insert_bit_field(0, int_data_type("int", 4), 3, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn delete_removes_component_and_shifts_ordinals() {
        let mut u = sample();
        u.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        u.union_data_type_add(byte_data_type("dword", 4), -1, None, None).unwrap();
        u.union_data_type_add(byte_data_type("word", 2), -1, None, None).unwrap();
        assert_eq!(u.length(), 4);

        u.union_data_type_delete(1).unwrap(); // remove "dword"
        assert_eq!(u.union_data_type_get_num_components(), 2);
        assert_eq!(u.union_data_type_get_component(1).unwrap().get_data_type_name(), "word");
        // max remaining component length is now 2 ("byte"=1, "word"=2)
        assert_eq!(u.length(), 2);
    }

    #[test]
    fn delete_rejects_out_of_bounds_ordinal() {
        let mut u = sample();
        assert!(u.union_data_type_delete(0).is_err());
    }

    #[test]
    fn delete_set_empty_is_no_op() {
        let mut u = sample();
        u.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        assert!(u.union_data_type_delete_set(&HashSet::new()).is_ok());
        assert_eq!(u.union_data_type_get_num_components(), 1);
    }

    #[test]
    fn delete_set_single_matches_delete() {
        let mut u = sample();
        u.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        u.union_data_type_add(byte_data_type("dword", 4), -1, None, None).unwrap();
        let mut ordinals = HashSet::new();
        ordinals.insert(1);
        u.union_data_type_delete_set(&ordinals).unwrap();
        assert_eq!(u.union_data_type_get_num_components(), 1);
        assert_eq!(u.length(), 1);
    }

    #[test]
    fn delete_set_multiple_shifts_and_recomputes_length() {
        let mut u = sample();
        u.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        u.union_data_type_add(byte_data_type("dword", 4), -1, None, None).unwrap();
        u.union_data_type_add(byte_data_type("word", 2), -1, None, None).unwrap();
        u.union_data_type_add(byte_data_type("qword", 8), -1, None, None).unwrap();

        let mut ordinals = HashSet::new();
        ordinals.insert(0);
        ordinals.insert(3);
        u.union_data_type_delete_set(&ordinals).unwrap();

        assert_eq!(u.union_data_type_get_num_components(), 2);
        assert_eq!(u.union_data_type_get_component(0).unwrap().get_data_type_name(), "dword");
        assert_eq!(u.union_data_type_get_component(0).unwrap().get_ordinal(), 0);
        assert_eq!(u.union_data_type_get_component(1).unwrap().get_data_type_name(), "word");
        assert_eq!(u.union_data_type_get_component(1).unwrap().get_ordinal(), 1);
        assert_eq!(u.length(), 4);
    }

    #[test]
    fn is_equivalent_compares_packing_and_components() {
        let mut u1 = sample();
        u1.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        let mut u2 = sample();
        u2.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        assert!(u1.union_data_type_is_equivalent(&u2));

        u2.union_data_type_add(byte_data_type("word", 2), -1, None, None).unwrap();
        assert!(!u1.union_data_type_is_equivalent(&u2));
    }

    #[test]
    fn replace_with_copies_components_and_settings() {
        let mut source = sample();
        source.union_data_type_add(byte_data_type("byte", 1), -1, None, None).unwrap();
        source.union_data_type_add(byte_data_type("dword", 4), -1, None, None).unwrap();

        let mut target = sample();
        target.union_data_type_add(byte_data_type("qword", 8), -1, None, None).unwrap();

        target.union_data_type_replace_with(&source).unwrap();

        assert_eq!(target.union_data_type_get_num_components(), 2);
        assert_eq!(target.length(), 4);
        assert_eq!(target.union_data_type_get_component(0).unwrap().get_data_type_name(), "byte");
        assert_eq!(target.union_data_type_get_component(1).unwrap().get_data_type_name(), "dword");
    }

    // ------------------------------------------------------------------------------------------
    // `UnionDataType`: the first real, production concrete `UnionDataType` (as opposed to the
    // `#[cfg(test)]`-scoped `UnionDataType` above). Mirrors
    // `structure_data_type`'s identical `StructureDataType` test coverage.
    // ------------------------------------------------------------------------------------------

    #[test]
    fn new_creates_empty_root_category_union() {
        let u = UnionDataType::new("Foo");
        assert_eq!(u.get_name(), "Foo");
        assert_eq!(u.get_category_path(), ROOT.clone());
        assert!(u.union_data_type_is_zero_length());
        assert_eq!(DataType::get_length(&u), 1);
        assert!(u.is_not_yet_defined());
    }

    #[test]
    #[should_panic(expected = "Invalid DataType name")]
    fn new_rejects_invalid_name() {
        UnionDataType::new("   ");
    }

    #[test]
    fn new_in_category_uses_specified_category() {
        let path = CategoryPath::new(ROOT.clone(), &["cat"]).expect("valid category path");
        let u = UnionDataType::new_in_category(path.clone(), "Foo");
        assert_eq!(u.get_category_path(), path);
    }

    #[test]
    fn with_archive_identity_preserves_universal_id_and_change_times() {
        let u = UnionDataType::with_archive_identity(ROOT.clone(), "Foo", UniversalID::new(42), None, 100, 200, None);
        assert_eq!(u.universal_id, UniversalID::new(42));
        assert_eq!(u.last_change_time, 100);
        assert_eq!(u.last_change_time_in_source_archive, 200);
    }

    #[test]
    fn add_insert_delete_via_composite_trait_object() {
        let mut u = UnionDataType::new("Foo");
        let composite: &mut dyn Composite = &mut u;
        composite.add(byte_data_type("int", 4)).expect("add int");
        composite.add_with_name(byte_data_type("short", 2), Some("field1".to_string()), None).expect("add short");
        assert_eq!(composite.get_num_components(), 2);
        assert_eq!(composite.get_num_defined_components(), 2);

        composite.insert(1, byte_data_type("byte", 1)).expect("insert byte");
        assert_eq!(composite.get_num_components(), 3);
        assert_eq!(composite.get_component(1).unwrap().get_data_type_name(), "byte");

        composite.delete(0).expect("delete ordinal 0");
        assert_eq!(composite.get_num_components(), 2);
        assert_eq!(composite.get_component(0).unwrap().get_data_type_name(), "byte");
    }

    #[test]
    fn get_components_via_union_trait_object() {
        let mut u = UnionDataType::new("Foo");
        u.add(byte_data_type("int", 4)).expect("add int");
        u.add(byte_data_type("short", 2)).expect("add short");

        let union: &dyn crate::program::model::data::union::Union = &u;
        assert_eq!(union.get_num_components(), 2);
        let components = union.get_components();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].get_data_type_name(), "int");
        assert_eq!(components[1].get_data_type_name(), "short");
        // union length is the max of its components' lengths.
        assert_eq!(DataType::get_length(&u), 4);
    }

    #[test]
    fn is_equivalent_between_two_real_unions() {
        let mut a = UnionDataType::new("A");
        a.union_data_type_add(byte_data_type("int", 4), -1, Some("x".to_string()), None).unwrap();

        let mut b = UnionDataType::new("B");
        b.union_data_type_add(byte_data_type("int", 4), -1, Some("x".to_string()), None).unwrap();

        assert!(a.union_data_type_is_equivalent(&b));

        b.union_data_type_add(byte_data_type("short", 2), -1, Some("y".to_string()), None).unwrap();
        assert!(!a.union_data_type_is_equivalent(&b));
    }

    #[test]
    fn copy_data_type_produces_independent_equivalent_union() {
        struct NoopDtm;
        impl DataTypeManager for NoopDtm {
            fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
                shared_default_organization()
            }
        }

        let mut original = UnionDataType::new("Original");
        original.add_with_name(byte_data_type("int", 4), Some("field0".to_string()), None).unwrap();
        original.set_description("a description").unwrap();

        let copy = original.copy_data_type(&NoopDtm);
        let copy_union = copy.as_union().expect("copy is a Union");
        assert_eq!(copy.get_name(), "Original");
        assert_eq!(copy.get_description(), "a description");
        assert_eq!(copy_union.get_num_components(), 1);
        assert_eq!(
            Composite::get_component(copy_union, 0).unwrap().get_data_type_name(),
            "int"
        );

        // Independent: mutating the original does not affect the copy.
        original.add_with_name(byte_data_type("short", 2), Some("field1".to_string()), None).unwrap();
        assert_eq!(Composite::get_num_components(&original), 2);
        assert_eq!(copy_union.get_num_components(), 1);
    }

    #[test]
    fn clone_data_type_preserves_archive_identity() {
        struct NoopDtm;
        impl DataTypeManager for NoopDtm {
            fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
                shared_default_organization()
            }
        }

        let mut original =
            UnionDataType::with_archive_identity(ROOT.clone(), "Original", UniversalID::new(7), None, 10, 20, None);
        original.add_with_name(byte_data_type("int", 4), Some("field0".to_string()), None).unwrap();

        let cloned = original.clone_data_type(&NoopDtm);
        let cloned_union = cloned.as_union().expect("clone is a Union");
        assert_eq!(cloned.get_name(), "Original");
        assert_eq!(cloned_union.get_num_components(), 1);
    }

    #[test]
    fn clone_union_via_union_trait_object_preserves_components() {
        let mut original = UnionDataType::new("Original");
        original.add(byte_data_type("int", 4)).unwrap();

        struct NoopDtm;
        impl DataTypeManager for NoopDtm {
            fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
                shared_default_organization()
            }
        }

        let union_ref: &dyn crate::program::model::data::union::Union = &original;
        let cloned = union_ref.clone_union(&NoopDtm);
        assert_eq!(cloned.get_num_components(), 1);
    }

    #[test]
    fn non_packed_alignment_defaults_to_one_and_machine_alignment_uses_data_organization() {
        let u = UnionDataType::new("Foo");
        assert_eq!(DataType::get_alignment(&u), 1);

        let mut machine_aligned = UnionDataType::new("Bar");
        machine_aligned.set_to_machine_aligned();
        assert_eq!(DataType::get_alignment(&machine_aligned), 8); // DataOrganizationImpl::DEFAULT_MACHINE_ALIGNMENT
    }

    #[test]
    fn packing_enabled_union_computes_alignment_without_panicking() {
        let mut u = UnionDataType::new("Packed");
        u.set_packing_enabled(true);
        u.add(byte_data_type("int", 4)).expect("add int");
        u.add(byte_data_type("byte", 1)).expect("add byte");
        let alignment = DataType::get_alignment(&u);
        assert!(alignment >= 1);
        assert!(u.is_packing_enabled());
    }

    #[test]
    fn data_type_size_changed_resizes_matching_component_and_recomputes_length() {
        let mut u = UnionDataType::new("Foo");
        u.union_data_type_add(byte_data_type("wide", 8), -1, None, None).unwrap();
        u.union_data_type_add(byte_data_type("short", 2), -1, None, None).unwrap();
        assert_eq!(u.stored_union_length(), 8); // max(8, 2)

        // Simulate "wide"'s own data type shrinking from 8 bytes to 4.
        u.union_data_type_data_type_size_changed(byte_data_type("wide", 4).as_ref()).unwrap();

        assert_eq!(u.components()[0].get_length(), 4);
        assert_eq!(u.stored_union_length(), 4); // max(4, 2), recomputed by the repack this triggers
    }

    #[test]
    fn data_type_alignment_changed_is_no_op_when_non_packed() {
        let mut u = UnionDataType::new("Foo");
        u.union_data_type_add(byte_data_type("int", 4), -1, None, None).unwrap();
        let length_before = u.stored_union_length();
        u.union_data_type_data_type_alignment_changed(byte_data_type("int", 4).as_ref());
        assert_eq!(u.stored_union_length(), length_before);
    }

    #[test]
    fn data_type_alignment_changed_repacks_when_packing_enabled() {
        let mut u = UnionDataType::new("Packed");
        u.set_packing_enabled(true);
        u.add(byte_data_type("int", 4)).expect("add int");
        // Must not panic reaching into the data organization, and must leave the union in a
        // consistent, still-packed state.
        u.union_data_type_data_type_alignment_changed(byte_data_type("int", 4).as_ref());
        assert!(u.is_packing_enabled());
        assert_eq!(Composite::get_num_components(&u), 1);
    }

    #[test]
    fn data_type_deleted_substitutes_bad_data_type_stand_in() {
        let mut u = UnionDataType::new("Foo");
        u.union_data_type_add(byte_data_type("int", 4), -1, Some("a".to_string()), None).unwrap();
        u.union_data_type_add(byte_data_type("short", 2), -1, Some("b".to_string()), None).unwrap();

        u.union_data_type_data_type_deleted(byte_data_type("int", 4).as_ref());

        assert_eq!(u.components()[0].get_data_type().get_name(), "-BAD-");
        assert_eq!(u.components()[1].get_data_type().get_name(), "short"); // unaffected
    }

    #[test]
    fn data_type_replaced_swaps_component() {
        let mut u = UnionDataType::new("Foo");
        u.union_data_type_add(byte_data_type("int", 4), -1, Some("a".to_string()), None).unwrap();

        u.union_data_type_data_type_replaced(byte_data_type("int", 4).as_ref(), byte_data_type("long", 8))
            .unwrap();

        assert_eq!(u.components()[0].get_data_type().get_name(), "long");
        assert_eq!(u.components()[0].get_length(), 8);
        assert_eq!(u.stored_union_length(), 8);
    }

    #[test]
    fn data_type_replaced_falls_back_but_keeps_javas_original_length_quirk() {
        let mut outer = UnionDataType::new("Outer");
        outer.union_data_type_add(byte_data_type("int", 4), -1, Some("x".to_string()), None).unwrap();

        // "Inner" contains a field path-equal to "Outer" itself, so replacing Outer's "int"
        // component with an Inner instance would create a cyclic composite; checkAncestry should
        // reject it, falling back to storing the `Undefined1DataType.dataType` stand-in.
        let mut inner = UnionDataType::new("Inner");
        inner.union_data_type_add(byte_data_type("Outer", 6), -1, Some("back".to_string()), None).unwrap();
        assert_eq!(DataType::get_length(&inner), 6);

        outer
            .union_data_type_data_type_replaced(byte_data_type("int", 4).as_ref(), Box::new(inner))
            .unwrap();

        // The stored replacement is the Undefined1 stand-in (name "undefined1")...
        assert_eq!(outer.components()[0].get_data_type().get_name(), "undefined1");
        // ...but matching Java's `getPreferredComponentLength(newDt, ...)` verbatim quirk (using
        // the *original* `new_dt` -- "Inner", length 6 -- rather than the actually-stored
        // replacement), the component's length is 6, not the stand-in's own length of 1.
        assert_eq!(outer.components()[0].get_length(), 6);
    }

    #[test]
    fn data_type_replaced_updates_bitfield_base_type() {
        let mut u = UnionDataType::new("Foo");
        u.union_data_type_add_bit_field(int_data_type("int", 4), 5, Some("flags".to_string()), None)
            .unwrap();

        u.union_data_type_data_type_replaced(int_data_type("int", 4).as_ref(), int_data_type("long", 8))
            .unwrap();

        let stored = u.components()[0].get_data_type();
        let bitfield = stored.as_bit_field_data_type().expect("still a bitfield");
        assert_eq!(bitfield.get_base_data_type().get_name(), "long");
        assert_eq!(bitfield.get_declared_bit_size(), 5);
    }

    struct MockBuf;
    impl MemBuffer for MockBuf {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}
}

/// Ports of `ghidra.program.model.data.UnionDataTypeTest` with the Java expected values (the
/// `StringDataType` member of Java's `struct_1` fixture is replaced by an equal-length `byte[10]`
/// until the string types are ported).
#[cfg(test)]
mod java_tests {
    use super::*;
    use crate::program::model::data::array_data_type::ArrayDataType;
    use crate::program::model::data::byte_data_type::ByteDataType;
    use crate::program::model::data::composite_test_utils::assert_expected_composite;
    use crate::program::model::data::dword_data_type::DWordDataType;
    use crate::program::model::data::integer_data_type::IntegerDataType;
    use crate::program::model::data::short_data_type::ShortDataType;
    use crate::program::model::data::structure_data_type::StructureDataType;
    use crate::program::model::data::word_data_type::WordDataType;

    fn boxed(d: Arc<dyn DataType>) -> Box<dyn DataType> {
        share_data_type(&d)
    }
    fn s(text: &str) -> Option<String> {
        Some(text.to_string())
    }

    /// `UnionDataTypeTest.setUp()`.
    fn test_union() -> UnionDataType {
        let mut u = UnionDataType::new("TestUnion");
        u.add_with_name(boxed(ByteDataType::data_type()), s("field1"), s("Comment1")).unwrap();
        u.add_with_name(boxed(WordDataType::data_type()), None, s("Comment2")).unwrap();
        u.add_with_name(boxed(DWordDataType::data_type()), s("field3"), None).unwrap();
        u.add_with_name(boxed(ByteDataType::data_type()), s("field4"), s("Comment4")).unwrap();
        u
    }

    /// Java's `struct_1`: a byte followed by a 10-byte member (length 11).
    fn struct_1() -> StructureDataType {
        let mut st = StructureDataType::new("struct_1", 0);
        st.add(boxed(ByteDataType::data_type())).unwrap();
        st.add(Box::new(ArrayDataType::new(ByteDataType::data_type(), 10).unwrap())).unwrap();
        st
    }

    #[test]
    fn test_add_get_insert() {
        let mut u = test_union();
        assert_eq!((u.get_length(), u.get_num_components()), (4, 4));
        let dtc = Composite::get_component(&u, 3).unwrap();
        assert_eq!(dtc.get_field_name(), s("field4"));
        assert_eq!(dtc.get_data_type().get_name(), "byte");
        assert_eq!(dtc.get_default_field_name(), s("field3"));

        let st = struct_1();
        let len = st.get_length();
        let newdtc = u.add_with_name(Box::new(st), s("field5"), s("comments")).unwrap();
        assert_eq!(u.get_length(), len);
        let dtc = Composite::get_component(&u, 4).unwrap();
        assert_eq!((dtc.get_ordinal(), newdtc.get_ordinal()), (4, 4));
        assert_eq!(dtc.get_field_name(), s("field5"));
        assert_eq!(dtc.get_comment(), s("comments"));
        assert_eq!(u.get_components().len(), 5);

        let mut u = test_union();
        u.insert_with_length_and_name(2, Box::new(struct_1()), 11, s("field5"), s("field5 comments")).unwrap();
        assert_eq!(u.get_length(), 11);
        assert_eq!(Composite::get_component(&u, 2).unwrap().get_field_name(), s("field5"));
    }

    #[test]
    fn test_bit_field_union() {
        let mut u = test_union();
        for _ in 0..4 {
            Composite::delete(&mut u, 0).unwrap();
        }
        // NOTE: bitOffset ignored for union
        Union::insert_bit_field(&mut u, 0, boxed(IntegerDataType::data_type()), 2, s("bf1"), s("bf1Comment")).unwrap();
        u.insert(0, boxed(ShortDataType::data_type())).unwrap();
        assert_expected_composite(
            "UnionDataTypeTest",
            "/TestUnion\npack(disabled)\nUnion TestUnion {\n   0   short   2      \"\"\n   0   int:2(0)   1   bf1   \"bf1Comment\"\n}\nLength: 2 Alignment: 1",
            &u,
        );
        u.set_packing_enabled(true);
        assert_expected_composite(
            "UnionDataTypeTest",
            "/TestUnion\npack()\nUnion TestUnion {\n   0   short   2      \"\"\n   0   int:2(0)   1   bf1   \"bf1Comment\"\n}\nLength: 4 Alignment: 4",
            &u,
        );
    }

    #[test]
    fn test_insert_bit_field_little_and_big_endian() {
        let mut u = test_union();
        Union::insert_bit_field(&mut u, 2, boxed(IntegerDataType::data_type()), 4, s("bf1"), s("bf1Comment")).unwrap();
        Union::insert_bit_field(&mut u, 3, boxed(ByteDataType::data_type()), 4, s("bf2"), s("bf2Comment")).unwrap();
        assert_expected_composite(
            "UnionDataTypeTest",
            "/TestUnion\npack(disabled)\nUnion TestUnion {\n   0   byte   1   field1   \"Comment1\"\n   0   word   2      \"Comment2\"\n   0   int:4(0)   1   bf1   \"bf1Comment\"\n   0   byte:4(0)   1   bf2   \"bf2Comment\"\n   0   dword   4   field3   \"\"\n   0   byte   1   field4   \"Comment4\"\n}\nLength: 4 Alignment: 1",
            &u,
        );

        struct BigEndianDtm(Arc<DataOrganizationImpl>);
        impl DataTypeManager for BigEndianDtm {
            fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
                self.0.clone()
            }
        }
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(true);
        let dtm = BigEndianDtm(Arc::new(org));
        let mut be = test_union().clone_union_impl(Some(&dtm));
        Union::insert_bit_field(&mut be, 2, boxed(IntegerDataType::data_type()), 4, s("bf1"), s("bf1Comment")).unwrap();
        Union::insert_bit_field(&mut be, 3, boxed(ByteDataType::data_type()), 4, s("bf2"), s("bf2Comment")).unwrap();
        assert_expected_composite(
            "UnionDataTypeTest",
            "/TestUnion\npack(disabled)\nUnion TestUnion {\n   0   byte   1   field1   \"Comment1\"\n   0   word   2      \"Comment2\"\n   0   int:4(4)   1   bf1   \"bf1Comment\"\n   0   byte:4(4)   1   bf2   \"bf2Comment\"\n   0   dword   4   field3   \"\"\n   0   byte   1   field4   \"Comment4\"\n}\nLength: 4 Alignment: 1",
            &be,
        );
    }

    #[test]
    fn test_delete_and_delete_many() {
        let mut u = test_union();
        u.add(Box::new(struct_1())).unwrap();
        assert_eq!(u.get_length(), 11);
        Composite::delete(&mut u, 4).unwrap();
        assert_eq!(u.get_length(), 4);
        Composite::delete(&mut u, 2).unwrap();
        assert_eq!(u.get_length(), 2);

        let mut u = test_union();
        u.add(Box::new(struct_1())).unwrap();
        assert_expected_composite(
            "UnionDataTypeTest",
            "/TestUnion\npack(disabled)\nUnion TestUnion {\n   0   byte   1   field1   \"Comment1\"\n   0   word   2      \"Comment2\"\n   0   dword   4   field3   \"\"\n   0   byte   1   field4   \"Comment4\"\n   0   struct_1   11      \"\"\n}\nLength: 11 Alignment: 1",
            &u,
        );
        u.delete_set(&[2, 4].into_iter().collect()).unwrap();
        assert_eq!(u.get_length(), 2);
        let comps = u.get_defined_components();
        assert_eq!(comps[2].get_data_type().get_name(), "byte");
        assert_eq!(comps[2].get_ordinal(), 2);
    }

    #[test]
    fn test_is_part_of() {
        let mut st = struct_1();
        let mystring = StructureDataType::new("mystring", 10);
        st.add(Box::new(mystring.clone())).unwrap();
        let mut u = test_union();
        u.add(Box::new(st)).unwrap();
        assert!(u.is_part_of(&mystring));
        assert!(!u.is_part_of(&StructureDataType::new("mystring", 10)));
    }

    #[test]
    fn test_replace_with_and_clone_copy() {
        let mut u = test_union();
        let mut new_union = UnionDataType::new("Replaced");
        new_union.set_description("testReplaceWith()").unwrap();
        new_union.insert_with_length_and_name(0, boxed(DWordDataType::data_type()), 4, s("field2"), None).unwrap();
        new_union.insert_with_length_and_name(0, boxed(WordDataType::data_type()), 2, None, s("Comment2")).unwrap();
        new_union.insert_with_length_and_name(0, boxed(ByteDataType::data_type()), 1, s("field0"), s("Comment1")).unwrap();
        u.replace_with(&new_union);
        assert_eq!((u.get_length(), u.get_num_components()), (4, 3));
        let names: Vec<_> = u.get_components().iter().map(|c| c.get_field_name()).collect();
        assert_eq!(names, vec![s("field0"), None, s("field2")]);
        assert_eq!(u.get_name(), "TestUnion");
        assert!(u.is_equivalent(&new_union));
        assert!(u.try_replace_with(&StructureDataType::new("S", 1)).is_err());

        let u = test_union();
        struct Dtm;
        impl DataTypeManager for Dtm {
            fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
                shared_default_organization()
            }
        }
        let cloned = u.clone_data_type(&Dtm);
        assert_eq!(cloned.get_length(), 4);
        assert_eq!(cloned.get_universal_id(), u.get_universal_id());
        let copied = u.copy_data_type(&Dtm);
        assert_eq!(copied.get_length(), 4);
        assert_ne!(copied.get_universal_id(), u.get_universal_id());
        assert!(copied.is_equivalent(&u));
    }
}
