//! Port of `ghidra.program.model.data.StructureDataType`: the in-memory (non-database-backed)
//! `Structure` implementation.
//!
//! [`StructureDataType`] is a concrete struct (Java: a concrete class extending
//! `CompositeDataTypeImpl`). Its `Composite`/`Structure`/`DataType` trait impls delegate to the
//! inherent `structure_data_type_*` methods below, which port the Java method bodies one for one
//! (binary searches over the defined-component list by offset, ordinal and normalized bit
//! offset; non-packed offset/ordinal bookkeeping; packed layout via
//! [`AlignedStructurePacker`] and the real
//! [`AlignedComponentPacker`](super::aligned_component_packer::AlignedComponentPacker)).
//!
//! Divergences from Java, all following from the build-then-share convention for composites
//! (2026-09-27) or from Rust ownership:
//!   - Parent tracking (`addParent`/`removeParent`) and `notifySizeChanged`/
//!     `notifyAlignmentChanged` are not performed: an in-memory structure is an owned value that
//!     nothing registers as a parent; a data type manager copies it on resolve.
//!   - The associated manager is recorded only as its data organization, so inserted data types
//!     are not `clone(dataMgr)`-rebound; they are shared as given.
//!   - Data type identity (Java `==`) in `dataTypeDeleted`/`dataTypeReplaced`/
//!     `dataTypeSizeChanged` is compared by data type path.
//!   - `BadDataType` is represented by the local [`BadDataTypeStandIn`] until `BadDataType` is
//!     ported (it needs `Dynamic::get_replacement_base_type` to become `Option`-returning; parked).

use crate::docking::settings::settings::Settings;
use crate::program::model::data::aligned_component_packer::AlignedComponentPacker as RealAlignedComponentPacker;
use crate::program::model::data::aligned_structure_inspector::AlignedStructureInspector;
use crate::program::model::data::aligned_structure_packer::AlignedStructurePacker;
use crate::program::model::data::alignment_type::AlignmentType;
use crate::program::model::data::bit_field_data_type::{
    check_base_data_type, get_effective_bit_size, get_minimum_storage_size_no_offset, is_valid_base_data_type,
    BitFieldDataType,
};
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl;
use crate::program::model::data::composite_internal::{
    compare_component_to_offset, compare_component_to_ordinal, stored_minimum_alignment_of, stored_packing_value_of,
    CompositeInternal, DEFAULT_ALIGNMENT, NO_PACKING,
};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::{DataType, SetDataTypeNameError, UnsupportedOperationError};
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_component_impl::DataTypeComponentImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::default_data_type::DefaultDataType;
use crate::program::model::data::undefined1_data_type::Undefined1DataType;
use crate::program::model::data::built_in::shared_default_organization;
use crate::program::model::data::internal_data_type_component::InternalDataTypeComponent;
use crate::program::model::data::packing_type::PackingType;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::data::structure::{get_normalized_bitfield_offset, Structure};
use crate::program::model::data::structure_internal::StructureInternal;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::{share_data_type, AlignedComponentPacker};
use crate::util::exception::DuplicateNameException;
use crate::util::universal_id_generator::next_id;
use crate::util::UniversalID;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::sync::Arc;

/// Local stand-in for Ghidra's `BadDataType.dataType` singleton (an instance of the private
/// `ghidra.program.model.data.BadDataType`), used by
/// [`structure_data_type_data_type_deleted`](StructureDataType::structure_data_type_data_type_deleted)
/// in place of a deleted (non-bitfield) component's data type, matching Java's
/// `setComponentDataType(dtc, BadDataType.dataType, i)`. [`BadDataType`](super::bad_data_type::BadDataType)
/// is itself only a trait in this crate with no ready-made concrete singleton instance (see its
/// module docs, which flag this exact gap), so -- mirroring `DataType.DEFAULT` ([`DefaultDataType`]) above --
/// this minimal local type stands in for just the two properties every call site actually needs:
/// `getName()` (`"-BAD-"`) and `getLength()` (`-1`, real Java's documented "unknown length"
/// sentinel). Since `-1` is not `> 0`, [`preferred_component_length_for_data_type`](super::composite_data_type_impl::preferred_component_length_for_data_type)
/// always falls through to returning the *original* component length unchanged for this stand-in
/// (matching Java's own `dtcLen`-preserving behavior for a real `BadDataType`, which has the
/// identical `getLength() == -1`), so the fact that this stand-in does not also implement the real
/// `BadDataType`/`Dynamic` traits (unlike the genuine Java singleton, which is `Dynamic`) has no
/// observable effect on any computation performed here -- see
/// [`structure_data_type_set_component_data_type`](StructureDataType::structure_data_type_set_component_data_type)'s
/// own doc comment for the arithmetic that makes the two paths converge.
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

/// Port of `DataTypeComponentImpl.isUndefined()`'s test, applied to a freshly-constructed
/// component's data type (`dataType == DataType.DEFAULT`), used below in place of
/// `dtc.isUndefined()` where only the data type (not yet wrapped in a component) is at hand.
fn is_dynamic_with_specifiable_length(data_type: &dyn DataType) -> bool {
    data_type
        .as_dynamic()
        .map(|d| d.can_specify_length())
        .unwrap_or(false)
}

/// Port of the relevant cases of `DataTypeUtilities.isSecondPartOfFirst(DataType, DataType)`,
/// used by [`structure_data_type_check_ancestry`] to walk into `data_type`'s own composition
/// tree looking for `target`. A near-duplicate of
/// [`composite_data_type_impl::is_part_of_data_type`](super::composite_data_type_impl), which
/// exists separately (rather than being reused directly) because that helper needs *ownership*
/// of `data_type` only to reach [`DataType::into_composite`]'s consuming downcast, whereas every
/// caller here already owns `data_type` for other purposes afterward (e.g. to build the new
/// component being inserted) and cannot give it up; the borrowing
/// [`DataType::as_composite`] downcast sidesteps that. See that sibling helper's own doc comment
/// for the identical `Array`-case caveat (conservatively treated as "not part of").
fn is_part_of_data_type_by_ref(data_type: &dyn DataType, target: &dyn DataType) -> bool {
    if data_type.is_pointer() || target.is_pointer() {
        return false;
    }
    if data_type.get_data_type_path() == target.get_data_type_path() {
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

/// Port of the private `DataTypeUtilities.checkValidReplacementDataType(DataType)`, used by
/// [`check_valid_replacement`]. Unlike Java, there is no early return for a `DataTypeDB`-backed
/// `data_type` (this crate's [`DataType`] trait has no `is_data_type_db`-style marker yet to
/// recognize a database-backed implementor generically), so every candidate is checked against the
/// same void/default/bitfield/factory/dynamic rules Java applies to non-`DataTypeDB` types.
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
/// [`StructureDataType::structure_data_type_data_type_replaced`] ahead of (and, matching Java,
/// unguarded by the same try/catch as) the validate/clone/check-ancestry sequence that follows it.
fn check_valid_replacement(replaced_dt: &dyn DataType, replacement_dt: &dyn DataType) -> Result<(), String> {
    check_valid_replacement_data_type(replaced_dt)?;
    check_valid_replacement_data_type(replacement_dt)?;
    check_for_invalid_function_definition_replacement(replaced_dt, replacement_dt)
}

/// Adapter routing a real [`DataTypeComponentImpl`]'s state through the
/// `Box<dyn InternalDataTypeComponent>` shape that
/// [`AlignedStructurePacker::pack_components`](AlignedStructurePacker::pack_components) requires,
/// used only by [`StructureDataType::structure_data_type_pack`].
///
/// `data_type` is kept as an `Arc<dyn DataType>` (mirroring
/// [`DataTypeComponentImpl`]'s own storage strategy, and using the same
/// [`share_data_type`] convention as [`BitFieldDataType::get_base_data_type`]) rather than a
/// `Box<dyn DataType>`, since [`DataTypeComponent::get_data_type`] must be answerable repeatedly
/// from a `&self` borrow and `dyn DataType` has no `Clone` bound. This lets
/// [`structure_data_type_pack`](StructureDataType::structure_data_type_pack) read every field this
/// adapter carries back out through ordinary (object-safe) [`DataTypeComponent`]/
/// [`InternalDataTypeComponent`] trait methods once packing completes -- no downcast back to the
/// concrete adapter type is ever needed, since nothing in [`AlignedStructurePacker::pack_components`]
/// replaces list elements, only mutates them in place via `&mut dyn InternalDataTypeComponent`.
struct PackableComponent {
    data_type: Arc<dyn DataType>,
    ordinal: i32,
    offset: i32,
    length: i32,
    is_bit_field: bool,
    field_name: Option<String>,
    comment: Option<String>,
}

impl PackableComponent {
    fn from_snapshot(dtc: &DataTypeComponentImpl) -> Self {
        PackableComponent {
            data_type: Arc::from(dtc.get_data_type()),
            ordinal: dtc.get_ordinal(),
            offset: dtc.get_offset(),
            length: dtc.get_length(),
            is_bit_field: dtc.is_bit_field_component(),
            field_name: dtc.get_field_name(),
            comment: dtc.get_comment(),
        }
    }
}

impl DataTypeComponent for PackableComponent {
    fn get_ordinal(&self) -> i32 {
        self.ordinal
    }
    fn get_offset(&self) -> i32 {
        self.offset
    }
    fn get_length(&self) -> i32 {
        self.length
    }
    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }
    fn get_data_type_name(&self) -> String {
        self.data_type.get_name()
    }
    fn get_field_name(&self) -> Option<String> {
        self.field_name.clone()
    }
    fn get_comment(&self) -> Option<String> {
        self.comment.clone()
    }
    fn is_bit_field_component(&self) -> bool {
        self.is_bit_field
    }
}

impl InternalDataTypeComponent for PackableComponent {
    fn set_data_type(&mut self, data_type: Box<dyn DataType>) {
        self.is_bit_field = data_type.is_bit_field_type();
        self.data_type = Arc::from(data_type);
    }
    fn update(&mut self, ordinal: i32, offset: i32, length: i32) {
        self.ordinal = ordinal;
        self.offset = offset;
        self.length = length;
    }
}

/// Rebuilds an owned [`DataTypeComponentImpl`] from a packed [`PackableComponent`] (accessed only
/// through its object-safe [`InternalDataTypeComponent`]/[`DataTypeComponent`] interface -- see
/// [`PackableComponent`]'s own doc comment for why no downcast is needed).
fn rebuild_packed_component(boxed: Box<dyn InternalDataTypeComponent>) -> DataTypeComponentImpl {
    DataTypeComponentImpl::new(
        boxed.get_data_type(),
        None,
        boxed.get_length(),
        boxed.get_ordinal(),
        boxed.get_offset(),
        boxed.get_field_name(),
        boxed.get_comment(),
    )
}

/// Port of `Structure.BitOffsetComparator.compare(Object, Object)`, specialized to the one
/// direction every caller here needs (comparing a defined component against a normalized target
/// bit offset -- Java's symmetric `Integer`-vs-`DataTypeComponent` overload handling is therefore
/// unnecessary). Follows the same `compare(component, target)` convention as
/// [`compare_component_to_offset`]/[`compare_component_to_ordinal`]: a component is "equal" if the
/// target bit offset falls within its normalized bit footprint.
fn compare_component_to_bit_offset(dtc: &DataTypeComponentImpl, bit_offset: i32, big_endian: bool) -> Ordering {
    let (start_bit, end_bit) = if dtc.is_bit_field_component() {
        let dt = dtc.get_data_type();
        let bitfield = dt
            .as_bit_field()
            .expect("is_bit_field_component() implies as_bit_field() returns Some");
        let bit_size = bitfield.get_bit_size();
        let start = get_normalized_bitfield_offset(
            dtc.get_offset(),
            dtc.get_length(),
            bit_size,
            bitfield.get_bit_offset(),
            big_endian,
        );
        (start, start + bit_size - 1)
    } else {
        let start = 8 * dtc.get_offset();
        (start, start + 8 * dtc.get_length() - 1)
    };
    if bit_offset < start_bit {
        Ordering::Greater
    } else if bit_offset > end_bit {
        Ordering::Less
    } else {
        Ordering::Equal
    }
}

/// Basic (in-memory, non-database-backed) implementation of the structure data type.
///
/// Port of `ghidra.program.model.data.StructureDataType`. See the module-level documentation for
/// what was ported, defaulted, and intentionally omitted.
///
/// NOTE: Implementation is not thread safe (matches the Java class's documented contract).
impl StructureDataType {
    /// The private `structLength` field.
    fn stored_struct_length(&self) -> i32 {
        self.struct_length
    }

    /// Sets the private `structLength` field.
    fn set_stored_struct_length(&mut self, length: i32) {
        self.struct_length = length;
    }

    /// The private `components` field (`List<DataTypeComponentImpl>`), in offset/ordinal order.
    fn components(&self) -> &Vec<DataTypeComponentImpl> {
        &self.components
    }

    /// Mutable access to the private `components` field.
    fn components_mut(&mut self) -> &mut Vec<DataTypeComponentImpl> {
        &mut self.components
    }

    /// The private `numComponents` field.
    fn stored_num_components(&self) -> i32 {
        self.num_components
    }

    /// Sets the private `numComponents` field.
    fn set_stored_num_components(&mut self, num_components: i32) {
        self.num_components = num_components;
    }

    /// Port of `StructureDataType.isZeroLength()`. Exposed under a distinct name since
    /// [`DataType::is_zero_length`](crate::program::model::data::data_type::DataType::is_zero_length)
    /// already provides a (placeholder) default. A concrete `impl DataType for ...` should
    /// delegate to this.
    fn structure_data_type_is_zero_length(&self) -> bool {
        self.stored_struct_length() == 0
    }

    /// Port of `StructureDataType.getLength()`: a zero-length structure reports a length of 1
    /// since a defined data unit cannot have zero length. Exposed under a distinct name since
    /// [`DataType::get_length`](crate::program::model::data::data_type::DataType::get_length)
    /// already provides a (placeholder) default. A concrete `impl DataType for ...` should
    /// delegate to this.
    fn length(&self) -> i32 {
        let len = self.stored_struct_length();
        if len == 0 {
            1
        } else {
            len
        }
    }

    /// Port of `StructureDataType.hasLanguageDependantLength()`. Exposed under a distinct name
    /// since
    /// [`CompositeDataTypeImpl::composite_impl_has_language_dependant_length`](CompositeDataTypeImpl::composite_impl_has_language_dependant_length)
    /// is required (abstract in Java too) with no default of its own; a concrete implementation
    /// should delegate its answer to this.
    fn structure_data_type_has_language_dependant_length(&self) -> bool {
        self.is_packing_enabled()
    }

    /// Port of `StructureDataType.getRepresentation(MemBuffer, Settings, int)`. Exposed under a
    /// distinct name since
    /// [`DataType::get_representation`](crate::program::model::data::data_type::DataType::get_representation)
    /// already provides a (placeholder) default. A concrete `impl DataType for ...` should
    /// delegate to this.
    fn representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        if self.composite_impl_is_not_yet_defined() {
            "<Empty-Structure>".to_string()
        } else {
            String::new()
        }
    }

    /// Port of `StructureDataType.getDefaultLabelPrefix()`. Exposed under a distinct name since
    /// [`DataType::get_default_label_prefix`](crate::program::model::data::data_type::DataType::get_default_label_prefix)
    /// already provides a (placeholder, `None`) default. A concrete `impl DataType for ...` should
    /// delegate to this.
    fn default_label_prefix(&self) -> Option<String> {
        Some(self.get_name())
    }

    /// Port of `StructureDataType.getNumComponents()`. Exposed under a distinct name since
    /// [`Composite::get_num_components`](crate::program::model::data::composite::Composite::get_num_components)
    /// already provides a (placeholder) default. A concrete `impl Composite for ...` should
    /// delegate to this.
    fn structure_data_type_get_num_components(&self) -> i32 {
        self.stored_num_components()
    }

    /// Port of `StructureDataType.getNumDefinedComponents()`. Exposed under a distinct name since
    /// [`Composite::get_num_defined_components`](crate::program::model::data::composite::Composite::get_num_defined_components)
    /// already provides a (placeholder) default. A concrete `impl Composite for ...` should
    /// delegate to this.
    fn structure_data_type_get_num_defined_components(&self) -> i32 {
        self.components().len() as i32
    }

    /// Port of `StructureDataType.getDefinedComponents()`. Exposed under a distinct name since
    /// [`Composite::get_defined_components`](crate::program::model::data::composite::Composite::get_defined_components)
    /// already provides a (placeholder) default. Returns borrowed references directly (rather than
    /// `Box<dyn DataTypeComponent>`, which the `Composite` trait signature requires) since this is
    /// a new method free to choose its own shape; a concrete `impl Composite for ...` that needs
    /// the boxed form can box a [`DataTypeComponentImpl::snapshot`]-based copy of each entry.
    fn structure_data_type_get_defined_components(&self) -> Vec<&DataTypeComponentImpl> {
        self.components().iter().collect()
    }

    /// Port of `StructureDataType.getComponent(int)`: returns the defined component at `ordinal`
    /// if one exists there, or else synthesizes a fresh 1-byte "undefined" filler component (see
    /// `DataType.DEFAULT` ([`DefaultDataType`])) at the appropriate offset. Exposed under a distinct name since
    /// [`Composite::get_component`](crate::program::model::data::composite::Composite::get_component)
    /// already provides a (placeholder) default.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn structure_data_type_get_component(&self, ordinal: i32) -> Result<DataTypeComponentImpl, String> {
        if ordinal < 0 || ordinal >= self.stored_num_components() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        match self
            .components()
            .binary_search_by(|dtc| compare_component_to_ordinal(dtc, ordinal))
        {
            Ok(index) => Ok(self.components()[index].snapshot()),
            Err(insert_index) => {
                let offset = if insert_index == 0 {
                    ordinal
                } else {
                    let dtc = &self.components()[insert_index - 1];
                    let mut offset = dtc.get_end_offset() + ordinal - dtc.get_ordinal();
                    if dtc.get_length() == 0 {
                        offset -= 1;
                    }
                    offset
                };
                Ok(DataTypeComponentImpl::new(
                    DefaultDataType::boxed(),
                    None,
                    1,
                    ordinal,
                    offset,
                    None,
                    None,
                ))
            }
        }
    }

    /// Port of `StructureDataType.getComponents()`: every component (defined and synthesized
    /// undefined filler alike), one per ordinal from `0` to `getNumComponents() - 1`. Exposed
    /// under a distinct name since
    /// [`Composite::get_components`](crate::program::model::data::composite::Composite::get_components)
    /// already provides a (placeholder) default.
    fn structure_data_type_get_components(&self) -> Vec<DataTypeComponentImpl> {
        (0..self.stored_num_components())
            .map(|ordinal| {
                self.structure_data_type_get_component(ordinal)
                    .expect("ordinal within [0, numComponents) is always valid")
            })
            .collect()
    }

    /// Port of `DataTypeUtilities.checkAncestry(DataType, DataType)`, called as
    /// `checkAncestry(this, componentDataType)` throughout this trait's `add`/`insert`/
    /// `insertAtOffset`/`replaceWith` methods. Rejects `component_data_type` if adding it to this
    /// structure would create a cyclic composite (i.e. this structure is already reachable
    /// somewhere within `component_data_type`'s own composition tree).
    ///
    /// # Errors
    /// Returns `Err` if `component_data_type` has this structure within it (mirrors
    /// `DataTypeDependencyException`).
    fn structure_data_type_check_ancestry(&self, component_data_type: &dyn DataType) -> Result<(), String> {
        if is_part_of_data_type_by_ref(component_data_type, self) {
            return Err(format!(
                "DataTypeDependencyException: Data type {} has {} within it.",
                component_data_type.get_display_name(),
                self.get_display_name()
            ));
        }
        Ok(())
    }

    /// Port of `StructureDataType.add(DataType, int, String, String)`: `doAdd` with
    /// `packAndNotify = true`.
    ///
    /// # Errors
    /// See [`structure_data_type_do_add`](Self::structure_data_type_do_add).
    fn structure_data_type_add(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        self.structure_data_type_do_add(data_type, length, component_name, comment, true)
    }

    /// Port of the private `StructureDataType.doAdd(DataType, int, String, String, boolean)`:
    /// adds a new component to the end of this structure. Unlike an insert at the end, a
    /// non-packed structure always grows by a positive `length` when one is given.
    ///
    /// The returned component reflects the layout after any repack (Java returns the live
    /// component object, which the repack updates in place).
    ///
    /// # Errors
    /// Returns `Err` if the data type is not allowed in a composite or a positive length cannot be
    /// determined for it (mirrors `IllegalArgumentException`), or if `data_type` would create a
    /// cyclic composite (mirrors `DataTypeDependencyException`).
    fn structure_data_type_do_add(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
        pack_and_notify: bool,
    ) -> Result<DataTypeComponentImpl, String> {
        let data_type = self.composite_impl_validate_data_type(data_type)?;
        self.structure_data_type_check_ancestry(data_type.as_ref())?;

        let num_components = self.stored_num_components();
        let struct_length = self.stored_struct_length();

        if data_type.is_default_data_type() {
            // assume non-packed structure - will grow by 1-byte; DEFAULT components are never
            // stored in the defined-component list
            self.set_stored_num_components(num_components + 1);
            self.set_stored_struct_length(struct_length + 1);
            return Ok(DataTypeComponentImpl::new(data_type, None, 1, num_components, struct_length, None, None));
        }

        let dynamic_specifiable = is_dynamic_with_specifiable_length(data_type.as_ref());
        let component_length =
            self.composite_impl_preferred_component_length_default(data_type.as_ref(), dynamic_specifiable, length)?;

        let dtc = DataTypeComponentImpl::new(
            data_type,
            None,
            component_length,
            num_components,
            struct_length,
            component_name,
            comment,
        );
        self.components_mut().push(dtc);

        let mut structure_growth = component_length;
        if structure_growth != 0 && !self.is_packing_enabled() && length > 0 {
            structure_growth = length;
        }

        self.set_stored_num_components(num_components + 1);
        self.set_stored_struct_length(struct_length + structure_growth);

        if pack_and_notify && self.is_packing_enabled() {
            self.structure_data_type_repack(false);
        }

        Ok(self.component_snapshot(self.components().len() - 1))
    }

    /// Port of `StructureDataType.shiftOffsets(int, int, int)`: shift every defined component
    /// from `index` onward by `delta_ordinal`/`delta_offset`, and adjust `structLength`/
    /// `numComponents` to match.
    fn structure_data_type_shift_offsets(&mut self, index: usize, delta_ordinal: i32, delta_offset: i32) {
        if delta_offset == 0 && delta_ordinal == 0 {
            return;
        }
        for dtc in self.components_mut().iter_mut().skip(index) {
            dtc.set_offset(dtc.get_offset() + delta_offset);
            dtc.set_ordinal(dtc.get_ordinal() + delta_ordinal);
        }
        let new_length = self.stored_struct_length() + delta_offset;
        self.set_stored_struct_length(new_length);
        let new_num = self.stored_num_components() + delta_ordinal;
        self.set_stored_num_components(new_num);
    }

    /// Port of the private `StructureDataType.backupToFirstComponentContainingOffset(int, int)`.
    fn structure_data_type_backup_to_first_component_containing_offset(&self, index: i32, offset: i32) -> i32 {
        if index == 0 {
            return 0;
        }
        let mut index = index;
        while index != 0 {
            let previous = &self.components()[(index - 1) as usize];
            if !previous.contains_offset(offset) {
                break;
            }
            index -= 1;
        }
        index
    }

    /// Port of the private `StructureDataType.afterNonZeroComponentsAtOffset(int, int)`.
    fn structure_data_type_after_non_zero_components_at_offset(&self, index: i32, offset: i32) -> i32 {
        let max_index = self.components().len() as i32;
        let mut index = index;
        while index < max_index {
            let dtc = &self.components()[index as usize];
            if dtc.get_offset() != offset || dtc.get_length() != 0 {
                break;
            }
            index += 1;
        }
        index
    }

    /// Port of the private `StructureDataType.advanceToLastComponentContainingOffset(int, int)`.
    fn structure_data_type_advance_to_last_component_containing_offset(&self, index: i32, offset: i32) -> i32 {
        let mut index = index;
        while (index as usize) < self.components().len().saturating_sub(1) {
            let next = &self.components()[(index + 1) as usize];
            if !next.contains_offset(offset) {
                break;
            }
            index += 1;
        }
        index
    }

    /// Port of `StructureDataType.insertAtOffset(int, DataType, int, String, String)`. See the
    /// module docs for what is skipped (`BitFieldDataType` handling, `dataType.clone(dataMgr)`,
    /// real packed-structure repacking).
    ///
    /// # Errors
    /// Returns `Err` if `offset` is negative, or a positive length cannot be determined for the
    /// specified data type (mirrors `IllegalArgumentException`), or if `data_type` would create a
    /// cyclic composite (mirrors `DataTypeDependencyException`).
    fn structure_data_type_insert_at_offset(
        &mut self,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        if offset < 0 {
            return Err("IllegalArgumentException: Offset cannot be negative.".to_string());
        }

        let data_type = self.composite_impl_validate_data_type(data_type)?;
        self.structure_data_type_check_ancestry(data_type.as_ref())?;
        let dynamic_specifiable = is_dynamic_with_specifiable_length(data_type.as_ref());
        let length = self.composite_impl_preferred_component_length_default(
            data_type.as_ref(),
            dynamic_specifiable,
            length,
        )?;

        if offset > self.stored_struct_length() && !self.is_packing_enabled() {
            let grow = offset - self.stored_struct_length();
            self.set_stored_num_components(self.stored_num_components() + grow);
            self.set_stored_struct_length(offset);
        }

        let search = self
            .components()
            .binary_search_by(|dtc| compare_component_to_offset(dtc, offset));
        let mut additional_shift = 0;
        let index = match search {
            Ok(found) => {
                let mut idx = self
                    .structure_data_type_backup_to_first_component_containing_offset(found as i32, offset);
                idx = self.structure_data_type_after_non_zero_components_at_offset(idx, offset);
                if length != 0 && (idx as usize) < self.components().len() {
                    let dtc = &self.components()[idx as usize];
                    additional_shift = offset - dtc.get_offset();
                }
                idx
            }
            Err(insert_at) => insert_at as i32,
        };

        let mut ordinal = offset;
        if index > 0 {
            let dtc = &self.components()[(index - 1) as usize];
            ordinal = dtc.get_ordinal();
            if dtc.get_offset() == offset {
                ordinal += 1;
            } else {
                ordinal += offset - dtc.get_end_offset();
            }
        }

        if data_type.is_default_data_type() {
            self.structure_data_type_shift_offsets(
                index as usize,
                1 + additional_shift,
                1 + additional_shift,
            );
            return Ok(DataTypeComponentImpl::new(data_type, None, 1, ordinal, offset, None, None));
        }

        let dtc = DataTypeComponentImpl::new(
            data_type,
            None,
            length,
            ordinal,
            offset,
            component_name,
            comment,
        );
        self.structure_data_type_shift_offsets(index as usize, 1 + additional_shift, length + additional_shift);
        self.components_mut().insert(index as usize, dtc);

        self.structure_data_type_repack(false);
        // notifySizeChanged(): no-op, see module docs.

        Ok(self.components()[index as usize].snapshot())
    }

    /// Port of `StructureDataType.insert(int, DataType, int, String, String)`. See the module
    /// docs for what is skipped (bitfield-overlap shifting, `dataType.clone(dataMgr)`, real
    /// packed-structure repacking).
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds, a positive length cannot be determined for
    /// the specified data type (mirrors `IndexOutOfBoundsException`/`IllegalArgumentException`),
    /// or `data_type` would create a cyclic composite (mirrors `DataTypeDependencyException`).
    fn structure_data_type_insert(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        if ordinal < 0 || ordinal > self.stored_num_components() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        if ordinal == self.stored_num_components() {
            return self.structure_data_type_add(data_type, length, component_name, comment);
        }

        let data_type = self.composite_impl_validate_data_type(data_type)?;
        self.structure_data_type_check_ancestry(data_type.as_ref())?;

        let idx = if self.is_packing_enabled() {
            ordinal
        } else {
            match self
                .components()
                .binary_search_by(|dtc| compare_component_to_ordinal(dtc, ordinal))
            {
                Ok(found) => found as i32,
                Err(insert_at) => insert_at as i32,
            }
        };

        if data_type.is_default_data_type() {
            self.structure_data_type_shift_offsets(idx as usize, 1, 1);
            return self.structure_data_type_get_component(ordinal);
        }

        let dynamic_specifiable = is_dynamic_with_specifiable_length(data_type.as_ref());
        let length = self.composite_impl_preferred_component_length_default(
            data_type.as_ref(),
            dynamic_specifiable,
            length,
        )?;

        let offset = self.structure_data_type_get_component(ordinal)?.get_offset();
        let dtc = DataTypeComponentImpl::new(
            data_type,
            None,
            length,
            ordinal,
            offset,
            component_name,
            comment,
        );
        self.structure_data_type_shift_offsets(idx as usize, 1, length);
        self.components_mut().insert(idx as usize, dtc);

        self.structure_data_type_repack(false);
        // notifySizeChanged(): no-op, see module docs.

        Ok(self.components()[idx as usize].snapshot())
    }

    /// Port of `StructureDataType.addBitField(DataType, int, String, String)`. See the module
    /// docs for what is skipped (`baseDataType.clone(dataMgr)`, `data_type.add_parent(self)`).
    ///
    /// # Errors
    /// Returns `Err` if `base_data_type` is not a valid bitfield base type (mirrors
    /// `InvalidDataTypeException`), or if a positive length cannot be determined (mirrors
    /// `IllegalArgumentException`, via [`structure_data_type_add`](StructureDataType::structure_data_type_add)).
    fn structure_data_type_add_bit_field(
        &mut self,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        check_base_data_type(base_data_type.as_ref())
            .map_err(|e| format!("InvalidDataTypeException: {}", e.message()))?;
        // baseDataType.clone(dataMgr) skipped, see module docs.
        let bit_field_dt = BitFieldDataType::new_at_offset_zero(base_data_type, bit_size)
            .map_err(|e| format!("InvalidDataTypeException: {}", e.message()))?;
        let storage_size = bit_field_dt.get_storage_size();
        self.structure_data_type_add(Box::new(bit_field_dt), storage_size, component_name, comment)
    }

    /// Port of `StructureDataType.insertBitField(int, int, int, DataType, int, String, String)`.
    /// See the module docs for what is skipped (`baseDataType.clone(dataMgr)`).
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`), if
    /// `base_data_type` is not a valid bitfield base type (mirrors `InvalidDataTypeException`), or
    /// if a positive length cannot be determined (mirrors `IllegalArgumentException`).
    fn structure_data_type_insert_bit_field(
        &mut self,
        ordinal: i32,
        byte_width: i32,
        bit_offset: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        if ordinal < 0 || ordinal > self.stored_num_components() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        check_base_data_type(base_data_type.as_ref())
            .map_err(|e| format!("InvalidDataTypeException: {}", e.message()))?;
        // baseDataType.clone(dataMgr) skipped, see module docs.

        if !self.is_packing_enabled() {
            let offset = if ordinal < self.stored_num_components() {
                self.structure_data_type_get_component(ordinal)?.get_offset()
            } else {
                self.stored_struct_length()
            };
            return self.structure_data_type_insert_bit_field_at(
                offset,
                byte_width,
                bit_offset,
                base_data_type,
                bit_size,
                component_name,
                comment,
            );
        }

        // handle aligned bitfield insertion
        let bit_field_dt = BitFieldDataType::new_at_offset_zero(base_data_type, bit_size)
            .map_err(|e| format!("InvalidDataTypeException: {}", e.message()))?;
        let storage_size = bit_field_dt.get_storage_size();
        self.structure_data_type_insert(ordinal, Box::new(bit_field_dt), storage_size, component_name, comment)
    }

    /// Port of `StructureDataType.insertBitFieldAt(int, int, int, DataType, int, String,
    /// String)`. Intended for use with non-packed structures where the bitfield must be placed
    /// precisely; see the module docs for what is skipped (`baseDataType.clone(dataMgr)`,
    /// `bitfieldDt.addParent(this)`).
    ///
    /// NOTE: matching Java exactly, the `is_packing_enabled()` branch below performs a *nested*
    /// [`structure_data_type_insert_bit_field`](StructureDataType::structure_data_type_insert_bit_field)
    /// call whose return value is discarded, purely for its side effect on `components`/
    /// `numComponents`/`structLength` -- and this method still unconditionally inserts its *own*
    /// component afterward too. This looks like a latent quirk in the original Java (calling this
    /// particular entry point directly against a packing-enabled structure is unusual; ordinary
    /// packed-bitfield insertion goes through
    /// [`structure_data_type_insert_bit_field`](StructureDataType::structure_data_type_insert_bit_field)
    /// directly, which never reaches this method), but it is ported verbatim rather than "fixed"
    /// per this crate's faithful-porting policy.
    ///
    /// # Errors
    /// Returns `Err` if `byte_offset`/`bit_size` is negative or `byte_width` is non-positive, or
    /// too small for the requested bitfield (mirrors `IllegalArgumentException`), or if
    /// `base_data_type` is not a valid bitfield base type (mirrors `InvalidDataTypeException`).
    fn structure_data_type_insert_bit_field_at(
        &mut self,
        byte_offset: i32,
        byte_width: i32,
        bit_offset: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        if byte_offset < 0 || bit_size < 0 {
            return Err(
                "IllegalArgumentException: Negative values not permitted when defining bitfield".to_string(),
            );
        }
        if byte_width <= 0 {
            return Err("IllegalArgumentException: Invalid byteWidth".to_string());
        }

        check_base_data_type(base_data_type.as_ref())
            .map_err(|e| format!("InvalidDataTypeException: {}", e.message()))?;
        // baseDataType.clone(dataMgr) skipped, see module docs.
        let base_data_type: Arc<dyn DataType> = Arc::from(base_data_type);

        let effective_bit_size = get_effective_bit_size(bit_size, base_data_type.get_length());

        let min_byte_width = get_minimum_storage_size_no_offset(effective_bit_size + bit_offset);
        if byte_width < min_byte_width {
            return Err("IllegalArgumentException: Bitfield does not fit within specified constraints".to_string());
        }

        let big_endian = self.get_data_organization().is_big_endian();

        let mut has_conflict = false;
        let mut additional_shift = 0i32;

        let start_bit_offset =
            get_normalized_bitfield_offset(byte_offset, byte_width, effective_bit_size, bit_offset, big_endian);

        let start_index = match self
            .components()
            .binary_search_by(|dtc| compare_component_to_bit_offset(dtc, start_bit_offset, big_endian))
        {
            Err(insert_at) => insert_at as i32,
            Ok(found) => {
                has_conflict = true;
                let dtc = &self.components()[found];
                if bit_size == 0 || dtc.is_zero_bit_field_component() {
                    has_conflict = dtc.get_offset() != (start_bit_offset / 8);
                }
                if has_conflict {
                    additional_shift = byte_offset - dtc.get_offset();
                }
                found as i32
            }
        };

        let ordinal = if (start_index as usize) < self.components().len() {
            self.components()[start_index as usize].get_ordinal()
        } else {
            start_index
        };

        if self.is_packing_enabled() {
            // See this method's own doc comment: ported verbatim, including the discarded return
            // value and the unconditional insertion that still follows below.
            let _ = self.structure_data_type_insert_bit_field(
                ordinal,
                0,
                0,
                share_data_type(&base_data_type),
                effective_bit_size,
                component_name.clone(),
                comment.clone(),
            );
        }

        let mut end_index = start_index;
        if (start_index as usize) < self.components().len() {
            let mut end_bit_offset = start_bit_offset;
            if effective_bit_size != 0 {
                end_bit_offset += effective_bit_size - 1;
            }
            end_index = match self
                .components()
                .binary_search_by(|dtc| compare_component_to_bit_offset(dtc, end_bit_offset, big_endian))
            {
                Err(insert_at) => insert_at as i32,
                Ok(found) => {
                    if effective_bit_size != 0 {
                        has_conflict = true;
                    }
                    found as i32
                }
            };
        }

        if start_index != end_index {
            has_conflict = true;
        }

        if has_conflict {
            self.structure_data_type_shift_offsets(start_index as usize, 1, byte_width + additional_shift);
        }

        let required_length = byte_offset + byte_width;
        if required_length > self.stored_struct_length() {
            self.set_stored_struct_length(required_length);
        }

        let storage_bit_offset = bit_offset % 8;
        let revised_offset = if big_endian {
            byte_offset + byte_width - ((effective_bit_size + bit_offset + 7) / 8)
        } else {
            byte_offset + (bit_offset / 8)
        };

        let bit_field_dt = BitFieldDataType::new(share_data_type(&base_data_type), bit_size, storage_bit_offset)
            .map_err(|e| format!("InvalidDataTypeException: {}", e.message()))?;
        let storage_size = bit_field_dt.get_storage_size();

        let dtc = DataTypeComponentImpl::new(
            Box::new(bit_field_dt),
            None,
            storage_size,
            ordinal,
            revised_offset,
            component_name,
            comment,
        );
        // bitfieldDt.addParent(this): no-op, see module docs.
        self.components_mut().insert(start_index as usize, dtc);

        self.structure_data_type_adjust_non_packed_components();
        // notifySizeChanged(): no-op, see module docs.

        Ok(self.components()[start_index as usize].snapshot())
    }

    /// Port of `StructureDataType.repack(boolean)`. Returns `true` if a layout change was
    /// detected.
    ///
    /// The packing-enabled branch delegates to
    /// [`structure_data_type_pack`](StructureDataType::structure_data_type_pack) (real
    /// `AlignedStructurePacker` integration); the non-packed branch performs the adjustment
    /// ([`structure_data_type_adjust_non_packed_components`](StructureDataType::structure_data_type_adjust_non_packed_components))
    /// faithfully, matching Java's `!isPackingEnabled()` branch. Unlike Java, no `structAlignment`
    /// field is cached/compared here (see the module docs on `composite_impl_alignment`), so an
    /// alignment-only change with an unchanged length/component-count is not separately detected
    /// as "changed" -- this only matters for the `notify` path, which is a no-op in this port
    /// regardless (see the module docs on `notifySizeChanged`/`notifyAlignmentChanged`).
    fn structure_data_type_repack(&mut self, notify: bool) -> bool {
        let old_length = self.stored_struct_length();
        let changed = if !self.is_packing_enabled() {
            self.structure_data_type_adjust_non_packed_components()
        } else {
            self.structure_data_type_pack()
        };
        if changed && notify && old_length != self.stored_struct_length() {
            // notifySizeChanged(): no-op, see module docs.
        }
        changed
    }

    /// Port of the packing-enabled branch of `StructureDataType.repack(boolean)`: delegates the
    /// actual alignment-driven layout computation to
    /// [`AlignedStructurePacker::pack_components`](AlignedStructurePacker::pack_components) (this
    /// trait's new [`AlignedStructurePacker`] supertrait bound), converting this structure's
    /// `Vec<DataTypeComponentImpl>` to and from the `Box<dyn InternalDataTypeComponent>` shape
    /// that method requires via the [`PackableComponent`] adapter. Returns `true` if a layout
    /// change was detected, matching Java's `componentsChanged || (structLength changed) ||
    /// (numComponents changed)` (the `structAlignment` comparison term is dropped -- see
    /// [`structure_data_type_repack`](StructureDataType::structure_data_type_repack)'s own doc
    /// comment).
    ///
    /// NOTE: the quality of the computed layout depends entirely on whatever
    /// [`AlignedStructurePacker::create_component_packer`] a concrete `StructureDataType`
    /// implementor supplies; [`StructureDataType`] (this crate's real, production
    /// implementation) supplies the genuine, bitfield-aware
    /// [`aligned_component_packer::AlignedComponentPacker`](super::aligned_component_packer::AlignedComponentPacker)
    /// port (2026-09).
    fn structure_data_type_pack(&mut self) -> bool {
        let old_length = self.stored_struct_length();
        let old_num_components = self.stored_num_components();

        let old_components = std::mem::take(self.components_mut());
        let mut packable: Vec<Box<dyn InternalDataTypeComponent>> = old_components
            .iter()
            .map(|dtc| Box::new(PackableComponent::from_snapshot(dtc)) as Box<dyn InternalDataTypeComponent>)
            .collect();

        let result = self.pack_components(&*self, &mut packable);

        *self.components_mut() = packable.into_iter().map(rebuild_packed_component).collect();

        self.set_stored_struct_length(result.structure_length);
        self.set_stored_num_components(result.num_components);

        result.components_changed
            || old_length != result.structure_length
            || old_num_components != result.num_components
    }

    /// Port of the private `StructureDataType.adjustNonPackedComponents()`: recompute each
    /// defined component's ordinal (accounting for undefined filler components implicitly
    /// occupying the gaps between/after them) and the overall `numComponents` count. Returns
    /// `true` if anything changed.
    fn structure_data_type_adjust_non_packed_components(&mut self) -> bool {
        let mut changed = false;
        let mut component_count = 0i32;
        let mut current_offset = 0i32;
        for dtc in self.components_mut().iter_mut() {
            let component_length = dtc.get_length();
            let component_offset = dtc.get_offset();
            let num_undefined_before = component_offset - current_offset;
            if num_undefined_before > 0 {
                component_count += num_undefined_before;
            }
            current_offset = component_offset + component_length;
            if dtc.get_ordinal() != component_count {
                dtc.set_ordinal(component_count);
                changed = true;
            }
            component_count += 1;
        }

        let num_undefined_after = self.stored_struct_length() - current_offset;
        component_count += num_undefined_after;
        if self.stored_num_components() != component_count {
            self.set_stored_num_components(component_count);
            changed = true;
        }
        // Alignment re-caching (Java's `structAlignment` field) intentionally not touched here;
        // see the module docs re: `composite_impl_alignment` being left to the concrete
        // implementor pending `AlignedStructureInspector` integration.
        changed
    }

    /// Port of `StructureDataType.isEquivalent(DataType)`. Java's `instanceof StructureInternal`
    /// test is [`DataType::as_structure`]; the other structure's stored packing and minimum
    /// alignment values are recovered from its public packing/alignment API
    /// ([`stored_packing_value_of`]/[`stored_minimum_alignment_of`]).
    fn structure_data_type_is_equivalent(&self, data_type: &dyn DataType) -> bool {
        if std::ptr::addr_eq(data_type as *const dyn DataType, self as *const Self) {
            return true;
        }
        let Some(other) = data_type.as_structure() else {
            return false;
        };
        let other_length = if other.is_zero_length() { 0 } else { other.get_length() };
        let packing = self.stored_packing_value();
        if packing != stored_packing_value_of(other)
            || self.stored_minimum_alignment_value() != stored_minimum_alignment_of(other)
            || (packing == NO_PACKING && self.stored_struct_length() != other_length)
        {
            return false;
        }

        let my_num_comps = self.components().len();
        if my_num_comps as i32 != other.get_num_defined_components() {
            return false;
        }
        let other_defined_components = other.get_defined_components();
        if other_defined_components.len() != my_num_comps {
            // safety check
            return false;
        }
        let packed = self.is_packing_enabled();
        self.components()
            .iter()
            .zip(other_defined_components.iter())
            .all(|(mine, theirs)| mine.is_equivalent_within(theirs.as_ref(), packed))
    }

    /// Port of `StructureDataType.replaceWith(DataType)`: replaces this structure's components
    /// with those of `data_type` (which must be a structure), including its packing and alignment
    /// settings.
    ///
    /// NOTE: unlike adding new components (which guarantees field-name uniqueness), this preserves
    /// the other structure's component names verbatim, matching Java.
    ///
    /// # Errors
    /// Returns `Err` if `data_type` is not a structure (mirrors Java's bare
    /// `IllegalArgumentException`), or if a component data type would create a cyclic composite
    /// (mirrors the `DataTypeDependencyException` Java rethrows as `IllegalArgumentException`).
    fn structure_data_type_replace_with(&mut self, data_type: &dyn DataType) -> Result<(), String> {
        let Some(other) = data_type.as_structure() else {
            return Err("IllegalArgumentException".to_string());
        };

        self.components_mut().clear();
        self.set_stored_num_components(0);
        self.set_stored_struct_length(0);
        self.struct_alignment = -1;

        self.set_stored_packing_value_raw(stored_packing_value_of(other));
        self.set_stored_minimum_alignment_value(stored_minimum_alignment_of(other));

        if other.is_packing_enabled() {
            // doReplaceWithPacked
            for dtc in other.get_defined_components() {
                let dt = dtc.get_data_type();
                let length = if dt.as_dynamic().is_some() { dtc.get_length() } else { -1 };
                self.structure_data_type_do_add(dt, length, dtc.get_field_name(), dtc.get_comment(), false)?;
            }
        } else if !other.is_not_yet_defined() {
            // doReplaceWithNonPacked
            let new_length = if other.is_zero_length() { 0 } else { other.get_length() };
            self.set_stored_struct_length(new_length);
            self.set_stored_num_components(new_length);

            let other_components = other.get_defined_components();
            let count = other_components.len();
            for (i, dtc) in other_components.iter().enumerate() {
                let dt = dtc.get_data_type();
                self.structure_data_type_check_ancestry(dt.as_ref())?;
                let is_dynamic = dt.as_dynamic().is_some();
                let length = if dtc.is_bit_field_component() || is_dynamic {
                    dtc.get_length()
                } else {
                    // determine maxLength for fixed-length types
                    let max_offset = if i + 1 < count {
                        other_components[i + 1].get_offset()
                    } else {
                        self.stored_struct_length()
                    };
                    let max_length = max_offset - dtc.get_offset();
                    self.composite_impl_preferred_component_length(
                        dt.as_ref(),
                        is_dynamic_with_specifiable_length(dt.as_ref()),
                        -1,
                        max_length,
                    )?
                };
                // Note: original component name is preserved
                let new_dtc = DataTypeComponentImpl::new(
                    dt,
                    None,
                    length,
                    dtc.get_ordinal(),
                    dtc.get_offset(),
                    dtc.get_field_name(),
                    dtc.get_comment(),
                );
                self.components_mut().push(new_dtc);
            }
        }

        self.structure_data_type_repack(false);
        Ok(())
    }

    /// Port of the private `StructureDataType.doDelete(int)`. See the module docs re:
    /// `dtc.getDataType().removeParent(this)` being skipped (no parent-notification wiring).
    fn structure_data_type_do_delete(&mut self, index: usize) -> DataTypeComponentImpl {
        self.components_mut().remove(index)
    }

    /// Port of the private `StructureDataType.doDeleteWithComponentShift(int, boolean)`.
    fn structure_data_type_do_delete_with_component_shift(
        &mut self,
        index: usize,
        disable_offset_shift: bool,
    ) -> DataTypeComponentImpl {
        let dtc = self.structure_data_type_do_delete(index);
        if self.is_packing_enabled() {
            return dtc;
        }
        let shift_amount = if disable_offset_shift || dtc.is_bit_field_component() {
            0
        } else {
            dtc.get_length()
        };
        self.structure_data_type_shift_offsets(index, -1, -shift_amount);
        dtc
    }

    /// Port of `StructureDataType.delete(int)`.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn structure_data_type_delete(&mut self, ordinal: i32) -> Result<(), String> {
        if ordinal < 0 || ordinal >= self.stored_num_components() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        if self.is_packing_enabled() {
            self.structure_data_type_do_delete_with_component_shift(ordinal as usize, false);
        } else {
            match self
                .components()
                .binary_search_by(|dtc| compare_component_to_ordinal(dtc, ordinal))
            {
                Ok(idx) => {
                    self.structure_data_type_do_delete_with_component_shift(idx, false);
                }
                Err(idx) => {
                    // Assume non-packed removal of an undefined (DEFAULT) filler component.
                    self.structure_data_type_shift_offsets(idx, -1, -1);
                }
            }
        }
        self.structure_data_type_repack(false);
        // notifySizeChanged(): no-op, see module docs.
        Ok(())
    }

    /// Port of `StructureDataType.delete(Set<Integer>)`: batch-delete every listed ordinal in a
    /// single pass, correctly accounting for undefined-filler ordinals interleaved between the
    /// listed ones (non-packed case) rather than repeatedly calling
    /// [`structure_data_type_delete`](StructureDataType::structure_data_type_delete) per ordinal
    /// (which the `ordinals.size() == 1` fast path below still does, matching Java).
    ///
    /// # Errors
    /// Returns `Err` if any ordinal is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn structure_data_type_delete_ordinals(&mut self, ordinals: &HashSet<i32>) -> Result<(), String> {
        if ordinals.is_empty() {
            return Ok(());
        }
        if ordinals.len() == 1 {
            let ordinal = *ordinals.iter().next().expect("checked len == 1 above");
            return self.structure_data_type_delete(ordinal);
        }

        use std::collections::BTreeSet;
        use std::ops::Bound::{Excluded, Unbounded};

        let sorted_ordinals: BTreeSet<i32> = ordinals.iter().copied().collect();
        let first_ordinal = *sorted_ordinals.iter().next().expect("checked non-empty above");
        let last_ordinal = *sorted_ordinals.iter().next_back().expect("checked non-empty above");
        let num_components = self.stored_num_components();
        if first_ordinal < 0 || last_ordinal >= num_components {
            return Err(format!(
                "IndexOutOfBoundsException: {} ordinals specified",
                ordinals.len()
            ));
        }

        let mut next_ordinal = Some(first_ordinal);
        let mut ordinal_adjustment = 0i32;
        let mut offset_adjustment = 0i32;
        let mut last_defined_ordinal = -1i32;
        let is_packed = self.is_packing_enabled();
        let mut bitfield_removed = false;

        let old_components = std::mem::take(self.components_mut());
        let mut new_components = Vec::with_capacity(old_components.len());

        for mut dtc in old_components {
            let ordinal = dtc.get_ordinal();
            if !is_packed {
                if let Some(next) = next_ordinal {
                    if next < ordinal {
                        let removed_filler: Vec<i32> = sorted_ordinals
                            .range((Excluded(last_defined_ordinal), Excluded(ordinal)))
                            .copied()
                            .collect();
                        if !removed_filler.is_empty() {
                            let undefined_remove_count = removed_filler.len() as i32;
                            ordinal_adjustment -= undefined_remove_count;
                            offset_adjustment -= undefined_remove_count;
                            let last_removed = *removed_filler.last().expect("checked non-empty above");
                            next_ordinal = sorted_ordinals
                                .range((Excluded(last_removed), Unbounded))
                                .next()
                                .copied();
                        }
                    }
                }
            }

            if next_ordinal == Some(ordinal) {
                if dtc.is_bit_field_component() {
                    bitfield_removed = true;
                } else {
                    offset_adjustment -= dtc.get_length();
                }
                ordinal_adjustment -= 1;
                last_defined_ordinal = ordinal;
                next_ordinal = sorted_ordinals
                    .range((Excluded(ordinal), Unbounded))
                    .next()
                    .copied();
            } else {
                if ordinal_adjustment != 0 {
                    dtc.set_offset(dtc.get_offset() + offset_adjustment);
                    dtc.set_ordinal(dtc.get_ordinal() + ordinal_adjustment);
                }
                last_defined_ordinal = ordinal;
                new_components.push(dtc);
            }
        }

        if !is_packed {
            let removed_filler_count = sorted_ordinals
                .range((Excluded(last_defined_ordinal), Excluded(num_components)))
                .count() as i32;
            if removed_filler_count > 0 {
                ordinal_adjustment -= removed_filler_count;
                offset_adjustment -= removed_filler_count;
            }
        }

        *self.components_mut() = new_components;
        self.set_stored_num_components(num_components + ordinal_adjustment);

        if is_packed {
            self.structure_data_type_repack(true);
        } else {
            self.set_stored_struct_length(self.stored_struct_length() + offset_adjustment);
            if bitfield_removed {
                self.structure_data_type_repack(false);
            }
            // notifySizeChanged(): no-op, see module docs.
        }
        Ok(())
    }

    /// Port of `StructureDataType.deleteAtOffset(int)`.
    ///
    /// # Errors
    /// Returns `Err` if `offset` is negative (mirrors `IllegalArgumentException`).
    fn structure_data_type_delete_at_offset(&mut self, offset: i32) -> Result<(), String> {
        if offset < 0 {
            return Err("IllegalArgumentException: Offset cannot be negative.".to_string());
        }
        if offset > self.stored_struct_length() {
            return Ok(());
        }
        match self
            .components()
            .binary_search_by(|dtc| compare_component_to_offset(dtc, offset))
        {
            Err(insert_at) => {
                if offset == self.stored_struct_length() {
                    return Ok(());
                }
                self.structure_data_type_shift_offsets(insert_at, -1, -1);
            }
            Ok(found) => {
                let mut index = self
                    .structure_data_type_advance_to_last_component_containing_offset(found as i32, offset);
                while index >= 0
                    && self.components()[index as usize].contains_offset(offset)
                {
                    self.structure_data_type_do_delete_with_component_shift(index as usize, false);
                    index -= 1;
                }
            }
        }
        self.structure_data_type_repack(false);
        // notifySizeChanged(): no-op, see module docs.
        Ok(())
    }

    /// Port of `StructureDataType.clearAtOffset(int)`: like
    /// [`structure_data_type_delete_at_offset`](StructureDataType::structure_data_type_delete_at_offset)
    /// but preserves the structure length and placement of other components (clears in place
    /// rather than shifting).
    ///
    /// # Errors
    /// Returns `Err` if `offset` is negative (mirrors `IllegalArgumentException`).
    fn structure_data_type_clear_at_offset(&mut self, offset: i32) -> Result<(), String> {
        if offset < 0 {
            return Err("IllegalArgumentException: Offset cannot be negative.".to_string());
        }
        if offset > self.stored_struct_length() {
            return Ok(());
        }
        if let Ok(found) = self
            .components()
            .binary_search_by(|dtc| compare_component_to_offset(dtc, offset))
        {
            let mut index =
                self.structure_data_type_advance_to_last_component_containing_offset(found as i32, offset);
            while index >= 0 && self.components()[index as usize].contains_offset(offset) {
                self.structure_data_type_do_delete_with_component_shift(index as usize, true);
                index -= 1;
            }
        }
        self.structure_data_type_repack(false);
        // notifySizeChanged(): no-op, see module docs.
        Ok(())
    }

    /// Port of `StructureDataType.clearComponent(int)`.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    fn structure_data_type_clear_component(&mut self, ordinal: i32) -> Result<(), String> {
        if self.is_packing_enabled() {
            return self.structure_data_type_delete(ordinal);
        }
        if ordinal < 0 || ordinal >= self.stored_num_components() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        if let Ok(idx) = self
            .components()
            .binary_search_by(|dtc| compare_component_to_ordinal(dtc, ordinal))
        {
            let dtc = self.components_mut().remove(idx);
            let len = dtc.get_length();
            if len > 1 {
                self.structure_data_type_shift_offsets(idx, len - 1, 0);
            }
            self.structure_data_type_repack(false);
        }
        Ok(())
    }

    /// Port of `StructureDataType.deleteAll()`.
    fn structure_data_type_delete_all(&mut self) {
        self.components_mut().clear();
        self.set_stored_struct_length(0);
        self.set_stored_num_components(0);
        // notifySizeChanged(): no-op, see module docs.
    }

    /// Port of the private `StructureDataType.doGrowStructure(int)` plus the public
    /// `growStructure(int)` wrapper (their split exists in Java only so `setLength` can call the
    /// former without `repack`/`notifySizeChanged`, which this crate has no equivalent caller
    /// for yet, so they are merged here).
    ///
    /// # Errors
    /// Returns `Err` if `amount` is negative (mirrors `IllegalArgumentException`).
    fn structure_data_type_grow_structure(&mut self, amount: i32) -> Result<(), String> {
        if amount < 0 {
            return Err(format!("IllegalArgumentException: Invalid growth amount: {amount}"));
        }
        if amount == 0 || self.is_packing_enabled() {
            return Ok(());
        }
        let new_num = self.stored_num_components() + amount;
        self.set_stored_num_components(new_num);
        let new_length = self.stored_struct_length() + amount;
        self.set_stored_struct_length(new_length);
        self.structure_data_type_repack(false);
        // notifySizeChanged(): no-op, see module docs.
        Ok(())
    }

    /// Port of `StructureDataType.setLength(int)`.
    ///
    /// # Errors
    /// Returns `Err` if `len` is negative (mirrors `IllegalArgumentException`).
    fn structure_data_type_set_length(&mut self, len: i32) -> Result<(), String> {
        if len < 0 {
            return Err(format!("IllegalArgumentException: Invalid length: {len}"));
        }
        if len == self.stored_struct_length() || self.is_packing_enabled() {
            return Ok(());
        }
        if len < self.stored_struct_length() {
            let index = match self
                .components()
                .binary_search_by(|dtc| compare_component_to_offset(dtc, len))
            {
                Err(insert_at) => insert_at as i32,
                Ok(found) => {
                    let mut idx = self
                        .structure_data_type_backup_to_first_component_containing_offset(found as i32, len);
                    idx = self.structure_data_type_after_non_zero_components_at_offset(idx, len);
                    idx
                }
            };
            let defined_component_count = self.components().len() as i32;
            if index >= 0 && index < defined_component_count {
                self.components_mut().truncate(index as usize);
            }
        } else {
            let delta = len - self.stored_struct_length();
            self.set_stored_num_components(self.stored_num_components() + delta);
        }
        self.set_stored_struct_length(len);
        self.structure_data_type_repack(false);
        // notifySizeChanged(): no-op, see module docs.
        Ok(())
    }

    /// Port of the private `StructureDataType.generateUndefinedComponent(int, int)`. Unlike
    /// Java's negative-index-encoded `missingComponentIndex` parameter (`Collections.binarySearch`'s
    /// raw "not found" return value, `-insertionPoint - 1`), `missing_component_index` here is
    /// already the plain, non-negative insertion point -- Rust's `Vec::binary_search_by` never
    /// uses Java's encoding trick, so every caller below passes the decoded value directly (the
    /// encode-then-immediately-decode round trip Java performs in a couple of call sites is a
    /// no-op and is elided).
    fn structure_data_type_generate_undefined_component(
        &self,
        offset: i32,
        missing_component_index: i32,
    ) -> DataTypeComponentImpl {
        let mut ordinal = offset;
        if missing_component_index > 0 {
            let dtc = &self.components()[(missing_component_index - 1) as usize];
            ordinal = dtc.get_ordinal() + offset - dtc.get_end_offset();
            if dtc.get_length() == 0 {
                ordinal += 1;
            }
        }
        DataTypeComponentImpl::new(DefaultDataType::boxed(), None, 1, ordinal, offset, None, None)
    }

    /// Port of the private `StructureDataType.indexOfFirstNonZeroLenComponentContainingOffset(int,
    /// int)`.
    fn structure_data_type_index_of_first_non_zero_len_component_containing_offset(
        &self,
        index: i32,
        offset: i32,
    ) -> i32 {
        let mut index = self.structure_data_type_backup_to_first_component_containing_offset(index, offset);
        loop {
            let is_zero_len = self.components()[index as usize].get_length() == 0;
            if !is_zero_len || (index as usize) >= self.components().len() - 1 {
                break;
            }
            let next_contains = self.components()[(index + 1) as usize].contains_offset(offset);
            if !next_contains {
                break;
            }
            index += 1;
        }
        index
    }

    /// Port of `StructureDataType.getDefinedComponentAtOrAfterOffset(int)`.
    fn structure_data_type_get_defined_component_at_or_after_offset(
        &self,
        offset: i32,
    ) -> Option<DataTypeComponentImpl> {
        if offset > self.stored_struct_length() || offset < 0 {
            return None;
        }
        match self
            .components()
            .binary_search_by(|dtc| compare_component_to_offset(dtc, offset))
        {
            Ok(found) => {
                let index =
                    self.structure_data_type_backup_to_first_component_containing_offset(found as i32, offset);
                Some(self.components()[index as usize].snapshot())
            }
            Err(insert_at) => self.components().get(insert_at).map(DataTypeComponentImpl::snapshot),
        }
    }

    /// Port of `StructureDataType.getComponentContaining(int)`.
    fn structure_data_type_get_component_containing(&self, offset: i32) -> Option<DataTypeComponentImpl> {
        if offset > self.stored_struct_length() || offset < 0 {
            return None;
        }
        match self
            .components()
            .binary_search_by(|dtc| compare_component_to_offset(dtc, offset))
        {
            Ok(found) => {
                let index = self
                    .structure_data_type_index_of_first_non_zero_len_component_containing_offset(
                        found as i32,
                        offset,
                    );
                let dtc = &self.components()[index as usize];
                if dtc.get_length() != 0 {
                    return Some(dtc.snapshot());
                }
                if offset != self.stored_struct_length() && !self.is_packing_enabled() {
                    return Some(self.structure_data_type_generate_undefined_component(offset, index));
                }
                None
            }
            Err(insert_at) => {
                if offset != self.stored_struct_length() && !self.is_packing_enabled() {
                    Some(self.structure_data_type_generate_undefined_component(offset, insert_at as i32))
                } else {
                    None
                }
            }
        }
    }

    /// Port of `StructureDataType.getComponentsContaining(int)`.
    fn structure_data_type_get_components_containing(&self, offset: i32) -> Vec<DataTypeComponentImpl> {
        let mut list = Vec::new();
        if offset > self.stored_struct_length() || offset < 0 {
            return list;
        }
        let mut has_sized_component = false;
        let insertion_index = match self
            .components()
            .binary_search_by(|dtc| compare_component_to_offset(dtc, offset))
        {
            Ok(found) => {
                let mut index =
                    self.structure_data_type_backup_to_first_component_containing_offset(found as i32, offset);
                while (index as usize) < self.components().len() {
                    let dtc = &self.components()[index as usize];
                    if !dtc.contains_offset(offset) {
                        break;
                    }
                    has_sized_component |= dtc.get_length() != 0;
                    list.push(dtc.snapshot());
                    index += 1;
                }
                index
            }
            Err(insert_at) => insert_at as i32,
        };
        if !has_sized_component && offset != self.stored_struct_length() && !self.is_packing_enabled() {
            list.push(self.structure_data_type_generate_undefined_component(offset, insertion_index));
        }
        list
    }

    /// Port of `StructureDataType.getDataTypeAt(int)`: the lowest-level component containing
    /// `offset`, recursing into a nested `Structure` component if one is found there.
    fn structure_data_type_get_data_type_at(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
        let dtc = self.structure_data_type_get_component_containing(offset)?;
        let dt = dtc.get_data_type();
        if let Some(inner_struct) = dt.as_structure() {
            return inner_struct.get_data_type_at(offset - dtc.get_offset());
        }
        Some(Box::new(dtc))
    }

    /// Port of the private `StructureDataType.doComponentReplacement(LinkedList<DataTypeComponentImpl>,
    /// int, DataType, int, String, String)`: attempt a "quick update" of a single defined component
    /// in place (no size/alignment/offset change, matching Java's fast-path condition exactly,
    /// including its `dataType.getAlignment() == oldDt.getAlignment()` packed-structure check), or
    /// else fall through to the full [`structure_data_type_replace_components`] sequence-replacement
    /// algorithm followed by a repack.
    ///
    /// `replaced_components` must be non-empty (mirrors Java's unconditional `.get(0)` on a
    /// caller-populated `LinkedList` -- every caller below always populates at least one entry).
    /// The quick-update path is only ever reachable when `replaced_components[0]` is a genuine
    /// defined component already present in [`components`](StructureDataType::components) (a
    /// synthesized undefined-filler placeholder's data type is always the `DataType.DEFAULT` ([`DefaultDataType`])
    /// stand-in, which trips the `oldDt != DEFAULT` check below and forces the full path) -- its
    /// exact list slot is relocated by ordinal (stable at this point, since nothing has been
    /// mutated yet) rather than threaded through as a separate index parameter, since Java relies on
    /// `oldComponent` being the very same object reference stored in `components`.
    ///
    /// # Errors
    /// Returns `Err` if the quick-update path's target ordinal cannot be relocated in
    /// [`components`](StructureDataType::components) (should be unreachable, see above), or
    /// whatever [`structure_data_type_replace_components`] itself can return.
    fn structure_data_type_do_component_replacement(
        &mut self,
        replaced_components: &[DataTypeComponentImpl],
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Option<DataTypeComponentImpl>, String> {
        let old_component = &replaced_components[0];
        let old_dt = old_component.get_data_type();

        let quick_update = replaced_components.len() == 1
            && !old_dt.is_default_data_type()
            && !data_type.is_default_data_type()
            && length == old_component.get_length()
            && offset == old_component.get_offset()
            && (!self.is_packing_enabled() || data_type.get_alignment() == old_dt.get_alignment());

        if quick_update {
            let target_ordinal = old_component.get_ordinal();
            let idx = self
                .components()
                .binary_search_by(|dtc| compare_component_to_ordinal(dtc, target_ordinal))
                .map_err(|_| {
                    "AssertException: quick-update target component not found".to_string()
                })?;
            self.components_mut()[idx].update_special(field_name, data_type, comment);
            return Ok(Some(self.components()[idx].snapshot()));
        }

        let new_component = self.structure_data_type_replace_components(
            replaced_components,
            data_type,
            offset,
            length,
            field_name,
            comment,
        )?;

        self.structure_data_type_repack(false);
        // notifySizeChanged(): no-op, see module docs.

        Ok(new_component)
    }

    /// Port of `StructureDataType.replace(int, DataType, int, String, String)` (the public 3-arg
    /// `replace(int, DataType, int)` overload is just this with `None`/`None` names -- a concrete
    /// `impl Structure for ...` wires both the same way [`Structure::replace`]'s own default
    /// documents). Replaces the defined or synthesized-undefined component at `ordinal` with a new
    /// component of `data_type`, gathering every bit-field that overlaps the replaced component's
    /// byte range (case 3 below) so the whole overlapping run is replaced atomically, matching
    /// Java's `LinkedList`-based `replacedComponents` sequence exactly.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`), a
    /// zero-length component would be replaced with a non-zero-length one outside a packed
    /// structure, a positive length cannot be determined for `data_type`, `data_type` would create
    /// a cyclic composite (mirrors `DataTypeDependencyException`), or there is not enough undefined
    /// space to fit the replacement (all three mirror `IllegalArgumentException`).
    fn structure_data_type_replace(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        if ordinal < 0 || ordinal >= self.stored_num_components() {
            return Err(format!(
                "IndexOutOfBoundsException: ordinal {ordinal} out of bounds"
            ));
        }

        let data_type = self.composite_impl_validate_data_type(data_type)?;
        // dataType.clone(dataMgr): skipped, see module docs.
        self.structure_data_type_check_ancestry(data_type.as_ref())?;

        let dynamic_specifiable = is_dynamic_with_specifiable_length(data_type.as_ref());
        let length = self.composite_impl_preferred_component_length_default(
            data_type.as_ref(),
            dynamic_specifiable,
            length,
        )?;

        let is_packed = self.is_packing_enabled();
        let index_search = if is_packed {
            Ok(ordinal as usize)
        } else {
            self.components()
                .binary_search_by(|dtc| compare_component_to_ordinal(dtc, ordinal))
        };

        let mut replaced_components: Vec<DataTypeComponentImpl> = Vec::new();
        let offset;

        match index_search {
            Ok(idx) => {
                let orig_dtc = self.components()[idx].snapshot();
                offset = orig_dtc.get_offset();

                if is_packed || length == 0 {
                    // case 1: packed structure or zero-length replacement - do 1-for-1 replacement
                    replaced_components.push(orig_dtc);
                } else if orig_dtc.get_length() == 0 {
                    // case 2: replaced component is zero-length (like-for-like replacement handled
                    // by case 1 above)
                    return Err(
                        "IllegalArgumentException: Zero-length component may only be replaced with another zero-length component"
                            .to_string(),
                    );
                } else if orig_dtc.is_bit_field_component() {
                    // case 3: replacing bit-field (must replace all bit-fields which overlap)
                    let min_offset = orig_dtc.get_offset();
                    let max_offset = orig_dtc.get_end_offset();
                    replaced_components.push(orig_dtc);

                    // consume bit-field overlaps before
                    let mut i = idx as i32 - 1;
                    while i >= 0 {
                        let cand = self.components()[i as usize].snapshot();
                        if cand.get_length() == 0 || !cand.contains_offset(min_offset) {
                            break;
                        }
                        replaced_components.insert(0, cand);
                        i -= 1;
                    }

                    // consume bit-field overlaps after
                    let mut i = idx + 1;
                    while i < self.components().len() {
                        let cand = self.components()[i].snapshot();
                        if cand.get_length() == 0 || !cand.contains_offset(max_offset) {
                            break;
                        }
                        replaced_components.push(cand);
                        i += 1;
                    }
                } else {
                    // case 4: sized component replacement - do 1-for-1 replacement
                    replaced_components.push(orig_dtc);
                }
            }
            Err(insert_at) => {
                // case 5: undefined component replaced (non-packed only)
                let mut off = ordinal;
                if insert_at > 0 {
                    let dtc = &self.components()[insert_at - 1];
                    off = dtc.get_end_offset() + ordinal - dtc.get_ordinal();
                    if dtc.get_length() == 0 {
                        off -= 1;
                    }
                }
                offset = off;
                let orig_dtc = DataTypeComponentImpl::new(
                    DefaultDataType::boxed(),
                    None,
                    1,
                    ordinal,
                    offset,
                    None,
                    None,
                );
                if data_type.is_default_data_type() {
                    return Ok(orig_dtc); // no change
                }
                replaced_components.push(orig_dtc);
            }
        }

        let replace_component = self.structure_data_type_do_component_replacement(
            &replaced_components,
            offset,
            data_type,
            length,
            component_name,
            comment,
        )?;

        match replace_component {
            Some(c) => Ok(c),
            None => self.structure_data_type_get_component(ordinal),
        }
    }

    /// Port of `StructureDataType.replaceAtOffset(int, DataType, int, String, String)`. Replaces
    /// every defined component containing `offset` (or, for a packed structure with no component
    /// there, inserts instead -- cases 4/1 below early-return through
    /// [`structure_data_type_insert`] exactly as Java's `insert(...)` calls do) with a new
    /// component of `data_type`.
    ///
    /// Unlike [`structure_data_type_replace`], the preferred-length computation happens *after*
    /// the component search (matching Java's method body order exactly), so the early-return
    /// `insert` calls below receive the raw, caller-supplied `length` -- [`structure_data_type_insert`]
    /// computes its own preferred length internally anyway.
    ///
    /// # Errors
    /// Returns `Err` if `offset` is negative or beyond the end of the structure, a positive length
    /// cannot be determined for `data_type`, `data_type` would create a cyclic composite (mirrors
    /// `DataTypeDependencyException`), or there is not enough undefined space to fit the
    /// replacement (all mirror `IllegalArgumentException`).
    fn structure_data_type_replace_at_offset(
        &mut self,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        if offset < 0 {
            return Err("IllegalArgumentException: Offset cannot be negative.".to_string());
        }
        if offset >= self.stored_struct_length() {
            return Err(format!(
                "IllegalArgumentException: Offset {offset} is beyond end of structure ({}).",
                self.stored_struct_length()
            ));
        }

        let data_type = self.composite_impl_validate_data_type(data_type)?;
        // dataType.clone(dataMgr): skipped, see module docs.
        self.structure_data_type_check_ancestry(data_type.as_ref())?;

        let mut replaced_components: Vec<DataTypeComponentImpl> = Vec::new();

        let search = self
            .components()
            .binary_search_by(|dtc| compare_component_to_offset(dtc, offset));

        match search {
            Ok(found) => {
                let index = self
                    .structure_data_type_advance_to_last_component_containing_offset(found as i32, offset);
                let orig_dtc = self.components()[index as usize].snapshot();

                if orig_dtc.get_length() == 0 {
                    // case 1: only defined component(s) at offset are zero-length
                    if self.is_packing_enabled() {
                        // if packed: insert after zero-length component
                        return self.structure_data_type_insert(
                            index + 1,
                            data_type,
                            length,
                            component_name,
                            comment,
                        );
                    }
                    // if non-packed: replace undefined component which immediately follows the
                    // zero-length component
                    replaced_components.push(DataTypeComponentImpl::new(
                        DefaultDataType::boxed(),
                        None,
                        1,
                        orig_dtc.get_ordinal() + 1,
                        offset,
                        None,
                        None,
                    ));
                } else if orig_dtc.is_bit_field_component() {
                    // case 2: sized component at offset is bit-field (must replace all bit-fields
                    // which contain offset)
                    replaced_components.push(orig_dtc);
                    let mut i = index - 1;
                    while i >= 0 {
                        let cand = self.components()[i as usize].snapshot();
                        if cand.get_length() == 0 || !cand.contains_offset(offset) {
                            break;
                        }
                        replaced_components.insert(0, cand);
                        i -= 1;
                    }
                } else {
                    // case 3: normal replacement of sized component
                    replaced_components.push(orig_dtc);
                }
            }
            Err(insert_at) => {
                // defined component not found
                if self.is_packing_enabled() {
                    // case 4: if replacing padding for packed struction perform insert at correct
                    // ordinal
                    return self.structure_data_type_insert(
                        insert_at as i32,
                        data_type,
                        length,
                        component_name,
                        comment,
                    );
                }

                // case 5: replace undefined component at offset - compute undefined component to
                // be replaced
                let mut ordinal = offset;
                if insert_at > 0 {
                    let dtc = &self.components()[insert_at - 1];
                    ordinal = dtc.get_ordinal() + offset - dtc.get_end_offset();
                }
                let orig_dtc = DataTypeComponentImpl::new(
                    DefaultDataType::boxed(),
                    None,
                    1,
                    ordinal,
                    offset,
                    None,
                    None,
                );
                if data_type.is_default_data_type() {
                    return Ok(orig_dtc); // no change
                }
                replaced_components.push(orig_dtc);
            }
        }

        let dynamic_specifiable = is_dynamic_with_specifiable_length(data_type.as_ref());
        let length = self.composite_impl_preferred_component_length_default(
            data_type.as_ref(),
            dynamic_specifiable,
            length,
        )?;

        let replace_component = self.structure_data_type_do_component_replacement(
            &replaced_components,
            offset,
            data_type,
            length,
            component_name,
            comment,
        )?;

        match replace_component {
            Some(c) => Ok(c),
            None => self.structure_data_type_get_component_containing(offset).ok_or_else(|| {
                "AssertException: no component containing offset after replacement".to_string()
            }),
        }
    }

    /// Port of the private `StructureDataType.checkUndefinedSpaceAvailabilityAfter(int, int,
    /// DataType, int)`: verify (and, where the replaced run reaches the last defined component,
    /// grow the structure to make) enough trailing undefined byte space for a
    /// [`structure_data_type_replace_components`] call.
    ///
    /// # Errors
    /// Returns `Err` if there is not enough undefined space and the replaced run does not reach
    /// the last defined component (mirrors `IllegalArgumentException`).
    fn structure_data_type_check_undefined_space_availability_after(
        &mut self,
        last_ordinal_replaced_or_updated: i32,
        bytes_needed: i32,
        new_data_type: &dyn DataType,
        offset: i32,
    ) -> Result<(), String> {
        if bytes_needed <= 0 {
            return Ok(());
        }
        let bytes_available =
            self.structure_data_type_get_num_undefined_bytes(last_ordinal_replaced_or_updated + 1);
        if bytes_available < bytes_needed {
            if last_ordinal_replaced_or_updated == self.structure_data_type_get_last_defined_component_ordinal() {
                self.structure_data_type_grow_structure(bytes_needed - bytes_available)?;
            } else {
                return Err(format!(
                    "IllegalArgumentException: Not enough undefined bytes to fit {} in structure {} at offset 0x{:x}. It needs {} more byte(s) to be able to fit.",
                    new_data_type.get_path_name(),
                    self.get_path_name(),
                    offset,
                    bytes_needed - bytes_available
                ));
            }
        }
        Ok(())
    }

    /// Port of the private `StructureDataType.replaceComponents(LinkedList<DataTypeComponentImpl>,
    /// DataType, int, int, String, String)`: replace an ordered, adjacent run of components
    /// (`orig_components`) with a single new component (or, if `data_type` is the
    /// `DataType.DEFAULT` ([`DefaultDataType`]) `DataType.DEFAULT` stand-in, perform a clear-only operation with
    /// no replacement component). For a non-packed structure, only the replaced run's own defined
    /// list entries are removed/inserted -- every *other* defined component's absolute byte offset
    /// is left untouched, and only its ordinal shifts (by `deltaOrdinal`) to reflect how many
    /// implicit undefined-byte ordinals now separate it from its neighbor; this mirrors Java's
    /// `shiftOffsets(index + 1, deltaOrdinal, 0)` call (`deltaOffset` is always `0` here).
    ///
    /// # Errors
    /// Returns `Err` if `new_offset` falls outside `orig_components`' bounds, `orig_components`
    /// contains an undefined component alongside others or non-sequential ordinals (both mirror
    /// `AssertException`), the deleted run does not match `orig_components` ordinal-for-ordinal
    /// (mirrors `AssertException`), or there is not enough undefined space to fit the replacement
    /// (mirrors `IllegalArgumentException`, via
    /// [`structure_data_type_check_undefined_space_availability_after`]).
    fn structure_data_type_replace_components(
        &mut self,
        orig_components: &[DataTypeComponentImpl],
        data_type: Box<dyn DataType>,
        new_offset: i32,
        length: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Option<DataTypeComponentImpl>, String> {
        let clear_only = data_type.is_default_data_type();
        let length = if clear_only { 0 } else { length };

        let orig_first = &orig_components[0];
        let orig_last = &orig_components[orig_components.len() - 1];
        let orig_first_ordinal = orig_first.get_ordinal();
        let orig_last_ordinal = orig_last.get_ordinal();
        let min_replaced_offset = orig_first.get_offset();
        let max_replaced_offset = orig_last.get_end_offset();

        // Perform origComponents checks
        if new_offset < min_replaced_offset || new_offset > max_replaced_offset {
            return Err("AssertException: newOffset not contained within origComponents".to_string());
        }
        if orig_components.len() > 1 {
            let mut check_ordinal = orig_first_ordinal;
            for dtc in orig_components {
                if dtc.is_undefined() {
                    return Err(
                        "AssertException: undefined component within multi-component sequence".to_string(),
                    );
                }
                if dtc.get_ordinal() != check_ordinal {
                    return Err("AssertException: non-sequential components specified".to_string());
                }
                check_ordinal += 1;
            }
        }

        let leading_unused_bytes = new_offset - min_replaced_offset;
        let is_packed = self.is_packing_enabled();
        let mut new_ordinal = orig_first_ordinal;
        if !is_packed {
            new_ordinal += leading_unused_bytes; // leading unused bytes will become undefined components
        }

        // compute space freed by component removal
        let mut orig_length = 0;
        if orig_last.get_length() != 0 {
            orig_length = max_replaced_offset - min_replaced_offset + 1;
        }

        if !clear_only && !is_packed {
            let bytes_needed = length - orig_length + leading_unused_bytes;
            self.structure_data_type_check_undefined_space_availability_after(
                orig_last_ordinal,
                bytes_needed,
                data_type.as_ref(),
                new_offset,
            )?;
        }

        // determine defined component list insertion point, remove old components
        // and insert new component in list
        let raw_index: Result<usize, usize> = if is_packed {
            Ok(new_ordinal as usize)
        } else {
            self.components()
                .binary_search_by(|dtc| compare_component_to_ordinal(dtc, orig_first_ordinal))
        };

        let index = match raw_index {
            Ok(idx) => {
                for orig_dtc in orig_components {
                    let removed = self.structure_data_type_do_delete(idx);
                    if removed.get_ordinal() != orig_dtc.get_ordinal() {
                        return Err("AssertException: component replacement mismatch".to_string());
                    }
                }
                idx
            }
            Err(insert_at) => insert_at, // undefined component replacement
        };

        let mut new_dtc = None;
        if !clear_only {
            // insert new component
            let component = DataTypeComponentImpl::new(
                data_type,
                None,
                length,
                new_ordinal,
                new_offset,
                field_name,
                comment,
            );
            self.components_mut().insert(index, component);
            new_dtc = Some(self.components()[index].snapshot());
            // dataType.addParent(this): skipped, see module docs.
        }

        // adjust ordinals of trailing components - defer if packing is enabled
        if !is_packed {
            let delta_ordinal = -(orig_components.len() as i32) + orig_length - length;
            self.structure_data_type_shift_offsets(index + 1, delta_ordinal, 0);
        }
        Ok(new_dtc)
    }

    /// Port of the private `StructureDataType.getLastDefinedComponentOrdinal()`.
    fn structure_data_type_get_last_defined_component_ordinal(&self) -> i32 {
        match self.components().last() {
            None => 0,
            Some(dtc) => dtc.get_ordinal(),
        }
    }

    /// Port of the protected `StructureDataType.getNumUndefinedBytes(int)`: the number of
    /// contiguous undefined bytes beginning at the component ordinal `index`.
    fn structure_data_type_get_num_undefined_bytes(&self, index: i32) -> i32 {
        if index >= self.stored_num_components() {
            return 0;
        }
        match self
            .components()
            .binary_search_by(|dtc| compare_component_to_ordinal(dtc, index))
        {
            Ok(_) => 0,
            Err(insert_at) => {
                if insert_at >= self.components().len() {
                    return self.stored_num_components() - index;
                }
                self.components()[insert_at].get_ordinal() - index
            }
        }
    }

    /// Port of the private `StructureDataType.getAvailableComponentSpace(int)`: the available
    /// space for an existing defined component (identified by its index into
    /// [`components`](StructureDataType::components), *not* its ordinal) in relation to the next
    /// defined component or the end of the structure. Returns `-1` if packing is enabled
    /// (matching Java), or `i32::MAX` (Java's `Integer.MAX_VALUE`) if `index` is the last defined
    /// component of a non-packed structure.
    fn structure_data_type_get_available_component_space(&self, index: usize) -> i32 {
        if self.is_packing_enabled() {
            return -1;
        }
        let next_index = index + 1;
        if next_index < self.components().len() {
            let offset = self.components()[index].get_offset();
            return self.components()[next_index].get_offset() - offset;
        }
        i32::MAX
    }

    /// Port of the private `StructureDataType.consumeBytesAfter(int, int)`, including its inlined
    /// call to `doGrowStructure(int)` for the last-component case (unlike
    /// [`structure_data_type_grow_structure`](StructureDataType::structure_data_type_grow_structure),
    /// which additionally repacks/notifies to serve as the public `growStructure(int)` entry
    /// point, the growth performed here is the bare field update only, matching Java's private
    /// `doGrowStructure` exactly -- every caller below already performs its own repack
    /// afterward). Returns the number of bytes actually consumed.
    fn structure_data_type_consume_bytes_after(&mut self, index: usize, num_bytes: i32) -> i32 {
        let this_len = self.components()[index].get_length();
        let this_offset = self.components()[index].get_offset();
        let next_offset = this_offset + this_len;
        let available = if index == self.components().len() - 1 {
            let mut available = self.stored_struct_length() - next_offset;
            if num_bytes > available {
                let amount = num_bytes - available;
                self.set_stored_num_components(self.stored_num_components() + amount);
                self.set_stored_struct_length(self.stored_struct_length() + amount);
                available = num_bytes;
            }
            available
        } else {
            self.components()[index + 1].get_offset() - next_offset
        };
        if num_bytes <= available {
            self.components_mut()[index].set_length(this_len + num_bytes);
            num_bytes
        } else {
            self.components_mut()[index].set_length(this_len + available);
            available
        }
    }

    /// Port of `StructureDataType.dataTypeSizeChanged(DataType)`: react to a component's data type
    /// resizing, shrinking or growing that component (absorbing/releasing undefined filler bytes
    /// around it via [`structure_data_type_shift_offsets`](StructureDataType::structure_data_type_shift_offsets)/
    /// [`structure_data_type_consume_bytes_after`](StructureDataType::structure_data_type_consume_bytes_after))
    /// as needed, or -- for a packing-enabled structure -- simply repacking. Bitfield components
    /// are skipped entirely (matching Java's "unsupported" comment: a bitfield's own base type
    /// should not itself trigger this notification for the bitfield component).
    ///
    /// # Errors
    /// Returns `Err` if a positive preferred length cannot be determined for `dt` at some matching
    /// component (mirrors `IllegalArgumentException`, propagated unguarded exactly as Java leaves
    /// it uncaught).
    fn structure_data_type_data_type_size_changed(&mut self, dt: &dyn DataType) -> Result<(), String> {
        if dt.is_bit_field_type() {
            return Ok(());
        }
        if self.is_packing_enabled() {
            self.structure_data_type_repack(true);
            return Ok(());
        }
        let old_length = self.stored_struct_length();
        let mut changed = false;
        let target_path = dt.get_data_type_path();
        let is_dynamic = is_dynamic_with_specifiable_length(dt);
        let n = self.components().len();
        let mut i = 0;
        while i < n {
            if self.components()[i].get_data_type().get_data_type_path() == target_path {
                let dtc_len = self.components()[i].get_length();
                let available = self.structure_data_type_get_available_component_space(i);
                let length =
                    self.composite_impl_preferred_component_length(dt, is_dynamic, dtc_len, available)?;
                if length < dtc_len {
                    self.components_mut()[i].set_length(length);
                    self.structure_data_type_shift_offsets(i + 1, dtc_len - length, 0);
                    changed = true;
                } else if length > dtc_len {
                    let consumed = self.structure_data_type_consume_bytes_after(i, length - dtc_len);
                    if consumed > 0 {
                        self.structure_data_type_shift_offsets(i + 1, -consumed, 0);
                        changed = true;
                    }
                }
            }
            i += 1;
        }
        if changed {
            self.structure_data_type_repack(false);
            if old_length != self.stored_struct_length() {
                // notifySizeChanged(): no-op, see module docs.
            }
        }
        Ok(())
    }

    /// Port of `StructureDataType.dataTypeAlignmentChanged(DataType)`: only a packing-enabled
    /// structure's layout can depend on a component's alignment, so this is a no-op otherwise.
    fn structure_data_type_data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        let _ = dt;
        if self.is_packing_enabled() {
            self.structure_data_type_repack(true);
        }
    }

    /// Port of the protected `CompositeDataTypeImpl.updateBitFieldDataType(DataTypeComponentImpl,
    /// DataType, DataType)`, specialized to operate directly on this structure's own
    /// `Vec<DataTypeComponentImpl>` storage (identifying the target component by `index` rather
    /// than by value) rather than through the object-unsafe `Box<dyn DataTypeComponent>`-based
    /// [`CompositeDataTypeImpl::composite_impl_update_bit_field_data_type`], which remains stubbed
    /// at `Ok(false)` for exactly this reason -- see that method's own doc comment. `old_dt`
    /// identity is approximated the same way every other `== `-style comparison in this module is
    /// (via [`DataType::get_data_type_path`] equality, not true reference identity); `new_dt` is an
    /// `Arc` (rather than a plain `Box`) so a single replacement value can be reused across
    /// multiple matching bitfield components in one caller's loop, mirroring
    /// [`PackableComponent`]'s own reason for the same choice.
    ///
    /// # Errors
    /// Returns `Err` if the component at `index` is not actually a bit-field component (mirrors
    /// the Java `AssertException`), or if reconstructing the bitfield around the new base type
    /// fails (also mirrors an `AssertException`, since Java treats that as "unexpected").
    fn structure_data_type_update_bit_field_data_type(
        &mut self,
        index: usize,
        old_dt: &dyn DataType,
        new_dt: Option<&Arc<dyn DataType>>,
    ) -> Result<bool, String> {
        if !self.components()[index].is_bit_field_component() {
            return Err("AssertException: expected bitfield component".to_string());
        }
        let Some(new_dt) = new_dt else {
            // BitFieldDataType.isValidBaseDataType(null) is always false in Java, so a `null`
            // replacement always short-circuits to "not modified" here too.
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
        let new_bitfield = BitFieldDataType::new(share_data_type(new_dt), declared_bit_size, bit_offset)
            .map_err(|e| format!("AssertException: {}", e.message()))?;
        self.components_mut()[index].set_data_type(Box::new(new_bitfield));
        // oldDt.removeParent(this)/newDt.addParent(this): no-op, see module docs.
        Ok(true)
    }

    /// Port of the private `StructureDataType.setComponentDataType(DataTypeComponentImpl,
    /// DataType, int)`. Note that for a replacement data type whose `getLength()` is negative
    /// (e.g. [`bad_data_type_stand_in`]'s stand-in for the real `BadDataType.dataType`, which
    /// mirrors the genuine singleton's own `getLength() == -1`), the preferred-length computation
    /// always yields the *original* `old_len` back unchanged (`dtLength >= 0` fails, so neither
    /// the `max_length`-clamped candidate nor the final `dtLength`-clamped candidate ever
    /// overrides it) -- so the resize branches below never actually trigger for that caller,
    /// matching the "Should be no impact" comment on Java's `dataTypeDeleted` above its `repack`
    /// call.
    ///
    /// # Errors
    /// Returns `Err` if a positive preferred length cannot be determined for `new_dt` (mirrors
    /// `IllegalArgumentException`); unreachable for [`bad_data_type_stand_in`] per the above.
    fn structure_data_type_set_component_data_type(
        &mut self,
        index: usize,
        new_dt: Box<dyn DataType>,
    ) -> Result<(), String> {
        // comp.getDataType().removeParent(this)/newDt.addParent(this): no-op, see module docs.
        self.components_mut()[index].set_data_type(new_dt);
        if self.is_packing_enabled() {
            return Ok(());
        }
        let old_len = self.components()[index].get_length();
        let current_dt = self.components()[index].get_data_type();
        let is_dynamic = is_dynamic_with_specifiable_length(current_dt.as_ref());
        let available = self.structure_data_type_get_available_component_space(index);
        let length =
            self.composite_impl_preferred_component_length(current_dt.as_ref(), is_dynamic, old_len, available)?;
        if length < old_len {
            self.components_mut()[index].set_length(length);
            self.structure_data_type_shift_offsets(index + 1, old_len - length, 0);
        } else if length > old_len {
            let consumed = self.structure_data_type_consume_bytes_after(index, length - old_len);
            if consumed > 0 {
                self.structure_data_type_shift_offsets(index + 1, -consumed, 0);
            }
        }
        Ok(())
    }

    /// Port of `StructureDataType.dataTypeDeleted(DataType)`: a component of the deleted type
    /// becomes `BadDataType`; a bitfield whose base type was deleted reverts to its primitive
    /// integer base type. Data type identity (Java `==`) is compared by data type path.
    ///
    /// # Errors
    /// Returns `Err` if [`structure_data_type_set_component_data_type`](Self::structure_data_type_set_component_data_type)
    /// fails for some matching component.
    fn structure_data_type_data_type_deleted(&mut self, dt: &dyn DataType) -> Result<(), String> {
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
                    if self.structure_data_type_update_bit_field_data_type(i, dt, Some(&primitive))? {
                        changed = true;
                    }
                }
            } else if self.components()[i].get_data_type().get_data_type_path() == target_path {
                self.structure_data_type_set_component_data_type(i, bad_data_type_stand_in())?;
                changed = true;
            }
        }
        if changed && !self.is_packing_enabled() {
            self.structure_data_type_repack(true);
        }
        Ok(())
    }

    /// Port of `StructureDataType.dataTypeReplaced(DataType, DataType)`. Exposed taking an owned
    /// `new_dt: Box<dyn DataType>` rather than the borrowed `&dyn DataType` the generic
    /// [`DataType::data_type_replaced`] placeholder default uses: this method needs to *store* the
    /// (possibly re-validated) replacement inside a component, which is impossible to do
    /// generically from a borrowed reference without a `Clone` bound on [`DataType`] (the same
    /// class of ownership problem [`PackableComponent`]'s own doc comment describes) -- so unlike
    /// [`structure_data_type_data_type_size_changed`](StructureDataType::structure_data_type_data_type_size_changed)/
    /// [`structure_data_type_data_type_alignment_changed`](StructureDataType::structure_data_type_data_type_alignment_changed)/
    /// [`structure_data_type_data_type_deleted`](StructureDataType::structure_data_type_data_type_deleted)
    /// (all three of which only ever need to *compare against* the notified data type, and so keep
    /// the generic default's `&dyn DataType` shape and are wired into
    /// [`StructureDataType`]'s own `impl DataType`), this method cannot be reached from a
    /// concrete implementor's `DataType::data_type_replaced` override without that implementor
    /// separately tracking its own way to reconstruct an owned replacement (e.g. its own
    /// `DataTypeManager` handle) -- out of scope here, so `StructureDataType` leaves
    /// `DataType::data_type_replaced` at its inherited placeholder default.
    ///
    /// See the module docs for what is skipped (`dataType.clone(dataMgr)`, parent-notification
    /// wiring).
    ///
    /// # Errors
    /// Returns `Err` if `old_dt`/`new_dt` fail `DataTypeUtilities.checkValidReplacement`'s checks
    /// (mirrors `IllegalArgumentException`, and matching Java, *not* subject to the fallback the
    /// validate/ancestry-check sequence below gets), or if
    /// [`structure_data_type_update_bit_field_data_type`](StructureDataType::structure_data_type_update_bit_field_data_type)
    /// fails for some matching bitfield component.
    fn structure_data_type_data_type_replaced(
        &mut self,
        old_dt: &dyn DataType,
        new_dt: Box<dyn DataType>,
    ) -> Result<(), String> {
        check_valid_replacement(old_dt, new_dt.as_ref())?;

        let replacement_dt: Box<dyn DataType> = {
            let validated = self.composite_impl_validate_data_type(new_dt);
            // replacementDt.clone(dataMgr): skipped, see module docs.
            let checked = validated.and_then(|dt| {
                self.structure_data_type_check_ancestry(dt.as_ref())?;
                Ok(dt)
            });
            match checked {
                Ok(dt) => dt,
                Err(_) => {
                    if self.is_packing_enabled() {
                        share_data_type(&Undefined1DataType::data_type())
                    } else {
                        DefaultDataType::boxed()
                    }
                }
            }
        };
        let replacement_arc: Arc<dyn DataType> = Arc::from(replacement_dt);

        let old_path = old_dt.get_data_type_path();
        let mut changed = false;
        let n = self.components().len();
        for i in (0..n).rev() {
            if self.components()[i].is_bit_field_component() {
                if self.structure_data_type_update_bit_field_data_type(i, old_dt, Some(&replacement_arc))? {
                    changed = true;
                }
            } else if self.components()[i].get_data_type().get_data_type_path() == old_path {
                self.structure_data_type_set_component_data_type(i, share_data_type(&replacement_arc))?;
                changed = true;
            }
        }
        if changed {
            self.structure_data_type_repack(false);
            // notifySizeChanged(): no-op, see module docs.
        }
        Ok(())
    }
}

/// Port of `DataUtilities.isValidDataTypeName(String)`'s check as applied by the
/// `GenericDataType` constructor chain (`StructureDataType`'s Java superclass), used by
/// [`StructureDataType::new_in_category`]. A local duplicate of
/// [`composite_data_type_impl::check_valid_name`](super::composite_data_type_impl)'s identical
/// logic (that helper is private to its own module and used for the checked-exception `setName`
/// path rather than this panic-based constructor path).
fn is_valid_structure_name(name: &str) -> bool {
    !name.trim().is_empty() && !name.chars().any(|c| c.is_control())
}

/// Basic in-memory (non-database-backed) implementation of a structure data type.
///
/// Port of `ghidra.program.model.data.StructureDataType`.
///
/// Composites follow the build-then-share convention (decided 2026-09-27): a structure is an
/// owned value edited through `&mut self`; to change one that is already shared as an
/// `Arc<dyn DataType>`, clone it, edit the clone and resolve it into the data type manager
/// (Java's `resolve()` copies too). There is no interior locking.
///
/// Field layout mirrors the Java class: `category_path`/`name`/`description` are the inherited
/// `GenericDataType`/`CompositeDataTypeImpl` fields, `minimum_alignment_value`/`packing_value` the
/// raw `CompositeDataTypeImpl.minimumAlignment`/`.packing` fields, and `struct_length`/
/// `struct_alignment`/`num_components`/`components` this class's own fields.
///
/// The associated `DataTypeManager` is recorded only as its [`DataOrganizationImpl`] (the
/// manager itself is not `Send + Sync`), the same convention as
/// [`BuiltInBase`](super::built_in::BuiltInBase). Consequently `dataType.clone(dataMgr)` on
/// inserted components is not performed: component data types are shared as given.
///
/// Components handed out through [`Composite`]/[`Structure`] are snapshots whose parent is a
/// snapshot of this structure, so parent-dependent component behaviour (default field names,
/// packed equivalence) matches Java; editing such a snapshot does not edit the structure.
pub struct StructureDataType {
    category_path: CategoryPath,
    name: String,
    description: Option<String>,
    data_organization: Option<Arc<DataOrganizationImpl>>,
    minimum_alignment_value: i32,
    packing_value: i32,
    struct_length: i32,
    struct_alignment: i32,
    num_components: i32,
    components: Vec<DataTypeComponentImpl>,
    universal_id: UniversalID,
    source_archive_id: Option<UniversalID>,
    last_change_time: i64,
    last_change_time_in_source_archive: i64,
}

/// Transitional name for [`StructureDataType`], kept while in-flight branches still import the
/// old `StructureDataTypeImpl` struct name.
#[deprecated(note = "renamed to StructureDataType")]
pub type StructureDataTypeImpl = StructureDataType;

impl Clone for StructureDataType {
    /// A value copy with the same identity (universal ID, source archive and change times) and
    /// components that share their data types with the original.
    fn clone(&self) -> Self {
        StructureDataType {
            category_path: self.category_path.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            data_organization: self.data_organization.clone(),
            minimum_alignment_value: self.minimum_alignment_value,
            packing_value: self.packing_value,
            struct_length: self.struct_length,
            struct_alignment: self.struct_alignment,
            num_components: self.num_components,
            components: self.components.iter().map(DataTypeComponentImpl::snapshot).collect(),
            universal_id: self.universal_id,
            source_archive_id: self.source_archive_id,
            last_change_time: self.last_change_time,
            last_change_time_in_source_archive: self.last_change_time_in_source_archive,
        }
    }
}

impl std::fmt::Debug for StructureDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::program::model::data::composite_internal::to_string(self))
    }
}

impl StructureDataType {
    /// Construct a new structure with the given name and length. The root category is used.
    ///
    /// A `length` of 0 makes the structure report a length of 1 and
    /// [`is_not_yet_defined`](DataType::is_not_yet_defined) `true`.
    ///
    /// Port of `StructureDataType(String, int)`.
    ///
    /// # Panics
    /// Panics (standing in for `IllegalArgumentException`) if `length` is negative, or if `name`
    /// is not a valid data-type name.
    pub fn new(name: impl Into<String>, length: i32) -> Self {
        Self::new_in_category(ROOT.clone(), name, length)
    }

    /// Construct a new structure with the given name and length within the specified category.
    ///
    /// Port of `StructureDataType(CategoryPath, String, int)`.
    ///
    /// # Panics
    /// See [`new`](Self::new).
    pub fn new_in_category(category_path: CategoryPath, name: impl Into<String>, length: i32) -> Self {
        Self::with_manager(category_path, name, length, None)
    }

    /// Construct a new structure associated with a data type manager, whose data organization
    /// then governs packing, alignment and endianness.
    ///
    /// Port of `StructureDataType(CategoryPath, String, int, DataTypeManager)` (and, with
    /// [`ROOT`], of `StructureDataType(String, int, DataTypeManager)`).
    ///
    /// # Panics
    /// See [`new`](Self::new).
    pub fn with_manager(
        category_path: CategoryPath,
        name: impl Into<String>,
        length: i32,
        dtm: Option<&dyn DataTypeManager>,
    ) -> Self {
        let name = name.into();
        if !is_valid_structure_name(&name) {
            panic!("IllegalArgumentException: Invalid DataType name: {name}");
        }
        if length < 0 {
            panic!("IllegalArgumentException: Length can't be negative");
        }
        StructureDataType {
            category_path,
            name,
            description: None,
            data_organization: dtm.map(|dtm| dtm.get_data_organization()),
            minimum_alignment_value: DEFAULT_ALIGNMENT,
            packing_value: NO_PACKING,
            struct_length: length,
            struct_alignment: 0,
            num_components: length,
            components: Vec::new(),
            universal_id: next_id(),
            source_archive_id: None,
            last_change_time: 0,
            last_change_time_in_source_archive: 0,
        }
    }

    /// Construct a new structure with an explicit archive identity.
    ///
    /// Port of the 8-argument constructor taking `universalID`/`sourceArchive`/`lastChangeTime`/
    /// `lastChangeTimeInSourceArchive`/`dtm`. `source_archive` is tracked only by ID, matching
    /// [`EnumDataType::with_archive_identity`](super::enum_data_type::EnumDataType::with_archive_identity).
    ///
    /// # Panics
    /// Panics if `name` is not a valid data-type name. (Unlike the other constructors, the Java
    /// original does not reject a negative length here, and neither does this port.)
    #[allow(clippy::too_many_arguments)]
    pub fn with_archive_identity(
        category_path: CategoryPath,
        name: impl Into<String>,
        length: i32,
        universal_id: UniversalID,
        source_archive: Option<&dyn SourceArchive>,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
        dtm: Option<&dyn DataTypeManager>,
    ) -> Self {
        let mut s = Self::with_manager(category_path, name, length.max(0), dtm);
        s.struct_length = length;
        s.num_components = length;
        s.universal_id = universal_id;
        s.source_archive_id = source_archive.map(|a| a.source_archive_id());
        s.last_change_time = last_change_time;
        s.last_change_time_in_source_archive = last_change_time_in_source_archive;
        s
    }

    /// A snapshot of the defined component at `index` of the components list.
    fn component_snapshot(&self, index: usize) -> DataTypeComponentImpl {
        self.components()[index].snapshot()
    }

    /// Port of `StructureDataType.replaceWith(DataType)` returning the error Java throws as an
    /// `IllegalArgumentException` (`data_type` is not a structure, or would create a cycle).
    ///
    /// # Errors
    /// See above.
    pub fn try_replace_with(&mut self, data_type: &dyn DataType) -> Result<(), String> {
        self.structure_data_type_replace_with(data_type)
    }

    /// Port of `StructureDataType.dataTypeReplaced(DataType, DataType)` with an owned replacement:
    /// every component (and bitfield base type) of type `old_dt` switches to `new_dt`. An invalid
    /// replacement becomes `undefined1` (packed) or `DataType.DEFAULT` (non-packed).
    ///
    /// # Errors
    /// Returns `Err` if `old_dt`/`new_dt` fail `DataTypeUtilities.checkValidReplacement`.
    pub fn replace_data_type(&mut self, old_dt: &dyn DataType, new_dt: Arc<dyn DataType>) -> Result<(), String> {
        self.structure_data_type_data_type_replaced(old_dt, share_data_type(&new_dt))
    }

    /// A snapshot of this structure, used as the parent of the components handed out by one
    /// public call.
    fn parent_snapshot(&self) -> Arc<dyn CompositeDataTypeImpl> {
        Arc::new(self.clone())
    }

    /// A component handed out through the public API, with this structure as its parent.
    fn handed_out(&self, dtc: DataTypeComponentImpl) -> Box<dyn DataTypeComponent> {
        Box::new(dtc.with_parent(Some(self.parent_snapshot())))
    }

    /// Several components handed out by one public call, sharing one parent snapshot.
    fn handed_out_all(&self, components: Vec<DataTypeComponentImpl>) -> Vec<Box<dyn DataTypeComponent>> {
        let parent = self.parent_snapshot();
        components
            .into_iter()
            .map(|dtc| Box::new(dtc.with_parent(Some(parent.clone()))) as Box<dyn DataTypeComponent>)
            .collect()
    }
}

impl DataType for StructureDataType {
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

    /// The associated manager's data organization, or the default organization when the
    /// structure was created without one (Java `AbstractDataType.getDataOrganization()`).
    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        self.data_organization.clone().unwrap_or_else(shared_default_organization)
    }

    fn get_mnemonic(&self, settings: &dyn Settings) -> String {
        self.composite_impl_mnemonic(settings)
    }

    fn get_length(&self) -> i32 {
        StructureDataType::length(self)
    }

    /// Java `CompositeDataTypeImpl.getAlignedLength()` is final and returns `getLength()`.
    fn get_aligned_length(&self) -> i32 {
        StructureDataType::length(self)
    }

    fn is_zero_length(&self) -> bool {
        self.structure_data_type_is_zero_length()
    }

    fn has_language_dependant_length(&self) -> bool {
        self.structure_data_type_has_language_dependant_length()
    }

    fn get_alignment(&self) -> i32 {
        self.composite_impl_alignment()
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        StructureDataType::representation(self, buf, settings, length)
    }

    fn get_default_label_prefix(&self) -> Option<String> {
        StructureDataType::default_label_prefix(self)
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
        self.structure_data_type_is_equivalent(dt)
    }

    /// Port of `StructureDataType.replaceWith(DataType)`.
    ///
    /// # Panics
    /// Panics (Java throws `IllegalArgumentException`) if `data_type` is not a structure or
    /// contains this structure. Use [`StructureDataType::try_replace_with`] to receive the error
    /// instead.
    fn replace_with(&mut self, data_type: &dyn DataType) {
        if let Err(e) = self.structure_data_type_replace_with(data_type) {
            panic!("{e}");
        }
    }

    fn runtime_class(&self) -> Option<std::any::TypeId> {
        Some(std::any::TypeId::of::<StructureDataType>())
    }

    fn is_structure(&self) -> bool {
        true
    }

    fn as_structure(&self) -> Option<&dyn Structure> {
        Some(self)
    }

    fn as_composite(&self) -> Option<&dyn Composite> {
        Some(self)
    }

    fn as_composite_mut(&mut self) -> Option<&mut dyn Composite> {
        Some(self)
    }

    fn into_composite(self: Box<Self>) -> Option<Box<dyn Composite>> {
        Some(self)
    }

    /// Port of `StructureDataType.copy(DataTypeManager)`: a new structure (new identity, no
    /// source archive) associated with `dtm`, repopulated from this one.
    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let mut copy =
            StructureDataType::with_manager(self.get_category_path(), self.get_name(), self.stored_struct_length(), Some(dtm));
        copy.composite_impl_set_description(Some(&self.get_description()));
        copy.structure_data_type_replace_with(self)
            .expect("replaceWith from a structure cannot fail on a fresh structure");
        Box::new(copy)
    }

    /// Port of `StructureDataType.clone(DataTypeManager)`: like
    /// [`copy_data_type`](Self::copy_data_type) but preserving this structure's universal ID,
    /// source archive and change times. Java returns `this` when `dtm` is already the associated
    /// manager; the manager itself is not recorded (see the type docs), so a clone is always made.
    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let mut clone = StructureDataType::with_archive_identity(
            self.get_category_path(),
            self.get_name(),
            self.stored_struct_length(),
            self.universal_id,
            None,
            self.last_change_time,
            self.last_change_time_in_source_archive,
            Some(dtm),
        );
        clone.source_archive_id = self.source_archive_id;
        clone.composite_impl_set_description(Some(&self.get_description()));
        clone
            .structure_data_type_replace_with(self)
            .expect("replaceWith from a structure cannot fail on a fresh structure");
        Box::new(clone)
    }

    /// Port of `StructureDataType.dataTypeSizeChanged(DataType)`. Java lets an
    /// `IllegalArgumentException` for an invalid preferred length escape; this signature has no
    /// error channel, so the structure is left as it was at the point of failure.
    fn data_type_size_changed(&mut self, dt: &dyn DataType) {
        let _ = self.structure_data_type_data_type_size_changed(dt);
    }

    /// Port of `StructureDataType.dataTypeAlignmentChanged(DataType)`.
    fn data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        self.structure_data_type_data_type_alignment_changed(dt);
    }

    /// Port of `StructureDataType.dataTypeDeleted(DataType)`.
    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        let _ = self.structure_data_type_data_type_deleted(dt);
    }

    // `data_type_replaced(&dyn DataType, &dyn DataType)` keeps the trait default: storing the
    // replacement needs an owned handle, which a borrowed `&dyn DataType` cannot provide. The
    // in-memory structure is not registered as a parent of anything (build-then-share), so no
    // manager calls it; `StructureDataType::replace_data_type` is the owned-handle entry point.
}

impl Composite for StructureDataType {
    fn get_num_components(&self) -> i32 {
        self.structure_data_type_get_num_components()
    }

    fn get_num_defined_components(&self) -> i32 {
        self.structure_data_type_get_num_defined_components()
    }

    fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_get_component(ordinal)
            .map(|c| self.handed_out(c))
    }

    fn get_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        self.handed_out_all(self.structure_data_type_get_components())
    }

    fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        self.handed_out_all(self.components().iter().map(DataTypeComponentImpl::snapshot).collect())
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
        self.structure_data_type_add_bit_field(base_data_type, bit_size, component_name, comment)
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
        self.structure_data_type_delete(ordinal)
    }

    fn delete_set(&mut self, ordinals: &HashSet<i32>) -> Result<(), String> {
        self.structure_data_type_delete_ordinals(ordinals)
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

impl CompositeInternal for StructureDataType {
    fn get_stored_packing_value(&self) -> i32 {
        self.composite_impl_stored_packing_value()
    }

    fn get_stored_minimum_alignment(&self) -> i32 {
        self.composite_impl_stored_minimum_alignment()
    }
}

impl Structure for StructureDataType {
    fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_get_component(ordinal)
            .map(|c| self.handed_out(c))
    }

    fn get_defined_component_at_or_after_offset(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
        self.structure_data_type_get_defined_component_at_or_after_offset(offset)
            .map(|c| self.handed_out(c))
    }

    fn get_component_containing(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
        self.structure_data_type_get_component_containing(offset)
            .map(|c| self.handed_out(c))
    }

    fn get_components_containing(&self, offset: i32) -> Vec<Box<dyn DataTypeComponent>> {
        self.handed_out_all(self.structure_data_type_get_components_containing(offset))
    }

    fn get_data_type_at(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
        self.structure_data_type_get_data_type_at(offset)
    }

    fn insert_bit_field(
        &mut self,
        ordinal: i32,
        byte_width: i32,
        bit_offset: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_insert_bit_field(
            ordinal,
            byte_width,
            bit_offset,
            base_data_type,
            bit_size,
            component_name,
            comment,
        )
        .map(|c| self.handed_out(c))
    }

    fn insert_bit_field_at(
        &mut self,
        byte_offset: i32,
        byte_width: i32,
        bit_offset: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_insert_bit_field_at(
            byte_offset,
            byte_width,
            bit_offset,
            base_data_type,
            bit_size,
            component_name,
            comment,
        )
        .map(|c| self.handed_out(c))
    }

    fn insert_at_offset(
        &mut self,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_insert_at_offset(offset, data_type, length, None, None)
            .map(|c| self.handed_out(c))
    }

    fn insert_at_offset_with_name(
        &mut self,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_insert_at_offset(offset, data_type, length, component_name, comment)
            .map(|c| self.handed_out(c))
    }

    fn delete_at_offset(&mut self, offset: i32) -> Result<(), String> {
        self.structure_data_type_delete_at_offset(offset)
    }

    fn delete_all(&mut self) {
        self.structure_data_type_delete_all();
    }

    fn clear_at_offset(&mut self, offset: i32) {
        let _ = self.structure_data_type_clear_at_offset(offset);
    }

    fn clear_component(&mut self, ordinal: i32) -> Result<(), String> {
        self.structure_data_type_clear_component(ordinal)
    }

    fn grow_structure(&mut self, amount: i32) -> Result<(), String> {
        self.structure_data_type_grow_structure(amount)
    }

    fn set_length(&mut self, length: i32) -> Result<(), String> {
        self.structure_data_type_set_length(length)
    }

    fn replace(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_replace(ordinal, data_type, length, None, None)
            .map(|c| self.handed_out(c))
    }

    fn replace_with_name(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_replace(ordinal, data_type, length, component_name, comment)
            .map(|c| self.handed_out(c))
    }

    fn replace_at_offset(
        &mut self,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_replace_at_offset(offset, data_type, length, component_name, comment)
            .map(|c| self.handed_out(c))
    }
}

impl StructureInternal for StructureDataType {}

impl CompositeDataTypeImpl for StructureDataType {
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
        self.structure_data_type_has_language_dependant_length()
    }

    fn repack_with_notify(&mut self, notify: bool) -> bool {
        self.structure_data_type_repack(notify)
    }

    /// Port of `StructureDataType.getAlignment()`: the alignment recorded by the last repack,
    /// or else computed on demand. (Java caches the computed value in `structAlignment`; a `&self`
    /// getter cannot, so an unrepacked structure recomputes.)
    fn composite_impl_alignment(&self) -> i32 {
        if self.struct_alignment > 0 {
            return self.struct_alignment;
        }
        if self.is_packing_enabled() {
            self.pack_components_readonly(self).alignment
        } else {
            self.composite_impl_non_packed_alignment()
        }
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
        self.structure_data_type_add(data_type, length, field_name, comment)
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
        self.structure_data_type_insert(ordinal, data_type, length, field_name, comment)
            .map(|c| self.handed_out(c))
    }

    /// Port of `CompositeDataTypeImpl.validateDataType(DataType)`: `DataType.DEFAULT` becomes
    /// `Undefined1DataType` in a packed structure; dynamic types must allow a specified length;
    /// factory types and types without a positive length are rejected.
    fn composite_impl_validate_data_type(&self, data_type: Box<dyn DataType>) -> Result<Box<dyn DataType>, String> {
        if data_type.is_default_data_type() {
            if self.is_packing_enabled() {
                return Ok(share_data_type(&Undefined1DataType::data_type()));
            }
            return Ok(data_type);
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

impl AlignedStructurePacker for StructureDataType {
    fn create_component_packer(
        &self,
        pack_value: i32,
        data_organization: &DataOrganizationImpl,
    ) -> Box<dyn AlignedComponentPacker> {
        Box::new(RealAlignedComponentPacker::new(pack_value, data_organization))
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
    use crate::program::model::data::byte_data_type::ByteDataType;
    use crate::program::model::data::dword_data_type::DWordDataType;
    use crate::program::model::mem::MemoryAccessException;

    fn sample() -> StructureDataType {
        StructureDataType::new("MyStruct", 0)
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
    fn zero_length_structure_reports_length_one_and_empty_representation() {
        let s = sample();
        assert!(s.structure_data_type_is_zero_length());
        assert_eq!(s.length(), 1);
        assert_eq!(
            s.representation(&MockBuf, &MockSettings, 0),
            "<Empty-Structure>"
        );
    }

    #[test]
    fn defined_structure_reports_stored_length_and_blank_representation() {
        let mut s = sample();
        s.set_stored_struct_length(8);
        s.num_components = 1;
        assert!(!s.structure_data_type_is_zero_length());
        assert_eq!(s.length(), 8);
        assert_eq!(s.representation(&MockBuf, &MockSettings, 8), "");
    }

    #[test]
    fn has_language_dependant_length_tracks_packing() {
        let mut s = sample();
        assert!(!s.structure_data_type_has_language_dependant_length());
        s.packing_value = crate::program::model::data::composite_internal::DEFAULT_PACKING;
        assert!(s.structure_data_type_has_language_dependant_length());
    }

    #[test]
    fn default_label_prefix_uses_name() {
        let s = sample();
        assert_eq!(s.default_label_prefix(), Some("MyStruct".to_string()));
    }

    #[test]
    fn add_grows_structure_and_appends_defined_component() {
        let mut s = sample();
        let dtc = s
            .structure_data_type_add(byte_data_type("int", 4), -1, Some("field0".to_string()), None)
            .unwrap();
        assert_eq!(dtc.get_offset(), 0);
        assert_eq!(dtc.get_ordinal(), 0);
        assert_eq!(dtc.get_length(), 4);
        assert_eq!(s.stored_struct_length(), 4);
        assert_eq!(s.structure_data_type_get_num_components(), 1);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 1);

        let dtc2 = s
            .structure_data_type_add(byte_data_type("short", 2), -1, None, None)
            .unwrap();
        assert_eq!(dtc2.get_offset(), 4);
        assert_eq!(dtc2.get_ordinal(), 1);
        assert_eq!(s.stored_struct_length(), 6);
        assert_eq!(s.structure_data_type_get_num_components(), 2);
    }

    #[test]
    fn add_rejects_cyclic_component_via_check_ancestry() {
        // "Outer" contains "Inner" contains a same-named-and-pathed "Outer" -- adding this
        // three-level "Inner" (which already has "Outer" within it) to "Outer" itself would be
        // cyclic, matching Java's `DataTypeUtilities.checkAncestry` rejection.
        let mut nested_outer = sample();
        nested_outer.name = "Outer".to_string();

        let mut inner = sample();
        inner.name = "Inner".to_string();
        inner
            .structure_data_type_add(Box::new(nested_outer), -1, Some("back_ref".to_string()), None)
            .unwrap();

        let mut outer = sample();
        outer.name = "Outer".to_string();
        let err = match outer.structure_data_type_add(Box::new(inner), -1, None, None) {
            Err(e) => e,
            Ok(_) => panic!("expected a cyclic-dependency rejection"),
        };
        assert!(err.contains("DataTypeDependencyException"));
        // The rejected add must not have partially mutated the structure.
        assert_eq!(outer.structure_data_type_get_num_defined_components(), 0);
    }

    #[test]
    fn add_accepts_non_cyclic_component() {
        // A plain (non-composite) component is never "part of" anything -- check_ancestry must
        // not spuriously reject ordinary adds (already exercised implicitly by every other test
        // in this module, but asserted explicitly here as the direct counterpart to the rejection
        // test above).
        let mut s = sample();
        assert!(s
            .structure_data_type_add(byte_data_type("int", 4), -1, None, None)
            .is_ok());
    }

    #[test]
    fn get_component_synthesizes_undefined_filler_between_defined_components() {
        let mut s = sample();
        // Defined component of length 4 at ordinal/offset 0, then a length-1 gap (ordinal 1,
        // offset 4) before another defined component at ordinal 2, offset 5 -- built directly via
        // `components_mut` to control offsets precisely (mirroring a non-packed structure with an
        // explicit undefined byte in the middle).
        s.components_mut().push(DataTypeComponentImpl::new(
            byte_data_type("int", 4),
            None,
            4,
            0,
            0,
            None,
            None,
        ));
        s.components_mut().push(DataTypeComponentImpl::new(
            byte_data_type("byte", 1),
            None,
            1,
            2,
            5,
            None,
            None,
        ));
        s.set_stored_num_components(3);
        s.set_stored_struct_length(6);

        let defined = s.structure_data_type_get_component(0).unwrap();
        assert_eq!(defined.get_length(), 4);

        let undefined = s.structure_data_type_get_component(1).unwrap();
        assert!(undefined.is_undefined());
        assert_eq!(undefined.get_offset(), 4);
        assert_eq!(undefined.get_length(), 1);

        let defined2 = s.structure_data_type_get_component(2).unwrap();
        assert_eq!(defined2.get_offset(), 5);

        assert!(s.structure_data_type_get_component(3).is_err());

        let all = s.structure_data_type_get_components();
        assert_eq!(all.len(), 3);
        assert!(all[1].is_undefined());
    }

    #[test]
    fn repack_recomputes_ordinals_and_num_components_for_non_packed_gaps() {
        let mut s = sample();
        // A single defined 4-byte component placed at offset 2 (as if two undefined bytes were
        // manually inserted before it) with a stale ordinal of 0 and a structure length of 8
        // (two undefined bytes trail it too); repack should recompute the ordinal to 2 (after the
        // two leading undefined bytes) and numComponents to 7 (2 leading + 1 defined + 2
        // trailing... i.e. undefined-byte-count + defined-component-count).
        s.components_mut().push(DataTypeComponentImpl::new(
            byte_data_type("int", 4),
            None,
            4,
            0,
            2,
            None,
            None,
        ));
        s.set_stored_struct_length(8);
        s.set_stored_num_components(1);

        let changed = s.structure_data_type_repack(false);
        assert!(changed);
        assert_eq!(s.components()[0].get_ordinal(), 2);
        // 2 leading undefined + 1 defined + 2 trailing undefined (offsets 6,7) = 5
        assert_eq!(s.structure_data_type_get_num_components(), 5);

        // Running repack again with nothing changed should report no change.
        assert!(!s.structure_data_type_repack(false));
    }

    #[test]
    fn packed_repack_computes_layout_via_aligned_structure_packer() {
        let mut s = sample();
        s.packing_value = crate::program::model::data::composite_internal::DEFAULT_PACKING;

        // Default data organization: byte aligns to 1, dword to 4.
        s.structure_data_type_add(share_data_type(&ByteDataType::data_type()), -1, Some("a".to_string()), None)
            .unwrap();
        assert_eq!(s.stored_struct_length(), 1);

        s.structure_data_type_add(share_data_type(&DWordDataType::data_type()), -1, Some("b".to_string()), None)
            .unwrap();

        // "a" (len 1) stays at offset 0; "b" (len 4) is aligned up from next_offset=1 to offset
        // 4; overall length (10 -> aligned to 4-byte alignment) is 8.
        assert_eq!(s.structure_data_type_get_num_components(), 2);
        assert_eq!(s.stored_struct_length(), 8);
        let a = s.structure_data_type_get_component(0).unwrap();
        assert_eq!(a.get_offset(), 0);
        assert_eq!(a.get_field_name(), Some("a".to_string()));
        let b = s.structure_data_type_get_component(1).unwrap();
        assert_eq!(b.get_offset(), 4);
        assert_eq!(b.get_length(), 4);
        assert_eq!(b.get_field_name(), Some("b".to_string()));

        // Repacking again with a stable layout reports no further change.
        assert!(!s.structure_data_type_repack(false));
    }

    #[test]
    fn is_equivalent_compares_packing_length_and_components() {
        let mut a = sample();
        a.structure_data_type_add(byte_data_type("int", 4), -1, Some("x".to_string()), None)
            .unwrap();

        let mut b = sample();
        b.structure_data_type_add(byte_data_type("int", 4), -1, Some("x".to_string()), None)
            .unwrap();

        assert!(a.structure_data_type_is_equivalent(&b));

        // Different field name -> DataTypeComponentImpl::is_equivalent should differ.
        let mut c = sample();
        c.structure_data_type_add(byte_data_type("int", 4), -1, Some("y".to_string()), None)
            .unwrap();
        assert!(!a.structure_data_type_is_equivalent(&c));

        // Different structure length (non-packed) -> not equivalent.
        let mut d = sample();
        d.structure_data_type_add(byte_data_type("int", 4), -1, Some("x".to_string()), None)
            .unwrap();
        d.set_stored_struct_length(9);
        assert!(!a.structure_data_type_is_equivalent(&d));
    }

    #[test]
    fn replace_with_copies_non_packed_components_and_settings() {
        let mut source = sample();
        source
            .structure_data_type_add(byte_data_type("int", 4), -1, Some("a".to_string()), None)
            .unwrap();
        source
            .structure_data_type_add(byte_data_type("short", 2), -1, Some("b".to_string()), None)
            .unwrap();

        let mut target = sample();
        // Pre-existing (now-stale) state that replaceWith must fully discard.
        target
            .structure_data_type_add(byte_data_type("byte", 1), -1, Some("stale".to_string()), None)
            .unwrap();

        target.structure_data_type_replace_with(&source).unwrap();

        assert_eq!(target.stored_struct_length(), 6);
        assert_eq!(target.structure_data_type_get_num_defined_components(), 2);
        let a = target.structure_data_type_get_component(0).unwrap();
        assert_eq!(a.get_field_name(), Some("a".to_string()));
        assert_eq!(a.get_offset(), 0);
        let b = target.structure_data_type_get_component(1).unwrap();
        assert_eq!(b.get_field_name(), Some("b".to_string()));
        assert_eq!(b.get_offset(), 4);
    }

    #[test]
    fn replace_with_empty_source_clears_target() {
        let source = sample(); // isNotYetDefined() -- no components, non-packed
        let mut target = three_component_sample();

        target.structure_data_type_replace_with(&source).unwrap();

        assert_eq!(target.structure_data_type_get_num_defined_components(), 0);
        assert_eq!(target.stored_struct_length(), 0);
    }

    #[test]
    fn replace_with_packed_source_uses_add_and_computes_layout() {
        let mut source = sample();
        source.packing_value = crate::program::model::data::composite_internal::DEFAULT_PACKING;
        source
            .structure_data_type_add(share_data_type(&ByteDataType::data_type()), -1, Some("a".to_string()), None)
            .unwrap();
        source
            .structure_data_type_add(share_data_type(&DWordDataType::data_type()), -1, Some("b".to_string()), None)
            .unwrap();

        let mut target = sample();
        target.structure_data_type_replace_with(&source).unwrap();

        assert!(target.is_packing_enabled());
        assert_eq!(target.structure_data_type_get_num_defined_components(), 2);
        assert_eq!(target.stored_struct_length(), 8); // dword aligned to 4
        let b = target.structure_data_type_get_component(1).unwrap();
        assert_eq!(b.get_offset(), 4);
    }

    #[test]
    fn insert_at_offset_shifts_existing_defined_components() {
        let mut s = sample();
        s.structure_data_type_add(byte_data_type("int", 4), -1, Some("a".to_string()), None)
            .unwrap();
        s.structure_data_type_add(byte_data_type("int", 4), -1, Some("b".to_string()), None)
            .unwrap();
        assert_eq!(s.stored_struct_length(), 8);

        // Insert a 2-byte component right at offset 4 (between the two existing components):
        // the second component should shift from offset 4 to offset 6.
        let inserted = s
            .structure_data_type_insert_at_offset(4, byte_data_type("short", 2), -1, Some("mid".to_string()), None)
            .unwrap();
        assert_eq!(inserted.get_offset(), 4);
        assert_eq!(inserted.get_ordinal(), 1);
        assert_eq!(s.stored_struct_length(), 10);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 3);

        let shifted = s.structure_data_type_get_component(2).unwrap();
        assert_eq!(shifted.get_offset(), 6);
        assert_eq!(shifted.get_field_name(), Some("b".to_string()));
    }

    #[test]
    fn insert_at_offset_beyond_current_length_grows_structure_with_padding() {
        let mut s = sample();
        s.structure_data_type_add(byte_data_type("int", 4), -1, None, None)
            .unwrap();
        // Insert at offset 8 (4 bytes past the current 4-byte end) -- Java grows the structure
        // with undefined padding first, then places the new component at offset 8.
        let inserted = s
            .structure_data_type_insert_at_offset(8, byte_data_type("byte", 1), -1, None, None)
            .unwrap();
        assert_eq!(inserted.get_offset(), 8);
        assert_eq!(s.stored_struct_length(), 9);
        // 1 defined int (ordinal 0, occupying offsets 0-3) + 4 undefined single-byte fillers
        // (offsets 4-7, one ordinal each) + 1 defined byte (offset 8) = 6 ordinals total; the
        // structLength (9, one past the last occupied byte) is a byte count, not an ordinal count.
        assert_eq!(s.structure_data_type_get_num_components(), 6);
    }

    #[test]
    fn insert_at_ordinal_shifts_and_inserts_before_existing_component() {
        let mut s = sample();
        s.structure_data_type_add(byte_data_type("int", 4), -1, Some("a".to_string()), None)
            .unwrap();
        s.structure_data_type_add(byte_data_type("int", 4), -1, Some("b".to_string()), None)
            .unwrap();

        // Insert at ordinal 1 (before "b") -- matches Java's insert(int, DataType, int, String,
        // String).
        let inserted = s
            .structure_data_type_insert(1, byte_data_type("short", 2), -1, Some("mid".to_string()), None)
            .unwrap();
        assert_eq!(inserted.get_offset(), 4);
        assert_eq!(inserted.get_ordinal(), 1);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 3);

        let b = s.structure_data_type_get_component(2).unwrap();
        assert_eq!(b.get_field_name(), Some("b".to_string()));
        assert_eq!(b.get_offset(), 6);
    }

    #[test]
    fn insert_at_ordinal_equal_to_num_components_delegates_to_add() {
        let mut s = sample();
        s.structure_data_type_add(byte_data_type("int", 4), -1, None, None)
            .unwrap();
        let inserted = s
            .structure_data_type_insert(1, byte_data_type("byte", 1), -1, None, None)
            .unwrap();
        assert_eq!(inserted.get_offset(), 4);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
    }

    #[test]
    fn insert_rejects_out_of_bounds_ordinal() {
        let mut s = sample();
        assert!(s
            .structure_data_type_insert(1, byte_data_type("byte", 1), -1, None, None)
            .is_err());
        assert!(s
            .structure_data_type_insert_at_offset(-1, byte_data_type("byte", 1), -1, None, None)
            .is_err());
    }

    /// Builds a 3-component non-packed structure: int@0 (ordinal 0), short@4 (ordinal 1),
    /// byte@6 (ordinal 2), structLength=7.
    fn three_component_sample() -> StructureDataType {
        let mut s = sample();
        s.structure_data_type_add(byte_data_type("int", 4), -1, Some("a".to_string()), None)
            .unwrap();
        s.structure_data_type_add(byte_data_type("short", 2), -1, Some("b".to_string()), None)
            .unwrap();
        s.structure_data_type_add(byte_data_type("byte", 1), -1, Some("c".to_string()), None)
            .unwrap();
        assert_eq!(s.stored_struct_length(), 7);
        s
    }

    #[test]
    fn delete_removes_component_and_shifts_following_offsets() {
        let mut s = three_component_sample();
        s.structure_data_type_delete(1).unwrap(); // remove "b" (short@4)
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
        assert_eq!(s.stored_struct_length(), 5);
        let c = s.structure_data_type_get_component(1).unwrap();
        assert_eq!(c.get_field_name(), Some("c".to_string()));
        assert_eq!(c.get_offset(), 4);
    }

    #[test]
    fn delete_rejects_out_of_bounds_ordinal() {
        let mut s = three_component_sample();
        assert!(s.structure_data_type_delete(10).is_err());
    }

    #[test]
    fn delete_ordinals_batch_matches_sequential_deletes() {
        let mut s = three_component_sample();
        let mut ordinals = HashSet::new();
        ordinals.insert(0);
        ordinals.insert(2);
        s.structure_data_type_delete_ordinals(&ordinals).unwrap();
        assert_eq!(s.structure_data_type_get_num_defined_components(), 1);
        let remaining = s.structure_data_type_get_component(0).unwrap();
        assert_eq!(remaining.get_field_name(), Some("b".to_string()));
        assert_eq!(remaining.get_offset(), 0);
        assert_eq!(s.stored_struct_length(), 2);
    }

    #[test]
    fn delete_ordinals_empty_set_is_no_op() {
        let mut s = three_component_sample();
        s.structure_data_type_delete_ordinals(&HashSet::new()).unwrap();
        assert_eq!(s.structure_data_type_get_num_defined_components(), 3);
    }

    #[test]
    fn delete_at_offset_removes_containing_component_and_shifts() {
        let mut s = three_component_sample();
        s.structure_data_type_delete_at_offset(4).unwrap(); // removes "b" (short@4..5)
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
        assert_eq!(s.stored_struct_length(), 5);
    }

    #[test]
    fn clear_at_offset_preserves_length_and_leaves_undefined_gap() {
        let mut s = three_component_sample();
        s.structure_data_type_clear_at_offset(4).unwrap(); // clears "b" in place
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
        // Structure length unchanged (clear does not shift trailing components).
        assert_eq!(s.stored_struct_length(), 7);
        let filler = s.structure_data_type_get_component(1).unwrap();
        assert!(filler.is_undefined());
    }

    #[test]
    fn clear_component_removes_defined_component_without_shifting_offset() {
        let mut s = three_component_sample();
        s.structure_data_type_clear_component(1).unwrap();
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
        assert_eq!(s.stored_struct_length(), 7);
    }

    #[test]
    fn delete_all_resets_structure() {
        let mut s = three_component_sample();
        s.structure_data_type_delete_all();
        assert_eq!(s.structure_data_type_get_num_defined_components(), 0);
        assert_eq!(s.structure_data_type_get_num_components(), 0);
        assert_eq!(s.stored_struct_length(), 0);
    }

    #[test]
    fn grow_structure_adds_undefined_bytes_at_end() {
        let mut s = three_component_sample();
        s.structure_data_type_grow_structure(3).unwrap();
        assert_eq!(s.stored_struct_length(), 10);
        assert_eq!(s.structure_data_type_get_num_components(), 6);
        assert!(s.structure_data_type_grow_structure(-1).is_err());
    }

    #[test]
    fn set_length_grows_and_shrinks() {
        let mut s = three_component_sample();
        s.structure_data_type_set_length(10).unwrap();
        assert_eq!(s.stored_struct_length(), 10);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 3);

        s.structure_data_type_set_length(5).unwrap();
        assert_eq!(s.stored_struct_length(), 5);
        // Truncates the "b" (short@4..5) and "c" (byte@6) components since they fall at/after
        // offset 5.
        assert_eq!(s.structure_data_type_get_num_defined_components(), 1);
        assert!(s.structure_data_type_set_length(-1).is_err());
    }

    #[test]
    fn get_component_containing_and_at_or_after_offset() {
        let s = three_component_sample();
        let containing = s.structure_data_type_get_component_containing(5).unwrap();
        assert_eq!(containing.get_field_name(), Some("b".to_string()));

        // Offset 5 falls within "b" (short@4, occupying offsets 4-5), so the "at or after" query
        // returns "b" itself, not the next component.
        let at_or_after = s
            .structure_data_type_get_defined_component_at_or_after_offset(5)
            .unwrap();
        assert_eq!(at_or_after.get_field_name(), Some("b".to_string()));

        // Offset 6 falls exactly at the start of "c" (byte@6).
        let at_c = s
            .structure_data_type_get_defined_component_at_or_after_offset(6)
            .unwrap();
        assert_eq!(at_c.get_field_name(), Some("c".to_string()));

        assert!(s.structure_data_type_get_component_containing(-1).is_none());
        assert!(s.structure_data_type_get_component_containing(100).is_none());
    }

    #[test]
    fn get_components_containing_includes_undefined_filler() {
        let mut s = sample();
        s.structure_data_type_add(byte_data_type("int", 4), -1, None, None)
            .unwrap();
        s.set_stored_struct_length(6); // 2 trailing undefined bytes
        s.set_stored_num_components(6);
        let containing = s.structure_data_type_get_components_containing(4);
        assert_eq!(containing.len(), 1);
        assert!(containing[0].is_undefined());
    }

    #[test]
    fn get_data_type_at_returns_component_containing_offset() {
        let s = three_component_sample();
        let dtc = s.structure_data_type_get_data_type_at(5).unwrap();
        assert_eq!(dtc.get_field_name(), Some("b".to_string()));
    }

    #[test]
    fn add_bit_field_appends_bitfield_component() {
        let mut s = sample();
        let dtc = s
            .structure_data_type_add_bit_field(int_data_type("int", 4), 3, Some("flag".to_string()), None)
            .unwrap();
        assert!(dtc.is_bit_field_component());
        assert_eq!(dtc.get_offset(), 0);
        assert_eq!(dtc.get_length(), 1); // storage size for a 3-bit field at offset 0
        assert_eq!(s.stored_struct_length(), 1);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 1);
    }

    #[test]
    fn add_bit_field_rejects_invalid_base_type() {
        let mut s = sample();
        let err = match s.structure_data_type_add_bit_field(byte_data_type("notint", 4), 3, None, None) {
            Err(e) => e,
            Ok(_) => panic!("expected an invalid-base-type error"),
        };
        assert!(err.contains("InvalidDataTypeException"));
    }

    #[test]
    fn insert_bit_field_at_places_bitfield_at_requested_offset() {
        let mut s = sample();
        s.structure_data_type_add(byte_data_type("int", 4), -1, Some("a".to_string()), None)
            .unwrap();

        // Insert a 4-bit field at bit-offset 2 within byte offset 4 (right after "a"), byteWidth 1.
        let dtc = s
            .structure_data_type_insert_bit_field_at(4, 1, 2, int_data_type("byte", 1), 4, Some("bits".to_string()), None)
            .unwrap();
        assert!(dtc.is_bit_field_component());
        assert_eq!(dtc.get_offset(), 4);
        assert_eq!(dtc.get_length(), 1);
        assert_eq!(s.stored_struct_length(), 5);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
    }

    #[test]
    fn insert_bit_field_at_rejects_negative_offset_and_bad_byte_width() {
        let mut s = sample();
        assert!(s
            .structure_data_type_insert_bit_field_at(-1, 1, 0, int_data_type("byte", 1), 4, None, None)
            .is_err());
        assert!(s
            .structure_data_type_insert_bit_field_at(0, 0, 0, int_data_type("byte", 1), 4, None, None)
            .is_err());
        assert!(s
            .structure_data_type_insert_bit_field_at(0, 1, 0, byte_data_type("notint", 1), 4, None, None)
            .is_err());
    }

    #[test]
    fn insert_bit_field_non_packed_delegates_to_insert_bit_field_at() {
        let mut s = sample();
        s.structure_data_type_add(byte_data_type("int", 4), -1, Some("a".to_string()), None)
            .unwrap();
        // Non-packed insertBitField(ordinal) resolves the byte offset from the target ordinal's
        // component (here, appending past the end -> offset == current struct length).
        let dtc = s
            .structure_data_type_insert_bit_field(1, 1, 0, int_data_type("byte", 1), 4, Some("bits".to_string()), None)
            .unwrap();
        assert!(dtc.is_bit_field_component());
        assert_eq!(dtc.get_offset(), 4);
        assert_eq!(s.stored_struct_length(), 5);
    }

    #[test]
    fn insert_bit_field_packed_delegates_to_insert() {
        let mut s = sample();
        s.packing_value = crate::program::model::data::composite_internal::DEFAULT_PACKING;
        s.structure_data_type_add(byte_data_type("byte", 1), -1, Some("a".to_string()), None)
            .unwrap();

        let dtc = s
            .structure_data_type_insert_bit_field(1, 0, 0, int_data_type("int", 4), 4, Some("bits".to_string()), None)
            .unwrap();
        assert!(dtc.is_bit_field_component());
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
    }

    #[test]
    fn insert_bit_field_rejects_out_of_bounds_ordinal() {
        let mut s = sample();
        assert!(s
            .structure_data_type_insert_bit_field(5, 1, 0, int_data_type("byte", 1), 4, None, None)
            .is_err());
    }

    // ------------------------------------------------------------------------------------------
    // `StructureDataType`: the first real, production concrete `StructureDataType` (as
    // opposed to the `#[cfg(test)]`-scoped `StructureDataType` above). These tests exercise
    // construction, `copy`/`clone`, and the ancestor `Composite`/`Structure`/`DataType` trait
    // surface (`add`/`insert`/`delete`/`get_component`/etc., not just the `structure_data_type_*`
    // methods directly) to prove the whole trait stack genuinely composes on a real struct.
    // ------------------------------------------------------------------------------------------

    #[test]
    fn new_creates_empty_root_category_structure() {
        let s = StructureDataType::new("Foo", 0);
        assert_eq!(s.get_name(), "Foo");
        assert_eq!(s.get_category_path(), ROOT.clone());
        assert!(s.structure_data_type_is_zero_length());
        assert_eq!(DataType::get_length(&s), 1);
        assert!(s.is_not_yet_defined());
    }

    #[test]
    fn new_with_length_reports_that_length_and_num_components() {
        let s = StructureDataType::new("Foo", 4);
        assert_eq!(DataType::get_length(&s), 4);
        assert_eq!(Composite::get_num_components(&s), 4);
        assert_eq!(Composite::get_num_defined_components(&s), 0);
        assert!(!s.is_not_yet_defined());
    }

    #[test]
    #[should_panic(expected = "Length can't be negative")]
    fn new_rejects_negative_length() {
        StructureDataType::new("Foo", -1);
    }

    #[test]
    #[should_panic(expected = "Invalid DataType name")]
    fn new_rejects_invalid_name() {
        StructureDataType::new("   ", 0);
    }

    #[test]
    fn new_in_category_uses_specified_category() {
        let path = CategoryPath::new(ROOT.clone(), &["cat"]).expect("valid category path");
        let s = StructureDataType::new_in_category(path.clone(), "Foo", 0);
        assert_eq!(s.get_category_path(), path);
    }

    #[test]
    fn with_archive_identity_preserves_universal_id_and_change_times() {
        let s = StructureDataType::with_archive_identity(
            ROOT.clone(),
            "Foo",
            0,
            UniversalID::new(42),
            None,
            100,
            200,
            None,
        );
        assert_eq!(s.universal_id, UniversalID::new(42));
        assert_eq!(s.last_change_time, 100);
        assert_eq!(s.last_change_time_in_source_archive, 200);
    }

    struct RealByteDataType {
        name: &'static str,
        length: i32,
    }
    impl DataType for RealByteDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name() && self.length == dt.get_length()
        }
    }

    fn dt(name: &'static str, length: i32) -> Box<dyn DataType> {
        Box::new(RealByteDataType { name, length })
    }

    #[test]
    fn add_insert_delete_via_composite_trait_object() {
        let mut s = StructureDataType::new("Foo", 0);
        let composite: &mut dyn Composite = &mut s;
        composite.add(dt("int", 4)).expect("add int");
        composite.add_with_name(dt("short", 2), Some("field1".to_string()), None).expect("add short");
        assert_eq!(composite.get_num_components(), 2);
        assert_eq!(composite.get_num_defined_components(), 2);

        composite.insert(1, dt("byte", 1)).expect("insert byte");
        assert_eq!(composite.get_num_components(), 3);
        assert_eq!(composite.get_component(1).unwrap().get_data_type().get_name(), "byte");

        composite.delete(0).expect("delete ordinal 0");
        assert_eq!(composite.get_num_components(), 2);
        assert_eq!(composite.get_component(0).unwrap().get_data_type().get_name(), "byte");
    }

    #[test]
    fn get_components_and_defined_components_via_structure_trait_object() {
        let mut s = StructureDataType::new("Foo", 0);
        s.add(dt("int", 4)).expect("add int");
        s.add(dt("short", 2)).expect("add short");

        let structure: &dyn Structure = &s;
        assert_eq!(structure.get_num_components(), 2);
        let components = structure.get_components();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].get_data_type().get_name(), "int");
        assert_eq!(components[1].get_data_type().get_name(), "short");

        assert_eq!(
            structure.get_component_containing(0).unwrap().get_data_type().get_name(),
            "int"
        );
        assert_eq!(
            structure.get_component_at(4).unwrap().get_data_type().get_name(),
            "short"
        );
    }

    #[test]
    fn is_equivalent_between_two_real_structures() {
        let mut a = StructureDataType::new("A", 0);
        a.structure_data_type_add(dt("int", 4), -1, Some("x".to_string()), None).unwrap();

        let mut b = StructureDataType::new("B", 0);
        b.structure_data_type_add(dt("int", 4), -1, Some("x".to_string()), None).unwrap();

        assert!(a.structure_data_type_is_equivalent(&b));

        b.structure_data_type_add(dt("short", 2), -1, Some("y".to_string()), None).unwrap();
        assert!(!a.structure_data_type_is_equivalent(&b));
    }

    #[test]
    fn copy_data_type_produces_independent_equivalent_structure() {
        struct NoopDtm;
        impl DataTypeManager for NoopDtm {
            fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
                shared_default_organization()
            }
        }

        let mut original = StructureDataType::new("Original", 0);
        original.add_with_name(dt("int", 4), Some("field0".to_string()), None).unwrap();
        original.set_description("a description").unwrap();

        let copy = original.copy_data_type(&NoopDtm);
        let copy_struct = copy.as_structure().expect("copy is a Structure");
        assert_eq!(copy.get_name(), "Original");
        assert_eq!(copy.get_description(), "a description");
        assert_eq!(copy_struct.get_num_components(), 1);
        assert_eq!(
            Structure::get_component(copy_struct, 0).unwrap().get_data_type().get_name(),
            "int"
        );

        // Independent: mutating the original does not affect the copy.
        original.add_with_name(dt("short", 2), Some("field1".to_string()), None).unwrap();
        assert_eq!(Composite::get_num_components(&original), 2);
        assert_eq!(copy_struct.get_num_components(), 1);
    }

    #[test]
    fn clone_data_type_preserves_archive_identity() {
        struct NoopDtm;
        impl DataTypeManager for NoopDtm {
            fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
                shared_default_organization()
            }
        }

        let mut original = StructureDataType::with_archive_identity(
            ROOT.clone(),
            "Original",
            0,
            UniversalID::new(7),
            None,
            10,
            20,
            None,
        );
        original.add_with_name(dt("int", 4), Some("field0".to_string()), None).unwrap();

        let cloned = original.clone_data_type(&NoopDtm);
        let cloned_struct = cloned.as_structure().expect("clone is a Structure");
        assert_eq!(cloned.get_name(), "Original");
        assert_eq!(cloned_struct.get_num_components(), 1);
    }

    #[test]
    fn non_packed_alignment_defaults_to_one_and_machine_alignment_uses_data_organization() {
        let s = StructureDataType::new("Foo", 0);
        assert_eq!(DataType::get_alignment(&s), 1);

        let mut machine_aligned = StructureDataType::new("Bar", 0);
        machine_aligned.set_to_machine_aligned();
        assert_eq!(DataType::get_alignment(&machine_aligned), 8); // DataOrganizationImpl::DEFAULT_MACHINE_ALIGNMENT
    }

    #[test]
    fn packing_enabled_structure_computes_alignment_without_panicking() {
        let mut s = StructureDataType::new("Packed", 0);
        s.set_packing_enabled(true);
        s.add(dt("int", 4)).expect("add int");
        s.add(dt("byte", 1)).expect("add byte");
        // Must not panic reaching into the data organization/`AlignedComponentPacker`.
        let alignment = DataType::get_alignment(&s);
        assert!(alignment >= 1);
        assert!(s.is_packing_enabled());
    }

    #[test]
    fn data_type_size_changed_shrinks_component_and_opens_undefined_gap() {
        let mut s = StructureDataType::new("Foo", 0);
        s.structure_data_type_add(dt("wide", 8), -1, None, None).unwrap();
        s.structure_data_type_add(dt("short", 2), -1, None, None).unwrap();
        assert_eq!(s.stored_struct_length(), 10);

        // Simulate "wide"'s own data type shrinking from 8 bytes to 4.
        s.structure_data_type_data_type_size_changed(dt("wide", 4).as_ref()).unwrap();

        assert_eq!(s.components()[0].get_length(), 4);
        assert_eq!(s.components()[1].get_offset(), 8); // unmoved: the freed bytes become undefined filler
        assert_eq!(s.components()[1].get_ordinal(), 5); // 1 + 4 newly-opened undefined ordinals
        assert_eq!(s.stored_struct_length(), 10); // overall length unchanged
        assert_eq!(s.stored_num_components(), 6); // 2 defined + 4 undefined filler
    }

    #[test]
    fn data_type_size_changed_grows_last_component_and_grows_structure() {
        let mut s = StructureDataType::new("Foo", 0);
        s.structure_data_type_add(dt("small", 2), -1, None, None).unwrap();
        assert_eq!(s.stored_struct_length(), 2);

        // Simulate "small"'s own data type growing from 2 bytes to 6: no room after it, so the
        // structure itself must grow (exercising the private `doGrowStructure` path inlined into
        // `consumeBytesAfter`).
        s.structure_data_type_data_type_size_changed(dt("small", 6).as_ref()).unwrap();

        assert_eq!(s.components()[0].get_length(), 6);
        assert_eq!(s.stored_struct_length(), 6);
        assert_eq!(s.stored_num_components(), 1); // fully consumed, no leftover undefined bytes
    }

    #[test]
    fn data_type_alignment_changed_is_no_op_when_non_packed() {
        let mut s = StructureDataType::new("Foo", 0);
        s.structure_data_type_add(dt("int", 4), -1, None, None).unwrap();
        let length_before = s.stored_struct_length();
        s.structure_data_type_data_type_alignment_changed(dt("int", 4).as_ref());
        assert_eq!(s.stored_struct_length(), length_before);
    }

    #[test]
    fn data_type_alignment_changed_repacks_when_packing_enabled() {
        let mut s = StructureDataType::new("Packed", 0);
        s.set_packing_enabled(true);
        s.add(dt("int", 4)).expect("add int");
        // Must not panic reaching into the data organization/`AlignedComponentPacker`, and must
        // leave the structure in a consistent, still-packed state.
        s.structure_data_type_data_type_alignment_changed(dt("int", 4).as_ref());
        assert!(s.is_packing_enabled());
        assert_eq!(Composite::get_num_components(&s), 1);
    }

    #[test]
    fn data_type_deleted_substitutes_bad_data_type_stand_in_preserving_length() {
        let mut s = StructureDataType::new("Foo", 0);
        s.structure_data_type_add(dt("int", 4), -1, Some("a".to_string()), None).unwrap();
        s.structure_data_type_add(dt("short", 2), -1, Some("b".to_string()), None).unwrap();

        s.structure_data_type_data_type_deleted(dt("int", 4).as_ref()).unwrap();

        assert_eq!(s.components()[0].get_data_type().get_name(), "-BAD-");
        assert_eq!(s.components()[0].get_length(), 4); // BadDataType's getLength()==-1 preserves oldLen
        assert_eq!(s.components()[1].get_data_type().get_name(), "short"); // unaffected
        assert_eq!(s.stored_struct_length(), 6); // no impact on overall layout
    }

    #[test]
    fn data_type_replaced_swaps_component_and_grows_to_new_length() {
        let mut s = StructureDataType::new("Foo", 0);
        s.structure_data_type_add(dt("int", 4), -1, Some("a".to_string()), None).unwrap();

        s.structure_data_type_data_type_replaced(dt("int", 4).as_ref(), dt("long", 8)).unwrap();

        assert_eq!(s.components()[0].get_data_type().get_name(), "long");
        assert_eq!(s.components()[0].get_length(), 8);
        assert_eq!(s.stored_struct_length(), 8);
        assert_eq!(s.stored_num_components(), 1);
    }

    #[test]
    fn data_type_replaced_falls_back_to_default_on_ancestry_rejection() {
        let mut outer = StructureDataType::new("Outer", 0);
        outer.structure_data_type_add(dt("int", 4), -1, Some("x".to_string()), None).unwrap();

        // "Inner" contains a field path-equal to "Outer" itself, so replacing Outer's "int"
        // component with an Inner instance would create a cyclic composite; checkAncestry should
        // reject it, falling back to the non-packed `DataType.DEFAULT` stand-in.
        let mut inner = StructureDataType::new("Inner", 0);
        inner.structure_data_type_add(dt("Outer", 4), -1, Some("back".to_string()), None).unwrap();

        outer
            .structure_data_type_data_type_replaced(dt("int", 4).as_ref(), Box::new(inner))
            .unwrap();

        assert!(outer.components()[0].get_data_type().is_default_data_type());
        assert_eq!(outer.components()[0].get_length(), 1);
        assert_eq!(outer.stored_struct_length(), 4); // unchanged: substituting a 1-byte filler just
                                                       // opens undefined bytes, doesn't shrink the struct
        assert_eq!(outer.stored_num_components(), 4);
    }

    #[test]
    fn data_type_replaced_updates_bitfield_base_type() {
        let mut s = StructureDataType::new("Foo", 0);
        s.structure_data_type_add_bit_field(int_data_type("int", 4), 5, Some("flags".to_string()), None)
            .unwrap();

        s.structure_data_type_data_type_replaced(int_data_type("int", 4).as_ref(), int_data_type("long", 8))
            .unwrap();

        let stored = s.components()[0].get_data_type();
        let bitfield = stored.as_bit_field_data_type().expect("still a bitfield");
        assert_eq!(bitfield.get_base_data_type().get_name(), "long");
        assert_eq!(bitfield.get_declared_bit_size(), 5);
    }

    // --------------------------------------------------------------------------------------
    // `replace`/`replaceAtOffset`: ported from `StructureDataType.replace`/`.replaceAtOffset`'s
    // real Java algorithm. Several of these are direct Rust ports of the verified Java JUnit
    // fixtures in `StructureDBTest` (`testReplace1`/`testReplace2`/`testReplace3`/
    // `testReplaceFailure`/`testReplaceAt`), reusing that file's exact same non-packed
    // byte/word/dword/byte fixture (offsets 0/1/3/7, lengths 1/2/4/1, total length 8) so the
    // expected final ordinals/offsets below are cross-checked against real Ghidra behavior
    // rather than hand-derived.
    // --------------------------------------------------------------------------------------

    /// Matches `StructureDBTest.setUp()`'s fixture: four real (non-packed) components with no
    /// gaps -- offsets 0/1/3/7, lengths 1/2/4/1, total length 8.
    fn byte_word_dword_byte_struct() -> StructureDataType {
        let mut s = StructureDataType::new("Test", 0);
        s.structure_data_type_add(dt("byte1", 1), -1, Some("field1".to_string()), None)
            .unwrap();
        s.structure_data_type_add(dt("word", 2), -1, None, None).unwrap();
        s.structure_data_type_add(dt("dword", 4), -1, Some("field3".to_string()), None)
            .unwrap();
        s.structure_data_type_add(dt("byte4", 1), -1, Some("field4".to_string()), None)
            .unwrap();
        s
    }

    #[test]
    fn replace_same_size_quick_updates_in_place() {
        // Port of `StructureDBTest.testReplace2` ("same size").
        let mut s = byte_word_dword_byte_struct();
        let replaced = s
            .structure_data_type_replace(0, dt("char", 1), 1, None, None)
            .unwrap();
        assert_eq!(replaced.get_data_type().get_name(), "char");
        assert_eq!(s.stored_struct_length(), 8);
        assert_eq!(s.structure_data_type_get_num_components(), 4);
        // Every other component is untouched by an in-place quick update.
        assert_eq!(s.components()[1].get_offset(), 1);
        assert_eq!(s.components()[1].get_ordinal(), 1);
        assert_eq!(s.components()[1].get_data_type().get_name(), "word");
    }

    #[test]
    fn replace_smaller_opens_undefined_gap_and_shifts_trailing_ordinals() {
        // Port of `StructureDBTest.testReplace3` ("smaller").
        let mut s = byte_word_dword_byte_struct();
        let replaced = s
            .structure_data_type_replace(1, dt("char", 1), 1, None, None)
            .unwrap();
        assert_eq!(replaced.get_data_type().get_name(), "char");
        assert_eq!(replaced.get_offset(), 1);
        assert_eq!(replaced.get_ordinal(), 1);

        assert_eq!(s.stored_struct_length(), 8);
        // Total ordinal count grows by one (the byte freed by the 2->1 byte shrink becomes a
        // new undefined ordinal); the defined-component count itself is unchanged (still 4 real
        // entries -- this is a like-for-like swap, not a removal).
        assert_eq!(s.structure_data_type_get_num_components(), 5);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 4);
        assert_eq!(s.components()[2].get_data_type().get_name(), "dword");
        assert_eq!(s.components()[2].get_offset(), 3); // unmoved: non-packed offsets never shift
        assert_eq!(s.components()[2].get_ordinal(), 3); // shifted from 2 by the newly-opened gap
    }

    #[test]
    fn replace_fails_when_not_enough_undefined_space_and_not_last_component() {
        // Port of `StructureDBTest.testReplaceFailure` ("bigger, no space below").
        let mut s = byte_word_dword_byte_struct();
        let err = match s.structure_data_type_replace(0, dt("qword", 8), 8, None, None) {
            Err(e) => e,
            Ok(_) => panic!("expected an IllegalArgumentException-style error"),
        };
        assert!(err.contains("Not enough undefined bytes"));
        // A failed replace must leave the structure untouched.
        assert_eq!(s.stored_struct_length(), 8);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 4);
        assert_eq!(s.components()[0].get_data_type().get_name(), "byte1");
    }

    #[test]
    fn replace_growing_into_available_trailing_undefined_space_fits_exactly() {
        let mut s = StructureDataType::new("Foo", 4); // 4 bytes, entirely undefined
        let dtc = s
            .structure_data_type_replace(0, dt("small", 1), 1, Some("a".to_string()), None)
            .unwrap();
        assert_eq!(dtc.get_offset(), 0);
        assert_eq!(s.stored_struct_length(), 4);
        assert_eq!(s.stored_num_components(), 4); // 1 defined + 3 undefined filler

        // Growing "small" (1 byte) to 4 bytes exactly consumes the 3 remaining undefined bytes
        // -- no structure growth needed, since it is the last (only) defined component.
        let dtc2 = s
            .structure_data_type_replace(0, dt("wide", 4), 4, Some("a2".to_string()), None)
            .unwrap();
        assert_eq!(dtc2.get_offset(), 0);
        assert_eq!(dtc2.get_length(), 4);
        assert_eq!(s.stored_struct_length(), 4); // fit entirely within existing space
        assert_eq!(s.structure_data_type_get_num_defined_components(), 1);
        assert_eq!(s.stored_num_components(), 1); // no leftover undefined bytes
    }

    #[test]
    fn replace_growing_beyond_available_space_grows_the_structure() {
        let mut s = StructureDataType::new("Foo", 4); // 4 bytes, entirely undefined
        s.structure_data_type_replace(0, dt("small", 1), 1, Some("a".to_string()), None)
            .unwrap();
        assert_eq!(s.stored_struct_length(), 4);

        // Growing "small" (1 byte, the last/only defined component) to 5 bytes needs one more
        // byte than the 3 remaining undefined bytes provide, so the structure itself must grow
        // (exercising `checkUndefinedSpaceAvailabilityAfter`'s `growStructure` call).
        let dtc = s
            .structure_data_type_replace(0, dt("wide", 5), 5, Some("a2".to_string()), None)
            .unwrap();
        assert_eq!(dtc.get_offset(), 0);
        assert_eq!(dtc.get_length(), 5);
        assert_eq!(s.stored_struct_length(), 5); // grew by one byte
        assert_eq!(s.structure_data_type_get_num_defined_components(), 1);
        assert_eq!(s.stored_num_components(), 1);
    }

    #[test]
    fn replace_consolidates_overlapping_bitfields_sharing_a_byte() {
        let mut s = StructureDataType::new("Foo", 0);
        // Two 4-bit fields packed into the same single byte (offset 0), occupying disjoint bit
        // ranges (bits 0-3 and 4-7) but the same byte-level footprint.
        s.structure_data_type_insert_bit_field_at(0, 1, 0, int_data_type("byte", 1), 4, Some("lo".to_string()), None)
            .unwrap();
        s.structure_data_type_insert_bit_field_at(0, 1, 4, int_data_type("byte", 1), 4, Some("hi".to_string()), None)
            .unwrap();
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
        assert_eq!(s.stored_struct_length(), 1);

        // Replacing either bitfield must consume both: `StructureDataType.replace`'s bit-field
        // overlap check (case 3) operates at byte granularity via `containsOffset`, matching
        // Java exactly, so both bit-fields sharing this byte are replaced atomically.
        let replaced = s
            .structure_data_type_replace(0, dt("merged", 1), 1, Some("merged".to_string()), None)
            .unwrap();
        assert_eq!(replaced.get_data_type().get_name(), "merged");
        assert_eq!(replaced.get_offset(), 0);
        assert!(!replaced.is_bit_field_component());
        assert_eq!(s.structure_data_type_get_num_defined_components(), 1);
        assert_eq!(s.stored_struct_length(), 1);
        assert_eq!(s.stored_num_components(), 1);
        assert!(!s.components()[0].is_bit_field_component());
    }

    #[test]
    fn replace_in_packed_structure_quick_updates_when_length_and_alignment_match() {
        let mut s = StructureDataType::new("Packed", 0);
        s.set_packing_enabled(true);
        s.structure_data_type_add(dt("byte1", 1), -1, Some("a".to_string()), None).unwrap();
        s.structure_data_type_add(dt("byte2", 1), -1, Some("b".to_string()), None).unwrap();

        // Same length (1) and same (default) alignment as the replaced component triggers the
        // quick-update fast path even though packing is enabled (`doComponentReplacement`'s
        // `dataType.getAlignment() == oldDt.getAlignment()` check).
        let replaced = s
            .structure_data_type_replace(0, dt("replacement", 1), 1, Some("a2".to_string()), None)
            .unwrap();
        assert_eq!(replaced.get_data_type().get_name(), "replacement");
        assert_eq!(replaced.get_ordinal(), 0);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
        assert_eq!(s.components()[0].get_data_type().get_name(), "replacement");
        // Untouched by the quick update (no repack performed on this path).
        assert_eq!(s.components()[1].get_data_type().get_name(), "byte2");
        assert_eq!(s.components()[1].get_ordinal(), 1);
    }

    #[test]
    fn replace_in_packed_structure_falls_back_to_full_replacement_when_size_differs() {
        let mut s = StructureDataType::new("Packed", 0);
        s.set_packing_enabled(true);
        s.structure_data_type_add(dt("byte1", 1), -1, Some("a".to_string()), None).unwrap();
        s.structure_data_type_add(dt("byte2", 1), -1, Some("b".to_string()), None).unwrap();

        let replaced = s
            .structure_data_type_replace(0, dt("replacement", 4), 4, Some("a2".to_string()), None)
            .unwrap();
        assert_eq!(replaced.get_data_type().get_name(), "replacement");
        // Packed structures always do a direct 1-for-1 component swap regardless of size change
        // -- undefined-space bookkeeping is exclusive to non-packed structures.
        assert_eq!(s.structure_data_type_get_num_defined_components(), 2);
        assert_eq!(s.components()[0].get_data_type().get_name(), "replacement");
        assert_eq!(s.components()[1].get_data_type().get_name(), "byte2");
    }

    #[test]
    fn replace_at_offset_matches_verified_java_fixture() {
        // Port of `StructureDBTest.testReplaceAt`.
        let mut s = byte_word_dword_byte_struct();
        assert_eq!(s.stored_struct_length(), 8);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 4);

        s.structure_data_type_replace_at_offset(0, DefaultDataType::boxed(), -1, Some("a".to_string()), None)
            .unwrap();
        s.structure_data_type_replace_at_offset(1, dt("byteb", 1), -1, Some("b".to_string()), None)
            .unwrap();
        s.structure_data_type_replace_at_offset(2, dt("bytec", 1), -1, Some("c".to_string()), None)
            .unwrap();
        s.structure_data_type_replace_at_offset(4, dt("chard", 1), -1, Some("d".to_string()), None)
            .unwrap();

        assert_eq!(s.stored_struct_length(), 8);
        assert_eq!(s.structure_data_type_get_num_defined_components(), 4);

        assert_eq!(s.components()[0].get_offset(), 1);
        assert_eq!(s.components()[0].get_ordinal(), 1);
        assert_eq!(s.components()[0].get_data_type().get_name(), "byteb");

        assert_eq!(s.components()[1].get_offset(), 2);
        assert_eq!(s.components()[1].get_ordinal(), 2);
        assert_eq!(s.components()[1].get_data_type().get_name(), "bytec");

        assert_eq!(s.components()[2].get_offset(), 4);
        assert_eq!(s.components()[2].get_ordinal(), 4);
        assert_eq!(s.components()[2].get_data_type().get_name(), "chard");

        assert_eq!(s.components()[3].get_offset(), 7);
        assert_eq!(s.components()[3].get_ordinal(), 7);
        assert_eq!(s.components()[3].get_data_type().get_name(), "byte4");
    }

    #[test]
    fn replace_at_offset_rejects_negative_and_out_of_bounds_offsets() {
        let mut s = byte_word_dword_byte_struct();
        match s.structure_data_type_replace_at_offset(-1, dt("x", 1), 1, None, None) {
            Err(e) => assert!(e.contains("negative")),
            Ok(_) => panic!("expected an error for a negative offset"),
        }
        match s.structure_data_type_replace_at_offset(8, dt("x", 1), 1, None, None) {
            Err(e) => assert!(e.contains("beyond end")),
            Ok(_) => panic!("expected an error for an out-of-bounds offset"),
        }
    }

    #[test]
    fn replace_and_replace_with_name_via_structure_trait_object() {
        let mut s = StructureDataType::new("Foo", 0);
        s.add(dt("int", 4)).expect("add int");
        s.add(dt("short", 2)).expect("add short");

        {
            let structure: &mut dyn Structure = &mut s;
            let replaced = structure
                .replace_with_name(0, dt("uint", 4), 4, Some("f".to_string()), None)
                .expect("replace_with_name ordinal 0");
            assert_eq!(replaced.get_data_type().get_name(), "uint");
            assert_eq!(replaced.get_field_name(), Some("f".to_string()));

            let replaced_at = structure
                .replace_at_offset(4, dt("ushort", 2), 2, Some("g".to_string()), None)
                .expect("replace_at_offset offset 4");
            assert_eq!(replaced_at.get_data_type().get_name(), "ushort");
        }

        assert_eq!(Composite::get_num_defined_components(&s), 2);
    }

    struct MockBuf;
    impl MemBuffer for MockBuf {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, buf: &mut [u8], _offset: i32) -> usize {
            buf.fill(0);
            buf.len()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}
}
