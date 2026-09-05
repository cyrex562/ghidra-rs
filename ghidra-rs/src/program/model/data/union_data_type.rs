//! Port of `ghidra.program.model.data.UnionDataType`, mirroring
//! [`StructureDataType`](super::structure_data_type::StructureDataType)'s "promoted to a trait
//! because it was selected as a dependency-cycle cut-point" precedent.
//!
//! The Java class is a concrete, in-memory (non-database-backed) `Union` implementation:
//! `UnionDataType extends CompositeDataTypeImpl implements UnionInternal`. Both
//! [`CompositeDataTypeImpl`](super::composite_data_type_impl::CompositeDataTypeImpl) and
//! [`UnionInternal`](super::union_internal::UnionInternal) (which itself pulls in
//! [`Union`](super::union::Union), [`Composite`](super::composite::Composite) and
//! [`DataType`](super::data_type::DataType)) are already real, richly-defaulted ported traits, so
//! -- exactly like [`StructureDataType`](super::structure_data_type::StructureDataType) -- this
//! trait only adds what genuinely differs about *this* concrete class.
//!
//! A `Union` has no offset-based layout: every component is anchored at byte offset 0 (its
//! `createComponent` calls always pass `offset = 0`), and the union's own length is simply the
//! largest of its components' (possibly bitfield-adjusted) lengths, aligned up when packing is
//! enabled. This makes the component-management surface below meaningfully **simpler** than
//! [`StructureDataType`]'s: there is no offset bookkeeping, no undefined filler synthesis, no
//! binary search over offsets, and the defined-component list's index always equals a component's
//! ordinal (insert/delete keep the two in lockstep), so `components()[ordinal]` is always the
//! direct answer to `getComponent(ordinal)` -- no `compare_component_to_ordinal` binary search is
//! needed the way [`StructureDataType`] needs one.
//!
//! ## Porting progress (2026-09, incremental)
//!
//! This is being built up in the same incremental, build+test-gated fashion
//! [`StructureDataType`] was. So far this covers: the private-field accessors, the small
//! `getLength`/`isZeroLength`/`hasLanguageDependantLength`/`getRepresentation`/
//! `getDefaultLabelPrefix` deltas, the read-only component-query surface
//! (`getNumComponents`/`getNumDefinedComponents`/`getComponent`/`getComponents`/
//! `getDefinedComponents`), and `DataTypeUtilities.checkAncestry`. Still to come in later
//! commits: `getAlignment`/`repack`, `add`/`insert`/`addBitField`/`insertBitField`, and
//! `delete`/`delete(Set)`/`isEquivalent`/`replaceWith`. Do not flip `UnionDataType.java`'s
//! `PORT_MANIFEST.tsv` row to `DONE` until all of that lands (and even then, see the eventual
//! final module doc's own "explicitly not yet ported" list for `dataTypeAlignmentChanged`-family
//! methods and `copy`/`clone`, which mirror [`StructureDataType`]'s identical omissions).

use crate::program::model::data::bit_field_data_type::{
    check_base_data_type, get_effective_bit_size, get_minimum_storage_size_no_offset, BitFieldDataType,
};
use crate::program::model::data::composite_alignment_helper;
use crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_component_impl::DataTypeComponentImpl;
use crate::program::model::data::union_internal::UnionInternal;
use crate::program::model::mem::MemBuffer;
use crate::docking::settings::settings::Settings;

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

/// Basic (in-memory, non-database-backed) implementation of the union data type.
///
/// Port of `ghidra.program.model.data.UnionDataType`. See the module-level documentation for what
/// was ported, defaulted, and intentionally omitted (a work in progress; see the "porting
/// progress" note there).
///
/// NOTE: Implementation is not thread safe (matches the Java class's documented contract).
pub trait UnionDataType: UnionInternal + CompositeDataTypeImpl {
    /// Backing storage for the private `unionLength` field.
    fn stored_union_length(&self) -> i32;

    /// Mutator for the private `unionLength` field's backing storage.
    fn set_stored_union_length(&mut self, length: i32);

    /// Backing storage for the private `unionAlignment` field.
    fn stored_union_alignment(&self) -> i32;

    /// Mutator for the private `unionAlignment` field's backing storage.
    fn set_stored_union_alignment(&mut self, alignment: i32);

    /// Backing storage for the private `components` field (`List<DataTypeComponentImpl>`).
    fn components(&self) -> &Vec<DataTypeComponentImpl>;

    /// Mutator for the private `components` field's backing storage.
    fn components_mut(&mut self) -> &mut Vec<DataTypeComponentImpl>;

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
    fn union_data_type_check_ancestry(&self, component_data_type: &dyn DataType) -> Result<(), String>
    where
        Self: Sized,
    {
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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
        let bit_field_packing = self.get_data_organization().get_bit_field_packing();
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
    fn union_data_type_alignment(&self) -> i32
    where
        Self: Sized,
    {
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
    fn union_data_type_repack(&mut self, notify: bool) -> bool
    where
        Self: Sized,
    {
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
            new_length = crate::program::seam_stubs::get_aligned_offset(new_alignment, new_length);
            self.set_stored_union_length(new_length);
        }

        let changed = old_length != new_length || old_alignment != new_alignment;

        if changed && notify {
            // notifySizeChanged()/notifyAlignmentChanged(): no-op, see module docs.
        }
        changed
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

    /// Minimal mock proving object-safety and exercising real behavior, mirroring
    /// `StructureDataType`'s own `MockStructureDataType` test fixture.
    struct MockUnionDataType {
        name: String,
        union_length: i32,
        union_alignment: i32,
        packing_type: PackingType,
        components: Vec<DataTypeComponentImpl>,
    }

    /// Minimal [`DataOrganization`](crate::program::model::data::data_organization::DataOrganization)
    /// stand-in, needed only so [`UnionDataType::union_data_type_alignment`]/
    /// [`UnionDataType::union_data_type_get_bit_field_allocation`] have something to call
    /// `get_machine_alignment()`/`is_big_endian()`/`get_bit_field_packing()` on -- matches the
    /// identical mock already used by `StructureDataType`'s own tests.
    struct MockDataOrganization;
    impl crate::program::model::data::data_organization::DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            2
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            0
        }
        fn get_machine_alignment(&self) -> i32 {
            8
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(&self) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
            struct MockBitFieldPacking;
            impl crate::program::model::data::bit_field_packing::BitFieldPacking for MockBitFieldPacking {
                fn use_ms_convention(&self) -> bool {
                    false
                }
                fn is_type_alignment_enabled(&self) -> bool {
                    true
                }
                fn get_zero_length_boundary(&self) -> i32 {
                    0
                }
            }
            Box::new(MockBitFieldPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            vec![]
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            String::new()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    impl DataType for MockUnionDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_data_organization(&self) -> Box<dyn crate::program::model::data::data_organization::DataOrganization> {
            Box::new(MockDataOrganization)
        }
        fn as_composite(&self) -> Option<&dyn Composite> {
            Some(self)
        }
        fn get_length(&self) -> i32 {
            UnionDataType::length(self)
        }
        fn is_union(&self) -> bool {
            true
        }
    }

    impl Composite for MockUnionDataType {
        fn get_num_components(&self) -> i32 {
            self.components.len() as i32
        }
        fn get_packing_type(&self) -> PackingType {
            self.packing_type
        }
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .map(|dtc| Box::new(dtc.snapshot()) as Box<dyn DataTypeComponent>)
                .collect()
        }
    }

    impl CompositeInternal for MockUnionDataType {
        fn get_stored_packing_value(&self) -> i32 {
            if self.packing_type == PackingType::Disabled {
                crate::program::model::data::composite_internal::NO_PACKING
            } else {
                crate::program::model::data::composite_internal::DEFAULT_PACKING
            }
        }
    }

    impl crate::program::model::data::union::Union for MockUnionDataType {
        fn clone_union(&self, _dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager) -> Box<dyn crate::program::model::data::union::Union> {
            unimplemented!("not exercised by these tests")
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
                .map(|dtc| Box::new(dtc) as Box<dyn DataTypeComponent>)
        }
    }

    impl UnionInternal for MockUnionDataType {}

    impl CompositeDataTypeImpl for MockUnionDataType {
        fn stored_description(&self) -> String {
            String::new()
        }
        fn set_stored_description(&mut self, _description: String) {}
        fn stored_minimum_alignment_value(&self) -> i32 {
            0
        }
        fn set_stored_minimum_alignment_value(&mut self, _minimum_alignment: i32) {}
        fn stored_packing_value(&self) -> i32 {
            if self.packing_type == PackingType::Disabled {
                crate::program::model::data::composite_internal::NO_PACKING
            } else {
                crate::program::model::data::composite_internal::DEFAULT_PACKING
            }
        }
        fn set_stored_packing_value_raw(&mut self, packing: i32) {
            self.packing_type = if packing < crate::program::model::data::composite_internal::DEFAULT_PACKING {
                PackingType::Disabled
            } else if packing == crate::program::model::data::composite_internal::DEFAULT_PACKING {
                PackingType::Default
            } else {
                PackingType::Explicit
            };
        }
        fn set_stored_name(&mut self, name: String) {
            self.name = name;
        }
        fn composite_impl_has_language_dependant_length(&self) -> bool {
            UnionDataType::union_data_type_has_language_dependant_length(self)
        }
        fn repack_with_notify(&mut self, notify: bool) -> bool {
            UnionDataType::union_data_type_repack(self, notify)
        }
        fn composite_impl_alignment(&self) -> i32 {
            UnionDataType::union_data_type_alignment(self)
        }
        fn for_each_defined_component(&self, consumer: &mut dyn FnMut(&dyn DataTypeComponent)) {
            for dtc in self.components() {
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
                .map(|dtc| Box::new(dtc) as Box<dyn DataTypeComponent>)
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
                .map(|dtc| Box::new(dtc) as Box<dyn DataTypeComponent>)
        }
        fn composite_impl_validate_data_type(
            &self,
            data_type: Box<dyn DataType>,
        ) -> Result<Box<dyn DataType>, String> {
            Ok(data_type)
        }
        fn composite_impl_update_bit_field_data_type(
            &mut self,
            _bitfield_component: Box<dyn DataTypeComponent>,
            _old_dt: &dyn DataType,
            _new_dt: Option<&dyn DataType>,
        ) -> Result<bool, String> {
            Ok(false)
        }
    }

    impl UnionDataType for MockUnionDataType {
        fn stored_union_length(&self) -> i32 {
            self.union_length
        }
        fn set_stored_union_length(&mut self, length: i32) {
            self.union_length = length;
        }
        fn stored_union_alignment(&self) -> i32 {
            self.union_alignment
        }
        fn set_stored_union_alignment(&mut self, alignment: i32) {
            self.union_alignment = alignment;
        }
        fn components(&self) -> &Vec<DataTypeComponentImpl> {
            &self.components
        }
        fn components_mut(&mut self) -> &mut Vec<DataTypeComponentImpl> {
            &mut self.components
        }
    }

    fn sample() -> MockUnionDataType {
        MockUnionDataType {
            name: "MyUnion".to_string(),
            union_length: 0,
            union_alignment: 0,
            packing_type: PackingType::Disabled,
            components: Vec::new(),
        }
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
    fn usable_as_trait_object() {
        let u = sample();
        let dyn_union: &dyn UnionDataType = &u;
        assert!(dyn_union.union_data_type_is_zero_length());
        assert_eq!(dyn_union.length(), 1);
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
        u.packing_type = PackingType::Default;
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
