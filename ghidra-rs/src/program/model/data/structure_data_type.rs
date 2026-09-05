//! Port of `ghidra.program.model.data.StructureDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class is a concrete, in-memory (non-database-backed) `Structure` implementation:
//! `StructureDataType extends CompositeDataTypeImpl implements StructureInternal`. Both
//! [`CompositeDataTypeImpl`](super::composite_data_type_impl::CompositeDataTypeImpl) and
//! [`StructureInternal`](super::structure_internal::StructureInternal) (which itself pulls in
//! [`Structure`](super::structure::Structure), [`Composite`](super::composite::Composite) and
//! [`DataType`](super::data_type::DataType)) are already real, richly-defaulted ported traits, so
//! -- mirroring the precedent set by
//! [`StructureDb`](crate::program::database::data::structure_db::StructureDb) for the sibling
//! database-backed implementation `StructureDB` -- this trait only adds what genuinely differs
//! about *this* concrete class; every public method it overrides that already belongs to one of
//! those ancestor contracts is intentionally not repeated here:
//!   - The entire component-manipulation surface (`getComponent`, `insertAtOffset`, `add`,
//!     `insert`, `delete`(s), `deleteAtOffset`, `clearAtOffset`, `clearComponent`, `replace`,
//!     `replaceAtOffset`, `addBitField`, `insertBitField(At)`, `getDefinedComponents`,
//!     `getComponents`, `getNumComponents`, `getNumDefinedComponents`, `deleteAll`,
//!     `growStructure`, `setLength`, `getDefinedComponentAtOrAfterOffset`,
//!     `getComponentContaining`, `getComponentsContaining`, `getDataTypeAt`) already exists,
//!     method-for-method, as a (placeholder-default) [`Structure`](super::structure::Structure) or
//!     [`Composite`](super::composite::Composite) trait method.
//!   - `forEachDefinedComponent` and `repack(boolean)` already exist as required
//!     [`CompositeDataTypeImpl`](super::composite_data_type_impl::CompositeDataTypeImpl) methods
//!     (`for_each_defined_component`, `repack_with_notify`).
//!   - `getAlignment()` already exists as the required
//!     [`CompositeDataTypeImpl::composite_impl_alignment`](super::composite_data_type_impl::CompositeDataTypeImpl::composite_impl_alignment).
//!     Its real Java body calls `AlignedStructureInspector.packComponents(this)` for the
//!     packing-enabled case, a helper class that is not yet ported; rather than adding a
//!     placeholder stub for a method this trait does not otherwise need, that computation is left
//!     to whatever concrete type eventually backs `composite_impl_alignment` (which already has no
//!     default for the same reason -- it is `abstract` in `CompositeDataTypeImpl` too).
//!   - `isEquivalent`, `dataTypeSizeChanged`, `dataTypeAlignmentChanged`, `dataTypeDeleted`,
//!     `dataTypeReplaced`, and `replaceWith` already exist as (placeholder-default)
//!     [`DataType`](super::data_type::DataType) methods of the same name/shape.
//!   - `copy(DataTypeManager)`/`clone(DataTypeManager)` are covariant-return overrides of
//!     [`DataType::copy_data_type`]/[`DataType::clone_data_type`], which already return the
//!     necessary `Box<dyn DataType>` (a concrete `StructureDataType` impl already narrows to a
//!     `Structure` internally; the trait-object return type is unchanged).
//!   - The five public constructors have no trait-method equivalent (traits cannot return `Self`
//!     as a sized, constructible value); a concrete implementation supplies its own `new`.
//!
//! A handful of small methods have real Java bodies that differ from the generic default already
//! sitting on an ancestor trait (so Rust requires a distinct name to avoid an ambiguous override,
//! per the `composite_impl_*`/`structure_db_*` naming precedent already used by sibling traits):
//!   - [`structure_data_type_is_zero_length`](StructureDataType::structure_data_type_is_zero_length) /
//!     [`length`](StructureDataType::length), which need the private `structLength` field --
//!     exposed via the required [`stored_struct_length`](StructureDataType::stored_struct_length)/
//!     [`set_stored_struct_length`](StructureDataType::set_stored_struct_length) accessors,
//!     mirroring [`CompositeDataTypeImpl`]'s `stored_description`-style convention for private
//!     field storage.
//!   - [`structure_data_type_has_language_dependant_length`](StructureDataType::structure_data_type_has_language_dependant_length), which
//!     answers the required `CompositeDataTypeImpl::composite_impl_has_language_dependant_length`
//!     with real logic (`isPackingEnabled()`) needing no new state.
//!   - [`representation`](StructureDataType::representation), which returns
//!     `"<Empty-Structure>"` when not yet defined instead of [`DataType::get_representation`]'s
//!     empty-string default, built on the already-real
//!     [`CompositeDataTypeImpl::composite_impl_is_not_yet_defined`].
//!   - [`default_label_prefix`](StructureDataType::default_label_prefix), which returns the
//!     structure's own name instead of [`DataType::get_default_label_prefix`]'s `None` default.
//!
//! ## Component-management surface (2026-09 extension)
//!
//! The original skeleton left the entire component-manipulation surface
//! (`getComponent`/`add`/`insert`/`delete`(s)/`replace`/etc.) to the ancestor
//! [`Structure`](super::structure::Structure)/[`Composite`](super::composite::Composite) traits'
//! *placeholder* defaults (they return `Err`/empty/`None` -- see those traits' own doc comments).
//! Nobody had actually written the real, stateful bodies anywhere, which is the load-bearing part
//! of this class. This extension adds that real logic here, as new `structure_data_type_*`
//! methods (the same naming convention as the small delta above) backed by four new required
//! accessors -- [`components`](StructureDataType::components)/
//! [`components_mut`](StructureDataType::components_mut) for the private `List<DataTypeComponentImpl>
//! components` field, and [`stored_num_components`](StructureDataType::stored_num_components)/
//! [`set_stored_num_components`](StructureDataType::set_stored_num_components) for the private
//! `int numComponents` field. A concrete `impl Structure`/`impl Composite for ...` is expected to
//! delegate its real method bodies to these, exactly as documented for the pre-existing delta
//! methods above.
//!
//! Ported so far, faithfully translating the Java algorithms (binary search over `components` by
//! offset/ordinal via [`compare_component_to_offset`]/[`compare_component_to_ordinal`]):
//! `getNumComponents`, `getNumDefinedComponents`, `getDefinedComponents`, `getComponents`,
//! `getComponent(int)` (including undefined-filler synthesis), `add(DataType, int, String,
//! String)` (`doAdd`), `insert(int, DataType, int, String, String)`, `insertAtOffset(int,
//! DataType, int, String, String)` (plus their shared private helpers `shiftOffsets`,
//! `backupToFirstComponentContainingOffset`, `afterNonZeroComponentsAtOffset`,
//! `advanceToLastComponentContainingOffset`), `isEquivalent`, and the non-packed half of
//! `repack`/`adjustNonPackedComponents`.
//!
//! Explicitly and intentionally **not yet ported** (do not flip `StructureDataType.java`'s
//! `PORT_MANIFEST.tsv` row to `DONE` until these are addressed or a narrower definition of "done"
//! is agreed):
//!   - **Packed-structure (`isPackingEnabled() == true`) layout is not computed.** Java's `repack`
//!     calls `AlignedStructurePacker.packComponents` for the packed case to compute
//!     alignment-driven offsets/padding/length; that integration is not wired here (the
//!     `AlignedStructurePacker` trait itself requires its own per-implementor accessors that a
//!     `StructureDataType` concrete type has not been given yet). The methods below still update
//!     `components`/`numComponents`/`structLength` bookkeeping correctly for the *non-packed*
//!     case; for a packing-enabled composite they fall back to simple sequential-append placement
//!     without alignment padding, which is a known, documented deviation from Java rather than a
//!     silent bug -- callers should not rely on packed-structure offsets/length being correct yet.
//!   - `delete(int)`, `delete(Set<Integer>)`, `deleteAtOffset`, `clearAtOffset`, `clearComponent`,
//!     `deleteAll`, `growStructure`, `setLength`, `getComponentContaining`,
//!     `getComponentsContaining`, `getDefinedComponentAtOrAfterOffset`, and `getDataTypeAt` are not
//!     ported yet, despite [`structure_data_type_advance_to_last_component_containing_offset`](StructureDataType::structure_data_type_advance_to_last_component_containing_offset)
//!     (one of their shared helpers) already being ported ahead of them.
//!   - `addBitField`/`insertBitField`/`insertBitFieldAt` (bitfield support) are not ported. These
//!     require the `BitOffsetComparator`-based overlap/conflict detection across bit-granular
//!     ranges, which is a substantial, mostly-independent algorithm; see
//!     [`get_normalized_bitfield_offset`](super::structure::get_normalized_bitfield_offset) for
//!     the one piece of that machinery already ported. `structure_data_type_insert`'s bitfield-
//!     overlap shift adjustment (Java's `existingDtc.isBitFieldComponent()` branch) is likewise
//!     skipped for the same reason.
//!   - `replace`/`replaceAtOffset`/`dataTypeSizeChanged`/`dataTypeAlignmentChanged`/
//!     `dataTypeDeleted`/`dataTypeReplaced`/`replaceWith`/`copy`/`clone` are not ported. `replace`
//!     in particular has an intricate multi-case algorithm (bit-field-overlap consolidation,
//!     "quick update" fast path, `LinkedList<DataTypeComponentImpl>` sequence replacement) that
//!     was not reached this session.
//!   - `DataTypeUtilities.checkAncestry` (cyclic-dependency rejection) is not ported anywhere in
//!     this crate yet, so it is not called from `structure_data_type_add`/`_insert`/
//!     `_insert_at_offset` below (unlike Java, adding a data type that would create a cyclic
//!     composite is not currently rejected here).
//!   - `dataType.clone(dataMgr)` (deep-cloning an inserted data type against this structure's own
//!     `DataTypeManager`) is skipped; the data type is stored as given.
//!   - `data_type.addParent(this)`/`removeParent(this)` (the child `DataType`'s own
//!     parent-notification list, used for size/alignment-change fan-out) is **not** wired from
//!     `structure_data_type_add`/`_insert`/`_insert_at_offset`: doing so from a default trait
//!     method would need to upcast `&mut self` (typed as `&mut Self: StructureDataType`) to
//!     `&dyn DataType`, which is not attempted this session to avoid depending on trait-object
//!     upcasting support; a concrete implementor's own `impl Composite for ...`/`impl Structure
//!     for ...` wrapper is free to call it itself after delegating here.
//!   - `DataTypeComponentImpl`'s `parent` back-reference is always `None` for every component
//!     constructed by the methods above, rather than an `Arc` to the owning structure, since
//!     wiring a genuine self-referential `Arc<Self>` would require every concrete
//!     `StructureDataType` implementor to be constructed via `Arc::new_cyclic`, a much bigger
//!     architectural change than this session's scope. This only affects
//!     [`DataTypeComponent::get_parent`]/parent-dependent settings lookups on a *component*
//!     (e.g. `getDefaultSettings()`'s `DataTypeManager`-based immutability check always falls back
//!     to "immutable" since no parent is found); it does not affect any of the offset/ordinal/
//!     length bookkeeping ported above.
//!   - `notifySizeChanged()`/`notifyAlignmentChanged()` (walking the *composite's own* parent
//!     chain to fan out change notifications, plus `DataTypeManager` notification) are no-ops
//!     here: nothing in this crate yet tracks a `StructureDataType` composite's own parents.

use crate::docking::settings::settings::Settings;
use crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl;
use crate::program::model::data::composite_internal::{
    compare_component_to_offset, compare_component_to_ordinal,
};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_component_impl::DataTypeComponentImpl;
use crate::program::model::data::structure_internal::StructureInternal;
use crate::program::model::mem::MemBuffer;
use std::collections::HashSet;

/// Local stand-in for Ghidra's `DataType.DEFAULT` singleton (an instance of
/// `ghidra.program.model.data.DefaultDataType`), used only to synthesize the implicit "undefined"
/// filler components a non-packed structure reports between/after its explicitly defined
/// components. [`DefaultDataType`](super::default_data_type::DefaultDataType) is itself only a
/// mixin trait in this crate with no ready-made concrete singleton instance (see its module
/// docs), so this minimal local type exists purely so the component-management methods below have
/// something concrete to hand back; it is not itself the subject of this port.
#[derive(Debug, Clone, Copy)]
struct UndefinedFillerDataType;

impl DataType for UndefinedFillerDataType {
    fn get_name(&self) -> String {
        "undefined".to_string()
    }
    fn get_length(&self) -> i32 {
        1
    }
    fn is_default_data_type(&self) -> bool {
        true
    }
}

fn undefined_filler_data_type() -> Box<dyn DataType> {
    Box::new(UndefinedFillerDataType)
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

/// Basic (in-memory, non-database-backed) implementation of the structure data type.
///
/// Port of `ghidra.program.model.data.StructureDataType`. See the module-level documentation for
/// what was ported, defaulted, and intentionally omitted.
///
/// NOTE: Implementation is not thread safe (matches the Java class's documented contract).
pub trait StructureDataType: StructureInternal + CompositeDataTypeImpl {
    /// Backing storage for the private `structLength` field.
    fn stored_struct_length(&self) -> i32;

    /// Mutator for the private `structLength` field's backing storage.
    fn set_stored_struct_length(&mut self, length: i32);

    /// Backing storage for the private `components` field (`List<DataTypeComponentImpl>`).
    fn components(&self) -> &Vec<DataTypeComponentImpl>;

    /// Mutator for the private `components` field's backing storage.
    fn components_mut(&mut self) -> &mut Vec<DataTypeComponentImpl>;

    /// Backing storage for the private `numComponents` field.
    fn stored_num_components(&self) -> i32;

    /// Mutator for the private `numComponents` field's backing storage.
    fn set_stored_num_components(&mut self, num_components: i32);

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
    /// [`UndefinedFillerDataType`]) at the appropriate offset. Exposed under a distinct name since
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
                    undefined_filler_data_type(),
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

    /// Port of the private `StructureDataType.doAdd(DataType, int, String, String, boolean)`,
    /// called with `packAndNotify = true` (matching the public
    /// `add(DataType, int, String, String)` entry point; see the module docs for what is skipped
    /// -- `dataType.clone(dataMgr)`/`checkAncestry`/`data_type.add_parent(self)`/real
    /// packed-structure repacking).
    ///
    /// # Errors
    /// Returns `Err` if a positive length cannot be determined for the specified data type
    /// (mirrors `IllegalArgumentException`/`DataTypeDependencyException`).
    fn structure_data_type_add(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<DataTypeComponentImpl, String> {
        let data_type = self.composite_impl_validate_data_type(data_type)?;

        let num_components = self.stored_num_components();
        let struct_length = self.stored_struct_length();

        if data_type.is_default_data_type() {
            // Assume non-packed structure growth by 1 byte; not added to `components` (matches
            // Java's `dataType == DataType.DEFAULT` branch, which never touches the list).
            self.set_stored_num_components(num_components + 1);
            self.set_stored_struct_length(struct_length + 1);
            return Ok(DataTypeComponentImpl::new(
                data_type,
                None,
                1,
                num_components,
                struct_length,
                None,
                None,
            ));
        }

        let dynamic_specifiable = is_dynamic_with_specifiable_length(data_type.as_ref());
        let component_length = self.composite_impl_preferred_component_length_default(
            data_type.as_ref(),
            dynamic_specifiable,
            length,
        )?;

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
        let stored = self
            .components()
            .last()
            .expect("just pushed")
            .snapshot();

        let mut structure_growth = stored.get_length();
        if structure_growth != 0 && !self.is_packing_enabled() && length > 0 {
            structure_growth = length;
        }

        self.set_stored_num_components(num_components + 1);
        self.set_stored_struct_length(struct_length + structure_growth);

        if self.is_packing_enabled() {
            self.structure_data_type_repack(false);
        }
        // notifySizeChanged(): no-op, see module docs.

        Ok(stored)
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
    /// `checkAncestry`, real packed-structure repacking).
    ///
    /// # Errors
    /// Returns `Err` if `offset` is negative, or a positive length cannot be determined for the
    /// specified data type (mirrors `IllegalArgumentException`).
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
    /// docs for what is skipped (bitfield-overlap shifting, `dataType.clone(dataMgr)`,
    /// `checkAncestry`, real packed-structure repacking).
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds, or a positive length cannot be determined for
    /// the specified data type (mirrors `IndexOutOfBoundsException`/`IllegalArgumentException`).
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

    /// Port of `StructureDataType.repack(boolean)`. See the module docs for why the
    /// packing-enabled branch (`AlignedStructurePacker` integration) is not implemented here --
    /// this only performs the non-packed adjustment
    /// ([`structure_data_type_adjust_non_packed_components`](StructureDataType::structure_data_type_adjust_non_packed_components))
    /// faithfully, matching Java's `!isPackingEnabled()` branch. Returns `true` if a layout
    /// change was detected.
    fn structure_data_type_repack(&mut self, notify: bool) -> bool {
        let old_length = self.stored_struct_length();
        let changed = if !self.is_packing_enabled() {
            self.structure_data_type_adjust_non_packed_components()
        } else {
            false
        };
        if changed && notify && old_length != self.stored_struct_length() {
            // notifySizeChanged(): no-op, see module docs.
        }
        changed
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

    /// Port of `StructureDataType.isEquivalent(DataType)`, generalized over any other
    /// `StructureDataType` implementor (Java's `dataType instanceof StructureInternal` downcast
    /// has no direct `dyn Trait` equivalent, so callers compare against a known
    /// `&dyn StructureDataType` rather than a `&dyn DataType`).
    fn structure_data_type_is_equivalent(&self, other: &dyn StructureDataType) -> bool {
        let other_length = if other.structure_data_type_is_zero_length() {
            0
        } else {
            other.length()
        };
        if self.get_stored_packing_value() != other.get_stored_packing_value()
            || self.get_stored_minimum_alignment() != other.get_stored_minimum_alignment()
            || (self.get_stored_packing_value() == crate::program::model::data::composite_internal::NO_PACKING
                && self.stored_struct_length() != other_length)
        {
            return false;
        }

        let my_components = self.components();
        let other_components = other.components();
        if my_components.len() != other_components.len() {
            return false;
        }
        my_components
            .iter()
            .zip(other_components.iter())
            .all(|(a, b)| a.is_equivalent(b))
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
    use crate::program::model::mem::MemoryAccessException;

    /// Minimal mock proving object-safety and exercising real (non-trivially-true) behavior: a
    /// structure's zero-length/length/representation/label-prefix all track its stored length and
    /// name, `has_language_dependant_length` tracks its packing state, and (as of the 2026-09
    /// component-management extension) `components`/`num_components` back the real add/get/repack
    /// logic ported above -- exactly the Java semantics this trait ports. Plain fields (not
    /// `Cell`) since every mutator already takes `&mut self`; `Cell`/`RefCell` would also make this
    /// type `!Sync`, which [`DataType`]'s `Send + Sync` supertrait bound forbids.
    struct MockStructureDataType {
        name: String,
        struct_length: i32,
        num_components: i32,
        packing_type: PackingType,
        components: Vec<DataTypeComponentImpl>,
    }

    impl DataType for MockStructureDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl Composite for MockStructureDataType {
        fn get_num_components(&self) -> i32 {
            self.num_components
        }
        fn get_packing_type(&self) -> PackingType {
            self.packing_type
        }
    }

    impl CompositeInternal for MockStructureDataType {
        fn get_stored_packing_value(&self) -> i32 {
            if self.packing_type == PackingType::Disabled {
                crate::program::model::data::composite_internal::NO_PACKING
            } else {
                crate::program::model::data::composite_internal::DEFAULT_PACKING
            }
        }
    }

    impl crate::program::model::data::structure::Structure for MockStructureDataType {}

    impl StructureInternal for MockStructureDataType {}

    impl CompositeDataTypeImpl for MockStructureDataType {
        fn stored_description(&self) -> String {
            String::new()
        }
        fn set_stored_description(&mut self, _description: String) {}
        fn stored_minimum_alignment_value(&self) -> i32 {
            0
        }
        fn set_stored_minimum_alignment_value(&mut self, _minimum_alignment: i32) {}
        fn stored_packing_value(&self) -> i32 {
            0
        }
        fn set_stored_packing_value_raw(&mut self, _packing: i32) {}
        fn set_stored_name(&mut self, name: String) {
            self.name = name;
        }
        fn composite_impl_has_language_dependant_length(&self) -> bool {
            StructureDataType::structure_data_type_has_language_dependant_length(self)
        }
        fn repack_with_notify(&mut self, _notify: bool) -> bool {
            false
        }
        fn composite_impl_alignment(&self) -> i32 {
            1
        }
        fn for_each_defined_component(&self, _consumer: &mut dyn FnMut(&dyn DataTypeComponent)) {}
        fn composite_impl_add_with_length_and_name(
            &mut self,
            _data_type: Box<dyn DataType>,
            _length: i32,
            _field_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            Err("not needed for this smoke test".to_string())
        }
        fn composite_impl_insert_with_length_and_name(
            &mut self,
            _ordinal: i32,
            _data_type: Box<dyn DataType>,
            _length: i32,
            _field_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            Err("not needed for this smoke test".to_string())
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

    impl StructureDataType for MockStructureDataType {
        fn stored_struct_length(&self) -> i32 {
            self.struct_length
        }
        fn set_stored_struct_length(&mut self, length: i32) {
            self.struct_length = length;
        }
        fn components(&self) -> &Vec<DataTypeComponentImpl> {
            &self.components
        }
        fn components_mut(&mut self) -> &mut Vec<DataTypeComponentImpl> {
            &mut self.components
        }
        fn stored_num_components(&self) -> i32 {
            self.num_components
        }
        fn set_stored_num_components(&mut self, num_components: i32) {
            self.num_components = num_components;
        }
    }

    fn sample() -> MockStructureDataType {
        MockStructureDataType {
            name: "MyStruct".to_string(),
            struct_length: 0,
            num_components: 0,
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
            fn is_equivalent(&self, dt: &dyn DataType) -> bool {
                self.name == dt.get_name() && self.length == dt.get_length()
            }
        }
        Box::new(SimpleDataType {
            name: name.to_string(),
            length,
        })
    }

    #[test]
    fn usable_as_trait_object() {
        let s = sample();
        let dyn_struct: &dyn StructureDataType = &s;
        assert!(dyn_struct.structure_data_type_is_zero_length());
        assert_eq!(dyn_struct.length(), 1);
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
        s.packing_type = PackingType::Default;
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
