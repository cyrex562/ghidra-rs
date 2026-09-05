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
//! DataType, int, String, String)`, `delete(int)`, `delete(Set<Integer>)`, `deleteAtOffset`,
//! `clearAtOffset`, `clearComponent`, `deleteAll`, `growStructure`, `setLength`,
//! `getComponentContaining`, `getComponentsContaining`, `getDefinedComponentAtOrAfterOffset`,
//! `getDataTypeAt`, `isEquivalent`, and the non-packed half of `repack`/
//! `adjustNonPackedComponents` (plus their shared private helpers: `shiftOffsets`,
//! `backupToFirstComponentContainingOffset`, `afterNonZeroComponentsAtOffset`,
//! `advanceToLastComponentContainingOffset`, `doDelete`, `doDeleteWithComponentShift`,
//! `generateUndefinedComponent`, `indexOfFirstNonZeroLenComponentContainingOffset`). Rust's
//! `Vec::binary_search_by` returns a plain `Result<usize, usize>` rather than `Collections
//! .binarySearch`'s single negative-encoded `int` (`-insertionPoint - 1` when absent), so callers
//! below never need Java's encode/decode dance; a couple of Java call sites round-trip through it
//! pointlessly (encoding an already-in-hand index just to immediately decode it back inside
//! `generateUndefinedComponent`/`getComponentsContaining`), which is elided here as a no-op.
//!
//! ## Packed-structure layout and bitfield support (2026-09 extension, continued)
//!
//! Two of the previously-open gaps above are now closed:
//!
//! - **Packed-structure (`isPackingEnabled() == true`) layout is now computed** via a real
//!   [`AlignedStructurePacker`](AlignedStructurePacker) integration: this trait now requires
//!   `Self: AlignedStructurePacker` (a new supertrait bound), and
//!   [`structure_data_type_pack`](StructureDataType::structure_data_type_pack) (called from the
//!   packed branch of [`structure_data_type_repack`](StructureDataType::structure_data_type_repack),
//!   mirroring Java's `repack(boolean)`) converts this structure's `Vec<DataTypeComponentImpl>`
//!   to and from the `Box<dyn InternalDataTypeComponent>` shape
//!   [`AlignedStructurePacker::pack_components`] requires via the [`PackableComponent`] adapter
//!   (an `Arc<dyn DataType>`-backed proxy, needed since `dyn DataType` has no `Clone` bound and
//!   [`DataTypeComponent::get_data_type`] must be answerable repeatedly from `&self`; no downcast
//!   back to the concrete adapter is ever needed since every mutated field is read back out
//!   through ordinary trait methods -- see [`PackableComponent`]'s own doc comment). **The wiring
//!   is real, but its output quality depends entirely on whichever
//!   [`AlignedStructurePacker::create_component_packer`] a concrete implementor supplies**: this
//!   crate still has no production (bitfield-aware) `AlignedComponentPacker` port -- only test
//!   doubles exist (here and in `aligned_structure_packer`'s own tests) -- so a real implementor
//!   must currently supply a simplistic packer or wait on that separate port. Unlike Java, no
//!   `structAlignment` field is cached/compared for the "changed" return value (see
//!   [`structure_data_type_repack`](StructureDataType::structure_data_type_repack)'s own doc
//!   comment for why this only matters for the no-op `notify` path).
//! - **`addBitField`/`insertBitField`/`insertBitFieldAt` are now ported** as
//!   [`structure_data_type_add_bit_field`](StructureDataType::structure_data_type_add_bit_field)/
//!   [`structure_data_type_insert_bit_field`](StructureDataType::structure_data_type_insert_bit_field)/
//!   [`structure_data_type_insert_bit_field_at`](StructureDataType::structure_data_type_insert_bit_field_at),
//!   including the `BitOffsetComparator`-based overlap/conflict detection across bit-granular
//!   ranges (ported as the private [`compare_component_to_bit_offset`] helper, building on
//!   [`get_normalized_bitfield_offset`](super::structure::get_normalized_bitfield_offset), which
//!   was already ported). `structure_data_type_insert_bit_field_at`'s own doc comment flags one
//!   Java quirk ported verbatim rather than "fixed": calling it directly against a
//!   packing-enabled structure triggers a nested insertion whose return value is discarded, after
//!   which the method still unconditionally inserts its own component. `structure_data_type_insert`'s
//!   separate bitfield-overlap shift adjustment (Java's `existingDtc.isBitFieldComponent()` branch
//!   inside plain, non-bitfield `insert`) remains unported -- it is independent of the three
//!   bitfield entry points above.
//!
//! While porting the above, [`crate::program::seam_stubs::SharedDataType`] (backing
//! [`crate::program::seam_stubs::share_data_type`], used by [`PackableComponent`] and by the
//! bitfield methods' internal re-sharing of a caller-supplied base data type) was found to not
//! forward `is_integer_type`/`is_signed_integer_type`/`get_alignment`, silently breaking bitfield
//! base-type validation for any base type reached only through a shared handle; those three
//! methods were added to its forwarded set (a strict completeness fix, not a behavior change, for
//! that shared crate-wide utility).
//!
//! `replaceWith(DataType)` is also now ported, as
//! [`structure_data_type_replace_with`](StructureDataType::structure_data_type_replace_with)
//! (same `&dyn StructureDataType` convention as `structure_data_type_is_equivalent`, standing in
//! for Java's `instanceof StructureInternal` downcast): clears this structure's components and
//! packing/alignment settings and repopulates them from `other`, delegating to
//! [`structure_data_type_add`](StructureDataType::structure_data_type_add) for the packed case
//! (`doReplaceWithPacked`) and constructing components directly (preserving `other`'s
//! offsets/ordinals/field names verbatim) for the non-packed case (`doReplaceWithNonPacked`).
//!
//! `DataTypeUtilities.checkAncestry` (cyclic-dependency rejection) is now ported too, as
//! [`structure_data_type_check_ancestry`](StructureDataType::structure_data_type_check_ancestry),
//! and wired into `structure_data_type_add`/`_insert`/`_insert_at_offset`/`_replace_with` at the
//! same call sites Java's `checkAncestry(this, dataType)` occupies: adding a data type that would
//! create a cyclic composite is now rejected here, matching Java. It reuses the walk already
//! ported for [`CompositeDataTypeImpl::composite_impl_is_part_of`] (`isSecondPartOfFirst`) in the
//! opposite direction, via a new borrowing-only sibling helper
//! ([`is_part_of_data_type_by_ref`]) rather than that method's own ownership-consuming one, since
//! every caller here still needs its `data_type` afterward.
//!
//! ## `copy`/`clone` now real (2026-09, concrete `StructureDataTypeImpl`)
//!
//! [`StructureDataTypeImpl`] is now this crate's first real, production concrete implementation
//! of this trait (previously every test exercised these default methods against a
//! `#[cfg(test)]`-scoped `MockStructureDataType` double). It supplies the real constructors this
//! module's first doc paragraph said a trait default method cannot provide, and wires
//! `copy`/`clone` for real ([`DataType::copy_data_type`]/[`DataType::clone_data_type`]: construct
//! a fresh `StructureDataTypeImpl` and call [`structure_data_type_replace_with`] on it, matching
//! `StructureDataType.copy`/`.clone`'s actual Java bodies) -- see [`StructureDataTypeImpl`]'s own
//! doc comment for exactly what it does and does not cover.
//!
//! ## `dataType*Changed`/`dataTypeDeleted`/`dataTypeReplaced` now real (2026-09, continued)
//!
//! `dataTypeSizeChanged`/`dataTypeAlignmentChanged`/`dataTypeDeleted`/`dataTypeReplaced` are now
//! ported, as [`structure_data_type_data_type_size_changed`](StructureDataType::structure_data_type_data_type_size_changed)/
//! [`structure_data_type_data_type_alignment_changed`](StructureDataType::structure_data_type_data_type_alignment_changed)/
//! [`structure_data_type_data_type_deleted`](StructureDataType::structure_data_type_data_type_deleted)/
//! [`structure_data_type_data_type_replaced`](StructureDataType::structure_data_type_data_type_replaced),
//! backed by two new small private helpers ([`structure_data_type_get_available_component_space`](StructureDataType::structure_data_type_get_available_component_space)/
//! [`structure_data_type_consume_bytes_after`](StructureDataType::structure_data_type_consume_bytes_after))
//! and one new "update a bitfield in place" helper
//! ([`structure_data_type_update_bit_field_data_type`](StructureDataType::structure_data_type_update_bit_field_data_type),
//! which operates directly on this structure's own `Vec<DataTypeComponentImpl>` rather than
//! through the pre-existing but object-unsafe-in-practice
//! [`CompositeDataTypeImpl::composite_impl_update_bit_field_data_type`], which stays stubbed at
//! `Ok(false)`). The first three are wired all the way into `StructureDataTypeImpl`'s own `impl
//! DataType` ([`DataType::data_type_size_changed`]/[`data_type_alignment_changed`]/
//! [`data_type_deleted`]) since they only ever need to *compare against* the notified data type
//! (via [`DataType::get_data_type_path`] equality, this crate's established reference-identity
//! approximation); `dataTypeReplaced` cannot be wired the same way since it needs to *store* an
//! owned copy of the replacement, which the generic `data_type_replaced(&mut self, old_dt, new_dt:
//! &dyn DataType)` placeholder has no way to hand over without a `Clone` bound on [`DataType`] --
//! see [`structure_data_type_data_type_replaced`]'s own doc comment for the full explanation and
//! for why `StructureDataTypeImpl` therefore leaves that one override at its inherited default.
//!
//! Two singleton stand-ins were added, mirroring [`UndefinedFillerDataType`]'s existing precedent
//! for `DataType.DEFAULT`: [`BadDataTypeStandIn`]/[`bad_data_type_stand_in`] for
//! `BadDataType.dataType` (used by `dataTypeDeleted`) and [`Undefined1StandIn`]/
//! [`undefined1_stand_in`] for `Undefined1DataType.dataType` (used by `dataTypeReplaced`'s
//! packed-structure fallback) -- both traits remain concrete-singleton-less in this crate (see
//! their own module docs), and a previous session's attempt at this same porting task had flagged
//! that gap as a hard blocker; it is not, once a minimal local stand-in (matching every property
//! its own call sites actually read) is written the same way [`UndefinedFillerDataType`] already
//! was for `DataType.DEFAULT`.
//!
//! While porting this, [`crate::program::seam_stubs::SharedDataType`] (the same shared utility
//! flagged once already above for a different forwarding gap) was found *again* to not forward
//! `is_bit_field_type`/`as_bit_field_data_type`: any caller downcasting a bitfield component's data
//! type after routing it through [`DataTypeComponent::get_data_type`] (which returns a
//! `share_data_type`-wrapped handle) would silently see "not a bitfield" even when the underlying
//! shared value really is one. Both were added to its forwarded set (again a strict completeness
//! fix, not a behavior change).
//!
//! Explicitly and intentionally **not yet ported** (do not flip `StructureDataType.java`'s
//! `PORT_MANIFEST.tsv` row to `DONE` until these are addressed or a narrower definition of "done"
//! is agreed):
//!   - `replace`/`replaceAtOffset` are not ported: an intricate multi-case algorithm
//!     (bit-field-overlap consolidation, "quick update" fast path, `LinkedList<DataTypeComponentImpl>`
//!     sequence replacement) that was not reached this session.
//!   - Within `dataTypeDeleted`, the case where a *bitfield's* base type (rather than a plain
//!     component's data type) is deleted -- which Java reverts to the base type's own primitive
//!     integer type via `BitFieldDataType.getPrimitiveBaseDataType()` (walking through
//!     `TypeDef`/`Enum` down to an `AbstractIntegerDataType`) -- is not ported, since that method
//!     does not exist in this crate yet; such a bitfield is left unchanged instead of reverted.
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
    compare_component_to_offset, compare_component_to_ordinal, CompositeInternal, DEFAULT_ALIGNMENT,
    NO_PACKING,
};
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::{DataType, SetDataTypeNameError, UnsupportedOperationError};
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_component_impl::DataTypeComponentImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::internal_data_type_component::InternalDataTypeComponent;
use crate::program::model::data::packing_type::PackingType;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::data::structure::{get_normalized_bitfield_offset, Structure};
use crate::program::model::data::structure_internal::StructureInternal;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::{share_data_type, AlignedComponentPacker};
use crate::util::exception::DuplicateNameException;
use crate::util::UniversalID;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::sync::Arc;

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

/// Local stand-in for Ghidra's `BadDataType.dataType` singleton (an instance of the private
/// `ghidra.program.model.data.BadDataType`), used by
/// [`structure_data_type_data_type_deleted`](StructureDataType::structure_data_type_data_type_deleted)
/// in place of a deleted (non-bitfield) component's data type, matching Java's
/// `setComponentDataType(dtc, BadDataType.dataType, i)`. [`BadDataType`](super::bad_data_type::BadDataType)
/// is itself only a trait in this crate with no ready-made concrete singleton instance (see its
/// module docs, which flag this exact gap), so -- mirroring [`UndefinedFillerDataType`] above --
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

/// Local stand-in for Ghidra's `Undefined1DataType.dataType` singleton, used by
/// [`structure_data_type_data_type_replaced`](StructureDataType::structure_data_type_data_type_replaced)
/// as the packed-structure fallback replacement when validation/ancestry-checking the real
/// replacement data type fails, matching Java's `replacementDt = isPackingEnabled() ?
/// Undefined1DataType.dataType : DataType.DEFAULT`. [`Undefined1DataType`](super::undefined1_data_type)
/// is itself only a trait in this crate with no ready-made concrete singleton instance (see its
/// module docs, which flag this exact gap) -- this minimal local type stands in for the one
/// property every call site actually needs: a fixed, positive `getLength() == 1`.
#[derive(Debug, Clone, Copy)]
struct Undefined1StandIn;

impl DataType for Undefined1StandIn {
    fn get_name(&self) -> String {
        "undefined1".to_string()
    }
    fn get_length(&self) -> i32 {
        1
    }
    fn is_undefined_type(&self) -> bool {
        true
    }
}

fn undefined1_stand_in() -> Box<dyn DataType> {
    Box::new(Undefined1StandIn)
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
pub trait StructureDataType: StructureInternal + CompositeDataTypeImpl + AlignedStructurePacker {
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

    /// Port of `DataTypeUtilities.checkAncestry(DataType, DataType)`, called as
    /// `checkAncestry(this, componentDataType)` throughout this trait's `add`/`insert`/
    /// `insertAtOffset`/`replaceWith` methods. Rejects `component_data_type` if adding it to this
    /// structure would create a cyclic composite (i.e. this structure is already reachable
    /// somewhere within `component_data_type`'s own composition tree).
    ///
    /// # Errors
    /// Returns `Err` if `component_data_type` has this structure within it (mirrors
    /// `DataTypeDependencyException`).
    fn structure_data_type_check_ancestry(&self, component_data_type: &dyn DataType) -> Result<(), String>
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

    /// Port of the private `StructureDataType.doAdd(DataType, int, String, String, boolean)`,
    /// called with `packAndNotify = true` (matching the public
    /// `add(DataType, int, String, String)` entry point; see the module docs for what is skipped
    /// -- `dataType.clone(dataMgr)`/`data_type.add_parent(self)`/real packed-structure
    /// repacking).
    ///
    /// # Errors
    /// Returns `Err` if a positive length cannot be determined for the specified data type
    /// (mirrors `IllegalArgumentException`), or if `data_type` would create a cyclic composite
    /// (mirrors `DataTypeDependencyException`).
    fn structure_data_type_add(
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
        self.structure_data_type_check_ancestry(data_type.as_ref())?;

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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
    ) -> Result<DataTypeComponentImpl, String>
    where
        Self: Sized,
    {
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
    fn structure_data_type_repack(&mut self, notify: bool) -> bool
    where
        Self: Sized,
    {
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
    /// implementor supplies -- this crate has no production (bitfield-aware) `AlignedComponentPacker`
    /// port yet (only test doubles), so a real implementor must currently either accept a
    /// simplistic sequential packer or wait on that separate port. The wiring itself, though, is
    /// real: once a faithful `AlignedComponentPacker` exists, this method needs no further changes.
    fn structure_data_type_pack(&mut self) -> bool
    where
        Self: Sized,
    {
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

    /// Port of `StructureDataType.replaceWith(DataType)`, generalized over any other
    /// `StructureDataType` implementor (same `&dyn StructureDataType` convention as
    /// [`structure_data_type_is_equivalent`](StructureDataType::structure_data_type_is_equivalent),
    /// standing in for Java's `instanceof StructureInternal` downcast). Replaces this structure's
    /// internal components with those of `other`, including packing and alignment settings.
    ///
    /// NOTE: unlike adding new components (which guarantees field-name uniqueness), this preserves
    /// `other`'s component names verbatim, matching Java. See the module docs for what is skipped
    /// (`dataType.clone(dataMgr)`, `data_type.removeParent(this)`/`addParent(this)`, and the
    /// `structAlignment = -1` reset, since no such field is tracked by this port).
    ///
    /// # Errors
    /// Returns `Err` if any of `other`'s (non-packed) component data types would create a cyclic
    /// composite (mirrors `DataTypeDependencyException`), or if the underlying
    /// [`structure_data_type_add`](StructureDataType::structure_data_type_add) call fails for the
    /// packed case.
    fn structure_data_type_replace_with(&mut self, other: &dyn StructureDataType) -> Result<(), String>
    where
        Self: Sized,
    {
        // dtc.getDataType().removeParent(this) for each existing component: skipped, see module
        // docs re: parent-notification wiring.
        self.components_mut().clear();
        self.set_stored_num_components(0);
        self.set_stored_struct_length(0);

        self.set_stored_packing_value_raw(other.get_stored_packing_value());
        self.set_stored_minimum_alignment_value(other.get_stored_minimum_alignment());

        if other.is_packing_enabled() {
            for dtc in other.components() {
                let dt = dtc.get_data_type();
                let length = if dt.as_dynamic().is_some() { dtc.get_length() } else { -1 };
                self.structure_data_type_add(dt, length, dtc.get_field_name(), dtc.get_comment())?;
            }
        } else if !other.composite_impl_is_not_yet_defined() {
            let new_length = if other.structure_data_type_is_zero_length() {
                0
            } else {
                other.length()
            };
            self.set_stored_struct_length(new_length);
            self.set_stored_num_components(new_length);

            let other_components = other.components();
            let count = other_components.len();
            for (i, dtc) in other_components.iter().enumerate() {
                let dt = dtc.get_data_type();
                // dt.clone(dataMgr): skipped, see module docs.
                self.structure_data_type_check_ancestry(dt.as_ref())?;
                let is_dynamic = dt.as_dynamic().is_some();
                let length = if dtc.is_bit_field_component() || is_dynamic {
                    dtc.get_length()
                } else {
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
        // notifySizeChanged(): no-op, see module docs.
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
    fn structure_data_type_delete(&mut self, ordinal: i32) -> Result<(), String>
    where
        Self: Sized,
    {
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
    fn structure_data_type_delete_ordinals(&mut self, ordinals: &HashSet<i32>) -> Result<(), String>
    where
        Self: Sized,
    {
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
    fn structure_data_type_delete_at_offset(&mut self, offset: i32) -> Result<(), String>
    where
        Self: Sized,
    {
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
    fn structure_data_type_clear_at_offset(&mut self, offset: i32) -> Result<(), String>
    where
        Self: Sized,
    {
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
    fn structure_data_type_clear_component(&mut self, ordinal: i32) -> Result<(), String>
    where
        Self: Sized,
    {
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
    fn structure_data_type_grow_structure(&mut self, amount: i32) -> Result<(), String>
    where
        Self: Sized,
    {
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
    fn structure_data_type_set_length(&mut self, len: i32) -> Result<(), String>
    where
        Self: Sized,
    {
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
        DataTypeComponentImpl::new(undefined_filler_data_type(), None, 1, ordinal, offset, None, None)
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

    /// Port of the private `StructureDataType.getAvailableComponentSpace(int)`: the available
    /// space for an existing defined component (identified by its index into
    /// [`components`](StructureDataType::components), *not* its ordinal) in relation to the next
    /// defined component or the end of the structure. Returns `-1` if packing is enabled
    /// (matching Java), or `i32::MAX` (Java's `Integer.MAX_VALUE`) if `index` is the last defined
    /// component of a non-packed structure.
    fn structure_data_type_get_available_component_space(&self, index: usize) -> i32
    where
        Self: Sized,
    {
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
    fn structure_data_type_consume_bytes_after(&mut self, index: usize, num_bytes: i32) -> i32
    where
        Self: Sized,
    {
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
    fn structure_data_type_data_type_size_changed(&mut self, dt: &dyn DataType) -> Result<(), String>
    where
        Self: Sized,
    {
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
    fn structure_data_type_data_type_alignment_changed(&mut self, dt: &dyn DataType)
    where
        Self: Sized,
    {
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
    ) -> Result<bool, String>
    where
        Self: Sized,
    {
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
    ) -> Result<(), String>
    where
        Self: Sized,
    {
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

    /// Port of `StructureDataType.dataTypeDeleted(DataType)`. See the module docs for what is
    /// skipped: the bitfield-base-type-deleted "revert to primitive type" case (Java's
    /// `updateBitFieldDataType(dtc, dt, bitfieldDt.getPrimitiveBaseDataType())` branch), which
    /// needs `BitFieldDataType.getPrimitiveBaseDataType()` (walking through `TypeDef`/`Enum` down
    /// to a primitive `AbstractIntegerDataType`), not yet ported in this crate -- a bitfield whose
    /// base type is deleted is therefore left unchanged here rather than reverted, and does not
    /// contribute to `changed` below.
    ///
    /// # Errors
    /// Returns `Err` if [`structure_data_type_set_component_data_type`](StructureDataType::structure_data_type_set_component_data_type)
    /// fails for some matching component (see its own doc comment; unreachable in practice here
    /// since the substituted [`bad_data_type_stand_in`] always succeeds).
    fn structure_data_type_data_type_deleted(&mut self, dt: &dyn DataType) -> Result<(), String>
    where
        Self: Sized,
    {
        let target_path = dt.get_data_type_path();
        let mut changed = false;
        let n = self.components().len();
        for i in (0..n).rev() {
            if self.components()[i].is_bit_field_component() {
                // Bitfield-base-type-deleted revert-to-primitive-type case: not ported, see this
                // method's own doc comment.
                continue;
            }
            if self.components()[i].get_data_type().get_data_type_path() == target_path {
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
    /// [`StructureDataTypeImpl`]'s own `impl DataType`), this method cannot be reached from a
    /// concrete implementor's `DataType::data_type_replaced` override without that implementor
    /// separately tracking its own way to reconstruct an owned replacement (e.g. its own
    /// `DataTypeManager` handle) -- out of scope here, so `StructureDataTypeImpl` leaves
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
    ) -> Result<(), String>
    where
        Self: Sized,
    {
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
                        undefined1_stand_in()
                    } else {
                        undefined_filler_data_type()
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

/// Placeholder [`DataOrganization`] used by [`StructureDataTypeImpl::get_data_organization`] until
/// a real per-program `DataOrganization` can be wired through a `DataTypeManager` (this crate has
/// no concrete, production `DataOrganization` implementation yet -- every other existing concrete
/// data type in this module, e.g. [`EnumDataType`](super::enum_data_type::EnumDataType), simply
/// leaves [`DataType::get_data_organization`] at its `unimplemented!()` default instead). Values
/// mirror common LP64 conventions (8-byte pointers, 4-byte `int`, 8-byte `long`), matching the
/// identical `MockDataOrganization` test double already used throughout this module's and
/// [`aligned_structure_packer`](super::aligned_structure_packer)'s tests -- this is the same
/// values, promoted out of `#[cfg(test)]` so [`StructureDataTypeImpl`]'s packing-enabled alignment
/// computation ([`AlignedStructurePacker::pack_components`]) has something real to call.
struct DefaultDataOrganization;

impl DataOrganization for DefaultDataOrganization {
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
        struct DefaultBitFieldPacking;
        impl crate::program::model::data::bit_field_packing::BitFieldPacking for DefaultBitFieldPacking {
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
        Box::new(DefaultBitFieldPacking)
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

/// Simplistic, non-bitfield-aware stand-in for the real (not-yet-ported) `AlignedComponentPacker`
/// algorithm: packs each component immediately after the previous one, aligned to its own length.
/// Mirrors the identical test double already used by this module's and
/// [`aligned_structure_packer`](super::aligned_structure_packer)'s tests, promoted here (rather
/// than kept `#[cfg(test)]`-only) so [`StructureDataTypeImpl`]'s packing-enabled path has a real
/// (if not bitfield-aware) packer to call -- see
/// [`StructureDataType`]'s own module docs on why no production `AlignedComponentPacker` exists
/// yet.
struct BasicComponentPacker {
    next_offset: i32,
    max_length: i32,
}

impl AlignedComponentPacker for BasicComponentPacker {
    fn add_component(&mut self, dtc: &mut dyn InternalDataTypeComponent, _is_last_component: bool) {
        let length = dtc.get_length().max(1);
        self.max_length = self.max_length.max(length);
        let offset = crate::program::seam_stubs::get_aligned_offset(length, self.next_offset);
        let component_length = dtc.get_length();
        dtc.update(dtc.get_ordinal(), offset, component_length);
        self.next_offset = offset + component_length;
    }
    fn get_default_alignment(&self) -> i32 {
        self.max_length
    }
    fn get_length(&self) -> i32 {
        self.next_offset
    }
    fn components_changed(&self) -> bool {
        false
    }
}

/// Port of `DataUtilities.isValidDataTypeName(String)`'s check as applied by the
/// `GenericDataType` constructor chain (`StructureDataType`'s Java superclass), used by
/// [`StructureDataTypeImpl::new_in_category`]. A local duplicate of
/// [`composite_data_type_impl::check_valid_name`](super::composite_data_type_impl)'s identical
/// logic (that helper is private to its own module and used for the checked-exception `setName`
/// path rather than this panic-based constructor path).
fn is_valid_structure_name(name: &str) -> bool {
    !name.trim().is_empty() && !name.chars().any(|c| c.is_control())
}

/// The first real, concrete, production implementation of [`StructureDataType`] in this crate.
///
/// Port of `ghidra.program.model.data.StructureDataType` itself (the trait of the same name in
/// this module exists only because it was promoted to a trait as a dependency-cycle cut-point --
/// see this module's top-level doc comment). Every previous test of [`StructureDataType`]'s
/// default methods exercised them against a `#[cfg(test)]`-scoped `MockStructureDataType` double;
/// this type is the real thing, meant for actual use, with real Java-faithful constructors and a
/// real `copy`/`clone` (both of which have no home as trait default methods at all, since a trait
/// default method cannot return a sized, constructible `Self` -- see the module docs).
///
/// Field layout mirrors the Java class directly: `category_path`/`name`/`description` stand in
/// for the inherited `GenericDataType`/`CompositeDataTypeImpl` fields, `minimum_alignment_value`/
/// `packing_value` are the raw `CompositeDataTypeImpl.minimumAlignment`/`.packing` fields (the
/// `composite_impl_*` default methods on [`CompositeDataTypeImpl`] already contain all the real
/// logic that interprets these two raw values -- this struct only needs to store and expose them),
/// and `struct_length`/`num_components`/`components` are `StructureDataType`'s own
/// `structLength`/`numComponents`/`components` fields.
///
/// Known, intentional gaps (beyond the ones already documented for the [`StructureDataType`] trait
/// itself, which all still apply verbatim -- `replace`/`replaceAtOffset`/`dataType*Changed`/
/// `dataType.clone(dataMgr)`/parent tracking):
///   - [`get_data_organization`](DataType::get_data_organization) returns a fixed
///     [`DefaultDataOrganization`] rather than one derived from an associated `DataTypeManager`,
///     since `dataMgr` is not tracked at all (matching
///     [`EnumDataType`](super::enum_data_type::EnumDataType)'s identical simplification).
///   - [`AlignedStructurePacker::create_component_packer`] returns a [`BasicComponentPacker`], a
///     simplistic sequential (non-bitfield-aware) packer, since this crate has no production
///     `AlignedComponentPacker` port yet.
///   - [`DataType::is_equivalent`]/[`DataType::replace_with`] are left at their generic
///     placeholder defaults (matching `MockStructureDataType`'s own precedent): both would need to
///     downcast an arbitrary `&dyn DataType` to `&dyn StructureDataType` specifically (not just
///     `&dyn Structure`, since [`structure_data_type_is_equivalent`](StructureDataType::structure_data_type_is_equivalent)/
///     [`structure_data_type_replace_with`](StructureDataType::structure_data_type_replace_with)
///     need direct access to the other side's `components()`), and no such downcast hook exists on
///     [`DataType`] (adding one would invert the dependency direction this trait was split out to
///     cut). Callers who already have two `StructureDataTypeImpl` values (or anything else
///     implementing [`StructureDataType`]) can call
///     [`structure_data_type_is_equivalent`](StructureDataType::structure_data_type_is_equivalent)/
///     [`structure_data_type_replace_with`](StructureDataType::structure_data_type_replace_with)
///     directly, exactly as [`copy_data_type`](DataType::copy_data_type)/
///     [`clone_data_type`](DataType::clone_data_type) below do.
pub struct StructureDataTypeImpl {
    category_path: CategoryPath,
    name: String,
    description: Option<String>,
    minimum_alignment_value: i32,
    packing_value: i32,
    struct_length: i32,
    num_components: i32,
    components: Vec<DataTypeComponentImpl>,
    universal_id: UniversalID,
    source_archive_id: Option<UniversalID>,
    last_change_time: i64,
    last_change_time_in_source_archive: i64,
}

impl StructureDataTypeImpl {
    /// Construct a new structure with the given name and length. The root category is used.
    ///
    /// Port of the 2-arg Java constructor `StructureDataType(String, int)` (the 3-arg overload
    /// additionally taking a `DataTypeManager` collapses into this one, matching
    /// [`EnumDataType::new`](super::enum_data_type::EnumDataType::new)'s identical
    /// simplification: `dataMgr` is not tracked).
    ///
    /// # Panics
    /// Panics (standing in for `IllegalArgumentException`) if `length` is negative, or if `name`
    /// is not a valid data-type name.
    pub fn new(name: impl Into<String>, length: i32) -> Self {
        Self::new_in_category(ROOT.clone(), name, length)
    }

    /// Construct a new structure with the given name and length within the specified category.
    ///
    /// Port of the 4-arg Java constructor `StructureDataType(CategoryPath, String, int,
    /// DataTypeManager)` (collapsed with its 3-arg `dataMgr`-less overload, same simplification as
    /// [`new`](Self::new)).
    ///
    /// # Panics
    /// See [`new`](Self::new).
    pub fn new_in_category(category_path: CategoryPath, name: impl Into<String>, length: i32) -> Self {
        let name = name.into();
        if length < 0 {
            panic!("IllegalArgumentException: Length can't be negative");
        }
        if !is_valid_structure_name(&name) {
            panic!("IllegalArgumentException: Invalid DataType name: {name}");
        }
        StructureDataTypeImpl {
            category_path,
            name,
            description: None,
            minimum_alignment_value: DEFAULT_ALIGNMENT,
            packing_value: NO_PACKING,
            struct_length: length,
            num_components: length,
            components: Vec::new(),
            universal_id: UniversalID::new(0),
            source_archive_id: None,
            last_change_time: 0,
            last_change_time_in_source_archive: 0,
        }
    }

    /// Construct a new structure with an explicit archive identity.
    ///
    /// Port of the 8-arg Java constructor taking `universalID`/`sourceArchive`/`lastChangeTime`/
    /// `lastChangeTimeInSourceArchive`. `source_archive` is tracked only by ID, matching
    /// [`EnumDataType::with_archive_identity`](super::enum_data_type::EnumDataType::with_archive_identity)'s
    /// identical simplification.
    ///
    /// # Panics
    /// See [`new`](Self::new).
    #[allow(clippy::too_many_arguments)]
    pub fn with_archive_identity(
        category_path: CategoryPath,
        name: impl Into<String>,
        length: i32,
        universal_id: UniversalID,
        source_archive: Option<&dyn SourceArchive>,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
    ) -> Self {
        let mut s = Self::new_in_category(category_path, name, length);
        s.universal_id = universal_id;
        s.source_archive_id = source_archive.map(|a| a.source_archive_id());
        s.last_change_time = last_change_time;
        s.last_change_time_in_source_archive = last_change_time_in_source_archive;
        s
    }
}

impl DataType for StructureDataTypeImpl {
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

    fn get_data_organization(&self) -> Box<dyn DataOrganization> {
        Box::new(DefaultDataOrganization)
    }

    fn get_mnemonic(&self, settings: &dyn Settings) -> String {
        self.composite_impl_mnemonic(settings)
    }

    fn get_length(&self) -> i32 {
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

    fn is_structure(&self) -> bool {
        true
    }

    fn as_structure(&self) -> Option<&dyn Structure> {
        Some(self)
    }

    fn as_composite(&self) -> Option<&dyn Composite> {
        Some(self)
    }

    /// Port of `StructureDataType.copy(DataTypeManager)`: constructs a brand-new
    /// `StructureDataTypeImpl` (new identity, no source archive) and repopulates it from `self` via
    /// [`structure_data_type_replace_with`](StructureDataType::structure_data_type_replace_with).
    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let _ = dtm;
        let mut copy = StructureDataTypeImpl::new_in_category(
            self.get_category_path(),
            self.get_name(),
            self.stored_struct_length(),
        );
        copy.composite_impl_set_description(Some(&self.get_description()));
        copy.structure_data_type_replace_with(self)
            .expect("replaceWith from a well-formed StructureDataTypeImpl cannot fail");
        Box::new(copy)
    }

    /// Port of `StructureDataType.clone(DataTypeManager)`: like
    /// [`copy_data_type`](Self::copy_data_type) but preserves this structure's archive identity
    /// (`universalID`/`sourceArchive`/change-time fields) on the clone. Java short-circuits and
    /// returns `this` when `dataMgr == dataMgr`; since `dataMgr` is not tracked here at all (see
    /// the struct docs), that identity check can never apply and this always produces a fresh
    /// clone.
    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let _ = dtm;
        let mut clone = StructureDataTypeImpl::with_archive_identity(
            self.get_category_path(),
            self.get_name(),
            self.stored_struct_length(),
            self.universal_id,
            None,
            self.last_change_time,
            self.last_change_time_in_source_archive,
        );
        clone.source_archive_id = self.source_archive_id;
        clone.composite_impl_set_description(Some(&self.get_description()));
        clone
            .structure_data_type_replace_with(self)
            .expect("replaceWith from a well-formed StructureDataTypeImpl cannot fail");
        Box::new(clone)
    }

    /// Port of `StructureDataType.dataTypeSizeChanged(DataType)`. See
    /// [`structure_data_type_data_type_size_changed`](StructureDataType::structure_data_type_data_type_size_changed)'s
    /// own doc comment for the ported algorithm; a genuinely invalid preferred length (mirroring
    /// Java's uncaught `IllegalArgumentException`) is treated here as "nothing to do" rather than
    /// panicking, since this override's signature has no `Result` to propagate through.
    fn data_type_size_changed(&mut self, dt: &dyn DataType) {
        let _ = self.structure_data_type_data_type_size_changed(dt);
    }

    /// Port of `StructureDataType.dataTypeAlignmentChanged(DataType)`.
    fn data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        self.structure_data_type_data_type_alignment_changed(dt);
    }

    /// Port of `StructureDataType.dataTypeDeleted(DataType)`. See
    /// [`structure_data_type_data_type_deleted`](StructureDataType::structure_data_type_data_type_deleted)'s
    /// own doc comment for what is skipped (the bitfield-base-type-deleted revert case).
    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        let _ = self.structure_data_type_data_type_deleted(dt);
    }

    // `data_type_replaced` is intentionally left at its inherited placeholder default: see
    // `structure_data_type_data_type_replaced`'s own doc comment for why it cannot be reached
    // generically from this override's borrowed `new_dt: &dyn DataType`.
}

impl Composite for StructureDataTypeImpl {
    fn get_num_components(&self) -> i32 {
        self.structure_data_type_get_num_components()
    }

    fn get_num_defined_components(&self) -> i32 {
        self.structure_data_type_get_num_defined_components()
    }

    fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_get_component(ordinal)
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }

    fn get_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        self.structure_data_type_get_components()
            .into_iter()
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
            .collect()
    }

    fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        self.structure_data_type_get_defined_components()
            .into_iter()
            .map(|c| Box::new(c.snapshot()) as Box<dyn DataTypeComponent>)
            .collect()
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
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
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

impl CompositeInternal for StructureDataTypeImpl {
    fn get_stored_packing_value(&self) -> i32 {
        self.composite_impl_stored_packing_value()
    }

    fn get_stored_minimum_alignment(&self) -> i32 {
        self.composite_impl_stored_minimum_alignment()
    }
}

impl Structure for StructureDataTypeImpl {
    fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_get_component(ordinal)
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }

    fn get_defined_component_at_or_after_offset(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
        self.structure_data_type_get_defined_component_at_or_after_offset(offset)
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }

    fn get_component_containing(&self, offset: i32) -> Option<Box<dyn DataTypeComponent>> {
        self.structure_data_type_get_component_containing(offset)
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }

    fn get_components_containing(&self, offset: i32) -> Vec<Box<dyn DataTypeComponent>> {
        self.structure_data_type_get_components_containing(offset)
            .into_iter()
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
            .collect()
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
        .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
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
        .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }

    fn insert_at_offset(
        &mut self,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.structure_data_type_insert_at_offset(offset, data_type, length, None, None)
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
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
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
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

    // `replace`/`replace_with_name`/`replace_at_offset` are intentionally left at their
    // placeholder defaults -- see the module docs' "explicitly and intentionally not yet ported"
    // list; `Structure.replace(...)`'s real Java algorithm was never ported.
}

impl StructureInternal for StructureDataTypeImpl {}

impl CompositeDataTypeImpl for StructureDataTypeImpl {
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

    /// Port of `StructureDataType.getAlignment()`. Unlike Java, this does not cache into a
    /// `structAlignment`-equivalent field (this struct has none -- see the module docs on why
    /// [`StructureDataType`] tracks no such field), so a packing-enabled structure recomputes its
    /// alignment from scratch on every call; this is a harmless performance-only divergence
    /// (identical to the one already documented for [`UnionDataType::union_data_type_alignment`](super::union_data_type::UnionDataType::union_data_type_alignment)),
    /// not a correctness one.
    fn composite_impl_alignment(&self) -> i32 {
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
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
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
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }

    /// Port of `CompositeDataTypeImpl.validateDataType(DataType)`, real but for one skip: Java's
    /// `dataType == DataType.DEFAULT` branch additionally substitutes `Undefined1DataType.dataType`
    /// when packing is enabled (or always, for a `Union`); this crate has no constructible
    /// `Undefined1DataType` singleton (see [`super::undefined1_data_type`]'s own module docs), so
    /// the substitution is skipped and the `DEFAULT`-like value is passed through unchanged. The
    /// `instanceof FactoryDataType` check is also skipped, matching this trait's own module docs on
    /// why [`DataType`] exposes no `FactoryDataType` downcast hook yet.
    fn composite_impl_validate_data_type(&self, data_type: Box<dyn DataType>) -> Result<Box<dyn DataType>, String> {
        if data_type.is_default_data_type() {
            return Ok(data_type);
        }
        if let Some(dynamic) = data_type.as_dynamic() {
            if !dynamic.can_specify_length() {
                return Err(format!(
                    "IllegalArgumentException: The \"{}\" data type is not allowed in a composite data type.",
                    data_type.get_name()
                ));
            }
        } else if data_type.get_length() <= 0 {
            return Err(format!(
                "IllegalArgumentException: The \"{}\" data type is not allowed in a composite data type.",
                data_type.get_name()
            ));
        }
        Ok(data_type)
    }

    /// Not wired: the only Java caller, `dataTypeReplaced`, is not ported (see the module docs'
    /// "explicitly and intentionally not yet ported" list).
    fn composite_impl_update_bit_field_data_type(
        &mut self,
        bitfield_component: Box<dyn DataTypeComponent>,
        old_dt: &dyn DataType,
        new_dt: Option<&dyn DataType>,
    ) -> Result<bool, String> {
        let (_, _, _) = (bitfield_component, old_dt, new_dt);
        Ok(false)
    }
}

impl AlignedStructurePacker for StructureDataTypeImpl {
    fn create_component_packer(
        &self,
        _pack_value: i32,
        _data_organization: &dyn DataOrganization,
    ) -> Box<dyn AlignedComponentPacker> {
        Box::new(BasicComponentPacker { next_offset: 0, max_length: 1 })
    }
}

impl StructureDataType for StructureDataTypeImpl {
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

    /// Minimal [`DataOrganization`] stand-in, needed only so
    /// [`AlignedStructurePacker::pack_components`]'s default body has something to call
    /// `get_machine_alignment()`/`is_big_endian()`/`get_bit_field_packing()` on -- matches the
    /// identical mock already used by
    /// [`aligned_structure_packer`](crate::program::model::data::aligned_structure_packer)'s own
    /// tests.
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

    impl DataType for MockStructureDataType {
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
            StructureDataType::length(self)
        }
    }

    impl Composite for MockStructureDataType {
        fn get_num_components(&self) -> i32 {
            self.num_components
        }
        fn get_packing_type(&self) -> PackingType {
            self.packing_type
        }
        // Bridges the placeholder `Composite::get_defined_components` default to this mock's
        // real `components` storage -- needed so `is_part_of_data_type_by_ref`'s recursive walk
        // (used by `structure_data_type_check_ancestry`) can actually see nested components when
        // a `MockStructureDataType` itself appears as another structure's component data type,
        // exactly as the module docs describe a real concrete `impl Composite for ...` doing.
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .map(|dtc| Box::new(dtc.snapshot()) as Box<dyn DataTypeComponent>)
                .collect()
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
            // Mirrors `get_stored_packing_value` below -- both derive from the single
            // `packing_type` field so a `structure_data_type_replace_with` (which only ever
            // writes through this raw setter) is observable via `is_packing_enabled()`/
            // `get_packing_type()` too, exactly as a real concrete implementor would wire it.
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

    /// Sequential, non-bitfield-aware stand-in for the real (not-yet-ported) `AlignedComponentPacker`
    /// algorithm, matching the identical test double already used by
    /// [`aligned_structure_packer`](crate::program::model::data::aligned_structure_packer)'s own
    /// tests: packs each component immediately after the previous one, aligned to its own length.
    struct SequentialComponentPacker {
        next_offset: i32,
        max_length: i32,
    }

    impl crate::program::seam_stubs::AlignedComponentPacker for SequentialComponentPacker {
        fn add_component(&mut self, dtc: &mut dyn InternalDataTypeComponent, _is_last_component: bool) {
            let length = dtc.get_length().max(1);
            self.max_length = self.max_length.max(length);
            let offset = crate::program::seam_stubs::get_aligned_offset(length, self.next_offset);
            let component_length = dtc.get_length();
            dtc.update(dtc.get_ordinal(), offset, component_length);
            self.next_offset = offset + component_length;
        }
        fn get_default_alignment(&self) -> i32 {
            self.max_length
        }
        fn get_length(&self) -> i32 {
            self.next_offset
        }
        fn components_changed(&self) -> bool {
            false
        }
    }

    impl AlignedStructurePacker for MockStructureDataType {
        fn create_component_packer(
            &self,
            _pack_value: i32,
            _data_organization: &dyn crate::program::model::data::data_organization::DataOrganization,
        ) -> Box<dyn crate::program::seam_stubs::AlignedComponentPacker> {
            Box::new(SequentialComponentPacker { next_offset: 0, max_length: 1 })
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
        s.packing_type = PackingType::Default;

        // The test-double `SequentialComponentPacker` places each component immediately after
        // the previous one, aligned to its own length (matching
        // `aligned_structure_packer`'s own test module's identical packer).
        s.structure_data_type_add(byte_data_type("byte", 1), -1, Some("a".to_string()), None)
            .unwrap();
        assert_eq!(s.stored_struct_length(), 1);

        s.structure_data_type_add(byte_data_type("int", 4), -1, Some("b".to_string()), None)
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
        source.packing_type = PackingType::Default;
        source
            .structure_data_type_add(byte_data_type("byte", 1), -1, Some("a".to_string()), None)
            .unwrap();
        source
            .structure_data_type_add(byte_data_type("int", 4), -1, Some("b".to_string()), None)
            .unwrap();

        let mut target = sample();
        target.structure_data_type_replace_with(&source).unwrap();

        assert!(target.is_packing_enabled());
        assert_eq!(target.structure_data_type_get_num_defined_components(), 2);
        assert_eq!(target.stored_struct_length(), 8); // matches the sequential test packer's layout
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
    fn three_component_sample() -> MockStructureDataType {
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
        s.packing_type = PackingType::Default;
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
    // `StructureDataTypeImpl`: the first real, production concrete `StructureDataType` (as
    // opposed to the `#[cfg(test)]`-scoped `MockStructureDataType` above). These tests exercise
    // construction, `copy`/`clone`, and the ancestor `Composite`/`Structure`/`DataType` trait
    // surface (`add`/`insert`/`delete`/`get_component`/etc., not just the `structure_data_type_*`
    // methods directly) to prove the whole trait stack genuinely composes on a real struct.
    // ------------------------------------------------------------------------------------------

    #[test]
    fn new_creates_empty_root_category_structure() {
        let s = StructureDataTypeImpl::new("Foo", 0);
        assert_eq!(s.get_name(), "Foo");
        assert_eq!(s.get_category_path(), ROOT.clone());
        assert!(s.structure_data_type_is_zero_length());
        assert_eq!(DataType::get_length(&s), 1);
        assert!(s.is_not_yet_defined());
    }

    #[test]
    fn new_with_length_reports_that_length_and_num_components() {
        let s = StructureDataTypeImpl::new("Foo", 4);
        assert_eq!(DataType::get_length(&s), 4);
        assert_eq!(Composite::get_num_components(&s), 4);
        assert_eq!(Composite::get_num_defined_components(&s), 0);
        assert!(!s.is_not_yet_defined());
    }

    #[test]
    #[should_panic(expected = "Length can't be negative")]
    fn new_rejects_negative_length() {
        StructureDataTypeImpl::new("Foo", -1);
    }

    #[test]
    #[should_panic(expected = "Invalid DataType name")]
    fn new_rejects_invalid_name() {
        StructureDataTypeImpl::new("   ", 0);
    }

    #[test]
    fn new_in_category_uses_specified_category() {
        let path = CategoryPath::new(ROOT.clone(), &["cat"]).expect("valid category path");
        let s = StructureDataTypeImpl::new_in_category(path.clone(), "Foo", 0);
        assert_eq!(s.get_category_path(), path);
    }

    #[test]
    fn with_archive_identity_preserves_universal_id_and_change_times() {
        let s = StructureDataTypeImpl::with_archive_identity(
            ROOT.clone(),
            "Foo",
            0,
            UniversalID::new(42),
            None,
            100,
            200,
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
        let mut s = StructureDataTypeImpl::new("Foo", 0);
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
        let mut s = StructureDataTypeImpl::new("Foo", 0);
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
        let mut a = StructureDataTypeImpl::new("A", 0);
        a.structure_data_type_add(dt("int", 4), -1, Some("x".to_string()), None).unwrap();

        let mut b = StructureDataTypeImpl::new("B", 0);
        b.structure_data_type_add(dt("int", 4), -1, Some("x".to_string()), None).unwrap();

        assert!(a.structure_data_type_is_equivalent(&b));

        b.structure_data_type_add(dt("short", 2), -1, Some("y".to_string()), None).unwrap();
        assert!(!a.structure_data_type_is_equivalent(&b));
    }

    #[test]
    fn copy_data_type_produces_independent_equivalent_structure() {
        struct NoopDtm;
        impl DataTypeManager for NoopDtm {}

        let mut original = StructureDataTypeImpl::new("Original", 0);
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
        impl DataTypeManager for NoopDtm {}

        let mut original = StructureDataTypeImpl::with_archive_identity(
            ROOT.clone(),
            "Original",
            0,
            UniversalID::new(7),
            None,
            10,
            20,
        );
        original.add_with_name(dt("int", 4), Some("field0".to_string()), None).unwrap();

        let cloned = original.clone_data_type(&NoopDtm);
        let cloned_struct = cloned.as_structure().expect("clone is a Structure");
        assert_eq!(cloned.get_name(), "Original");
        assert_eq!(cloned_struct.get_num_components(), 1);
    }

    #[test]
    fn non_packed_alignment_defaults_to_one_and_machine_alignment_uses_data_organization() {
        let s = StructureDataTypeImpl::new("Foo", 0);
        assert_eq!(DataType::get_alignment(&s), 1);

        let mut machine_aligned = StructureDataTypeImpl::new("Bar", 0);
        machine_aligned.set_to_machine_aligned();
        assert_eq!(DataType::get_alignment(&machine_aligned), 8); // DefaultDataOrganization::get_machine_alignment
    }

    #[test]
    fn packing_enabled_structure_computes_alignment_without_panicking() {
        let mut s = StructureDataTypeImpl::new("Packed", 0);
        s.set_packing_enabled(true);
        s.add(dt("int", 4)).expect("add int");
        s.add(dt("byte", 1)).expect("add byte");
        // Must not panic reaching into `DefaultDataOrganization`/`BasicComponentPacker`.
        let alignment = DataType::get_alignment(&s);
        assert!(alignment >= 1);
        assert!(s.is_packing_enabled());
    }

    #[test]
    fn data_type_size_changed_shrinks_component_and_opens_undefined_gap() {
        let mut s = StructureDataTypeImpl::new("Foo", 0);
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
        let mut s = StructureDataTypeImpl::new("Foo", 0);
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
        let mut s = StructureDataTypeImpl::new("Foo", 0);
        s.structure_data_type_add(dt("int", 4), -1, None, None).unwrap();
        let length_before = s.stored_struct_length();
        s.structure_data_type_data_type_alignment_changed(dt("int", 4).as_ref());
        assert_eq!(s.stored_struct_length(), length_before);
    }

    #[test]
    fn data_type_alignment_changed_repacks_when_packing_enabled() {
        let mut s = StructureDataTypeImpl::new("Packed", 0);
        s.set_packing_enabled(true);
        s.add(dt("int", 4)).expect("add int");
        // Must not panic reaching into `DefaultDataOrganization`/`BasicComponentPacker`, and must
        // leave the structure in a consistent, still-packed state.
        s.structure_data_type_data_type_alignment_changed(dt("int", 4).as_ref());
        assert!(s.is_packing_enabled());
        assert_eq!(Composite::get_num_components(&s), 1);
    }

    #[test]
    fn data_type_deleted_substitutes_bad_data_type_stand_in_preserving_length() {
        let mut s = StructureDataTypeImpl::new("Foo", 0);
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
        let mut s = StructureDataTypeImpl::new("Foo", 0);
        s.structure_data_type_add(dt("int", 4), -1, Some("a".to_string()), None).unwrap();

        s.structure_data_type_data_type_replaced(dt("int", 4).as_ref(), dt("long", 8)).unwrap();

        assert_eq!(s.components()[0].get_data_type().get_name(), "long");
        assert_eq!(s.components()[0].get_length(), 8);
        assert_eq!(s.stored_struct_length(), 8);
        assert_eq!(s.stored_num_components(), 1);
    }

    #[test]
    fn data_type_replaced_falls_back_to_default_on_ancestry_rejection() {
        let mut outer = StructureDataTypeImpl::new("Outer", 0);
        outer.structure_data_type_add(dt("int", 4), -1, Some("x".to_string()), None).unwrap();

        // "Inner" contains a field path-equal to "Outer" itself, so replacing Outer's "int"
        // component with an Inner instance would create a cyclic composite; checkAncestry should
        // reject it, falling back to the non-packed `DataType.DEFAULT` stand-in.
        let mut inner = StructureDataTypeImpl::new("Inner", 0);
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
        let mut s = StructureDataTypeImpl::new("Foo", 0);
        s.structure_data_type_add_bit_field(int_data_type("int", 4), 5, Some("flags".to_string()), None)
            .unwrap();

        s.structure_data_type_data_type_replaced(int_data_type("int", 4).as_ref(), int_data_type("long", 8))
            .unwrap();

        let stored = s.components()[0].get_data_type();
        let bitfield = stored.as_bit_field_data_type().expect("still a bitfield");
        assert_eq!(bitfield.get_base_data_type().get_name(), "long");
        assert_eq!(bitfield.get_declared_bit_size(), 5);
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
