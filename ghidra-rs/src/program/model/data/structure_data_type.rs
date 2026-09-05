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
//! Explicitly and intentionally **not yet ported** (do not flip `StructureDataType.java`'s
//! `PORT_MANIFEST.tsv` row to `DONE` until these are addressed or a narrower definition of "done"
//! is agreed):
//!   - `replace`/`replaceAtOffset`/`dataTypeSizeChanged`/`dataTypeAlignmentChanged`/
//!     `dataTypeDeleted`/`dataTypeReplaced`/`copy`/`clone` are not ported. `replace`
//!     in particular has an intricate multi-case algorithm (bit-field-overlap consolidation,
//!     "quick update" fast path, `LinkedList<DataTypeComponentImpl>` sequence replacement) that
//!     was not reached this session. `copy`/`clone` additionally have no home as trait default
//!     methods at all in this architecture: both Java bodies construct a brand-new
//!     `StructureDataType` instance (`new StructureDataType(...)`) and then call `replaceWith`
//!     on it, but a Rust trait default method cannot return a sized, constructible `Self` (see
//!     this module's very first doc paragraph re: the five constructors); only a concrete
//!     implementor -- which alone knows how to build a fresh instance of itself -- can wire
//!     `copy`/`clone` up, by calling its own constructor and then
//!     `structure_data_type_replace_with`.
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
use crate::program::model::data::aligned_structure_packer::AlignedStructurePacker;
use crate::program::model::data::bit_field_data_type::{
    check_base_data_type, get_effective_bit_size, get_minimum_storage_size_no_offset, BitFieldDataType,
};
use crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl;
use crate::program::model::data::composite_internal::{
    compare_component_to_offset, compare_component_to_ordinal,
};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_component_impl::DataTypeComponentImpl;
use crate::program::model::data::internal_data_type_component::InternalDataTypeComponent;
use crate::program::model::data::structure::get_normalized_bitfield_offset;
use crate::program::model::data::structure_internal::StructureInternal;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::share_data_type;
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
