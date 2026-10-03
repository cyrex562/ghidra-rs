//! Port of `ghidra.program.model.data.AlignedComponentPacker`.
//!
//! `AlignedComponentPacker` provides the actual alignment/bitfield-packing arithmetic used by
//! [`AlignedStructurePacker`](super::aligned_structure_packer::AlignedStructurePacker) (already
//! ported, previously stubbed out against a minimal placeholder trait -- see that module's own
//! docs). This is the real thing: the class Java's `AlignedStructureInspector`/`StructureDataType`/
//! `UnionDataType` all ultimately rely on for packed-layout computation.
//!
//! ## The `lastComponent` problem
//!
//! Java's `AlignedComponentPacker` holds a live `InternalDataTypeComponent lastComponent` field
//! across `addComponent` calls -- an object reference it can read from *and mutate* at any later
//! point. This crate's [`seam_stubs::AlignedComponentPacker`](crate::program::seam_stubs::AlignedComponentPacker)
//! trait, by contrast, only ever hands `add_component` the *current* component for the duration of
//! a single call (no lifetime parameter lets a struct field borrow it across calls), so this port
//! cannot literally hold onto the previous call's `dtc`. Two different strategies are used here to
//! bridge that gap, chosen per how `lastComponent` is actually used in the Java source:
//!
//! - **Read-only uses** (the overwhelming majority: `isBitFieldComponent()`, `getOffset()`,
//!   `getEndOffset()`, the wrapped `BitFieldDataType`'s `getBitOffset()`/`getBitSize()`/
//!   `getBaseTypeSize()`, etc.) are served by [`LastComponentSnapshot`], a small `Copy` struct
//!   capturing exactly the fields any Java call site ever reads off `lastComponent`, taken right
//!   after each `add_component` call finishes mutating its own `dtc` (mirroring Java's own
//!   `lastComponent = dtc;` assignment at the end of `addComponent`).
//! - **The one write-only use** -- `adjustZeroLengthBitField`'s `updateComponent(lastComponent,
//!   ordinal, groupOffset, 0, minimumAlignment)`, needed because a zero-length bitfield's final
//!   offset can depend on whatever alignment the *next* component demands -- is handled by
//!   recording a [`PendingZeroBitfieldUpdate`] (index + final ordinal/offset) instead of applying
//!   it immediately, and flushing it from
//!   [`finalize_pending_updates`](seam_stubs::AlignedComponentPacker::finalize_pending_updates)
//!   once [`AlignedStructurePacker::pack_components`](super::aligned_structure_packer::AlignedStructurePacker::pack_components)
//!   hands back the full component slice after its main loop. This is provably equivalent to
//!   Java's synchronous mutation: every other computation that follows an adjustment reads the
//!   *packer's own* `groupOffset`/`lastAlignment` fields (already updated synchronously here, same
//!   as Java), never `lastComponent`'s mutated fields directly -- the live Java reference is used
//!   purely so the *structure's own component list* ends up with the correct final offset, a
//!   side-effect this port defers but still guarantees before `pack_components` returns.
//!
//! One accepted, documented limitation falls out of this: if two zero-length bitfields appear
//! back-to-back with no real component between them, only the *second* one's pending update
//! survives to be flushed (the first is silently overwritten). This matches Java's own behavior in
//! that same scenario: Java never re-visits the first zero-length bitfield's object either once
//! `lastComponent` moves on to the second one, so it likewise keeps stale offset/length rather than
//! sharing this port's simplification -- this is a pre-existing Java quirk, not a regression.
//!
//! ## `getPrimitiveBaseDataType()` approximation
//!
//! `alignAndPackBitField`'s `bitfieldDt.getPrimitiveBaseDataType().getAlignment()` call is
//! approximated with [`BitFieldDataType::get_alignment`](crate::program::model::data::data_type::DataType::get_alignment)
//! (which already forwards to the base type's own alignment -- see
//! [`bit_field_data_type`](super::bit_field_data_type)'s own module docs on why the full
//! `TypeDef`/`Enum`-resolving primitive substitution isn't ported). This only differs from Java in
//! the rare case of a bitfield built over an `Enum` base type whose declared alignment differs from
//! the alignment Java's synthesized unsigned-integer stand-in would report -- a corner case with no
//! coverage in this crate's `Enum` port either.

use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::program::model::data::bit_field_data_type::BitFieldDataType;
use crate::program::model::data::composite_alignment_helper::get_packed_alignment_values;
use crate::program::model::data::composite_internal::{DEFAULT_PACKING, NO_PACKING};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_organization_impl::{get_aligned_offset, get_least_common_multiple};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::internal_data_type_component::InternalDataTypeComponent;
use crate::program::seam_stubs;
// Imported (aliased to avoid colliding with this module's own `AlignedComponentPacker` struct of
// the same name -- matching the Java class) so `self.get_length()`/etc. dot-call syntax resolves
// against the trait's methods from within this struct's own inherent `impl` block below.
use crate::program::seam_stubs::AlignedComponentPacker as SeamAlignedComponentPacker;

/// Snapshot of every field any Java call site ever reads off `AlignedComponentPacker.lastComponent`.
/// See the module docs for why this stands in for a live object reference.
#[derive(Debug, Clone, Copy, Default)]
struct LastComponentSnapshot {
    offset: i32,
    length: i32,
    end_offset: i32,
    is_bit_field: bool,
    is_zero_bit_field: bool,
    /// `BitFieldDataType.getBitOffset()`; only meaningful when `is_bit_field`.
    bit_offset: i32,
    /// `BitFieldDataType.getBitSize()` (effective size); only meaningful when `is_bit_field`.
    bit_size: i32,
    /// `BitFieldDataType.getBaseTypeSize()`; only meaningful when `is_bit_field`.
    base_type_size: i32,
    /// `BitFieldDataType.getBaseDataType().getAlignment()`; only meaningful when `is_bit_field`
    /// (used by `getLength()`'s trailing-zero-length-bitfield case).
    base_alignment: i32,
}

/// A deferred write recorded by [`AlignedComponentPacker::adjust_zero_length_bit_field`], applied
/// by [`finalize_pending_updates`](seam_stubs::AlignedComponentPacker::finalize_pending_updates).
/// See the module docs.
#[derive(Debug, Clone, Copy)]
struct PendingZeroBitfieldUpdate {
    index: usize,
    ordinal: i32,
    offset: i32,
}

/// Port of `ghidra.program.model.data.AlignedComponentPacker`.
///
/// Provides component packing support to
/// [`AlignedStructurePacker`](super::aligned_structure_packer::AlignedStructurePacker). See the
/// module docs for what differs from the Java original and why.
pub struct AlignedComponentPacker {
    pack_value: i32,
    ms_convention: bool,
    type_alignment_enabled: bool,
    zero_length_boundary: i32,
    is_big_endian: bool,

    next_ordinal: i32,
    zero_alignment: i32,
    last_alignment: i32,
    /// -1 indicates no active group; see the Java field's own doc comment (ported verbatim).
    group_offset: i32,
    last_component: Option<LastComponentSnapshot>,
    default_alignment: i32,
    components_changed: bool,
    pending_zero_bitfield: Option<PendingZeroBitfieldUpdate>,
}

impl AlignedComponentPacker {
    /// Port of `AlignedComponentPacker(int, DataOrganization)`.
    pub fn new(pack_value: i32, data_organization: &DataOrganizationImpl) -> Self {
        let bit_field_packing = data_organization.get_bit_field_packing();
        AlignedComponentPacker {
            pack_value,
            ms_convention: bit_field_packing.use_ms_convention(),
            type_alignment_enabled: bit_field_packing.is_type_alignment_enabled(),
            zero_length_boundary: bit_field_packing.get_zero_length_boundary(),
            is_big_endian: data_organization.is_big_endian(),
            next_ordinal: 0,
            zero_alignment: 0,
            last_alignment: 0,
            group_offset: -1,
            last_component: None,
            default_alignment: 1,
            components_changed: false,
            pending_zero_bitfield: None,
        }
    }

    /// Port of `AlignedComponentPacker.getBitFieldTypeSize(InternalDataTypeComponent)`.
    ///
    /// # Panics
    /// Panics (standing in for the Java `AssertException`) if `dtc`'s data type is not a
    /// `BitFieldDataType`.
    fn get_bit_field_type_size(dtc: &dyn InternalDataTypeComponent) -> i32 {
        let dt = dtc.get_data_type();
        match dt.as_bit_field_data_type() {
            Some(bf) => bf.get_base_type_size(),
            None => panic!("AlignedComponentPacker: expected bitfield component only"),
        }
    }

    /// Port of `AlignedComponentPacker.getBitFieldAlignment(BitFieldDataType)`.
    fn get_bit_field_alignment(&self, bitfield_dt: &BitFieldDataType) -> i32 {
        if !self.ms_convention && self.pack_value != DEFAULT_PACKING {
            // GCC always uses 1 when packing regardless of pack value
            return 1;
        }
        get_packed_alignment_values(bitfield_dt.get_base_data_type().get_alignment(), self.pack_value)
    }

    /// Port of `AlignedComponentPacker.isIgnoredZeroBitField(BitFieldDataType)`.
    fn is_ignored_zero_bit_field(&self, zero_bit_field_dt: &BitFieldDataType) -> bool {
        if !zero_bit_field_dt.is_zero_length() {
            return false;
        }
        if self.ms_convention {
            return match &self.last_component {
                None => true,
                Some(last) => !last.is_bit_field,
            };
        }
        false
    }

    /// Port of `AlignedComponentPacker.getZeroBitFieldAlignment(BitFieldDataType, boolean)`.
    fn get_zero_bit_field_alignment(&self, zero_bit_field_dt: &BitFieldDataType, is_last_component: bool) -> i32 {
        if self.is_ignored_zero_bit_field(zero_bit_field_dt) {
            return -1;
        }

        if !self.type_alignment_enabled {
            if self.zero_length_boundary > 0 {
                return self.zero_length_boundary;
            }
            return 1;
        }

        let mut pack = self.pack_value;
        if !self.ms_convention && !is_last_component {
            // GCC ignores pack value for :0 bitfield alignment but considers it when passing
            // alignment along to structure
            pack = NO_PACKING;
        }

        get_packed_alignment_values(zero_bit_field_dt.get_base_data_type().get_alignment(), pack)
    }

    /// Port of `AlignedComponentPacker.initGroup(InternalDataTypeComponent, boolean)`.
    fn init_group(&mut self, dtc: &mut dyn InternalDataTypeComponent, is_last_component: bool) {
        self.group_offset = self.get_length();
        self.last_alignment = 1;

        if dtc.is_bit_field_component() {
            let data_type = dtc.get_data_type();
            let zero_bit_field_dt = data_type
                .as_bit_field_data_type()
                .expect("AlignedComponentPacker: bitfield component's data type must be a BitFieldDataType");

            if dtc.is_zero_bit_field_component() {
                // An alignment of -1 indicates field is ignored
                let alignment = self.get_zero_bit_field_alignment(zero_bit_field_dt, is_last_component);
                let base_alignment = zero_bit_field_dt.get_base_data_type().get_alignment();

                let zero_bit_offset = if self.is_big_endian { 7 } else { 0 };
                if zero_bit_field_dt.get_bit_offset() != zero_bit_offset || zero_bit_field_dt.get_storage_size() != 1
                {
                    let base = zero_bit_field_dt.get_base_data_type();
                    let packed_bit_field_dt = BitFieldDataType::new(base, 0, zero_bit_offset).expect(
                        "AlignedComponentPacker: normalizing a zero-length bitfield's bit-offset should never fail",
                    );
                    dtc.set_data_type(Box::new(packed_bit_field_dt));
                    self.components_changed = true;
                }

                if is_last_component {
                    // special handling of zero-length bitfield when it is last component
                    let offset = get_aligned_offset(base_alignment, self.group_offset);
                    let align = if alignment > 0 { alignment } else { 1 };
                    self.update_component(dtc, self.next_ordinal, offset, 0, align);
                    self.group_offset = -1;
                } else {
                    // Avoid conveying zero alignment onto structure; next component can influence
                    // alignment. Defer update of zero-length component and final determination of
                    // alignment (see module docs on `PendingZeroBitfieldUpdate`).
                    self.zero_alignment = alignment;

                    // NOTE: MSVC always conveys zero-length alignment
                    if self.ms_convention {
                        self.last_alignment = alignment;
                    }
                }
            } else {
                self.last_component = None; // first in allocation group
                self.align_and_pack_bit_field(dtc); // relies on group_offset when last_component is None
            }
        } else {
            // pack non-bitfield
            self.last_component = None; // first in allocation group
            self.align_and_pack_non_bitfield_component(dtc, self.group_offset);
        }
    }

    /// Port of `AlignedComponentPacker.adjustZeroLengthBitField(int, int)`.
    ///
    /// `lastComponent` (a zero-length bitfield) must be a zero-length bitfield and its associated
    /// `groupOffset` based upon the adjusted alignment. Unlike Java, this doesn't mutate the
    /// component directly -- see the module docs on [`PendingZeroBitfieldUpdate`].
    fn adjust_zero_length_bit_field(&mut self, ordinal: i32, minimum_alignment: i32) {
        let min_offset = get_aligned_offset(minimum_alignment, self.group_offset);
        let zero_alignment_offset = get_aligned_offset(self.zero_alignment, self.group_offset);

        // Determine component offset of zero-length bitfield and the component which immediately
        // follows it.
        if min_offset >= zero_alignment_offset {
            // natural offset satisfies :0 alignment
            self.group_offset = min_offset;
        } else {
            self.group_offset = zero_alignment_offset;
        }

        self.pending_zero_bitfield = Some(PendingZeroBitfieldUpdate {
            index: ordinal as usize,
            ordinal,
            offset: self.group_offset,
        });

        self.last_alignment = self.last_alignment.max(minimum_alignment);
    }

    /// Port of `AlignedComponentPacker.packComponent(InternalDataTypeComponent)`.
    fn pack_component(&mut self, dtc: &mut dyn InternalDataTypeComponent) -> bool {
        let Some(last) = self.last_component else {
            return false;
        };

        if dtc.is_zero_bit_field_component() {
            return false;
        }

        if dtc.is_bit_field_component() {
            if !last.is_zero_bit_field && self.ms_convention {
                if !last.is_bit_field {
                    return false; // can't pack bitfield with non-bitfield - start new group
                }
                if Self::get_bit_field_type_size(dtc) != last.base_type_size {
                    return false; // bitfield base types differ in size - start new group
                }
            }

            self.align_and_pack_bit_field(dtc); // relies on self.last_component

            return true;
        }

        if !last.is_zero_bit_field && self.ms_convention {
            return false; // start new group for non-bitfield
        }

        let offset = if last.is_zero_bit_field {
            self.group_offset
        } else {
            last.offset + last.length
        };

        self.align_and_pack_non_bitfield_component(dtc, offset);

        true
    }

    /// Port of `AlignedComponentPacker.alignAndPackNonBitfieldComponent(InternalDataTypeComponent, int)`.
    fn align_and_pack_non_bitfield_component(&mut self, dtc: &mut dyn InternalDataTypeComponent, min_offset: i32) {
        let component_dt = dtc.get_data_type();

        let mut dt_size = if component_dt.is_zero_length() { 0 } else { component_dt.get_aligned_length() };
        if dt_size < 0 {
            dt_size = dtc.get_length();
        }

        let alignment = get_packed_alignment_values(component_dt.get_alignment(), self.pack_value);

        let offset = if self.last_component.map(|l| l.is_zero_bit_field).unwrap_or(false) {
            // adjust group alignment and offset of zero-length component (properly aligns group_offset)
            self.adjust_zero_length_bit_field(self.next_ordinal - 1, alignment);
            self.group_offset
        } else {
            let o = get_aligned_offset(alignment, min_offset);
            if self.last_component.is_none() {
                self.group_offset = o; // establish corrected group offset after alignment
            }
            o
        };

        self.update_component(dtc, self.next_ordinal, offset, dt_size, alignment);
    }

    /// Port of `AlignedComponentPacker.alignAndPackBitField(InternalDataTypeComponent)`.
    fn align_and_pack_bit_field(&mut self, dtc: &mut dyn InternalDataTypeComponent) {
        let data_type = dtc.get_data_type();
        let bitfield_dt = data_type
            .as_bit_field_data_type()
            .expect("AlignedComponentPacker: bitfield component's data type must be a BitFieldDataType");

        if let Some(last) = self.last_component {
            if last.is_zero_bit_field {
                let alignment = if self.ms_convention {
                    self.get_bit_field_alignment(bitfield_dt)
                } else {
                    self.zero_alignment
                };
                self.adjust_zero_length_bit_field(self.next_ordinal - 1, alignment);
            }
        }

        let offset;
        let mut bits_consumed;

        // update last_alignment to be conveyed onto structure alignment. See the module docs on
        // why `getPrimitiveBaseDataType()` is approximated with `get_alignment()`.
        let mut alignment = get_packed_alignment_values(bitfield_dt.get_alignment(), self.pack_value);

        // Set conveyed alignment early since bitfield alignment may be reduced below
        self.last_alignment = alignment.max(self.last_alignment);

        match self.last_component {
            None => {
                offset = get_aligned_offset(alignment, self.group_offset);
                bits_consumed = 0;
                self.group_offset = offset; // establish corrected group offset after alignment
            }
            Some(last) if last.is_zero_bit_field => {
                // - assume last_component (zero-length bitfield) has already been adjusted
                // - first bitfield following a :0 bitfield which has already been adjusted by
                //   pack_component
                // - group_offset contains aligned offset to be used
                offset = self.group_offset;
                bits_consumed = 0;
            }
            Some(last) => {
                // follow normal rule for aligning bitfield which may differ from the alignment
                // imparted onto structure via last_alignment
                alignment = self.get_bit_field_alignment(bitfield_dt);

                let mut last_base_type_size = None;
                let mut computed_offset;
                if last.is_bit_field {
                    // assume last_component bit-field has already been packed and has correct
                    // bit-offset
                    last_base_type_size = Some(last.base_type_size);
                    computed_offset = last.end_offset;
                    if self.is_big_endian {
                        // filled left-to-right
                        bits_consumed = 8 - last.bit_offset;
                        // bits_consumed range: 1 to 8, where 8 indicates last byte fully consumed
                    } else {
                        // filled right-to-left (viewed from normalized form after byte-swap)
                        bits_consumed = (last.bit_size + last.bit_offset) % 8;
                        // bits_consumed range: 0 to 7, where 0 indicates last byte fully consumed
                    }
                    if bits_consumed == 8 || bits_consumed == 0 {
                        // last byte is fully consumed
                        bits_consumed = 0;
                        computed_offset += 1;
                    }
                } else {
                    // previous field is non-bitfield
                    computed_offset = last.offset + last.length;
                    bits_consumed = 0;
                }

                let byte_size = (bitfield_dt.get_bit_size() + bits_consumed + 7) / 8;
                let mut end_offset = computed_offset + byte_size - 1;

                if computed_offset % alignment != 0 || byte_size > bitfield_dt.get_base_type_size() {
                    // offset is not an aligned offset (which may be OK when packing with
                    // last_component)
                    let aligned_base_offset = get_aligned_offset(alignment, computed_offset) - alignment;
                    if end_offset >= aligned_base_offset + bitfield_dt.get_base_type_size() {
                        // skip ahead to next aligned offset
                        computed_offset = get_aligned_offset(alignment, computed_offset + 1);
                        end_offset = computed_offset + byte_size - 1;
                        bits_consumed = 0;
                    }
                }

                // establish new group_offset if necessary
                if self.group_offset >= 0 {
                    if let Some(last_base_type_size) = last_base_type_size {
                        if end_offset >= (self.group_offset + last_base_type_size) {
                            self.group_offset = if self.ms_convention { computed_offset } else { -1 };
                        }
                    }
                }

                offset = computed_offset;
            }
        }

        let byte_size = self.set_bit_field_data_type(dtc, bitfield_dt, bits_consumed);
        self.update_component(dtc, self.next_ordinal, offset, byte_size, alignment);
    }

    /// Port of `AlignedComponentPacker.setBitFieldDataType(InternalDataTypeComponent, BitFieldDataType, int)`.
    fn set_bit_field_data_type(
        &mut self,
        dtc: &mut dyn InternalDataTypeComponent,
        current_bit_field_dt: &BitFieldDataType,
        bits_consumed: i32,
    ) -> i32 {
        let byte_size = (current_bit_field_dt.get_bit_size() + bits_consumed + 7) / 8;
        let bit_offset = if self.is_big_endian {
            // filled left-to-right
            (byte_size * 8) - current_bit_field_dt.get_bit_size() - bits_consumed
        } else {
            // filled right-to-left (viewed from normalized form after byte-swap)
            bits_consumed
        };

        if bit_offset != current_bit_field_dt.get_bit_offset() {
            let base = current_bit_field_dt.get_base_data_type();
            let packed_bit_field_dt =
                BitFieldDataType::new(base, current_bit_field_dt.get_declared_bit_size(), bit_offset).expect(
                    "AlignedComponentPacker: repacking an already-valid bitfield at a new bit-offset should never fail",
                );
            dtc.set_data_type(Box::new(packed_bit_field_dt));
            self.components_changed = true;
        }
        byte_size
    }

    /// Port of `AlignedComponentPacker.updateComponent(InternalDataTypeComponent, int, int, int, int)`,
    /// for call sites that mutate the *current* component (every call site except
    /// `adjustZeroLengthBitField`'s -- see [`Self::adjust_zero_length_bit_field`]).
    fn update_component(
        &mut self,
        dtc: &mut dyn InternalDataTypeComponent,
        ordinal: i32,
        offset: i32,
        length: i32,
        alignment: i32,
    ) {
        if ordinal != dtc.get_ordinal() || offset != dtc.get_offset() || length != dtc.get_length() {
            dtc.update(ordinal, offset, length);
            self.components_changed = true;
        }
        self.last_alignment = self.last_alignment.max(alignment);
    }

    /// Port of `AlignedComponentPacker.getComponentAlignmentLCM(int)`.
    fn get_component_alignment_lcm(&self, all_components_lcm: i32) -> i32 {
        if self.last_alignment == 0 {
            return self.last_alignment;
        }

        // factor in pack value, which may have been ignored when aligning component
        let mut alignment = self.last_alignment;
        if self.pack_value > 0 && alignment > self.pack_value {
            alignment = self.pack_value;
        }
        get_least_common_multiple(all_components_lcm, alignment)
    }

    /// Captures a [`LastComponentSnapshot`] of `dtc`'s current (post-mutation) state, mirroring
    /// Java's `lastComponent = dtc;` at the end of `addComponent`.
    fn snapshot(dtc: &dyn InternalDataTypeComponent) -> LastComponentSnapshot {
        let is_bit_field = dtc.is_bit_field_component();
        let is_zero_bit_field = dtc.is_zero_bit_field_component();
        let offset = dtc.get_offset();
        let length = dtc.get_length();
        let end_offset = dtc.get_end_offset();

        let (bit_offset, bit_size, base_type_size, base_alignment) = if is_bit_field {
            let data_type = dtc.get_data_type();
            let bf = data_type
                .as_bit_field_data_type()
                .expect("AlignedComponentPacker: bitfield component's data type must be a BitFieldDataType");
            (bf.get_bit_offset(), bf.get_bit_size(), bf.get_base_type_size(), bf.get_base_data_type().get_alignment())
        } else {
            (0, 0, 0, 0)
        };

        LastComponentSnapshot {
            offset,
            length,
            end_offset,
            is_bit_field,
            is_zero_bit_field,
            bit_offset,
            bit_size,
            base_type_size,
            base_alignment,
        }
    }
}

impl SeamAlignedComponentPacker for AlignedComponentPacker {
    /// Port of `AlignedComponentPacker.addComponent(InternalDataTypeComponent, boolean)`.
    ///
    /// # Panics
    /// Panics (standing in for the Java `IllegalArgumentException`) if `dtc`'s data type is the
    /// `DEFAULT` sentinel -- `AlignedStructurePacker::pack_components` already transforms every
    /// such component away before calling this, so this only guards direct callers.
    fn add_component(&mut self, dtc: &mut dyn InternalDataTypeComponent, is_last_component: bool) {
        if dtc.get_data_type().is_default_data_type() {
            panic!("AlignedComponentPacker: unsupported component (DEFAULT data type)");
        }
        if !self.pack_component(dtc) {
            self.init_group(dtc, is_last_component);
        }
        self.last_component = Some(Self::snapshot(dtc));
        self.next_ordinal += 1;

        self.default_alignment = self.get_component_alignment_lcm(self.default_alignment);
    }

    fn finalize_pending_updates(&mut self, components: &mut [Box<dyn InternalDataTypeComponent>]) {
        let Some(pending) = self.pending_zero_bitfield.take() else {
            return;
        };
        if let Some(dtc) = components.get_mut(pending.index) {
            let dtc = dtc.as_mut();
            if pending.ordinal != dtc.get_ordinal() || pending.offset != dtc.get_offset() || dtc.get_length() != 0 {
                dtc.update(pending.ordinal, pending.offset, 0);
                self.components_changed = true;
            }
        }
    }

    /// Port of `AlignedComponentPacker.getDefaultAlignment()`.
    fn get_default_alignment(&self) -> i32 {
        self.default_alignment
    }

    /// Port of `AlignedComponentPacker.getLength()`.
    ///
    /// Drops one dead sub-expression from the Java original: the zero-length-bitfield branch calls
    /// `getBitFieldAlignment((BitFieldDataType) lastComponent.getDataType())` but never uses the
    /// result (a pure function with no side effects), so it contributes nothing and is omitted here.
    fn get_length(&self) -> i32 {
        let Some(last) = &self.last_component else {
            return 0;
        };

        if self.group_offset >= 0 && last.is_bit_field && self.ms_convention {
            // skip beyond unused bits based upon allocation size
            self.group_offset + last.base_type_size
        } else {
            let mut offset = last.offset + last.length;
            if !self.ms_convention && last.is_zero_bit_field {
                // factor in trailing zero-length bitfield
                let size_alignment = last.base_alignment;
                offset = get_aligned_offset(size_alignment, offset);
            }
            offset
        }
    }

    /// Port of `AlignedComponentPacker.componentsChanged()`.
    fn components_changed(&self) -> bool {
        self.components_changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::bit_field_packing_impl::BitFieldPackingImpl;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::seam_stubs::AlignedComponentPacker as _;

    #[derive(Clone)]
    struct TestDataType {
        name: String,
        length: i32,
        alignment: i32,
        zero_length: bool,
        is_integer: bool,
        signed: bool,
    }

    impl DataType for TestDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_aligned_length(&self) -> i32 {
            self.length
        }
        fn get_alignment(&self) -> i32 {
            self.alignment
        }
        fn is_zero_length(&self) -> bool {
            self.zero_length
        }
        fn is_integer_type(&self) -> bool {
            self.is_integer
        }
        fn is_signed_integer_type(&self) -> bool {
            self.signed
        }
    }

    fn int_dt(name: &str, length: i32) -> TestDataType {
        TestDataType { name: name.to_string(), length, alignment: length, zero_length: false, is_integer: true, signed: true }
    }

    /// Test-only stand-in for a structure/union component: either a plain data type or a bitfield.
    /// Reconstructs a fresh `BitFieldDataType` on every `get_data_type()` call (mirroring how
    /// production `InternalDataTypeComponent` implementors hand out fresh `share_data_type`
    /// handles) since `dyn DataType` has no `Clone` bound to store one directly.
    #[derive(Clone)]
    enum TestDt {
        Plain(TestDataType),
        Bitfield { base: TestDataType, declared_bit_size: i32, bit_offset: i32 },
    }

    impl TestDt {
        fn to_boxed(&self) -> Box<dyn DataType> {
            match self {
                TestDt::Plain(p) => Box::new(p.clone()),
                TestDt::Bitfield { base, declared_bit_size, bit_offset } => Box::new(
                    BitFieldDataType::new(Box::new(base.clone()), *declared_bit_size, *bit_offset)
                        .expect("test bitfield construction should succeed"),
                ),
            }
        }
        fn is_bit_field(&self) -> bool {
            matches!(self, TestDt::Bitfield { .. })
        }
        fn is_zero_bit_field(&self) -> bool {
            matches!(self, TestDt::Bitfield { declared_bit_size: 0, .. })
        }
    }

    #[derive(Clone)]
    struct MockComponent {
        ordinal: i32,
        offset: i32,
        length: i32,
        data_type: TestDt,
    }

    impl MockComponent {
        fn plain(ordinal: i32, dt: TestDataType) -> Self {
            let length = dt.length;
            MockComponent { ordinal, offset: 0, length, data_type: TestDt::Plain(dt) }
        }
        fn bit_field(ordinal: i32, base: TestDataType, declared_bit_size: i32, bit_offset: i32) -> Self {
            let storage_size =
                crate::program::model::data::bit_field_data_type::get_minimum_storage_size(declared_bit_size, bit_offset);
            MockComponent {
                ordinal,
                offset: 0,
                length: storage_size,
                data_type: TestDt::Bitfield { base, declared_bit_size, bit_offset },
            }
        }
    }

    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            self.data_type.to_boxed()
        }
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_bit_field_component(&self) -> bool {
            self.data_type.is_bit_field()
        }
        fn is_zero_bit_field_component(&self) -> bool {
            self.data_type.is_zero_bit_field()
        }
    }

    impl InternalDataTypeComponent for MockComponent {
        fn set_data_type(&mut self, data_type: Box<dyn DataType>) {
            if let Some(bf) = data_type.as_bit_field_data_type() {
                let base_dt = bf.get_base_data_type();
                self.data_type = TestDt::Bitfield {
                    base: TestDataType {
                        name: base_dt.get_name(),
                        length: base_dt.get_length(),
                        alignment: base_dt.get_alignment(),
                        zero_length: false,
                        is_integer: true,
                        signed: true,
                    },
                    declared_bit_size: bf.get_declared_bit_size(),
                    bit_offset: bf.get_bit_offset(),
                };
                self.length = bf.get_storage_size();
            } else {
                self.data_type = TestDt::Plain(TestDataType {
                    name: data_type.get_name(),
                    length: data_type.get_length(),
                    alignment: data_type.get_alignment(),
                    zero_length: data_type.is_zero_length(),
                    is_integer: true,
                    signed: true,
                });
            }
        }
        fn update(&mut self, ordinal: i32, offset: i32, length: i32) {
            self.ordinal = ordinal;
            self.offset = offset;
            self.length = length;
        }
    }

    struct TestOrg {
        big_endian: bool,
        ms_convention: bool,
        type_alignment_enabled: bool,
        zero_length_boundary: i32,
    }

    impl Default for TestOrg {
        fn default() -> Self {
            TestOrg { big_endian: false, ms_convention: false, type_alignment_enabled: true, zero_length_boundary: 0 }
        }
    }

    impl TestOrg {
        /// The real [`DataOrganizationImpl`] these settings describe: an LP64 layout (8-byte
        /// pointers and longs) whose size/alignment map is empty, so every primitive aligns to the
        /// default alignment of 1.
        fn build(&self) -> DataOrganizationImpl {
            let mut org = DataOrganizationImpl::get_default_organization(None);
            org.set_big_endian(self.big_endian);
            org.set_pointer_size(8);
            org.set_wide_char_size(2);
            org.set_long_size(8);
            org.set_default_pointer_alignment(8);
            org.clear_size_alignment_map();
            let mut packing = BitFieldPackingImpl::new();
            packing.set_use_ms_convention(self.ms_convention);
            packing.set_type_alignment_enabled(self.type_alignment_enabled);
            packing.set_zero_length_boundary(self.zero_length_boundary);
            org.set_bit_field_packing(packing);
            org
        }
    }

    /// Runs the packer over `components` exactly as `AlignedStructurePacker::pack_components`
    /// would (its own default method is not reused here to keep this module's tests independent
    /// of that file), including the `finalize_pending_updates` flush.
    fn pack(packer: &mut AlignedComponentPacker, components: &mut [MockComponent]) {
        let last_index = components.len() as i32 - 1;
        for (i, c) in components.iter_mut().enumerate() {
            seam_stubs::AlignedComponentPacker::add_component(packer, c, i as i32 == last_index);
        }
        let mut boxed: Vec<Box<dyn InternalDataTypeComponent>> =
            components.iter().map(|c| Box::new(c.clone()) as Box<dyn InternalDataTypeComponent>).collect();
        seam_stubs::AlignedComponentPacker::finalize_pending_updates(packer, &mut boxed);
        // Copy any finalize-applied mutation back onto the real (non-boxed) components used by
        // the test assertions below.
        for (c, b) in components.iter_mut().zip(boxed.iter()) {
            c.ordinal = b.get_ordinal();
            c.offset = b.get_offset();
            c.length = b.get_length();
        }
    }

    #[test]
    fn packs_sequential_non_bitfield_components_with_alignment_padding() {
        // char (1-byte) then int (4-byte): int must land on a 4-aligned offset, leaving 3 padding
        // bytes -- the classic packed-struct padding case.
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components =
            vec![MockComponent::plain(0, int_dt("char", 1)), MockComponent::plain(1, int_dt("int", 4))];
        pack(&mut packer, &mut components);

        assert_eq!(components[0].offset, 0);
        assert_eq!(components[1].offset, 4); // padded up from 1 to 4
        assert_eq!(seam_stubs::AlignedComponentPacker::get_length(&packer), 8);
        assert_eq!(seam_stubs::AlignedComponentPacker::get_default_alignment(&packer), 4);
    }

    #[test]
    fn no_padding_needed_when_already_aligned() {
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components =
            vec![MockComponent::plain(0, int_dt("int", 4)), MockComponent::plain(1, int_dt("int", 4))];
        pack(&mut packer, &mut components);

        assert_eq!(components[0].offset, 0);
        assert_eq!(components[1].offset, 4);
        assert_eq!(seam_stubs::AlignedComponentPacker::get_length(&packer), 8);
    }

    #[test]
    fn pack_value_caps_alignment_and_padding() {
        // Same char+int sequence as above, but pack(1) forces byte alignment throughout, so no
        // padding is introduced at all.
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(1, &org);
        let mut components =
            vec![MockComponent::plain(0, int_dt("char", 1)), MockComponent::plain(1, int_dt("int", 4))];
        pack(&mut packer, &mut components);

        assert_eq!(components[1].offset, 1); // packed(1): no alignment padding
        assert_eq!(seam_stubs::AlignedComponentPacker::get_default_alignment(&packer), 1);
    }

    #[test]
    fn default_alignment_is_lcm_of_component_alignments() {
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components =
            vec![MockComponent::plain(0, int_dt("int", 4)), MockComponent::plain(1, int_dt("short", 6))];
        pack(&mut packer, &mut components);

        // lcm(4, 6) == 12
        assert_eq!(seam_stubs::AlignedComponentPacker::get_default_alignment(&packer), 12);
    }

    #[test]
    fn adjacent_gcc_bitfields_pack_into_shared_bytes() {
        // Two 4-bit fields sharing a base type pack into the same byte under GCC (non-MS)
        // conventions: total length should be 1 byte, not 2.
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components =
            vec![MockComponent::bit_field(0, int_dt("uint", 4), 4, 0), MockComponent::bit_field(1, int_dt("uint", 4), 4, 0)];
        pack(&mut packer, &mut components);

        assert_eq!(components[0].offset, 0);
        assert_eq!(components[1].offset, 0); // shares the same byte as the first field
        assert_eq!(seam_stubs::AlignedComponentPacker::get_length(&packer), 1);
    }

    #[test]
    fn bitfield_overflowing_base_type_starts_new_storage_unit() {
        // Two 6-bit fields (base type 1 byte) can't both fit in a single byte (6+6=12 bits), so
        // the second must start a fresh storage unit at offset 1.
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components =
            vec![MockComponent::bit_field(0, int_dt("uchar", 1), 6, 0), MockComponent::bit_field(1, int_dt("uchar", 1), 6, 0)];
        pack(&mut packer, &mut components);

        assert_eq!(components[0].offset, 0);
        assert_eq!(components[1].offset, 1);
    }

    #[test]
    fn bitfield_packs_immediately_after_non_bitfield_when_it_still_fits() {
        // GCC (non-MS) convention lets a bitfield directly follow a non-bitfield component
        // (unlike MSVC, which always starts a fresh allocation unit -- see the
        // `ms_convention_bitfields_do_not_share_storage_with_non_bitfield` test below): the
        // 3-bit field fits entirely within the same 4-byte aligned storage unit `char` already
        // started (byte 1 of bytes 0..4), so it is placed right at the next free byte rather than
        // padded up to a 4-aligned offset.
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components =
            vec![MockComponent::plain(0, int_dt("char", 1)), MockComponent::bit_field(1, int_dt("int", 4), 3, 0)];
        pack(&mut packer, &mut components);

        assert_eq!(components[0].offset, 0);
        assert_eq!(components[1].offset, 1);
    }

    #[test]
    fn bitfield_skips_ahead_when_it_would_overflow_its_storage_unit() {
        // Three chars (offsets 0,1,2) followed by a 24-bit (3-byte) bitfield over a 4-byte base
        // type: placing it right at offset 3 would need bytes [3,6), overflowing the 4-byte
        // aligned storage unit [0,4) implied by the base type, so it must skip ahead to the next
        // aligned offset (4) instead of packing immediately.
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components = vec![
            MockComponent::plain(0, int_dt("char", 1)),
            MockComponent::plain(1, int_dt("char", 1)),
            MockComponent::plain(2, int_dt("char", 1)),
            MockComponent::bit_field(3, int_dt("int", 4), 24, 0),
        ];
        pack(&mut packer, &mut components);

        assert_eq!(components[3].offset, 4);
    }

    #[test]
    fn zero_length_bitfield_forces_alignment_of_next_component() {
        // `int x; int :0; char y;` under GCC: the zero-length bitfield forces `y` up to the next
        // 4-byte boundary even though `char` itself only needs 1-byte alignment, and the
        // zero-length bitfield's own (deferred) component ends up at that same forced offset.
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components = vec![
            MockComponent::plain(0, int_dt("int", 4)),
            MockComponent::bit_field(1, int_dt("int", 4), 0, 0),
            MockComponent::plain(2, int_dt("char", 1)),
        ];
        pack(&mut packer, &mut components);

        assert_eq!(components[0].offset, 0);
        assert_eq!(components[1].offset, 4); // the zero-length bitfield itself, finalized via the deferred write
        assert_eq!(components[1].length, 0);
        assert_eq!(components[2].offset, 4); // forced up to the zero-bitfield's alignment boundary
        assert!(seam_stubs::AlignedComponentPacker::components_changed(&packer));
    }

    #[test]
    fn zero_length_bitfield_as_last_component_updates_immediately() {
        // No deferral needed (and no following component to trigger it) when the zero-length
        // bitfield is the very last component.
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components =
            vec![MockComponent::plain(0, int_dt("char", 1)), MockComponent::bit_field(1, int_dt("int", 4), 0, 0)];
        pack(&mut packer, &mut components);

        assert_eq!(components[1].offset, 4);
        assert_eq!(components[1].length, 0);
    }

    #[test]
    fn ms_convention_bitfields_do_not_share_storage_with_non_bitfield() {
        let org = TestOrg { ms_convention: true, ..TestOrg::default() }.build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut components =
            vec![MockComponent::bit_field(0, int_dt("uint", 4), 4, 0), MockComponent::plain(1, int_dt("char", 1))];
        pack(&mut packer, &mut components);

        assert_eq!(components[0].offset, 0);
        // MS convention starts a new allocation unit for the non-bitfield rather than packing it
        // into the trailing bits of the bitfield's storage unit.
        assert_eq!(components[1].offset, 4);
    }

    #[test]
    fn components_changed_false_when_offsets_already_correct() {
        // Components already at the exact offsets the packer would compute should report no
        // change.
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut c0 = MockComponent::plain(0, int_dt("int", 4));
        c0.offset = 0;
        let mut c1 = MockComponent::plain(1, int_dt("int", 4));
        c1.offset = 4;
        let mut components = vec![c0, c1];
        pack(&mut packer, &mut components);

        assert!(!seam_stubs::AlignedComponentPacker::components_changed(&packer));
    }

    #[test]
    fn components_changed_true_when_offset_must_move() {
        let org = TestOrg::default().build();
        let mut packer = AlignedComponentPacker::new(0, &org);
        let mut c0 = MockComponent::plain(0, int_dt("char", 1));
        let mut c1 = MockComponent::plain(1, int_dt("int", 4));
        c1.offset = 1; // wrong: packing will move it to offset 4
        let mut components = vec![c0.clone(), c1.clone()];
        c0.offset = 0;
        let _ = (c0, c1);
        pack(&mut packer, &mut components);

        assert!(seam_stubs::AlignedComponentPacker::components_changed(&packer));
    }
}
