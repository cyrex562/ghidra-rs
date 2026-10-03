//! Port of `ghidra.program.model.pcode.PackedEncodeOverlay`.
//!
//! Alters address-space encoding for a specific overlay space: any space that matches the overlay
//! space is encoded as the overlayed (underlying) space instead, so addresses in the overlay space
//! get converted into the underlying space on the wire.
//!
//! The Java class `extends PatchPackedEncode`. Since Rust has no implementation inheritance, this
//! struct composes a [`PatchPackedEncode`] by value (a "has-a" in place of Java's "is-a",
//! following the `MappedDataEntry`-composes-`MappedEntry` precedent in this crate) and delegates
//! every [`Encoder`]/[`CachedEncoder`]/[`PatchEncoder`] member Java inherits unchanged straight
//! through to it, mirroring `super.foo()` for the members `PackedEncodeOverlay` does not itself
//! override. Only [`write_space`](Encoder::write_space) and
//! [`write_space_id`](PatchEncoder::write_space_id) (which Java fully overrides, each falling back
//! to `super.foo()` after possibly substituting the underlying space/id) have real bodies here.

use std::io;

use super::patch_packed_encode::PatchPackedEncode;
use super::{AttributeId, CachedEncoder, ElementId, Encoder, PatchEncoder};
use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::address::{AddressFormatException, AddressSpace, OverlayAddressSpace};

/// Port of `ghidra.program.model.pcode.PackedEncodeOverlay`.
pub struct PackedEncodeOverlay {
    inner: PatchPackedEncode,
    overlay: Option<OverlayAddressSpace>,
    /// Id of the overlay space.
    overlay_id: i32,
    /// Id of the space underlying the overlay.
    underlying_id: i32,
}

impl PackedEncodeOverlay {
    /// Port of `PackedEncodeOverlay(OverlayAddressSpace)`.
    ///
    /// # Errors
    /// Returns an [`AddressFormatException`] under the same condition Java's `setOverlay` does:
    /// the underlying space's `unique` index is `0`.
    pub fn new(spc: OverlayAddressSpace) -> Result<Self, AddressFormatException> {
        let mut this = Self {
            inner: PatchPackedEncode::new(),
            overlay: None,
            overlay_id: 0,
            underlying_id: 0,
        };
        this.set_overlay(spc)?;
        Ok(this)
    }

    /// Port of `PackedEncodeOverlay.setOverlay`.
    ///
    /// # Errors
    /// Returns an [`AddressFormatException`] if the underlying space's `unique` index is `0` -
    /// faithfully reproducing the real Java restriction.
    pub fn set_overlay(&mut self, spc: OverlayAddressSpace) -> Result<(), AddressFormatException> {
        self.overlay_id = spc.address_space().unique();
        let underlie = spc.overlayed_space();
        self.underlying_id = underlie.unique();
        if self.underlying_id == 0 {
            return Err(AddressFormatException::new(format!(
                "Cannot set overlay over {}",
                underlie.name()
            )));
        }
        self.overlay = Some(spc);
        Ok(())
    }
}

impl Encoder for PackedEncodeOverlay {
    fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
        self.inner.open_element(elem_id)
    }

    fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
        self.inner.close_element(elem_id)
    }

    fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
        self.inner.write_bool(attrib_id, val)
    }

    fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
        self.inner.write_signed_integer(attrib_id, val)
    }

    fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
        self.inner.write_unsigned_integer(attrib_id, val)
    }

    fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
        self.inner.write_string(attrib_id, val)
    }

    fn write_string_indexed(
        &mut self,
        attrib_id: AttributeId,
        index: i32,
        val: &str,
    ) -> io::Result<()> {
        self.inner.write_string_indexed(attrib_id, index, val)
    }

    /// Port of `PackedEncodeOverlay.writeSpace`. If `spc` is the overlay space this instance was
    /// configured with, substitutes the underlying (overlayed) space before delegating - matching
    /// Java's `spc == overlay` reference-equality check via [`AddressSpace`]'s value-based
    /// `PartialEq` (`space_id` + `name`), the closest faithful stand-in this crate has without an
    /// interned/identity-comparable `AddressSpace` type.
    fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
        let is_overlay = self
            .overlay
            .as_ref()
            .map(|o| o.address_space().as_ref() == spc)
            .unwrap_or(false);
        if is_overlay {
            let underlying = self.overlay.as_ref().unwrap().overlayed_space().clone();
            return self.inner.write_space(attrib_id, &underlying);
        }
        self.inner.write_space(attrib_id, spc)
    }

    fn write_space_indexed(
        &mut self,
        attrib_id: AttributeId,
        index: i32,
        name: &str,
    ) -> io::Result<()> {
        self.inner.write_space_indexed(attrib_id, index, name)
    }

    fn write_opcode(&mut self, attrib_id: AttributeId, opcode: OpCode) -> io::Result<()> {
        self.inner.write_opcode(attrib_id, opcode)
    }

    fn write_opcode_ordinal(&mut self, attrib_id: AttributeId, opcode: i32) -> io::Result<()> {
        self.inner.write_opcode_ordinal(attrib_id, opcode)
    }
}

impl CachedEncoder for PackedEncodeOverlay {
    fn clear(&mut self) {
        self.inner.clear()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn write_to(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        self.inner.write_to(writer)
    }
}

impl PatchEncoder for PackedEncodeOverlay {
    /// Port of `PackedEncodeOverlay.writeSpaceId`. If `space_id` is the overlay space's id,
    /// substitutes the underlying space's id before delegating.
    fn write_space_id(&mut self, attrib_id: AttributeId, space_id: i64) -> io::Result<()> {
        let space_id = if space_id == self.overlay_id as i64 {
            self.underlying_id as i64
        } else {
            space_id
        };
        self.inner.write_space_id(attrib_id, space_id)
    }

    fn size(&self) -> i32 {
        self.inner.size()
    }

    fn patch_integer_attribute(&mut self, pos: i32, attrib_id: AttributeId, val: i64) -> bool {
        self.inner.patch_integer_attribute(pos, attrib_id, val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        AddressSet, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::pcode::ids::{ATTRIB_SPACE, ATTRIB_VAL, ELEM_DATA};
    use crate::program::model::pcode::{Decoder, PackedDecode};
    use std::sync::Arc;

    fn overlay_over(underlie: &Arc<AddressSpace>, unique: i32) -> OverlayAddressSpace {
        OverlayAddressSpace::new("ov", underlie.clone(), unique, "ov", AddressSet::new())
    }

    /// The single most valuable test for this file: encoding the overlay space itself must
    /// produce exactly the same bytes as encoding the underlying space directly, and those bytes
    /// must decode back to the underlying space's basic-address-space index - proving the
    /// substitution actually happens on the wire, not just in memory.
    #[test]
    fn write_space_substitutes_underlying_space_for_overlay() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let overlay = overlay_over(&ram, 9);
        let overlay_space = overlay.address_space().clone();

        let mut encoder = PackedEncodeOverlay::new(overlay).unwrap();
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_space(ATTRIB_SPACE, &overlay_space).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        let mut bytes = Vec::new();
        encoder.write_to(&mut bytes).unwrap();

        let mut expected_encoder = PatchPackedEncode::new();
        expected_encoder.open_element(ELEM_DATA).unwrap();
        expected_encoder.write_space(ATTRIB_SPACE, &ram).unwrap();
        expected_encoder.close_element(ELEM_DATA).unwrap();
        let mut expected_bytes = Vec::new();
        expected_encoder.write_to(&mut expected_bytes).unwrap();

        assert_eq!(bytes, expected_bytes);

        let factory = Arc::new(DefaultAddressFactory::with_default_space(
            vec![ram.clone()],
            Some(ram.clone()),
        ));
        let decoder = PackedDecode::new(factory, bytes);
        let id = decoder.open_element().unwrap();
        assert_eq!(decoder.read_space_with_id(ATTRIB_SPACE).unwrap().name(), "ram");
        decoder.close_element(id).unwrap();
    }

    /// A space that is neither the overlay nor otherwise special encodes unchanged.
    #[test]
    fn write_space_passes_through_unrelated_space() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let other = AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 2);
        let overlay = overlay_over(&ram, 9);

        let mut encoder = PackedEncodeOverlay::new(overlay).unwrap();
        encoder.write_space(ATTRIB_SPACE, &other).unwrap();
        let mut bytes = Vec::new();
        encoder.write_to(&mut bytes).unwrap();

        let mut expected_encoder = PatchPackedEncode::new();
        expected_encoder.write_space(ATTRIB_SPACE, &other).unwrap();
        let mut expected_bytes = Vec::new();
        expected_encoder.write_to(&mut expected_bytes).unwrap();

        assert_eq!(bytes, expected_bytes);
    }

    /// `write_space_id` substitutes the overlay's id for the underlying id, and passes through any
    /// other id unchanged.
    #[test]
    fn write_space_id_substitutes_overlay_id() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let overlay = overlay_over(&ram, 9);
        let overlay_id = overlay.address_space().unique() as i64;

        let mut encoder = PackedEncodeOverlay::new(overlay).unwrap();
        encoder.write_space_id(ATTRIB_VAL, overlay_id).unwrap();
        let mut bytes = Vec::new();
        encoder.write_to(&mut bytes).unwrap();

        let mut expected_encoder = PatchPackedEncode::new();
        expected_encoder
            .write_space_id(ATTRIB_VAL, ram.unique() as i64)
            .unwrap();
        let mut expected_bytes = Vec::new();
        expected_encoder.write_to(&mut expected_bytes).unwrap();

        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn write_space_id_passes_through_unrelated_id() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let overlay = overlay_over(&ram, 9);

        let mut encoder = PackedEncodeOverlay::new(overlay).unwrap();
        encoder.write_space_id(ATTRIB_VAL, 4242).unwrap();
        let mut bytes = Vec::new();
        encoder.write_to(&mut bytes).unwrap();

        let mut expected_encoder = PatchPackedEncode::new();
        expected_encoder.write_space_id(ATTRIB_VAL, 4242).unwrap();
        let mut expected_bytes = Vec::new();
        expected_encoder.write_to(&mut expected_bytes).unwrap();

        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn new_over_index_zero_underlying_is_rejected() {
        let zero_space = AddressSpace::new("zero", 32, 1, AddressSpaceType::Ram, 0);
        let overlay = overlay_over(&zero_space, 9);
        assert!(PackedEncodeOverlay::new(overlay).is_err());
    }

    /// `PackedEncodeOverlay` composes `PatchPackedEncode`, so `patch_integer_attribute` (an
    /// unmodified passthrough) must still work through it end to end.
    #[test]
    fn patch_integer_attribute_passes_through() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let overlay = overlay_over(&ram, 9);

        let mut encoder = PackedEncodeOverlay::new(overlay).unwrap();
        let pos = encoder.size();
        encoder.open_element(ELEM_DATA).unwrap();
        encoder
            .write_unsigned_integer(ATTRIB_VAL, 0xffff_ffff_ffff_ffff)
            .unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        assert!(encoder.patch_integer_attribute(pos, ATTRIB_VAL, 777));

        let mut bytes = Vec::new();
        encoder.write_to(&mut bytes).unwrap();
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, bytes);
        let id = decoder.open_element().unwrap();
        assert_eq!(decoder.read_unsigned_integer_with_id(ATTRIB_VAL).unwrap(), 777);
        decoder.close_element(id).unwrap();
    }
}
