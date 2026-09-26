//! Port of `ghidra.program.model.pcode.PackedDecodeOverlay`.
//!
//! Alters address-space decoding for a specific overlay space: any decoded space that matches the
//! overlayed (underlying) space is replaced with the overlay itself, so that addresses decoded in
//! the underlying space's basic-address-space index slot come back as overlay addresses.
//!
//! The Java class `extends PackedDecode`. Since Rust has no implementation inheritance, this
//! struct composes a [`PackedDecode`] by value (a "has-a" in place of Java's "is-a", following the
//! `MappedDataEntry`-composes-`MappedEntry` precedent in this crate) and implements [`Decoder`] by
//! delegating every method straight through to it — Java's `PackedDecodeOverlay` does not override
//! any `Decoder`/`PackedDecode` method itself; its entire effect comes from mutating the inherited
//! protected `spaces` index table in its constructor/`setOverlay`, which is exactly what
//! [`PackedDecodeOverlay::set_overlay`] does here via the `pub(crate)` accessors added to
//! `PackedDecode` in `packed.rs` for this purpose
//! ([`PackedDecode::spaces_len`](crate::program::model::pcode::packed::PackedDecode::spaces_len),
//! [`PackedDecode::set_space_at`](crate::program::model::pcode::packed::PackedDecode::set_space_at)).
//! Those are new methods, not modifications to any existing `PackedDecode` method body.

use std::sync::{Arc, RwLock};

use super::decoder::{Decoder, DecoderError};
use super::ids::{AttributeId, ElementId};
use super::packed::PackedDecode;
use crate::program::model::address::{
    AddressFactory, AddressFormatException, AddressSpace, OverlayAddressSpace,
};

/// Port of `ghidra.program.model.pcode.PackedDecodeOverlay`.
pub struct PackedDecodeOverlay {
    inner: PackedDecode,
    overlay: RwLock<Option<OverlayAddressSpace>>,
}

impl PackedDecodeOverlay {
    /// Port of `PackedDecodeOverlay(AddressFactory, OverlayAddressSpace)`. Java's super
    /// constructor call is `super(addrFactory)` (no data yet - a separate `open()`/`ingestStream`
    /// step populates the buffer). This port instead requires `data` up front, following the same
    /// deviation this crate's [`PackedDecode::new`] already made from Java's several constructors
    /// (data-upfront ownership, documented on `PackedEncode`'s struct doc comment in `packed.rs`).
    ///
    /// # Errors
    /// Returns an [`AddressFormatException`] under the same condition Java's `setOverlay` does:
    /// the overlayed space's `unique` index is `0`, or falls outside the decoder's basic-address-
    /// space index table.
    pub fn new(
        addr_factory: Arc<dyn AddressFactory>,
        data: Vec<u8>,
        spc: OverlayAddressSpace,
    ) -> Result<Self, AddressFormatException> {
        let this = Self {
            inner: PackedDecode::new(addr_factory, data),
            overlay: RwLock::new(None),
        };
        this.set_overlay(spc)?;
        Ok(this)
    }

    /// Port of `PackedDecodeOverlay.setOverlay`. Takes `&self` (interior mutability via the
    /// `overlay` field's `RwLock`, matching the rest of this crate's `PackedDecode`, whose
    /// `Decoder` methods are likewise all `&self`) rather than `&mut self`, so a
    /// `PackedDecodeOverlay` can be reconfigured through a shared reference the same way
    /// `PackedDecode::set_address_factory` already is.
    ///
    /// # Errors
    /// Returns an [`AddressFormatException`] if the overlayed space's `unique` index is `0` or is
    /// out of range for the decoder's basic-address-space index table - faithfully reproducing the
    /// real Java restriction (index `0` is unconditionally rejected even though it is otherwise a
    /// valid table slot).
    pub fn set_overlay(&self, spc: OverlayAddressSpace) -> Result<(), AddressFormatException> {
        let mut overlay_guard = self.overlay.write().unwrap();
        if let Some(existing) = overlay_guard.as_ref() {
            let underlie = existing.overlayed_space();
            self.inner
                .set_space_at(underlie.unique() as usize, Some(underlie.clone()));
        }
        let underlie = spc.overlayed_space();
        let idx = underlie.unique();
        if idx == 0 || idx as usize >= self.inner.spaces_len() {
            return Err(AddressFormatException::new(format!(
                "Cannot set overlay over {}",
                underlie.name()
            )));
        }
        self.inner
            .set_space_at(idx as usize, Some(spc.address_space().clone()));
        *overlay_guard = Some(spc);
        Ok(())
    }
}

impl Decoder for PackedDecodeOverlay {
    fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
        self.inner.get_address_factory()
    }

    fn set_address_factory(&self, factory: Arc<dyn AddressFactory>) {
        self.inner.set_address_factory(factory)
    }

    fn peek_element(&self) -> Result<i32, DecoderError> {
        self.inner.peek_element()
    }

    fn open_element(&self) -> Result<i32, DecoderError> {
        self.inner.open_element()
    }

    fn open_element_with_id(&self, elem_id: ElementId) -> Result<i32, DecoderError> {
        self.inner.open_element_with_id(elem_id)
    }

    fn close_element(&self, id: i32) -> Result<(), DecoderError> {
        self.inner.close_element(id)
    }

    fn close_element_skipping(&self, id: i32) -> Result<(), DecoderError> {
        self.inner.close_element_skipping(id)
    }

    fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
        self.inner.get_next_attribute_id()
    }

    fn rewind_attributes(&self) {
        self.inner.rewind_attributes()
    }

    fn read_bool(&self) -> Result<bool, DecoderError> {
        self.inner.read_bool()
    }

    fn read_bool_with_id(&self, attrib_id: AttributeId) -> Result<bool, DecoderError> {
        self.inner.read_bool_with_id(attrib_id)
    }

    fn read_signed_integer(&self) -> Result<i64, DecoderError> {
        self.inner.read_signed_integer()
    }

    fn read_signed_integer_with_id(&self, attrib_id: AttributeId) -> Result<i64, DecoderError> {
        self.inner.read_signed_integer_with_id(attrib_id)
    }

    fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
        self.inner.read_unsigned_integer()
    }

    fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError> {
        self.inner.read_unsigned_integer_with_id(attrib_id)
    }

    fn read_string(&self) -> Result<String, DecoderError> {
        self.inner.read_string()
    }

    fn read_string_with_id(&self, attrib_id: AttributeId) -> Result<String, DecoderError> {
        self.inner.read_string_with_id(attrib_id)
    }

    fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
        self.inner.read_space()
    }

    fn read_space_with_id(
        &self,
        attrib_id: AttributeId,
    ) -> Result<Arc<AddressSpace>, DecoderError> {
        self.inner.read_space_with_id(attrib_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::pcode::ids::{ATTRIB_SPACE, ATTRIB_VAL, ELEM_DATA};
    use crate::program::model::pcode::{Encoder, PackedEncode};

    fn overlay_over(underlie: &Arc<AddressSpace>, unique: i32) -> OverlayAddressSpace {
        OverlayAddressSpace::new(
            "ov",
            underlie.clone(),
            unique,
            "ov",
            AddressSet::new(),
        )
    }

    /// The single most valuable test for this file: decode a basic-address-space index that
    /// refers to the underlying (overlayed) space's `unique` slot, and confirm it resolves to the
    /// overlay space's own `AddressSpace` once `set_overlay` has redirected that slot - a genuine
    /// override behavior, not a passthrough.
    #[test]
    fn decoded_space_resolves_to_overlay_after_set_overlay() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let factory = Arc::new(DefaultAddressFactory::with_default_space(
            vec![ram.clone()],
            Some(ram.clone()),
        ));
        let overlay = overlay_over(&ram, 9);

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        // Encode a reference to the *underlying* ram space by its basic-address-space index.
        encoder.write_space(ATTRIB_SPACE, &ram).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecodeOverlay::new(factory, bytes, overlay).unwrap();
        let id = decoder.open_element().unwrap();
        let decoded = decoder.read_space_with_id(ATTRIB_SPACE).unwrap();
        assert_eq!(decoded.name(), "ov");
        decoder.close_element(id).unwrap();
    }

    /// Before `set_overlay` succeeds (i.e. plain `PackedDecode` behavior, exercised through the
    /// inner decoder directly), the same index resolves to the real underlying space.
    #[test]
    fn plain_packed_decode_resolves_underlying_space_without_overlay() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let factory = Arc::new(DefaultAddressFactory::with_default_space(
            vec![ram.clone()],
            Some(ram.clone()),
        ));

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_space(ATTRIB_SPACE, &ram).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecode::new(factory, bytes);
        let id = decoder.open_element().unwrap();
        let decoded = decoder.read_space_with_id(ATTRIB_SPACE).unwrap();
        assert_eq!(decoded.name(), "ram");
        decoder.close_element(id).unwrap();
    }

    /// Calling `set_overlay` again with a new overlay restores the previous overlay's slot back to
    /// the real underlying space before installing the new one - mirrors the `if (overlay != null)`
    /// restoration branch in Java's `setOverlay`.
    #[test]
    fn set_overlay_again_restores_previous_slot_first() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let other = AddressSpace::new("other_ov", 32, 1, AddressSpaceType::Ram, 5);
        let factory = Arc::new(DefaultAddressFactory::with_default_space(
            vec![ram.clone(), other.clone()],
            Some(ram.clone()),
        ));
        let overlay_a = overlay_over(&ram, 9);
        let overlay_b = overlay_over(&ram, 10);

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_space(ATTRIB_SPACE, &ram).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecodeOverlay::new(factory, bytes.clone(), overlay_a).unwrap();
        decoder.set_overlay(overlay_b).unwrap();

        let id = decoder.open_element().unwrap();
        let decoded = decoder.read_space_with_id(ATTRIB_SPACE).unwrap();
        // The second overlay is the one now installed over `ram`'s slot.
        assert_eq!(decoded.unique(), 10);
        decoder.close_element(id).unwrap();
    }

    #[test]
    fn set_overlay_over_index_zero_is_rejected() {
        let zero_space = AddressSpace::new("zero", 32, 1, AddressSpaceType::Ram, 0);
        let factory = Arc::new(DefaultAddressFactory::with_default_space(
            vec![zero_space.clone()],
            Some(zero_space.clone()),
        ));
        let overlay = overlay_over(&zero_space, 9);

        let result = PackedDecodeOverlay::new(factory, Vec::new(), overlay);
        assert!(result.is_err());
    }

    #[test]
    fn set_overlay_out_of_range_index_is_rejected() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let factory = Arc::new(DefaultAddressFactory::with_default_space(
            vec![ram.clone()],
            Some(ram.clone()),
        ));
        // `far_away` is never registered with the factory, so its `unique` index (99) is out of
        // range for the decoder's basic-address-space index table.
        let far_away = AddressSpace::new("far_away", 32, 1, AddressSpaceType::Ram, 99);
        let overlay = overlay_over(&far_away, 9);

        let result = PackedDecodeOverlay::new(factory, Vec::new(), overlay);
        assert!(result.is_err());
    }

    /// Passthrough sanity check: everything besides address-space resolution behaves exactly like
    /// plain `PackedDecode` (string/int attribute round trip), confirming the `Decoder`
    /// delegation is complete and correct.
    #[test]
    fn non_space_decoding_is_unaffected_by_overlay() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let factory = Arc::new(DefaultAddressFactory::with_default_space(
            vec![ram.clone()],
            Some(ram.clone()),
        ));
        let overlay = overlay_over(&ram, 9);

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_signed_integer(ATTRIB_VAL, -99).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecodeOverlay::new(factory, bytes, overlay).unwrap();
        let id = decoder.open_element().unwrap();
        assert_eq!(decoder.read_signed_integer_with_id(ATTRIB_VAL).unwrap(), -99);
        decoder.close_element(id).unwrap();
    }
}
