//! Port of `ghidra.program.model.pcode.PatchPackedEncode`.
//!
//! An [`Encoder`] whose already-written bytes can be retroactively patched: a caller records a
//! byte position (via [`PatchEncoder::size`]) right before opening an element, writes the element
//! and its attributes (one of which is an integer written with a placeholder value that happens
//! to force the full 10-byte/70-bit wire encoding — see [`patch_integer_attribute`]'s doc comment
//! for why that matters), and can later revisit that recorded position to overwrite just the
//! integer's payload bytes in place.
//!
//! The Java class `extends PackedEncode implements PatchEncoder`. Since Rust has no
//! implementation inheritance, this struct composes a
//! [`PackedEncode<PackedBytes>`](crate::program::model::pcode::packed::PackedEncode) by value (a
//! "has-a" in place of Java's "is-a", following the `MappedDataEntry`-composes-`MappedEntry`
//! precedent in this crate) and delegates every [`Encoder`] method Java inherits unchanged
//! straight through to it, mirroring `super.foo()` for the members `PatchPackedEncode` does not
//! itself override.
//!
//! Java's `PatchPackedEncode()` constructor leaves `editStream` (and thus `outStream`, the field
//! `PackedEncode.writeHeader`/`writeInteger` write through) `null` until `clear()` is called;
//! calling any write method before `clear()` would throw a `NullPointerException`. This port
//! instead follows the same deviation `PackedEncode` itself already made (see that struct's doc
//! comment in `packed.rs`): [`PatchPackedEncode::new`] eagerly creates a real, immediately-usable
//! `PackedBytes(512)`-backed buffer rather than modeling a "null until cleared" state, since Rust
//! has no ergonomic non-`Option` way to represent "not yet initialized" and every real caller of
//! `CachedEncoder`/`PatchEncoder` is expected to be able to write immediately (per
//! `CachedEncoder::clear`'s own doc comment: "The encoder should be ready to write a new document
//! after this call" — i.e. it is *not* a precondition for being ready to write at all).
//!
//! `writeHeader`/`writeInteger` are `PackedEncode`'s own (originally private) helper methods,
//! reached here via `pub(crate)` visibility added to `packed.rs` for exactly this purpose (see the
//! doc comments on [`PackedEncode::write_header`](crate::program::model::pcode::packed::PackedEncode::write_header)
//! and [`PackedEncode::write_integer`](crate::program::model::pcode::packed::PackedEncode::write_integer)) —
//! this is the only change made to `PackedEncode`'s existing methods, and it is visibility-only;
//! no method body was altered.

use std::io;

use super::packed::{
    PackedEncode, ATTRIBUTE, ELEMENTID_MASK, ELEMENT_START, HEADEREXTEND_MASK, HEADER_MASK,
    LENGTHCODE_MASK, RAWDATA_BITSPERBYTE, RAWDATA_MARKER, RAWDATA_MASK, TYPECODE_ADDRESSSPACE,
    TYPECODE_BOOLEAN, TYPECODE_SHIFT, TYPECODE_SPECIALSPACE, TYPECODE_STRING,
};
use super::packed_bytes::PackedBytes;
use super::{AttributeId, CachedEncoder, ElementId, Encoder, PatchEncoder};
use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::address::AddressSpace;

/// Port of `AddressSpace.ID_UNIQUE_SHIFT`. Used by [`PatchPackedEncode::write_space_id`] to
/// recover a space's `unique` index from its packed `spaceId`, the same way
/// [`AddressSpace::new`](crate::program::model::address::AddressSpace::new) packs `unique` into
/// `space_id`'s upper bits (`(unique << 7) | (logsize << 4) | space_type`) when constructing one.
const ID_UNIQUE_SHIFT: i32 = 7;

/// Port of `ghidra.program.model.pcode.PatchPackedEncode`. See the module doc comment for the
/// composition strategy and the `new()`/`clear()` deviation from Java's "null until cleared"
/// constructor.
pub struct PatchPackedEncode {
    inner: PackedEncode<PackedBytes>,
}

impl Default for PatchPackedEncode {
    fn default() -> Self {
        Self::new()
    }
}

impl PatchPackedEncode {
    /// Port of `PatchPackedEncode()`, with the eager-initialization deviation documented in the
    /// module doc comment.
    pub fn new() -> Self {
        Self {
            inner: PackedEncode::new(PackedBytes::new(512)),
        }
    }

    /// Port of `PatchPackedEncode.skipOpen`. Returns the position just after the open-element
    /// directive at `pos`, or `None` if the byte at `pos` is not an open-element header (matching
    /// Java's `-1` sentinel).
    fn skip_open(&self, pos: usize) -> Option<usize> {
        let stream = self.inner.output_stream_ref();
        let val = stream.get_byte(pos) & (HEADER_MASK | HEADEREXTEND_MASK);
        if val == ELEMENT_START {
            Some(pos + 1)
        } else if val == (ELEMENT_START | HEADEREXTEND_MASK) {
            Some(pos + 2)
        } else {
            None
        }
    }

    /// Port of `PatchPackedEncode.readInteger`. Reads a `len`-byte (7-bit-per-byte) big-endian
    /// integer starting at `pos` directly out of the already-written buffer.
    fn read_integer(&self, pos: usize, len: usize) -> u64 {
        let stream = self.inner.output_stream_ref();
        let mut res: u64 = 0;
        for i in 0..len {
            res <<= RAWDATA_BITSPERBYTE;
            res |= (stream.get_byte(pos + i) & RAWDATA_MASK) as u64;
        }
        res
    }
}

impl Encoder for PatchPackedEncode {
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

    fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
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

impl CachedEncoder for PatchPackedEncode {
    /// Port of `PatchPackedEncode.clear`. Java replaces `editStream` with a fresh
    /// `new PackedBytes(512)` and repoints `outStream` at it; this composing port does the
    /// equivalent by replacing the whole inner `PackedEncode<PackedBytes>`.
    fn clear(&mut self) {
        self.inner = PackedEncode::new(PackedBytes::new(512));
    }

    /// Port of `PatchPackedEncode.isEmpty`.
    fn is_empty(&self) -> bool {
        self.inner.output_stream_ref().size() == 0
    }

    /// Port of `PatchPackedEncode.writeTo`.
    fn write_to(&self, writer: &mut dyn io::Write) -> io::Result<()> {
        self.inner.output_stream_ref().write_to(writer)
    }
}

impl PatchEncoder for PatchPackedEncode {
    /// Port of `PatchPackedEncode.writeSpaceId`.
    fn write_space_id(&mut self, attrib_id: AttributeId, space_id: i64) -> io::Result<()> {
        self.inner.write_header(ATTRIBUTE, attrib_id.id)?;
        // Java: `int uniqueId = (int) spaceId >> AddressSpace.ID_UNIQUE_SHIFT;` - narrows to
        // `int` first (truncating), then does a signed right shift by 7.
        let unique_id = ((space_id as i32) >> ID_UNIQUE_SHIFT) as i64;
        self.inner
            .write_integer(TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT, unique_id as u64)
    }

    /// Port of `PatchPackedEncode.size`.
    fn size(&self) -> i32 {
        self.inner.output_stream_ref().size() as i32
    }

    /// Port of `PatchPackedEncode.patchIntegerAttribute`.
    ///
    /// Faithfully reproduces a real Java quirk: the replacement `val` is written as the raw
    /// 64-bit two's-complement bit pattern split into ten 7-bit pieces (`(val >>> sa) & 0x7f`
    /// for `sa` from 63 down to 0), exactly like [`PackedEncode::write_integer`]'s own length-10
    /// branch — but *without* first going through [`Encoder::write_signed_integer`]'s
    /// negative-value transform (negate to a magnitude, tag the attribute `SIGNEDINT_NEGATIVE`).
    /// So patching a `SIGNEDINT_NEGATIVE`-tagged attribute (the only realistic way to reach the
    /// length-10 branch for an originally-negative value, since only `i64::MIN`'s magnitude sets
    /// the top bit) with a negative `val` does *not* round-trip back to `val`: the decoder still
    /// applies `wrapping_neg` on read (because the type byte, which only encodes
    /// POSITIVE/NEGATIVE/UNSIGNED and is untouched by patching, still says NEGATIVE), so a patched
    /// `val = -5` decodes back as `+5`. See
    /// `patch_integer_attribute_on_negative_type_does_not_negate_replacement` below for a test
    /// proving this. Patching an `UNSIGNED`-tagged attribute has no such surprise, since
    /// `read_unsigned_integer` never negates.
    fn patch_integer_attribute(&mut self, pos: i32, attrib_id: AttributeId, val: i64) -> bool {
        let Some(mut pos) = self.skip_open(pos as usize) else {
            return false;
        };
        let length: usize;
        loop {
            let header1 = self.inner.output_stream_ref().get_byte(pos);
            if (header1 & HEADER_MASK) != ATTRIBUTE {
                return false;
            }
            pos += 1;
            let mut curid = (header1 & ELEMENTID_MASK) as i32;
            if (header1 & HEADEREXTEND_MASK) != 0 {
                curid <<= RAWDATA_BITSPERBYTE;
                curid |= (self.inner.output_stream_ref().get_byte(pos) & RAWDATA_MASK) as i32;
                pos += 1;
            }
            let type_byte = self.inner.output_stream_ref().get_byte(pos);
            pos += 1;
            let attrib_type = type_byte >> TYPECODE_SHIFT;
            if attrib_type == TYPECODE_BOOLEAN || attrib_type == TYPECODE_SPECIALSPACE {
                continue; // has no additional data
            }
            let mut len = (type_byte & LENGTHCODE_MASK) as usize;
            if attrib_type == TYPECODE_STRING {
                len = self.read_integer(pos, len) as usize;
            }
            if attrib_id.id == curid {
                length = len;
                break;
            }
            pos += len; // Skip -length- data
        }
        if length != 10 {
            return false;
        }

        let mut sa: i32 = 9 * RAWDATA_BITSPERBYTE as i32;
        while sa >= 0 {
            let piece = (((val as u64) >> sa) & (RAWDATA_MASK as u64)) as u8 | RAWDATA_MARKER;
            // `insert_byte` (like Java's `PackedBytes.insertByte`) overwrites an already-written
            // byte in place; despite the name, it does not shift/insert.
            self.inner.output_stream().insert_byte(pos, piece);
            pos += 1;
            sa -= RAWDATA_BITSPERBYTE as i32;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::pcode::ids::{ATTRIB_SPACE, ATTRIB_VAL, ELEM_DATA};
    use crate::program::model::pcode::{Decoder, PackedDecode};
    use std::sync::Arc;

    /// The single most valuable test for this file: encode an unsigned integer forced into the
    /// full 10-byte wire encoding (a real precondition of `patch_integer_attribute`, not an
    /// artificial one - see its doc comment), confirm it decodes to the original value, then
    /// patch it to a different value at the recorded position and confirm the *new* value is what
    /// decodes out afterward.
    #[test]
    fn patch_integer_attribute_round_trip_changes_decoded_value() {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));

        let mut encoder = PatchPackedEncode::new();
        let pos = encoder.size();
        encoder.open_element(ELEM_DATA).unwrap();
        // Top bit set forces PackedEncode::write_integer's length-10 branch.
        encoder
            .write_unsigned_integer(ATTRIB_VAL, 0xffff_ffff_ffff_ffff)
            .unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        let mut bytes = Vec::new();
        encoder.write_to(&mut bytes).unwrap();
        let decoder = PackedDecode::new(factory.clone(), bytes);
        let id = decoder.open_element().unwrap();
        assert_eq!(
            decoder.read_unsigned_integer_with_id(ATTRIB_VAL).unwrap(),
            0xffff_ffff_ffff_ffff
        );
        decoder.close_element(id).unwrap();

        assert!(encoder.patch_integer_attribute(pos, ATTRIB_VAL, 12345));

        let mut patched_bytes = Vec::new();
        encoder.write_to(&mut patched_bytes).unwrap();
        let decoder = PackedDecode::new(factory, patched_bytes);
        let id = decoder.open_element().unwrap();
        assert_eq!(
            decoder.read_unsigned_integer_with_id(ATTRIB_VAL).unwrap(),
            12345
        );
        decoder.close_element(id).unwrap();
    }

    /// Documents the sign-transform quirk described on `patch_integer_attribute`'s doc comment: a
    /// `SIGNEDINT_NEGATIVE`-tagged attribute patched with a negative `val` does not decode back to
    /// `val`, because patching writes `val`'s raw bit pattern directly while the decoder still
    /// applies `wrapping_neg` (driven by the untouched NEGATIVE type byte).
    #[test]
    fn patch_integer_attribute_on_negative_type_does_not_negate_replacement() {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));

        let mut encoder = PatchPackedEncode::new();
        let pos = encoder.size();
        encoder.open_element(ELEM_DATA).unwrap();
        // i64::MIN is the only signed value whose magnitude sets the top bit, forcing length 10.
        encoder.write_signed_integer(ATTRIB_VAL, i64::MIN).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        assert!(encoder.patch_integer_attribute(pos, ATTRIB_VAL, -5));

        let mut bytes = Vec::new();
        encoder.write_to(&mut bytes).unwrap();
        let decoder = PackedDecode::new(factory, bytes);
        let id = decoder.open_element().unwrap();
        // Not -5: the raw bits of -5 get reinterpreted through the NEGATIVE type's wrapping_neg.
        assert_eq!(decoder.read_signed_integer_with_id(ATTRIB_VAL).unwrap(), 5);
        decoder.close_element(id).unwrap();
    }

    #[test]
    fn patch_integer_attribute_rejects_short_encoding() {
        // A small value doesn't reach the length-10 branch, so patching must fail rather than
        // corrupt adjacent bytes.
        let mut encoder = PatchPackedEncode::new();
        let pos = encoder.size();
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_signed_integer(ATTRIB_VAL, 42).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        assert!(!encoder.patch_integer_attribute(pos, ATTRIB_VAL, 999));
    }

    #[test]
    fn patch_integer_attribute_rejects_missing_attribute() {
        let mut encoder = PatchPackedEncode::new();
        let pos = encoder.size();
        encoder.open_element(ELEM_DATA).unwrap();
        encoder
            .write_unsigned_integer(ATTRIB_VAL, 0xffff_ffff_ffff_ffff)
            .unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        // ATTRIB_SPACE was never written, so the scan runs off the end of the attribute list.
        assert!(!encoder.patch_integer_attribute(pos, ATTRIB_SPACE, 1));
    }

    #[test]
    fn patch_integer_attribute_rejects_non_open_position() {
        let mut encoder = PatchPackedEncode::new();
        encoder.open_element(ELEM_DATA).unwrap();
        // `pos` here is mid-element, not at an open directive.
        let pos = encoder.size();
        encoder
            .write_unsigned_integer(ATTRIB_VAL, 0xffff_ffff_ffff_ffff)
            .unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        assert!(!encoder.patch_integer_attribute(pos, ATTRIB_VAL, 1));
    }

    #[test]
    fn clear_resets_to_empty() {
        let mut encoder = PatchPackedEncode::new();
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_bool(ATTRIB_VAL, true).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        assert!(!encoder.is_empty());

        encoder.clear();
        assert!(encoder.is_empty());
        assert_eq!(encoder.size(), 0);
    }

    #[test]
    fn is_empty_reflects_written_bytes() {
        let mut encoder = PatchPackedEncode::new();
        assert!(encoder.is_empty());
        encoder.open_element(ELEM_DATA).unwrap();
        assert!(!encoder.is_empty());
    }

    #[test]
    fn write_space_id_round_trips_through_unique_shift() {
        // Build a real AddressSpace so its `space_id()` is packed the same way
        // `AddressSpace::new` (and thus Java's `AddressSpace.ID_UNIQUE_SHIFT` convention) does,
        // then confirm `write_space_id` recovers the same `unique` index a plain `write_space`
        // call for that space would encode.
        let ram = AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            3,
        );
        let factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));

        let mut encoder_a = PatchPackedEncode::new();
        encoder_a.open_element(ELEM_DATA).unwrap();
        encoder_a
            .write_space_id(ATTRIB_SPACE, ram.space_id() as i64)
            .unwrap();
        encoder_a.close_element(ELEM_DATA).unwrap();
        let mut bytes_a = Vec::new();
        encoder_a.write_to(&mut bytes_a).unwrap();

        let mut encoder_b = PatchPackedEncode::new();
        encoder_b.open_element(ELEM_DATA).unwrap();
        encoder_b.write_space(ATTRIB_SPACE, &ram).unwrap();
        encoder_b.close_element(ELEM_DATA).unwrap();
        let mut bytes_b = Vec::new();
        encoder_b.write_to(&mut bytes_b).unwrap();

        assert_eq!(bytes_a, bytes_b);

        let decoder = PackedDecode::new(factory, bytes_a);
        let id = decoder.open_element().unwrap();
        assert_eq!(decoder.read_space_with_id(ATTRIB_SPACE).unwrap().name(), "ram");
        decoder.close_element(id).unwrap();
    }

    #[test]
    fn patch_encoder_is_object_safe() {
        let mut encoder: Box<dyn PatchEncoder> = Box::new(PatchPackedEncode::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_bool(ATTRIB_VAL, true).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        assert!(!encoder.is_empty());
        assert!(encoder.size() > 0);
    }
}
