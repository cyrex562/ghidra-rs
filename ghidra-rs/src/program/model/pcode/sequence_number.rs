//! Port of `ghidra.program.model.pcode.SequenceNumber`.
//!
//! Basically a unique address for a `PcodeOp`. It is unique, maintains the original assembly
//! instruction address, and is comparable within a basic block.
//!
//! This is a small, standalone value type (no `HighSymbol`/`HighVariable` involvement, no
//! dependency-cycle concerns), so it is ported as a plain concrete struct implementing `Ord`/
//! `PartialOrd`/`PartialEq`/`Eq`/`Hash` to mirror Java's `Comparable<SequenceNumber>` and
//! overridden `equals`/`hashCode`.
//!
//! # Quirk: `order` is excluded from equality/hashing/comparison
//!
//! Java's `equals`/`hashCode`/`compareTo` all deliberately ignore the mutable `order` field
//! (`order` "may change as basic block is edited", so including it would make a `SequenceNumber`
//! change identity as blocks are edited). This port reproduces that exactly via manual `PartialEq`/
//! `Eq`/`Hash`/`PartialOrd`/`Ord` implementations rather than `#[derive(...)]` (which would fold
//! `order` in); see `equality_and_ordering_ignore_order_field` below for a test proving it.
//!
//! # Deviation: `pc`/`uniq`/`order` are public fields, not private-plus-accessors
//!
//! Java's `pc`/`uniq`/`order` are `private` with `getTarget`/`getTime`/`setTime`/`getOrder`/
//! `setOrder` accessors. This crate already had a placeholder `SequenceNumber` (directly in
//! `pcode/mod.rs`, predating this real port) with public `pc`/`uniq`/`order` fields, and dozens of
//! already-ported call sites across the crate (`PcodeOp`/`PcodeOpAST`/the JIT emulator/etc., e.g.
//! `op.seqnum.pc`, `op.seqnum.uniq`) read those fields directly rather than through accessors.
//! Reverting to private fields here would ripple into every one of those call sites, well outside
//! this port's scope. This struct keeps the fields `pub` for that reason (a deliberate,
//! crate-convention deviation from Java's encapsulation -- not a fidelity gap), while still
//! providing the real `get_target`/`get_time`/`set_time`/`get_order`/`set_order` accessor methods
//! as thin wrappers, matching Java's public API surface for any caller that prefers them.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::io;

use crate::program::model::address::Address;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_OFFSET, ATTRIB_SPACE, ATTRIB_UNIQ, ELEM_SEQNUM};

/// A unique address for a `PcodeOp`. Port of `ghidra.program.model.pcode.SequenceNumber`. See the
/// module docs for why `pc`/`uniq`/`order` are `pub` fields rather than private-plus-accessors.
#[derive(Debug, Clone)]
pub struct SequenceNumber {
    /// Address of the assembly language instruction. Port of the private `pc` field.
    pub pc: Address,
    /// Sub-address for distinguishing multiple `PcodeOp`s at one instruction address. Does not
    /// change over the lifetime of the `PcodeOp`. Port of the private `uniq` field.
    pub uniq: i32,
    /// Relative position information of `PcodeOp`s within a basic block; may change as the basic
    /// block is edited. Port of the private `order` field.
    pub order: i32,
}

impl SequenceNumber {
    /// Construct a sequence number for an instruction at an address and sequence of pcode op
    /// within that instruction's set of pcode. Port of `SequenceNumber(Address, int)`.
    pub fn new(instr_addr: Address, sequence_num: i32) -> Self {
        // Java leaves `order` at its default `int` value (0) -- this constructor never sets it.
        SequenceNumber { pc: instr_addr, uniq: sequence_num, order: 0 }
    }

    /// Get the address of the instruction this sequence belongs to. Port of
    /// `SequenceNumber.getTarget()`.
    pub fn get_target(&self) -> &Address {
        &self.pc
    }

    /// Get the unique sub-address for distinguishing multiple `PcodeOp`s at one instruction
    /// address. Does not change over the lifetime of the `PcodeOp`. Port of
    /// `SequenceNumber.getTime()`.
    pub fn get_time(&self) -> i32 {
        self.uniq
    }

    /// Set the unique sub-address for distinguishing multiple `PcodeOp`s at one instruction
    /// address. Port of `SequenceNumber.setTime(int)`.
    pub fn set_time(&mut self, t: i32) {
        self.uniq = t;
    }

    /// Get the relative position information of `PcodeOp`s within a basic block, which may
    /// change as the basic block is edited. Port of `SequenceNumber.getOrder()`.
    pub fn get_order(&self) -> i32 {
        self.order
    }

    /// Set the relative position information of `PcodeOp`s within a basic block. Port of
    /// `SequenceNumber.setOrder(int)`.
    pub fn set_order(&mut self, o: i32) {
        self.order = o;
    }

    /// Encode this sequence number to the stream. Port of `SequenceNumber.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_SEQNUM)?;
        let space = self.pc.space();
        encoder.write_space(ATTRIB_SPACE, space)?;
        encoder.write_unsigned_integer(ATTRIB_OFFSET, self.pc.unsigned_offset())?;
        if self.uniq != -1 {
            encoder.write_unsigned_integer(ATTRIB_UNIQ, self.uniq as u64)?;
        }
        encoder.close_element(ELEM_SEQNUM)
    }

    /// Decode a new sequence number from the stream. Port of the static
    /// `SequenceNumber.decode(Decoder)`.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    pub fn decode(decoder: &dyn Decoder) -> Result<SequenceNumber, DecoderException> {
        let el = decoder.open_element_with_id(ELEM_SEQNUM).map_err(decode_err)?;
        let mut uniq: i32 = -1;
        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            } else if attrib_id == ATTRIB_UNIQ.id {
                uniq = decoder.read_unsigned_integer().map_err(decode_err)? as i32;
            }
        }
        let spc = decoder.read_space_with_id(ATTRIB_SPACE).map_err(decode_err)?;
        let offset = decoder.read_unsigned_integer_with_id(ATTRIB_OFFSET).map_err(decode_err)?;
        decoder.close_element(el).map_err(decode_err)?;
        Ok(SequenceNumber::new(spc.address(offset as i64), uniq))
    }
}

fn decode_err(e: crate::program::model::pcode::decoder::DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode SequenceNumber", e)
}

impl PartialEq for SequenceNumber {
    /// Port of `SequenceNumber.equals(Object)`: compares `pc` and `uniq` only. See the module
    /// docs for why `order` is deliberately excluded.
    fn eq(&self, other: &Self) -> bool {
        self.pc == other.pc && self.uniq == other.uniq
    }
}

impl Eq for SequenceNumber {}

impl Hash for SequenceNumber {
    /// Port of `SequenceNumber.hashCode()` (`pc.hashCode() + uniq`). See the module docs for why
    /// `order` is deliberately excluded ("Don't hash order, as this is mutable" in the original).
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pc.hash(state);
        self.uniq.hash(state);
    }
}

impl PartialOrd for SequenceNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SequenceNumber {
    /// Port of `SequenceNumber.compareTo(SequenceNumber)`: compares `pc` first, falling back to
    /// `uniq`. See the module docs for why `order` is deliberately excluded.
    fn cmp(&self, other: &Self) -> Ordering {
        let val = self.pc.cmp(&other.pc);
        if val != Ordering::Equal {
            return val;
        }
        self.uniq.cmp(&other.uniq)
    }
}

impl std::fmt::Display for SequenceNumber {
    /// Port of `SequenceNumber.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({}, 0x{:x}, {}, {})",
            self.pc.space().name(),
            self.pc.unsigned_offset(),
            self.uniq,
            self.order
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn other_space() -> Arc<AddressSpace> {
        AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 2)
    }

    #[test]
    fn new_sets_pc_and_time_with_order_defaulting_to_zero() {
        let space = ram_space();
        let addr = Address::new(space, 0x1000);
        let sq = SequenceNumber::new(addr.clone(), 5);

        assert_eq!(sq.get_target(), &addr);
        assert_eq!(sq.get_time(), 5);
        assert_eq!(sq.get_order(), 0);
    }

    #[test]
    fn setters_mutate_time_and_order() {
        let space = ram_space();
        let addr = Address::new(space, 0x1000);
        let mut sq = SequenceNumber::new(addr, 5);

        sq.set_time(9);
        sq.set_order(3);

        assert_eq!(sq.get_time(), 9);
        assert_eq!(sq.get_order(), 3);
    }

    /// `equals`/`hashCode`/`compareTo` all ignore the mutable `order` field -- two
    /// `SequenceNumber`s with the same `pc`/`uniq` but different `order` are equal, hash equal,
    /// and compare equal. See the module docs.
    #[test]
    fn equality_and_ordering_ignore_order_field() {
        let space = ram_space();
        let addr = Address::new(space, 0x2000);
        let mut a = SequenceNumber::new(addr.clone(), 7);
        let mut b = SequenceNumber::new(addr, 7);
        a.set_order(1);
        b.set_order(99);

        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), Ordering::Equal);

        use std::collections::hash_map::DefaultHasher;
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn different_uniq_at_same_address_are_not_equal_but_compare_by_uniq() {
        let space = ram_space();
        let addr = Address::new(space, 0x3000);
        let low = SequenceNumber::new(addr.clone(), 1);
        let high = SequenceNumber::new(addr, 2);

        assert_ne!(low, high);
        assert!(low < high);
        assert!(high > low);
    }

    #[test]
    fn address_takes_priority_over_uniq_in_ordering() {
        let low_space = ram_space();
        let low_addr = Address::new(low_space, 0x1000);
        let high_addr_same_space = Address::new(low_addr.space().clone(), 0x2000);

        // A huge `uniq` at the lower address still sorts before a tiny `uniq` at the higher
        // address, since `pc` is compared first.
        let a = SequenceNumber::new(low_addr, 1_000_000);
        let b = SequenceNumber::new(high_addr_same_space, 0);

        assert!(a < b);
    }

    #[test]
    fn different_address_spaces_are_not_equal_even_with_same_offset_and_uniq() {
        let a = SequenceNumber::new(Address::new(ram_space(), 0x1000), 4);
        let b = SequenceNumber::new(Address::new(other_space(), 0x1000), 4);

        assert_ne!(a, b);
    }

    #[test]
    fn to_string_matches_java_format() {
        let addr = Address::new(ram_space(), 0x1234);
        let mut sq = SequenceNumber::new(addr, 5);
        sq.set_order(2);

        assert_eq!(sq.to_string(), "(ram, 0x1234, 5, 2)");
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<ElementId>,
        closed: Vec<ElementId>,
        spaces: Vec<AttributeId>,
        unsigned: Vec<(AttributeId, u64)>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.opened.push(elem_id);
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.closed.push(elem_id);
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.unsigned.push((attrib_id, val));
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> io::Result<()> {
            Ok(())
        }
        fn write_string_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _val: &str) -> io::Result<()> {
            Ok(())
        }
        fn write_space(&mut self, attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
            self.spaces.push(attrib_id);
            Ok(())
        }
        fn write_space_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _name: &str) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    struct MockDecoder {
        space: Arc<AddressSpace>,
        offset: u64,
        uniq: Option<i32>,
        attr_step: std::sync::atomic::AtomicUsize,
    }

    impl Decoder for MockDecoder {
        fn get_address_factory(&self) -> Arc<dyn crate::program::model::address::AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn crate::program::model::address::AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(1)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            Ok(1)
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            let step = self.attr_step.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if step == 0 {
                if let Some(_u) = self.uniq {
                    return Ok(ATTRIB_UNIQ.id);
                }
            }
            Ok(0)
        }
        fn rewind_attributes(&self) {}
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            Ok(self.uniq.expect("read_unsigned_integer called with no uniq attribute pending") as u64)
        }
        fn read_unsigned_integer_with_id(&self, _attrib_id: AttributeId) -> Result<u64, DecoderError> {
            Ok(self.offset)
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
        fn read_space_with_id(&self, _attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            Ok(self.space.clone())
        }
    }

    #[test]
    fn decode_reads_space_offset_and_uniq() {
        let decoder = MockDecoder { space: ram_space(), offset: 0x6000, uniq: Some(42), attr_step: std::sync::atomic::AtomicUsize::new(0) };

        let sq = SequenceNumber::decode(&decoder).unwrap();

        assert_eq!(sq.get_time(), 42);
        assert_eq!(sq.get_target().unsigned_offset(), 0x6000);
        assert_eq!(sq.get_target().space().name(), "ram");
    }

    /// When no `uniq` attribute is present in the stream, `decode` leaves the sentinel `-1` in
    /// place (mirrors Java's `int uniq = -1;` default that the attribute loop never overwrites).
    #[test]
    fn decode_defaults_uniq_to_minus_one_when_attribute_absent() {
        let decoder = MockDecoder { space: ram_space(), offset: 0x7000, uniq: None, attr_step: std::sync::atomic::AtomicUsize::new(0) };

        let sq = SequenceNumber::decode(&decoder).unwrap();

        assert_eq!(sq.get_time(), -1);
    }

    #[test]
    fn encode_writes_space_offset_and_uniq() {
        let addr = Address::new(ram_space(), 0x4000);
        let sq = SequenceNumber::new(addr, 3);

        let mut encoder = RecordingEncoder::default();
        sq.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened, vec![ELEM_SEQNUM]);
        assert_eq!(encoder.closed, vec![ELEM_SEQNUM]);
        assert_eq!(encoder.spaces, vec![ATTRIB_SPACE]);
        assert!(encoder.unsigned.contains(&(ATTRIB_OFFSET, 0x4000)));
        assert!(encoder.unsigned.contains(&(ATTRIB_UNIQ, 3)));
    }

    /// `uniq == -1` is a sentinel skipped by `encode` (mirrors `if (uniq != -1)` in Java).
    #[test]
    fn encode_skips_uniq_attribute_when_sentinel() {
        let addr = Address::new(ram_space(), 0x5000);
        let sq = SequenceNumber::new(addr, -1);

        let mut encoder = RecordingEncoder::default();
        sq.encode(&mut encoder).unwrap();

        assert!(!encoder.unsigned.iter().any(|(id, _)| *id == ATTRIB_UNIQ));
    }
}
