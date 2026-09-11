//! Port of `ghidra.program.model.pcode.ParamMeasure`.
//!
//! A value type describing a candidate parameter's storage location (a [`Varnode`]) and its
//! "measure" -- a confidence/rank produced during return-value/parameter signature analysis. The
//! 74-line Java source is a thin, mostly-getter class: a no-arg constructor that leaves every
//! field `null`, an `isEmpty()` predicate, three getters, and a `decode` method that populates the
//! three fields from a stream.
//!
//! ## Scope boundary: `decode` is not implemented
//!
//! Java's `ParamMeasure.decode(Decoder, PcodeFactory)` is:
//! ```java
//! public void decode(Decoder decoder, PcodeFactory factory) throws DecoderException {
//!     vn = Varnode.decode(decoder, factory);
//!     dt = factory.getDataTypeManager().decodeDataType(decoder);
//!     int rankel = decoder.openElement(ElementId.ELEM_RANK);
//!     rank = (int) decoder.readSignedInteger(AttributeId.ATTRIB_VAL);
//!     decoder.closeElement(rankel);
//! }
//! ```
//! The second and third steps have real equivalents already available in this crate
//! ([`PcodeDataTypeManager::decode_data_type`](crate::program::model::pcode::pcode_data_type_manager::PcodeDataTypeManager::decode_data_type)
//! and [`Decoder::open_element_with_id`](crate::program::model::pcode::decoder::Decoder::open_element_with_id)
//! + [`Decoder::read_signed_integer_with_id`](crate::program::model::pcode::decoder::Decoder::read_signed_integer_with_id)
//! for the `<rank val="..">` element), but the first step -- the full static
//! `Varnode.decode(Decoder, PcodeFactory)` (`Varnode.java` lines 387-476) -- is **not** yet ported
//! in this crate. That method dispatches on `ELEM_VOID`/`ELEM_SPACEID`/`ELEM_IOP`, looks up
//! existing varnodes by reference id via `PcodeFactory.getRef`, handles composite/"join" address
//! pieces via `PcodeFactory.getJoinStorage`/`getJoinAddress`, and runs a second attribute pass
//! invoking `PcodeFactory.setMergeGroup`/`setPersistent`/`setAddrTied`/`setUnaffected`/`setInput`/
//! `setVolatile`. Only two much smaller helpers exist today: `address_xml::decode` (a plain
//! `<addr>` element, used for `AddressXML.decode`, not `Varnode.decode`) and a private
//! `decode_varnode_piece`/`decode_varnode_pieces` pair in the same file, used only for the "join"
//! address *string* format that `Varnode.decodePieces` also uses internally. Neither implements
//! `Varnode.decode`'s own element-dispatch/ref-lookup/rewind-attributes logic, and three of the
//! attribute ids it needs (`ATTRIB_GRP`, `ATTRIB_PERSISTS`, `ATTRIB_INPUT`) are not yet declared in
//! `ids.rs` either. Porting `Varnode::decode` is out of scope for this file -- it belongs to
//! `Varnode.java`, a separate (and already-`DONE`-marked) source file -- so `decode` is not
//! implemented here at all; see the `TODO(port)` below for the exact blocker.
//!
//! Every other method in the Java source (the no-arg constructor, `isEmpty`, `getVarnode`,
//! `getDataType`, `getRank`) is fully, faithfully ported below.

use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::Varnode;

/// Describes a candidate parameter's storage location and its measure (rank) during signature
/// analysis. Port of `ghidra.program.model.pcode.ParamMeasure`. See the module docs for the
/// `decode` scope boundary.
pub struct ParamMeasure {
    vn: Option<Varnode>,
    dt: Option<Box<dyn DataType>>,
    /// Java's `rank` field is a boxed `Integer`, `null` until `decode` populates it -- ported as
    /// `Option<i32>` to preserve that nullability rather than defaulting to `0`.
    rank: Option<i32>,
}

impl ParamMeasure {
    /// Constructs a `ParamMeasure`.
    ///
    /// Port of `ParamMeasure()`. The result is empty (per [`is_empty`](Self::is_empty)) until (in
    /// Java) `decode` is invoked -- see the module docs for why `decode` is not implemented here.
    pub fn new() -> Self {
        Self { vn: None, dt: None, rank: None }
    }

    /// Port of `ParamMeasure.isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.vn.is_none()
    }

    // TODO(port): `ParamMeasure.decode(Decoder, PcodeFactory)` is not implemented. It requires
    // `Varnode.decode(Decoder, PcodeFactory)` (Varnode.java lines 387-476), which this crate does
    // not yet port -- see the module docs above for exactly what's missing.

    /// Port of `ParamMeasure.getVarnode()`.
    pub fn get_varnode(&self) -> Option<&Varnode> {
        self.vn.as_ref()
    }

    /// Port of `ParamMeasure.getDataType()`.
    pub fn get_data_type(&self) -> Option<&dyn DataType> {
        self.dt.as_deref()
    }

    /// Port of `ParamMeasure.getRank()`.
    pub fn get_rank(&self) -> Option<i32> {
        self.rank
    }

    /// Test-only constructor standing in for what `decode` would populate, since `decode` itself
    /// cannot be ported yet (see module docs). Not a port of any Java method -- Java's only way to
    /// populate a non-empty `ParamMeasure` is `decode`.
    #[cfg(test)]
    fn for_test(vn: Varnode, dt: Box<dyn DataType>, rank: i32) -> Self {
        Self { vn: Some(vn), dt: Some(dt), rank: Some(rank) }
    }
}

impl Default for ParamMeasure {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct MockDataType {
        length: i32,
    }
    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn new_is_empty_with_no_varnode_data_type_or_rank() {
        let pm = ParamMeasure::new();

        assert!(pm.is_empty());
        assert!(pm.get_varnode().is_none());
        assert!(pm.get_data_type().is_none());
        assert!(pm.get_rank().is_none());
    }

    #[test]
    fn default_matches_new() {
        let pm = ParamMeasure::default();
        assert!(pm.is_empty());
    }

    #[test]
    fn populated_measure_is_not_empty_and_exposes_all_fields() {
        let vn = Varnode::new(Address::new(ram_space(), 0x1000), 4);
        let pm = ParamMeasure::for_test(vn.clone(), Box::new(MockDataType { length: 4 }), 7);

        assert!(!pm.is_empty());
        assert_eq!(pm.get_varnode(), Some(&vn));
        assert_eq!(pm.get_data_type().unwrap().get_length(), 4);
        assert_eq!(pm.get_rank(), Some(7));
    }

    #[test]
    fn different_varnodes_and_ranks_round_trip_independently() {
        let vn_a = Varnode::new(Address::new(ram_space(), 0x2000), 8);
        let vn_b = Varnode::new(Address::new(ram_space(), 0x3000), 1);
        let a = ParamMeasure::for_test(vn_a.clone(), Box::new(MockDataType { length: 8 }), 0);
        let b = ParamMeasure::for_test(vn_b.clone(), Box::new(MockDataType { length: 1 }), 99);

        assert_eq!(a.get_varnode(), Some(&vn_a));
        assert_eq!(a.get_rank(), Some(0));
        assert_eq!(b.get_varnode(), Some(&vn_b));
        assert_eq!(b.get_rank(), Some(99));
        assert_ne!(a.get_varnode(), b.get_varnode());
    }
}
