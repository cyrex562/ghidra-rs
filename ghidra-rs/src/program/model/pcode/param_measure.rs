//! Port of `ghidra.program.model.pcode.ParamMeasure`.
//!
//! A value type describing a candidate parameter's storage location (a [`Varnode`]) and its
//! "measure" -- a confidence/rank produced during return-value/parameter signature analysis. The
//! 74-line Java source is a thin, mostly-getter class: a no-arg constructor that leaves every
//! field `null`, an `isEmpty()` predicate, three getters, and a `decode` method that populates the
//! three fields from a stream.
//!
//! ## `decode` is now real
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
//! This was previously blocked on `Varnode.decode(Decoder, PcodeFactory)` (`Varnode.java` lines
//! 387-476), which this crate had not yet ported (`Varnode` was a phantom-`DONE` manifest row --
//! ~13 methods ported against a 649-line, ~38-public-method real class). That gap has since been
//! closed: [`Varnode::decode`](crate::program::model::pcode::Varnode::decode) is now a full port
//! (element-dispatch on `ELEM_VOID`/`ELEM_SPACEID`/`ELEM_IOP`, ref-registry lookup via
//! [`PcodeFactory::get_ref`], join-address handling via
//! [`PcodeFactory::get_join_storage`]/[`get_join_address`](crate::program::model::pcode::pcode_factory::PcodeFactory::get_join_address),
//! and the second attribute pass invoking
//! `set_merge_group`/`set_persistent`/`set_addr_tied`/`set_unaffected`/`set_input`/`set_volatile`),
//! so all three steps of `ParamMeasure.decode` now have real equivalents:
//! [`Varnode::decode`](crate::program::model::pcode::Varnode::decode),
//! [`PcodeDataTypeManager::decode_data_type`](crate::program::model::pcode::pcode_data_type_manager::PcodeDataTypeManager::decode_data_type),
//! and [`Decoder::open_element_with_id`](crate::program::model::pcode::decoder::Decoder::open_element_with_id)
//! + [`Decoder::read_signed_integer_with_id`](crate::program::model::pcode::decoder::Decoder::read_signed_integer_with_id)
//! for the `<rank val="..">` element.
//!
//! Every method in the Java source (the no-arg constructor, `isEmpty`, `getVarnode`,
//! `getDataType`, `getRank`, and now `decode`) is fully, faithfully ported below.

use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder::DecoderError;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::ids::{ATTRIB_VAL, ELEM_RANK};
use crate::program::model::pcode::pcode_factory::PcodeFactory;
use crate::program::model::pcode::Varnode;

/// Adapt a [`DecoderError`] to the [`DecoderException`] `ParamMeasure::decode` reports, mirroring
/// its `throws DecoderException` signature. Same pattern as `Varnode::decode_err`.
fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode ParamMeasure", e)
}

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

    /// Decode `self` from a stream: the storage varnode, its data type, and its rank. Port of
    /// `ParamMeasure.decode(Decoder, PcodeFactory)`.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    pub fn decode(&mut self, decoder: &dyn Decoder, factory: &dyn PcodeFactory) -> Result<(), DecoderException> {
        self.vn = Varnode::decode(decoder, factory)?;
        self.dt = Some(factory.get_data_type_manager().decode_data_type(decoder)?);
        let rankel = decoder.open_element_with_id(ELEM_RANK).map_err(decode_err)?;
        self.rank = Some(decoder.read_signed_integer_with_id(ATTRIB_VAL).map_err(decode_err)? as i32);
        decoder.close_element(rankel).map_err(decode_err)?;
        Ok(())
    }

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
    use crate::program::model::address::{
        Address, AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::ids::{
        AttributeId, ElementId, ATTRIB_OFFSET, ATTRIB_SPACE, ELEM_VARNODE,
    };
    use crate::program::model::pcode::pcode_data_type_manager::PcodeDataTypeManager;
    use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber};
    use crate::program::seam_stubs::{HighSymbol, VarnodeListStorage};
    use crate::util::exception::InvalidInputException;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Arc;

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

    // --- ParamMeasure::decode ---

    #[derive(Clone)]
    enum MockAttr {
        Space(Arc<AddressSpace>),
        UInt(u64),
        SInt(i64),
    }

    /// Minimal `Decoder` whose attribute stream is searched by id directly (independent of a
    /// scan position), sufficient for `Varnode::decode`'s space/offset attributes plus
    /// `ParamMeasure::decode`'s own `<rank val="..">` element.
    struct MockDecoder {
        factory: Arc<dyn AddressFactory>,
        attrs: Vec<(i32, MockAttr)>,
        pos: std::sync::atomic::AtomicUsize,
    }

    impl MockDecoder {
        fn new(factory: Arc<dyn AddressFactory>, attrs: Vec<(i32, MockAttr)>) -> Self {
            Self { factory, attrs, pos: std::sync::atomic::AtomicUsize::new(0) }
        }

        fn find_attr(&self, id: i32) -> &MockAttr {
            self.attrs
                .iter()
                .find(|(aid, _)| *aid == id)
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("mock decoder has no attribute with id {id}"))
        }
    }

    impl Decoder for MockDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            self.factory.clone()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(ELEM_VARNODE.id)
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(ELEM_VARNODE.id)
        }
        fn open_element_with_id(&self, elem_id: ElementId) -> Result<i32, DecoderError> {
            Ok(elem_id.id)
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            let idx = self.pos.load(std::sync::atomic::Ordering::SeqCst);
            if idx >= self.attrs.len() {
                return Ok(0);
            }
            self.pos.store(idx + 1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.attrs[idx].0)
        }
        fn rewind_attributes(&self) {
            self.pos.store(0, std::sync::atomic::Ordering::SeqCst);
        }
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            let idx = self.pos.load(std::sync::atomic::Ordering::SeqCst);
            match &self.attrs[idx - 1].1 {
                MockAttr::SInt(v) => Ok(*v),
                _ => panic!("not a signed integer attribute"),
            }
        }
        fn read_signed_integer_with_id(&self, attrib_id: AttributeId) -> Result<i64, DecoderError> {
            match self.find_attr(attrib_id.id) {
                MockAttr::SInt(v) => Ok(*v),
                _ => panic!("not a signed integer attribute"),
            }
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            let idx = self.pos.load(std::sync::atomic::Ordering::SeqCst);
            match &self.attrs[idx - 1].1 {
                MockAttr::UInt(v) => Ok(*v),
                _ => panic!("not an unsigned integer attribute"),
            }
        }
        fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError> {
            match self.find_attr(attrib_id.id) {
                MockAttr::UInt(v) => Ok(*v),
                _ => panic!("not an unsigned integer attribute"),
            }
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!("not exercised by these tests")
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            let idx = self.pos.load(std::sync::atomic::Ordering::SeqCst);
            match &self.attrs[idx - 1].1 {
                MockAttr::Space(v) => Ok(v.clone()),
                _ => panic!("not a space attribute"),
            }
        }
        fn read_space_with_id(&self, attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            match self.find_attr(attrib_id.id) {
                MockAttr::Space(v) => Ok(v.clone()),
                _ => panic!("not a space attribute"),
            }
        }
    }

    /// `PcodeDataTypeManager` whose `decode_data_type` ignores the decoder and returns a fixed
    /// data type -- data-type decoding has its own dedicated tests elsewhere; these tests exercise
    /// `ParamMeasure::decode`'s own three-step orchestration, not `decode_data_type`'s algorithm.
    struct FixedDataTypeManager {
        length: i32,
    }
    impl PcodeDataTypeManager for FixedDataTypeManager {
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not exercised by these tests")
        }
        fn decode_data_type(&self, _decoder: &dyn Decoder) -> Result<Box<dyn DataType>, DecoderException> {
            Ok(Box::new(MockDataType { length: self.length }))
        }
        fn encode_name_id_attributes(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::encoder::Encoder,
            _data_type: &dyn DataType,
        ) -> std::io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
        fn encode_type_ref(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::encoder::Encoder,
            _data_type: &dyn DataType,
            _size: i32,
        ) -> std::io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
        fn encode_type(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::encoder::Encoder,
            _data_type: &dyn DataType,
            _size: i32,
        ) -> std::io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
    }

    #[derive(Default)]
    struct TestPcodeFactory {
        address_factory: Option<Arc<dyn AddressFactory>>,
        data_type_length: i32,
        refs: RefCell<HashMap<i32, Varnode>>,
    }

    impl PcodeFactory for TestPcodeFactory {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            self.address_factory.clone().expect("address_factory not configured")
        }
        fn get_data_type_manager(&self) -> Arc<dyn PcodeDataTypeManager> {
            Arc::new(FixedDataTypeManager { length: self.data_type_length })
        }
        fn new_varnode_with_ref(&self, sz: i32, addr: Address, ref_id: i32) -> Varnode {
            let vn = Varnode::new(addr, sz);
            self.refs.borrow_mut().insert(ref_id, vn.clone());
            vn
        }
        fn get_join_address(&self, _storage: &dyn VariableStorage) -> Option<Address> {
            None
        }
        fn build_storage(&self, vn: &Varnode) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
            Ok(Box::new(VarnodeListStorage(vec![vn.clone()])))
        }
        fn get_ref(&self, refid: i32) -> Option<Varnode> {
            self.refs.borrow().get(&refid).cloned()
        }
        fn get_op_ref(&self, _refid: i32) -> Option<PcodeOp> {
            None
        }
        fn get_symbol(&self, _symbol_id: i64) -> Option<Arc<dyn HighSymbol>> {
            None
        }
        fn new_op(
            &self,
            sq: SequenceNumber,
            opc: OpCode,
            inputs: Vec<Varnode>,
            output: Option<Varnode>,
        ) -> PcodeOp {
            PcodeOp::new(opc, sq, inputs, output)
        }
    }

    #[test]
    fn decode_populates_varnode_data_type_and_rank() {
        let ram = ram_space();
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let attrs = vec![
            (ATTRIB_SPACE.id, MockAttr::Space(ram.clone())),
            (ATTRIB_OFFSET.id, MockAttr::UInt(0x400)),
            (ATTRIB_VAL.id, MockAttr::SInt(3)),
        ];
        let decoder = MockDecoder::new(addr_factory.clone(), attrs);
        let factory = TestPcodeFactory {
            address_factory: Some(addr_factory),
            data_type_length: 8,
            ..Default::default()
        };

        let mut pm = ParamMeasure::new();
        assert!(pm.is_empty());
        pm.decode(&decoder, &factory).unwrap();

        assert!(!pm.is_empty());
        assert_eq!(pm.get_varnode(), Some(&Varnode::new(ram.address(0x400), 4)));
        assert_eq!(pm.get_data_type().unwrap().get_length(), 8);
        assert_eq!(pm.get_rank(), Some(3));
    }

    #[test]
    fn decode_propagates_varnode_decode_errors() {
        // No "space"/"offset" attributes at all still succeeds for `Varnode::decode` (it falls
        // back to the "no address" sentinel), so instead force a failure the way `Varnode::decode`
        // itself can genuinely fail: an out-of-order "piece" sequence inside a join address.
        let ram = ram_space();
        let variable_space = AddressSpace::new("VARIABLE", 32, 1, AddressSpaceType::Variable, 9);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram]));
        let attrs = vec![
            (ATTRIB_SPACE.id, MockAttr::Space(variable_space)),
            (
                crate::program::model::pcode::ids::ATTRIB_PIECE.id + 1,
                MockAttr::UInt(0), // wrong type on purpose is irrelevant; index-out-of-order fires first
            ),
        ];
        let decoder = MockDecoder::new(addr_factory.clone(), attrs);
        let factory = TestPcodeFactory {
            address_factory: Some(addr_factory),
            data_type_length: 4,
            ..Default::default()
        };

        let mut pm = ParamMeasure::new();
        let err = pm.decode(&decoder, &factory).unwrap_err();
        assert!(err.to_string().contains("Invalid varnode pieces") || err.to_string().contains("must be in order"));
        // The failed decode must not have partially populated the measure.
        assert!(pm.is_empty());
    }
}
