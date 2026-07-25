//! Port of `ghidra.program.model.pcode.HighConstant`.
//!
//! A constant that has been given a data type (like a constant that is really a pointer).
//!
//! The Java class `extends HighVariable`, whose real port is not complete yet (only a minimal
//! placeholder lives at [`crate::program::seam_stubs::HighVariable`]); this type was selected as
//! a dependency-cycle cut-point, so it is promoted straight to a trait with that placeholder as
//! its supertrait bound. The placeholder was grown with `get_high_function`/`get_data_type`/
//! `get_size`/`decode_instances` (all the inherited `HighVariable` members this class actually
//! calls) so this trait's default methods have something to build on; see `STUBS.tsv`.
//!
//! [`HighSymbol`] is likewise only a minimal placeholder. [`HighFunction`] has since been ported
//! as its own trait (see [`crate::program::model::pcode::high_function`]); back when this module
//! was written it was still a placeholder grown with `get_global_symbol_map`/`get_pc_address`, both
//! of which now live as real methods on the ported trait. [`LocalSymbolMap`] was grown with
//! `get_symbol` (`LocalSymbolMap.getSymbol(long)`).
//!
//! [`HighConstant::decode`]'s deepest fallback -- calling `GlobalSymbolMap.populateSymbol`, and
//! (if that also fails) decoding a spacebase reference off the representative varnode's lone
//! p-code descendant via `HighFunctionDBUtil.getSpacebaseReferenceAddress` and looking up a
//! `Data` object in the `Program`'s `Listing` to synthesize a brand-new global symbol -- needs
//! mutable `GlobalSymbolMap` access and `VarnodeAST` descendant-tracking that this crate's
//! ownership model / plain [`Varnode`] cannot reach from here. That branch (and the sibling
//! `symbol.getFirstWholeMap() instanceof DynamicEntry` branch, which needs a `HighSymbol` mutator
//! not exposed by the placeholder) is therefore a documented best-effort no-op, mirroring
//! `HighFunctionDBUtil`'s own precedent for similarly unreachable mutation paths.

use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::ids::ATTRIB_SYMREF;
use crate::program::model::pcode::Varnode;
use crate::program::model::address::Address;
use crate::program::model::scalar::Scalar;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::seam_stubs::{HighSymbol, HighVariable};

/// A constant that has been given a data type (like a constant that is really a pointer). Port of
/// `ghidra.program.model.pcode.HighConstant`.
pub trait HighConstant: HighVariable {
    /// Stands in for `HighConstant.getSymbol()`, overriding `HighVariable.getSymbol()`. Not
    /// modeled generically on the [`HighVariable`] placeholder, since only `HighConstant` needs
    /// it here.
    fn get_symbol(&self) -> Option<Arc<dyn HighSymbol>>;

    /// Stands in for the private `symbol` field setter, needed by [`HighConstant::decode`]'s
    /// default body to record the symbol resolved from a decoded `symref`.
    fn set_symbol(&mut self, symbol: Option<Arc<dyn HighSymbol>>);

    /// Instruction address the variable comes into scope within the function. Port of
    /// `HighConstant.getPCAddress()`.
    fn get_pc_address(&self) -> Option<Address>;

    /// Stands in for the private `pcaddr` field setter, needed by [`HighConstant::decode`]'s
    /// default body.
    fn set_pc_address(&mut self, addr: Option<Address>);

    /// Constant as a [`Scalar`] object. Port of `HighConstant.getScalar()`.
    fn get_scalar(&self) -> Scalar {
        let mut value = self.get_representative().get_offset();
        let dt = self.get_data_type();
        let signed = dt.is_integer_type() && dt.is_signed_integer_type();
        let bit_length = self.get_size() * 8;
        if signed {
            // Force sign extension of value.
            let shift_cnt = 64 - bit_length;
            value <<= shift_cnt;
            value >>= shift_cnt;
        }
        Scalar::new_with_signedness(bit_length as u8, value, signed)
    }

    /// Decode this constant from a stream. Port of `HighConstant.decode(Decoder)`.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let function = self.get_high_function();

        let mut symref: u64 = 0;
        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            }
            if attrib_id == ATTRIB_SYMREF.id {
                symref = decoder.read_unsigned_integer().map_err(decode_err)?;
            }
        }

        self.decode_instances(decoder)?;

        let representative = self.get_representative();
        self.set_pc_address(function.get_pc_address(&representative));

        if symref != 0 {
            let symref = symref as i64;
            let mut symbol = function.get_local_symbol_map().get_symbol(symref);
            if symbol.is_none() {
                symbol = function.get_global_symbol_map().get_symbol_by_id(symref);
            }
            // See the module docs: synthesizing a brand-new global symbol (when neither lookup
            // above finds one) and linking a dynamic-entry symbol back to this constant both need
            // capabilities this crate's placeholders don't expose yet, so both are elided here.
            self.set_symbol(symbol);
        }

        Ok(())
    }
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode HighConstant", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::model::listing::Function;
    use crate::program::model::pcode::global_symbol_map::GlobalSymbolMap;
    use crate::program::seam_stubs::LocalSymbolMap;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn ram_addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    /// A minimal signed 32-bit integer data-type stand-in, exercising the
    /// `dt instanceof AbstractIntegerDataType` branch of [`HighConstant::get_scalar`].
    struct MockSignedInt32;
    impl DataType for MockSignedInt32 {
        fn get_length(&self) -> i32 {
            4
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_signed_integer_type(&self) -> bool {
            true
        }
    }

    /// A data-type that is not an integer type at all, exercising the "unsigned, no sign
    /// extension" branch of [`HighConstant::get_scalar`].
    struct MockOpaqueByte;
    impl DataType for MockOpaqueByte {
        fn get_length(&self) -> i32 {
            1
        }
    }

    struct MockHighSymbol {
        id: i64,
    }

    impl HighSymbol for MockHighSymbol {
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            unimplemented!("not needed for this smoke test")
        }
    }

    #[derive(Default)]
    struct MockLocalSymbolMap {
        symbols: HashMap<i64, Arc<dyn HighSymbol>>,
    }

    impl LocalSymbolMap for MockLocalSymbolMap {
        fn get_param_symbol(&self, _index: i32) -> Arc<dyn HighSymbol> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_symbol(&self, id: i64) -> Option<Arc<dyn HighSymbol>> {
            self.symbols.get(&id).cloned()
        }
    }

    #[derive(Default)]
    struct MockGlobalSymbolMap;

    impl GlobalSymbolMap for MockGlobalSymbolMap {
        fn populate_symbol(
            &mut self,
            _id: i64,
            _data_type: Option<Box<dyn DataType>>,
            _sz: i32,
        ) -> Option<Arc<dyn HighSymbol>> {
            None
        }
        fn populate_annotation(&mut self, _vn: &Varnode) {}
        fn new_symbol(
            &mut self,
            _id: i64,
            _addr: Address,
            _data_type: Option<Box<dyn DataType>>,
            _sz: i32,
        ) -> Arc<dyn HighSymbol> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_symbol_by_id(&self, _id: i64) -> Option<Arc<dyn HighSymbol>> {
            None
        }
        fn get_symbol_by_address(&self, _addr: &Address) -> Option<Arc<dyn HighSymbol>> {
            None
        }
        fn get_symbols(&self) -> Box<dyn Iterator<Item = Arc<dyn HighSymbol>> + '_> {
            Box::new(std::iter::empty())
        }
    }

    struct MockHighFunction {
        local_symbols: HashMap<i64, Arc<dyn HighSymbol>>,
        pc_address: Option<Address>,
    }

    impl HighFunction for MockHighFunction {
        fn get_function(&self) -> Box<dyn Function> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_id(&self) -> i64 {
            unimplemented!("not needed for this smoke test")
        }
        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_local_symbol_map(&self) -> Box<dyn LocalSymbolMap> {
            Box::new(MockLocalSymbolMap {
                symbols: self.local_symbols.clone(),
            })
        }
        fn get_global_symbol_map(&self) -> Arc<dyn GlobalSymbolMap> {
            Arc::new(MockGlobalSymbolMap)
        }
        fn get_pc_address(&self, _representative: &Varnode) -> Option<Address> {
            self.pc_address.clone()
        }
        fn grab_from_function(&mut self, _override_extrapop: i32, _include_default_names: bool, _do_override: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn decode(
            &mut self,
            _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
        ) -> Result<(), DecoderException> {
            unimplemented!("not needed for this smoke test")
        }
        fn split_out_merge_group(
            &mut self,
            _high: Box<dyn HighVariable>,
            _vn: &Varnode,
        ) -> Result<Box<dyn HighVariable>, crate::program::model::pcode::pcode_exception::PcodeException> {
            unimplemented!("not needed for this smoke test")
        }
        fn encode(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::encoder::Encoder,
            _id: i64,
            _namespace: &dyn crate::program::model::symbol::Namespace,
            _entry_point: Option<Address>,
            _size: i32,
        ) -> std::io::Result<()> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_volatile(&mut self, _vn: &Varnode, _val: bool) {
            unimplemented!("not needed for this smoke test")
        }
    }

    struct MockHighConstant {
        representative: Varnode,
        data_type: fn() -> Box<dyn DataType>,
        high_function: Arc<dyn HighFunction>,
        symbol: Option<Arc<dyn HighSymbol>>,
        pc_address: Option<Address>,
    }

    impl HighVariable for MockHighConstant {
        fn get_representative(&self) -> Varnode {
            self.representative.clone()
        }
        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            self.high_function.clone()
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            (self.data_type)()
        }
    }

    impl HighConstant for MockHighConstant {
        fn get_symbol(&self) -> Option<Arc<dyn HighSymbol>> {
            self.symbol.clone()
        }
        fn set_symbol(&mut self, symbol: Option<Arc<dyn HighSymbol>>) {
            self.symbol = symbol;
        }
        fn get_pc_address(&self) -> Option<Address> {
            self.pc_address.clone()
        }
        fn set_pc_address(&mut self, addr: Option<Address>) {
            self.pc_address = addr;
        }
    }

    /// A decoder that emits a single `ATTRIB_SYMREF` attribute carrying `symref`, then signals
    /// end-of-attributes.
    struct MockSymrefDecoder {
        symref: u64,
        emitted: AtomicBool,
    }

    impl Decoder for MockSymrefDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(0)
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
            if self.emitted.swap(true, Ordering::SeqCst) {
                Ok(0)
            } else {
                Ok(ATTRIB_SYMREF.id)
            }
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
            Ok(self.symref)
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<u64, DecoderError> {
            unimplemented!()
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
        fn read_space_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
    }

    fn mock_function(local_symbols: HashMap<i64, Arc<dyn HighSymbol>>, pc: Address) -> Arc<dyn HighFunction> {
        Arc::new(MockHighFunction {
            local_symbols,
            pc_address: Some(pc),
        })
    }

    /// Proves [`HighConstant`] is dyn-object-safe (usable as `&mut dyn HighConstant`) and that its
    /// default [`HighConstant::decode`] correctly resolves a `symref` attribute to the matching
    /// local symbol and records the p-code op address supplied by the `HighFunction`.
    #[test]
    fn decode_resolves_local_symbol_and_pc_address() {
        let space = ram_space();
        let representative = Varnode::new(ram_addr(&space, 0x2000), 4);
        let pc = ram_addr(&space, 0x400100);

        let mut local_symbols: HashMap<i64, Arc<dyn HighSymbol>> = HashMap::new();
        local_symbols.insert(99, Arc::new(MockHighSymbol { id: 99 }));

        let mut constant = MockHighConstant {
            representative,
            data_type: || Box::new(MockOpaqueByte),
            high_function: mock_function(local_symbols, pc.clone()),
            symbol: None,
            pc_address: None,
        };

        let decoder = MockSymrefDecoder {
            symref: 99,
            emitted: AtomicBool::new(false),
        };

        let obj: &mut dyn HighConstant = &mut constant;
        obj.decode(&decoder).expect("decode should succeed");

        assert_eq!(obj.get_symbol().expect("symbol should resolve").get_id(), 99);
        assert_eq!(obj.get_pc_address(), Some(pc));
    }

    /// A `symref` of `0` (the Java sentinel for "not associated with a symbol") must leave
    /// [`HighConstant::get_symbol`] unset, while the p-code op address is still recorded
    /// unconditionally.
    #[test]
    fn decode_with_no_symref_leaves_symbol_unset() {
        let space = ram_space();
        let representative = Varnode::new(ram_addr(&space, 0x3000), 4);
        let pc = ram_addr(&space, 0x400200);

        let mut constant = MockHighConstant {
            representative,
            data_type: || Box::new(MockOpaqueByte),
            high_function: mock_function(HashMap::new(), pc.clone()),
            symbol: None,
            pc_address: None,
        };

        let decoder = MockSymrefDecoder {
            symref: 0,
            emitted: AtomicBool::new(false),
        };

        constant.decode(&decoder).expect("decode should succeed");

        assert!(constant.get_symbol().is_none());
        assert_eq!(constant.get_pc_address(), Some(pc));
    }

    /// Exercises the real sign-extension arithmetic of [`HighConstant::get_scalar`] for a signed
    /// integer data type: a 32-bit all-ones pattern must sign-extend to `-1`.
    #[test]
    fn get_scalar_sign_extends_signed_integer_representative() {
        let space = ram_space();
        // 0xFFFFFFFF, the 32-bit two's-complement bit pattern for -1.
        let representative = Varnode::new(ram_addr(&space, 0xFFFF_FFFF), 4);

        let constant = MockHighConstant {
            representative,
            data_type: || Box::new(MockSignedInt32),
            high_function: mock_function(HashMap::new(), ram_addr(&space, 0)),
            symbol: None,
            pc_address: None,
        };

        let scalar = constant.get_scalar();
        assert!(scalar.is_signed());
        assert_eq!(scalar.get_signed_value(), -1);
    }

    /// A non-integer data type must not be sign-extended: the raw representative offset is
    /// reported unsigned.
    #[test]
    fn get_scalar_reports_unsigned_value_for_non_integer_type() {
        let space = ram_space();
        let representative = Varnode::new(ram_addr(&space, 0xFF), 1);

        let constant = MockHighConstant {
            representative,
            data_type: || Box::new(MockOpaqueByte),
            high_function: mock_function(HashMap::new(), ram_addr(&space, 0)),
            symbol: None,
            pc_address: None,
        };

        let scalar = constant.get_scalar();
        assert!(!scalar.is_signed());
        assert_eq!(scalar.get_unsigned_value(), 0xFF);
    }
}
