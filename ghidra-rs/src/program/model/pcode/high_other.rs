//! Port of `ghidra.program.model.pcode.HighOther`.
//!
//! Other forms of variable, typically compiler infrastructure like the stack pointer or saved
//! registers. Unlike [`HighLocal`](crate::program::model::pcode::high_local::HighLocal), a
//! `HighOther` is not necessarily backed by any
//! [`HighSymbol`](crate::program::seam_stubs::HighSymbol) at all.
//!
//! In Java this `extends HighVariable`; see
//! [`high_local`](crate::program::model::pcode::high_local)'s module docs for the shared
//! "`extends X`" convention (composition, not inheritance) this port follows, and for the
//! deliberate deviation of storing the representative internally as `Option<Varnode>` (panicking
//! with a descriptive message if read before it is attached, the closest faithful analogue of
//! Java's `null` field).
//!
//! # Known gap: `decodeInstances` and the `represent`-dependent parts of `decode`
//! Same gap as [`HighLocal::decode`](crate::program::model::pcode::high_local::HighLocal::decode):
//! [`HighVariable::decode_instances`] is a documented no-op pending
//! `HighFunction.getRef`/`PcodeDataTypeManager` support, so it does not populate `represent` here
//! either. Java's `decode` then unconditionally computes `pcaddr = function.getPCAddress(represent)`
//! from that (still-unset) representative; this port instead only computes `pcaddr` when a
//! representative happens to already be attached (e.g. via [`HighOther::new`]), leaving it `None`
//! otherwise rather than panicking through [`HighVariable::get_representative`].

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::high_variable::{HighVariable, HighVariableKind};
use crate::program::model::pcode::ids::{ATTRIB_OFFSET, ATTRIB_SYMREF};
use crate::program::model::pcode::Varnode;
use crate::program::seam_stubs::{share_data_type, HighSymbol, PlaceholderDataType};

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode HighOther", e)
}

/// Other forms of variable (typically compiler infrastructure). Port of
/// `ghidra.program.model.pcode.HighOther`.
pub struct HighOther {
    name: String,
    data_type: Option<Arc<dyn DataType>>,
    representative: Option<Varnode>,
    instances: Vec<Varnode>,
    offset: i32,
    function: Arc<dyn HighFunction>,
    pcaddr: Option<Address>,
    symbol: Option<Arc<dyn HighSymbol>>,
}

impl HighOther {
    /// Constructor for use with [`decode`](HighOther::decode). Port of `HighOther(HighFunction)`.
    pub fn new_for_decode(high: Arc<dyn HighFunction>) -> Self {
        HighOther {
            name: String::new(),
            data_type: None,
            representative: None,
            instances: Vec::new(),
            offset: -1,
            function: high,
            pcaddr: None,
            symbol: None,
        }
    }

    /// Construct a unique high NOT associated with a symbol. Port of
    /// `HighOther(DataType, Varnode, Varnode[], Address, HighFunction)`.
    pub fn new(
        data_type: Arc<dyn DataType>,
        vn: Varnode,
        inst: Option<Vec<Varnode>>,
        pc: Option<Address>,
        func: Arc<dyn HighFunction>,
    ) -> Self {
        let mut other = HighOther {
            name: String::new(),
            data_type: Some(data_type),
            representative: None,
            instances: Vec::new(),
            offset: -1,
            function: func,
            pcaddr: pc,
            symbol: None,
        };
        other.attach_instances(inst, vn);
        other
    }

    /// Instruction address the variable comes into scope within the function. Port of
    /// `HighOther.getPCAddress()`.
    pub fn get_pc_address(&self) -> Option<Address> {
        self.pcaddr.clone()
    }
}

impl HighVariable for HighOther {
    fn get_high_function(&self) -> Arc<dyn HighFunction> {
        self.function.clone()
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        match &self.data_type {
            Some(dt) => share_data_type(dt),
            None => Box::new(PlaceholderDataType),
        }
    }

    fn get_representative(&self) -> Varnode {
        self.representative
            .clone()
            .expect("HighOther::get_representative called before a representative was attached (decode() or new())")
    }

    fn get_instances(&self) -> Vec<Varnode> {
        self.instances.clone()
    }

    fn get_symbol(&self) -> Option<Arc<dyn HighSymbol>> {
        self.symbol.clone()
    }

    fn get_offset(&self) -> i32 {
        self.offset
    }

    fn set_representative(&mut self, rep: Varnode) {
        self.representative = Some(rep);
    }

    fn set_instances(&mut self, instances: Vec<Varnode>) {
        self.instances = instances;
    }

    fn kind(&self) -> HighVariableKind {
        HighVariableKind::Other
    }

    /// Port of `HighOther.decode(Decoder)`. See the module docs for the `decodeInstances`/
    /// `represent`-dependent gaps.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let mut symref: u64 = 0;
        self.offset = -1;
        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            }
            if attrib_id == ATTRIB_OFFSET.id {
                self.offset = decoder.read_signed_integer().map_err(decode_err)? as i32;
            } else if attrib_id == ATTRIB_SYMREF.id {
                symref = decoder.read_unsigned_integer().map_err(decode_err)?;
            }
        }

        // See the module docs: documented no-op pending HighFunction.getRef/
        // PcodeDataTypeManager support.
        self.decode_instances(decoder)?;

        self.name = "UNNAMED".to_string();
        // TODO(port): Java computes this unconditionally from `represent`, which
        // `decodeInstances` cannot currently populate; only attempt it when a representative
        // already happens to be attached (see module docs) rather than panicking.
        self.pcaddr = self
            .representative
            .as_ref()
            .and_then(|rep| self.function.get_pc_address(rep));

        if symref != 0 {
            let symbol = self.function.get_local_symbol_map().get_symbol(symref as i64);
            if let Some(symbol) = symbol {
                if self.offset < 0 {
                    self.name = symbol.get_name();
                }
                self.symbol = Some(symbol);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::model::pcode::pcode_exception::PcodeException;
    use crate::program::seam_stubs::LocalSymbolMap;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn ram_addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    struct MockHighSymbol {
        id: i64,
        name: String,
    }

    impl HighSymbol for MockHighSymbol {
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_name(&self) -> String {
            self.name.clone()
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

    struct MockHighFunction {
        local_symbols: HashMap<i64, Arc<dyn HighSymbol>>,
        pc_address: Option<Address>,
    }

    impl HighFunction for MockHighFunction {
        fn get_function(&self) -> Box<dyn crate::program::model::listing::Function> {
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
            Box::new(MockLocalSymbolMap { symbols: self.local_symbols.clone() })
        }
        fn get_global_symbol_map(&self) -> Arc<dyn crate::program::model::pcode::global_symbol_map::GlobalSymbolMap> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_pc_address(&self, _representative: &Varnode) -> Option<Address> {
            self.pc_address.clone()
        }
        fn grab_from_function(&mut self, _override_extrapop: i32, _include_default_names: bool, _do_override: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn decode(&mut self, _decoder: &dyn Decoder) -> Result<(), DecoderException> {
            unimplemented!("not needed for this smoke test")
        }
        fn split_out_merge_group(
            &mut self,
            _high: Box<dyn HighVariable>,
            _vn: &Varnode,
        ) -> Result<Box<dyn HighVariable>, PcodeException> {
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

    /// Emits `ATTRIB_OFFSET` and/or `ATTRIB_SYMREF` (in that order, whichever are `Some`), then
    /// end-of-attributes.
    struct MockDecoder {
        offset: Option<i64>,
        symref: Option<u64>,
        step: AtomicUsize,
    }

    impl Decoder for MockDecoder {
        fn get_address_factory(&self) -> Arc<dyn crate::program::model::address::AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn crate::program::model::address::AddressFactory>) {}
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
            let mut sequence = Vec::new();
            if self.offset.is_some() {
                sequence.push(ATTRIB_OFFSET.id);
            }
            if self.symref.is_some() {
                sequence.push(ATTRIB_SYMREF.id);
            }
            let step = self.step.fetch_add(1, Ordering::SeqCst);
            Ok(sequence.get(step).copied().unwrap_or(0))
        }
        fn rewind_attributes(&self) {}
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            Ok(self.offset.unwrap_or(0))
        }
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            Ok(self.symref.unwrap_or(0))
        }
        fn read_unsigned_integer_with_id(&self, _attrib_id: AttributeId) -> Result<u64, DecoderError> {
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
        fn read_space_with_id(&self, _attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
    }

    fn mock_function(symbols: HashMap<i64, Arc<dyn HighSymbol>>, pc: Option<Address>) -> Arc<dyn HighFunction> {
        Arc::new(MockHighFunction { local_symbols: symbols, pc_address: pc })
    }

    /// [`HighOther::new`] matches Java's "unique high NOT associated with a symbol" constructor:
    /// no symbol, empty name, `pcaddr`/representative/instances taken from the arguments.
    #[test]
    fn new_builds_symbol_less_variable() {
        let space = ram_space();
        let rep = Varnode::new(ram_addr(&space, 0x2000), 4);
        let pc = ram_addr(&space, 0x400000);
        let func = mock_function(HashMap::new(), None);

        let other = HighOther::new(Arc::new(PlaceholderDataType), rep.clone(), None, Some(pc.clone()), func);

        assert_eq!(other.get_name(), "");
        assert!(other.get_symbol().is_none());
        assert_eq!(other.get_representative(), rep);
        assert_eq!(other.get_pc_address(), Some(pc));
        assert_eq!(other.kind(), HighVariableKind::Other);
    }

    /// With no `symref` attribute, `decode` still names the variable "UNNAMED" and leaves the
    /// symbol unset -- matching Java's default before the `if (symref != 0)` branch.
    #[test]
    fn decode_without_symref_stays_unnamed_and_symbol_less() {
        let func = mock_function(HashMap::new(), None);
        let mut other = HighOther::new_for_decode(func);

        let decoder = MockDecoder { offset: None, symref: None, step: AtomicUsize::new(0) };
        HighVariable::decode(&mut other, &decoder).expect("decode should succeed");

        assert_eq!(other.get_name(), "UNNAMED");
        assert!(other.get_symbol().is_none());
        assert_eq!(other.get_offset(), -1);
    }

    /// A resolvable `symref` with no `offset` attribute (whole-symbol match) adopts the symbol's
    /// name, matching `if (symbol != null && offset < 0) name = symbol.getName();`.
    #[test]
    fn decode_with_symref_and_no_offset_adopts_symbol_name() {
        let mut symbols: HashMap<i64, Arc<dyn HighSymbol>> = HashMap::new();
        symbols.insert(9, Arc::new(MockHighSymbol { id: 9, name: "saved_reg".to_string() }));
        let func = mock_function(symbols, None);
        let mut other = HighOther::new_for_decode(func);

        let decoder = MockDecoder { offset: None, symref: Some(9), step: AtomicUsize::new(0) };
        HighVariable::decode(&mut other, &decoder).expect("decode should succeed");

        assert_eq!(other.get_name(), "saved_reg");
        assert!(other.get_symbol().is_some());
    }

    /// A resolvable `symref` combined with a non-negative `offset` (a partial/sub-piece match)
    /// keeps the "UNNAMED" name even though the symbol resolved, matching the real
    /// `offset < 0` guard.
    #[test]
    fn decode_with_symref_and_offset_keeps_unnamed() {
        let mut symbols: HashMap<i64, Arc<dyn HighSymbol>> = HashMap::new();
        symbols.insert(9, Arc::new(MockHighSymbol { id: 9, name: "saved_reg".to_string() }));
        let func = mock_function(symbols, None);
        let mut other = HighOther::new_for_decode(func);

        let decoder = MockDecoder { offset: Some(4), symref: Some(9), step: AtomicUsize::new(0) };
        HighVariable::decode(&mut other, &decoder).expect("decode should succeed");

        assert_eq!(other.get_name(), "UNNAMED");
        assert_eq!(other.get_offset(), 4);
        assert!(other.get_symbol().is_some());
    }

    /// `pcaddr` is computed from `function.getPCAddress(represent)` only when a representative is
    /// already attached (see module docs for why this differs from Java's unconditional read).
    #[test]
    fn decode_computes_pc_address_when_representative_already_attached() {
        let space = ram_space();
        let rep = Varnode::new(ram_addr(&space, 0x3000), 4);
        let pc = ram_addr(&space, 0x400500);
        let func = mock_function(HashMap::new(), Some(pc.clone()));
        let mut other = HighOther::new(Arc::new(PlaceholderDataType), rep, None, None, func);

        let decoder = MockDecoder { offset: None, symref: None, step: AtomicUsize::new(0) };
        HighVariable::decode(&mut other, &decoder).expect("decode should succeed");

        assert_eq!(other.get_pc_address(), Some(pc));
    }
}
