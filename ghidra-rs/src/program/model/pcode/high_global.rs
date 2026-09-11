//! Port of `ghidra.program.model.pcode.HighGlobal`.
//!
//! All references (per function) to a single global variable.
//!
//! In Java this `extends HighVariable`; see
//! [`high_local`](crate::program::model::pcode::high_local)'s module docs for the shared
//! "`extends X`" convention (composition, not inheritance) this port follows, and for the
//! deliberate deviation of storing the representative internally as `Option<Varnode>` (panicking
//! with a descriptive message if read before it is attached).
//!
//! # Known gaps in `decode`
//! - [`HighVariable::decode_instances`] is a documented no-op (see
//!   [`high_local`](crate::program::model::pcode::high_local)'s module docs), so `represent` is
//!   not populated by it here either.
//! - When the `symref` attribute is `0` or doesn't resolve to an existing global symbol, Java
//!   falls back to `GlobalSymbolMap.populateSymbol`/`.newSymbol` to synthesize one. Both need `&mut
//!   GlobalSymbolMap`, but [`HighFunction::get_global_symbol_map`] only ever hands back a shared
//!   `Arc<dyn GlobalSymbolMap>` -- the same architectural gap already documented on
//!   [`HighFunction::set_volatile`] ("marking a varnode volatile gives the `GlobalSymbolMap` a
//!   chance to populate an annotation, which needs mutable access that this trait's
//!   `Arc<dyn GlobalSymbolMap>`-returning `get_global_symbol_map` cannot provide"). That fallback
//!   is therefore not reachable from here and is left unimplemented: [`decode`](HighGlobal::decode)
//!   leaves the symbol unresolved (`None`) in that case instead of guessing or panicking.
//! - `symbol.setHighVariable(this)` is not reproducible: [`seam_stubs::HighSymbol`] only exposes a
//!   read-only `get_high_variable` getter (no setter), and is held here via `Arc` (shared, not
//!   mutably borrowable) even if one existed.

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
use crate::util::msg::Msg;

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode HighGlobal", e)
}

/// All references (per function) to a single global variable. Port of
/// `ghidra.program.model.pcode.HighGlobal`.
pub struct HighGlobal {
    name: String,
    data_type: Option<Arc<dyn DataType>>,
    representative: Option<Varnode>,
    instances: Vec<Varnode>,
    offset: i32,
    function: Arc<dyn HighFunction>,
    symbol: Option<Arc<dyn HighSymbol>>,
}

impl HighGlobal {
    /// Constructor for use with [`decode`](HighGlobal::decode). Port of
    /// `HighGlobal(HighFunction)`.
    pub fn new_for_decode(high: Arc<dyn HighFunction>) -> Self {
        HighGlobal {
            name: String::new(),
            data_type: None,
            representative: None,
            instances: Vec::new(),
            offset: -1,
            function: high,
            symbol: None,
        }
    }

    /// Port of `HighGlobal(HighSymbol, Varnode, Varnode[])`.
    pub fn new(sym: Arc<dyn HighSymbol>, vn: Varnode, inst: Option<Vec<Varnode>>) -> Self {
        let data_type: Arc<dyn DataType> = Arc::from(sym.get_data_type());
        let mut global = HighGlobal {
            name: sym.get_name(),
            data_type: Some(data_type),
            representative: None,
            instances: Vec::new(),
            offset: -1,
            function: sym.get_high_function(),
            symbol: Some(sym),
        };
        global.attach_instances(inst, vn);
        global
    }
}

impl HighVariable for HighGlobal {
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
            .expect("HighGlobal::get_representative called before a representative was attached (decode() or new())")
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
        HighVariableKind::Global
    }

    /// Port of `HighGlobal.decode(Decoder)`. See the module docs for the `decodeInstances`/
    /// `populateSymbol`/`newSymbol`/`setHighVariable` gaps.
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

        let symbol = if symref != 0 {
            self.function.get_global_symbol_map().get_symbol_by_id(symref as i64)
        } else {
            Msg::warn("HighGlobal", &"Missing symref attribute in <high> tag");
            None
        };

        // TODO(port): when `symbol` is still `None` here, Java synthesizes one via
        // `GlobalSymbolMap.populateSymbol`/`.newSymbol` -- see the module docs for why that
        // fallback is not reachable from this port (needs `&mut GlobalSymbolMap`, only `Arc<dyn
        // GlobalSymbolMap>` is available). `symbol` is left `None` in that case.
        if let Some(symbol) = &symbol {
            if self.offset < 0 {
                self.name = symbol.get_name();
            }
        }
        // TODO(port): `symbol.setHighVariable(this)` -- see module docs, not reproducible.
        self.symbol = symbol;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::global_symbol_map::GlobalSymbolMap;
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
        high_function: Arc<dyn HighFunction>,
    }

    impl HighSymbol for MockHighSymbol {
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            self.high_function.clone()
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    #[derive(Default)]
    struct MockGlobalSymbolMap {
        by_id: HashMap<i64, Arc<dyn HighSymbol>>,
    }

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
            id: i64,
            _addr: Address,
            _data_type: Option<Box<dyn DataType>>,
            _sz: i32,
        ) -> Arc<dyn HighSymbol> {
            Arc::new(MockHighSymbol {
                id,
                name: "synth_global".to_string(),
                high_function: Arc::new(MockHighFunction { by_id: HashMap::new() }),
            })
        }
        fn get_symbol_by_id(&self, id: i64) -> Option<Arc<dyn HighSymbol>> {
            self.by_id.get(&id).cloned()
        }
        fn get_symbol_by_address(&self, _addr: &Address) -> Option<Arc<dyn HighSymbol>> {
            None
        }
        fn get_symbols(&self) -> Box<dyn Iterator<Item = Arc<dyn HighSymbol>> + '_> {
            Box::new(self.by_id.values().cloned())
        }
    }

    struct MockHighFunction {
        by_id: HashMap<i64, Arc<dyn HighSymbol>>,
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
            unimplemented!("not needed for this smoke test")
        }
        fn get_global_symbol_map(&self) -> Arc<dyn GlobalSymbolMap> {
            Arc::new(MockGlobalSymbolMap { by_id: self.by_id.clone() })
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

    /// Emits `ATTRIB_OFFSET`/`ATTRIB_SYMREF` (whichever configured) then end-of-attributes.
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

    fn mock_function(map: MockGlobalSymbolMap) -> Arc<dyn HighFunction> {
        Arc::new(MockHighFunction { by_id: map.by_id })
    }

    /// [`HighGlobal::new`] matches Java's `HighGlobal(HighSymbol, Varnode, Varnode[])`: name and
    /// data type come from the symbol, not re-derived.
    #[test]
    fn new_takes_name_and_type_from_symbol() {
        let space = ram_space();
        let rep = Varnode::new(ram_addr(&space, 0x5000), 4);
        let sym: Arc<dyn HighSymbol> = Arc::new(MockHighSymbol {
            id: 1,
            name: "g_counter".to_string(),
            high_function: Arc::new(MockHighFunction { by_id: HashMap::new() }),
        });

        let global = HighGlobal::new(sym, rep.clone(), None);

        assert_eq!(global.get_name(), "g_counter");
        assert_eq!(global.get_representative(), rep);
        assert_eq!(global.kind(), HighVariableKind::Global);
        assert!(global.get_symbol().is_some());
    }

    /// Resolving an existing global symbol by id (the common case) adopts its name when there is
    /// no `offset` attribute (whole-symbol match).
    #[test]
    fn decode_resolves_existing_global_symbol_by_id() {
        let mut by_id: HashMap<i64, Arc<dyn HighSymbol>> = HashMap::new();
        by_id.insert(
            42,
            Arc::new(MockHighSymbol {
                id: 42,
                name: "g_existing".to_string(),
                high_function: Arc::new(MockHighFunction { by_id: HashMap::new() }),
            }),
        );
        let function = mock_function(MockGlobalSymbolMap { by_id });
        let mut global = HighGlobal::new_for_decode(function);

        let decoder = MockDecoder { offset: None, symref: Some(42), step: AtomicUsize::new(0) };
        HighVariable::decode(&mut global, &decoder).expect("decode should succeed");

        assert_eq!(global.get_name(), "g_existing");
        assert!(global.get_symbol().is_some());
    }

    /// An `offset` attribute (partial/sub-piece match) keeps the pre-decode name even though the
    /// symbol resolved, matching `if (offset < 0) name = symbol.getName();`.
    #[test]
    fn decode_with_offset_does_not_rename_from_resolved_symbol() {
        let mut by_id: HashMap<i64, Arc<dyn HighSymbol>> = HashMap::new();
        by_id.insert(
            7,
            Arc::new(MockHighSymbol {
                id: 7,
                name: "g_struct".to_string(),
                high_function: Arc::new(MockHighFunction { by_id: HashMap::new() }),
            }),
        );
        let function = mock_function(MockGlobalSymbolMap { by_id });
        let mut global = HighGlobal::new_for_decode(function);

        let decoder = MockDecoder { offset: Some(4), symref: Some(7), step: AtomicUsize::new(0) };
        HighVariable::decode(&mut global, &decoder).expect("decode should succeed");

        assert_eq!(global.get_name(), "");
        assert_eq!(global.get_offset(), 4);
        assert!(global.get_symbol().is_some());
    }

    /// A missing (`0`) or unresolvable `symref` leaves the symbol unresolved (`None`) rather than
    /// attempting the documented-as-unreachable synthesis fallback -- see the module docs.
    #[test]
    fn decode_leaves_symbol_unresolved_when_symref_missing() {
        let function = mock_function(MockGlobalSymbolMap::default());
        let mut global = HighGlobal::new_for_decode(function);

        let decoder = MockDecoder { offset: None, symref: None, step: AtomicUsize::new(0) };
        HighVariable::decode(&mut global, &decoder).expect("decode should succeed");

        assert!(global.get_symbol().is_none());
    }
}
