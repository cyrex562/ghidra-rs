//! Port of `ghidra.program.model.pcode.HighLocal`.
//!
//! A local variable in a function (as opposed to a global or a compiler-infrastructure
//! [`HighOther`](crate::program::model::pcode::high_other::HighOther)), always backed by a
//! [`HighSymbol`](crate::program::seam_stubs::HighSymbol).
//!
//! In Java this `extends HighVariable`. [`HighVariable`] has since been ported as its own trait
//! (see [`high_variable`](crate::program::model::pcode::high_variable)); following the
//! "`extends X`" convention established there for its own subclasses (composition, not
//! inheritance), [`HighLocal`] is a concrete struct implementing the [`HighVariable`] trait
//! directly, holding the protected `name`/`type`/`represent`/`instances`/`offset`/`function`
//! fields Java inherits from `HighVariable` plus its own private `pcaddr`/`symbol` fields.
//!
//! [`HighVariable::get_symbol`] is typed to return `Option<Arc<dyn
//! seam_stubs::HighSymbol>>` (not the newly-ported
//! [`high_symbol::HighSymbol`](crate::program::model::pcode::high_symbol::HighSymbol)): that is a
//! pre-existing characteristic of the already-ported [`HighVariable`] trait (see its own module
//! docs), not something this port introduces or attempts to fix.
//!
//! # Deliberate deviation: non-optional `Varnode` accessor over an internally-optional field
//! Java leaves `represent`/`instances`/`type` `null`/unset until `decodeInstances` (called from
//! [`decode`](HighLocal::decode)) populates them. [`HighVariable::get_representative`] has no
//! `Option` in its signature (it is a pre-existing, already-ported trait method), so this port
//! stores the representative internally as `Option<Varnode>` and has
//! [`get_representative`](HighLocal::get_representative) panic with a descriptive message if
//! called before it is set -- the closest faithful Rust analogue of Java returning `null` there
//! (any real caller immediately dereferences it and would NPE).
//!
//! # Known gap: `decodeInstances` and `symbol.setHighVariable(this)`
//! [`HighVariable::decode_instances`] (the protected `decodeInstances` this class's `decode`
//! calls) is a documented no-op on the already-ported [`HighVariable`] trait, pending
//! `HighFunction.getRef`/`PcodeDataTypeManager` access this crate does not expose yet (see that
//! trait's module docs). [`decode`](HighLocal::decode) still calls it faithfully (matching Java's
//! `decodeInstances(decoder)` call site exactly), but the representative/instances/data-type are
//! consequently *not* actually populated by this port's [`decode`](HighLocal::decode) the way
//! Java's is -- only the genuinely portable parts (the `symref`/`offset` attributes, resolving the
//! symbol via `LocalSymbolMap`, and the resulting name/`pcaddr`) are real. The trailing
//! `symbol.setHighVariable(this)` call (linking the resolved symbol back to this variable) is also
//! not reproducible: [`seam_stubs::HighSymbol`] only exposes a read-only `get_high_variable`
//! getter (no setter), and is held here via `Arc` (shared, not mutably borrowable) even if one
//! existed.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::high_variable::{HighVariable, HighVariableKind};
use crate::program::model::pcode::ids::ATTRIB_OFFSET;
use crate::program::model::pcode::Varnode;
use crate::program::seam_stubs::{share_data_type, HighSymbol, PlaceholderDataType};

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode HighLocal", e)
}

/// A local variable in a function. Port of `ghidra.program.model.pcode.HighLocal`.
pub struct HighLocal {
    name: String,
    data_type: Option<Arc<dyn DataType>>,
    representative: Option<Varnode>,
    instances: Vec<Varnode>,
    offset: i32,
    function: Arc<dyn HighFunction>,
    pcaddr: Option<Address>,
    symbol: Option<Arc<dyn HighSymbol>>,
}

impl HighLocal {
    /// Constructor for use with [`decode`](HighLocal::decode). Port of `HighLocal(HighFunction)`.
    pub fn new_for_decode(high: Arc<dyn HighFunction>) -> Self {
        HighLocal {
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

    /// Port of `HighLocal(DataType, Varnode, Varnode[], Address, HighSymbol)`.
    pub fn new(
        data_type: Arc<dyn DataType>,
        vn: Varnode,
        inst: Option<Vec<Varnode>>,
        pc: Option<Address>,
        sym: Arc<dyn HighSymbol>,
    ) -> Self {
        let mut local = HighLocal {
            name: sym.get_name(),
            data_type: Some(data_type),
            representative: None,
            instances: Vec::new(),
            offset: -1,
            function: sym.get_high_function(),
            pcaddr: pc,
            symbol: Some(sym),
        };
        local.attach_instances(inst, vn);
        local
    }

    /// Instruction address the variable comes into scope within the function. Port of
    /// `HighLocal.getPCAddress()`.
    pub fn get_pc_address(&self) -> Option<Address> {
        self.pcaddr.clone()
    }
}

impl HighVariable for HighLocal {
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
            .expect("HighLocal::get_representative called before a representative was attached (decode() or new())")
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
        HighVariableKind::Local
    }

    /// Port of `HighLocal.decode(Decoder)`. See the module docs for the `decodeInstances`/
    /// `setHighVariable` gaps.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let symref = decoder
            .read_unsigned_integer_with_id(crate::program::model::pcode::ids::ATTRIB_SYMREF)
            .map_err(decode_err)?;
        self.offset = -1;
        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            }
            if attrib_id == ATTRIB_OFFSET.id {
                self.offset = decoder.read_signed_integer().map_err(decode_err)? as i32;
                break;
            }
        }

        // See the module docs: this is a documented no-op pending HighFunction.getRef/
        // PcodeDataTypeManager support, so `represent`/`instances`/`type` are not actually
        // populated here the way Java's decodeInstances(decoder) populates them.
        self.decode_instances(decoder)?;

        let symbol = self.function.get_local_symbol_map().get_symbol(symref as i64);
        let symbol = symbol.ok_or_else(|| DecoderException::new("HighLocal is missing symbol"))?;

        if self.offset < 0 {
            self.name = symbol.get_name();
        } else {
            self.name = "UNNAMED".to_string();
        }
        self.pcaddr = symbol.get_pc_address();
        // TODO(port): `symbol.setHighVariable(this)` -- see module docs, not reproducible.
        self.symbol = Some(symbol);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::ids::{AttributeId, ElementId, ATTRIB_SYMREF};
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
        pc: Option<Address>,
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
        fn get_pc_address(&self) -> Option<Address> {
            self.pc.clone()
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

    /// Emits `ATTRIB_SYMREF` (always read first via `read_unsigned_integer_with_id`), then
    /// optionally an `ATTRIB_OFFSET` attribute, then end-of-attributes.
    struct MockDecoder {
        symref: u64,
        offset: Option<i64>,
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
            let step = self.step.fetch_add(1, Ordering::SeqCst);
            if step == 0 && self.offset.is_some() {
                Ok(ATTRIB_OFFSET.id)
            } else {
                Ok(0)
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
            Ok(self.offset.unwrap_or(0))
        }
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError> {
            assert_eq!(attrib_id, ATTRIB_SYMREF);
            Ok(self.symref)
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

    /// Proves the public two-constructor / `getPCAddress` / `getSymbol` / `kind` surface of
    /// [`HighLocal::new`] matches Java's `HighLocal(DataType, Varnode, Varnode[], Address,
    /// HighSymbol)`: name/offset/representative/instances are all taken from the arguments, not
    /// re-derived.
    #[test]
    fn new_populates_from_symbol_and_representative() {
        let space = ram_space();
        let rep = Varnode::new(ram_addr(&space, 0x1000), 4);
        let pc = ram_addr(&space, 0x400000);
        let backing_function: Arc<dyn HighFunction> =
            Arc::new(MockHighFunction { local_symbols: HashMap::new() });
        let sym: Arc<dyn HighSymbol> = Arc::new(MockHighSymbol {
            id: 5,
            name: "local_x".to_string(),
            pc: None,
            high_function: backing_function,
        });

        let local = HighLocal::new(
            Arc::new(PlaceholderDataType),
            rep.clone(),
            None,
            Some(pc.clone()),
            sym,
        );

        assert_eq!(local.get_name(), "local_x");
        assert_eq!(local.get_representative(), rep.clone());
        assert_eq!(local.get_instances(), vec![rep]);
        assert_eq!(local.get_pc_address(), Some(pc));
        assert_eq!(local.kind(), HighVariableKind::Local);
        assert!(local.get_symbol().is_some());
    }

    /// [`HighLocal::get_representative`] panics rather than silently fabricating data when called
    /// before a representative is attached -- the closest faithful analogue of Java's `null`
    /// `represent` field (any real caller immediately dereferences it and NPEs).
    #[test]
    #[should_panic(expected = "before a representative was attached")]
    fn get_representative_panics_before_decode() {
        let function: Arc<dyn HighFunction> =
            Arc::new(MockHighFunction { local_symbols: HashMap::new() });
        let local = HighLocal::new_for_decode(function);
        let _ = local.get_representative();
    }

    /// Exercises the genuinely-portable part of [`HighLocal::decode`]: resolving the symbol
    /// referenced by `symref` via the function's `LocalSymbolMap`, and deriving `name`/`pcaddr`
    /// from it when no `offset` attribute is present (offset stays `-1` -> whole-symbol match).
    #[test]
    fn decode_resolves_symbol_and_name_when_whole_match() {
        let space = ram_space();
        let pc = ram_addr(&space, 0x400100);
        let mut symbols: HashMap<i64, Arc<dyn HighSymbol>> = HashMap::new();
        symbols.insert(
            77,
            Arc::new(MockHighSymbol {
                id: 77,
                name: "param_1".to_string(),
                pc: Some(pc.clone()),
                high_function: Arc::new(MockHighFunction { local_symbols: HashMap::new() }),
            }),
        );
        let function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { local_symbols: symbols });
        let mut local = HighLocal::new_for_decode(function);

        let decoder = MockDecoder { symref: 77, offset: None, step: AtomicUsize::new(0) };
        HighVariable::decode(&mut local, &decoder).expect("decode should succeed");

        assert_eq!(local.get_name(), "param_1");
        assert_eq!(local.get_offset(), -1);
        assert_eq!(local.get_pc_address(), Some(pc));
    }

    /// When an `offset` attribute is present (a partial/sub-piece match), Java names the variable
    /// "UNNAMED" instead of taking the symbol's name.
    #[test]
    fn decode_with_offset_attribute_names_variable_unnamed() {
        let mut symbols: HashMap<i64, Arc<dyn HighSymbol>> = HashMap::new();
        symbols.insert(
            3,
            Arc::new(MockHighSymbol {
                id: 3,
                name: "struct_var".to_string(),
                pc: None,
                high_function: Arc::new(MockHighFunction { local_symbols: HashMap::new() }),
            }),
        );
        let function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { local_symbols: symbols });
        let mut local = HighLocal::new_for_decode(function);

        let decoder = MockDecoder { symref: 3, offset: Some(4), step: AtomicUsize::new(0) };
        HighVariable::decode(&mut local, &decoder).expect("decode should succeed");

        assert_eq!(local.get_name(), "UNNAMED");
        assert_eq!(local.get_offset(), 4);
    }

    /// Java throws `DecoderException("HighLocal is missing symbol")` when the `symref` doesn't
    /// resolve; this port raises the equivalent error rather than panicking or fabricating a
    /// symbol.
    #[test]
    fn decode_errors_when_symbol_reference_is_unresolved() {
        let function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { local_symbols: HashMap::new() });
        let mut local = HighLocal::new_for_decode(function);

        let decoder = MockDecoder { symref: 999, offset: None, step: AtomicUsize::new(0) };
        let err = HighVariable::decode(&mut local, &decoder).unwrap_err();
        assert_eq!(err.to_string(), "Decoding error: HighLocal is missing symbol");
    }
}
