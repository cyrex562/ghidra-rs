//! Port of `ghidra.program.model.pcode.HighParam`.
//!
//! A high-level function parameter.
//!
//! In Java this `extends HighLocal`. Following the "`extends X`" convention established
//! throughout this crate's `HighVariable` hierarchy (composition, not inheritance -- see
//! [`high_local`](crate::program::model::pcode::high_local)'s module docs), [`HighParam`] embeds
//! a [`HighLocal`] with no extra `HighVariable`-trait state of its own, adding only the private
//! `slot` field and delegating every [`HighVariable`] method to the embedded value.
//!
//! [`HighVariableKind`] has no dedicated `Param` variant (only `Generic`/`Constant`/`Local`/
//! `Global`/`Other`; see that enum's own docs), so [`HighParam::kind`] is left at the embedded
//! [`HighLocal`]'s `Local` (its default via delegation) rather than growing the shared enum for
//! this port. [`HighVariable::as_param_slot`] already exists specifically for this
//! `instanceof HighParam` case ("Implementors representing a parameter are expected to override
//! this to return their slot"), so [`HighParam`] overrides that instead, matching the trait's own
//! documented intent.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::high_local::HighLocal;
use crate::program::model::pcode::high_variable::{HighVariable, HighVariableKind};
use crate::program::model::pcode::Varnode;
use crate::program::seam_stubs::HighSymbol;

/// A high-level function parameter. Port of `ghidra.program.model.pcode.HighParam`.
pub struct HighParam {
    base: HighLocal,
    slot: i32,
}

impl HighParam {
    /// Constructor for use with [`decode`](HighParam::decode). Port of `HighParam(HighFunction)`.
    pub fn new_for_decode(high: Arc<dyn HighFunction>) -> Self {
        HighParam { base: HighLocal::new_for_decode(high), slot: 0 }
    }

    /// Port of `HighParam(DataType, Varnode, Address, int, HighSymbol)`.
    pub fn new(tp: Arc<dyn DataType>, rep: Varnode, pc: Option<Address>, slot: i32, sym: Arc<dyn HighSymbol>) -> Self {
        HighParam { base: HighLocal::new(tp, rep, None, pc, sym), slot }
    }

    /// Get the slot or parameter index. Port of `HighParam.getSlot()`.
    pub fn get_slot(&self) -> i32 {
        self.slot
    }

    /// Instruction address the variable comes into scope within the function. Delegates to the
    /// embedded [`HighLocal`]. Port of the inherited `HighLocal.getPCAddress()`.
    pub fn get_pc_address(&self) -> Option<Address> {
        self.base.get_pc_address()
    }
}

impl HighVariable for HighParam {
    fn get_high_function(&self) -> Arc<dyn HighFunction> {
        self.base.get_high_function()
    }

    fn get_name(&self) -> String {
        self.base.get_name()
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        self.base.get_data_type()
    }

    fn get_representative(&self) -> Varnode {
        self.base.get_representative()
    }

    fn get_instances(&self) -> Vec<Varnode> {
        self.base.get_instances()
    }

    fn get_symbol(&self) -> Option<Arc<dyn HighSymbol>> {
        self.base.get_symbol()
    }

    fn get_offset(&self) -> i32 {
        self.base.get_offset()
    }

    fn set_representative(&mut self, rep: Varnode) {
        self.base.set_representative(rep);
    }

    fn set_instances(&mut self, instances: Vec<Varnode>) {
        self.base.set_instances(instances);
    }

    fn as_param_slot(&self) -> Option<i32> {
        Some(self.slot)
    }

    fn kind(&self) -> HighVariableKind {
        self.base.kind()
    }

    /// Port of `HighParam.decode(Decoder)`: `super.decode(decoder)` followed by taking the slot
    /// from the resolved symbol's category index.
    ///
    /// # Panics
    /// Panics if the embedded [`HighLocal::decode`] somehow succeeds without leaving a resolved
    /// symbol attached -- this cannot happen through the public API, since
    /// [`HighLocal::decode`] always either resolves a symbol or returns an error first (mirroring
    /// Java, where `getSymbol()` is likewise guaranteed non-null after a successful
    /// `super.decode(decoder)`).
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        HighVariable::decode(&mut self.base, decoder)?;
        let sym = self
            .base
            .get_symbol()
            .expect("HighLocal::decode guarantees a resolved symbol on success");
        self.slot = sym.get_category_index();
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
        category_index: i32,
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
        fn get_category_index(&self) -> i32 {
            self.category_index
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

    struct MockDecoder {
        symref: u64,
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
            let _ = self.step.fetch_add(1, Ordering::SeqCst);
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

    fn no_function() -> Arc<dyn HighFunction> {
        Arc::new(MockHighFunction { local_symbols: HashMap::new() })
    }

    /// [`HighParam::new`] mirrors Java's `HighParam(DataType, Varnode, Address, int, HighSymbol)`:
    /// the slot comes straight from the constructor argument, and the embedded [`HighLocal`]
    /// state (name/representative/pcaddr) comes from the symbol/arguments, matching
    /// `super(tp, rep, null, pc, sym)`.
    #[test]
    fn new_takes_slot_directly_and_delegates_rest_to_high_local() {
        let space = ram_space();
        let rep = Varnode::new(ram_addr(&space, 0x1000), 4);
        let pc = ram_addr(&space, 0x400000);
        let sym: Arc<dyn HighSymbol> = Arc::new(MockHighSymbol {
            id: 1,
            name: "param_0".to_string(),
            category_index: 0,
            high_function: no_function(),
        });

        let param = HighParam::new(Arc::new(crate::program::seam_stubs::PlaceholderDataType), rep.clone(), Some(pc.clone()), 2, sym);

        assert_eq!(param.get_slot(), 2);
        assert_eq!(param.get_name(), "param_0");
        assert_eq!(param.get_representative(), rep);
        assert_eq!(param.get_pc_address(), Some(pc));
        assert_eq!(param.as_param_slot(), Some(2));
        assert_eq!(param.kind(), HighVariableKind::Local);
    }

    /// [`HighParam::decode`] runs the embedded [`HighLocal::decode`] then overwrites `slot` from
    /// the resolved symbol's category index, matching `super.decode(decoder); slot =
    /// sym.getCategoryIndex();`.
    #[test]
    fn decode_takes_slot_from_resolved_symbol_category_index() {
        let mut symbols: HashMap<i64, Arc<dyn HighSymbol>> = HashMap::new();
        symbols.insert(
            10,
            Arc::new(MockHighSymbol {
                id: 10,
                name: "param_1".to_string(),
                category_index: 1,
                high_function: no_function(),
            }),
        );
        let function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { local_symbols: symbols });
        let mut param = HighParam::new_for_decode(function);
        assert_eq!(param.get_slot(), 0);

        let decoder = MockDecoder { symref: 10, step: AtomicUsize::new(0) };
        HighVariable::decode(&mut param, &decoder).expect("decode should succeed");

        assert_eq!(param.get_slot(), 1);
        assert_eq!(param.get_name(), "param_1");
    }

    /// Decode failures (e.g. an unresolvable `symref`) propagate through
    /// [`HighParam::decode`] unchanged, exactly like Java's `super.decode(decoder)` throwing
    /// before `slot` is ever touched.
    #[test]
    fn decode_propagates_high_local_decode_errors() {
        let function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { local_symbols: HashMap::new() });
        let mut param = HighParam::new_for_decode(function);

        let decoder = MockDecoder { symref: 404, step: AtomicUsize::new(0) };
        let err = HighVariable::decode(&mut param, &decoder).unwrap_err();
        assert_eq!(err.to_string(), "Decoding error: HighLocal is missing symbol");
        assert_eq!(param.get_slot(), 0);
    }
}
