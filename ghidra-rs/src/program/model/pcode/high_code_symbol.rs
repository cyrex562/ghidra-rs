//! Port of `ghidra.program.model.pcode.HighCodeSymbol`.
//!
//! A global symbol as part of the decompiler's model of a function. This symbol can be backed by
//! a formal [`CodeSymbol`], obtained via [`HighCodeSymbol::get_code_symbol`]. This symbol can also
//! be backed by a formal [`Data`] object, obtained via [`HighCodeSymbol::get_data`]. If there is a
//! backing `CodeSymbol`, this takes its name; otherwise the name is dynamically generated (via
//! `SymbolUtilities`, not modeled here). The data-type attached to this does not necessarily match
//! the backing `CodeSymbol` or `Data` object.
//!
//! The Java class `extends HighSymbol`, whose real port is not complete yet (only a minimal
//! placeholder lives at [`crate::program::seam_stubs::HighSymbol`]); this type was selected as a
//! dependency-cycle cut-point, so it is promoted straight to a trait with that placeholder as its
//! supertrait bound, following the precedent of
//! [`HighConstant`](crate::program::model::pcode::high_constant::HighConstant) (also a
//! `HighSymbol` subclass cut at the same seam; [`HighVariable`](crate::program::model::pcode::high_variable::HighVariable)
//! has since been ported as its own trait). The placeholder was grown with a
//! `decode` default (`HighSymbol.decode(Decoder)`) so this trait's default `decode` method has
//! something to build on; see `STUBS.tsv`.
//!
//! The three Java constructors (which build a backing [`SymbolEntry`]/`MappedDataEntry` from a
//! `CodeSymbol`, an address+size, or a `Data` object) are construction-time wiring rather than
//! public API and have no Rust trait equivalent; implementors are expected to perform that setup
//! themselves and expose the result through [`get_code_symbol`](HighCodeSymbol::get_code_symbol)
//! and [`get_data`](HighCodeSymbol::get_data).

use std::sync::Arc;

use crate::program::database::symbol::CodeSymbol;
use crate::program::model::listing::Data;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::seam_stubs::HighSymbol;

/// A global symbol as part of the decompiler's model of a function. Port of
/// `ghidra.program.model.pcode.HighCodeSymbol`.
pub trait HighCodeSymbol: HighSymbol {
    /// Overrides `HighSymbol.isGlobal()`; a `HighCodeSymbol` is always global. Named the same as
    /// the supertrait method (mirroring
    /// [`CodeSymbol::is_primary`](crate::program::database::symbol::CodeSymbol::is_primary)
    /// overriding `Symbol::is_primary`); callers going through a `dyn HighCodeSymbol` must
    /// disambiguate with `HighCodeSymbol::is_global(&x)` to reach this override rather than the
    /// placeholder's default `false`.
    fn is_global(&self) -> bool {
        true
    }

    /// Get the `CodeSymbol` backing this, if it exists. Stands in for
    /// `HighCodeSymbol.getCodeSymbol()`.
    fn get_code_symbol(&self) -> Option<Arc<dyn CodeSymbol>>;

    /// Get the `Data` object backing this, if it exists. Stands in for
    /// `HighCodeSymbol.getData()` (which inspects `entryList[0]` for a `MappedDataEntry`; the
    /// underlying `SymbolEntry`/`MappedEntry`/`MappedDataEntry` hierarchy is not modeled
    /// separately here, so implementors are expected to track and hand back the backing `Data`
    /// object directly).
    fn get_data(&self) -> Option<Box<dyn Data>>;

    /// Stands in for the private `symbol` field setter, needed by [`HighCodeSymbol::decode`]'s
    /// default body to clear the backing `CodeSymbol` after decode: a `HighCodeSymbol` restored
    /// from a decompiler stream is never linked back to a live database symbol.
    fn clear_code_symbol(&mut self);

    /// Decode this symbol from a stream, overriding `HighSymbol.decode(Decoder)`. Mirrors
    /// `super.decode(decoder); symbol = null;`.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        HighSymbol::decode(self, decoder)?;
        self.clear_code_symbol();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::model::symbol::{Namespace, SourceType, Symbol, SymbolType};
    use crate::program::util::ProgramLocation;
    use crate::program::model::pcode::high_function::HighFunction;
    use std::sync::Arc;

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockCodeSymbol {
        id: i64,
        name: String,
        address: Address,
    }

    impl Symbol for MockCodeSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    impl CodeSymbol for MockCodeSymbol {
        fn delete_with_option(&mut self, _keep_references: bool) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn code_unit_containing(
            &self,
            _address: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }
        fn check_is_primary(&self) -> bool {
            true
        }
        fn primary_symbol_at_address(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn demote_primary_symbol(&mut self, _old: &Arc<dyn Symbol>) {}
        fn set_primary_flag(&mut self, _primary: bool) {}
        fn notify_primary_symbol_set(&mut self, _old_primary: Option<Arc<dyn Symbol>>) {}
        fn get_program_location(&self) -> Option<Box<dyn ProgramLocation>> {
            None
        }
        fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool {
            true
        }
        fn base_do_get_name(&self) -> String {
            self.name.clone()
        }
        fn validate_external_name_source(
            &self,
            _new_name: Option<&str>,
            source: SourceType,
        ) -> SourceType {
            source
        }
    }

    struct MockHighFunction;

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
        fn get_local_symbol_map(&self) -> Box<dyn crate::program::seam_stubs::LocalSymbolMap> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_global_symbol_map(
            &self,
        ) -> Arc<dyn crate::program::model::pcode::global_symbol_map::GlobalSymbolMap> {
            unimplemented!("not needed for this smoke test")
        }
        fn grab_from_function(&mut self, _override_extrapop: i32, _include_default_names: bool, _do_override: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn decode(
            &mut self,
            _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
        ) -> Result<(), crate::program::model::pcode::decoder_exception::DecoderException> {
            unimplemented!("not needed for this smoke test")
        }
        fn split_out_merge_group(
            &mut self,
            _high: Box<dyn crate::program::model::pcode::high_variable::HighVariable>,
            _vn: &crate::program::model::pcode::Varnode,
        ) -> Result<Box<dyn crate::program::model::pcode::high_variable::HighVariable>, crate::program::model::pcode::pcode_exception::PcodeException>
        {
            unimplemented!("not needed for this smoke test")
        }
        fn encode(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::encoder::Encoder,
            _id: i64,
            _namespace: &dyn crate::program::model::symbol::Namespace,
            _entry_point: Option<crate::program::model::address::Address>,
            _size: i32,
        ) -> std::io::Result<()> {
            unimplemented!("not needed for this smoke test")
        }
        fn set_volatile(&mut self, _vn: &crate::program::model::pcode::Varnode, _val: bool) {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// A no-op decoder used only to prove the default `decode` body threads a decoder through to
    /// `HighSymbol::decode` (also a no-op placeholder) without needing a real XML stream.
    struct NoopDecoder;

    impl Decoder for NoopDecoder {
        fn get_address_factory(
            &self,
        ) -> Arc<dyn crate::program::model::address::AddressFactory> {
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

    struct MockHighCodeSymbol {
        id: i64,
        code_symbol: Option<Arc<dyn CodeSymbol>>,
    }

    impl HighSymbol for MockHighCodeSymbol {
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            Arc::new(MockHighFunction)
        }
    }

    impl HighCodeSymbol for MockHighCodeSymbol {
        fn get_code_symbol(&self) -> Option<Arc<dyn CodeSymbol>> {
            self.code_symbol.clone()
        }
        fn get_data(&self) -> Option<Box<dyn Data>> {
            None
        }
        fn clear_code_symbol(&mut self) {
            self.code_symbol = None;
        }
    }

    fn plain_symbol() -> MockHighCodeSymbol {
        MockHighCodeSymbol {
            id: 42,
            code_symbol: Some(Arc::new(MockCodeSymbol {
                id: 42,
                name: "my_global".to_string(),
                address: ram_addr(0x1000),
            })),
        }
    }

    #[test]
    fn is_global_overrides_placeholder_default() {
        let sym = plain_symbol();
        // The `HighSymbol` placeholder defaults `is_global` to `false`; `HighCodeSymbol` must
        // override it to `true` regardless of any per-instance state.
        assert!(!HighSymbol::is_global(&sym));
        assert!(HighCodeSymbol::is_global(&sym));
    }

    #[test]
    fn get_code_symbol_returns_backing_symbol() {
        let sym = plain_symbol();
        let backing = sym.get_code_symbol().expect("should have a backing CodeSymbol");
        assert_eq!(backing.get_name(), "my_global");
        assert_eq!(backing.get_id(), 42);
    }

    #[test]
    fn decode_clears_backing_code_symbol() {
        let mut sym = plain_symbol();
        assert!(sym.get_code_symbol().is_some());

        let decoder = NoopDecoder;
        HighCodeSymbol::decode(&mut sym, &decoder).expect("decode should succeed");

        assert!(
            sym.get_code_symbol().is_none(),
            "decode() must clear the backing CodeSymbol, mirroring `symbol = null;`"
        );
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut boxed: Box<dyn HighCodeSymbol> = Box::new(plain_symbol());
        assert!(HighCodeSymbol::is_global(boxed.as_ref()));
        assert!(boxed.get_code_symbol().is_some());

        let decoder = NoopDecoder;
        HighCodeSymbol::decode(boxed.as_mut(), &decoder).expect("decode should succeed");
        assert!(boxed.get_code_symbol().is_none());
    }
}
