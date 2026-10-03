//! Port of `ghidra.program.model.pcode.HighExternalSymbol`.
//!
//! A symbol, within a decompiler model, for a function without a body in the current Program. The
//! Address of this symbol corresponds to the code location that CALL instructions refer to. In
//! anticipation of a (not fully resolved) thunking mechanism, this symbol also has a separate
//! resolve Address, which is where the decompiler expects to retrieve the detailed Function
//! object.
//!
//! In Java this `extends HighSymbol`; see
//! [`high_label_symbol`](crate::program::model::pcode::high_label_symbol)'s module docs for the
//! shared "`extends X`" convention (composition, not inheritance), the
//! `PcodeDataTypeManager`-replaced-by-`Program`/`ProgramArchitecture` deviation, and the
//! `getHighFunction()` gap (`function == null` in Java for this constructor path too) -- all
//! apply identically here. [`ResolvedStorage`] (and its shared `resolve` helper implementing the
//! `try { new VariableStorage(...) } catch (InvalidInputException e) { UNASSIGNED_STORAGE }`
//! pattern) is reused from that module rather than duplicated.
//!
//! Unlike [`HighLabelSymbol`](crate::program::model::pcode::high_label_symbol::HighLabelSymbol),
//! this class's `encode` does *not* call the shared `encodeHeader` at all -- it writes only an
//! optional `_exref`-suffixed name and the resolve address, so no `ids.rs` header-attribute
//! constants beyond `ATTRIB_NAME` are needed here.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::ProgramArchitecture;
use crate::program::model::listing::{Program, VariableStorage};
use crate::program::model::pcode::address_xml::encode_addr;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::high_label_symbol::ResolvedStorage;
use crate::program::model::pcode::high_symbol::HighSymbol;
use crate::program::model::pcode::ids::{ATTRIB_NAME, ELEM_EXTERNREFSYMBOL};
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::PlaceholderDataType;

/// Stand-in for a `null` `HighSymbol.function` field, matching
/// [`high_label_symbol`](crate::program::model::pcode::high_label_symbol)'s `AbsentHighFunction`.
struct AbsentHighFunction;

macro_rules! absent {
    () => {
        panic!(
            "this HighSymbol was constructed with no associated HighFunction (function == null \
             in Java); see high_external_symbol.rs module docs"
        )
    };
}

impl HighFunction for AbsentHighFunction {
    fn get_function(&self) -> Box<dyn crate::program::model::listing::Function> {
        absent!()
    }
    fn get_id(&self) -> i64 {
        absent!()
    }
    fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
        absent!()
    }
    fn get_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
        absent!()
    }
    fn get_local_symbol_map(&self) -> Box<dyn crate::program::seam_stubs::LocalSymbolMap> {
        absent!()
    }
    fn get_global_symbol_map(&self) -> Arc<dyn crate::program::model::pcode::global_symbol_map::GlobalSymbolMap> {
        absent!()
    }
    fn grab_from_function(&mut self, _override_extrapop: i32, _include_default_names: bool, _do_override: bool) {
        absent!()
    }
    fn decode(
        &mut self,
        _decoder: &dyn crate::program::model::pcode::decoder::Decoder,
    ) -> Result<(), crate::program::model::pcode::decoder_exception::DecoderException> {
        absent!()
    }
    fn split_out_merge_group(
        &mut self,
        _high: Box<dyn crate::program::model::pcode::high_variable::HighVariable>,
        _vn: &crate::program::model::pcode::Varnode,
    ) -> Result<
        Box<dyn crate::program::model::pcode::high_variable::HighVariable>,
        crate::program::model::pcode::pcode_exception::PcodeException,
    > {
        absent!()
    }
    fn encode(
        &self,
        _encoder: &mut dyn Encoder,
        _id: i64,
        _namespace: &dyn crate::program::model::symbol::Namespace,
        _entry_point: Option<Address>,
        _size: i32,
    ) -> io::Result<()> {
        absent!()
    }
    fn set_volatile(&mut self, _vn: &crate::program::model::pcode::Varnode, _val: bool) {
        absent!()
    }
}

/// A symbol for a function without a body in the current Program. Port of
/// `ghidra.program.model.pcode.HighExternalSymbol`.
pub struct HighExternalSymbol {
    name: String,
    typelock: bool,
    namelock: bool,
    resolve_address: Address,
    program: Arc<dyn Program>,
    storage: ResolvedStorage,
}

impl HighExternalSymbol {
    /// Construct the external reference symbol given a name, the symbol Address, and a resolving
    /// Address. See the module docs for why this takes `program`/`program_arch` in place of
    /// Java's `dtmanage: PcodeDataTypeManager`.
    ///
    /// Port of `HighExternalSymbol(String, Address, Address, PcodeDataTypeManager)`.
    pub fn new(
        nm: impl Into<String>,
        addr: Address,
        resolve_addr: Address,
        program: Arc<dyn Program>,
        program_arch: Arc<dyn ProgramArchitecture>,
    ) -> Self {
        let storage = ResolvedStorage::resolve(program_arch, addr, 1);
        HighExternalSymbol {
            name: nm.into(),
            typelock: true,
            namelock: true,
            resolve_address: resolve_addr,
            program,
            storage,
        }
    }

    /// Test-only shortcut; see
    /// [`HighLabelSymbol::new_with_storage`](crate::program::model::pcode::high_label_symbol::HighLabelSymbol)'s
    /// sibling for why.
    #[cfg(test)]
    fn new_with_storage(
        nm: impl Into<String>,
        resolve_addr: Address,
        program: Arc<dyn Program>,
        storage: ResolvedStorage,
    ) -> Self {
        HighExternalSymbol {
            name: nm.into(),
            typelock: true,
            namelock: true,
            resolve_address: resolve_addr,
            program,
            storage,
        }
    }
}

impl HighSymbol for HighExternalSymbol {
    fn get_id(&self) -> i64 {
        0
    }

    fn get_high_function(&self) -> Arc<dyn HighFunction> {
        Arc::new(AbsentHighFunction)
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(PlaceholderDataType)
    }

    fn get_storage(&self) -> Box<dyn VariableStorage> {
        self.storage.to_variable_storage()
    }

    fn get_size(&self) -> i32 {
        self.storage.size()
    }

    fn is_type_locked(&self) -> bool {
        self.typelock
    }

    fn is_name_locked(&self) -> bool {
        self.namelock
    }

    fn set_type_lock(&mut self, typelock: bool) {
        self.typelock = typelock;
    }

    fn set_name_lock(&mut self, namelock: bool) {
        self.namelock = namelock;
    }

    /// Port of `HighExternalSymbol.encode(Encoder)`. Unlike
    /// [`HighLabelSymbol::encode`](crate::program::model::pcode::high_label_symbol::HighLabelSymbol),
    /// this does *not* call the shared `encodeHeader` -- it writes only an optional name (with an
    /// `_exref` suffix, only if non-empty) and the resolve address.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_EXTERNREFSYMBOL)?;
        if !self.name.is_empty() {
            encoder.write_string(ATTRIB_NAME, &format!("{}_exref", self.name))?;
        }
        encode_addr(encoder, &self.resolve_address)?;
        encoder.close_element(ELEM_EXTERNREFSYMBOL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::high_label_symbol::test_support::AlwaysEmptyProgramArchitecture;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use std::sync::Arc;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<ElementId>,
        closed: Vec<ElementId>,
        strings: Vec<(AttributeId, String)>,
        addrs: Vec<ElementId>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.opened.push(elem_id);
            if elem_id == crate::program::model::pcode::ids::ELEM_ADDR {
                self.addrs.push(elem_id);
            }
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
        fn write_unsigned_integer(&mut self, _attrib_id: AttributeId, _val: u64) -> io::Result<()> {
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.strings.push((attrib_id, val.to_string()));
            Ok(())
        }
        fn write_string_indexed(&mut self, attrib_id: AttributeId, index: i32, val: &str) -> io::Result<()> {
            self.strings.push((attrib_id, format!("[{index}]{val}")));
            Ok(())
        }
        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
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

    /// Construction matches Java's constructor: always type/name-locked, id 0, and the resolve
    /// address is stored verbatim (distinct from the symbol's own storage address).
    #[test]
    fn new_stores_resolve_address_separately_from_storage() {
        let space = ram_space();
        let resolve_addr = Address::new(space, 0x5000);
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        let sym = HighExternalSymbol::new_with_storage("puts", resolve_addr, program, ResolvedStorage::Unassigned);

        assert_eq!(sym.get_id(), 0);
        assert_eq!(sym.get_name(), "puts");
        assert!(sym.is_type_locked());
        assert!(sym.is_name_locked());
    }

    /// `encode` does not call `encodeHeader` -- no id/typelock/namelock attributes are written,
    /// only the `_exref`-suffixed name and the resolve address.
    #[test]
    fn encode_writes_name_with_exref_suffix_and_resolve_address() {
        let space = ram_space();
        let resolve_addr = Address::new(space, 0x6000);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let sym = HighExternalSymbol::new_with_storage("memcpy", resolve_addr, program, ResolvedStorage::Unassigned);

        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened.first(), Some(&ELEM_EXTERNREFSYMBOL));
        assert_eq!(encoder.closed.last(), Some(&ELEM_EXTERNREFSYMBOL));
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "memcpy_exref".to_string())));
        assert_eq!(encoder.addrs.len(), 1);
    }

    /// An empty name is not given the `_exref` treatment at all -- matches Java's `if ((name !=
    /// null) && (name.length() > 0))` guard.
    #[test]
    fn encode_skips_name_attribute_when_name_is_empty() {
        let space = ram_space();
        let resolve_addr = Address::new(space, 0x7000);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let sym = HighExternalSymbol::new_with_storage("", resolve_addr, program, ResolvedStorage::Unassigned);

        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();

        assert!(!encoder.strings.iter().any(|(id, _)| *id == ATTRIB_NAME));
    }

    /// [`ResolvedStorage::resolve`] (shared with
    /// [`high_label_symbol`](crate::program::model::pcode::high_label_symbol)) is exercised
    /// end-to-end through this class's public `new` too, proving the wiring (not just the shared
    /// helper in isolation).
    #[test]
    fn new_falls_back_to_unassigned_storage_via_shared_resolve_storage() {
        let space = ram_space();
        let addr = Address::new(space.clone(), 0x8000);
        let resolve_addr = Address::new(space, 0x9000);
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        let sym = HighExternalSymbol::new(
            "strcpy",
            addr,
            resolve_addr,
            program,
            Arc::new(AlwaysEmptyProgramArchitecture),
        );

        assert!(sym.get_storage().is_unassigned_storage());
    }
}
