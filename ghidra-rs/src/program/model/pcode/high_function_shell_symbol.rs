//! Port of `ghidra.program.model.pcode.HighFunctionShellSymbol`.
//!
//! A function symbol that represents only a shell of (the name and address) the function, when no
//! other information is available.
//!
//! In Java this `extends HighSymbol`; see
//! [`high_label_symbol`](crate::program::model::pcode::high_label_symbol)'s module docs for the
//! shared "`extends X`" convention (composition, not inheritance), the
//! `PcodeDataTypeManager`-replaced-by-`Program`/`ProgramArchitecture` deviation, and the
//! `getHighFunction()` gap (`function == null` in Java for this constructor path too) -- all apply
//! identically here. [`ResolvedStorage`] is likewise reused rather than duplicated.
//!
//! # Additional deviation: `NameTransformer` replaces `dtmanage.getNameTransformer()`
//! `encode` calls `dtmanage.getNameTransformer().simplify(name)` to compute an "alternate" name;
//! `PcodeDataTypeManager` is not ported (see the module docs above for why it's replaced
//! elsewhere), so this port takes a
//! [`NameTransformer`](crate::program::model::symbol::NameTransformer) directly as a constructor
//! parameter in its place (callers with no real transformer can pass
//! [`IdentityNameTransformer`](crate::program::model::symbol::IdentityNameTransformer), under
//! which `altName == name` always and the `ATTRIB_LABEL` branch never fires -- matching a
//! `PcodeDataTypeManager` with no name-simplification rules configured).

use std::io;
use std::sync::Arc;

use crate::program::model::address::{Address, SpecialAddress};
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::ProgramArchitecture;
use crate::program::model::listing::{Program, VariableStorage};
use crate::program::model::pcode::address_xml::encode_addr;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::high_label_symbol::ResolvedStorage;
use crate::program::model::pcode::high_symbol::HighSymbol;
use crate::program::model::pcode::ids::{ATTRIB_ID, ATTRIB_LABEL, ATTRIB_NAME, ATTRIB_SIZE, ELEM_FUNCTION};
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::PlaceholderDataType;
use crate::program::model::symbol::NameTransformer;

/// Stand-in for a `null` `HighSymbol.function` field, matching
/// [`high_label_symbol`](crate::program::model::pcode::high_label_symbol)'s `AbsentHighFunction`.
struct AbsentHighFunction;

macro_rules! absent {
    () => {
        panic!(
            "this HighSymbol was constructed with no associated HighFunction (function == null \
             in Java); see high_function_shell_symbol.rs module docs"
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

/// A function symbol representing only a shell (name and address) of a function. Port of
/// `ghidra.program.model.pcode.HighFunctionShellSymbol`.
pub struct HighFunctionShellSymbol {
    id: i64,
    name: String,
    typelock: bool,
    namelock: bool,
    program: Arc<dyn Program>,
    storage: ResolvedStorage,
    name_transformer: Arc<dyn NameTransformer + Send + Sync>,
}

impl HighFunctionShellSymbol {
    /// Construct the function shell given a name and address. See the module docs for why this
    /// takes `program`/`program_arch`/`name_transformer` in place of Java's `manage:
    /// PcodeDataTypeManager`.
    ///
    /// Port of `HighFunctionShellSymbol(long, String, Address, PcodeDataTypeManager)`.
    pub fn new(
        id: i64,
        nm: impl Into<String>,
        addr: Address,
        program: Arc<dyn Program>,
        program_arch: Arc<dyn ProgramArchitecture>,
        name_transformer: Arc<dyn NameTransformer + Send + Sync>,
    ) -> Self {
        let storage = ResolvedStorage::resolve(program_arch, addr, 1);
        HighFunctionShellSymbol { id, name: nm.into(), typelock: true, namelock: true, program, storage, name_transformer }
    }

    /// Test-only shortcut; see
    /// [`HighLabelSymbol::new_with_storage`](crate::program::model::pcode::high_label_symbol::HighLabelSymbol)'s
    /// sibling for why.
    #[cfg(test)]
    fn new_with_storage(
        id: i64,
        nm: impl Into<String>,
        program: Arc<dyn Program>,
        storage: ResolvedStorage,
        name_transformer: Arc<dyn NameTransformer + Send + Sync>,
    ) -> Self {
        HighFunctionShellSymbol { id, name: nm.into(), typelock: true, namelock: true, program, storage, name_transformer }
    }
}

impl HighSymbol for HighFunctionShellSymbol {
    fn get_id(&self) -> i64 {
        self.id
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

    /// Overrides `HighSymbol.isGlobal()`. Port of `HighFunctionShellSymbol.isGlobal()`.
    fn is_global(&self) -> bool {
        true
    }

    /// Port of `HighFunctionShellSymbol.encode(Encoder)`. See the module docs for the
    /// `NameTransformer` deviation.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_FUNCTION)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.get_id() as u64)?;
        encoder.write_string(ATTRIB_NAME, &self.name)?;
        let alt_name = self.name_transformer.simplify(&self.name);
        if alt_name.as_ref() != self.name {
            encoder.write_string(ATTRIB_LABEL, &alt_name)?;
        }
        encoder.write_signed_integer(ATTRIB_SIZE, 1)?;
        let min_addr = self.storage.min_address().unwrap_or_else(SpecialAddress::no_address);
        encode_addr(encoder, &min_addr)?;
        encoder.close_element(ELEM_FUNCTION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::high_label_symbol::test_support::AlwaysEmptyProgramArchitecture;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::model::symbol::IdentityNameTransformer;
    use std::borrow::Cow;
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

    /// A `NameTransformer` that always strips a fixed prefix, letting tests exercise the
    /// `ATTRIB_LABEL` branch (which `IdentityNameTransformer` alone never can).
    struct StripPrefixTransformer(&'static str);
    impl NameTransformer for StripPrefixTransformer {
        fn simplify<'a>(&self, input: &'a str) -> Cow<'a, str> {
            match input.strip_prefix(self.0) {
                Some(rest) => Cow::Owned(rest.to_string()),
                None => Cow::Borrowed(input),
            }
        }
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<ElementId>,
        closed: Vec<ElementId>,
        strings: Vec<(AttributeId, String)>,
        unsigned: Vec<(AttributeId, u64)>,
        signed: Vec<(AttributeId, i64)>,
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
        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.signed.push((attrib_id, val));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.unsigned.push((attrib_id, val));
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

    /// `isGlobal()` overrides the `HighSymbol` placeholder default (`false`).
    #[test]
    fn is_global_is_always_true() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let sym = HighFunctionShellSymbol::new_with_storage(
            7,
            "shell_func",
            program,
            ResolvedStorage::Unassigned,
            Arc::new(IdentityNameTransformer),
        );
        assert!(sym.is_global());
        assert_eq!(sym.get_id(), 7);
    }

    /// With an identity name transformer, `altName == name` always, so `ATTRIB_LABEL` is never
    /// written -- matching a `PcodeDataTypeManager` with no simplification rules.
    #[test]
    fn encode_skips_label_when_name_transformer_is_identity() {
        let space = ram_space();
        let addr = Address::new(space, 0x1000);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let sym = HighFunctionShellSymbol::new_with_storage(
            1,
            "my_func",
            program,
            ResolvedStorage::Assigned(crate::program::model::pcode::Varnode::new(addr, 1)),
            Arc::new(IdentityNameTransformer),
        );

        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();

        assert_eq!(encoder.opened.first(), Some(&ELEM_FUNCTION));
        assert_eq!(encoder.closed.last(), Some(&ELEM_FUNCTION));
        assert!(encoder.unsigned.contains(&(ATTRIB_ID, 1)));
        assert!(encoder.strings.contains(&(ATTRIB_NAME, "my_func".to_string())));
        assert!(!encoder.strings.iter().any(|(id, _)| *id == ATTRIB_LABEL));
        assert!(encoder.signed.contains(&(ATTRIB_SIZE, 1)));
    }

    /// A `NameTransformer` that actually changes the name causes `ATTRIB_LABEL` to be written
    /// with the simplified form.
    #[test]
    fn encode_writes_label_when_name_transformer_changes_name() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let sym = HighFunctionShellSymbol::new_with_storage(
            2,
            "FUN_deadbeef",
            program,
            ResolvedStorage::Unassigned,
            Arc::new(StripPrefixTransformer("FUN_")),
        );

        let mut encoder = RecordingEncoder::default();
        sym.encode(&mut encoder).unwrap();

        assert!(encoder.strings.contains(&(ATTRIB_NAME, "FUN_deadbeef".to_string())));
        assert!(encoder.strings.contains(&(ATTRIB_LABEL, "deadbeef".to_string())));
    }

    /// [`ResolvedStorage::resolve`] (shared with
    /// [`high_label_symbol`](crate::program::model::pcode::high_label_symbol)) is exercised
    /// end-to-end through this class's public `new` too.
    #[test]
    fn new_falls_back_to_unassigned_storage_via_shared_resolve_storage() {
        let space = ram_space();
        let addr = Address::new(space, 0x2000);
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        let sym = HighFunctionShellSymbol::new(
            5,
            "shell",
            addr,
            program,
            Arc::new(AlwaysEmptyProgramArchitecture),
            Arc::new(IdentityNameTransformer),
        );

        assert!(sym.get_storage().is_unassigned_storage());
    }
}
