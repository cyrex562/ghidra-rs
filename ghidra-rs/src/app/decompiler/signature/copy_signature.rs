//! Port of `ghidra.app.decompiler.signature.CopySignature`.
//!
//! # Graduating the seam stub
//!
//! `crate::app::seam_stubs::CopySignature` was a placeholder standing in "before the real class
//! is ported," used only so [`decode_signatures`](crate::app::decompiler::signature::decode_signatures)
//! had something to construct and drive through the [`DebugSignature`] trait. This is that real
//! class; [`decode_signatures`] now dispatches `ELEM_COPYSIG` to this type instead, and the
//! placeholder has been removed from `seam_stubs`.

use crate::program::model::lang::language::Language;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::ids::{ATTRIB_HASH, ATTRIB_INDEX, ELEM_COPYSIG};

use super::debug_signature::{DebugSignature, DebugSignatureBase};

/// A feature representing 1 or more "stand-alone" copies in a basic block. A COPY operation is
/// considered stand-alone if either a constant or a function input is copied into a location that
/// is then not read directly by the function. These COPYs are incorporated into a single feature,
/// which encodes the number and type of COPYs but does not encode the order in which they occur
/// within the block.
///
/// Port of `ghidra.app.decompiler.signature.CopySignature`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CopySignature {
    /// The shared 32-bit feature hash. Port of the inherited `DebugSignature.hash` field.
    pub base: DebugSignatureBase,
    /// The basic block's index. Port of `CopySignature.index`.
    pub index: i32,
}

impl CopySignature {
    /// Creates a new, zeroed `CopySignature`, matching Java's implicit no-arg constructor (an
    /// instance with `hash == 0` and `index == 0` until [`Self::decode`] fills it in).
    pub fn new() -> Self {
        CopySignature { base: DebugSignatureBase::new(), index: 0 }
    }
}

impl DebugSignature for CopySignature {
    /// Port of `decode(Decoder)`.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let el = decoder.open_element_with_id(ELEM_COPYSIG).map_err(decode_err)?;
        self.base.hash = decoder.read_unsigned_integer_with_id(ATTRIB_HASH).map_err(decode_err)? as i32;
        self.index = decoder.read_signed_integer_with_id(ATTRIB_INDEX).map_err(decode_err)? as i32;
        decoder.close_element(el).map_err(decode_err)?;
        Ok(())
    }

    /// Port of `printRaw(Language, StringBuffer)`.
    fn print_raw(&self, _language: &dyn Language, buf: &mut String) {
        buf.push_str(&format!("{:x}", self.base.hash));
        buf.push_str(" - Copies in block ");
        buf.push_str(&self.index.to_string());
    }
}

fn decode_err(e: crate::program::model::pcode::decoder::DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode CopySignature", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpace};
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use std::sync::Arc;

    /// A `Decoder` double supplying exactly the `open_element`/attribute reads
    /// [`CopySignature::decode`] performs, in order.
    struct FixedDecoder {
        hash: u64,
        index: i64,
    }

    impl Decoder for FixedDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn open_element_with_id(&self, elem_id: ElementId) -> Result<i32, DecoderError> {
            assert_eq!(elem_id, ELEM_COPYSIG);
            Ok(1)
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            unimplemented!()
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            unimplemented!()
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
        fn read_signed_integer_with_id(&self, attrib_id: AttributeId) -> Result<i64, DecoderError> {
            assert_eq!(attrib_id, ATTRIB_INDEX);
            Ok(self.index)
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError> {
            assert_eq!(attrib_id, ATTRIB_HASH);
            Ok(self.hash)
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

    #[test]
    fn new_starts_zeroed() {
        let sig = CopySignature::new();
        assert_eq!(sig.base.hash, 0);
        assert_eq!(sig.index, 0);
        assert_eq!(sig, CopySignature::default());
    }

    #[test]
    fn decode_populates_hash_and_index() {
        let decoder = FixedDecoder { hash: 0xDEAD_BEEF, index: 7 };
        let mut sig = CopySignature::new();
        sig.decode(&decoder).unwrap();
        assert_eq!(sig.base.hash as u32, 0xDEAD_BEEF);
        assert_eq!(sig.index, 7);
    }

    #[test]
    fn print_raw_formats_hash_and_index() {
        let mut sig = CopySignature::new();
        sig.base.hash = 0xABCDu32 as i32;
        sig.index = 42;

        let mut buf = String::new();
        sig.print_raw(&UnusedLanguage, &mut buf);
        assert_eq!(buf, "abcd - Copies in block 42");
    }
}

/// `Language` double whose every method panics: [`CopySignature::print_raw`] never reads its
/// `language` argument (matching Java, where `printRaw`'s body never touches its `Language`
/// parameter either), so none of these methods are ever actually invoked by this module's tests.
/// Declared with full method coverage (rather than a handful of `unimplemented!()`s inline)
/// because [`Language`](crate::program::model::lang::language::Language) has no partial/stub
/// convenience trait to build on, unlike e.g. `InstructionStub` for `CodeUnit`.
#[cfg(test)]
struct UnusedLanguage;

#[cfg(test)]
impl crate::program::model::lang::language::Language for UnusedLanguage {
    fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
        unimplemented!("not exercised by this test")
    }
    fn get_language_description(
        &self,
    ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
        unimplemented!("not exercised by this test")
    }
    fn get_parallel_instruction_helper(
        &self,
    ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
    {
        unimplemented!("not exercised by this test")
    }
    fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
        unimplemented!("not exercised by this test")
    }
    fn get_version(&self) -> i32 {
        unimplemented!("not exercised by this test")
    }
    fn get_minor_version(&self) -> i32 {
        unimplemented!("not exercised by this test")
    }
    fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
        unimplemented!("not exercised by this test")
    }
    fn get_default_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
        unimplemented!("not exercised by this test")
    }
    fn get_default_data_space(&self) -> std::sync::Arc<crate::program::model::address::AddressSpace> {
        unimplemented!("not exercised by this test")
    }
    fn is_big_endian(&self) -> bool {
        unimplemented!("not exercised by this test")
    }
    fn get_instruction_alignment(&self) -> i32 {
        unimplemented!("not exercised by this test")
    }
    fn supports_pcode(&self) -> bool {
        unimplemented!("not exercised by this test")
    }
    fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
        unimplemented!("not exercised by this test")
    }
    fn parse(
        &self,
        _buf: &dyn crate::program::model::mem::MemBuffer,
        _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
        _in_delay_slot: bool,
    ) -> Result<
        Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
        crate::program::model::lang::language::ParseError,
    > {
        unimplemented!("not exercised by this test")
    }
    fn get_number_of_user_defined_op_names(&self) -> i32 {
        unimplemented!("not exercised by this test")
    }
    fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
        unimplemented!("not exercised by this test")
    }
    fn get_registers_at(
        &self,
        _address: &crate::program::model::address::Address,
    ) -> Vec<crate::program::model::lang::register::RegisterRef> {
        unimplemented!("not exercised by this test")
    }
    fn get_register_in_space(
        &self,
        _addrspc: &std::sync::Arc<crate::program::model::address::AddressSpace>,
        _offset: i64,
        _size: i32,
    ) -> Option<crate::program::model::lang::register::RegisterRef> {
        unimplemented!("not exercised by this test")
    }
    fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
        unimplemented!("not exercised by this test")
    }
    fn get_register_names(&self) -> Vec<String> {
        unimplemented!("not exercised by this test")
    }
    fn get_register_by_name(&self, _name: &str) -> Option<crate::program::model::lang::register::RegisterRef> {
        unimplemented!("not exercised by this test")
    }
    fn get_register_at(
        &self,
        _addr: &crate::program::model::address::Address,
        _size: i32,
    ) -> Option<crate::program::model::lang::register::RegisterRef> {
        unimplemented!("not exercised by this test")
    }
    fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
        unimplemented!("not exercised by this test")
    }
    fn get_context_base_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
        unimplemented!("not exercised by this test")
    }
    fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
        unimplemented!("not exercised by this test")
    }
    fn get_default_memory_blocks(
        &self,
    ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
        unimplemented!("not exercised by this test")
    }
    fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
        unimplemented!("not exercised by this test")
    }
    fn get_segmented_space(&self) -> String {
        unimplemented!("not exercised by this test")
    }
    fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
        unimplemented!("not exercised by this test")
    }
    fn apply_context_settings(
        &self,
        _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
    ) {
        unimplemented!("not exercised by this test")
    }
    fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
        unimplemented!("not exercised by this test")
    }
    fn get_compatible_compiler_spec_descriptions(
        &self,
    ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
        unimplemented!("not exercised by this test")
    }
    fn get_compiler_spec_by_id(
        &self,
        _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
    ) -> Result<
        Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
        crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
    > {
        unimplemented!("not exercised by this test")
    }
    fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
        unimplemented!("not exercised by this test")
    }
    fn has_property(&self, _key: &str) -> bool {
        unimplemented!("not exercised by this test")
    }
    fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
        unimplemented!("not exercised by this test")
    }
    fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
        unimplemented!("not exercised by this test")
    }
    fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
        unimplemented!("not exercised by this test")
    }
    fn get_property(&self, _key: &str) -> Option<String> {
        unimplemented!("not exercised by this test")
    }
    fn get_property_keys(&self) -> std::collections::HashSet<String> {
        unimplemented!("not exercised by this test")
    }
    fn has_manual(&self) -> bool {
        unimplemented!("not exercised by this test")
    }
    fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
        unimplemented!("not exercised by this test")
    }
    fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
        unimplemented!("not exercised by this test")
    }
    fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
        unimplemented!("not exercised by this test")
    }
    fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
        unimplemented!("not exercised by this test")
    }
    fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
        unimplemented!("not exercised by this test")
    }
    fn get_maximum_instruction_length(&self) -> Option<i32> {
        unimplemented!("not exercised by this test")
    }
}
