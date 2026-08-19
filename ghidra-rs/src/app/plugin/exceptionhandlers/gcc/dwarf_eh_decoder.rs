//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder`.
//!
//! Decodes a sequence of program bytes to Ghidra addressing types.

use crate::app::plugin::exceptionhandlers::gcc::{DwarfEhDataApplicationMode, DwarfEhDataDecodeFormat};
use crate::app::seam_stubs::DwarfDecodeContext;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryAccessException;

/// Java `interface DwarfEHDecoder` -- a genuine extension point implemented by each of the
/// concrete Dwarf exception-handling decoders (one per encoding/application-mode combination),
/// each independently driven by [`GccExceptionAnalyzer`](crate::app::plugin::exceptionhandlers::gcc)
/// and [`RegionDescriptor`](crate::app::plugin::exceptionhandlers::gcc) while walking `.eh_frame`
/// data.
pub trait DwarfEHDecoder {
    /// Gets the exception handling data decoding format.
    fn get_data_format(&self) -> DwarfEhDataDecodeFormat;

    /// Gets the data application mode.
    fn get_data_application_mode(&self) -> DwarfEhDataApplicationMode;

    /// Whether or not this decoder is for decoding signed or unsigned data.
    fn is_signed(&self) -> bool;

    /// Gets the size of the encoded data.
    ///
    /// `program` is the program containing the data to be decoded.
    fn get_decode_size(&self, program: &dyn Program) -> i32;

    /// Decodes an integer value which is indicated by `context`.
    ///
    /// # Errors
    /// Returns `Err` if the data can't be read.
    fn decode(&self, context: &DwarfDecodeContext) -> Result<i64, MemoryAccessException>;

    /// Decodes the address which is indicated by `context`.
    ///
    /// # Errors
    /// Returns `Err` if the data can't be read.
    fn decode_address(&self, context: &DwarfDecodeContext) -> Result<Address, MemoryAccessException>;

    /// Gets this decoder's encoded data type.
    ///
    /// `program` is the program containing the data to be decoded.
    fn get_data_type(&self, program: &dyn Program) -> Box<dyn DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::seam_stubs::PlaceholderDataType;
    use std::sync::Arc;

    /// Minimal implementor exercising the trait surface end-to-end, standing in for one of the
    /// concrete decoders (e.g. `SLEB128DwarfEHDecoder`, unsigned `DW_EH_PE_absptr`,
    /// `DW_EH_PE_uleb128`). Mirrors the fixed answers that decoder gives per the Java LSB DWARF
    /// extensions spec: unsigned, ULEB128-encoded, absolute-pointer application mode.
    struct StubUleb128AbsPtrDecoder;

    impl DwarfEHDecoder for StubUleb128AbsPtrDecoder {
        fn get_data_format(&self) -> DwarfEhDataDecodeFormat {
            DwarfEhDataDecodeFormat::Uleb128
        }

        fn get_data_application_mode(&self) -> DwarfEhDataApplicationMode {
            DwarfEhDataApplicationMode::AbsPtr
        }

        fn is_signed(&self) -> bool {
            false
        }

        fn get_decode_size(&self, _program: &dyn Program) -> i32 {
            // ULEB128 is variable-length; the Java `AbstractDwarfEHDecoder` subclasses for it
            // report -1 (unknown ahead of decode).
            -1
        }

        fn decode(&self, context: &DwarfDecodeContext) -> Result<i64, MemoryAccessException> {
            if context.get_address().offset() < 0 {
                return Err(MemoryAccessException::new("negative address"));
            }
            Ok(0x2a)
        }

        fn decode_address(&self, context: &DwarfDecodeContext) -> Result<Address, MemoryAccessException> {
            let value = self.decode(context)?;
            context
                .get_address()
                .add(value)
                .map_err(|e| MemoryAccessException::new(e.to_string()))
        }

        fn get_data_type(&self, _program: &dyn Program) -> Box<dyn DataType> {
            Box::new(PlaceholderDataType)
        }
    }

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:64:default".to_string()
        }
    }

    fn ram_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn reports_uleb128_absptr_unsigned() {
        let decoder = StubUleb128AbsPtrDecoder;
        assert_eq!(decoder.get_data_format(), DwarfEhDataDecodeFormat::Uleb128);
        assert_eq!(
            decoder.get_data_application_mode(),
            DwarfEhDataApplicationMode::AbsPtr
        );
        assert!(!decoder.is_signed());
    }

    #[test]
    fn decode_size_is_variable() {
        let decoder = StubUleb128AbsPtrDecoder;
        let program = MockProgram;
        assert_eq!(decoder.get_decode_size(&program), -1);
    }

    #[test]
    fn decode_reads_value_from_context() {
        let decoder = StubUleb128AbsPtrDecoder;
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let context = DwarfDecodeContext::new(program, ram_address(0x1000), None, None);

        assert_eq!(decoder.decode(&context).unwrap(), 0x2a);
    }

    #[test]
    fn decode_address_offsets_from_context_address() {
        let decoder = StubUleb128AbsPtrDecoder;
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let context = DwarfDecodeContext::new(program, ram_address(0x1000), None, None);

        let decoded = decoder.decode_address(&context).unwrap();
        assert_eq!(decoded.offset(), 0x1000 + 0x2a);
    }

    #[test]
    fn get_data_type_returns_a_data_type() {
        let decoder = StubUleb128AbsPtrDecoder;
        let program = MockProgram;
        let dt = decoder.get_data_type(&program);
        assert_eq!(dt.get_length(), 0);
    }
}
