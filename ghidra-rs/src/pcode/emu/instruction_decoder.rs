use crate::program::model::address::Address;
use crate::program::model::lang::Language;
use crate::program::model::listing::Instruction;
use crate::pcode::seam_stubs::{PseudoInstruction, RegisterValue};
use std::sync::Arc;

/// A means of decoding machine instructions from the bytes contained in the machine state.
///
/// Corresponds to `ghidra.pcode.emu.InstructionDecoder`.
pub trait InstructionDecoder: Send + Sync {
    /// Get the language for this decoder.
    fn get_language(&self) -> Arc<dyn Language>;

    /// Decode the instruction starting at the given address using the given context.
    ///
    /// This method cannot return null. If a decode error occurs, it must throw an exception.
    ///
    /// # Arguments
    /// * `address` - the address to start decoding
    /// * `context` - the disassembler/decode context, or `None` (Java's `null`) for a language
    ///   with no context register
    ///
    /// # Returns
    /// the decoded instruction
    fn decode_instruction(
        &mut self,
        address: &Address,
        context: Option<&dyn RegisterValue>,
    ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>>;

    /// Inform the decoder that the emulator thread just branched.
    ///
    /// # Arguments
    /// * `address` - the address of the branch
    fn branched(&mut self, address: &Address);

    /// Get the last instruction decoded.
    ///
    /// # Returns
    /// the instruction
    fn get_last_instruction(&self) -> Option<Arc<dyn Instruction>>;

    /// Get the length of the last decoded instruction, including delay slots.
    ///
    /// # Returns
    /// the length
    fn get_last_length_with_delays(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::seam_stubs::{PseudoInstruction, RegisterValue};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockPseudoInstruction;
    impl PseudoInstruction for MockPseudoInstruction {}

    struct MockRegisterValue;
    impl RegisterValue for MockRegisterValue {}

    struct TestDecoder {
        last_length_with_delays: i32,
    }

    impl InstructionDecoder for TestDecoder {
        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("test decoder should not call get_language")
        }

        fn decode_instruction(
            &mut self,
            _address: &Address,
            _context: Option<&dyn RegisterValue>,
        ) -> Result<Box<dyn PseudoInstruction>, Box<dyn std::error::Error>> {
            Ok(Box::new(MockPseudoInstruction))
        }

        fn branched(&mut self, _address: &Address) {}

        fn get_last_instruction(&self) -> Option<Arc<dyn Instruction>> {
            None
        }

        fn get_last_length_with_delays(&self) -> i32 {
            self.last_length_with_delays
        }
    }

    #[test]
    fn test_decoder_last_length() {
        let decoder = TestDecoder {
            last_length_with_delays: 8,
        };

        assert_eq!(decoder.get_last_length_with_delays(), 8);
    }

    #[test]
    fn test_decoder_no_instruction() {
        let decoder = TestDecoder {
            last_length_with_delays: 0,
        };

        assert!(decoder.get_last_instruction().is_none());
    }

    #[test]
    fn test_decode_instruction_succeeds() {
        let mut decoder = TestDecoder {
            last_length_with_delays: 4,
        };

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        let ctx = MockRegisterValue;

        let result = decoder.decode_instruction(&addr, Some(&ctx));
        assert!(result.is_ok());
    }

    #[test]
    fn test_branched_method() {
        let mut decoder = TestDecoder {
            last_length_with_delays: 4,
        };

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x2000);

        decoder.branched(&addr);
        assert_eq!(decoder.get_last_length_with_delays(), 4);
    }
}
