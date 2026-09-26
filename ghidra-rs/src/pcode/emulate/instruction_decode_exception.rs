use crate::program::model::address::Address;
use std::fmt;

/// Exception thrown when instruction decoding fails.
///
/// Corresponds to `ghidra.pcode.emulate.InstructionDecodeException`.
///
/// # Deprecation
///
/// This type is deprecated since Ghidra 12.1 and is scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
#[derive(Debug, Clone)]
pub struct InstructionDecodeException {
    message: String,
    pc: Address,
}

impl InstructionDecodeException {
    /// Constructs an `InstructionDecodeException` with the given reason and program counter.
    pub fn new(reason: impl Into<String>, pc: Address) -> Self {
        let reason_str = reason.into();
        let message = format!("Instruction decode failed ({}), PC={}", reason_str, pc);
        Self { message, pc }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the program counter where the decode failed.
    pub fn program_counter(&self) -> &Address {
        &self.pc
    }
}

impl fmt::Display for InstructionDecodeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for InstructionDecodeException {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn constructs_with_reason_and_address() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        #[allow(deprecated)]
        let exc = InstructionDecodeException::new("unknown opcode", addr);

        assert_eq!(exc.message(), "Instruction decode failed (unknown opcode), PC=ram:0x1000");
    }

    #[test]
    fn program_counter_returns_original_address() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x2000);
        #[allow(deprecated)]
        let exc = InstructionDecodeException::new("bad format", addr);

        assert_eq!(exc.program_counter().offset(), 0x2000);
        assert_eq!(exc.program_counter().space().name(), "ram");
    }

    #[test]
    fn display_shows_formatted_message() {
        let space = AddressSpace::new("code", 32, 1, AddressSpaceType::Code, 0);
        let addr = space.address(0x100);
        #[allow(deprecated)]
        let exc = InstructionDecodeException::new("illegal instruction", addr);

        let msg = format!("{}", exc);
        assert!(msg.contains("Instruction decode failed"));
        assert!(msg.contains("illegal instruction"));
        assert!(msg.contains("PC="));
    }

    #[test]
    fn debug_format_is_implemented() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x500);
        #[allow(deprecated)]
        let exc = InstructionDecodeException::new("oops", addr);

        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("InstructionDecodeException"));
    }

    #[test]
    fn implements_error_trait() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        #[allow(deprecated)]
        let exc = InstructionDecodeException::new("test", addr);

        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn clones_preserves_state() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x3000);
        #[allow(deprecated)]
        let exc1 = InstructionDecodeException::new("clone test", addr);
        let exc2 = exc1.clone();

        assert_eq!(exc1.message(), exc2.message());
        assert_eq!(exc1.program_counter().offset(), exc2.program_counter().offset());
    }
}
