use crate::program::model::address::Address;
use std::fmt;

/// Exception thrown when an unimplemented instruction is encountered.
///
/// Corresponds to `ghidra.pcode.emulate.UnimplementedInstructionException`.
///
/// # Deprecation
///
/// This type is deprecated since Ghidra 12.1 and is scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
#[derive(Debug, Clone)]
pub struct UnimplementedInstructionException {
    message: String,
    addr: Address,
}

impl UnimplementedInstructionException {
    /// Constructs an `UnimplementedInstructionException` with the given instruction address.
    pub fn new(addr: Address) -> Self {
        let message = format!("Unimplemented instruction, PC={}", addr);
        Self { message, addr }
    }

    /// Returns the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the address of the unimplemented instruction.
    pub fn instruction_address(&self) -> &Address {
        &self.addr
    }
}

impl fmt::Display for UnimplementedInstructionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for UnimplementedInstructionException {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn constructs_with_address() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        #[allow(deprecated)]
        let exc = UnimplementedInstructionException::new(addr);

        assert_eq!(exc.message(), "Unimplemented instruction, PC=ram:00001000");
    }

    #[test]
    fn instruction_address_returns_original_address() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x2000);
        #[allow(deprecated)]
        let exc = UnimplementedInstructionException::new(addr);

        assert_eq!(exc.instruction_address().offset(), 0x2000);
        assert_eq!(exc.instruction_address().space().name(), "ram");
    }

    #[test]
    fn display_shows_formatted_message() {
        let space = AddressSpace::new("code", 32, 1, AddressSpaceType::Code, 0);
        let addr = space.address(0x100);
        #[allow(deprecated)]
        let exc = UnimplementedInstructionException::new(addr);

        let msg = format!("{}", exc);
        assert_eq!(msg, "Unimplemented instruction, PC=code:00000100");
    }

    #[test]
    fn debug_format_is_implemented() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x500);
        #[allow(deprecated)]
        let exc = UnimplementedInstructionException::new(addr);

        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("UnimplementedInstructionException"));
    }

    #[test]
    fn implements_error_trait() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        #[allow(deprecated)]
        let exc = UnimplementedInstructionException::new(addr);

        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn clones_preserves_state() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x3000);
        #[allow(deprecated)]
        let exc1 = UnimplementedInstructionException::new(addr);
        let exc2 = exc1.clone();

        assert_eq!(exc1.message(), exc2.message());
        assert_eq!(exc1.instruction_address().offset(), exc2.instruction_address().offset());
    }
}
