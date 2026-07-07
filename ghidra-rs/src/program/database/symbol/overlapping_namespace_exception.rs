use crate::program::model::address::Address;
use std::fmt;

/// Exception thrown when namespace ranges overlap unexpectedly.
///
/// Port of `ghidra.program.database.symbol.OverlappingNamespaceException`.
#[derive(Debug, Clone)]
pub struct OverlappingNamespaceException {
    start: Address,
    end: Address,
}

impl OverlappingNamespaceException {
    /// Creates a new exception for overlapping namespace ranges.
    ///
    /// # Arguments
    /// * `start` - the start address of the overlapping namespace
    /// * `end` - the end address of the overlapping namespace
    pub fn new(start: Address, end: Address) -> Self {
        Self { start, end }
    }

    /// Returns the start address of the overlapping namespace.
    pub fn start(&self) -> Address {
        self.start.clone()
    }

    /// Returns the end address of the overlapping namespace.
    pub fn end(&self) -> Address {
        self.end.clone()
    }
}

impl fmt::Display for OverlappingNamespaceException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Overlapping namespace from {} to {}",
            self.start.offset(),
            self.end.offset()
        )
    }
}

impl std::error::Error for OverlappingNamespaceException {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn create_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn new_stores_addresses() {
        let start = create_address(0x1000);
        let end = create_address(0x2000);
        let exc = OverlappingNamespaceException::new(start.clone(), end.clone());

        assert_eq!(exc.start().offset(), 0x1000);
        assert_eq!(exc.end().offset(), 0x2000);
    }

    #[test]
    fn start_returns_start_address() {
        let start = create_address(0x1000);
        let end = create_address(0x2000);
        let exc = OverlappingNamespaceException::new(start.clone(), end);

        let retrieved_start = exc.start();
        assert_eq!(retrieved_start.offset(), start.offset());
    }

    #[test]
    fn end_returns_end_address() {
        let start = create_address(0x1000);
        let end = create_address(0x2000);
        let exc = OverlappingNamespaceException::new(start, end.clone());

        let retrieved_end = exc.end();
        assert_eq!(retrieved_end.offset(), end.offset());
    }

    #[test]
    fn display_shows_address_offsets() {
        let start = create_address(0x1000);
        let end = create_address(0x2000);
        let exc = OverlappingNamespaceException::new(start, end);

        let msg = exc.to_string();
        assert!(msg.contains("1000"));
        assert!(msg.contains("2000"));
    }

    #[test]
    fn implements_error_trait() {
        let start = create_address(0x100);
        let end = create_address(0x200);
        let exc = OverlappingNamespaceException::new(start, end);

        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn clone_produces_equal_exception() {
        let start = create_address(0x1000);
        let end = create_address(0x2000);
        let exc1 = OverlappingNamespaceException::new(start, end);
        let exc2 = exc1.clone();

        assert_eq!(exc1.start().offset(), exc2.start().offset());
        assert_eq!(exc1.end().offset(), exc2.end().offset());
    }

    #[test]
    fn different_addresses_show_in_display() {
        let start = create_address(0x5000);
        let end = create_address(0x5100);
        let exc = OverlappingNamespaceException::new(start, end);

        let msg = exc.to_string();
        assert!(msg.contains("5000"));
        assert!(msg.contains("5100"));
    }

    #[test]
    fn debug_format_contains_addresses() {
        let start = create_address(0x100);
        let end = create_address(0x200);
        let exc = OverlappingNamespaceException::new(start, end);

        let s = format!("{:?}", exc);
        assert!(s.contains("OverlappingNamespaceException"));
    }
}
