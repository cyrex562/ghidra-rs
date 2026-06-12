use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
use crate::program::model::mem::{MemoryAccessException, MemoryBlock, MemoryBlockType};

/// Test stub for `MemoryBlock`.
///
/// This mirrors Ghidra's `MemoryBlockStub`: tests can use it directly for
/// start/end address behavior or extend the pattern with their own test type
/// when other methods are needed.
pub struct MemoryBlockStub {
    start: Address,
    end: Address,
}

impl MemoryBlockStub {
    /// Constructs a stub using a synthetic no-address range.
    pub fn no_address() -> Self {
        let no_space = AddressSpace::new("NO_ADDRESS", 0, 1, AddressSpaceType::None, 0);
        let no_address = Address::new(no_space, 0);
        Self::new(no_address.clone(), no_address)
    }

    /// Constructs a stub with explicit start and end addresses.
    pub fn new(start: Address, end: Address) -> Self {
        Self { start, end }
    }

    /// Returns the address range for this stub.
    pub fn get_address_range(&self) -> AddressRange {
        AddressRange::new(self.start.clone(), self.end.clone())
    }

    /// Returns the memory block type reported by the Java stub.
    pub const fn get_type(&self) -> MemoryBlockType {
        MemoryBlockType::Default
    }

    /// Returns whether this stub represents an overlay block.
    pub const fn is_overlay(&self) -> bool {
        false
    }
}

impl Default for MemoryBlockStub {
    fn default() -> Self {
        Self::no_address()
    }
}

impl MemoryBlock for MemoryBlockStub {
    fn get_name(&self) -> &str {
        unsupported()
    }

    fn get_start(&self) -> Address {
        self.start.clone()
    }

    fn get_end(&self) -> Address {
        self.end.clone()
    }

    fn get_size(&self) -> u64 {
        unsupported()
    }

    fn is_initialized(&self) -> bool {
        unsupported()
    }

    fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
        unsupported()
    }

    fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
        unsupported()
    }

    fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
        unsupported()
    }
}

fn unsupported<T>() -> T {
    panic!("unsupported memory block stub operation")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn explicit_constructor_preserves_start_end_and_range() {
        let start = test_address(0x1000);
        let end = test_address(0x101f);
        let stub = MemoryBlockStub::new(start.clone(), end.clone());

        assert_eq!(stub.get_start(), start);
        assert_eq!(stub.get_end(), end);
        assert_eq!(stub.get_address_range().min_address(), &start);
        assert_eq!(stub.get_address_range().max_address(), &end);
    }

    #[test]
    fn default_constructor_uses_synthetic_no_address_range() {
        let stub = MemoryBlockStub::default();

        assert_eq!(stub.get_start(), stub.get_end());
        assert_eq!(stub.get_start().space().name(), "NO_ADDRESS");
    }

    #[test]
    fn type_and_overlay_match_java_stub() {
        let stub = MemoryBlockStub::default();

        assert_eq!(stub.get_type(), MemoryBlockType::Default);
        assert!(!stub.is_overlay());
    }

    #[test]
    #[should_panic(expected = "unsupported memory block stub operation")]
    fn unsupported_methods_panic() {
        let stub = MemoryBlockStub::default();

        let _ = stub.get_size();
    }
}
