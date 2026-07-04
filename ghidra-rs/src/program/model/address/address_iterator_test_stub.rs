use crate::program::model::address::Address;
use super::AddressIterator;

/// A simple test stub for AddressIterator used in testing.
///
/// This provides an implementation of AddressIterator for testing purposes,
/// wrapping a collection of addresses and yielding them one by one.
pub struct AddressIteratorTestStub {
    addresses: Vec<Address>,
    index: usize,
}

impl AddressIteratorTestStub {
    /// Creates a test stub from a vector of addresses.
    pub fn new(addresses: Vec<Address>) -> Self {
        Self { addresses, index: 0 }
    }
}

impl AddressIterator for AddressIteratorTestStub {
    fn has_next(&self) -> bool {
        self.index < self.addresses.len()
    }

    fn next_address(&mut self) -> Option<Address> {
        if self.has_next() {
            let addr = self.addresses[self.index].clone();
            self.index += 1;
            Some(addr)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn empty_stub_has_no_addresses() {
        let mut stub = AddressIteratorTestStub::new(vec![]);

        assert!(!stub.has_next());
        assert!(stub.next_address().is_none());
    }

    #[test]
    fn stub_iterates_addresses_in_order() {
        let addresses = vec![addr(0x1000), addr(0x2000), addr(0x3000)];
        let mut stub = AddressIteratorTestStub::new(addresses.clone());

        assert!(stub.has_next());
        assert_eq!(stub.next_address(), Some(addresses[0].clone()));
        assert!(stub.has_next());
        assert_eq!(stub.next_address(), Some(addresses[1].clone()));
        assert!(stub.has_next());
        assert_eq!(stub.next_address(), Some(addresses[2].clone()));
        assert!(!stub.has_next());
        assert!(stub.next_address().is_none());
    }

    #[test]
    fn stub_returns_none_after_exhaustion() {
        let addresses = vec![addr(0x1000)];
        let mut stub = AddressIteratorTestStub::new(addresses);

        assert!(stub.has_next());
        stub.next_address();
        assert!(!stub.has_next());
        assert!(stub.next_address().is_none());
        assert!(stub.next_address().is_none());
    }

    #[test]
    fn stub_with_single_address() {
        let addresses = vec![addr(0x5000)];
        let mut stub = AddressIteratorTestStub::new(addresses.clone());

        assert!(stub.has_next());
        assert_eq!(stub.next_address(), Some(addresses[0].clone()));
        assert!(!stub.has_next());
    }
}
