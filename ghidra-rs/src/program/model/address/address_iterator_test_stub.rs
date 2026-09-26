use crate::program::model::address::Address;
use super::BoxedAddressIterator;

/// A simple test stub for BoxedAddressIterator used in testing.
///
/// This provides an implementation of BoxedAddressIterator for testing purposes,
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

impl Iterator for AddressIteratorTestStub {
    type Item = Address;

    fn next(&mut self) -> Option<Address> {
        let addr = self.addresses.get(self.index)?.clone();
        self.index += 1;
        Some(addr)
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

        assert_eq!(stub.next(), None);
        assert!(stub.next().is_none());
    }

    #[test]
    fn stub_iterates_addresses_in_order() {
        let addresses = vec![addr(0x1000), addr(0x2000), addr(0x3000)];
        let mut stub = AddressIteratorTestStub::new(addresses.clone());
        assert_eq!(stub.next(), Some(addresses[0].clone()));
        assert_eq!(stub.next(), Some(addresses[1].clone()));
        assert_eq!(stub.next(), Some(addresses[2].clone()));
        assert_eq!(stub.next(), None);
        assert!(stub.next().is_none());
    }

    #[test]
    fn stub_returns_none_after_exhaustion() {
        let addresses = vec![addr(0x1000)];
        let mut stub = AddressIteratorTestStub::new(addresses);
        stub.next();
        assert_eq!(stub.next(), None);
        assert!(stub.next().is_none());
        assert!(stub.next().is_none());
    }

    #[test]
    fn stub_with_single_address() {
        let addresses = vec![addr(0x5000)];
        let mut stub = AddressIteratorTestStub::new(addresses.clone());
        assert_eq!(stub.next(), Some(addresses[0].clone()));
        assert_eq!(stub.next(), None);
    }
}
