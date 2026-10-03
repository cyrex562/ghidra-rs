use crate::program::model::address::Address;

/// A row storing random forest proximity information for a potential function start.
///
/// Records the function start address and the number of agreeing trees in the random forest model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimilarStartRowObject {
    func_start: Address,
    num_agreements: i32,
}

impl SimilarStartRowObject {
    /// Creates a row for the given function start address and number of agreeing trees.
    pub fn new(func_start: Address, num_agreements: i32) -> Self {
        Self {
            func_start,
            num_agreements,
        }
    }

    /// Returns the function start address.
    pub fn func_start(&self) -> Address {
        self.func_start.clone()
    }

    /// Returns the number of agreeing trees.
    pub fn num_agreements(&self) -> i32 {
        self.num_agreements
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn new_stores_fields() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        let row = SimilarStartRowObject::new(addr.clone(), 5);
        assert_eq!(row.func_start(), addr);
        assert_eq!(row.num_agreements(), 5);
    }

    #[test]
    fn zero_agreements() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x2000);
        let row = SimilarStartRowObject::new(addr.clone(), 0);
        assert_eq!(row.func_start(), addr);
        assert_eq!(row.num_agreements(), 0);
    }

    #[test]
    fn equality() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr1 = Address::new(space.clone(), 0x3000);
        let addr2 = Address::new(space, 0x3000);
        let row_a = SimilarStartRowObject::new(addr1, 10);
        let row_b = SimilarStartRowObject::new(addr2, 10);
        assert_eq!(row_a, row_b);
    }

    #[test]
    fn inequality_different_addresses() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr1 = Address::new(space.clone(), 0x4000);
        let addr2 = Address::new(space, 0x5000);
        let row_a = SimilarStartRowObject::new(addr1, 10);
        let row_b = SimilarStartRowObject::new(addr2, 10);
        assert_ne!(row_a, row_b);
    }

    #[test]
    fn inequality_different_agreements() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x6000);
        let row_a = SimilarStartRowObject::new(addr.clone(), 10);
        let row_b = SimilarStartRowObject::new(addr, 20);
        assert_ne!(row_a, row_b);
    }

    #[test]
    fn clone() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x7000);
        let row = SimilarStartRowObject::new(addr.clone(), 15);
        let cloned = row.clone();
        assert_eq!(row, cloned);
    }
}
