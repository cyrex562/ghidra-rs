use crate::program::model::address::Address;

/// Info about a byte block edit.
///
/// Port of `ghidra.app.plugin.core.format.ByteEditInfo`.
#[derive(Clone, Debug)]
pub struct ByteEditInfo {
    block_start_addr: Address,
    offset: i128,
    old_value: Vec<u8>,
    new_value: Vec<u8>,
}

impl ByteEditInfo {
    /// Construct a new byte edit info.
    ///
    /// # Arguments
    /// * `block_start_addr` - starting address of the block
    /// * `offset` - offset into the block
    /// * `old_value` - old value of the bytes
    /// * `new_value` - new value of the bytes
    pub fn new(
        block_start_addr: Address,
        offset: i128,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
    ) -> Self {
        Self {
            block_start_addr,
            offset,
            old_value,
            new_value,
        }
    }

    /// Get the old value.
    pub fn old_value(&self) -> &[u8] {
        &self.old_value
    }

    /// Get the new value.
    pub fn new_value(&self) -> &[u8] {
        &self.new_value
    }

    /// Get the block offset.
    pub fn offset(&self) -> i128 {
        self.offset
    }

    /// Get the block address.
    pub fn block_address(&self) -> &Address {
        &self.block_start_addr
    }
}

impl PartialEq for ByteEditInfo {
    fn eq(&self, other: &Self) -> bool {
        self.block_start_addr == other.block_start_addr
            && self.offset == other.offset
            && self.old_value == other.old_value
            && self.new_value == other.new_value
    }
}

impl Eq for ByteEditInfo {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn construct_stores_all_fields() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        let old = vec![0xAA, 0xBB];
        let new = vec![0xCC, 0xDD];

        let info = ByteEditInfo::new(addr.clone(), 100, old.clone(), new.clone());

        assert_eq!(info.block_address(), &addr);
        assert_eq!(info.offset(), 100);
        assert_eq!(info.old_value(), &old[..]);
        assert_eq!(info.new_value(), &new[..]);
    }

    #[test]
    fn equality_requires_all_fields_match() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x2000);
        let old = vec![0xAA, 0xBB];
        let new = vec![0xCC, 0xDD];

        let info1 = ByteEditInfo::new(addr1.clone(), 100, old.clone(), new.clone());
        let info2 = ByteEditInfo::new(addr1.clone(), 100, old.clone(), new.clone());
        let info3 = ByteEditInfo::new(addr2, 100, old.clone(), new.clone());
        let info4 = ByteEditInfo::new(addr1.clone(), 200, old.clone(), new.clone());
        let info5 = ByteEditInfo::new(
            addr1.clone(),
            100,
            vec![0x11, 0x22],
            new.clone(),
        );
        let info6 = ByteEditInfo::new(addr1, 100, old, vec![0x11, 0x22]);

        assert_eq!(info1, info2);
        assert_ne!(info1, info3);
        assert_ne!(info1, info4);
        assert_ne!(info1, info5);
        assert_ne!(info1, info6);
    }

    #[test]
    fn values_are_independent() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);
        let old = vec![0x01, 0x02, 0x03];
        let new = vec![0xFF, 0xFE];

        let info = ByteEditInfo::new(addr, 50, old, new);

        assert_eq!(info.old_value().len(), 3);
        assert_eq!(info.new_value().len(), 2);
        assert_eq!(info.old_value()[0], 0x01);
        assert_eq!(info.new_value()[0], 0xFF);
    }

    #[test]
    fn empty_values_allowed() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);

        let info = ByteEditInfo::new(addr, 0, vec![], vec![]);

        assert_eq!(info.old_value().len(), 0);
        assert_eq!(info.new_value().len(), 0);
    }
}
