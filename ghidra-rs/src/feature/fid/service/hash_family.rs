use std::collections::BTreeMap;
use std::sync::Arc;

use crate::feature::fid::hash::FidHashQuad;
use crate::program::model::address::Address;

/// Container class for the neighborhood of hashes around a function. Contains
/// the FidHashQuad for the function, for all its parents (callers), all its children (callees),
/// and all the names of the children whose hashes could not be resolved.
pub struct HashFamily {
    address: Address,
    hash: Arc<dyn FidHashQuad>,
    parents: BTreeMap<i64, Arc<dyn FidHashQuad>>,
    children: BTreeMap<i64, Arc<dyn FidHashQuad>>,
}

impl HashFamily {
    /// Creates a new HashFamily with the given address and hash.
    pub(crate) fn new(address: Address, hash: Arc<dyn FidHashQuad>) -> Self {
        Self {
            address,
            hash,
            parents: BTreeMap::new(),
            children: BTreeMap::new(),
        }
    }

    /// Adds a parent (caller) hash to this family.
    pub(crate) fn add_parent(&mut self, parent: Arc<dyn FidHashQuad>) {
        let key = parent.full_hash();
        self.parents.insert(key, parent);
    }

    /// Adds a child (callee) hash to this family.
    pub(crate) fn add_child(&mut self, child: Arc<dyn FidHashQuad>) {
        let key = child.full_hash();
        self.children.insert(key, child);
    }

    /// Returns the address of this function.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the hash for this function.
    pub fn hash(&self) -> Arc<dyn FidHashQuad> {
        Arc::clone(&self.hash)
    }

    /// Returns the parent (caller) hashes.
    pub fn parents(&self) -> Vec<Arc<dyn FidHashQuad>> {
        self.parents.values().cloned().collect()
    }

    /// Returns the child (callee) hashes.
    pub fn children(&self) -> Vec<Arc<dyn FidHashQuad>> {
        self.children.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::fid::hash::fid_hash_quad_impl::FidHashQuadImpl;

    struct MockQuad {
        full_hash: i64,
    }

    impl FidHashQuad for MockQuad {
        fn code_unit_size(&self) -> i16 {
            10
        }

        fn full_hash(&self) -> i64 {
            self.full_hash
        }

        fn specific_hash_additional_size(&self) -> i8 {
            3
        }

        fn specific_hash(&self) -> i64 {
            0xDEAD_BEEF_CAFE_1234_u64 as i64
        }
    }

    fn create_test_address() -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0x1000)
    }

    #[test]
    fn test_creation_initializes_empty_families() {
        let address = create_test_address();
        let hash = Arc::new(MockQuad { full_hash: 0x1234 }) as Arc<dyn FidHashQuad>;
        let family = HashFamily::new(address.clone(), hash.clone());

        assert_eq!(family.address(), &address);
        assert_eq!(family.hash().full_hash(), 0x1234);
        assert_eq!(family.parents().len(), 0);
        assert_eq!(family.children().len(), 0);
    }

    #[test]
    fn test_add_parent() {
        let address = create_test_address();
        let hash = Arc::new(MockQuad { full_hash: 0x1234 }) as Arc<dyn FidHashQuad>;
        let mut family = HashFamily::new(address, hash);

        let parent = Arc::new(MockQuad { full_hash: 0x5678 }) as Arc<dyn FidHashQuad>;
        family.add_parent(parent.clone());

        assert_eq!(family.parents().len(), 1);
        assert_eq!(family.parents()[0].full_hash(), 0x5678);
    }

    #[test]
    fn test_add_child() {
        let address = create_test_address();
        let hash = Arc::new(MockQuad { full_hash: 0x1234 }) as Arc<dyn FidHashQuad>;
        let mut family = HashFamily::new(address, hash);

        let child = Arc::new(MockQuad { full_hash: 0xABCD }) as Arc<dyn FidHashQuad>;
        family.add_child(child.clone());

        assert_eq!(family.children().len(), 1);
        assert_eq!(family.children()[0].full_hash(), 0xABCD);
    }

    #[test]
    fn test_multiple_parents_keyed_by_full_hash() {
        let address = create_test_address();
        let hash = Arc::new(MockQuad { full_hash: 0x1234 }) as Arc<dyn FidHashQuad>;
        let mut family = HashFamily::new(address, hash);

        let parent1 = Arc::new(MockQuad { full_hash: 0x5678 }) as Arc<dyn FidHashQuad>;
        let parent2 = Arc::new(MockQuad { full_hash: 0x9ABC }) as Arc<dyn FidHashQuad>;
        family.add_parent(parent1);
        family.add_parent(parent2);

        assert_eq!(family.parents().len(), 2);
    }

    #[test]
    fn test_duplicate_parents_by_full_hash_replaced() {
        let address = create_test_address();
        let hash = Arc::new(MockQuad { full_hash: 0x1234 }) as Arc<dyn FidHashQuad>;
        let mut family = HashFamily::new(address, hash);

        let parent1 = Arc::new(MockQuad { full_hash: 0x5678 }) as Arc<dyn FidHashQuad>;
        family.add_parent(parent1);

        let parent2 = Arc::new(MockQuad { full_hash: 0x5678 }) as Arc<dyn FidHashQuad>;
        family.add_parent(parent2);

        assert_eq!(family.parents().len(), 1);
        assert_eq!(family.parents()[0].full_hash(), 0x5678);
    }

    #[test]
    fn test_multiple_children() {
        let address = create_test_address();
        let hash = Arc::new(MockQuad { full_hash: 0x1234 }) as Arc<dyn FidHashQuad>;
        let mut family = HashFamily::new(address, hash);

        let child1 = Arc::new(MockQuad { full_hash: 0xABCD }) as Arc<dyn FidHashQuad>;
        let child2 = Arc::new(MockQuad { full_hash: 0xEF01 }) as Arc<dyn FidHashQuad>;
        family.add_child(child1);
        family.add_child(child2);

        assert_eq!(family.children().len(), 2);
    }

    #[test]
    fn test_parents_and_children_independent() {
        let address = create_test_address();
        let hash = Arc::new(MockQuad { full_hash: 0x1234 }) as Arc<dyn FidHashQuad>;
        let mut family = HashFamily::new(address, hash);

        let parent = Arc::new(MockQuad { full_hash: 0x5678 }) as Arc<dyn FidHashQuad>;
        let child = Arc::new(MockQuad { full_hash: 0xABCD }) as Arc<dyn FidHashQuad>;
        family.add_parent(parent);
        family.add_child(child);

        assert_eq!(family.parents().len(), 1);
        assert_eq!(family.children().len(), 1);
    }

    #[test]
    fn test_real_hash_quad_impl() {
        let address = create_test_address();
        let quad = FidHashQuadImpl::new(10, 0x1234_5678_9ABC_DEF0_u64 as i64, 3, 0xDEAD_BEEF_CAFE_1234_u64 as i64);
        let hash = Arc::new(quad) as Arc<dyn FidHashQuad>;
        let family = HashFamily::new(address, hash.clone());

        assert_eq!(family.hash().full_hash(), 0x1234_5678_9ABC_DEF0_u64 as i64);
        assert_eq!(family.hash().code_unit_size(), 10);
        assert_eq!(family.hash().specific_hash_additional_size(), 3);
    }
}
