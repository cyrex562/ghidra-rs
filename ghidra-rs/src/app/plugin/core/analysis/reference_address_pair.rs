use crate::program::model::address::{Address, SpecialAddress};

/// A pair of source and destination addresses associated with a reference.
///
/// Maps to `ghidra.app.plugin.core.analysis.ReferenceAddressPair`.
#[derive(Clone, Debug)]
pub struct ReferenceAddressPair {
    source: Address,
    destination: Address,
}

impl ReferenceAddressPair {
    /// Creates a new pair of reference addresses.
    ///
    /// If either address is null, it is replaced with the NO_ADDRESS sentinel.
    pub fn new(source: Option<Address>, destination: Option<Address>) -> Self {
        let source = source.unwrap_or_else(SpecialAddress::no_address);
        let destination = destination.unwrap_or_else(SpecialAddress::no_address);
        Self {
            source,
            destination,
        }
    }

    /// Returns the source address of this reference.
    pub fn source(&self) -> &Address {
        &self.source
    }

    /// Returns the destination address of this reference.
    pub fn destination(&self) -> &Address {
        &self.destination
    }
}

impl PartialEq for ReferenceAddressPair {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.destination == other.destination
    }
}

impl Eq for ReferenceAddressPair {}

impl std::hash::Hash for ReferenceAddressPair {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.source.hash(&mut hasher);
        let hash1 = std::hash::Hasher::finish(&hasher);

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.destination.hash(&mut hasher);
        let hash2 = std::hash::Hasher::finish(&hasher);

        (hash1 ^ hash2).hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::collections::HashSet;

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(ram, offset)
    }

    #[test]
    fn creates_pair_with_addresses() {
        let src = ram_address(0x1000);
        let dst = ram_address(0x2000);
        let pair = ReferenceAddressPair::new(Some(src.clone()), Some(dst.clone()));

        assert_eq!(*pair.source(), src);
        assert_eq!(*pair.destination(), dst);
    }

    #[test]
    fn replaces_none_source_with_no_address() {
        let dst = ram_address(0x2000);
        let pair = ReferenceAddressPair::new(None, Some(dst.clone()));

        assert_eq!(pair.source().to_string(), "NO ADDRESS");
        assert_eq!(*pair.destination(), dst);
    }

    #[test]
    fn replaces_none_destination_with_no_address() {
        let src = ram_address(0x1000);
        let pair = ReferenceAddressPair::new(Some(src.clone()), None);

        assert_eq!(*pair.source(), src);
        assert_eq!(pair.destination().to_string(), "NO ADDRESS");
    }

    #[test]
    fn replaces_both_none_with_no_address() {
        let pair = ReferenceAddressPair::new(None, None);

        assert_eq!(pair.source().to_string(), "NO ADDRESS");
        assert_eq!(pair.destination().to_string(), "NO ADDRESS");
    }

    #[test]
    fn equal_pairs_with_same_addresses() {
        let src = ram_address(0x1000);
        let dst = ram_address(0x2000);
        let pair1 = ReferenceAddressPair::new(Some(src.clone()), Some(dst.clone()));
        let pair2 = ReferenceAddressPair::new(Some(src.clone()), Some(dst.clone()));

        assert_eq!(pair1, pair2);
    }

    #[test]
    fn not_equal_pairs_with_different_sources() {
        let src1 = ram_address(0x1000);
        let src2 = ram_address(0x1001);
        let dst = ram_address(0x2000);
        let pair1 = ReferenceAddressPair::new(Some(src1), Some(dst.clone()));
        let pair2 = ReferenceAddressPair::new(Some(src2), Some(dst));

        assert_ne!(pair1, pair2);
    }

    #[test]
    fn not_equal_pairs_with_different_destinations() {
        let src = ram_address(0x1000);
        let dst1 = ram_address(0x2000);
        let dst2 = ram_address(0x2001);
        let pair1 = ReferenceAddressPair::new(Some(src.clone()), Some(dst1));
        let pair2 = ReferenceAddressPair::new(Some(src), Some(dst2));

        assert_ne!(pair1, pair2);
    }

    #[test]
    fn equal_pairs_have_same_hash() {
        let src = ram_address(0x1000);
        let dst = ram_address(0x2000);
        let pair1 = ReferenceAddressPair::new(Some(src.clone()), Some(dst.clone()));
        let pair2 = ReferenceAddressPair::new(Some(src), Some(dst));

        let mut set = HashSet::new();
        set.insert(pair1);
        assert!(set.contains(&pair2));
    }

    #[test]
    fn can_be_used_in_hash_map() {
        use std::collections::HashMap;

        let src = ram_address(0x1000);
        let dst = ram_address(0x2000);
        let pair = ReferenceAddressPair::new(Some(src), Some(dst));

        let mut map = HashMap::new();
        map.insert(pair.clone(), "test_value");

        assert_eq!(map.get(&pair), Some(&"test_value"));
    }
}
