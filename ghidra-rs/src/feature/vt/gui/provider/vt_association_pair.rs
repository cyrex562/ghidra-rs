use crate::feature::vt::api::main::vt_association_type::VtAssociationType;
use crate::program::model::address::Address;
use std::fmt;

/// A source/destination address pair together with the type of version-tracking
/// association it represents.
#[derive(Clone, Debug)]
pub struct VtAssociationPair {
    source_address: Address,
    destination_address: Address,
    association_type: VtAssociationType,
}

impl VtAssociationPair {
    /// Creates a new association pair.
    pub fn new(
        source_address: Address,
        destination_address: Address,
        association_type: VtAssociationType,
    ) -> Self {
        Self {
            source_address,
            destination_address,
            association_type,
        }
    }

    /// Returns the source address of this pair.
    pub fn source(&self) -> &Address {
        &self.source_address
    }

    /// Returns the destination address of this pair.
    pub fn destination(&self) -> &Address {
        &self.destination_address
    }

    /// Returns the association type of this pair.
    pub fn association_type(&self) -> VtAssociationType {
        self.association_type
    }
}

impl PartialEq for VtAssociationPair {
    fn eq(&self, other: &Self) -> bool {
        self.destination_address == other.destination_address
            && self.source_address == other.source_address
            && self.association_type == other.association_type
    }
}

impl Eq for VtAssociationPair {}

impl std::hash::Hash for VtAssociationPair {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.destination_address.hash(state);
        self.source_address.hash(state);
        self.association_type.hash(state);
    }
}

impl fmt::Display for VtAssociationPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{\n\tsource: {},\n\tdest: {},\n\ttype: {},\n}}",
            self.source_address, self.destination_address, self.association_type
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn addr(space_name: &str, offset: i64) -> Address {
        let space = AddressSpace::new(space_name, 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    fn hash_of(pair: &VtAssociationPair) -> u64 {
        let mut h = DefaultHasher::new();
        pair.hash(&mut h);
        h.finish()
    }

    #[test]
    fn new_stores_fields() {
        let source = addr("ram", 0x1000);
        let dest = addr("ram", 0x2000);
        let pair = VtAssociationPair::new(source.clone(), dest.clone(), VtAssociationType::Function);

        assert_eq!(*pair.source(), source);
        assert_eq!(*pair.destination(), dest);
        assert_eq!(pair.association_type(), VtAssociationType::Function);
    }

    #[test]
    fn equality_based_on_all_fields() {
        let a = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let b = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_source() {
        let a = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let b = VtAssociationPair::new(
            addr("ram", 0x1001),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_destination() {
        let a = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let b = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2001),
            VtAssociationType::Function,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_type() {
        let a = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let b = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Data,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn hash_consistent_with_equality() {
        let a = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let b = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn hash_differs_for_different_pairs() {
        let a = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let b = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Data,
        );
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn display_matches_java_format() {
        let pair = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let expected = format!(
            "{{\n\tsource: {},\n\tdest: {},\n\ttype: {},\n}}",
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function
        );
        assert_eq!(pair.to_string(), expected);
    }

    #[test]
    fn clone_is_independent() {
        let pair = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let cloned = pair.clone();
        assert_eq!(pair, cloned);
    }

    #[test]
    fn hash_in_collection() {
        use std::collections::HashSet;
        let a = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let b = VtAssociationPair::new(
            addr("ram", 0x1001),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );
        let c = VtAssociationPair::new(
            addr("ram", 0x1000),
            addr("ram", 0x2000),
            VtAssociationType::Function,
        );

        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(c);
        assert_eq!(set.len(), 2);
    }
}
