use std::cmp::Ordering;

use crate::program::model::address::Address;
use crate::program::model::listing::CommentType;

/// A row object representing a single comment in the comment window table, identified by
/// the address and comment type of the comment it refers to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CommentRowObject {
    address: Address,
    comment_type: CommentType,
}

impl CommentRowObject {
    pub fn new(address: Address, comment_type: CommentType) -> Self {
        Self { address, comment_type }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn comment_type(&self) -> CommentType {
        self.comment_type
    }
}

impl PartialOrd for CommentRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CommentRowObject {
    fn cmp(&self, other: &Self) -> Ordering {
        self.address
            .cmp(&other.address)
            .then_with(|| self.comment_type.ordinal().cmp(&other.comment_type.ordinal()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    #[test]
    fn accessors_return_constructed_values() {
        let obj = CommentRowObject::new(addr(0x100), CommentType::Eol);
        assert_eq!(*obj.address(), addr(0x100));
        assert_eq!(obj.comment_type(), CommentType::Eol);
    }

    #[test]
    fn equality_requires_both_fields_to_match() {
        let a = CommentRowObject::new(addr(0x100), CommentType::Eol);
        let b = CommentRowObject::new(addr(0x100), CommentType::Eol);
        let diff_addr = CommentRowObject::new(addr(0x200), CommentType::Eol);
        let diff_type = CommentRowObject::new(addr(0x100), CommentType::Pre);
        assert_eq!(a, b);
        assert_ne!(a, diff_addr);
        assert_ne!(a, diff_type);
    }

    #[test]
    fn ordering_compares_address_first() {
        let lo = CommentRowObject::new(addr(0x100), CommentType::Repeatable);
        let hi = CommentRowObject::new(addr(0x200), CommentType::Eol);
        assert!(lo < hi);
    }

    #[test]
    fn ordering_falls_back_to_comment_type_when_addresses_equal() {
        let eol = CommentRowObject::new(addr(0x100), CommentType::Eol);
        let pre = CommentRowObject::new(addr(0x100), CommentType::Pre);
        assert!(eol < pre);
        assert_eq!(eol.cmp(&eol), Ordering::Equal);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        let a = CommentRowObject::new(addr(0x100), CommentType::Eol);
        let b = CommentRowObject::new(addr(0x100), CommentType::Eol);
        set.insert(a);
        assert!(set.contains(&b));
    }
}
