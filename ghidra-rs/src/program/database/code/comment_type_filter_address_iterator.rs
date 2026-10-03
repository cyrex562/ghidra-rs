//! Port of `ghidra.program.database.code.CommentTypeFilterAddressIterator`.
//!
//! The Java constructor takes a `Program` purely to call `program.getListing()` once and hold
//! onto the result; this port takes the [`Listing`] reference directly instead. `Listing::
//! get_comment` itself only needs `&self`, so nothing is lost by skipping the `Program` hop --
//! and `Program::get_listing` requires `&mut self` in this port (see its doc comment), which
//! would force this iterator to hold an exclusive borrow of the whole `Program` for its entire
//! lifetime just to make read-only comment lookups.

use crate::program::model::address::{Address, BoxedAddressIterator};
use crate::program::model::listing::{CommentType, Listing};

/// Filters the given address iterator to only return addresses that have a comment of the given
/// type.
///
/// Port of `ghidra.program.database.code.CommentTypeFilterAddressIterator`. See the module docs
/// for the `Program` -> `Listing` deviation.
pub struct CommentTypeFilterAddressIterator<'a> {
    listing: &'a dyn Listing,
    it: BoxedAddressIterator,
    comment_type: CommentType,
}

impl<'a> CommentTypeFilterAddressIterator<'a> {
    /// Constructs a new `CommentTypeFilterAddressIterator`. `listing` is used to look up whether
    /// each candidate address has a comment of `comment_type`; `it` is the address iterator whose
    /// items are tested.
    pub fn new(listing: &'a dyn Listing, it: BoxedAddressIterator, comment_type: CommentType) -> Self {
        CommentTypeFilterAddressIterator {
            listing,
            it,
            comment_type,
        }
    }
}

impl<'a> Iterator for CommentTypeFilterAddressIterator<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Address> {
        for addr in self.it.by_ref() {
            if self.listing.get_comment(self.comment_type, &addr).is_some() {
                return Some(addr);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::StubListing;
    use std::collections::HashMap;

    /// Overrides only [`StubListing::get_comment`]; every other `Listing` method panics if
    /// exercised, which none of these tests do.
    struct MockListing {
        comments: HashMap<(CommentType, i64), String>,
    }

    impl StubListing for MockListing {
        fn get_comment(&self, comment_type: CommentType, address: &Address) -> Option<String> {
            self.comments
                .get(&(comment_type, address.offset()))
                .cloned()
        }
    }

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    #[test]
    fn filters_to_addresses_with_matching_comment_type() {
        let space = space();
        let mut comments = HashMap::new();
        comments.insert((CommentType::Plate, 0x1000), "hello".to_string());
        comments.insert((CommentType::Eol, 0x2000), "world".to_string());
        let listing = MockListing { comments };

        let addrs: BoxedAddressIterator = Box::new(
            vec![space.address(0x1000), space.address(0x1500), space.address(0x2000)].into_iter(),
        );

        let mut iter = CommentTypeFilterAddressIterator::new(&listing, addrs, CommentType::Plate);
        assert_eq!(iter.next(), Some(space.address(0x1000)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn empty_when_no_addresses_have_matching_comment() {
        let space = space();
        let listing = MockListing {
            comments: HashMap::new(),
        };
        let addrs: BoxedAddressIterator =
            Box::new(vec![space.address(0x1000), space.address(0x2000)].into_iter());

        let mut iter = CommentTypeFilterAddressIterator::new(&listing, addrs, CommentType::Eol);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn behaves_as_boxed_iterator() {
        let space = space();
        let mut comments = HashMap::new();
        comments.insert((CommentType::Repeatable, 0x10), "a".to_string());
        comments.insert((CommentType::Repeatable, 0x30), "b".to_string());
        let listing = MockListing { comments };

        let addrs: BoxedAddressIterator = Box::new(
            vec![space.address(0x10), space.address(0x20), space.address(0x30)].into_iter(),
        );
        let iter: Box<dyn Iterator<Item = Address>> = Box::new(
            CommentTypeFilterAddressIterator::new(&listing, addrs, CommentType::Repeatable),
        );
        let collected: Vec<Address> = iter.collect();
        assert_eq!(collected, vec![space.address(0x10), space.address(0x30)]);
    }
}
