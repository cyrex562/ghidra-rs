//! Address iteration for the text-search plugin.
//!
//! Port of `ghidra.app.plugin.core.searchtext.iterators.SearchAddressIterator`.
//!
//! The Java interface (`hasNext()` + `next()`) had no business surviving translation: it is
//! `std::iter::Iterator<Item = Address>` with a Java-shaped peek bolted on. It is gone, and
//! the search iterators are plain Rust iterators, so callers get the whole adaptor ecosystem
//! (`map`/`filter`/`take_while`/`chain`) instead of a two-method trait that supported none of
//! it. `hasNext()` has no equivalent method because it does not need one: use
//! [`std::iter::Peekable`] when you must look without consuming, or `while let Some(a) =
//! it.next()` when you must not.
//!
//! See `OWNERSHIP_MIGRATION.md` (the `ITER` verdict in `CONVENTION_QUEUE.tsv`).

use crate::program::model::address::Address;

/// A type-erased address iterator, for the places that genuinely need to hold several
/// different kinds of search iterator at once (see
/// [`ListingDisplaySearchAddressIterator`](super::super::ListingDisplaySearchAddressIterator),
/// which merges one iterator per search category).
///
/// `Box<dyn Iterator<Item = Address>>` is idiomatic Rust, not the Java-interface-as-trait-object
/// pattern the ownership migration is removing: the erased type here is `std::Iterator` itself.
/// Prefer a concrete iterator type or `impl Iterator<Item = Address>` wherever the set of
/// iterator types is known at the call site.
pub type BoxedSearchAddressIterator = Box<dyn Iterator<Item = Address>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    /// A search iterator is now just an iterator: anything that yields addresses works,
    /// including a plain `Vec` iterator, with no bespoke trait to implement.
    fn boxed(addresses: Vec<Address>) -> BoxedSearchAddressIterator {
        Box::new(addresses.into_iter())
    }

    #[test]
    fn empty_iterator_yields_nothing() {
        let mut iter = boxed(vec![]);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn peekable_replaces_has_next() {
        let mut iter = boxed(vec![addr(0)]).peekable();
        assert!(iter.peek().is_some());
        iter.next();
        assert!(iter.peek().is_none());
    }

    #[test]
    fn iterator_returns_addresses_in_order() {
        let iter = boxed(vec![addr(0), addr(8), addr(16)]);
        assert_eq!(iter.collect::<Vec<_>>(), vec![addr(0), addr(8), addr(16)]);
    }

    #[test]
    fn next_keeps_returning_none_when_empty() {
        let mut iter = boxed(vec![]);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn adaptors_now_work_on_a_search_iterator() {
        // The point of the conversion: none of this was expressible against the old
        // `has_next`/`next` trait.
        let found: Vec<Address> = boxed(vec![addr(0), addr(8), addr(16)])
            .filter(|a| a.offset() > 0)
            .take(1)
            .collect();
        assert_eq!(found, vec![addr(8)]);
    }
}
