//! Port of `ghidra.program.database.register.IndexToAddressRangeIteratorAdapter`.

use crate::program::database::map::AddressMap;
use crate::program::model::address::{AddressRange, AddressRangeIterator};
use crate::util::datastruct::{IndexRange, IndexRangeIterator};

/// Adapts an [`IndexRangeIterator`] (raw database-key ranges) into an [`AddressRangeIterator`]
/// by decoding each endpoint through an [`AddressMap`].
///
/// Port of `ghidra.program.database.register.IndexToAddressRangeIteratorAdapter`.
pub struct IndexToAddressRangeIteratorAdapter<'a> {
    map: &'a dyn AddressMap,
    it: Box<dyn IndexRangeIterator + 'a>,
}

impl<'a> IndexToAddressRangeIteratorAdapter<'a> {
    /// Constructs a new adapter given an [`AddressMap`] and [`IndexRangeIterator`].
    pub fn new(address_map: &'a dyn AddressMap, it: Box<dyn IndexRangeIterator + 'a>) -> Self {
        Self { map: address_map, it }
    }

    fn decode(&self, index_range: IndexRange) -> AddressRange {
        let start = self.map.decode_address(index_range.start());
        let end = self.map.decode_address(index_range.end());
        AddressRange::new(start, end)
    }
}

impl<'a> Iterator for IndexToAddressRangeIteratorAdapter<'a> {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.it.has_next() {
            return None;
        }
        let index_range = self.it.next();
        Some(self.decode(index_range))
    }
}

impl<'a> AddressRangeIterator for IndexToAddressRangeIteratorAdapter<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange,
    };
    use std::sync::Arc;

    /// Minimal identity-mapping `AddressMap` test double: this adapter only ever calls
    /// `decode_address`, so nothing else needs to be meaningful.
    struct IdentityAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for IdentityAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }

        fn decode_address(&self, value: i64) -> Address {
            self.space.address(value)
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }

        fn get_key_ranges_absolute(
            &self,
            start: &Address,
            end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            vec![KeyRange::new(start.offset(), end.offset())]
        }

        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(IdentityAddressMap { space: self.space.clone() })
        }

        fn is_upgraded(&self) -> bool {
            false
        }

        fn get_image_base(&self) -> Address {
            self.space.address(0)
        }
    }

    struct VecIndexRangeIterator {
        ranges: std::vec::IntoIter<IndexRange>,
    }

    impl VecIndexRangeIterator {
        fn new(ranges: Vec<IndexRange>) -> Self {
            Self { ranges: ranges.into_iter() }
        }
    }

    impl IndexRangeIterator for VecIndexRangeIterator {
        fn has_next(&self) -> bool {
            // `IndexRange` is `Copy`, so `ExactSizeIterator::len` is a reliable, allocation-free
            // stand-in for a true one-element lookahead here.
            self.ranges.len() > 0
        }

        fn next(&mut self) -> IndexRange {
            self.ranges.next().expect("next() called with no more ranges")
        }
    }

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn adapts_index_ranges_to_decoded_address_ranges() {
        let space = test_space();
        let map = IdentityAddressMap { space: space.clone() };
        let inner = VecIndexRangeIterator::new(vec![IndexRange::new(0x10, 0x1f), IndexRange::new(0x30, 0x3f)]);
        let mut adapter = IndexToAddressRangeIteratorAdapter::new(&map, Box::new(inner));

        let r1 = adapter.next().expect("first range");
        assert_eq!(r1.min_address(), &space.address(0x10));
        assert_eq!(r1.max_address(), &space.address(0x1f));

        let r2 = adapter.next().expect("second range");
        assert_eq!(r2.min_address(), &space.address(0x30));
        assert_eq!(r2.max_address(), &space.address(0x3f));

        assert!(adapter.next().is_none());
    }

    #[test]
    fn empty_iterator_yields_no_ranges() {
        let space = test_space();
        let map = IdentityAddressMap { space };
        let inner = VecIndexRangeIterator::new(vec![]);
        let mut adapter = IndexToAddressRangeIteratorAdapter::new(&map, Box::new(inner));
        assert!(adapter.next().is_none());
    }
}
