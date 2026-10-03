use crate::util::datastruct::index_range::IndexRange;
use crate::util::datastruct::index_range_iterator::IndexRangeIterator;
use crate::util::long_iterator::LongIterator;
use crate::util::map::{ValueMap, ValueMapIter};

/// Iterator over Property Set Index ranges that have the same value.
///
/// Port of `ghidra.util.datastruct.PropertySetIndexRangeIterator`.
///
/// Java's constructor takes a `ValueMap set` (an interface) and immediately calls
/// `set.getPropertyIterator(start + 1)` on it, storing the resulting `LongIterator` in a field.
/// This crate's [`ValueMap::get_property_iterator_from`] returns [`ValueMapIter`] -- the
/// equivalent of `LongIteratorImpl` (see that type's own docs) -- but requires `Self: Sized`
/// (needed to keep [`ValueMap`] itself object-safe elsewhere), so it can't be called through a
/// `&dyn ValueMap<T>`. `PropertySetIndexRangeIterator` is therefore generic over the concrete
/// `M: ValueMap<T>` implementation, constructed from a `&M` directly, rather than boxing a trait
/// object.
pub struct PropertySetIndexRangeIterator<'a, T, M: ValueMap<T>> {
    long_it: ValueMapIter<'a, T, M>,
    index_range: Option<IndexRange>,
}

impl<'a, T, M: ValueMap<T>> PropertySetIndexRangeIterator<'a, T, M> {
    /// Constructs a new `PropertySetIndexRangeIterator` over `set`, starting after `start`.
    ///
    /// Mirrors `PropertySetIndexRangeIterator(ValueMap set, long start)`.
    pub fn new(set: &'a M, start: i64) -> Self {
        let mut long_it = set.get_property_iterator_from(start + 1);
        let index_range = if long_it.has_next() {
            Some(IndexRange::new(start, long_it.next() - 1))
        } else {
            Some(IndexRange::new(start, i64::MAX))
        };
        Self { long_it, index_range }
    }

    fn get_next_index_range(&mut self) {
        let Some(index_range) = self.index_range else {
            return;
        };
        let old_end = index_range.end();
        if old_end == i64::MAX {
            self.index_range = None;
            return;
        }
        if self.long_it.has_next() {
            self.index_range = Some(IndexRange::new(old_end + 1, self.long_it.next() - 1));
            return;
        }
        self.index_range = Some(IndexRange::new(old_end + 1, i64::MAX));
    }
}

impl<'a, T, M: ValueMap<T>> IndexRangeIterator for PropertySetIndexRangeIterator<'a, T, M> {
    /// Mirrors `hasNext()`.
    fn has_next(&self) -> bool {
        self.index_range.is_some()
    }

    /// Mirrors `next()`.
    ///
    /// # Panics
    /// Panics if called when [`IndexRangeIterator::has_next`] is `false`, matching the
    /// [`IndexRangeIterator`] trait's documented contract.
    fn next(&mut self) -> IndexRange {
        let temp = self
            .index_range
            .expect("PropertySetIndexRangeIterator::next called when has_next() is false");
        self.get_next_index_range();
        temp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::NoValueException;
    use crate::util::map::{
        clamp_num_page_bits, compute_page_mask, compute_page_size, ValueStoragePage, ValueStoragePageIndex,
        DEFAULT_NUMBER_PAGE_BITS,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::io::{self, Read, Write};

    /// Minimal in-memory [`ValueStoragePage`] mirroring the worked example established in
    /// `value_map.rs`'s own tests.
    #[derive(Default)]
    struct MockPage {
        values: BTreeMap<i16, i32>,
    }

    impl ValueStoragePage<i32> for MockPage {
        fn get_next(&self, offset: i16) -> Option<i16> {
            self.values
                .range((std::ops::Bound::Excluded(offset), std::ops::Bound::Unbounded))
                .next()
                .map(|(&k, _)| k)
        }
        fn get_previous(&self, offset: i16) -> Option<i16> {
            self.values.range(..offset).next_back().map(|(&k, _)| k)
        }
        fn get_first(&self) -> Option<i16> {
            self.values.keys().next().copied()
        }
        fn get_last(&self) -> Option<i16> {
            self.values.keys().next_back().copied()
        }
        fn is_empty(&self) -> bool {
            self.values.is_empty()
        }
        fn has_property(&self, offset: i16) -> bool {
            self.values.contains_key(&offset)
        }
        fn add_key(&mut self, key: i16) {
            self.values.entry(key).or_insert(0);
        }
        fn get_size(&self) -> usize {
            self.values.len()
        }
        fn remove(&mut self, offset: i16) -> bool {
            self.values.remove(&offset).is_some()
        }
        fn get_saveable_object(
            &self,
            _offset: i16,
        ) -> Result<Option<Box<dyn crate::util::saveable::Saveable>>, crate::util::map::TypeMismatchException>
        {
            Err(crate::util::map::TypeMismatchException::new())
        }
        fn add_saveable_object(&mut self, _offset: i16, _value: Box<dyn crate::util::saveable::Saveable>) {}
        fn get_object(&self, offset: i16) -> Option<i32> {
            self.values.get(&offset).copied()
        }
        fn add_object(&mut self, offset: i16, value: i32) {
            self.values.insert(offset, value);
        }
        fn get_string(&self, _offset: i16) -> Option<String> {
            None
        }
        fn add_string(&mut self, _offset: i16, _value: String) {}
        fn get_int(&self, offset: i16) -> Result<i32, NoValueException> {
            self.values.get(&offset).copied().ok_or_else(NoValueException::new)
        }
        fn add_int(&mut self, offset: i16, value: i32) {
            self.values.insert(offset, value);
        }
        fn get_long(&self, _offset: i16) -> Result<i64, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_long(&mut self, _offset: i16, _value: i64) {}
        fn get_short(&self, _offset: i16) -> Result<i16, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_short(&mut self, _offset: i16, _value: i16) {}
        fn get_byte(&self, _offset: i16) -> Result<i8, NoValueException> {
            Err(NoValueException::new())
        }
        fn add_byte(&mut self, _offset: i16, _value: i8) {}
    }

    /// Minimal [`ValueMap<i32>`] used purely to exercise
    /// [`PropertySetIndexRangeIterator`] end-to-end against a real (if small) property store.
    #[derive(Default)]
    struct MockValueMap {
        num_page_bits: u32,
        page_mask: i64,
        page_size: i16,
        num_properties: i32,
        page_index: ValueStoragePageIndex,
        pages: HashMap<i64, MockPage>,
    }

    impl MockValueMap {
        fn new() -> Self {
            let num_page_bits = clamp_num_page_bits(DEFAULT_NUMBER_PAGE_BITS);
            let page_mask = compute_page_mask(num_page_bits);
            Self {
                num_page_bits,
                page_mask,
                page_size: compute_page_size(page_mask),
                ..Default::default()
            }
        }

        fn put(&mut self, index: i64, value: i32) {
            let page_id = self.get_page_id(index);
            let offset = self.get_page_offset(index);
            let page = self.get_or_create_page(page_id);
            let before = page.get_size();
            page.add_object(offset, value);
            let added = page.get_size() - before;
            self.num_properties += added as i32;
        }
    }

    impl ValueMap<i32> for MockValueMap {
        fn get_data_size(&self) -> i32 {
            4
        }
        fn move_index(&mut self, _from: i64, _to: i64) {}
        fn save_property(&self, _out: &mut dyn Write, _addr: i64) -> io::Result<()> {
            Ok(())
        }
        fn restore_property(&mut self, _input: &mut dyn Read, _addr: i64) -> io::Result<()> {
            Ok(())
        }
        fn name(&self) -> &str {
            "mock"
        }
        fn num_page_bits(&self) -> u32 {
            self.num_page_bits
        }
        fn page_mask(&self) -> i64 {
            self.page_mask
        }
        fn page_size(&self) -> i16 {
            self.page_size
        }
        fn num_properties(&self) -> i32 {
            self.num_properties
        }
        fn num_properties_mut(&mut self) -> &mut i32 {
            &mut self.num_properties
        }
        fn page_index(&self) -> &ValueStoragePageIndex {
            &self.page_index
        }
        fn page_index_mut(&mut self) -> &mut ValueStoragePageIndex {
            &mut self.page_index
        }
        fn get_page(&self, page_id: i64) -> Option<&dyn ValueStoragePage<i32>> {
            self.pages.get(&page_id).map(|p| p as &dyn ValueStoragePage<i32>)
        }
        fn get_page_mut(&mut self, page_id: i64) -> Option<&mut dyn ValueStoragePage<i32>> {
            self.pages.get_mut(&page_id).map(|p| p as &mut dyn ValueStoragePage<i32>)
        }
        fn get_or_create_page(&mut self, page_id: i64) -> &mut dyn ValueStoragePage<i32> {
            if !self.pages.contains_key(&page_id) {
                self.pages.insert(page_id, MockPage::default());
                self.page_index.add(page_id);
            }
            self.pages.get_mut(&page_id).unwrap()
        }
        fn remove_page_storage(&mut self, page_id: i64) {
            self.pages.remove(&page_id);
        }
    }

    #[test]
    fn no_properties_yields_a_single_unbounded_range() {
        let map = MockValueMap::new();
        let mut it = PropertySetIndexRangeIterator::new(&map, 0);
        assert!(it.has_next());
        let range = it.next();
        assert_eq!(range.start(), 0);
        assert_eq!(range.end(), i64::MAX);
        assert!(!it.has_next());
    }

    #[test]
    fn ranges_split_at_each_property_index() {
        let mut map = MockValueMap::new();
        map.put(5, 1);
        map.put(10, 1);

        let mut it = PropertySetIndexRangeIterator::new(&map, 0);

        let r1 = it.next();
        assert_eq!(r1, IndexRange::new(0, 4));

        let r2 = it.next();
        assert_eq!(r2, IndexRange::new(5, 9));

        let r3 = it.next();
        assert_eq!(r3, IndexRange::new(10, i64::MAX));

        assert!(!it.has_next());
    }

    #[test]
    fn starting_between_two_properties() {
        let mut map = MockValueMap::new();
        map.put(5, 1);
        map.put(10, 1);

        let mut it = PropertySetIndexRangeIterator::new(&map, 6);
        let r1 = it.next();
        assert_eq!(r1, IndexRange::new(6, 9));
        let r2 = it.next();
        assert_eq!(r2, IndexRange::new(10, i64::MAX));
        assert!(!it.has_next());
    }

    #[test]
    #[should_panic(expected = "has_next() is false")]
    fn next_after_exhaustion_panics() {
        let map = MockValueMap::new();
        let mut it = PropertySetIndexRangeIterator::new(&map, 0);
        it.next();
        it.next();
    }

    #[test]
    fn properties_across_pages_still_split_correctly() {
        let mut map = MockValueMap::new();
        let page_span = 1i64 << DEFAULT_NUMBER_PAGE_BITS;
        map.put(3, 1);
        map.put(page_span + 2, 1);

        let mut it = PropertySetIndexRangeIterator::new(&map, 0);
        assert_eq!(it.next(), IndexRange::new(0, 2));
        assert_eq!(it.next(), IndexRange::new(3, page_span + 1));
        assert_eq!(it.next(), IndexRange::new(page_span + 2, i64::MAX));
        assert!(!it.has_next());
    }
}
