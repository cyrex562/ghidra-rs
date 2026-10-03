//! Port of `ghidra.program.model.sourcemap.SourceMapEntryIterator`.

use crate::program::model::sourcemap::SourceMapEntry;
use std::sync::Arc;

/// Iterator that returns [`SourceMapEntry`] items.
///
/// This trait mirrors Ghidra's `SourceMapEntryIterator`, which combines the behavior of both
/// `Iterator` and `Iterable` in Java.
pub trait SourceMapEntryIterator: Iterator<Item = Arc<dyn SourceMapEntry>> {}

/// Empty source map entry iterator, mirroring `SourceMapEntryIterator.EMPTY_ITERATOR`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptySourceMapEntryIterator;

impl Iterator for EmptySourceMapEntryIterator {
    type Item = Arc<dyn SourceMapEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl SourceMapEntryIterator for EmptySourceMapEntryIterator {}

/// List-based source map entry iterator.
///
/// Wraps a vector of entries and iterates over them by consuming ownership.
pub struct ListSourceMapEntryIterator {
    iter: std::vec::IntoIter<Arc<dyn SourceMapEntry>>,
}

impl ListSourceMapEntryIterator {
    /// Creates a new iterator over the supplied source map entries.
    pub fn new(items: Vec<Arc<dyn SourceMapEntry>>) -> Self {
        Self { iter: items.into_iter() }
    }
}

impl Iterator for ListSourceMapEntryIterator {
    type Item = Arc<dyn SourceMapEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl SourceMapEntryIterator for ListSourceMapEntryIterator {}

/// Creates an empty source map entry iterator, mirroring `SourceMapEntryIterator.EMPTY_ITERATOR`.
pub fn empty() -> Box<dyn SourceMapEntryIterator> {
    Box::new(EmptySourceMapEntryIterator)
}

/// Creates a source map entry iterator from a vector of entries.
pub fn of(items: Vec<Arc<dyn SourceMapEntry>>) -> Box<dyn SourceMapEntryIterator> {
    Box::new(ListSourceMapEntryIterator::new(items))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::database::sourcemap::SourceFile;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockSourceMapEntry {
        line_number: i32,
        base_address: Address,
    }

    impl SourceMapEntry for MockSourceMapEntry {
        fn get_line_number(&self) -> i32 {
            self.line_number
        }

        fn get_source_file(&self) -> SourceFile {
            SourceFile::new("/src/file.c").unwrap()
        }

        fn get_base_address(&self) -> Address {
            self.base_address.clone()
        }

        fn get_length(&self) -> i64 {
            4
        }

        fn get_range(&self) -> Option<AddressRange> {
            Some(AddressRange::new(
                self.base_address.clone(),
                mock_address(self.base_address.offset() + 3),
            ))
        }

        fn compare_to(&self, other: &dyn SourceMapEntry) -> std::cmp::Ordering {
            self.base_address
                .cmp(&other.get_base_address())
                .then_with(|| self.line_number.cmp(&other.get_line_number()))
        }
    }

    #[test]
    fn empty_iterator_returns_none() {
        let mut iterator = EmptySourceMapEntryIterator;
        assert!(iterator.next().is_none());
    }

    #[test]
    fn empty_from_factory_returns_none() {
        let mut iterator = empty();
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_yields_entries_in_order() {
        let items: Vec<Arc<dyn SourceMapEntry>> = vec![
            Arc::new(MockSourceMapEntry { line_number: 1, base_address: mock_address(0x100) }),
            Arc::new(MockSourceMapEntry { line_number: 2, base_address: mock_address(0x200) }),
        ];
        let mut iterator = of(items);

        let first = iterator.next().expect("first entry");
        assert_eq!(first.get_line_number(), 1);
        assert_eq!(first.get_base_address(), mock_address(0x100));

        let second = iterator.next().expect("second entry");
        assert_eq!(second.get_line_number(), 2);

        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_empty_list() {
        let items: Vec<Arc<dyn SourceMapEntry>> = vec![];
        let mut iterator = ListSourceMapEntryIterator::new(items);

        assert!(iterator.next().is_none());
    }
}
