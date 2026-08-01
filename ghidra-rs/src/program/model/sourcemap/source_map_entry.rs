//! Port of `ghidra.program.model.sourcemap.SourceMapEntry` as a trait (cycle cut-point).
//!
//! A `SourceMapEntry` associates a [`SourceFile`], a line number, a base address, and a length.
//! If the length is positive, the base address and the length determine an [`AddressRange`]; the
//! length of a `SourceMapEntry` is then the length of that range, i.e. the number of addresses it
//! contains (see `AddressRange::len`). The range is meant to contain all the bytes corresponding
//! to a given line of source. The length can be 0, in which case the associated range is `None`.
//! Negative lengths are not allowed by the Java type; callers construct entries through
//! `SourceFileManager`, which enforces this and the other invariants documented on the Java
//! interface (no restrictions are re-checked here, since this trait only exposes read access to
//! already-constructed entries).
//!
//! `Comparable<SourceMapEntry>` is ported as [`compare_to`](SourceMapEntry::compare_to), taking
//! `&dyn SourceMapEntry` so the trait stays object-safe, matching the `compare_to` convention used
//! elsewhere in this crate (e.g. `SubMemoryBlock::compare_to`).

use crate::program::database::sourcemap::SourceFile;
use crate::program::model::address::{Address, AddressRange};

/// A `SourceMapEntry` consists of a [`SourceFile`], a line number, a base address, and a length.
///
/// Port of `ghidra.program.model.sourcemap.SourceMapEntry`. See the module docs for what was
/// left out and why.
pub trait SourceMapEntry {
    /// Returns the line number. Stands in for `SourceMapEntry.getLineNumber()`.
    fn get_line_number(&self) -> i32;

    /// Returns the source file. Stands in for `SourceMapEntry.getSourceFile()`.
    fn get_source_file(&self) -> SourceFile;

    /// Returns the base address of the entry. Stands in for `SourceMapEntry.getBaseAddress()`.
    fn get_base_address(&self) -> Address;

    /// Returns the length of the range (number of addresses). Stands in for
    /// `SourceMapEntry.getLength()`.
    fn get_length(&self) -> i64;

    /// Returns the address range, or `None` for length-0 entries. Stands in for
    /// `SourceMapEntry.getRange()`.
    fn get_range(&self) -> Option<AddressRange>;

    /// Compares this entry to `other`. Stands in for `SourceMapEntry`'s
    /// `Comparable<SourceMapEntry>.compareTo(SourceMapEntry)`.
    fn compare_to(&self, other: &dyn SourceMapEntry) -> std::cmp::Ordering;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::cmp::Ordering;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockEntry {
        line_number: i32,
        source_file: SourceFile,
        base_address: Address,
        length: i64,
    }

    impl SourceMapEntry for MockEntry {
        fn get_line_number(&self) -> i32 {
            self.line_number
        }

        fn get_source_file(&self) -> SourceFile {
            self.source_file.clone()
        }

        fn get_base_address(&self) -> Address {
            self.base_address.clone()
        }

        fn get_length(&self) -> i64 {
            self.length
        }

        fn get_range(&self) -> Option<AddressRange> {
            if self.length == 0 {
                None
            } else {
                Some(
                    AddressRange::from_start_len(self.base_address.clone(), self.length as u64)
                        .expect("no overflow in test"),
                )
            }
        }

        fn compare_to(&self, other: &dyn SourceMapEntry) -> Ordering {
            self.base_address
                .cmp(&other.get_base_address())
                .then_with(|| self.line_number.cmp(&other.get_line_number()))
        }
    }

    fn mock_source_file(name: &str) -> SourceFile {
        SourceFile::new(&format!("/src/{name}")).expect("valid source file")
    }

    #[test]
    fn zero_length_entry_has_no_range() {
        let entry = MockEntry {
            line_number: 10,
            source_file: mock_source_file("foo.c"),
            base_address: mock_address(0x1000),
            length: 0,
        };
        assert_eq!(entry.get_range(), None);
        assert_eq!(entry.get_length(), 0);
    }

    #[test]
    fn positive_length_entry_has_derived_range() {
        let entry = MockEntry {
            line_number: 20,
            source_file: mock_source_file("bar.c"),
            base_address: mock_address(0x2000),
            length: 0x10,
        };
        let range = entry.get_range().expect("non-empty range");
        assert_eq!(range.min_address(), &mock_address(0x2000));
        assert_eq!(range.max_address(), &mock_address(0x200f));
    }

    #[test]
    fn compare_to_orders_by_base_address_then_line() {
        let low = MockEntry {
            line_number: 1,
            source_file: mock_source_file("a.c"),
            base_address: mock_address(0x100),
            length: 4,
        };
        let high = MockEntry {
            line_number: 1,
            source_file: mock_source_file("a.c"),
            base_address: mock_address(0x200),
            length: 4,
        };
        assert_eq!(low.compare_to(&high), Ordering::Less);
        assert_eq!(high.compare_to(&low), Ordering::Greater);
        assert_eq!(low.compare_to(&low), Ordering::Equal);
    }
}
