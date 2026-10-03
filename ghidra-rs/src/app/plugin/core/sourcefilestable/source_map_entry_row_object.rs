//! Port of `ghidra.app.plugin.core.sourcefilestable.SourceMapEntryRowObject`.

use crate::program::model::address::Address;

/// A row object for the source map entry table (`SourceMapEntryTableModel`).
#[derive(Debug, Clone)]
pub struct SourceMapEntryRowObject {
    base_address: Address,
    line_number: i32,
    length: i64,
    count: i32,
}

impl SourceMapEntryRowObject {
    /// Creates a row for the source map entry at `base_address` for source line `line_number`,
    /// with the entry's `length` and the `count` of mappings for that source line.
    pub fn new(base_address: Address, line_number: i32, length: i64, count: i32) -> Self {
        Self { base_address, line_number, length, count }
    }

    /// Returns the base address.
    pub fn get_base_address(&self) -> &Address {
        &self.base_address
    }

    /// Returns the source file line number.
    pub fn get_line_number(&self) -> i32 {
        self.line_number
    }

    /// Returns the length of the associated source map entry.
    pub fn get_length(&self) -> i64 {
        self.length
    }

    /// Returns the number of entries for this line number.
    pub fn get_count(&self) -> i32 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn accessors_return_constructor_values() {
        let row = SourceMapEntryRowObject::new(addr(0x401000), 42, 16, 3);
        assert_eq!(row.get_base_address().offset(), 0x401000);
        assert_eq!(row.get_line_number(), 42);
        assert_eq!(row.get_length(), 16);
        assert_eq!(row.get_count(), 3);
    }

    #[test]
    fn zero_length_entry_and_extreme_values_are_kept_verbatim() {
        // Java stores the fields without validation; a zero-length entry is legal.
        let row = SourceMapEntryRowObject::new(addr(0), i32::MAX, 0, 1);
        assert_eq!(row.get_base_address().offset(), 0);
        assert_eq!(row.get_line_number(), i32::MAX);
        assert_eq!(row.get_length(), 0);
        assert_eq!(row.get_count(), 1);

        let big = SourceMapEntryRowObject::new(addr(0x10), 1, i64::MAX, 0);
        assert_eq!(big.get_length(), i64::MAX);
        assert_eq!(big.get_count(), 0);
    }
}
