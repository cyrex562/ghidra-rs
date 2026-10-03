use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Base structure holding the shared state of indirect table headers (DWARFAddressListHeader,
/// DWARFLocationListHeader, etc).
///
/// Mirrors the concrete fields and methods of the abstract Java class
/// `DWARFIndirectTableHeader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DWARFIndirectTableHeaderBase {
    start_offset: u64,
    end_offset: u64,
    first_element_offset: u64,
}

impl DWARFIndirectTableHeaderBase {
    pub fn new(start_offset: u64, end_offset: u64, first_element_offset: u64) -> Self {
        DWARFIndirectTableHeaderBase {
            start_offset,
            end_offset,
            first_element_offset,
        }
    }

    /// Mirrors `DWARFIndirectTableHeader.getStartOffset()`.
    pub fn get_start_offset(&self) -> u64 {
        self.start_offset
    }

    /// Mirrors `DWARFIndirectTableHeader.getFirstElementOffset()`.
    pub fn get_first_element_offset(&self) -> u64 {
        self.first_element_offset
    }

    /// Mirrors `DWARFIndirectTableHeader.getEndOffset()`.
    pub fn get_end_offset(&self) -> u64 {
        self.end_offset
    }
}

/// Abstract interface for indirect table headers, declaring the abstract method
/// from the Java class `DWARFIndirectTableHeader`.
///
/// Concrete implementations should embed a `DWARFIndirectTableHeaderBase` and implement
/// this trait to define the offset lookup behavior specific to their header type.
pub trait DWARFIndirectTableHeader {
    /// Mirrors `DWARFIndirectTableHeader.getOffset(int, BinaryReader)`.
    fn get_offset(&self, index: i32, reader: &BinaryReader) -> io::Result<i64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_creation_and_getters() {
        let base = DWARFIndirectTableHeaderBase::new(0x100, 0x200, 0x150);
        assert_eq!(base.get_start_offset(), 0x100);
        assert_eq!(base.get_end_offset(), 0x200);
        assert_eq!(base.get_first_element_offset(), 0x150);
    }

    #[test]
    fn base_construction_with_different_offsets() {
        let base = DWARFIndirectTableHeaderBase::new(0, 0x1000, 0x500);
        assert_eq!(base.get_start_offset(), 0);
        assert_eq!(base.get_end_offset(), 0x1000);
        assert_eq!(base.get_first_element_offset(), 0x500);
    }

    #[test]
    fn base_clone_and_equality() {
        let base1 = DWARFIndirectTableHeaderBase::new(0x100, 0x200, 0x150);
        let base2 = base1.clone();
        assert_eq!(base1, base2);
    }
}
