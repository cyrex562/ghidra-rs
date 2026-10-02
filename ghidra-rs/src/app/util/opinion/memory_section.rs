//! Port of `ghidra.app.util.opinion.MemorySection`: one memory "section" a
//! [`MemorySectionResolverBase`](super::memory_section_resolver::MemorySectionResolverBase) will
//! place into program memory.
//!
//! Java keys a section by the `MemoryLoadable` (ELF segment / section header object) it came
//! from, compared by identity; here the key is any small copyable identifier `K` the loader
//! chooses (the ELF builder uses the header's index), which gives the same identity semantics
//! without borrowing the header.

use std::fmt;
use std::sync::Arc;

use crate::program::model::address::{AddressRange, AddressSpace, AddressSpaceType};
use crate::program::model::address::Address;

/// A memory "section" awaiting resolution into memory blocks.
#[derive(Debug, Clone)]
pub struct MemorySection<K> {
    pub(crate) key: Option<K>,
    // source data information
    pub(crate) is_initialized: bool,
    pub(crate) file_offset: i64,
    /// Byte length of section.
    pub(crate) length: i64,
    pub(crate) is_fragmentation_ok: bool,
    // destination information
    pub(crate) physical_addr_range: AddressRange,
    // metadata
    pub(crate) section_name: String,
    pub(crate) is_readable: bool,
    pub(crate) is_writable: bool,
    pub(crate) is_execute: bool,
    pub(crate) comment: Option<String>,
}

/// Java's `IllegalArgumentException("memory-based address required")`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("memory-based address required")]
pub struct NotMemoryAddressError;

impl<K> MemorySection<K> {
    /// Mirrors the package-private constructor.
    ///
    /// # Errors
    /// [`NotMemoryAddressError`] if `physical_addr_range` is not in a memory space.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: Option<K>,
        is_initialized: bool,
        file_offset: i64,
        length: i64,
        physical_addr_range: AddressRange,
        section_name: String,
        is_readable: bool,
        is_writable: bool,
        is_execute: bool,
        comment: Option<String>,
        is_fragmentation_ok: bool,
    ) -> Result<Self, NotMemoryAddressError> {
        if !physical_addr_range.space().is_memory_space() {
            return Err(NotMemoryAddressError);
        }
        Ok(MemorySection {
            key,
            is_initialized,
            file_offset,
            length,
            physical_addr_range,
            section_name,
            is_readable,
            is_writable,
            is_execute,
            comment,
            is_fragmentation_ok,
        })
    }

    pub fn get_key(&self) -> Option<&K> {
        self.key.as_ref()
    }

    pub fn is_initialized(&self) -> bool {
        self.is_initialized
    }

    pub fn get_file_offset(&self) -> i64 {
        self.file_offset
    }

    pub fn get_number_of_bytes(&self) -> i64 {
        self.length
    }

    pub fn get_physical_address_range(&self) -> &AddressRange {
        &self.physical_addr_range
    }

    pub fn get_min_physical_address(&self) -> &Address {
        self.physical_addr_range.min_address()
    }

    pub fn get_max_physical_address(&self) -> &Address {
        self.physical_addr_range.max_address()
    }

    pub fn get_physical_address_space(&self) -> &Arc<AddressSpace> {
        self.physical_addr_range.min_address().space()
    }

    pub fn get_section_name(&self) -> &str {
        &self.section_name
    }

    /// Mirrors `isLoaded()`: Java compares the space against the `AddressSpace.OTHER_SPACE`
    /// singleton; any OTHER-typed space is that space here.
    pub fn is_loaded(&self) -> bool {
        self.physical_addr_range.space().space_type() != AddressSpaceType::Other
    }

    pub fn is_readable(&self) -> bool {
        self.is_readable
    }

    pub fn is_writable(&self) -> bool {
        self.is_writable
    }

    pub fn is_execute(&self) -> bool {
        self.is_execute
    }

    pub fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }
}

impl<K> fmt::Display for MemorySection<K> {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let range = format!(
            "[{}, {}]",
            self.physical_addr_range.min_address(),
            self.physical_addr_range.max_address()
        );
        if self.is_initialized {
            write!(f, "{} ({}, {} @ {})", self.section_name, self.file_offset, self.length, range)
        } else {
            write!(f, "{} (uninitialized @ {})", self.section_name, range)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(space: &Arc<AddressSpace>, start: i64, end: i64) -> AddressRange {
        AddressRange::new(space.address(start), space.address(end))
    }

    #[test]
    fn rejects_non_memory_space_and_reports_loaded() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let other = AddressSpace::new("OTHER", 64, 1, AddressSpaceType::Other, 0);
        let reg = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2);
        let s = MemorySection::<u8>::new(
            Some(1), true, 0x40, 0x10, range(&ram, 0x1000, 0x100f), ".text".into(), true, false,
            true, None, false,
        )
        .unwrap();
        assert!(s.is_loaded());
        assert_eq!(s.get_number_of_bytes(), 0x10);
        assert_eq!(s.get_key(), Some(&1));
        let o = MemorySection::<u8>::new(
            None, true, 0, 4, range(&other, 0, 3), ".comment".into(), false, false, false, None,
            false,
        )
        .unwrap();
        assert!(!o.is_loaded());
        assert!(MemorySection::<u8>::new(
            None, false, -1, 4, range(&reg, 0, 3), "r".into(), false, false, false, None, false,
        )
        .is_err());
    }
}
