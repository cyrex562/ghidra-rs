use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Data;

/// DataBuffer provides an array-like interface into a set of Data at a specific index.
/// Data can be retrieved by using a positive offset from the current position.
/// The purpose of this trait is to provide an opaque storage mechanism for Data
/// that is made up of other Data items.
///
/// This interface does not provide methods to reposition the data item buffer.
/// This is so that it is clear that methods accepting this base trait are not to
/// modify the base Address for this object.
///
/// Port of `ghidra.program.model.listing.DataBuffer`.
pub trait DataBuffer {
    /// Get one Data item from the buffer at the current position plus offset.
    ///
    /// # Arguments
    /// * `offset` - the displacement from the current position.
    ///
    /// # Returns
    /// The Data item at offset from the current position.
    ///
    /// # Errors
    /// Returns `None` if the offset is negative or exceeds the address space.
    fn get_data(&self, offset: i32) -> Option<Arc<dyn Data>>;

    /// Get the next data item starting after offset.
    ///
    /// # Arguments
    /// * `offset` - offset to look after
    ///
    /// # Returns
    /// Data item starting after this offset, or `None` if no such item exists.
    fn get_data_after(&self, offset: i32) -> Option<Arc<dyn Data>>;

    /// Get the previous data item starting before offset.
    ///
    /// # Arguments
    /// * `offset` - offset to look before
    ///
    /// # Returns
    /// Data item starting before this offset, or `None` if no such item exists.
    fn get_data_before(&self, offset: i32) -> Option<Arc<dyn Data>>;

    /// Get the offset to the next data item found after offset.
    ///
    /// # Arguments
    /// * `offset` - offset to look after
    ///
    /// # Returns
    /// The offset of the first data item existing after this one,
    /// or `None` if no such item exists.
    fn get_next_offset(&self, offset: i32) -> Option<i32>;

    /// Get the offset to the previous data item existing before this offset.
    ///
    /// # Arguments
    /// * `offset` - offset to look before
    ///
    /// # Returns
    /// The offset of the first data item existing before this one,
    /// or `None` if no such item exists.
    fn get_previous_offset(&self, offset: i32) -> Option<i32>;

    /// Get an array of data items that begin at or after start up to end.
    /// - Data items that exist before start are not returned
    /// - Data items that exist before end, but terminate after end ARE returned
    ///
    /// # Arguments
    /// * `start` - start offset
    /// * `end` - end offset
    ///
    /// # Returns
    /// Array of Data items that exist between start and end.
    fn get_data_range(&self, start: i32, end: i32) -> Vec<Arc<dyn Data>>;

    /// Get the Address which corresponds to the offset 0.
    ///
    /// # Returns
    /// The current address of offset 0.
    fn get_address(&self) -> Address;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct TestDataBuffer {
        base_address: Address,
    }

    impl TestDataBuffer {
        fn new() -> Self {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Self {
                base_address: Address::new(space, 0),
            }
        }
    }

    impl DataBuffer for TestDataBuffer {
        fn get_data(&self, _offset: i32) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_data_after(&self, _offset: i32) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_data_before(&self, _offset: i32) -> Option<Arc<dyn Data>> {
            None
        }

        fn get_next_offset(&self, _offset: i32) -> Option<i32> {
            None
        }

        fn get_previous_offset(&self, _offset: i32) -> Option<i32> {
            None
        }

        fn get_data_range(&self, _start: i32, _end: i32) -> Vec<Arc<dyn Data>> {
            vec![]
        }

        fn get_address(&self) -> Address {
            self.base_address.clone()
        }
    }

    #[test]
    fn test_get_address() {
        let buffer = TestDataBuffer::new();
        let address = buffer.get_address();
        assert_eq!(address.offset(), 0);
    }

    #[test]
    fn test_get_data_returns_none() {
        let buffer = TestDataBuffer::new();
        assert!(buffer.get_data(0).is_none());
    }

    #[test]
    fn test_get_data_after_returns_none() {
        let buffer = TestDataBuffer::new();
        assert!(buffer.get_data_after(0).is_none());
    }

    #[test]
    fn test_get_data_before_returns_none() {
        let buffer = TestDataBuffer::new();
        assert!(buffer.get_data_before(0).is_none());
    }

    #[test]
    fn test_get_next_offset_returns_none() {
        let buffer = TestDataBuffer::new();
        assert_eq!(buffer.get_next_offset(0), None);
    }

    #[test]
    fn test_get_previous_offset_returns_none() {
        let buffer = TestDataBuffer::new();
        assert_eq!(buffer.get_previous_offset(0), None);
    }

    #[test]
    fn test_get_data_range_returns_empty() {
        let buffer = TestDataBuffer::new();
        let data = buffer.get_data_range(0, 10);
        assert_eq!(data.len(), 0);
    }
}
