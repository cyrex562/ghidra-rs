use std::sync::Arc;

use crate::feature::base::memsearch::bytesource::AddressableByteSource;
use crate::program::model::address::{Address, AddressRange};
use crate::util::bytesearch::byte_sequence::ByteSequence;

/// A [`ByteSequence`] view into an [`AddressableByteSource`].
///
/// By specifying an address and length, this type provides a view into the byte source as an
/// indexable sequence of bytes. It is mutable and can be reused by setting a new address range
/// for this sequence, avoiding constantly allocating large byte arrays.
///
/// Port of `ghidra.util.bytesearch.AddressableByteSequence`.
pub struct AddressableByteSequence {
    byte_source: Arc<dyn AddressableByteSource>,
    bytes: Vec<u8>,
    capacity: usize,
    start_address: Option<Address>,
    length: usize,
}

impl AddressableByteSequence {
    /// Java: `AddressableByteSequence(AddressableByteSource, int)`.
    ///
    /// - `byte_source`: the source of the underlying bytes to buffer from.
    /// - `capacity`: the maximum size range that this object will buffer.
    pub fn new(byte_source: Arc<dyn AddressableByteSource>, capacity: usize) -> Self {
        Self {
            byte_source,
            bytes: vec![0u8; capacity],
            capacity,
            start_address: None,
            length: 0,
        }
    }

    /// Sets this view to an empty byte sequence.
    ///
    /// Java: `clear()`.
    pub fn clear(&mut self) {
        self.start_address = None;
        self.length = 0;
    }

    /// Sets the range of bytes that this object will buffer, from an [`AddressRange`]. This
    /// immediately reads the bytes from the byte source into the internal buffer.
    ///
    /// Java: `setRange(AddressRange)`. Java converts the range's `BigLength` to an `int` and
    /// throws `IllegalArgumentException` if it overflows; ranges here are already bounded by
    /// `usize`, so the length is used directly.
    pub fn set_range(&mut self, range: &AddressRange) {
        self.set_range_at(range.min_address().clone(), range.length() as usize);
    }

    /// Sets the range of bytes that this object will buffer. This immediately reads the bytes
    /// from the byte source into the internal buffer.
    ///
    /// Java: `setRange(Address, int)`.
    ///
    /// # Panics
    ///
    /// Panics if `length` exceeds the sequence's capacity, matching Java's
    /// `IllegalArgumentException("Length exceeds capacity")`.
    pub fn set_range_at(&mut self, start: Address, length: usize) {
        assert!(length <= self.capacity, "Length exceeds capacity");
        self.byte_source.get_bytes(&start, &mut self.bytes[..length], length);
        self.start_address = Some(start);
        self.length = length;
    }

    /// Returns the address of the byte represented by the given index into this buffer.
    ///
    /// Java: `getAddress(int)`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds, matching Java's `IndexOutOfBoundsException`.
    pub fn get_address(&self, index: usize) -> Address {
        assert!(index < self.length, "index out of bounds");
        if index == 0 {
            return self.start_address.clone().expect("range must be set");
        }
        self.start_address
            .as_ref()
            .expect("range must be set")
            .add(index as i64)
            .expect("address overflow")
    }
}

impl ByteSequence for AddressableByteSequence {
    /// Java: `getLength()`.
    fn len(&self) -> usize {
        self.length
    }

    /// Java: `getByte(int)`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds, matching Java's `IndexOutOfBoundsException`.
    fn get_byte(&self, index: usize) -> u8 {
        assert!(index < self.length, "index out of bounds");
        self.bytes[index]
    }

    /// Java: `getBytes(int, int)`.
    ///
    /// # Panics
    ///
    /// Panics if the requested range is out of bounds, matching Java's
    /// `IndexOutOfBoundsException`.
    fn get_bytes(&self, index: usize, size: usize) -> Vec<u8> {
        assert!(index + size <= self.length, "index out of bounds");
        self.bytes[index..index + size].to_vec()
    }

    /// Java: `hasAvailableBytes(int, int)`.
    fn has_available_bytes(&self, index: usize, length: usize) -> bool {
        index.checked_add(length).map_or(false, |end| end <= self.length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::base::memsearch::bytesource::{
        addressable_byte_source::generate_program_location, SearchRegion,
    };
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{
        AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::listing::Program;
    use crate::program::util::program_location::ProgramLocation;

    struct MockProgram {
        factory: Arc<dyn AddressFactory>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "test".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
    }

    /// A byte source backed by an in-memory buffer, addressed relative to a base address.
    struct TestByteSource {
        base: Address,
        data: Vec<u8>,
    }

    impl AddressableByteSource for TestByteSource {
        fn get_bytes(&self, address: &Address, bytes: &mut [u8], length: usize) -> usize {
            let offset = address.subtract(&self.base) as usize;
            let to_copy = length.min(self.data.len().saturating_sub(offset));
            bytes[..to_copy].copy_from_slice(&self.data[offset..offset + to_copy]);
            to_copy
        }

        fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>> {
            vec![]
        }

        fn invalidate(&mut self) {}

        fn get_canonical_location(&self, address: &Address) -> Box<dyn ProgramLocation> {
            generate_program_location(
                Arc::new(MockProgram {
                    factory: Arc::new(DefaultAddressFactory::new(vec![])) as Arc<dyn AddressFactory>,
                }),
                address,
            )
        }

        fn rebase_from_canonical(&self, location: &dyn ProgramLocation) -> Address {
            location.get_address()
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    fn source(data: &[u8]) -> Arc<dyn AddressableByteSource> {
        Arc::new(TestByteSource { base: ram_address(0x1000), data: data.to_vec() })
    }

    #[test]
    fn new_sequence_is_empty() {
        let seq = AddressableByteSequence::new(source(&[1, 2, 3]), 16);
        assert_eq!(seq.len(), 0);
        assert!(seq.is_empty());
    }

    #[test]
    fn set_range_at_reads_bytes_from_source() {
        let mut seq = AddressableByteSequence::new(source(&[0xAA, 0xBB, 0xCC, 0xDD]), 16);
        seq.set_range_at(ram_address(0x1000), 4);
        assert_eq!(seq.len(), 4);
        assert_eq!(seq.get_byte(0), 0xAA);
        assert_eq!(seq.get_byte(1), 0xBB);
        assert_eq!(seq.get_byte(2), 0xCC);
        assert_eq!(seq.get_byte(3), 0xDD);
    }

    #[test]
    fn set_range_at_partial_offset() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3, 4, 5]), 16);
        seq.set_range_at(ram_address(0x1002), 3);
        assert_eq!(seq.len(), 3);
        assert_eq!(seq.get_byte(0), 3);
        assert_eq!(seq.get_byte(1), 4);
        assert_eq!(seq.get_byte(2), 5);
    }

    #[test]
    fn set_range_from_address_range() {
        let mut seq = AddressableByteSequence::new(source(&[9, 8, 7, 6]), 16);
        let range = AddressRange::new(ram_address(0x1000), ram_address(0x1002));
        seq.set_range(&range);
        assert_eq!(seq.len(), 3);
        assert_eq!(seq.get_bytes(0, 3), vec![9, 8, 7]);
    }

    #[test]
    #[should_panic(expected = "Length exceeds capacity")]
    fn set_range_at_panics_when_length_exceeds_capacity() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3, 4, 5]), 4);
        seq.set_range_at(ram_address(0x1000), 5);
    }

    #[test]
    fn set_range_at_exact_capacity_succeeds() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3, 4]), 4);
        seq.set_range_at(ram_address(0x1000), 4);
        assert_eq!(seq.len(), 4);
    }

    #[test]
    fn clear_resets_to_empty() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3]), 16);
        seq.set_range_at(ram_address(0x1000), 3);
        assert_eq!(seq.len(), 3);
        seq.clear();
        assert_eq!(seq.len(), 0);
        assert!(seq.is_empty());
    }

    #[test]
    fn get_address_returns_addresses_relative_to_start() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3, 4]), 16);
        seq.set_range_at(ram_address(0x1000), 4);
        assert_eq!(seq.get_address(0), ram_address(0x1000));
        assert_eq!(seq.get_address(1), ram_address(0x1001));
        assert_eq!(seq.get_address(3), ram_address(0x1003));
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn get_address_panics_out_of_bounds() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3]), 16);
        seq.set_range_at(ram_address(0x1000), 3);
        let _ = seq.get_address(3);
    }

    #[test]
    fn get_byte_panics_out_of_bounds() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3]), 16);
        seq.set_range_at(ram_address(0x1000), 3);
        // Scope catch_unwind tightly around just the call under test, per house rule: a loose
        // #[should_panic] on a multi-step test only proves *a* panic happened somewhere, not
        // that this specific call panicked.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| seq.get_byte(3)));
        assert!(result.is_err(), "get_byte(3) on a length-3 sequence must panic");
    }

    #[test]
    fn get_bytes_returns_requested_slice() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3, 4, 5]), 16);
        seq.set_range_at(ram_address(0x1000), 5);
        assert_eq!(seq.get_bytes(1, 3), vec![2, 3, 4]);
    }

    #[test]
    fn get_bytes_panics_when_range_exceeds_length() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3]), 16);
        seq.set_range_at(ram_address(0x1000), 3);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| seq.get_bytes(1, 3)));
        assert!(result.is_err(), "get_bytes(1, 3) on a length-3 sequence must panic");
    }

    #[test]
    fn has_available_bytes_within_and_outside_bounds() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3, 4]), 16);
        seq.set_range_at(ram_address(0x1000), 4);
        assert!(seq.has_available_bytes(0, 4));
        assert!(seq.has_available_bytes(2, 2));
        assert!(!seq.has_available_bytes(2, 3));
        assert!(!seq.has_available_bytes(4, 1));
    }

    #[test]
    fn has_available_bytes_overflow_safe() {
        let seq = AddressableByteSequence::new(source(&[1]), 16);
        assert!(!seq.has_available_bytes(usize::MAX, 2));
    }

    #[test]
    fn sequence_can_be_reused_across_multiple_ranges() {
        // Java's doc comment: "It is mutable and can be reused by setting a new address range
        // for this sequence. This was to avoid constantly allocating large byte arrays."
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3, 4, 5, 6]), 16);
        seq.set_range_at(ram_address(0x1000), 2);
        assert_eq!(seq.get_bytes(0, 2), vec![1, 2]);
        seq.set_range_at(ram_address(0x1003), 3);
        assert_eq!(seq.get_bytes(0, 3), vec![4, 5, 6]);
        // The underlying buffer is reused, not reallocated: length reflects only the latest
        // range even though the buffer's capacity is larger.
        assert_eq!(seq.len(), 3);
    }

    #[test]
    fn implements_byte_sequence_trait_object() {
        let mut seq = AddressableByteSequence::new(source(&[1, 2, 3]), 16);
        seq.set_range_at(ram_address(0x1000), 3);
        let as_trait: &dyn ByteSequence = &seq;
        assert_eq!(as_trait.len(), 3);
        assert_eq!(as_trait.get_byte(0), 1);
    }
}
