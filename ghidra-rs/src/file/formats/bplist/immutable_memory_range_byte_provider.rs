use std::io;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::program::model::address::Address;
use crate::program::model::mem::Memory;

/// A read-only [`ByteProvider`] view over a fixed, inclusive `[start, end]`
/// address range of a [`Memory`].
///
/// Corresponds to `ghidra.file.formats.bplist.ImmutableMemoryRangeByteProvider`.
pub struct ImmutableMemoryRangeByteProvider<'a> {
    memory: &'a dyn Memory,
    start: Address,
    end: Address,
}

impl<'a> ImmutableMemoryRangeByteProvider<'a> {
    /// Creates a provider over `memory` spanning the inclusive range `[start, end]`.
    pub fn new(memory: &'a dyn Memory, start: Address, end: Address) -> Self {
        Self { memory, start, end }
    }
}

impl<'a> ByteProvider for ImmutableMemoryRangeByteProvider<'a> {
    fn length(&mut self) -> io::Result<u64> {
        Ok((self.end.subtract(&self.start) + 1) as u64)
    }

    /// Mirrors the Java source's comparison directions exactly (`start >=
    /// indexAddress && end <= indexAddress`), which only admits `index == 0`
    /// for a non-degenerate range. This looks like a latent bug upstream, but
    /// parity is preserved rather than silently "fixed" here.
    fn is_valid_index(&mut self, index: u64) -> bool {
        let Ok(displacement) = i64::try_from(index) else {
            return false;
        };
        let Ok(index_address) = self.start.add(displacement) else {
            return false;
        };
        self.start.cmp(&index_address) != std::cmp::Ordering::Less
            && self.end.cmp(&index_address) != std::cmp::Ordering::Greater
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        let displacement = i64::try_from(index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let index_address = self
            .start
            .add(displacement)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        self.memory
            .get_byte(&index_address)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        let displacement = i64::try_from(index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let index_address = self
            .start
            .add(displacement)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let mut bytes = vec![0u8; length];
        let n_read = self.memory.get_bytes(&index_address, &mut bytes);
        if n_read != length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Unable to read {length} bytes at index {index}"),
            ));
        }
        Ok(bytes)
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ImmutableMemoryRangeByteProvider does not support writes",
        ))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ImmutableMemoryRangeByteProvider does not support writes",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::Arc;

    struct FakeMemory {
        base: Address,
        data: Vec<u8>,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let offset = addr.subtract(&self.base);
            self.data
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let offset = addr.subtract(&self.base) as usize;
            let available = self.data.len().saturating_sub(offset);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.data[offset..offset + n]);
            n
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("read-only fake"))
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[test]
    fn length_is_inclusive_range_size() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![0u8; 4] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1003));
        assert_eq!(provider.length().unwrap(), 4);
    }

    #[test]
    fn length_of_single_byte_range_is_one() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![0u8; 1] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1000));
        assert_eq!(provider.length().unwrap(), 1);
    }

    #[test]
    fn is_valid_index_only_true_at_zero_for_single_byte_range() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![0xAB] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1000));
        assert!(provider.is_valid_index(0));
        assert!(!provider.is_valid_index(1));
    }

    #[test]
    fn is_valid_index_false_for_wider_range() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![0u8; 4] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1003));
        // Mirrors the Java source's comparison directions, which only admit
        // index == 0 when start == end.
        assert!(!provider.is_valid_index(0));
        assert!(!provider.is_valid_index(2));
    }

    #[test]
    fn read_byte_reads_from_underlying_memory() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![0x11, 0x22, 0x33] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1002));
        assert_eq!(provider.read_byte(1).unwrap(), 0x22);
    }

    #[test]
    fn read_byte_out_of_bounds_errors() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![0x11] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1000));
        assert!(provider.read_byte(5).is_err());
    }

    #[test]
    fn read_bytes_reads_a_slice() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![1, 2, 3, 4, 5] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1004));
        assert_eq!(provider.read_bytes(1, 3).unwrap(), vec![2, 3, 4]);
    }

    #[test]
    fn read_bytes_short_read_errors() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![1, 2] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1001));
        assert!(provider.read_bytes(0, 10).is_err());
    }

    #[test]
    fn write_byte_is_unsupported() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![1] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1000));
        let err = provider.write_byte(0, 0xFF).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn write_bytes_is_unsupported() {
        let memory = FakeMemory { base: addr(0x1000), data: vec![1] };
        let mut provider = ImmutableMemoryRangeByteProvider::new(&memory, addr(0x1000), addr(0x1000));
        let err = provider.write_bytes(0, &[0xFF]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
