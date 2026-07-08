use crate::program::model::address::Address;
use crate::program::model::mem::{Memory, MemoryAccessException};

/// Extends [`Memory`] with default implementations for typed multi-byte reads and writes,
/// built entirely on top of the required `get_bytes`/`set_bytes` primitives.
///
/// Port of `ghidra.trace.util.MemoryAdapter`.
pub trait MemoryAdapter: Memory {
    /// Reads exactly `length` bytes at `addr`, failing if fewer bytes are available.
    fn must_read(&self, addr: &Address, length: usize) -> Result<Vec<u8>, MemoryAccessException> {
        let mut buf = vec![0u8; length];
        if self.get_bytes(addr, &mut buf) != length {
            return Err(MemoryAccessException::default());
        }
        Ok(buf)
    }

    /// Reads a 16-bit value at `addr`, defaulting to big-endian order.
    fn get_short(&self, addr: &Address) -> Result<i16, MemoryAccessException> {
        self.get_short_with_endian(addr, true)
    }

    /// Reads a 16-bit value at `addr` in the requested byte order.
    fn get_short_with_endian(
        &self,
        addr: &Address,
        big_endian: bool,
    ) -> Result<i16, MemoryAccessException> {
        let buf = self.must_read(addr, 2)?;
        let bytes = [buf[0], buf[1]];
        Ok(if big_endian {
            i16::from_be_bytes(bytes)
        } else {
            i16::from_le_bytes(bytes)
        })
    }

    /// Reads 16-bit values into `dest`, defaulting to big-endian order.
    fn get_shorts(&self, addr: &Address, dest: &mut [i16]) -> usize {
        let n_elem = dest.len();
        self.get_shorts_range(addr, dest, 0, n_elem)
    }

    /// Reads up to `n_elem` 16-bit values into `dest` starting at `d_index`, defaulting to
    /// big-endian order.
    fn get_shorts_range(
        &self,
        addr: &Address,
        dest: &mut [i16],
        d_index: usize,
        n_elem: usize,
    ) -> usize {
        self.get_shorts_with_endian(addr, dest, d_index, n_elem, true)
    }

    /// Reads up to `n_elem` 16-bit values into `dest` starting at `d_index`, in the requested
    /// byte order. Returns the number of values actually read.
    fn get_shorts_with_endian(
        &self,
        addr: &Address,
        dest: &mut [i16],
        d_index: usize,
        n_elem: usize,
        big_endian: bool,
    ) -> usize {
        let mut buf = vec![0u8; 2 * n_elem];
        let got = self.get_bytes(addr, &mut buf) / 2;
        for i in 0..got {
            let bytes = [buf[2 * i], buf[2 * i + 1]];
            dest[d_index + i] = if big_endian {
                i16::from_be_bytes(bytes)
            } else {
                i16::from_le_bytes(bytes)
            };
        }
        got
    }

    /// Reads a 32-bit value at `addr`, defaulting to big-endian order.
    fn get_int(&self, addr: &Address) -> Result<i32, MemoryAccessException> {
        self.get_int_with_endian(addr, true)
    }

    /// Reads a 32-bit value at `addr` in the requested byte order.
    fn get_int_with_endian(
        &self,
        addr: &Address,
        big_endian: bool,
    ) -> Result<i32, MemoryAccessException> {
        let buf = self.must_read(addr, 4)?;
        let bytes = [buf[0], buf[1], buf[2], buf[3]];
        Ok(if big_endian {
            i32::from_be_bytes(bytes)
        } else {
            i32::from_le_bytes(bytes)
        })
    }

    /// Reads 32-bit values into `dest`, defaulting to big-endian order.
    fn get_ints(&self, addr: &Address, dest: &mut [i32]) -> usize {
        let n_elem = dest.len();
        self.get_ints_range(addr, dest, 0, n_elem)
    }

    /// Reads up to `n_elem` 32-bit values into `dest` starting at `d_index`, defaulting to
    /// big-endian order.
    fn get_ints_range(
        &self,
        addr: &Address,
        dest: &mut [i32],
        d_index: usize,
        n_elem: usize,
    ) -> usize {
        self.get_ints_with_endian(addr, dest, d_index, n_elem, true)
    }

    /// Reads up to `n_elem` 32-bit values into `dest` starting at `d_index`, in the requested
    /// byte order. Returns the number of values actually read.
    fn get_ints_with_endian(
        &self,
        addr: &Address,
        dest: &mut [i32],
        d_index: usize,
        n_elem: usize,
        big_endian: bool,
    ) -> usize {
        let mut buf = vec![0u8; 4 * n_elem];
        let got = self.get_bytes(addr, &mut buf) / 4;
        for i in 0..got {
            let bytes = [buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]];
            dest[d_index + i] = if big_endian {
                i32::from_be_bytes(bytes)
            } else {
                i32::from_le_bytes(bytes)
            };
        }
        got
    }

    /// Reads a 64-bit value at `addr`, defaulting to big-endian order.
    fn get_long(&self, addr: &Address) -> Result<i64, MemoryAccessException> {
        self.get_long_with_endian(addr, true)
    }

    /// Reads a 64-bit value at `addr` in the requested byte order.
    fn get_long_with_endian(
        &self,
        addr: &Address,
        big_endian: bool,
    ) -> Result<i64, MemoryAccessException> {
        let buf = self.must_read(addr, 8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buf);
        Ok(if big_endian {
            i64::from_be_bytes(bytes)
        } else {
            i64::from_le_bytes(bytes)
        })
    }

    /// Reads 64-bit values into `dest`, defaulting to big-endian order.
    fn get_longs(&self, addr: &Address, dest: &mut [i64]) -> usize {
        let n_elem = dest.len();
        self.get_longs_range(addr, dest, 0, n_elem)
    }

    /// Reads up to `n_elem` 64-bit values into `dest` starting at `d_index`, defaulting to
    /// big-endian order.
    fn get_longs_range(
        &self,
        addr: &Address,
        dest: &mut [i64],
        d_index: usize,
        n_elem: usize,
    ) -> usize {
        self.get_longs_with_endian(addr, dest, d_index, n_elem, true)
    }

    /// Reads up to `n_elem` 64-bit values into `dest` starting at `d_index`, in the requested
    /// byte order. Returns the number of values actually read.
    fn get_longs_with_endian(
        &self,
        addr: &Address,
        dest: &mut [i64],
        d_index: usize,
        n_elem: usize,
        big_endian: bool,
    ) -> usize {
        let mut buf = vec![0u8; 8 * n_elem];
        let got = self.get_bytes(addr, &mut buf) / 8;
        for i in 0..got {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[8 * i..8 * i + 8]);
            dest[d_index + i] = if big_endian {
                i64::from_be_bytes(bytes)
            } else {
                i64::from_le_bytes(bytes)
            };
        }
        got
    }

    /// Writes a single byte at `addr`.
    fn set_byte(&mut self, addr: &Address, value: u8) -> Result<(), MemoryAccessException> {
        self.set_bytes(addr, &[value])
    }

    /// Writes a 16-bit value at `addr`, defaulting to big-endian order.
    fn set_short(&mut self, addr: &Address, value: i16) -> Result<(), MemoryAccessException> {
        self.set_short_with_endian(addr, value, true)
    }

    /// Writes a 16-bit value at `addr` in the requested byte order.
    fn set_short_with_endian(
        &mut self,
        addr: &Address,
        value: i16,
        big_endian: bool,
    ) -> Result<(), MemoryAccessException> {
        let bytes = if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.set_bytes(addr, &bytes)
    }

    /// Writes a 32-bit value at `addr`, defaulting to big-endian order.
    fn set_int(&mut self, addr: &Address, value: i32) -> Result<(), MemoryAccessException> {
        self.set_int_with_endian(addr, value, true)
    }

    /// Writes a 32-bit value at `addr` in the requested byte order.
    fn set_int_with_endian(
        &mut self,
        addr: &Address,
        value: i32,
        big_endian: bool,
    ) -> Result<(), MemoryAccessException> {
        let bytes = if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.set_bytes(addr, &bytes)
    }

    /// Writes a 64-bit value at `addr`, defaulting to big-endian order.
    fn set_long(&mut self, addr: &Address, value: i64) -> Result<(), MemoryAccessException> {
        self.set_long_with_endian(addr, value, true)
    }

    /// Writes a 64-bit value at `addr` in the requested byte order.
    fn set_long_with_endian(
        &mut self,
        addr: &Address,
        value: i64,
        big_endian: bool,
    ) -> Result<(), MemoryAccessException> {
        let bytes = if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.set_bytes(addr, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn create_test_address_space() -> Arc<AddressSpace> {
        AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    struct MockMemory {
        data: Vec<u8>,
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            true
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.data
                .get(addr.offset() as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let start = addr.offset() as usize;
            if start >= self.data.len() {
                return 0;
            }
            let available = self.data.len() - start;
            let to_read = dest.len().min(available);
            dest[..to_read].copy_from_slice(&self.data[start..start + to_read]);
            to_read
        }

        fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
            let start = addr.offset() as usize;
            if start + source.len() > self.data.len() {
                self.data.resize(start + source.len(), 0);
            }
            self.data[start..start + source.len()].copy_from_slice(source);
            Ok(())
        }
    }

    impl MemoryAdapter for MockMemory {}

    #[test]
    fn must_read_fails_when_short() {
        let space = create_test_address_space();
        let mem = MockMemory { data: vec![1, 2] };
        assert!(mem.must_read(&addr(&space, 0), 4).is_err());
    }

    #[test]
    fn get_short_defaults_to_big_endian() {
        let space = create_test_address_space();
        let mem = MockMemory {
            data: vec![0x12, 0x34],
        };
        assert_eq!(mem.get_short(&addr(&space, 0)).unwrap(), 0x1234i16);
    }

    #[test]
    fn get_short_with_endian_little() {
        let space = create_test_address_space();
        let mem = MockMemory {
            data: vec![0x12, 0x34],
        };
        assert_eq!(
            mem.get_short_with_endian(&addr(&space, 0), false).unwrap(),
            0x3412i16
        );
    }

    #[test]
    fn get_int_defaults_to_big_endian() {
        let space = create_test_address_space();
        let mem = MockMemory {
            data: vec![0x12, 0x34, 0x56, 0x78],
        };
        assert_eq!(mem.get_int(&addr(&space, 0)).unwrap(), 0x12345678i32);
    }

    #[test]
    fn get_long_defaults_to_big_endian() {
        let space = create_test_address_space();
        let mem = MockMemory {
            data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        };
        assert_eq!(
            mem.get_long(&addr(&space, 0)).unwrap(),
            0x0102030405060708i64
        );
    }

    #[test]
    fn get_shorts_reads_multiple_values() {
        let space = create_test_address_space();
        let mem = MockMemory {
            data: vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03],
        };
        let mut dest = [0i16; 3];
        let got = mem.get_shorts(&addr(&space, 0), &mut dest);
        assert_eq!(got, 3);
        assert_eq!(dest, [1, 2, 3]);
    }

    #[test]
    fn get_shorts_reports_partial_read() {
        let space = create_test_address_space();
        let mem = MockMemory {
            data: vec![0x00, 0x01, 0x00, 0x02, 0x00],
        };
        let mut dest = [0i16; 3];
        let got = mem.get_shorts(&addr(&space, 0), &mut dest);
        assert_eq!(got, 2);
        assert_eq!(dest[..2], [1, 2]);
    }

    #[test]
    fn get_ints_reads_multiple_values() {
        let space = create_test_address_space();
        let mem = MockMemory {
            data: vec![
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            ],
        };
        let mut dest = [0i32; 2];
        let got = mem.get_ints(&addr(&space, 0), &mut dest);
        assert_eq!(got, 2);
        assert_eq!(dest, [1, 2]);
    }

    #[test]
    fn get_longs_reads_multiple_values() {
        let space = create_test_address_space();
        let mem = MockMemory {
            data: vec![
                0, 0, 0, 0, 0, 0, 0, 1, //
                0, 0, 0, 0, 0, 0, 0, 2, //
            ],
        };
        let mut dest = [0i64; 2];
        let got = mem.get_longs(&addr(&space, 0), &mut dest);
        assert_eq!(got, 2);
        assert_eq!(dest, [1, 2]);
    }

    #[test]
    fn set_byte_writes_single_byte() {
        let space = create_test_address_space();
        let mut mem = MockMemory { data: vec![0, 0] };
        mem.set_byte(&addr(&space, 1), 0xAB).unwrap();
        assert_eq!(mem.data, vec![0, 0xAB]);
    }

    #[test]
    fn set_short_defaults_to_big_endian() {
        let space = create_test_address_space();
        let mut mem = MockMemory { data: vec![0, 0] };
        mem.set_short(&addr(&space, 0), 0x1234).unwrap();
        assert_eq!(mem.data, vec![0x12, 0x34]);
    }

    #[test]
    fn set_short_with_endian_little() {
        let space = create_test_address_space();
        let mut mem = MockMemory { data: vec![0, 0] };
        mem.set_short_with_endian(&addr(&space, 0), 0x1234, false)
            .unwrap();
        assert_eq!(mem.data, vec![0x34, 0x12]);
    }

    #[test]
    fn set_int_defaults_to_big_endian() {
        let space = create_test_address_space();
        let mut mem = MockMemory {
            data: vec![0, 0, 0, 0],
        };
        mem.set_int(&addr(&space, 0), 0x12345678).unwrap();
        assert_eq!(mem.data, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn set_long_defaults_to_big_endian() {
        let space = create_test_address_space();
        let mut mem = MockMemory {
            data: vec![0; 8],
        };
        mem.set_long(&addr(&space, 0), 0x0102030405060708).unwrap();
        assert_eq!(
            mem.data,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }
}
