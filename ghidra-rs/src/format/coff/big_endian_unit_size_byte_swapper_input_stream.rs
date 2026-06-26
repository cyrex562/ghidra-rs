use std::io::{self, Read};

/// Wraps a reader and byte-swaps within fixed-size addressable units.
///
/// All COFF files are stored as little endian. However, for COFF binaries
/// targeted for WORD-addressable big endian processors, the bytes for the
/// section must be swapped inside the addressable unit.
pub struct BigEndianUnitSizeByteSwapper<R> {
    inner: R,
    unit_size: usize,
    buffer: Vec<u8>,
    /// Index of the next byte to return from `buffer`; -1 when the buffer needs refill.
    buffer_pos: i64,
}

impl<R: Read> BigEndianUnitSizeByteSwapper<R> {
    /// Creates a new swapper wrapping `inner`, reversing bytes in groups of `unit_size`.
    pub fn new(inner: R, unit_size: usize) -> Self {
        assert!(unit_size > 0, "unit_size must be positive");
        Self {
            inner,
            unit_size,
            buffer: vec![0u8; unit_size],
            buffer_pos: -1,
        }
    }
}

impl<R: Read> Read for BigEndianUnitSizeByteSwapper<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.buffer_pos < 0 {
            // Fill one unit from the inner reader, matching Java's byte-at-a-time loop.
            let mut filled = 0;
            while filled < self.unit_size {
                let n = self.inner.read(&mut self.buffer[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                return Ok(0);
            }
            self.buffer_pos = (filled as i64) - 1;
        }
        let byte = self.buffer[self.buffer_pos as usize];
        self.buffer_pos -= 1;
        buf[0] = byte;
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn read_all(mut r: impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn unit_size_1_is_passthrough() {
        let data = vec![0x01u8, 0x02, 0x03];
        let swapper = BigEndianUnitSizeByteSwapper::new(data.as_slice(), 1);
        assert_eq!(read_all(swapper), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn unit_size_2_swaps_pairs() {
        // Input bytes [A, B, C, D] → units [A,B] and [C,D] reversed → [B, A, D, C]
        let data = vec![0xAAu8, 0xBB, 0xCC, 0xDD];
        let swapper = BigEndianUnitSizeByteSwapper::new(data.as_slice(), 2);
        assert_eq!(read_all(swapper), vec![0xBB, 0xAA, 0xDD, 0xCC]);
    }

    #[test]
    fn unit_size_4_swaps_quads() {
        // Input [01 02 03 04 05 06 07 08] → [04 03 02 01 08 07 06 05]
        let data = vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let swapper = BigEndianUnitSizeByteSwapper::new(data.as_slice(), 4);
        assert_eq!(
            read_all(swapper),
            vec![0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05]
        );
    }

    #[test]
    fn empty_input_returns_empty() {
        let data: Vec<u8> = vec![];
        let swapper = BigEndianUnitSizeByteSwapper::new(data.as_slice(), 2);
        assert_eq!(read_all(swapper), Vec::<u8>::new());
    }

    #[test]
    fn single_unit() {
        let data = vec![0x11u8, 0x22, 0x33, 0x44];
        let swapper = BigEndianUnitSizeByteSwapper::new(data.as_slice(), 4);
        assert_eq!(read_all(swapper), vec![0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn reads_one_byte_at_a_time() {
        let data = vec![0xAAu8, 0xBB];
        let mut swapper = BigEndianUnitSizeByteSwapper::new(data.as_slice(), 2);
        let mut byte = [0u8; 1];
        assert_eq!(swapper.read(&mut byte).unwrap(), 1);
        assert_eq!(byte[0], 0xBB);
        assert_eq!(swapper.read(&mut byte).unwrap(), 1);
        assert_eq!(byte[0], 0xAA);
        assert_eq!(swapper.read(&mut byte).unwrap(), 0);
    }
}
