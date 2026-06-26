use std::io;
use std::io::Read;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// Wraps a [`ByteProvider`] and presents it as a [`Read`] stream.
///
/// The stream is limited to a region of the underlying provider, with an optional
/// zero-filled padding appended after the real data. The provider is **not** closed
/// when this reader is dropped.
///
/// Total bytes readable: `length + pad_count`.
pub struct ByteProviderPaddedInputStream<'a, P: ByteProvider> {
    provider: &'a mut P,
    current_bp_offset: u64,
    bp_end_offset: u64,
    bp_end_pad_offset: u64,
}

impl<'a, P: ByteProvider> ByteProviderPaddedInputStream<'a, P> {
    /// Creates a new padded stream over `provider`.
    ///
    /// - `start_offset`: first byte position within the provider to expose.
    /// - `length`: number of real bytes to expose.
    /// - `pad_count`: number of synthetic zero bytes to append after the real region.
    pub fn new(provider: &'a mut P, start_offset: u64, length: u64, pad_count: u64) -> Self {
        let bp_end_offset = start_offset + length;
        let bp_end_pad_offset = bp_end_offset + pad_count;
        ByteProviderPaddedInputStream {
            provider,
            current_bp_offset: start_offset,
            bp_end_offset,
            bp_end_pad_offset,
        }
    }

    /// Returns the number of bytes remaining (real + padding), capped at `i32::MAX`
    /// to mirror Java's `InputStream.available()` contract.
    pub fn available(&self) -> usize {
        let remaining = self.bp_end_pad_offset.saturating_sub(self.current_bp_offset);
        remaining.min(i32::MAX as u64) as usize
    }
}

impl<'a, P: ByteProvider> Read for ByteProviderPaddedInputStream<'a, P> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.current_bp_offset >= self.bp_end_pad_offset {
            return Ok(0);
        }

        let mut written = 0;

        // Read real bytes from the provider.
        if self.current_bp_offset < self.bp_end_offset {
            let real_remaining = self.bp_end_offset - self.current_bp_offset;
            let to_read = buf.len().min(real_remaining as usize);
            let data = self.provider.read_bytes(self.current_bp_offset, to_read)?;
            buf[..to_read].copy_from_slice(&data);
            self.current_bp_offset += to_read as u64;
            written += to_read;
        }

        // Fill padding bytes with zero.
        if written < buf.len() && self.current_bp_offset < self.bp_end_pad_offset {
            let pad_remaining = self.bp_end_pad_offset - self.current_bp_offset;
            let to_pad = (buf.len() - written).min(pad_remaining as usize);
            for slot in &mut buf[written..written + to_pad] {
                *slot = 0;
            }
            self.current_bp_offset += to_pad as u64;
            written += to_pad;
        }

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct VecProvider {
        data: Vec<u8>,
    }

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.data.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.data.len()
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.data
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"));
            }
            Ok(self.data[start..end].to_vec())
        }
        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            self.data[index as usize] = value;
            Ok(())
        }
        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            self.data[start..start + values.len()].copy_from_slice(values);
            Ok(())
        }
    }

    fn make_provider(data: &[u8]) -> VecProvider {
        VecProvider { data: data.to_vec() }
    }

    #[test]
    fn reads_full_region() {
        let mut p = make_provider(&[1, 2, 3, 4, 5]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 5, 0);
        let mut buf = vec![0u8; 5];
        assert_eq!(stream.read(&mut buf).unwrap(), 5);
        assert_eq!(buf, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn reads_subregion() {
        let mut p = make_provider(&[10, 20, 30, 40, 50]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 1, 3, 0);
        let mut buf = vec![0u8; 3];
        assert_eq!(stream.read(&mut buf).unwrap(), 3);
        assert_eq!(buf, vec![20, 30, 40]);
    }

    #[test]
    fn padding_only_stream() {
        let mut p = make_provider(&[]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 0, 4);
        let mut buf = vec![0xFFu8; 4];
        assert_eq!(stream.read(&mut buf).unwrap(), 4);
        assert_eq!(buf, vec![0, 0, 0, 0]);
    }

    #[test]
    fn real_bytes_then_padding() {
        let mut p = make_provider(&[1, 2, 3]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 3, 2);
        let mut buf = vec![0xFFu8; 5];
        assert_eq!(stream.read(&mut buf).unwrap(), 5);
        assert_eq!(buf, vec![1, 2, 3, 0, 0]);
    }

    #[test]
    fn eof_returns_zero() {
        let mut p = make_provider(&[1, 2]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 2, 0);
        let mut buf = vec![0u8; 2];
        stream.read(&mut buf).unwrap();
        assert_eq!(stream.read(&mut buf).unwrap(), 0); // EOF
    }

    #[test]
    fn empty_stream_returns_zero() {
        let mut p = make_provider(&[]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 0, 0);
        let mut buf = vec![0u8; 4];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn available_counts_real_and_padding() {
        let mut p = make_provider(&[1, 2, 3]);
        let stream = ByteProviderPaddedInputStream::new(&mut p, 0, 3, 5);
        assert_eq!(stream.available(), 8);
    }

    #[test]
    fn available_decreases_after_reads() {
        let mut p = make_provider(&[1, 2, 3]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 3, 2);
        assert_eq!(stream.available(), 5);
        let mut buf = vec![0u8; 2];
        stream.read(&mut buf).unwrap();
        assert_eq!(stream.available(), 3);
    }

    #[test]
    fn available_at_eof_is_zero() {
        let mut p = make_provider(&[1]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 1, 0);
        let mut buf = vec![0u8; 1];
        stream.read(&mut buf).unwrap();
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn partial_read_when_buf_smaller_than_remaining() {
        let mut p = make_provider(&[10, 20, 30, 40]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 4, 0);
        let mut buf = vec![0u8; 2];
        assert_eq!(stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, vec![10, 20]);
        assert_eq!(stream.available(), 2);
        assert_eq!(stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, vec![30, 40]);
    }

    #[test]
    fn reads_across_real_to_pad_boundary() {
        let mut p = make_provider(&[7, 8]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 2, 3);
        let mut buf = vec![0xFFu8; 5];
        assert_eq!(stream.read(&mut buf).unwrap(), 5);
        assert_eq!(buf, vec![7, 8, 0, 0, 0]);
    }

    #[test]
    fn start_offset_respected() {
        let mut p = make_provider(&[0, 0, 5, 6, 7]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 2, 3, 0);
        let mut buf = vec![0u8; 3];
        assert_eq!(stream.read(&mut buf).unwrap(), 3);
        assert_eq!(buf, vec![5, 6, 7]);
    }

    #[test]
    fn empty_buf_returns_zero_without_advancing() {
        let mut p = make_provider(&[1, 2, 3]);
        let mut stream = ByteProviderPaddedInputStream::new(&mut p, 0, 3, 0);
        assert_eq!(stream.read(&mut []).unwrap(), 0);
        assert_eq!(stream.available(), 3);
    }
}
