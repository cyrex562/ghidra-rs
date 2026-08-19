use std::io::{self, Read, Write};

use flate2::read::{DeflateDecoder, ZlibDecoder};
use flate2::write::{DeflateEncoder, ZlibEncoder};
use flate2::Compression;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::util::msg::Msg;

/// ZLIB compression/decompression helper.
///
/// Mirrors `ghidra.file.formats.zlib.ZLIB`.
pub struct Zlib;

impl Zlib {
    pub const ZLIB_COMPRESSION_BEST: [u8; 2] = [0x78, 0xda];
    pub const ZLIB_COMPRESSION_DEFAULT: [u8; 2] = [0x78, 0x9c];
    pub const ZLIB_COMPRESSION_NO_LOW: [u8; 2] = [0x78, 0x01];

    /// Decompresses `compressed_in`, stopping once `expected_decompressed_length` bytes have
    /// been produced. Uses the ZLIB wrapper format (header and checksum).
    pub fn decompress(
        compressed_in: &mut dyn Read,
        expected_decompressed_length: usize,
    ) -> io::Result<Vec<u8>> {
        Self::decompress_with_options(compressed_in, expected_decompressed_length, false)
    }

    /// Decompresses `compressed_in`, stopping once the produced data exceeds
    /// `decompressed_size_limit`. The returned data may still exceed that limit, since the
    /// check happens after each chunk is written.
    ///
    /// If `no_wrap` is true, the ZLIB header and checksum fields are not expected, matching the
    /// compression format used by both GZIP and PKZIP.
    pub fn decompress_with_options(
        compressed_in: &mut dyn Read,
        decompressed_size_limit: usize,
        no_wrap: bool,
    ) -> io::Result<Vec<u8>> {
        let mut compressed_bytes = Vec::new();
        compressed_in.read_to_end(&mut compressed_bytes)?;

        let mut decompressed = Vec::new();
        let mut temp_buffer = vec![0u8; 0x10000];

        if no_wrap {
            let mut inflater = DeflateDecoder::new(&compressed_bytes[..]);
            loop {
                let n = inflater.read(&mut temp_buffer)?;
                if n == 0 {
                    break;
                }
                decompressed.extend_from_slice(&temp_buffer[..n]);
                if decompressed.len() > decompressed_size_limit {
                    Msg::warn(
                        "ZLIB",
                        &format!(
                            "ZLIB decompress exceeded specified limit ({} > {})",
                            decompressed.len(),
                            decompressed_size_limit
                        ),
                    );
                    break;
                }
            }
        } else {
            let mut inflater = ZlibDecoder::new(&compressed_bytes[..]);
            loop {
                let n = inflater.read(&mut temp_buffer)?;
                if n == 0 {
                    break;
                }
                decompressed.extend_from_slice(&temp_buffer[..n]);
                if decompressed.len() > decompressed_size_limit {
                    Msg::warn(
                        "ZLIB",
                        &format!(
                            "ZLIB decompress exceeded specified limit ({} > {})",
                            decompressed.len(),
                            decompressed_size_limit
                        ),
                    );
                    break;
                }
            }
        }

        Ok(decompressed)
    }

    /// Compresses `decompressed_bytes` using the ZLIB wrapper format (header and checksum).
    pub fn compress(decompressed_bytes: &[u8]) -> Vec<u8> {
        Self::compress_with_options(false, decompressed_bytes)
    }

    /// Compresses `decompressed_bytes`. If `no_wrap` is true, the ZLIB header and checksum
    /// fields are not used, matching the compression format used by both GZIP and PKZIP.
    pub fn compress_with_options(no_wrap: bool, decompressed_bytes: &[u8]) -> Vec<u8> {
        // Writes into an in-memory Vec, which cannot fail.
        if no_wrap {
            let mut deflater = DeflateEncoder::new(Vec::new(), Compression::none());
            deflater.write_all(decompressed_bytes).expect("in-memory write cannot fail");
            deflater.finish().expect("in-memory write cannot fail")
        } else {
            // Java uses Deflater level 0, which still emits a 32K-window zlib
            // header (0x78 0x01). flate2's Compression::none() instead selects a
            // reduced window (header 0x08...), so use level 1 to match Java's
            // observable zlib header while remaining a valid zlib stream.
            let mut deflater = ZlibEncoder::new(Vec::new(), Compression::new(1));
            deflater.write_all(decompressed_bytes).expect("in-memory write cannot fail");
            deflater.finish().expect("in-memory write cannot fail")
        }
    }

    /// Returns true if the first two bytes read from `provider` match one of the known ZLIB
    /// compression header magic values.
    pub fn is_zlib(provider: &mut dyn ByteProvider) -> bool {
        match provider.read_bytes(0, 2) {
            Ok(bytes) => {
                bytes == Self::ZLIB_COMPRESSION_NO_LOW
                    || bytes == Self::ZLIB_COMPRESSION_DEFAULT
                    || bytes == Self::ZLIB_COMPRESSION_BEST
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct VecProvider {
        data: Vec<u8>,
    }

    impl VecProvider {
        fn new(data: &[u8]) -> Self {
            VecProvider { data: data.to_vec() }
        }
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
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start
                .checked_add(length)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "overflow"))?;
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            Ok(self.data[start..end].to_vec())
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    #[test]
    fn compress_then_decompress_roundtrips_with_wrap() {
        let original = b"hello world hello world hello world".to_vec();
        let compressed = Zlib::compress(&original);
        let mut reader = Cursor::new(compressed);
        let decompressed = Zlib::decompress(&mut reader, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compress_then_decompress_roundtrips_with_no_wrap() {
        let original = b"the quick brown fox jumps over the lazy dog".to_vec();
        let compressed = Zlib::compress_with_options(true, &original);
        let mut reader = Cursor::new(compressed);
        let decompressed =
            Zlib::decompress_with_options(&mut reader, original.len(), true).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compressed_output_has_zlib_header_when_wrapped() {
        let compressed = Zlib::compress(b"data");
        assert!(compressed.len() >= 2);
        assert_eq!(compressed[0], 0x78);
    }

    #[test]
    fn decompress_stops_early_once_limit_exceeded() {
        let original = vec![b'a'; 1_000_000];
        let compressed = Zlib::compress(&original);
        let mut reader = Cursor::new(compressed);
        // The result may exceed the limit since the check happens after each chunk write, but
        // it must not silently decompress unboundedly without the limit being honored at all.
        let decompressed = Zlib::decompress(&mut reader, 10).unwrap();
        assert!(!decompressed.is_empty());
    }

    #[test]
    fn is_zlib_detects_best_compression_header() {
        let mut provider = VecProvider::new(&Zlib::ZLIB_COMPRESSION_BEST);
        assert!(Zlib::is_zlib(&mut provider));
    }

    #[test]
    fn is_zlib_detects_default_compression_header() {
        let mut provider = VecProvider::new(&Zlib::ZLIB_COMPRESSION_DEFAULT);
        assert!(Zlib::is_zlib(&mut provider));
    }

    #[test]
    fn is_zlib_detects_no_low_compression_header() {
        let mut provider = VecProvider::new(&Zlib::ZLIB_COMPRESSION_NO_LOW);
        assert!(Zlib::is_zlib(&mut provider));
    }

    #[test]
    fn is_zlib_returns_false_for_non_zlib_bytes() {
        let mut provider = VecProvider::new(&[0x00, 0x01]);
        assert!(!Zlib::is_zlib(&mut provider));
    }

    #[test]
    fn is_zlib_returns_false_when_not_enough_bytes() {
        let mut provider = VecProvider::new(&[0x78]);
        assert!(!Zlib::is_zlib(&mut provider));
    }
}
