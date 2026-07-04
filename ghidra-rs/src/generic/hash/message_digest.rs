use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A trait defining the interface for computing message digests.
///
/// Implementations provide one-way hash functions supporting incremental updates
/// with various data types. After calling [`digest`](Self::digest) or related methods,
/// the digest is reset and ready for reuse.
pub trait MessageDigest {
    /// Returns a string that identifies the algorithm, independent of implementation details.
    fn get_algorithm(&self) -> &str;

    /// Returns the length of the digest in bytes.
    fn get_digest_length(&self) -> usize;

    /// Updates the digest using the specified byte.
    fn update(&mut self, input: u8);

    /// Updates the digest using the specified short (big endian).
    fn update_short(&mut self, input: i16);

    /// Updates the digest using the specified int (big endian).
    fn update_int(&mut self, input: i32);

    /// Updates the digest using the specified long (big endian).
    fn update_long(&mut self, input: i64);

    /// Updates the digest using the specified array of bytes. Do not use a monitor.
    fn update_bytes(&mut self, input: &[u8]);

    /// Updates the digest using the specified array of bytes, starting at the specified offset
    /// (and for the specified length). Do not use a monitor.
    fn update_bytes_with_offset(&mut self, input: &[u8], offset: usize, len: usize);

    /// Updates the digest using the specified array of bytes.
    fn update_bytes_monitored(
        &mut self,
        input: &[u8],
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Updates the digest using the specified array of bytes, starting at the specified offset
    /// (and for the specified length).
    fn update_bytes_with_offset_monitored(
        &mut self,
        input: &[u8],
        offset: usize,
        len: usize,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Completes the hash computation by performing final operations such as padding.
    /// The digest is reset after this call is made.
    fn digest(&mut self) -> Vec<u8>;

    /// Completes the hash computation by performing final operations such as padding,
    /// and returns (up to) the first 8 bytes as a big-endian long value.
    /// The digest is reset after this call is made.
    fn digest_long(&mut self) -> i64;

    /// Completes the hash computation by performing final operations such as padding.
    /// The digest is reset after this call is made.
    /// Stores the result into the output buffer at the given offset.
    ///
    /// Returns the number of bytes placed into buf.
    fn digest_into_buf(&mut self, buf: &mut [u8], offset: usize, len: usize) -> usize;

    /// Resets the digest for further use.
    fn reset(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDigest {
        algorithm: String,
        digest_length: usize,
        data: Vec<u8>,
    }

    impl MockDigest {
        fn new(algorithm: &str, digest_length: usize) -> Self {
            MockDigest {
                algorithm: algorithm.to_string(),
                digest_length,
                data: Vec::new(),
            }
        }
    }

    impl MessageDigest for MockDigest {
        fn get_algorithm(&self) -> &str {
            &self.algorithm
        }

        fn get_digest_length(&self) -> usize {
            self.digest_length
        }

        fn update(&mut self, input: u8) {
            self.data.push(input);
        }

        fn update_short(&mut self, input: i16) {
            self.data.extend_from_slice(&input.to_be_bytes());
        }

        fn update_int(&mut self, input: i32) {
            self.data.extend_from_slice(&input.to_be_bytes());
        }

        fn update_long(&mut self, input: i64) {
            self.data.extend_from_slice(&input.to_be_bytes());
        }

        fn update_bytes(&mut self, input: &[u8]) {
            self.data.extend_from_slice(input);
        }

        fn update_bytes_with_offset(&mut self, input: &[u8], offset: usize, len: usize) {
            let end = std::cmp::min(offset + len, input.len());
            if offset < input.len() {
                self.data.extend_from_slice(&input[offset..end]);
            }
        }

        fn update_bytes_monitored(
            &mut self,
            input: &[u8],
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.update_bytes(input);
            Ok(())
        }

        fn update_bytes_with_offset_monitored(
            &mut self,
            input: &[u8],
            offset: usize,
            len: usize,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.update_bytes_with_offset(input, offset, len);
            Ok(())
        }

        fn digest(&mut self) -> Vec<u8> {
            let result = self.data.clone();
            self.data.clear();
            result
        }

        fn digest_long(&mut self) -> i64 {
            let result = self.digest();
            if result.len() >= 8 {
                i64::from_be_bytes([
                    result[0], result[1], result[2], result[3], result[4], result[5], result[6],
                    result[7],
                ])
            } else if result.is_empty() {
                0i64
            } else {
                let mut buf = [0u8; 8];
                buf[..result.len()].copy_from_slice(&result);
                i64::from_be_bytes(buf)
            }
        }

        fn digest_into_buf(&mut self, buf: &mut [u8], offset: usize, len: usize) -> usize {
            let result = self.digest();
            let copy_len = std::cmp::min(len, result.len());
            let end = std::cmp::min(offset + copy_len, buf.len());
            if offset < buf.len() {
                buf[offset..end].copy_from_slice(&result[..end - offset]);
            }
            copy_len
        }

        fn reset(&mut self) {
            self.data.clear();
        }
    }

    #[test]
    fn algorithm_name_is_returned() {
        let digest = MockDigest::new("SHA-256", 32);
        assert_eq!(digest.get_algorithm(), "SHA-256");
    }

    #[test]
    fn digest_length_is_returned() {
        let digest = MockDigest::new("SHA-256", 32);
        assert_eq!(digest.get_digest_length(), 32);
    }

    #[test]
    fn update_single_byte() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update(42);
        let result = digest.digest();
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn update_short_big_endian() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update_short(0x1234);
        let result = digest.digest();
        assert_eq!(result, vec![0x12, 0x34]);
    }

    #[test]
    fn update_int_big_endian() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update_int(0x12345678);
        let result = digest.digest();
        assert_eq!(result, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn update_long_big_endian() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update_long(0x123456789ABCDEF0);
        let result = digest.digest();
        assert_eq!(
            result,
            vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
        );
    }

    #[test]
    fn update_bytes() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update_bytes(b"hello");
        let result = digest.digest();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn update_bytes_with_offset() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update_bytes_with_offset(b"hello world", 6, 5);
        let result = digest.digest();
        assert_eq!(result, b"world");
    }

    #[test]
    fn update_bytes_with_offset_partial() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update_bytes_with_offset(b"hello", 2, 10);
        let result = digest.digest();
        assert_eq!(result, b"llo");
    }

    #[test]
    fn digest_long_from_bytes() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update_long(0x0102030405060708);
        let long_val = digest.digest_long();
        assert_eq!(long_val, 0x0102030405060708i64);
    }

    #[test]
    fn digest_long_zero() {
        let mut digest = MockDigest::new("MOCK", 16);
        let long_val = digest.digest_long();
        assert_eq!(long_val, 0i64);
    }

    #[test]
    fn digest_into_buf() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update_bytes(b"hello");
        let mut buf = [0u8; 16];
        let written = digest.digest_into_buf(&mut buf, 2, 10);
        assert_eq!(written, 5);
        assert_eq!(&buf[2..7], b"hello");
    }

    #[test]
    fn reset_clears_data() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update(1);
        digest.update(2);
        digest.reset();
        let result = digest.digest();
        assert!(result.is_empty());
    }

    #[test]
    fn multiple_digest_calls_reset() {
        let mut digest = MockDigest::new("MOCK", 16);
        digest.update(1);
        let _ = digest.digest();
        digest.update(2);
        let result = digest.digest();
        assert_eq!(result, vec![2]);
    }
}
