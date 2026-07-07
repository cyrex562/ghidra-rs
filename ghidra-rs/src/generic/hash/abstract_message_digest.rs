use crate::generic::hash::MessageDigest;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Behavior a concrete message digest algorithm must supply.
///
/// Mirrors the methods of `generic.hash.MessageDigest` that `AbstractMessageDigest` leaves
/// abstract for its Java subclasses to implement: the single-byte update, the buffer-based
/// digest, the long digest, and reset. Rust has no inheritance, so algorithm-specific state
/// (e.g. a running hash value) lives on the implementor of this trait, and
/// [`AbstractMessageDigest`] holds it via composition, driving the template-method logic that
/// Java's abstract class finalized.
pub trait MessageDigestBehavior {
    /// Updates the digest using the specified byte.
    fn update(&mut self, input: u8);

    /// Updates the digest using the specified array of bytes, starting at `offset` for `len`
    /// bytes. The default loops over [`update`](Self::update); override for efficiency, as the
    /// Java doc on this method warns.
    fn update_bytes_with_offset(&mut self, input: &[u8], offset: usize, len: usize) {
        let mut offset = offset;
        for _ in 0..len {
            self.update(input[offset]);
            offset += 1;
        }
    }

    /// Same as [`update_bytes_with_offset`](Self::update_bytes_with_offset), but checks
    /// `monitor` for cancellation before each byte.
    fn update_bytes_with_offset_monitored(
        &mut self,
        input: &[u8],
        offset: usize,
        len: usize,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let mut offset = offset;
        for _ in 0..len {
            monitor.check_cancelled()?;
            self.update(input[offset]);
            offset += 1;
        }
        Ok(())
    }

    /// Completes the hash computation by performing final operations such as padding, storing
    /// the result into `buf` at `offset` for up to `len` bytes. The digest is reset after this
    /// call. Returns the number of bytes placed into `buf`.
    fn digest_into_buf(&mut self, buf: &mut [u8], offset: usize, len: usize) -> usize;

    /// Completes the hash computation, returning (up to) the first 8 bytes as a big-endian
    /// long value. The digest is reset after this call.
    fn digest_long(&mut self) -> i64;

    /// Resets the digest for further use.
    fn reset(&mut self);
}

/// Port of `generic.hash.AbstractMessageDigest`.
///
/// Java subclasses inherit this class's `algorithm`/`digestLength` fields and its `final`
/// template-method implementations of the byte/short/int/long/array `update` overloads and
/// `digest()`. Rust has no inheritance, so this struct instead owns that shared state plus a
/// boxed [`MessageDigestBehavior`] supplying the algorithm-specific pieces, and implements
/// [`MessageDigest`] in full on their behalf.
pub struct AbstractMessageDigest {
    algorithm: String,
    digest_length: usize,
    behavior: Box<dyn MessageDigestBehavior>,
}

impl AbstractMessageDigest {
    /// Creates a new digest with the given algorithm name, digest length in bytes, and
    /// algorithm-specific behavior.
    pub fn new(
        algorithm: impl Into<String>,
        digest_length: usize,
        behavior: Box<dyn MessageDigestBehavior>,
    ) -> Self {
        Self { algorithm: algorithm.into(), digest_length, behavior }
    }
}

impl MessageDigest for AbstractMessageDigest {
    fn get_algorithm(&self) -> &str {
        &self.algorithm
    }

    fn get_digest_length(&self) -> usize {
        self.digest_length
    }

    fn update(&mut self, input: u8) {
        self.behavior.update(input);
    }

    fn update_short(&mut self, input: i16) {
        self.update(((input >> 8) & 0xff) as u8);
        self.update((input & 0xff) as u8);
    }

    fn update_int(&mut self, input: i32) {
        self.update(((input >> 24) & 0xff) as u8);
        self.update(((input >> 16) & 0xff) as u8);
        self.update(((input >> 8) & 0xff) as u8);
        self.update((input & 0xff) as u8);
    }

    fn update_long(&mut self, input: i64) {
        self.update(((input >> 56) & 0xff) as u8);
        self.update(((input >> 48) & 0xff) as u8);
        self.update(((input >> 40) & 0xff) as u8);
        self.update(((input >> 32) & 0xff) as u8);
        self.update(((input >> 24) & 0xff) as u8);
        self.update(((input >> 16) & 0xff) as u8);
        self.update(((input >> 8) & 0xff) as u8);
        self.update((input & 0xff) as u8);
    }

    fn update_bytes(&mut self, input: &[u8]) {
        self.update_bytes_with_offset(input, 0, input.len());
    }

    fn update_bytes_with_offset(&mut self, input: &[u8], offset: usize, len: usize) {
        self.behavior.update_bytes_with_offset(input, offset, len);
    }

    fn update_bytes_monitored(
        &mut self,
        input: &[u8],
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        self.update_bytes_with_offset_monitored(input, 0, input.len(), monitor)
    }

    fn update_bytes_with_offset_monitored(
        &mut self,
        input: &[u8],
        offset: usize,
        len: usize,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        self.behavior.update_bytes_with_offset_monitored(input, offset, len, monitor)
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut results = vec![0u8; self.digest_length];
        self.digest_into_buf(&mut results, 0, self.digest_length);
        results
    }

    fn digest_long(&mut self) -> i64 {
        self.behavior.digest_long()
    }

    fn digest_into_buf(&mut self, buf: &mut [u8], offset: usize, len: usize) -> usize {
        self.behavior.digest_into_buf(buf, offset, len)
    }

    fn reset(&mut self) {
        self.behavior.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockBehavior {
        data: Vec<u8>,
        reset_calls: usize,
    }

    impl MockBehavior {
        fn new() -> Self {
            MockBehavior { data: Vec::new(), reset_calls: 0 }
        }
    }

    impl MessageDigestBehavior for MockBehavior {
        fn update(&mut self, input: u8) {
            self.data.push(input);
        }

        fn digest_into_buf(&mut self, buf: &mut [u8], offset: usize, len: usize) -> usize {
            let copy_len = std::cmp::min(len, self.data.len());
            let end = std::cmp::min(offset + copy_len, buf.len());
            if offset < buf.len() {
                buf[offset..end].copy_from_slice(&self.data[..end - offset]);
            }
            self.data.clear();
            copy_len
        }

        fn digest_long(&mut self) -> i64 {
            let result = std::mem::take(&mut self.data);
            if result.len() >= 8 {
                i64::from_be_bytes([
                    result[0], result[1], result[2], result[3], result[4], result[5], result[6],
                    result[7],
                ])
            } else {
                0
            }
        }

        fn reset(&mut self) {
            self.reset_calls += 1;
            self.data.clear();
        }
    }

    struct CancelAfterMonitor {
        remaining: AtomicUsize,
    }

    impl TaskMonitor for CancelAfterMonitor {
        fn is_cancelled(&self) -> bool {
            self.remaining.load(Ordering::SeqCst) == 0
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            let remaining = self.remaining.load(Ordering::SeqCst);
            if remaining == 0 {
                return Err(CancelledException::default());
            }
            self.remaining.store(remaining - 1, Ordering::SeqCst);
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {
            self.remaining.store(0, Ordering::SeqCst);
        }
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    fn new_digest() -> AbstractMessageDigest {
        AbstractMessageDigest::new("MOCK", 16, Box::new(MockBehavior::new()))
    }

    #[test]
    fn algorithm_name_is_returned() {
        let digest = new_digest();
        assert_eq!(digest.get_algorithm(), "MOCK");
    }

    #[test]
    fn digest_length_is_returned() {
        let digest = new_digest();
        assert_eq!(digest.get_digest_length(), 16);
    }

    #[test]
    fn update_single_byte() {
        let mut digest = new_digest();
        digest.update(42);
        assert_eq!(digest.digest_into_buf(&mut [0u8; 1], 0, 1), 1);
    }

    #[test]
    fn update_short_big_endian() {
        let mut digest = new_digest();
        digest.update_short(0x1234);
        let mut buf = [0u8; 2];
        let written = digest.digest_into_buf(&mut buf, 0, 2);
        assert_eq!(written, 2);
        assert_eq!(buf, [0x12, 0x34]);
    }

    #[test]
    fn update_int_big_endian() {
        let mut digest = new_digest();
        digest.update_int(0x1234_5678);
        let mut buf = [0u8; 4];
        digest.digest_into_buf(&mut buf, 0, 4);
        assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn update_long_big_endian() {
        let mut digest = new_digest();
        digest.update_long(0x0102_0304_0506_0708);
        let mut buf = [0u8; 8];
        digest.digest_into_buf(&mut buf, 0, 8);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn update_bytes_delegates_full_slice() {
        let mut digest = new_digest();
        digest.update_bytes(b"hello");
        let mut buf = [0u8; 5];
        digest.digest_into_buf(&mut buf, 0, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn update_bytes_with_offset_slices_input() {
        let mut digest = new_digest();
        digest.update_bytes_with_offset(b"hello world", 6, 5);
        let mut buf = [0u8; 5];
        digest.digest_into_buf(&mut buf, 0, 5);
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn digest_uses_digest_length_as_buffer_size() {
        let mut digest = AbstractMessageDigest::new("MOCK", 4, Box::new(MockBehavior::new()));
        digest.update_bytes(b"abcd");
        let result = digest.digest();
        assert_eq!(result, b"abcd");
    }

    #[test]
    fn digest_long_from_bytes() {
        let mut digest = new_digest();
        digest.update_long(0x0102_0304_0506_0708);
        assert_eq!(digest.digest_long(), 0x0102_0304_0506_0708u64 as i64);
    }

    #[test]
    fn reset_delegates_to_behavior() {
        let mut behavior = MockBehavior::new();
        behavior.update(1);
        let mut digest = AbstractMessageDigest::new("MOCK", 16, Box::new(behavior));
        digest.reset();
        // Nothing observable through the trait besides no panic; verify via digest_into_buf
        // returning zero bytes copied since the mock cleared its data on reset.
        let mut buf = [0xffu8; 1];
        assert_eq!(digest.digest_into_buf(&mut buf, 0, 1), 0);
    }

    #[test]
    fn update_bytes_monitored_updates_full_input() {
        let mut digest = new_digest();
        let monitor = CancelAfterMonitor { remaining: AtomicUsize::new(10) };
        digest.update_bytes_monitored(b"hi", &monitor).unwrap();
        let mut buf = [0u8; 2];
        digest.digest_into_buf(&mut buf, 0, 2);
        assert_eq!(&buf, b"hi");
    }

    #[test]
    fn update_bytes_with_offset_monitored_stops_on_cancellation() {
        let mut digest = new_digest();
        let monitor = CancelAfterMonitor { remaining: AtomicUsize::new(2) };
        let result = digest.update_bytes_with_offset_monitored(b"hello", 0, 5, &monitor);
        assert!(result.is_err());
    }
}
