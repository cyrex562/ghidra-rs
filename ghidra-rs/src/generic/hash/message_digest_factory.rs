use crate::generic::hash::MessageDigest;

/// A factory for creating [`MessageDigest`] implementations.
///
/// This trait provides a factory method to create new message digest instances
/// with the appropriate algorithm and state.
pub trait MessageDigestFactory {
    /// Creates a new [`MessageDigest`] instance ready to compute message digests.
    fn create_digest(&self) -> Box<dyn MessageDigest>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    struct MockMessageDigest;

    impl MessageDigest for MockMessageDigest {
        fn get_algorithm(&self) -> &str {
            "TEST"
        }

        fn get_digest_length(&self) -> usize {
            16
        }

        fn update(&mut self, _input: u8) {}

        fn update_short(&mut self, _input: i16) {}

        fn update_int(&mut self, _input: i32) {}

        fn update_long(&mut self, _input: i64) {}

        fn update_bytes(&mut self, _input: &[u8]) {}

        fn update_bytes_with_offset(&mut self, _input: &[u8], _offset: usize, _len: usize) {}

        fn update_bytes_monitored(
            &mut self,
            _input: &[u8],
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn update_bytes_with_offset_monitored(
            &mut self,
            _input: &[u8],
            _offset: usize,
            _len: usize,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn digest(&mut self) -> Vec<u8> {
            vec![0; 16]
        }

        fn digest_long(&mut self) -> i64 {
            0
        }

        fn digest_into_buf(&mut self, buf: &mut [u8], offset: usize, len: usize) -> usize {
            let n = buf.len().saturating_sub(offset).min(len);
            for i in 0..n {
                buf[offset + i] = 0;
            }
            n
        }

        fn reset(&mut self) {}
    }

    struct TestFactory;

    impl MessageDigestFactory for TestFactory {
        fn create_digest(&self) -> Box<dyn MessageDigest> {
            Box::new(MockMessageDigest)
        }
    }

    #[test]
    fn factory_creates_digest() {
        let factory = TestFactory;
        let digest = factory.create_digest();
        assert_eq!(digest.get_algorithm(), "TEST");
        assert_eq!(digest.get_digest_length(), 16);
    }

    #[test]
    fn factory_creates_independent_instances() {
        let factory = TestFactory;
        let digest1 = factory.create_digest();
        let digest2 = factory.create_digest();

        assert_eq!(digest1.get_algorithm(), digest2.get_algorithm());
        assert_eq!(digest1.get_digest_length(), digest2.get_digest_length());
    }
}
