use std::io::{Read, Write};

use crate::util::task::TaskMonitor;

use super::CliToolWrapper;

/// Functionality common to stream decompressor CLI tools.
///
/// Mirrors `ghidra.file.cliwrapper.StreamDecompressorCliToolWrapper`.
pub trait StreamDecompressorCliToolWrapper: CliToolWrapper {
    /// Decompresses an input stream and writes the result to an output stream.
    ///
    /// # Arguments
    ///
    /// * `is` - Input stream containing compressed data.
    /// * `os` - Output stream to write decompressed data to.
    /// * `monitor` - Task monitor for progress tracking and cancellation.
    ///
    /// # Returns
    ///
    /// `Ok(())` if decompression succeeds, or an I/O error if it fails.
    fn decompress_stream(
        &self,
        is: &mut dyn Read,
        os: &mut dyn Write,
        monitor: &dyn TaskMonitor,
    ) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct MockStreamDecompressor {
        should_fail: bool,
    }

    impl CliToolWrapper for MockStreamDecompressor {
        fn is_valid(&self, _monitor: &dyn TaskMonitor) -> bool {
            true
        }
    }

    impl StreamDecompressorCliToolWrapper for MockStreamDecompressor {
        fn decompress_stream(
            &self,
            _is: &mut dyn Read,
            _os: &mut dyn Write,
            _monitor: &dyn TaskMonitor,
        ) -> std::io::Result<()> {
            if self.should_fail {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "test failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn trait_object_construction() {
        let mock = MockStreamDecompressor { should_fail: false };
        let _: &dyn StreamDecompressorCliToolWrapper = &mock;
    }

    #[test]
    fn decompress_stream_success() {
        let mock = MockStreamDecompressor { should_fail: false };
        let monitor = crate::util::task::DummyMonitor;
        let mut input = Cursor::new(vec![1, 2, 3]);
        let mut output = Vec::new();

        let result = mock.decompress_stream(&mut input, &mut output, &monitor);
        assert!(result.is_ok());
    }

    #[test]
    fn decompress_stream_failure() {
        let mock = MockStreamDecompressor { should_fail: true };
        let monitor = crate::util::task::DummyMonitor;
        let mut input = Cursor::new(vec![1, 2, 3]);
        let mut output = Vec::new();

        let result = mock.decompress_stream(&mut input, &mut output, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn stream_decompressor_with_data() {
        struct EchoDecompressor;

        impl CliToolWrapper for EchoDecompressor {
            fn is_valid(&self, _monitor: &dyn TaskMonitor) -> bool {
                true
            }
        }

        impl StreamDecompressorCliToolWrapper for EchoDecompressor {
            fn decompress_stream(
                &self,
                is: &mut dyn Read,
                os: &mut dyn Write,
                _monitor: &dyn TaskMonitor,
            ) -> std::io::Result<()> {
                let mut buffer = [0u8; 256];
                loop {
                    let n = is.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    os.write_all(&buffer[..n])?;
                }
                Ok(())
            }
        }

        let decompressor = EchoDecompressor;
        let monitor = crate::util::task::DummyMonitor;
        let data = vec![1, 2, 3, 4, 5];
        let mut input = Cursor::new(data.clone());
        let mut output = Vec::new();

        let result = decompressor.decompress_stream(&mut input, &mut output, &monitor);
        assert!(result.is_ok());
        assert_eq!(output, data);
    }

    #[test]
    fn multiple_trait_objects() {
        let success = MockStreamDecompressor { should_fail: false };
        let failure = MockStreamDecompressor { should_fail: true };

        let tools: Vec<&dyn StreamDecompressorCliToolWrapper> = vec![&success, &failure];
        let monitor = crate::util::task::DummyMonitor;
        let mut input = Cursor::new(vec![]);
        let mut output = Vec::new();

        assert!(tools[0].decompress_stream(&mut input, &mut output, &monitor).is_ok());
        assert!(tools[1].decompress_stream(&mut input, &mut output, &monitor).is_err());
    }
}
