use std::io::{self, Read, Seek, SeekFrom};

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// Adapter from a Ghidra [`ByteProvider`] to a standard [`Read`] + [`Seek`] stream.
///
/// Mirrors `ghidra.file.formats.sevenzip.SZByteProviderStream`, which bridges a
/// `ByteProvider` to the SevenZipJBinding `IInStream` interface (`seek(offset,
/// seekOrigin)` / `read(byte[])` / `close()`). That contract maps directly onto
/// Rust's [`Seek`] and [`Read`] traits, so this type implements those instead of
/// reproducing the third-party `IInStream` interface.
pub struct SZByteProviderStream<P: ByteProvider> {
    provider: Option<P>,
    position: u64,
}

impl<P: ByteProvider> SZByteProviderStream<P> {
    /// Wraps `provider`, starting at position `0`.
    pub fn new(provider: P) -> Self {
        SZByteProviderStream {
            provider: Some(provider),
            position: 0,
        }
    }

    /// Drops the underlying provider. Idempotent: closing an already-closed
    /// stream is a no-op. Mirrors the Java `close()`, which closed the wrapped
    /// `ByteProvider`.
    pub fn close(&mut self) {
        self.provider = None;
    }
}

impl<P: ByteProvider> Seek for SZByteProviderStream<P> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos: i64 = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::Current(offset) => self.position as i64 + offset,
            SeekFrom::End(offset) => {
                let len = match &mut self.provider {
                    Some(provider) => provider.length()?,
                    None => 0,
                };
                len as i64 + offset
            }
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid offset: {new_pos}"),
            ));
        }

        self.position = new_pos as u64;
        Ok(self.position)
    }
}

impl<P: ByteProvider> Read for SZByteProviderStream<P> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let provider = match &mut self.provider {
            Some(provider) => provider,
            None => return Ok(0),
        };

        let len = provider.length()?;
        let bytes_to_read = (buf.len() as u64).min(len.saturating_sub(self.position));
        if bytes_to_read == 0 {
            return Ok(0);
        }

        let bytes = provider.read_bytes(self.position, bytes_to_read as usize)?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        self.position += bytes.len() as u64;
        Ok(bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecProvider {
        data: Vec<u8>,
    }

    impl VecProvider {
        fn new(data: Vec<u8>) -> Self {
            VecProvider { data }
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
            let end = start + length;
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            Ok(self.data[start..end].to_vec())
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            let i = index as usize;
            if i >= self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            self.data[i] = value;
            Ok(())
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            let end = start + values.len();
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            self.data[start..end].copy_from_slice(values);
            Ok(())
        }
    }

    #[test]
    fn reads_from_start() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2, 3, 4, 5]));
        let mut buf = [0u8; 3];
        assert_eq!(stream.read(&mut buf).unwrap(), 3);
        assert_eq!(buf, [1, 2, 3]);
    }

    #[test]
    fn read_advances_position_across_calls() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2, 3, 4, 5]));
        let mut buf = [0u8; 2];
        stream.read(&mut buf).unwrap();
        assert_eq!(stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [3, 4]);
    }

    #[test]
    fn read_past_end_is_truncated() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2, 3]));
        let mut buf = [0u8; 10];
        assert_eq!(stream.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], &[1, 2, 3]);
    }

    #[test]
    fn read_at_eof_returns_zero() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2]));
        let mut buf = [0u8; 4];
        stream.read(&mut buf).unwrap();
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn seek_set_moves_to_absolute_offset() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2, 3, 4, 5]));
        assert_eq!(stream.seek(SeekFrom::Start(2)).unwrap(), 2);
        let mut buf = [0u8; 2];
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [3, 4]);
    }

    #[test]
    fn seek_cur_is_relative_to_position() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2, 3, 4, 5]));
        stream.seek(SeekFrom::Start(1)).unwrap();
        assert_eq!(stream.seek(SeekFrom::Current(2)).unwrap(), 3);
        let mut buf = [0u8; 1];
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [4]);
    }

    #[test]
    fn seek_end_is_relative_to_length() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2, 3, 4, 5]));
        assert_eq!(stream.seek(SeekFrom::End(-2)).unwrap(), 3);
        let mut buf = [0u8; 2];
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [4, 5]);
    }

    #[test]
    fn seek_negative_result_errors() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2, 3]));
        assert!(stream.seek(SeekFrom::Current(-5)).is_err());
    }

    #[test]
    fn close_causes_subsequent_reads_to_report_eof() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2, 3]));
        stream.close();
        let mut buf = [0u8; 3];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn close_is_idempotent() {
        let mut stream = SZByteProviderStream::new(VecProvider::new(vec![1, 2, 3]));
        stream.close();
        stream.close();
        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }
}
