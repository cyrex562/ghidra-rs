use std::io::{self, Read};

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// A [`ByteProvider`] that wraps a forward-only [`Read`] stream.
///
/// Reads are permitted only at ever-increasing offsets. Attempting to read from
/// an offset earlier than the current stream position returns an error. Skipping
/// forward is handled by discarding bytes read from the stream.
pub struct InputStreamByteProvider {
    stream: Box<dyn Read>,
    length: u64,
    current_index: u64,
}

impl InputStreamByteProvider {
    /// Creates a new provider wrapping `stream` with the given reported `length`.
    pub fn new(stream: Box<dyn Read>, length: u64) -> Self {
        InputStreamByteProvider { stream, length, current_index: 0 }
    }

    /// Returns a human-readable name that includes the current stream position and total length.
    pub fn name(&self) -> String {
        format!(
            "InputStreamByteProvider Index=0x{:x} Length=0x{:x}",
            self.current_index, self.length
        )
    }

    /// Returns `name()` as the absolute path identifier.
    pub fn absolute_path(&self) -> String {
        self.name()
    }

    fn skip_to(&mut self, target: u64) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        while self.current_index < target {
            let to_read = (target - self.current_index).min(buf.len() as u64) as usize;
            let n = self.stream.read(&mut buf[..to_read])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Not enough bytes were skipped.",
                ));
            }
            self.current_index += n as u64;
        }
        Ok(())
    }
}

impl ByteProvider for InputStreamByteProvider {
    fn length(&mut self) -> io::Result<u64> {
        Ok(self.length)
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        index < self.length
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        if index < self.current_index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Attempted to read byte that was already read.",
            ));
        }
        if index > self.current_index {
            self.skip_to(index)?;
        }
        let mut buf = [0u8; 1];
        match self.stream.read(&mut buf)? {
            0 => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")),
            _ => {
                self.current_index += 1;
                Ok(buf[0])
            }
        }
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        if index < self.current_index {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Attempted to read bytes that were already read.",
            ));
        }
        if index > self.current_index {
            self.skip_to(index)?;
        }
        let mut buf = vec![0u8; length];
        self.stream.read_exact(&mut buf)?;
        self.current_index += length as u64;
        Ok(buf)
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "InputStreamByteProvider does not support writes",
        ))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "InputStreamByteProvider does not support writes",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_provider(data: &[u8]) -> InputStreamByteProvider {
        InputStreamByteProvider::new(Box::new(Cursor::new(data.to_vec())), data.len() as u64)
    }

    #[test]
    fn length_matches_constructor() {
        let mut p = make_provider(&[1, 2, 3]);
        assert_eq!(p.length().unwrap(), 3);
    }

    #[test]
    fn is_valid_index_bounds() {
        let mut p = make_provider(&[1, 2, 3]);
        assert!(p.is_valid_index(0));
        assert!(p.is_valid_index(2));
        assert!(!p.is_valid_index(3));
    }

    #[test]
    fn read_byte_sequential() {
        let mut p = make_provider(&[10, 20, 30]);
        assert_eq!(p.read_byte(0).unwrap(), 10);
        assert_eq!(p.read_byte(1).unwrap(), 20);
        assert_eq!(p.read_byte(2).unwrap(), 30);
    }

    #[test]
    fn read_byte_skip_forward() {
        let mut p = make_provider(&[0, 1, 2, 3, 4]);
        assert_eq!(p.read_byte(3).unwrap(), 3);
    }

    #[test]
    fn read_byte_backward_errors() {
        let mut p = make_provider(&[1, 2, 3]);
        p.read_byte(1).unwrap();
        let err = p.read_byte(0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("already read"));
    }

    #[test]
    fn read_byte_eof_errors() {
        let mut p = make_provider(&[]);
        let err = p.read_byte(0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_bytes_sequential() {
        let mut p = make_provider(&[1, 2, 3, 4, 5]);
        assert_eq!(p.read_bytes(0, 3).unwrap(), vec![1, 2, 3]);
        assert_eq!(p.read_bytes(3, 2).unwrap(), vec![4, 5]);
    }

    #[test]
    fn read_bytes_skip_forward() {
        let mut p = make_provider(&[0, 0, 5, 6, 7]);
        assert_eq!(p.read_bytes(2, 3).unwrap(), vec![5, 6, 7]);
    }

    #[test]
    fn read_bytes_backward_errors() {
        let mut p = make_provider(&[1, 2, 3, 4]);
        p.read_bytes(2, 1).unwrap();
        let err = p.read_bytes(0, 2).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("already read"));
    }

    #[test]
    fn read_bytes_eof_errors() {
        let mut p = make_provider(&[1, 2]);
        let err = p.read_bytes(0, 5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn write_byte_unsupported() {
        let mut p = make_provider(&[1, 2, 3]);
        let err = p.write_byte(0, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn write_bytes_unsupported() {
        let mut p = make_provider(&[1, 2, 3]);
        let err = p.write_bytes(0, &[0]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn name_includes_index_and_length() {
        let p = make_provider(&[0u8; 16]);
        let name = p.name();
        assert!(name.contains("Index=0x0"), "name={}", name);
        assert!(name.contains("Length=0x10"), "name={}", name);
    }

    #[test]
    fn absolute_path_matches_name() {
        let p = make_provider(&[0u8; 4]);
        assert_eq!(p.name(), p.absolute_path());
    }

    #[test]
    fn skip_past_eof_errors() {
        let mut p = make_provider(&[1, 2]);
        let err = p.read_byte(10).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
