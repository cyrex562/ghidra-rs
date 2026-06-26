use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// A [`ByteProvider`] that guarantees `write_byte` and `write_bytes` are
/// fully supported (i.e. will not return `ErrorKind::Unsupported`).
///
/// Mirrors `ghidra.app.util.bin.MutableByteProvider` from the original Ghidra
/// source. In Java the interface redeclared the write methods; in Rust they
/// already live on [`ByteProvider`], so this trait is a pure marker that
/// distinguishes writable providers from read-only ones.
pub trait MutableByteProvider: ByteProvider {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

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
            let end = start.checked_add(length).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "overflow")
            })?;
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

    impl MutableByteProvider for VecProvider {}

    fn make_mutable(data: &[u8]) -> impl MutableByteProvider {
        VecProvider::new(data.to_vec())
    }

    #[test]
    fn mutable_provider_is_byte_provider() {
        let mut p = make_mutable(&[1, 2, 3]);
        assert_eq!(p.length().unwrap(), 3);
        assert_eq!(p.read_byte(0).unwrap(), 1);
    }

    #[test]
    fn write_byte_mutates_single_byte() {
        let mut p = make_mutable(&[0, 0, 0]);
        p.write_byte(1, 42).unwrap();
        assert_eq!(p.read_byte(1).unwrap(), 42);
        assert_eq!(p.read_byte(0).unwrap(), 0);
        assert_eq!(p.read_byte(2).unwrap(), 0);
    }

    #[test]
    fn write_bytes_mutates_range() {
        let mut p = make_mutable(&[0u8; 5]);
        p.write_bytes(1, &[10, 20, 30]).unwrap();
        assert_eq!(p.read_bytes(0, 5).unwrap(), vec![0, 10, 20, 30, 0]);
    }

    #[test]
    fn write_byte_out_of_bounds_errors() {
        let mut p = make_mutable(&[1, 2, 3]);
        let err = p.write_byte(5, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn write_bytes_out_of_bounds_errors() {
        let mut p = make_mutable(&[1, 2, 3]);
        let err = p.write_bytes(2, &[10, 20]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn is_valid_index_at_bounds() {
        let mut p = make_mutable(&[1, 2, 3]);
        assert!(p.is_valid_index(0));
        assert!(p.is_valid_index(2));
        assert!(!p.is_valid_index(3));
    }
}
