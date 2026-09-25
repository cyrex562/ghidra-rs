//! Port of `ghidra.app.util.bin.ByteProviderWrapper`.
//!
//! A [`ByteProvider`] constrained to a sub-section of an existing provider, optionally tagged
//! with a different [`Fsrl`]. Closing the wrapper does not close the wrapped provider.
//!
//! Java holds the wrapped provider by (garbage-collected) reference. Here the wrapper is
//! generic over how it holds it: any `P` that dereferences to a [`ByteProvider`] -- a borrow
//! (`&dyn ByteProvider`) for a short-lived view, or a shared handle (`Rc<dyn ByteProvider>`)
//! when the wrapper must outlive the caller's borrow, as a filesystem's `getByteProvider`
//! result does.

use std::io;
use std::ops::Deref;
use std::path::PathBuf;

use crate::filesystem::gfilesystem::fsrl::Fsrl;

use super::byte_provider::ByteProvider;

/// A [`ByteProvider`] view of `sub_length` bytes of another provider starting at
/// `sub_offset`.
///
/// Mirrors `ghidra.app.util.bin.ByteProviderWrapper`.
pub struct ByteProviderWrapper<P> {
    provider: P,
    sub_offset: u64,
    sub_length: u64,
    fsrl: Option<Fsrl>,
}

impl<P> ByteProviderWrapper<P>
where
    P: Deref,
    P::Target: ByteProvider,
{
    /// Wraps the whole of `provider`, tagged with `fsrl`.
    ///
    /// Mirrors `ByteProviderWrapper(ByteProvider, FSRL)`.
    pub fn new(provider: P, fsrl: Option<Fsrl>) -> Self {
        let len = provider.length();
        Self::with_range_and_fsrl(provider, 0, len, fsrl)
    }

    /// Wraps a sub-range of `provider`, with no FSRL of its own.
    ///
    /// Mirrors `ByteProviderWrapper(ByteProvider, long, long)`.
    pub fn with_range(provider: P, sub_offset: u64, sub_length: u64) -> Self {
        Self::with_range_and_fsrl(provider, sub_offset, sub_length, None)
    }

    /// Wraps a sub-range of `provider`, tagged with `fsrl`.
    ///
    /// Mirrors `ByteProviderWrapper(ByteProvider, long, long, FSRL)`.
    pub fn with_range_and_fsrl(
        provider: P,
        sub_offset: u64,
        sub_length: u64,
        fsrl: Option<Fsrl>,
    ) -> Self {
        ByteProviderWrapper { provider, sub_offset, sub_length, fsrl }
    }

    fn check_index(&self, index: u64) -> io::Result<()> {
        if index >= self.sub_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid index: {index}"),
            ));
        }
        Ok(())
    }
}

impl<P> ByteProvider for ByteProviderWrapper<P>
where
    P: Deref,
    P::Target: ByteProvider,
{
    /// There is no file that represents the actual contents of the subrange.
    fn get_file(&self) -> Option<PathBuf> {
        None
    }

    fn get_name(&self) -> Option<String> {
        match &self.fsrl {
            Some(fsrl) => fsrl.name(),
            None => Some(format!(
                "{}[0x{:x},0x{:x}]",
                self.provider.get_name().as_deref().unwrap_or("null"),
                self.sub_offset,
                self.sub_length
            )),
        }
    }

    fn get_absolute_path(&self) -> Option<String> {
        match &self.fsrl {
            Some(fsrl) => fsrl.path().map(str::to_owned),
            None => Some(format!(
                "{}[0x{:x},0x{:x}]",
                self.provider.get_absolute_path().as_deref().unwrap_or("null"),
                self.sub_offset,
                self.sub_length
            )),
        }
    }

    fn length(&self) -> u64 {
        self.sub_length
    }

    fn is_valid_index(&self, index: u64) -> bool {
        index < self.sub_length && self.provider.is_valid_index(self.sub_offset + index)
    }

    /// Does not close the wrapped provider.
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.check_index(index)?;
        self.provider.read_byte(self.sub_offset + index)
    }

    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        self.check_index(index)?;
        if index.checked_add(length).is_none_or(|end| end > self.sub_length) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Unable to read past EOF: {index}, {length}"),
            ));
        }
        self.provider.read_bytes(self.sub_offset + index, length)
    }

    fn get_fsrl(&self) -> Option<&Fsrl> {
        self.fsrl.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    struct VecProvider {
        bytes: Vec<u8>,
        closed: Cell<bool>,
    }

    impl VecProvider {
        fn new(bytes: &[u8]) -> Self {
            VecProvider { bytes: bytes.to_vec(), closed: Cell::new(false) }
        }
    }

    impl ByteProvider for VecProvider {
        fn get_file(&self) -> Option<PathBuf> {
            Some(PathBuf::from("/tmp/base.bin"))
        }
        fn get_name(&self) -> Option<String> {
            Some("base.bin".into())
        }
        fn get_absolute_path(&self) -> Option<String> {
            Some("/tmp/base.bin".into())
        }
        fn length(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn is_valid_index(&self, index: u64) -> bool {
            index < self.bytes.len() as u64
        }
        fn close(&mut self) -> io::Result<()> {
            self.closed.set(true);
            Ok(())
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
            let (s, e) = (index as usize, (index + length) as usize);
            self.bytes
                .get(s..e)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
    }

    #[test]
    fn sub_range_reads_are_offset() {
        let base = VecProvider::new(b"0123456789");
        let w = ByteProviderWrapper::with_range(&base as &dyn ByteProvider, 2, 5);
        assert_eq!(w.length(), 5);
        assert_eq!(w.read_byte(0).unwrap(), b'2');
        assert_eq!(w.read_bytes(1, 4).unwrap(), b"3456");
        assert!(w.is_valid_index(4));
        assert!(!w.is_valid_index(5));
        assert!(w.get_file().is_none());
    }

    #[test]
    fn out_of_range_reads_error() {
        let base = VecProvider::new(b"0123456789");
        let w = ByteProviderWrapper::with_range(&base as &dyn ByteProvider, 2, 5);
        assert!(w.read_byte(5).is_err());
        assert!(w.read_bytes(5, 0).is_err());
        let err = w.read_bytes(3, 3).unwrap_err();
        assert_eq!(err.to_string(), "Unable to read past EOF: 3, 3");
    }

    #[test]
    fn name_and_path_without_fsrl_describe_range() {
        let base = VecProvider::new(b"0123456789");
        let w = ByteProviderWrapper::with_range(&base as &dyn ByteProvider, 0x10, 0x20);
        assert_eq!(w.get_name().unwrap(), "base.bin[0x10,0x20]");
        assert_eq!(w.get_absolute_path().unwrap(), "/tmp/base.bin[0x10,0x20]");
        assert!(w.get_fsrl().is_none());
    }

    #[test]
    fn fsrl_supplies_name_and_path() {
        let base = VecProvider::new(b"abc");
        let fsrl = Fsrl::from_string("file:///a/b/payload.txt").unwrap();
        let w = ByteProviderWrapper::new(&base as &dyn ByteProvider, Some(fsrl.clone()));
        assert_eq!(w.length(), 3);
        assert_eq!(w.get_name().unwrap(), "payload.txt");
        assert_eq!(w.get_absolute_path().unwrap(), "/a/b/payload.txt");
        assert_eq!(w.get_fsrl(), Some(&fsrl));
    }

    #[test]
    fn close_does_not_close_wrapped_provider() {
        let base: Rc<VecProvider> = Rc::new(VecProvider::new(b"abc"));
        let mut w = ByteProviderWrapper::new(base.clone(), None);
        w.close().unwrap();
        assert!(!base.closed.get());
        assert_eq!(w.read_bytes(0, 3).unwrap(), b"abc");
    }
}
