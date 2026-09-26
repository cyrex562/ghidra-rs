//! Port of `ghidra.app.util.bin.ByteProvider`.
//!
//! A genuine open extension point (18 in-repo implementers) for generic random-access byte
//! access -- the single most depended-on interface in the `app::util::bin` package. Use
//! `&dyn ByteProvider`/`Box<dyn ByteProvider>` only where the call site is genuinely polymorphic
//! over unknown implementers; prefer a generic `impl ByteProvider` parameter otherwise.
//!
//! PROMOTE: this replaces the minimal placeholder previously at
//! [`crate::app::util::bin::seam_stubs::ByteProvider`] (see `STUBS.tsv`), which existed only so
//! that [`EmptyByteProvider`](super::empty_byte_provider::EmptyByteProvider) -- ported earlier in
//! the same dependency-cycle cut (`ByteProvider.EMPTY_BYTEPROVIDER = new EmptyByteProvider()` is
//! a forward reference from this interface back to that concrete type) -- could compile before
//! this file existed.
//!
//! Not the same type as, and NOT to be confused with, the unrelated
//! `ghidra.formats.gfilesystem`-flavored seekable-storage trait already named `ByteProvider` at
//! [`crate::filesystem::ghidra::g_binary_reader::ByteProvider`]. That trait predates this port,
//! is a purpose-built (and non-conforming -- e.g. it lacks `get_name`/`get_absolute_path`/
//! `close`, and bakes `write_byte`/`write_bytes` into the base rather than
//! `MutableByteProvider`) seam for `GBinaryReader`/`BinaryReader`, and already has ~180
//! call sites depending on its exact (different) shape; reconciling those two is a separate,
//! much larger undertaking outside the scope of this file and was left untouched here.
//!
//! Java's `readByte`/`readBytes`/`close`/`getInputStream` declare `throws IOException`; those
//! become [`io::Result`] here. `length()`/`isValidIndex(long)` do not throw in Java and stay
//! infallible. Java's `File getFile()` becomes [`PathBuf`] (no filesystem access implied, same
//! as Java: just an identity).

use std::io::{self, Read};
use std::path::PathBuf;

use crate::filesystem::gfilesystem::fsrl::Fsrl;

/// An interface for a generic random-access byte provider.
///
/// Mirrors `ghidra.app.util.bin.ByteProvider`.
pub trait ByteProvider {
    /// Returns the underlying file for this provider, or `None` if not associated with a file.
    ///
    /// Mirrors `getFile()`.
    fn get_file(&self) -> Option<PathBuf>;

    /// Returns the name of this provider (e.g. the underlying file name), or `None` if there is
    /// no name.
    ///
    /// Mirrors `getName()`.
    fn get_name(&self) -> Option<String>;

    /// Returns the absolute path (similar to, but not a, URI) to this provider, or `None` if not
    /// associated with a file.
    ///
    /// Mirrors `getAbsolutePath()`.
    fn get_absolute_path(&self) -> Option<String>;

    /// Returns the length of this provider.
    ///
    /// Mirrors `length()`.
    fn length(&self) -> u64;

    /// Returns true if the specified index is valid.
    ///
    /// Mirrors `isValidIndex(long)`.
    fn is_valid_index(&self, index: u64) -> bool;

    /// Releases any resources this provider may have occupied.
    ///
    /// Mirrors `close()`.
    fn close(&mut self) -> io::Result<()>;

    /// Reads a byte at the specified index.
    ///
    /// Mirrors `readByte(long)`.
    fn read_byte(&self, index: u64) -> io::Result<u8>;

    /// Reads `length` bytes starting at the specified index.
    ///
    /// Mirrors `readBytes(long, long)`.
    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>>;

    /// Returns the [`Fsrl`] of the underlying file for this provider, or `None` if this provider
    /// is not associated with a file.
    ///
    /// Java's default derives this from `FileSystemService.getInstance().getLocalFSRL(getFile())`,
    /// which is not ported yet; this default conservatively returns `None` instead. Concrete
    /// implementations that have a real identity (e.g. [`EmptyByteProvider`]'s stored `FSRL`)
    /// override this directly, exactly as `EmptyByteProvider.getFSRL()` does in Java.
    ///
    /// Mirrors the default `getFSRL()`.
    fn get_fsrl(&self) -> Option<&Fsrl> {
        None
    }

    /// Returns true if this provider does not contain any bytes.
    ///
    /// Mirrors the default `isEmpty()`.
    fn is_empty(&self) -> bool {
        self.length() == 0
    }

    /// Returns a stream over this provider's bytes, starting at `index`.
    ///
    /// Java's default returns a lazy `ByteProviderInputStream` wrapping `this`; that type
    /// ([`crate::app::util::bin::byte_provider_input_stream::ByteProviderInputStream`]) is
    /// generic over the unrelated, pre-existing `ByteProvider` trait (see the module docs) and
    /// so cannot be reused here without entangling the two. This default instead reads the
    /// remaining bytes eagerly and wraps them in a [`std::io::Cursor`], which is
    /// observationally equivalent for callers that only read forward from `index` to EOF (the
    /// documented contract).
    ///
    /// Mirrors the default `getInputStream(long)`.
    fn get_input_stream(&self, index: u64) -> io::Result<Box<dyn Read>> {
        if index > self.length() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid start position: {index}"),
            ));
        }
        let remaining = self.length() - index;
        let bytes = self.read_bytes(index, remaining)?;
        Ok(Box::new(io::Cursor::new(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecProvider {
        data: Vec<u8>,
    }

    impl ByteProvider for VecProvider {
        fn get_file(&self) -> Option<PathBuf> {
            None
        }
        fn get_name(&self) -> Option<String> {
            None
        }
        fn get_absolute_path(&self) -> Option<String> {
            None
        }
        fn length(&self) -> u64 {
            self.data.len() as u64
        }
        fn is_valid_index(&self, index: u64) -> bool {
            (index as usize) < self.data.len()
        }
        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.data
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of range"))
        }
        fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length as usize;
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "out of range"));
            }
            Ok(self.data[start..end].to_vec())
        }
    }

    #[test]
    fn is_empty_default_derives_from_length() {
        let empty = VecProvider { data: vec![] };
        let nonempty = VecProvider { data: vec![1, 2, 3] };
        assert!(empty.is_empty());
        assert!(!nonempty.is_empty());
    }

    #[test]
    fn get_input_stream_reads_from_index_to_eof() {
        let p = VecProvider { data: vec![10, 20, 30, 40] };
        let mut stream = p.get_input_stream(1).unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, vec![20, 30, 40]);
    }

    #[test]
    fn get_input_stream_past_length_errors() {
        let p = VecProvider { data: vec![1, 2] };
        assert!(p.get_input_stream(3).is_err());
    }

    #[test]
    fn get_fsrl_default_is_none() {
        let p = VecProvider { data: vec![] };
        assert!(p.get_fsrl().is_none());
    }

    #[test]
    fn trait_is_object_safe() {
        let p: Box<dyn ByteProvider> = Box::new(VecProvider { data: vec![7] });
        assert_eq!(p.length(), 1);
        assert_eq!(p.read_byte(0).unwrap(), 7);
    }
}
