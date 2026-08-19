//! Trait ported from the class `ghidra.program.database.mem.FileBytes`.
//!
//! In Java, `FileBytes` provides access to all the byte values (both original and modified) from
//! an imported file: it wraps a pair of `DBBuffer` arrays (the immutable original bytes and a
//! layered view that records any subsequent edits) plus a `final FileBytesAdapter adapter` field
//! used only to refresh those buffers when the backing record changes. That `adapter` coupling
//! (`FileBytes` -> `FileBytesAdapter` -> `FileBytes` via `createFileBytes`/`getAllFileBytes`) is
//! exactly the cycle this port needs to cut, so the adapter/`DBRecord` plumbing (the constructor,
//! `refresh(DBRecord)`, and the package-private `getId`) is left to whatever concrete,
//! DB-backed implementor is written later; this trait models the byte-access contract that every
//! other ported type actually depends on. `equals`/`hashCode` are Java's stand-in for reference
//! identity on a shared, mutable record and are likewise omitted -- callers needing identity
//! should compare `Arc::ptr_eq` on the trait object, matching the idiom already used for
//! `Arc<dyn FileBytes>` elsewhere in this crate (e.g.
//! [`FileBytesAdapter`](crate::program::database::mem::file_bytes_adapter::FileBytesAdapter)).
//!
//! Java's `getModifiedByte`/`getOriginalByte`/`putByte`/`putBytes` are all declared `synchronized`
//! because many holders can share one `FileBytes` instance (it is handed out as a shared object via
//! `getAllFileBytes`/`createFileBytes`); the mutating methods here take `&self` rather than
//! `&mut self` for the same reason -- a real implementor is expected to guard its buffers with its
//! own interior mutability (e.g. a `Mutex`), not rely on unique borrowing.

use std::error::Error;
use std::fmt;
use std::io;

/// Error type aggregating the exceptions thrown by Java's `FileBytes` byte-access and mutation
/// methods (`IOException`, `IndexOutOfBoundsException`, and `ConcurrentModificationException`
/// from the private `checkValid` guard used once a `FileBytes` has been invalidated).
#[derive(Debug)]
pub enum FileBytesError {
    /// Mirrors `IOException`: a database or stream I/O error occurred.
    Io(io::Error),
    /// Mirrors `IndexOutOfBoundsException`: the requested offset (or array range) is invalid.
    IndexOutOfBounds(String),
    /// Mirrors `ConcurrentModificationException`: this `FileBytes` has been invalidated (its
    /// backing memory block was removed) and can no longer be read or written.
    Invalidated,
}

impl fmt::Display for FileBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::IndexOutOfBounds(msg) => write!(f, "index out of bounds: {msg}"),
            Self::Invalidated => write!(f, "FileBytes has been invalidated"),
        }
    }
}

impl Error for FileBytesError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for FileBytesError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Provides access to all the byte values (both original and modified) from an imported file.
pub trait FileBytes: Send + Sync {
    /// Returns the name of the file that supplied the bytes. Mirrors `FileBytes.getFilename()`.
    fn get_filename(&self) -> &str;

    /// Returns the offset in the original file from where these bytes originated. Normally this
    /// will be 0, but in the case where the program is actually a piece in some other file (e.g.
    /// tar, zip), this will be the offset into the file corresponding to the first byte in this
    /// `FileBytes` object. Mirrors `FileBytes.getFileOffset()`.
    fn get_file_offset(&self) -> i64;

    /// Returns the number of bytes from the original source file that are stored in the
    /// database. Mirrors `FileBytes.getSize()`.
    fn get_size(&self) -> i64;

    /// Returns the (possibly modified) byte at the given offset for this file bytes object.
    /// Mirrors `FileBytes.getModifiedByte(long)`.
    fn get_modified_byte(&self, offset: i64) -> Result<u8, FileBytesError>;

    /// Returns the original byte value at the given offset for this file bytes object. Mirrors
    /// `FileBytes.getOriginalByte(long)`.
    fn get_original_byte(&self, offset: i64) -> Result<u8, FileBytesError>;

    /// Tries to get `length` (possibly modified) bytes from this `FileBytes` entry at the given
    /// offset into the file bytes, placing them into `b` starting at `off`. May return fewer
    /// bytes if the requested length is beyond the end of the file bytes. Returns the number of
    /// bytes actually populated. Mirrors `FileBytes.getModifiedBytes(long, byte[], int, int)`.
    fn get_modified_bytes_range(
        &self,
        offset: i64,
        b: &mut [u8],
        off: usize,
        length: usize,
    ) -> Result<usize, FileBytesError>;

    /// Tries to get `length` original bytes from this `FileBytes` entry at the given offset into
    /// the file bytes, placing them into `b` starting at `off`. May return fewer bytes if the
    /// requested length is beyond the end of the file bytes. Returns the number of bytes
    /// actually populated. Mirrors `FileBytes.getOriginalBytes(long, byte[], int, int)`.
    fn get_original_bytes_range(
        &self,
        offset: i64,
        b: &mut [u8],
        off: usize,
        length: usize,
    ) -> Result<usize, FileBytesError>;

    /// Tries to fill all of `b` with (possibly modified) bytes from this `FileBytes` entry
    /// starting at `offset`. May populate fewer bytes if the requested length is beyond the end
    /// of the file bytes. Mirrors `FileBytes.getModifiedBytes(long, byte[])`.
    fn get_modified_bytes(&self, offset: i64, b: &mut [u8]) -> Result<usize, FileBytesError> {
        let length = b.len();
        self.get_modified_bytes_range(offset, b, 0, length)
    }

    /// Tries to fill all of `b` with original bytes from this `FileBytes` entry starting at
    /// `offset`. May populate fewer bytes if the requested length is beyond the end of the file
    /// bytes. Mirrors `FileBytes.getOriginalBytes(long, byte[])`.
    fn get_original_bytes(&self, offset: i64, b: &mut [u8]) -> Result<usize, FileBytesError> {
        let length = b.len();
        self.get_original_bytes_range(offset, b, 0, length)
    }

    /// Changes the byte at the given offset to the given value. Note, the original byte can
    /// still be accessed via [`get_original_byte`](FileBytes::get_original_byte). If the byte is
    /// changed more than once, only the original value is preserved. Mirrors
    /// `FileBytes.putByte(long, byte)`.
    fn put_byte(&self, offset: i64, b: u8) -> Result<(), FileBytesError>;

    /// Changes `length` bytes at the given offset to the values in `b` starting at `off`. Note,
    /// the original bytes can still be accessed via
    /// [`get_original_bytes_range`](FileBytes::get_original_bytes_range). If the bytes are
    /// changed more than once, only the original values are preserved. Returns the number of
    /// bytes written. Mirrors `FileBytes.putBytes(long, byte[], int, int)`.
    fn put_bytes_range(
        &self,
        offset: i64,
        b: &[u8],
        off: usize,
        length: usize,
    ) -> Result<usize, FileBytesError>;

    /// Changes all of `b`'s bytes starting at the given offset. Note, the original bytes can
    /// still be accessed via [`get_original_bytes`](FileBytes::get_original_bytes). If the bytes
    /// are changed more than once, only the original values are preserved. Returns the number of
    /// bytes written. Mirrors `FileBytes.putBytes(long, byte[])`.
    fn put_bytes(&self, offset: i64, b: &[u8]) -> Result<usize, FileBytesError> {
        let length = b.len();
        self.put_bytes_range(offset, b, 0, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A minimal in-memory `FileBytes` used to prove the trait is object-safe and that its
    /// default methods behave correctly against real (non-trivial) layered original/modified
    /// state, standing in for the real DB-backed implementation.
    struct MockFileBytes {
        filename: String,
        file_offset: i64,
        original: Vec<u8>,
        modified: Mutex<Vec<u8>>,
        invalid: Mutex<bool>,
    }

    impl MockFileBytes {
        fn new(filename: &str, file_offset: i64, original: Vec<u8>) -> Self {
            let modified = original.clone();
            Self {
                filename: filename.to_string(),
                file_offset,
                original,
                modified: Mutex::new(modified),
                invalid: Mutex::new(false),
            }
        }

        fn check_valid(&self) -> Result<(), FileBytesError> {
            if *self.invalid.lock().unwrap() {
                Err(FileBytesError::Invalidated)
            } else {
                Ok(())
            }
        }
    }

    impl FileBytes for MockFileBytes {
        fn get_filename(&self) -> &str {
            &self.filename
        }

        fn get_file_offset(&self) -> i64 {
            self.file_offset
        }

        fn get_size(&self) -> i64 {
            self.original.len() as i64
        }

        fn get_modified_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
            self.check_valid()?;
            let modified = self.modified.lock().unwrap();
            modified
                .get(offset as usize)
                .copied()
                .ok_or_else(|| FileBytesError::IndexOutOfBounds(offset.to_string()))
        }

        fn get_original_byte(&self, offset: i64) -> Result<u8, FileBytesError> {
            self.check_valid()?;
            self.original
                .get(offset as usize)
                .copied()
                .ok_or_else(|| FileBytesError::IndexOutOfBounds(offset.to_string()))
        }

        fn get_modified_bytes_range(
            &self,
            offset: i64,
            b: &mut [u8],
            off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            self.check_valid()?;
            let modified = self.modified.lock().unwrap();
            let start = offset as usize;
            let available = modified.len().saturating_sub(start);
            let n = length.min(available);
            b[off..off + n].copy_from_slice(&modified[start..start + n]);
            Ok(n)
        }

        fn get_original_bytes_range(
            &self,
            offset: i64,
            b: &mut [u8],
            off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            self.check_valid()?;
            let start = offset as usize;
            let available = self.original.len().saturating_sub(start);
            let n = length.min(available);
            b[off..off + n].copy_from_slice(&self.original[start..start + n]);
            Ok(n)
        }

        fn put_byte(&self, offset: i64, b: u8) -> Result<(), FileBytesError> {
            self.check_valid()?;
            if offset < 0 || offset as usize >= self.original.len() {
                return Err(FileBytesError::IndexOutOfBounds(offset.to_string()));
            }
            self.modified.lock().unwrap()[offset as usize] = b;
            Ok(())
        }

        fn put_bytes_range(
            &self,
            offset: i64,
            b: &[u8],
            off: usize,
            length: usize,
        ) -> Result<usize, FileBytesError> {
            self.check_valid()?;
            let mut modified = self.modified.lock().unwrap();
            let start = offset as usize;
            let available = modified.len().saturating_sub(start);
            let n = length.min(available);
            modified[start..start + n].copy_from_slice(&b[off..off + n]);
            Ok(n)
        }
    }

    #[test]
    fn original_bytes_are_unaffected_by_writes() {
        let fb = MockFileBytes::new("orig.bin", 0, vec![1, 2, 3, 4]);
        fb.put_byte(1, 0xFF).unwrap();
        assert_eq!(fb.get_modified_byte(1).unwrap(), 0xFF);
        assert_eq!(fb.get_original_byte(1).unwrap(), 2);
    }

    #[test]
    fn get_bytes_clamps_to_available_length() {
        let fb = MockFileBytes::new("a.bin", 0, vec![10, 20, 30, 40]);
        let mut dest = [0u8; 10];
        let n = fb.get_original_bytes(2, &mut dest).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&dest[..2], &[30, 40]);
    }

    #[test]
    fn put_bytes_round_trips_through_range_variant() {
        let fb = MockFileBytes::new("a.bin", 0, vec![0; 4]);
        let written = fb.put_bytes(0, &[9, 8, 7, 6]).unwrap();
        assert_eq!(written, 4);
        let mut out = [0u8; 4];
        fb.get_modified_bytes(0, &mut out).unwrap();
        assert_eq!(out, [9, 8, 7, 6]);
    }

    #[test]
    fn invalidated_file_bytes_reject_all_access() {
        let fb = MockFileBytes::new("a.bin", 0, vec![1, 2, 3]);
        *fb.invalid.lock().unwrap() = true;
        assert!(matches!(
            fb.get_original_byte(0),
            Err(FileBytesError::Invalidated)
        ));
        assert!(matches!(
            fb.put_byte(0, 5),
            Err(FileBytesError::Invalidated)
        ));
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let boxed: Box<dyn FileBytes> = Box::new(MockFileBytes::new("a.bin", 0x10, vec![1, 2]));
        assert_eq!(boxed.get_filename(), "a.bin");
        assert_eq!(boxed.get_file_offset(), 0x10);
        assert_eq!(boxed.get_size(), 2);
    }
}
