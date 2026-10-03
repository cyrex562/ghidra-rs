//! Port of `ghidra.formats.gfilesystem.RefdByteProvider`.

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::app::util::bin::byte_provider::ByteProvider;

use super::file_system_ref::FileSystemRef;
use super::fsrl::Fsrl;

/// A [`ByteProvider`] along with a [`FileSystemRef`] that keeps the filesystem it came from
/// pinned while the provider is in use.
///
/// Mirrors `ghidra.formats.gfilesystem.RefdByteProvider`. Closing it closes both the wrapped
/// provider and the ref; if it is dropped unclosed, the ref releases itself.
pub struct RefdByteProvider {
    fs_ref: FileSystemRef,
    provider: Box<dyn ByteProvider>,
    fsrl: Option<Fsrl>,
}

impl RefdByteProvider {
    /// Wraps `provider`, which came from the filesystem `fs_ref` pins, identified by `fsrl`.
    /// Mirrors `RefdByteProvider(FileSystemRef, ByteProvider, FSRL)`.
    pub fn new(fs_ref: FileSystemRef, provider: Box<dyn ByteProvider>, fsrl: Option<Fsrl>) -> Self {
        RefdByteProvider { fs_ref, provider, fsrl }
    }

    /// The wrapped provider. Mirrors the package-private `getWrappedByteProvider()`.
    pub fn get_wrapped_byte_provider(&self) -> &dyn ByteProvider {
        &*self.provider
    }
}

impl ByteProvider for RefdByteProvider {
    fn get_file(&self) -> Option<PathBuf> {
        self.provider.get_file()
    }

    fn get_name(&self) -> Option<String> {
        match &self.fsrl {
            Some(f) => f.name(),
            None => self.provider.get_name(),
        }
    }

    fn get_absolute_path(&self) -> Option<String> {
        match &self.fsrl {
            Some(f) => f.path().map(str::to_string),
            None => self.provider.get_absolute_path(),
        }
    }

    fn get_fsrl(&self) -> Option<&Fsrl> {
        self.fsrl.as_ref()
    }

    fn length(&self) -> u64 {
        self.provider.length()
    }

    fn is_valid_index(&self, index: u64) -> bool {
        self.provider.is_valid_index(index)
    }

    fn close(&mut self) -> io::Result<()> {
        self.provider.close()?;
        if !self.fs_ref.is_closed() {
            self.fs_ref.close().map_err(io::Error::other)?;
        }
        Ok(())
    }

    fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.provider.read_byte(index)
    }

    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        self.provider.read_bytes(index, length)
    }

    fn get_input_stream(&self, index: u64) -> io::Result<Box<dyn io::Read>> {
        self.provider.get_input_stream(index)
    }
}

/// Mirrors `toString()`.
impl fmt::Display for RefdByteProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.provider.get_fsrl().map_or("null".to_string(), ToString::to_string);
        write!(f, "ByteProvider {inner} in file system {}", self.fs_ref.get_filesystem().get_fsrl())
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
    use crate::filesystem::gfilesystem::file_system_ref_manager::test_support::EmptyFs;
    use crate::filesystem::gfilesystem::g_file_system::FsHandle;

    #[test]
    fn delegates_reads_and_prefers_its_own_fsrl() {
        let fs: FsHandle = Rc::new(EmptyFs::new("empty"));
        let r = fs.get_ref_manager().create(&fs).unwrap();
        let inner = ByteArrayProvider::with_name("inner", vec![1u8, 2, 3]);
        let fsrl = Fsrl::from_string("empty:///dir/outer.bin").unwrap();
        let mut p = RefdByteProvider::new(r, Box::new(inner), Some(fsrl.clone()));
        assert_eq!(p.read_bytes(1, 2).unwrap(), vec![2, 3]);
        assert_eq!(p.get_name().as_deref(), Some("outer.bin"));
        assert_eq!(p.get_absolute_path().as_deref(), Some("/dir/outer.bin"));
        assert_eq!(p.get_fsrl(), Some(&fsrl));
        assert_eq!(fs.get_ref_manager().ref_count(), 1);
        p.close().unwrap();
        assert_eq!(fs.get_ref_manager().ref_count(), 0);
    }

    #[test]
    fn without_fsrl_falls_back_to_wrapped_name() {
        let fs: FsHandle = Rc::new(EmptyFs::new("empty"));
        let r = fs.get_ref_manager().create(&fs).unwrap();
        let p = RefdByteProvider::new(r, Box::new(ByteArrayProvider::with_name("inner", vec![0u8])), None);
        assert_eq!(p.get_name().as_deref(), Some("inner"));
        assert_eq!(p.to_string(), "ByteProvider null in file system empty://");
        drop(p);
        assert_eq!(fs.get_ref_manager().ref_count(), 0);
    }
}
