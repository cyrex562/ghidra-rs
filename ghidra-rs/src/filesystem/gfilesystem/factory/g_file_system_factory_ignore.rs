//! Port of `ghidra.formats.gfilesystem.factory.GFileSystemFactoryIgnore`.

use super::g_file_system_factory::GFileSystemFactory;

/// A factory that marks its filesystem as one the
/// [`FileSystemFactoryMgr`](super::file_system_factory_mgr::FileSystemFactoryMgr) must not
/// register (e.g. the local filesystem, which is created directly).
///
/// Mirrors `ghidra.formats.gfilesystem.factory.GFileSystemFactoryIgnore`, a concrete class.
#[derive(Debug, Default, Clone, Copy)]
pub struct GFileSystemFactoryIgnore;

impl GFileSystemFactory for GFileSystemFactoryIgnore {
    fn is_ignore(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ignore() {
        let f: &dyn GFileSystemFactory = &GFileSystemFactoryIgnore;
        assert!(f.is_ignore());
        assert!(f.as_byte_provider_factory().is_none());
    }
}
