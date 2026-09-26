//! Port of `ghidra.formats.gfilesystem.factory.GFileSystemFactory`.

use super::g_file_system_factory_byte_provider::GFileSystemFactoryByteProvider;
use super::g_file_system_probe_byte_provider::GFileSystemProbeByteProvider;
use super::g_file_system_probe_bytes_only::GFileSystemProbeBytesOnly;

/// An empty interface that is a common type for the real factory interfaces to derive from.
///
/// Mirrors `ghidra.formats.gfilesystem.factory.GFileSystemFactory<FSTYPE>`. Java's
/// `FileSystemFactoryMgr` discovers what a factory can do with `instanceof` checks against the
/// sub-interfaces; here a factory exposes those capabilities through the `as_*` accessors,
/// each defaulting to "not supported". The Java `FSTYPE` parameter is not carried: factories
/// hand back type-erased [`FsHandle`](crate::filesystem::gfilesystem::g_file_system::FsHandle)s,
/// and the registry records the concrete filesystem type in its
/// [`FileSystemInfoRec`](super::file_system_info_rec::FileSystemInfoRec) instead.
pub trait GFileSystemFactory {
    /// This factory as a [`GFileSystemFactoryByteProvider`], if it is one.
    fn as_byte_provider_factory(&self) -> Option<&dyn GFileSystemFactoryByteProvider> {
        None
    }

    /// This factory as a [`GFileSystemProbeBytesOnly`], if it is one.
    fn as_probe_bytes_only(&self) -> Option<&dyn GFileSystemProbeBytesOnly> {
        None
    }

    /// This factory as a [`GFileSystemProbeByteProvider`], if it is one.
    fn as_probe_byte_provider(&self) -> Option<&dyn GFileSystemProbeByteProvider> {
        None
    }

    /// `true` for [`GFileSystemFactoryIgnore`](super::g_file_system_factory_ignore::GFileSystemFactoryIgnore),
    /// whose filesystems are never registered.
    fn is_ignore(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyFactory;
    impl GFileSystemFactory for DummyFactory {}

    #[test]
    fn capabilities_default_to_none() {
        let f: Box<dyn GFileSystemFactory> = Box::new(DummyFactory);
        assert!(f.as_byte_provider_factory().is_none());
        assert!(f.as_probe_bytes_only().is_none());
        assert!(f.as_probe_byte_provider().is_none());
        assert!(!f.is_ignore());
    }
}
