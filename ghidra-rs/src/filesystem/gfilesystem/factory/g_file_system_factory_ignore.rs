use crate::filesystem::seam_stubs::GFileSystemLike;

use super::g_file_system_factory::GFileSystemFactory;

/// Marker trait that tells the file system factory manager to not register this
/// filesystem instance.
///
/// This is the Rust equivalent of
/// `ghidra.formats.gfilesystem.factory.GFileSystemFactoryIgnore`.
pub trait GFileSystemFactoryIgnore<FSTYPE: GFileSystemLike>: GFileSystemFactory<FSTYPE> {
    // nada
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyFileSystem;
    impl GFileSystemLike for DummyFileSystem {}

    struct IgnoredFactory;
    impl GFileSystemFactory<DummyFileSystem> for IgnoredFactory {}
    impl GFileSystemFactoryIgnore<DummyFileSystem> for IgnoredFactory {}

    #[test]
    fn marker_trait_is_implementable() {
        let _factory = IgnoredFactory;
    }

    #[test]
    fn boxed_dyn_factory_ignore_is_accepted() {
        let factory: Box<dyn GFileSystemFactoryIgnore<DummyFileSystem>> = Box::new(IgnoredFactory);
        // Confirms the object-safe trait can also be used through its supertrait bound.
        let _: &dyn GFileSystemFactory<DummyFileSystem> = &*factory;
    }
}
