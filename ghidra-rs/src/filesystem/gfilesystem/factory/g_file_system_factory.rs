use crate::filesystem::seam_stubs::GFileSystemLike;

/// An empty trait that is a common bound for the real factory traits to derive from.
///
/// This is the Rust equivalent of
/// `ghidra.formats.gfilesystem.factory.GFileSystemFactory`.
pub trait GFileSystemFactory<FSTYPE: GFileSystemLike> {
    // empty trait
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyFileSystem;
    impl GFileSystemLike for DummyFileSystem {}

    struct DummyFactory;
    impl GFileSystemFactory<DummyFileSystem> for DummyFactory {}

    #[test]
    fn marker_trait_is_implementable() {
        let _factory = DummyFactory;
    }

    #[test]
    fn boxed_dyn_factory_is_accepted() {
        let _factory: Box<dyn GFileSystemFactory<DummyFileSystem>> = Box::new(DummyFactory);
    }
}
