/// ART image root indices for Oreo.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/image.h#189>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRootOreo {
    DexCaches,
    ClassRoots,
    /// App image only.
    ClassLoader,
    /// Sentinel: number of elements in this enum.
    ImageRootsMax,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_constructible() {
        let _ = ImageRootOreo::DexCaches;
        let _ = ImageRootOreo::ClassRoots;
        let _ = ImageRootOreo::ClassLoader;
        let _ = ImageRootOreo::ImageRootsMax;
    }

    #[test]
    fn equality() {
        assert_eq!(ImageRootOreo::DexCaches, ImageRootOreo::DexCaches);
        assert_ne!(ImageRootOreo::DexCaches, ImageRootOreo::ClassRoots);
    }

    #[test]
    fn copy_semantics() {
        let a = ImageRootOreo::ClassLoader;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", ImageRootOreo::DexCaches), "DexCaches");
        assert_eq!(format!("{:?}", ImageRootOreo::ClassRoots), "ClassRoots");
        assert_eq!(format!("{:?}", ImageRootOreo::ClassLoader), "ClassLoader");
        assert_eq!(
            format!("{:?}", ImageRootOreo::ImageRootsMax),
            "ImageRootsMax"
        );
    }
}
