/// ART image root indices for Pie.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/image.h#207>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRootPie {
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
        let _ = ImageRootPie::DexCaches;
        let _ = ImageRootPie::ClassRoots;
        let _ = ImageRootPie::ClassLoader;
        let _ = ImageRootPie::ImageRootsMax;
    }

    #[test]
    fn equality() {
        assert_eq!(ImageRootPie::DexCaches, ImageRootPie::DexCaches);
        assert_ne!(ImageRootPie::DexCaches, ImageRootPie::ClassRoots);
    }

    #[test]
    fn copy_semantics() {
        let a = ImageRootPie::ClassLoader;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", ImageRootPie::DexCaches), "DexCaches");
        assert_eq!(format!("{:?}", ImageRootPie::ClassRoots), "ClassRoots");
        assert_eq!(format!("{:?}", ImageRootPie::ClassLoader), "ClassLoader");
        assert_eq!(
            format!("{:?}", ImageRootPie::ImageRootsMax),
            "ImageRootsMax"
        );
    }
}
