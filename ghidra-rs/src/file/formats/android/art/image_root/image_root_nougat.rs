/// ART image root indices for Nougat.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/nougat-release/runtime/image.h#187>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRootNougat {
    DexCaches,
    ClassRoots,
    /// Sentinel: number of elements in this enum.
    ImageRootsMax,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_constructible() {
        let _ = ImageRootNougat::DexCaches;
        let _ = ImageRootNougat::ClassRoots;
        let _ = ImageRootNougat::ImageRootsMax;
    }

    #[test]
    fn equality() {
        assert_eq!(ImageRootNougat::DexCaches, ImageRootNougat::DexCaches);
        assert_ne!(ImageRootNougat::DexCaches, ImageRootNougat::ClassRoots);
    }

    #[test]
    fn copy_semantics() {
        let a = ImageRootNougat::ClassRoots;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", ImageRootNougat::DexCaches), "DexCaches");
        assert_eq!(format!("{:?}", ImageRootNougat::ClassRoots), "ClassRoots");
        assert_eq!(
            format!("{:?}", ImageRootNougat::ImageRootsMax),
            "ImageRootsMax"
        );
    }
}
