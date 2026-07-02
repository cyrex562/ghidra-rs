/// ART image root indices (generic).
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/android11-release/runtime/image.h#224>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRootR {
    DexCaches,
    ClassRoots,
    /// Different for boot image and app image; see aliases below.
    SpecialRoots,
    /// Sentinel: number of elements in this enum.
    ImageRootsMax,
}

impl ImageRootR {
    /// The class loader used to build the app image.
    pub const APP_IMAGE_CLASS_LOADER: Self = Self::SpecialRoots;
    /// Array of boot image objects that must be kept live.
    pub const BOOT_IMAGE_LIVE_OBJECTS: Self = Self::SpecialRoots;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_constructible() {
        let _ = ImageRootR::DexCaches;
        let _ = ImageRootR::ClassRoots;
        let _ = ImageRootR::SpecialRoots;
        let _ = ImageRootR::ImageRootsMax;
    }

    #[test]
    fn aliases_equal_special_roots() {
        assert_eq!(ImageRootR::APP_IMAGE_CLASS_LOADER, ImageRootR::SpecialRoots);
        assert_eq!(ImageRootR::BOOT_IMAGE_LIVE_OBJECTS, ImageRootR::SpecialRoots);
        assert_eq!(
            ImageRootR::APP_IMAGE_CLASS_LOADER,
            ImageRootR::BOOT_IMAGE_LIVE_OBJECTS
        );
    }

    #[test]
    fn equality() {
        assert_eq!(ImageRootR::DexCaches, ImageRootR::DexCaches);
        assert_ne!(ImageRootR::DexCaches, ImageRootR::ClassRoots);
        assert_ne!(ImageRootR::SpecialRoots, ImageRootR::ImageRootsMax);
    }

    #[test]
    fn copy_semantics() {
        let a = ImageRootR::SpecialRoots;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", ImageRootR::DexCaches), "DexCaches");
        assert_eq!(format!("{:?}", ImageRootR::ClassRoots), "ClassRoots");
        assert_eq!(format!("{:?}", ImageRootR::SpecialRoots), "SpecialRoots");
        assert_eq!(format!("{:?}", ImageRootR::ImageRootsMax), "ImageRootsMax");
    }
}
