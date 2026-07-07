/// ART image root indices for Android Q (10).
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/image.h#222>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRootQ {
    DexCaches,
    ClassRoots,
    /// Pre-allocated OOME when throwing exception.
    OomeWhenThrowingException,
    /// Pre-allocated OOME when throwing OOME.
    OomeWhenThrowingOome,
    /// Pre-allocated OOME when handling StackOverflowError.
    OomeWhenHandlingStackOverflow,
    /// Pre-allocated NoClassDefFoundError.
    NoClassDefFoundError,
    /// Different for boot image and app image; see aliases below.
    SpecialRoots,
    /// Sentinel: number of elements in this enum.
    ImageRootsMax,
}

impl ImageRootQ {
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
        let _ = ImageRootQ::DexCaches;
        let _ = ImageRootQ::ClassRoots;
        let _ = ImageRootQ::OomeWhenThrowingException;
        let _ = ImageRootQ::OomeWhenThrowingOome;
        let _ = ImageRootQ::OomeWhenHandlingStackOverflow;
        let _ = ImageRootQ::NoClassDefFoundError;
        let _ = ImageRootQ::SpecialRoots;
        let _ = ImageRootQ::ImageRootsMax;
    }

    #[test]
    fn aliases_equal_special_roots() {
        assert_eq!(ImageRootQ::APP_IMAGE_CLASS_LOADER, ImageRootQ::SpecialRoots);
        assert_eq!(ImageRootQ::BOOT_IMAGE_LIVE_OBJECTS, ImageRootQ::SpecialRoots);
        assert_eq!(
            ImageRootQ::APP_IMAGE_CLASS_LOADER,
            ImageRootQ::BOOT_IMAGE_LIVE_OBJECTS
        );
    }

    #[test]
    fn equality() {
        assert_eq!(ImageRootQ::DexCaches, ImageRootQ::DexCaches);
        assert_ne!(ImageRootQ::DexCaches, ImageRootQ::ClassRoots);
        assert_ne!(ImageRootQ::SpecialRoots, ImageRootQ::ImageRootsMax);
    }

    #[test]
    fn copy_semantics() {
        let a = ImageRootQ::OomeWhenThrowingException;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", ImageRootQ::DexCaches), "DexCaches");
        assert_eq!(format!("{:?}", ImageRootQ::ClassRoots), "ClassRoots");
        assert_eq!(
            format!("{:?}", ImageRootQ::OomeWhenThrowingException),
            "OomeWhenThrowingException"
        );
        assert_eq!(
            format!("{:?}", ImageRootQ::OomeWhenThrowingOome),
            "OomeWhenThrowingOome"
        );
        assert_eq!(
            format!("{:?}", ImageRootQ::OomeWhenHandlingStackOverflow),
            "OomeWhenHandlingStackOverflow"
        );
        assert_eq!(
            format!("{:?}", ImageRootQ::NoClassDefFoundError),
            "NoClassDefFoundError"
        );
        assert_eq!(format!("{:?}", ImageRootQ::SpecialRoots), "SpecialRoots");
        assert_eq!(format!("{:?}", ImageRootQ::ImageRootsMax), "ImageRootsMax");
    }
}
