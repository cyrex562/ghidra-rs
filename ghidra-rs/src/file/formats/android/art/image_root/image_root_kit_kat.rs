/// ART image root indices for KitKat.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/image.h#91>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRootKitKat {
    ResolutionMethod,
    CalleeSaveMethod,
    RefsOnlySaveMethod,
    RefsAndArgsSaveMethod,
    OatLocation,
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
        let _ = ImageRootKitKat::ResolutionMethod;
        let _ = ImageRootKitKat::CalleeSaveMethod;
        let _ = ImageRootKitKat::RefsOnlySaveMethod;
        let _ = ImageRootKitKat::RefsAndArgsSaveMethod;
        let _ = ImageRootKitKat::OatLocation;
        let _ = ImageRootKitKat::DexCaches;
        let _ = ImageRootKitKat::ClassRoots;
        let _ = ImageRootKitKat::ImageRootsMax;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ImageRootKitKat::ResolutionMethod,
            ImageRootKitKat::ResolutionMethod
        );
        assert_ne!(
            ImageRootKitKat::ResolutionMethod,
            ImageRootKitKat::CalleeSaveMethod
        );
    }

    #[test]
    fn copy_semantics() {
        let a = ImageRootKitKat::OatLocation;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", ImageRootKitKat::ResolutionMethod),
            "ResolutionMethod"
        );
        assert_eq!(
            format!("{:?}", ImageRootKitKat::ImageRootsMax),
            "ImageRootsMax"
        );
        assert_eq!(
            format!("{:?}", ImageRootKitKat::DexCaches),
            "DexCaches"
        );
    }
}
