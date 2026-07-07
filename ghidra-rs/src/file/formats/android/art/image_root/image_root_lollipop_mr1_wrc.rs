/// ART image root indices for Lollipop MR1 WRC.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-wfc-release/runtime/image.h#106>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRootLollipopMr1Wrc {
    ResolutionMethod,
    ImtConflictMethod,
    ImtUnimplementedMethod,
    DefaultImt,
    CalleeSaveMethod,
    RefsOnlySaveMethod,
    RefsAndArgsSaveMethod,
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
        let _ = ImageRootLollipopMr1Wrc::ResolutionMethod;
        let _ = ImageRootLollipopMr1Wrc::ImtConflictMethod;
        let _ = ImageRootLollipopMr1Wrc::ImtUnimplementedMethod;
        let _ = ImageRootLollipopMr1Wrc::DefaultImt;
        let _ = ImageRootLollipopMr1Wrc::CalleeSaveMethod;
        let _ = ImageRootLollipopMr1Wrc::RefsOnlySaveMethod;
        let _ = ImageRootLollipopMr1Wrc::RefsAndArgsSaveMethod;
        let _ = ImageRootLollipopMr1Wrc::DexCaches;
        let _ = ImageRootLollipopMr1Wrc::ClassRoots;
        let _ = ImageRootLollipopMr1Wrc::ImageRootsMax;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ImageRootLollipopMr1Wrc::ResolutionMethod,
            ImageRootLollipopMr1Wrc::ResolutionMethod
        );
        assert_ne!(
            ImageRootLollipopMr1Wrc::ResolutionMethod,
            ImageRootLollipopMr1Wrc::ImtConflictMethod
        );
    }

    #[test]
    fn copy_semantics() {
        let a = ImageRootLollipopMr1Wrc::DefaultImt;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", ImageRootLollipopMr1Wrc::ResolutionMethod),
            "ResolutionMethod"
        );
        assert_eq!(
            format!("{:?}", ImageRootLollipopMr1Wrc::ImtUnimplementedMethod),
            "ImtUnimplementedMethod"
        );
        assert_eq!(
            format!("{:?}", ImageRootLollipopMr1Wrc::ImageRootsMax),
            "ImageRootsMax"
        );
    }
}
