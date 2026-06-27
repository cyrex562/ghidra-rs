/// ART image root indices for Lollipop.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/image.h#105>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRootLollipop {
    ResolutionMethod,
    ImtConflictMethod,
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
        let _ = ImageRootLollipop::ResolutionMethod;
        let _ = ImageRootLollipop::ImtConflictMethod;
        let _ = ImageRootLollipop::DefaultImt;
        let _ = ImageRootLollipop::CalleeSaveMethod;
        let _ = ImageRootLollipop::RefsOnlySaveMethod;
        let _ = ImageRootLollipop::RefsAndArgsSaveMethod;
        let _ = ImageRootLollipop::DexCaches;
        let _ = ImageRootLollipop::ClassRoots;
        let _ = ImageRootLollipop::ImageRootsMax;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ImageRootLollipop::ResolutionMethod,
            ImageRootLollipop::ResolutionMethod
        );
        assert_ne!(
            ImageRootLollipop::ResolutionMethod,
            ImageRootLollipop::ImtConflictMethod
        );
    }

    #[test]
    fn copy_semantics() {
        let a = ImageRootLollipop::DefaultImt;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", ImageRootLollipop::ResolutionMethod),
            "ResolutionMethod"
        );
        assert_eq!(
            format!("{:?}", ImageRootLollipop::ImageRootsMax),
            "ImageRootsMax"
        );
        assert_eq!(
            format!("{:?}", ImageRootLollipop::ImtConflictMethod),
            "ImtConflictMethod"
        );
    }
}
