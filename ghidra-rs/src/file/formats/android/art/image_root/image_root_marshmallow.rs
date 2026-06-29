/// ART image root indices for Marshmallow.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/marshmallow-release/runtime/image.h#125>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRootMarshmallow {
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
        let _ = ImageRootMarshmallow::ResolutionMethod;
        let _ = ImageRootMarshmallow::ImtConflictMethod;
        let _ = ImageRootMarshmallow::DefaultImt;
        let _ = ImageRootMarshmallow::CalleeSaveMethod;
        let _ = ImageRootMarshmallow::RefsOnlySaveMethod;
        let _ = ImageRootMarshmallow::RefsAndArgsSaveMethod;
        let _ = ImageRootMarshmallow::DexCaches;
        let _ = ImageRootMarshmallow::ClassRoots;
        let _ = ImageRootMarshmallow::ImageRootsMax;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ImageRootMarshmallow::ResolutionMethod,
            ImageRootMarshmallow::ResolutionMethod
        );
        assert_ne!(
            ImageRootMarshmallow::ResolutionMethod,
            ImageRootMarshmallow::ImtConflictMethod
        );
    }

    #[test]
    fn copy_semantics() {
        let a = ImageRootMarshmallow::DefaultImt;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", ImageRootMarshmallow::ResolutionMethod),
            "ResolutionMethod"
        );
        assert_eq!(
            format!("{:?}", ImageRootMarshmallow::DefaultImt),
            "DefaultImt"
        );
        assert_eq!(
            format!("{:?}", ImageRootMarshmallow::ImageRootsMax),
            "ImageRootsMax"
        );
    }
}
