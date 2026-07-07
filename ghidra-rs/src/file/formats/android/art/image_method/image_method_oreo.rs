/// ART image method indices for Oreo.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/image.h#178>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageMethodOreo {
    ResolutionMethod,
    ImtConflictMethod,
    ImtUnimplementedMethod,
    SaveAllCalleeSavesMethod,
    SaveRefsOnlyMethod,
    SaveRefsAndArgsMethod,
    SaveEverythingMethod,
    /// Sentinel: number of elements in this enum.
    ImageMethodsCount,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_constructible() {
        let _ = ImageMethodOreo::ResolutionMethod;
        let _ = ImageMethodOreo::ImtConflictMethod;
        let _ = ImageMethodOreo::ImtUnimplementedMethod;
        let _ = ImageMethodOreo::SaveAllCalleeSavesMethod;
        let _ = ImageMethodOreo::SaveRefsOnlyMethod;
        let _ = ImageMethodOreo::SaveRefsAndArgsMethod;
        let _ = ImageMethodOreo::SaveEverythingMethod;
        let _ = ImageMethodOreo::ImageMethodsCount;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ImageMethodOreo::ResolutionMethod,
            ImageMethodOreo::ResolutionMethod
        );
        assert_ne!(
            ImageMethodOreo::ResolutionMethod,
            ImageMethodOreo::ImtConflictMethod
        );
    }

    #[test]
    fn copy_semantics() {
        let a = ImageMethodOreo::SaveEverythingMethod;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", ImageMethodOreo::ResolutionMethod),
            "ResolutionMethod"
        );
        assert_eq!(
            format!("{:?}", ImageMethodOreo::ImageMethodsCount),
            "ImageMethodsCount"
        );
    }
}
