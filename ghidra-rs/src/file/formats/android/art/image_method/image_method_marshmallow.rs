/// ART image method indices for Marshmallow.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/marshmallow-release/runtime/image.h#125>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageMethodMarshmallow {
    ResolutionMethod,
    ImtConflictMethod,
    ImtUnimplementedMethod,
    CalleeSaveMethod,
    RefsOnlySaveMethod,
    RefsAndArgsSaveMethod,
    /// Sentinel: number of elements in this enum.
    ImageMethodsCount,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_constructible() {
        let _ = ImageMethodMarshmallow::ResolutionMethod;
        let _ = ImageMethodMarshmallow::ImtConflictMethod;
        let _ = ImageMethodMarshmallow::ImtUnimplementedMethod;
        let _ = ImageMethodMarshmallow::CalleeSaveMethod;
        let _ = ImageMethodMarshmallow::RefsOnlySaveMethod;
        let _ = ImageMethodMarshmallow::RefsAndArgsSaveMethod;
        let _ = ImageMethodMarshmallow::ImageMethodsCount;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ImageMethodMarshmallow::ResolutionMethod,
            ImageMethodMarshmallow::ResolutionMethod
        );
        assert_ne!(
            ImageMethodMarshmallow::ResolutionMethod,
            ImageMethodMarshmallow::ImtConflictMethod
        );
    }

    #[test]
    fn copy_semantics() {
        let a = ImageMethodMarshmallow::CalleeSaveMethod;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", ImageMethodMarshmallow::ResolutionMethod),
            "ResolutionMethod"
        );
        assert_eq!(
            format!("{:?}", ImageMethodMarshmallow::ImageMethodsCount),
            "ImageMethodsCount"
        );
    }
}
