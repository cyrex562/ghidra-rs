/// ART image method indices for Android Pie (9).
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/image.h#194>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageMethodPie {
    ResolutionMethod,
    ImtConflictMethod,
    ImtUnimplementedMethod,
    SaveAllCalleeSavesMethod,
    SaveRefsOnlyMethod,
    SaveRefsAndArgsMethod,
    SaveEverythingMethod,
    SaveEverythingMethodForClinit,
    SaveEverythingMethodForSuspendCheck,
    /// Sentinel: number of elements in this enum.
    ImageMethodsCount,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_constructible() {
        let _ = ImageMethodPie::ResolutionMethod;
        let _ = ImageMethodPie::ImtConflictMethod;
        let _ = ImageMethodPie::ImtUnimplementedMethod;
        let _ = ImageMethodPie::SaveAllCalleeSavesMethod;
        let _ = ImageMethodPie::SaveRefsOnlyMethod;
        let _ = ImageMethodPie::SaveRefsAndArgsMethod;
        let _ = ImageMethodPie::SaveEverythingMethod;
        let _ = ImageMethodPie::SaveEverythingMethodForClinit;
        let _ = ImageMethodPie::SaveEverythingMethodForSuspendCheck;
        let _ = ImageMethodPie::ImageMethodsCount;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ImageMethodPie::ResolutionMethod,
            ImageMethodPie::ResolutionMethod
        );
        assert_ne!(
            ImageMethodPie::ResolutionMethod,
            ImageMethodPie::ImtConflictMethod
        );
    }

    #[test]
    fn copy_semantics() {
        let a = ImageMethodPie::SaveEverythingMethod;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", ImageMethodPie::ResolutionMethod),
            "ResolutionMethod"
        );
        assert_eq!(
            format!("{:?}", ImageMethodPie::ImageMethodsCount),
            "ImageMethodsCount"
        );
        assert_eq!(
            format!("{:?}", ImageMethodPie::SaveEverythingMethodForClinit),
            "SaveEverythingMethodForClinit"
        );
        assert_eq!(
            format!("{:?}", ImageMethodPie::SaveEverythingMethodForSuspendCheck),
            "SaveEverythingMethodForSuspendCheck"
        );
    }
}
