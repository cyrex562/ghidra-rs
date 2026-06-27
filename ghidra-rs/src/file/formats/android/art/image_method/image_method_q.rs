/// ART image method indices for Android Q (10).
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/image.h#209>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageMethodQ {
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
        let _ = ImageMethodQ::ResolutionMethod;
        let _ = ImageMethodQ::ImtConflictMethod;
        let _ = ImageMethodQ::ImtUnimplementedMethod;
        let _ = ImageMethodQ::SaveAllCalleeSavesMethod;
        let _ = ImageMethodQ::SaveRefsOnlyMethod;
        let _ = ImageMethodQ::SaveRefsAndArgsMethod;
        let _ = ImageMethodQ::SaveEverythingMethod;
        let _ = ImageMethodQ::SaveEverythingMethodForClinit;
        let _ = ImageMethodQ::SaveEverythingMethodForSuspendCheck;
        let _ = ImageMethodQ::ImageMethodsCount;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ImageMethodQ::ResolutionMethod,
            ImageMethodQ::ResolutionMethod
        );
        assert_ne!(
            ImageMethodQ::ResolutionMethod,
            ImageMethodQ::ImtConflictMethod
        );
    }

    #[test]
    fn copy_semantics() {
        let a = ImageMethodQ::SaveEverythingMethod;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", ImageMethodQ::ResolutionMethod),
            "ResolutionMethod"
        );
        assert_eq!(
            format!("{:?}", ImageMethodQ::ImageMethodsCount),
            "ImageMethodsCount"
        );
        assert_eq!(
            format!("{:?}", ImageMethodQ::SaveEverythingMethodForClinit),
            "SaveEverythingMethodForClinit"
        );
        assert_eq!(
            format!("{:?}", ImageMethodQ::SaveEverythingMethodForSuspendCheck),
            "SaveEverythingMethodForSuspendCheck"
        );
    }
}
