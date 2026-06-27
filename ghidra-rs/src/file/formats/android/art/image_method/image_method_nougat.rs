/// ART image method indices for Nougat.
///
/// See <https://android.googlesource.com/platform/art/+/refs/heads/nougat-release/runtime/image.h#177>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageMethodNougat {
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
        let _ = ImageMethodNougat::ResolutionMethod;
        let _ = ImageMethodNougat::ImtConflictMethod;
        let _ = ImageMethodNougat::ImtUnimplementedMethod;
        let _ = ImageMethodNougat::CalleeSaveMethod;
        let _ = ImageMethodNougat::RefsOnlySaveMethod;
        let _ = ImageMethodNougat::RefsAndArgsSaveMethod;
        let _ = ImageMethodNougat::ImageMethodsCount;
    }

    #[test]
    fn equality() {
        assert_eq!(
            ImageMethodNougat::ResolutionMethod,
            ImageMethodNougat::ResolutionMethod
        );
        assert_ne!(
            ImageMethodNougat::ResolutionMethod,
            ImageMethodNougat::ImtConflictMethod
        );
    }

    #[test]
    fn copy_semantics() {
        let a = ImageMethodNougat::CalleeSaveMethod;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", ImageMethodNougat::ResolutionMethod),
            "ResolutionMethod"
        );
        assert_eq!(
            format!("{:?}", ImageMethodNougat::ImageMethodsCount),
            "ImageMethodsCount"
        );
    }
}
