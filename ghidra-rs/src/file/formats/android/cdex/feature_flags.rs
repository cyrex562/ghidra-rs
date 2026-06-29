/// CDex (Compact Dex) feature flags.
///
/// Mirrors `ghidra.file.formats.android.cdex.FeatureFlags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeatureFlags;

impl FeatureFlags {
    pub const DEFAULT_METHODS: u32 = 0x1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_methods_value() {
        assert_eq!(FeatureFlags::DEFAULT_METHODS, 0x1);
    }

    #[test]
    fn default_methods_is_one() {
        assert_eq!(FeatureFlags::DEFAULT_METHODS, 1);
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(FeatureFlags::default(), FeatureFlags);
    }

    #[test]
    fn clone_is_equal() {
        let a = FeatureFlags;
        assert_eq!(a, a.clone());
    }

    #[test]
    fn debug_formats() {
        let s = format!("{:?}", FeatureFlags);
        assert_eq!(s, "FeatureFlags");
    }
}
