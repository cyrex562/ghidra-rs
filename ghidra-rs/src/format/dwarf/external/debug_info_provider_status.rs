/// Indicates the validity status of a debug info provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugInfoProviderStatus {
    Unknown,
    Valid,
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_distinct() {
        let variants = [
            DebugInfoProviderStatus::Unknown,
            DebugInfoProviderStatus::Valid,
            DebugInfoProviderStatus::Invalid,
        ];
        assert_eq!(variants.len(), 3);
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let original = DebugInfoProviderStatus::Valid;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", DebugInfoProviderStatus::Unknown), "Unknown");
        assert_eq!(format!("{:?}", DebugInfoProviderStatus::Valid), "Valid");
        assert_eq!(format!("{:?}", DebugInfoProviderStatus::Invalid), "Invalid");
    }
}
