/// Represents whether a vertex is an incoming vertex (the start or from) on an edge,
/// an outgoing vertex (the end or to) on an edge, or if it is both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FcgDirection {
    In,
    InAndOut,
    Out,
}

impl FcgDirection {
    pub fn is_source(&self) -> bool {
        *self == FcgDirection::InAndOut
    }

    pub fn is_in(&self) -> bool {
        *self == FcgDirection::In
    }

    pub fn is_out(&self) -> bool {
        *self == FcgDirection::Out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_in() {
        assert!(FcgDirection::In.is_in());
        assert!(!FcgDirection::InAndOut.is_in());
        assert!(!FcgDirection::Out.is_in());
    }

    #[test]
    fn test_is_out() {
        assert!(!FcgDirection::In.is_out());
        assert!(!FcgDirection::InAndOut.is_out());
        assert!(FcgDirection::Out.is_out());
    }

    #[test]
    fn test_is_source() {
        assert!(!FcgDirection::In.is_source());
        assert!(FcgDirection::InAndOut.is_source());
        assert!(!FcgDirection::Out.is_source());
    }

    #[test]
    fn test_only_one_variant_true_per_method() {
        let variants = [FcgDirection::In, FcgDirection::InAndOut, FcgDirection::Out];
        assert_eq!(variants.iter().filter(|v| v.is_in()).count(), 1);
        assert_eq!(variants.iter().filter(|v| v.is_out()).count(), 1);
        assert_eq!(variants.iter().filter(|v| v.is_source()).count(), 1);
    }
}
