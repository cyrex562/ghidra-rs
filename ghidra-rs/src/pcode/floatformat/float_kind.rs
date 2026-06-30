/// Classifies the kind of a floating-point value.
///
/// Corresponds to `ghidra.pcode.floatformat.FloatKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FloatKind {
    /// A finite value, including both normal and subnormal numbers.
    Finite,
    /// Positive or negative infinity.
    Infinite,
    /// A quiet NaN.
    QuietNan,
    /// A signaling NaN.
    SignalingNan,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(FloatKind::Finite, FloatKind::Infinite);
        assert_ne!(FloatKind::Infinite, FloatKind::QuietNan);
        assert_ne!(FloatKind::QuietNan, FloatKind::SignalingNan);
        assert_ne!(FloatKind::Finite, FloatKind::SignalingNan);
    }

    #[test]
    fn copy_and_clone() {
        let k = FloatKind::Finite;
        let k2 = k;
        assert_eq!(k, k2);
        let k3 = k.clone();
        assert_eq!(k, k3);
    }

    #[test]
    fn debug_output_contains_variant_name() {
        assert!(format!("{:?}", FloatKind::Finite).contains("Finite"));
        assert!(format!("{:?}", FloatKind::Infinite).contains("Infinite"));
        assert!(format!("{:?}", FloatKind::QuietNan).contains("QuietNan"));
        assert!(format!("{:?}", FloatKind::SignalingNan).contains("SignalingNan"));
    }

    #[test]
    fn all_four_variants_match() {
        let cases = [
            FloatKind::Finite,
            FloatKind::Infinite,
            FloatKind::QuietNan,
            FloatKind::SignalingNan,
        ];
        for k in cases {
            let _ = match k {
                FloatKind::Finite => 0,
                FloatKind::Infinite => 1,
                FloatKind::QuietNan => 2,
                FloatKind::SignalingNan => 3,
            };
        }
    }

    #[test]
    fn hash_is_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FloatKind::Finite);
        set.insert(FloatKind::Infinite);
        set.insert(FloatKind::QuietNan);
        set.insert(FloatKind::SignalingNan);
        assert_eq!(set.len(), 4);
        assert!(set.contains(&FloatKind::Finite));
    }
}
