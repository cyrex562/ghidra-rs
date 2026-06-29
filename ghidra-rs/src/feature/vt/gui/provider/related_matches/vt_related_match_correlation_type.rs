/// Classifies how a related match relates to the primary match in Version Tracking.
///
/// Mirrors `VTRelatedMatchCorrelationType` from the Java source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtRelatedMatchCorrelationType {
    /// The related match is a caller of the primary match.
    Caller,
    /// The related match is the call target (i.e. the same function called).
    Target,
    /// The related match is a callee of the primary match.
    Callee,
    /// The related match has no caller/callee relationship to the primary match.
    Unrelated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_distinct() {
        let variants = [
            VtRelatedMatchCorrelationType::Caller,
            VtRelatedMatchCorrelationType::Target,
            VtRelatedMatchCorrelationType::Callee,
            VtRelatedMatchCorrelationType::Unrelated,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn copy_semantics() {
        let a = VtRelatedMatchCorrelationType::Caller;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn clone_equals_original() {
        let v = VtRelatedMatchCorrelationType::Callee;
        assert_eq!(v.clone(), v);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", VtRelatedMatchCorrelationType::Caller), "Caller");
        assert_eq!(format!("{:?}", VtRelatedMatchCorrelationType::Target), "Target");
        assert_eq!(format!("{:?}", VtRelatedMatchCorrelationType::Callee), "Callee");
        assert_eq!(format!("{:?}", VtRelatedMatchCorrelationType::Unrelated), "Unrelated");
    }

    #[test]
    fn hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VtRelatedMatchCorrelationType::Caller);
        set.insert(VtRelatedMatchCorrelationType::Target);
        set.insert(VtRelatedMatchCorrelationType::Callee);
        set.insert(VtRelatedMatchCorrelationType::Unrelated);
        assert_eq!(set.len(), 4);
    }
}
