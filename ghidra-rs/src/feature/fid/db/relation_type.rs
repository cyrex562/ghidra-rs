/// The types of relations stored in the FID database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelationType {
    /// The callee exists in the same program as the caller.
    DirectCall,
    /// A call between two functions in different programs but in the same library,
    /// discovered by linking on the name.
    IntraLibraryCall,
    /// A call between two functions in entirely different libraries.
    InterLibraryCall,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_distinct() {
        let variants = [
            RelationType::DirectCall,
            RelationType::IntraLibraryCall,
            RelationType::InterLibraryCall,
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
    fn test_clone_and_copy() {
        let r = RelationType::IntraLibraryCall;
        let c = r;
        assert_eq!(r, c);
        assert_eq!(r.clone(), r);
    }

    #[test]
    fn test_debug() {
        assert_eq!(format!("{:?}", RelationType::DirectCall), "DirectCall");
        assert_eq!(
            format!("{:?}", RelationType::IntraLibraryCall),
            "IntraLibraryCall"
        );
        assert_eq!(
            format!("{:?}", RelationType::InterLibraryCall),
            "InterLibraryCall"
        );
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RelationType::DirectCall);
        set.insert(RelationType::IntraLibraryCall);
        set.insert(RelationType::InterLibraryCall);
        assert_eq!(set.len(), 3);
        assert!(set.contains(&RelationType::DirectCall));
        assert!(set.contains(&RelationType::IntraLibraryCall));
        assert!(set.contains(&RelationType::InterLibraryCall));
    }
}
