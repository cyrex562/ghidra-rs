/// Classifies the kind of BSim signature a feature describes.
///
/// Mirrors `ghidra.bsfv.BSimFeatureType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BSimFeatureType {
    /// Signature describes data-flow to a single varnode.
    DataFlow,

    /// Signature describes control-flow for a basic-block.
    ControlFlow,

    /// Signature describes control-flow for a basic-block and data-flow into
    /// the first (root) PcodeOp in the block.
    Combined,

    /// Signature describes data-flow into two root PcodeOps that are adjacent
    /// in a basic-block.
    DualFlow,

    /// Signature describes stand-alone COPY ops within a single block.
    CopySig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_distinct() {
        let variants = [
            BSimFeatureType::DataFlow,
            BSimFeatureType::ControlFlow,
            BSimFeatureType::Combined,
            BSimFeatureType::DualFlow,
            BSimFeatureType::CopySig,
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
    fn clone_and_copy() {
        let a = BSimFeatureType::DualFlow;
        let b = a;
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", BSimFeatureType::DataFlow), "DataFlow");
        assert_eq!(format!("{:?}", BSimFeatureType::ControlFlow), "ControlFlow");
        assert_eq!(format!("{:?}", BSimFeatureType::Combined), "Combined");
        assert_eq!(format!("{:?}", BSimFeatureType::DualFlow), "DualFlow");
        assert_eq!(format!("{:?}", BSimFeatureType::CopySig), "CopySig");
    }

    #[test]
    fn hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(BSimFeatureType::DataFlow);
        set.insert(BSimFeatureType::ControlFlow);
        set.insert(BSimFeatureType::Combined);
        set.insert(BSimFeatureType::DualFlow);
        set.insert(BSimFeatureType::CopySig);
        assert_eq!(set.len(), 5);
        assert!(set.contains(&BSimFeatureType::CopySig));
    }
}
