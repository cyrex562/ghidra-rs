/// A direction in a hyper-dimensional index, pairing a dimension index with a traversal direction.
///
/// Corresponds to `ghidra.util.database.spatial.hyper.HyperDirection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HyperDirection {
    pub dimension: i32,
    pub forward: bool,
}

impl HyperDirection {
    pub const DEFAULT: HyperDirection = HyperDirection { dimension: 0, forward: true };

    pub fn new(dimension: i32, forward: bool) -> Self {
        HyperDirection { dimension, forward }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_dimension_zero_forward() {
        assert_eq!(HyperDirection::DEFAULT.dimension, 0);
        assert!(HyperDirection::DEFAULT.forward);
    }

    #[test]
    fn new_stores_fields() {
        let d = HyperDirection::new(3, false);
        assert_eq!(d.dimension, 3);
        assert!(!d.forward);
    }

    #[test]
    fn equality() {
        assert_eq!(HyperDirection::new(1, true), HyperDirection::new(1, true));
        assert_ne!(HyperDirection::new(1, true), HyperDirection::new(1, false));
        assert_ne!(HyperDirection::new(1, true), HyperDirection::new(2, true));
    }

    #[test]
    fn copy_semantics() {
        let a = HyperDirection::new(5, true);
        let b = a;
        assert_eq!(a, b);
    }
}
