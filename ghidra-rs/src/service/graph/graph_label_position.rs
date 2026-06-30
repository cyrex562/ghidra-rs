/// Specification for the vertex label position relative to the vertex shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphLabelPosition {
    North,
    NorthEast,
    East,
    SouthEast,
    South,
    SouthWest,
    West,
    NorthWest,
    Center,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_distinct() {
        let variants = [
            GraphLabelPosition::North,
            GraphLabelPosition::NorthEast,
            GraphLabelPosition::East,
            GraphLabelPosition::SouthEast,
            GraphLabelPosition::South,
            GraphLabelPosition::SouthWest,
            GraphLabelPosition::West,
            GraphLabelPosition::NorthWest,
            GraphLabelPosition::Center,
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
        let a = GraphLabelPosition::Center;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_output_is_non_empty() {
        let pos = GraphLabelPosition::NorthWest;
        let s = format!("{:?}", pos);
        assert!(!s.is_empty());
    }
}
