/// Row and column information for points in a GridLocationMap. Using these instead
/// of typical points makes the code that translates from grid space to layout space much less
/// confusing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GridPoint {
    pub row: i32,
    pub col: i32,
}

impl GridPoint {
    /// Creates a new GridPoint with the given row and column.
    pub fn new(row: i32, col: i32) -> Self {
        Self { row, col }
    }

    /// Swaps the row and column values.
    pub fn transpose(&mut self) {
        std::mem::swap(&mut self.row, &mut self.col);
    }
}

impl std::fmt::Display for GridPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(r={},c={})", self.row, self.col)
    }
}

impl Default for GridPoint {
    fn default() -> Self {
        Self { row: 0, col: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let gp = GridPoint::new(3, 5);
        assert_eq!(gp.row, 3);
        assert_eq!(gp.col, 5);
    }

    #[test]
    fn test_default() {
        let gp = GridPoint::default();
        assert_eq!(gp.row, 0);
        assert_eq!(gp.col, 0);
    }

    #[test]
    fn test_equality() {
        let gp1 = GridPoint::new(3, 5);
        let gp2 = GridPoint::new(3, 5);
        let gp3 = GridPoint::new(4, 5);
        assert_eq!(gp1, gp2);
        assert_ne!(gp1, gp3);
    }

    #[test]
    fn test_transpose() {
        let mut gp = GridPoint::new(3, 5);
        gp.transpose();
        assert_eq!(gp.row, 5);
        assert_eq!(gp.col, 3);
    }

    #[test]
    fn test_transpose_square() {
        let mut gp = GridPoint::new(7, 7);
        gp.transpose();
        assert_eq!(gp.row, 7);
        assert_eq!(gp.col, 7);
    }

    #[test]
    fn test_display() {
        let gp = GridPoint::new(3, 5);
        assert_eq!(gp.to_string(), "(r=3,c=5)");
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let gp1 = GridPoint::new(3, 5);
        let gp2 = GridPoint::new(3, 5);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        gp1.hash(&mut h1);
        gp2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn test_copy_semantics() {
        let gp1 = GridPoint::new(2, 3);
        let gp2 = gp1;
        let gp3 = gp1;
        assert_eq!(gp1, gp2);
        assert_eq!(gp2, gp3);
    }
}
