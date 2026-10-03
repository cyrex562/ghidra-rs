use std::fmt;

/// Holds the intermediate results of an [`LSHVector`](super::LSHVector) compare operation.
///
/// Port of `generic.lsh.vector.VectorCompare`.
///
/// Java exposes every field as a public, mutable instance field that callers fill in directly
/// (typically `dotproduct`, `acount`, `bcount`, and `intersectcount` are set by the comparison
/// routine, then [`fill_out`](Self::fill_out) derives the rest); the fields are kept `pub` here
/// for the same reason rather than hidden behind accessors.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct VectorCompare {
    /// Result of the dot product.
    pub dotproduct: f64,
    /// Total number of hashes in the first vector.
    pub acount: i32,
    /// Total number of hashes in the second vector.
    pub bcount: i32,
    /// Total number of hashes in common.
    pub intersectcount: i32,
    /// Minimum vector count.
    pub min: i32,
    /// Maximum vector count.
    pub max: i32,
    /// Number of hashes flipped.
    pub numflip: i32,
    /// Difference in number of hashes.
    pub diff: i32,
}

impl VectorCompare {
    /// Creates a new `VectorCompare` with all fields zeroed, matching Java's default field
    /// initialization (`0`/`0.0`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Assumes `dotproduct`, `acount`, `bcount`, and `intersectcount` are already filled in, and
    /// calculates the remaining values: `min`, `max`, `numflip`, and `diff`.
    ///
    /// Assumes the smaller vector is produced by flipping and removing hashes from the bigger
    /// vector. `numflip` is the number of flipped hashes, and `diff` is the difference in the
    /// number of hashes, both derived from this `VectorCompare` result.
    ///
    /// Port of `VectorCompare.fillOut()`.
    pub fn fill_out(&mut self) {
        if self.acount < self.bcount {
            // Smallest vector is a
            self.min = self.acount;
            self.max = self.bcount;
        } else {
            // Smallest vector is b
            self.min = self.bcount;
            self.max = self.acount;
        }
        self.diff = self.max - self.min; // Subtract to get a positive difference
        self.numflip = self.min - self.intersectcount; // Number of hashes in smallest vector not in intersection
    }
}

impl fmt::Display for VectorCompare {
    /// Port of `VectorCompare.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nVectorCompare: ")?;
        write!(f, "\n  Result of the dot product     = {}", self.dotproduct)?;
        write!(f, "\n  # of hashes in first vector   = {}", self.acount)?;
        write!(f, "\n  # of hashes in second vector  = {}", self.bcount)?;
        write!(f, "\n  # of hashes in common         = {}", self.intersectcount)?;
        write!(f, "\n  Minimum vector count          = {}", self.min)?;
        write!(f, "\n  Maximum vector count          = {}", self.max)?;
        write!(f, "\n  Number of hashes flipped      = {}", self.numflip)?;
        write!(f, "\n  Difference in # of hashes     = {}", self.diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_default_are_zeroed() {
        let vc = VectorCompare::new();
        assert_eq!(vc.dotproduct, 0.0);
        assert_eq!(vc.acount, 0);
        assert_eq!(vc.bcount, 0);
        assert_eq!(vc.intersectcount, 0);
        assert_eq!(vc.min, 0);
        assert_eq!(vc.max, 0);
        assert_eq!(vc.numflip, 0);
        assert_eq!(vc.diff, 0);
        assert_eq!(vc, VectorCompare::default());
    }

    #[test]
    fn fill_out_when_a_is_smaller() {
        let mut vc = VectorCompare { acount: 5, bcount: 12, intersectcount: 4, ..Default::default() };
        vc.fill_out();
        assert_eq!(vc.min, 5);
        assert_eq!(vc.max, 12);
        assert_eq!(vc.diff, 7);
        assert_eq!(vc.numflip, 1); // min(5) - intersectcount(4)
    }

    #[test]
    fn fill_out_when_b_is_smaller() {
        let mut vc = VectorCompare { acount: 20, bcount: 8, intersectcount: 6, ..Default::default() };
        vc.fill_out();
        assert_eq!(vc.min, 8);
        assert_eq!(vc.max, 20);
        assert_eq!(vc.diff, 12);
        assert_eq!(vc.numflip, 2); // min(8) - intersectcount(6)
    }

    #[test]
    fn fill_out_when_counts_are_equal() {
        // Java: `acount < bcount` is false when equal, so b is treated as the "smallest" vector
        // (an arbitrary but faithfully reproduced tie-break).
        let mut vc = VectorCompare { acount: 10, bcount: 10, intersectcount: 10, ..Default::default() };
        vc.fill_out();
        assert_eq!(vc.min, 10);
        assert_eq!(vc.max, 10);
        assert_eq!(vc.diff, 0);
        assert_eq!(vc.numflip, 0);
    }

    #[test]
    fn fill_out_intersect_exceeding_min_yields_negative_numflip() {
        // Java performs no clamping here; if intersectcount (perhaps computed differently by a
        // caller) exceeds min, numflip legitimately goes negative. Faithfully reproduced, not
        // "fixed".
        let mut vc = VectorCompare { acount: 3, bcount: 9, intersectcount: 5, ..Default::default() };
        vc.fill_out();
        assert_eq!(vc.min, 3);
        assert_eq!(vc.numflip, -2);
    }

    #[test]
    fn fill_out_all_zero_counts() {
        let mut vc = VectorCompare::new();
        vc.fill_out();
        assert_eq!(vc.min, 0);
        assert_eq!(vc.max, 0);
        assert_eq!(vc.diff, 0);
        assert_eq!(vc.numflip, 0);
    }

    #[test]
    fn to_string_matches_java_format() {
        let mut vc = VectorCompare { dotproduct: 1.5, acount: 3, bcount: 7, intersectcount: 2, ..Default::default() };
        vc.fill_out();
        let text = vc.to_string();
        assert_eq!(
            text,
            "\nVectorCompare: \
             \n  Result of the dot product     = 1.5\
             \n  # of hashes in first vector   = 3\
             \n  # of hashes in second vector  = 7\
             \n  # of hashes in common         = 2\
             \n  Minimum vector count          = 3\
             \n  Maximum vector count          = 7\
             \n  Number of hashes flipped      = 1\
             \n  Difference in # of hashes     = 4"
        );
    }

    #[test]
    fn copy_semantics_do_not_alias() {
        let mut a = VectorCompare::new();
        a.acount = 5;
        let mut b = a; // Copy, not a shared reference
        b.acount = 9;
        assert_eq!(a.acount, 5);
        assert_eq!(b.acount, 9);
    }
}
