/// A row in a `FunctionStartAlignmentTableModel`.
///
/// Records how many function entry points share a given remainder when
/// divided by an alignment modulus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionStartAlignmentRowObject {
    remainder: i64,
    num_funcs: i64,
}

impl FunctionStartAlignmentRowObject {
    /// Creates a row for the given `remainder` and `num_funcs` count.
    pub fn new(remainder: i64, num_funcs: i64) -> Self {
        Self { remainder, num_funcs }
    }

    /// Returns the remainder after dividing the entry point by the alignment modulus.
    pub fn remainder(&self) -> i64 {
        self.remainder
    }

    /// Returns the number of functions with this remainder.
    pub fn num_funcs(&self) -> i64 {
        self.num_funcs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_fields() {
        let row = FunctionStartAlignmentRowObject::new(3, 42);
        assert_eq!(row.remainder(), 3);
        assert_eq!(row.num_funcs(), 42);
    }

    #[test]
    fn zero_values() {
        let row = FunctionStartAlignmentRowObject::new(0, 0);
        assert_eq!(row.remainder(), 0);
        assert_eq!(row.num_funcs(), 0);
    }

    #[test]
    fn equality() {
        let a = FunctionStartAlignmentRowObject::new(1, 10);
        let b = FunctionStartAlignmentRowObject::new(1, 10);
        let c = FunctionStartAlignmentRowObject::new(2, 10);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn negative_values_allowed() {
        let row = FunctionStartAlignmentRowObject::new(-1, -5);
        assert_eq!(row.remainder(), -1);
        assert_eq!(row.num_funcs(), -5);
    }
}
