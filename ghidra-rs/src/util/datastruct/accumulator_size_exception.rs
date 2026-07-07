use std::fmt;

/// Thrown when an [`Accumulator`](super::Accumulator) has exceeded its maximum capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatorSizeException {
    max_size: usize,
}

impl AccumulatorSizeException {
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }

    /// Returns the maximum capacity that was exceeded.
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

impl fmt::Display for AccumulatorSizeException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Maximum capacity exceeded: {}", self.max_size)
    }
}

impl std::error::Error for AccumulatorSizeException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_max_size() {
        let e = AccumulatorSizeException::new(42);
        assert_eq!(e.max_size(), 42);
    }

    #[test]
    fn display_matches_java_message() {
        let e = AccumulatorSizeException::new(100);
        assert_eq!(e.to_string(), "Maximum capacity exceeded: 100");
    }

    #[test]
    fn display_zero_max_size() {
        let e = AccumulatorSizeException::new(0);
        assert_eq!(e.to_string(), "Maximum capacity exceeded: 0");
    }

    #[test]
    fn implements_error_trait() {
        let e = AccumulatorSizeException::new(5);
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn clone_equality() {
        let e = AccumulatorSizeException::new(7);
        assert_eq!(e.clone(), e);
    }
}
