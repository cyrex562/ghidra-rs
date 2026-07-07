/// A contiguous byte-range with an inclusive start and an exclusive end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pair {
    start: i64,
    end: i64,
}

impl Pair {
    /// Construct a new `Pair` with the given `start` and `end` offsets.
    pub fn new(start: i64, end: i64) -> Self {
        Self { start, end }
    }

    /// Return the start offset.
    pub fn get_start(&self) -> i64 {
        self.start
    }

    /// Set the start offset.
    pub fn set_start(&mut self, start: i64) {
        self.start = start;
    }

    /// Return the end offset.
    pub fn get_end(&self) -> i64 {
        self.end
    }

    /// Set the end offset.
    pub fn set_end(&mut self, end: i64) {
        self.end = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_start_and_end() {
        let p = Pair::new(10, 20);
        assert_eq!(p.get_start(), 10);
        assert_eq!(p.get_end(), 20);
    }

    #[test]
    fn set_start_updates_value() {
        let mut p = Pair::new(0, 100);
        p.set_start(42);
        assert_eq!(p.get_start(), 42);
    }

    #[test]
    fn set_end_updates_value() {
        let mut p = Pair::new(0, 100);
        p.set_end(200);
        assert_eq!(p.get_end(), 200);
    }

    #[test]
    fn equality_same_values() {
        assert_eq!(Pair::new(1, 2), Pair::new(1, 2));
    }

    #[test]
    fn equality_different_start() {
        assert_ne!(Pair::new(1, 2), Pair::new(3, 2));
    }

    #[test]
    fn equality_different_end() {
        assert_ne!(Pair::new(1, 2), Pair::new(1, 3));
    }

    #[test]
    fn zero_length_range() {
        let p = Pair::new(5, 5);
        assert_eq!(p.get_start(), p.get_end());
    }

    #[test]
    fn negative_offsets() {
        let p = Pair::new(-100, -50);
        assert_eq!(p.get_start(), -100);
        assert_eq!(p.get_end(), -50);
    }

    #[test]
    fn clone_is_independent() {
        let a = Pair::new(1, 2);
        let mut b = a;
        b.set_start(99);
        assert_eq!(a.get_start(), 1);
    }
}
