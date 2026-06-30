use std::fmt;

/// Mutable long wrapper allowing pass-by-reference mutation.
///
/// Models `ghidra.pcodeCPort.utils.MutableLong`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MutableLong {
    value: i64,
}

impl MutableLong {
    pub fn new(value: i64) -> Self {
        MutableLong { value }
    }

    pub fn increment(&mut self) {
        self.value += 1;
    }

    pub fn get(&self) -> i64 {
        self.value
    }

    pub fn set(&mut self, i: i64) {
        self.value = i;
    }

    pub fn add(&mut self, amount: i64) {
        self.value += amount;
    }
}

impl Default for MutableLong {
    fn default() -> Self {
        MutableLong { value: 0 }
    }
}

impl fmt::Display for MutableLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zero() {
        assert_eq!(MutableLong::default().get(), 0);
    }

    #[test]
    fn new_stores_value() {
        assert_eq!(MutableLong::new(42).get(), 42);
    }

    #[test]
    fn increment() {
        let mut m = MutableLong::new(5);
        m.increment();
        assert_eq!(m.get(), 6);
    }

    #[test]
    fn set_replaces_value() {
        let mut m = MutableLong::new(1);
        m.set(99);
        assert_eq!(m.get(), 99);
    }

    #[test]
    fn add_increases_value() {
        let mut m = MutableLong::new(10);
        m.add(7);
        assert_eq!(m.get(), 17);
    }

    #[test]
    fn display_matches_java_tostring() {
        assert_eq!(format!("{}", MutableLong::new(0)), "0");
        assert_eq!(format!("{}", MutableLong::new(-3)), "-3");
        assert_eq!(format!("{}", MutableLong::new(100)), "100");
    }

    #[test]
    fn clone_and_eq() {
        let a = MutableLong::new(7);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn large_value() {
        let mut m = MutableLong::new(i64::MAX - 1);
        m.increment();
        assert_eq!(m.get(), i64::MAX);
    }

    #[test]
    fn negative_add() {
        let mut m = MutableLong::new(100);
        m.add(-50);
        assert_eq!(m.get(), 50);
    }
}
