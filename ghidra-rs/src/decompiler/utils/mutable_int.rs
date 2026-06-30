use std::fmt;

/// Mutable integer wrapper allowing pass-by-reference mutation.
///
/// Models `ghidra.pcodeCPort.utils.MutableInt`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MutableInt {
    value: i32,
}

impl MutableInt {
    pub fn new(value: i32) -> Self {
        MutableInt { value }
    }

    pub fn increment(&mut self) {
        self.value += 1;
    }

    pub fn get(&self) -> i32 {
        self.value
    }

    pub fn set(&mut self, i: i32) {
        self.value = i;
    }

    pub fn add(&mut self, amount: i32) {
        self.value += amount;
    }
}

impl Default for MutableInt {
    fn default() -> Self {
        MutableInt { value: 0 }
    }
}

impl fmt::Display for MutableInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zero() {
        assert_eq!(MutableInt::default().get(), 0);
    }

    #[test]
    fn new_stores_value() {
        assert_eq!(MutableInt::new(42).get(), 42);
    }

    #[test]
    fn increment() {
        let mut m = MutableInt::new(5);
        m.increment();
        assert_eq!(m.get(), 6);
    }

    #[test]
    fn set_replaces_value() {
        let mut m = MutableInt::new(1);
        m.set(99);
        assert_eq!(m.get(), 99);
    }

    #[test]
    fn add_increases_value() {
        let mut m = MutableInt::new(10);
        m.add(7);
        assert_eq!(m.get(), 17);
    }

    #[test]
    fn display_matches_java_tostring() {
        assert_eq!(format!("{}", MutableInt::new(0)), "0");
        assert_eq!(format!("{}", MutableInt::new(-3)), "-3");
        assert_eq!(format!("{}", MutableInt::new(100)), "100");
    }

    #[test]
    fn clone_and_eq() {
        let a = MutableInt::new(7);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
