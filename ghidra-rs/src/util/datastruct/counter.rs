use std::fmt;

/// A mutable integer counter, intended for use in collections to avoid the
/// overhead of immutable boxed integers.
///
/// This type is not thread-safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Counter {
    value: i32,
}

impl Counter {
    /// Creates a new counter with an initial value of 0.
    pub fn new() -> Self {
        Self { value: 0 }
    }

    /// Creates a new counter with the given initial value.
    pub fn with_value(value: i32) -> Self {
        Self { value }
    }

    /// Returns the current value of this counter.
    pub fn count(&self) -> i32 {
        self.value
    }

    /// Returns the current value of this counter.
    pub fn get(&self) -> i32 {
        self.value
    }

    /// Sets the value of this counter.
    pub fn set(&mut self, value: i32) {
        self.value = value;
    }

    /// Increments the counter by 1.
    pub fn increment(&mut self) {
        self.value += 1;
    }

    /// Decrements the counter by 1.
    pub fn decrement(&mut self) {
        self.value -= 1;
    }

    /// Adds `n` to the counter.
    pub fn add(&mut self, n: i32) {
        self.value += n;
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

impl From<i32> for Counter {
    fn from(value: i32) -> Self {
        Self::with_value(value)
    }
}

impl From<Counter> for i32 {
    fn from(c: Counter) -> i32 {
        c.value
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_value_is_zero() {
        let c = Counter::new();
        assert_eq!(c.count(), 0);
    }

    #[test]
    fn with_value_sets_initial_value() {
        let c = Counter::with_value(42);
        assert_eq!(c.count(), 42);
    }

    #[test]
    fn count_and_get_return_same_value() {
        let c = Counter::with_value(7);
        assert_eq!(c.count(), c.get());
    }

    #[test]
    fn increment_adds_one() {
        let mut c = Counter::new();
        c.increment();
        assert_eq!(c.count(), 1);
        c.increment();
        assert_eq!(c.count(), 2);
    }

    #[test]
    fn decrement_subtracts_one() {
        let mut c = Counter::with_value(3);
        c.decrement();
        assert_eq!(c.count(), 2);
    }

    #[test]
    fn add_changes_value() {
        let mut c = Counter::with_value(10);
        c.add(5);
        assert_eq!(c.count(), 15);
        c.add(-3);
        assert_eq!(c.count(), 12);
    }

    #[test]
    fn set_replaces_value() {
        let mut c = Counter::new();
        c.set(99);
        assert_eq!(c.count(), 99);
    }

    #[test]
    fn default_trait_is_zero() {
        let c = Counter::default();
        assert_eq!(c.count(), 0);
    }

    #[test]
    fn from_i32_conversion() {
        let c = Counter::from(5);
        assert_eq!(c.count(), 5);
    }

    #[test]
    fn into_i32_conversion() {
        let c = Counter::with_value(13);
        let v: i32 = c.into();
        assert_eq!(v, 13);
    }

    #[test]
    fn display_shows_value() {
        let c = Counter::with_value(7);
        assert_eq!(c.to_string(), "7");
    }

    #[test]
    fn negative_initial_value() {
        let c = Counter::with_value(-5);
        assert_eq!(c.count(), -5);
    }

    #[test]
    fn ordering() {
        let a = Counter::with_value(1);
        let b = Counter::with_value(2);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, Counter::with_value(1));
    }
}
