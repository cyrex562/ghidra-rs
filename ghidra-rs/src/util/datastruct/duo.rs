#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    Left,
    Right,
}

impl Side {
    /// Returns the opposite side (LEFT ↔ RIGHT).
    pub fn other_side(&self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

/// Holds two objects of the same type. Uses LEFT and RIGHT to refer to each item.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Duo<T> {
    pub left: T,
    pub right: T,
}

impl<T> Duo<T> {
    /// Creates a new Duo with the given left and right values.
    pub fn new(left: T, right: T) -> Self {
        Self { left, right }
    }

    /// Gets the value for the given side.
    pub fn get(&self, side: Side) -> &T {
        match side {
            Side::Left => &self.left,
            Side::Right => &self.right,
        }
    }

    /// Creates a new Duo, replacing the value for just one side.
    pub fn with(&self, side: Side, new_value: T) -> Self
    where
        T: Clone,
    {
        match side {
            Side::Left => Self::new(new_value, self.right.clone()),
            Side::Right => Self::new(self.left.clone(), new_value),
        }
    }

    /// Invokes the given closure on both the left and right values.
    pub fn each<F>(&self, mut f: F)
    where
        F: FnMut(&T),
    {
        f(&self.left);
        f(&self.right);
    }

    /// Returns true if both values equal the given left and right values.
    pub fn equals_values(&self, other_left: &T, other_right: &T) -> bool
    where
        T: PartialEq,
    {
        self.left == *other_left && self.right == *other_right
    }
}

impl<T: Default> Default for Duo<T> {
    fn default() -> Self {
        Self {
            left: T::default(),
            right: T::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_get() {
        let duo = Duo::new(10, 20);
        assert_eq!(*duo.get(Side::Left), 10);
        assert_eq!(*duo.get(Side::Right), 20);
    }

    #[test]
    fn test_with_left() {
        let duo = Duo::new(10, 20);
        let duo2 = duo.with(Side::Left, 30);
        assert_eq!(duo2.left, 30);
        assert_eq!(duo2.right, 20);
    }

    #[test]
    fn test_with_right() {
        let duo = Duo::new(10, 20);
        let duo2 = duo.with(Side::Right, 99);
        assert_eq!(duo2.left, 10);
        assert_eq!(duo2.right, 99);
    }

    #[test]
    fn test_each() {
        let duo = Duo::new(5, 10);
        let mut sum = 0;
        duo.each(|&v| sum += v);
        assert_eq!(sum, 15);
    }

    #[test]
    fn test_equals_values_true() {
        let duo = Duo::new("hello", "world");
        assert!(duo.equals_values(&"hello", &"world"));
    }

    #[test]
    fn test_equals_values_false() {
        let duo = Duo::new("hello", "world");
        assert!(!duo.equals_values(&"hello", &"there"));
        assert!(!duo.equals_values(&"hi", &"world"));
    }

    #[test]
    fn test_default() {
        let duo: Duo<i32> = Duo::default();
        assert_eq!(duo.left, 0);
        assert_eq!(duo.right, 0);
    }

    #[test]
    fn test_side_other_side() {
        assert_eq!(Side::Left.other_side(), Side::Right);
        assert_eq!(Side::Right.other_side(), Side::Left);
    }

    #[test]
    fn test_clone_and_equality() {
        let duo1 = Duo::new(42, 43);
        let duo2 = duo1.clone();
        assert_eq!(duo1, duo2);
    }
}
