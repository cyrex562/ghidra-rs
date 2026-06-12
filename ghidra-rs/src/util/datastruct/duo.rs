#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    Left,
    Right,
}

impl Side {
    pub fn other_side(&self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Duo<T> {
    pub left: T,
    pub right: T,
}

impl<T> Duo<T> {
    pub fn new(left: T, right: T) -> Self {
        Self { left, right }
    }

    pub fn get(&self, side: Side) -> &T {
        match side {
            Side::Left => &self.left,
            Side::Right => &self.right,
        }
    }

    pub fn with(&self, side: Side, new_value: T) -> Self
    where
        T: Clone,
    {
        match side {
            Side::Left => Self::new(new_value, self.right.clone()),
            Side::Right => Self::new(self.left.clone(), new_value),
        }
    }

    pub fn each<F>(&self, mut f: F)
    where
        F: FnMut(&T),
    {
        f(&self.left);
        f(&self.right);
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
    fn test_duo() {
        let duo = Duo::new(10, 20);
        assert_eq!(*duo.get(Side::Left), 10);
        assert_eq!(*duo.get(Side::Right), 20);

        let duo2 = duo.with(Side::Left, 30);
        assert_eq!(duo2.left, 30);
        assert_eq!(duo2.right, 20);
    }
}
