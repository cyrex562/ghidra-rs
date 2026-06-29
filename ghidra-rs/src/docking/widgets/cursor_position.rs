use std::fmt;

/// A simple tracker of position in an object that allows more specialized users to extend and
/// add functionality.
///
/// Corresponds to `docking.widgets.CursorPosition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPosition {
    position: i32,
}

impl CursorPosition {
    pub fn new(position: i32) -> Self {
        Self { position }
    }

    pub fn set_offset(&mut self, offset: i32) {
        self.position += offset;
    }

    pub fn get_position(&self) -> i32 {
        self.position
    }
}

impl fmt::Display for CursorPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CursorPosition - {}", self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_position() {
        let cp = CursorPosition::new(5);
        assert_eq!(cp.get_position(), 5);
    }

    #[test]
    fn set_offset_adds_to_position() {
        let mut cp = CursorPosition::new(10);
        cp.set_offset(3);
        assert_eq!(cp.get_position(), 13);
    }

    #[test]
    fn set_offset_negative() {
        let mut cp = CursorPosition::new(10);
        cp.set_offset(-4);
        assert_eq!(cp.get_position(), 6);
    }

    #[test]
    fn set_offset_zero() {
        let mut cp = CursorPosition::new(7);
        cp.set_offset(0);
        assert_eq!(cp.get_position(), 7);
    }

    #[test]
    fn display_format() {
        let cp = CursorPosition::new(42);
        assert_eq!(cp.to_string(), "CursorPosition - 42");
    }

    #[test]
    fn display_zero() {
        let cp = CursorPosition::new(0);
        assert_eq!(cp.to_string(), "CursorPosition - 0");
    }
}
