/// Records the current top-of-screen position of the field panel viewer.
///
/// Corresponds to `docking.widgets.fieldpanel.support.ViewerPosition`.
#[derive(Debug, Clone)]
pub struct ViewerPosition {
    pub index: i128,
    pub x_offset: i32,
    pub y_offset: i32,
}

impl ViewerPosition {
    /// Creates a new `ViewerPosition` with the given index, x offset, and y offset.
    ///
    /// `y_offset` is 0 when the layout at the top is fully visible, or negative when
    /// it begins above the top of the screen.
    pub fn new(index: i128, x_offset: i32, y_offset: i32) -> Self {
        Self { index, x_offset, y_offset }
    }

    /// Creates a new `ViewerPosition` from an `i32` index.
    pub fn from_int_index(index: i32, x_offset: i32, y_offset: i32) -> Self {
        Self::new(index as i128, x_offset, y_offset)
    }

    /// Returns the index of the layout at the top of the screen as an `i32`.
    pub fn index_as_int(&self) -> i32 {
        self.index as i32
    }

    /// Returns the index of the layout at the top of the screen.
    pub fn index(&self) -> i128 {
        self.index
    }

    /// Returns the horizontal scroll position.
    pub fn x_offset(&self) -> i32 {
        self.x_offset
    }

    /// Returns the y coordinate of the layout at the top of the screen.
    pub fn y_offset(&self) -> i32 {
        self.y_offset
    }
}

/// Equality mirrors Java: only `index` and `y_offset` are compared; `x_offset` is excluded.
impl PartialEq for ViewerPosition {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.y_offset == other.y_offset
    }
}

impl Eq for ViewerPosition {}

impl std::fmt::Display for ViewerPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Index = {}, xOffset = {}, yOffset = {}", self.index, self.x_offset, self.y_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_fields() {
        let vp = ViewerPosition::new(10, 2, -5);
        assert_eq!(vp.index(), 10);
        assert_eq!(vp.x_offset(), 2);
        assert_eq!(vp.y_offset(), -5);
    }

    #[test]
    fn from_int_index_converts_correctly() {
        let vp = ViewerPosition::from_int_index(42, 0, 0);
        assert_eq!(vp.index(), 42);
        assert_eq!(vp.index_as_int(), 42);
    }

    #[test]
    fn index_as_int_truncates_to_i32() {
        let vp = ViewerPosition::new(7, 0, 0);
        assert_eq!(vp.index_as_int(), 7);
    }

    #[test]
    fn equality_ignores_x_offset() {
        let a = ViewerPosition::new(5, 0, -3);
        let b = ViewerPosition::new(5, 99, -3);
        assert_eq!(a, b);
    }

    #[test]
    fn equality_requires_same_index() {
        let a = ViewerPosition::new(1, 0, 0);
        let b = ViewerPosition::new(2, 0, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn equality_requires_same_y_offset() {
        let a = ViewerPosition::new(1, 0, 0);
        let b = ViewerPosition::new(1, 0, -1);
        assert_ne!(a, b);
    }

    #[test]
    fn display_format() {
        let vp = ViewerPosition::new(3, 1, -2);
        assert_eq!(vp.to_string(), "Index = 3, xOffset = 1, yOffset = -2");
    }

    #[test]
    fn zero_position() {
        let vp = ViewerPosition::new(0, 0, 0);
        assert_eq!(vp.index(), 0);
        assert_eq!(vp.x_offset(), 0);
        assert_eq!(vp.y_offset(), 0);
        assert_eq!(vp.to_string(), "Index = 0, xOffset = 0, yOffset = 0");
    }

    #[test]
    fn large_index() {
        let vp = ViewerPosition::new(i128::MAX, 0, 0);
        assert_eq!(vp.index(), i128::MAX);
    }
}
