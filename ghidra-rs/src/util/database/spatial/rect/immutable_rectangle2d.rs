use std::fmt;
use std::hash::{Hash, Hasher};

use super::euclidean_space2d::EuclideanSpace2D;

/// An immutable 2D axis-aligned rectangle that carries its own coordinate-space reference.
///
/// Corresponds to `ghidra.util.database.spatial.rect.ImmutableRectangle2D`.
///
/// The Java source is an abstract class; in Rust it becomes a concrete struct whose
/// fields are owned by the value. Concrete rectangle types either wrap this struct or
/// replicate its field layout. Coordinate ordering is enforced in debug builds via
/// `debug_assert!` matching the Java `assert` statements.
pub struct ImmutableRectangle2D<S: EuclideanSpace2D> {
    /// Lower X bound (inclusive).
    pub x1: S::X,
    /// Upper X bound (inclusive).
    pub x2: S::X,
    /// Lower Y bound (inclusive).
    pub y1: S::Y,
    /// Upper Y bound (inclusive).
    pub y2: S::Y,
    /// The coordinate space that defines ordering and distance operations.
    pub space: S,
}

impl<S: EuclideanSpace2D> ImmutableRectangle2D<S> {
    /// Creates a new rectangle.
    ///
    /// # Panics (debug only)
    ///
    /// Panics if `x1 > x2` or `y1 > y2` according to the space's ordering, mirroring
    /// the Java `assert` statements in the constructor.
    pub fn new(x1: S::X, x2: S::X, y1: S::Y, y2: S::Y, space: S) -> Self {
        use std::cmp::Ordering;
        debug_assert!(
            space.compare_x(&x1, &x2) != Ordering::Greater,
            "x1 must be <= x2"
        );
        debug_assert!(
            space.compare_y(&y1, &y2) != Ordering::Greater,
            "y1 must be <= y2"
        );
        Self { x1, x2, y1, y2, space }
    }

    /// Returns the lower X bound.
    pub fn get_x1(&self) -> &S::X {
        &self.x1
    }

    /// Returns the upper X bound.
    pub fn get_x2(&self) -> &S::X {
        &self.x2
    }

    /// Returns the lower Y bound.
    pub fn get_y1(&self) -> &S::Y {
        &self.y1
    }

    /// Returns the upper Y bound.
    pub fn get_y2(&self) -> &S::Y {
        &self.y2
    }

    /// Returns a reference to the coordinate space.
    pub fn get_space(&self) -> &S {
        &self.space
    }

    /// Returns the display string. Mirrors `Rectangle2D.description()` / `toString()`.
    pub fn description(&self) -> String
    where
        S::X: fmt::Display,
        S::Y: fmt::Display,
    {
        self.to_string()
    }
}

impl<S> fmt::Display for ImmutableRectangle2D<S>
where
    S: EuclideanSpace2D,
    S::X: fmt::Display,
    S::Y: fmt::Display,
{
    /// Mirrors `ImmutableRectangle2D.toString()`:
    /// `"rect[x1-x2]x[y1-y2]"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rect[{}-{}]x[{}-{}]", self.x1, self.x2, self.y1, self.y2)
    }
}

impl<S> fmt::Debug for ImmutableRectangle2D<S>
where
    S: EuclideanSpace2D,
    S::X: fmt::Display,
    S::Y: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<S> PartialEq for ImmutableRectangle2D<S>
where
    S: EuclideanSpace2D,
    S::X: PartialEq,
    S::Y: PartialEq,
{
    /// Mirrors `Rectangle2D.doEquals`: compares all four coordinate fields,
    /// ignoring the space instance.
    fn eq(&self, other: &Self) -> bool {
        self.x1 == other.x1
            && self.x2 == other.x2
            && self.y1 == other.y1
            && self.y2 == other.y2
    }
}

impl<S> Eq for ImmutableRectangle2D<S>
where
    S: EuclideanSpace2D,
    S::X: Eq,
    S::Y: Eq,
{
}

impl<S> Hash for ImmutableRectangle2D<S>
where
    S: EuclideanSpace2D,
    S::X: Hash,
    S::Y: Hash,
{
    /// Mirrors `Rectangle2D.doHashCode`: hashes the four coordinate fields in
    /// declaration order, matching `Objects.hash(x1, x2, y1, y2)` semantics.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.x1.hash(state);
        self.x2.hash(state);
        self.y1.hash(state);
        self.y2.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use super::*;

    // ── Minimal test space ────────────────────────────────────────────────────

    struct FullRect;

    #[derive(Clone)]
    struct IntSpace;

    impl EuclideanSpace2D for IntSpace {
        type X = i64;
        type Y = i64;
        type Rect = FullRect;

        fn compare_x(&self, x1: &i64, x2: &i64) -> Ordering {
            x1.cmp(x2)
        }
        fn compare_y(&self, y1: &i64, y2: &i64) -> Ordering {
            y1.cmp(y2)
        }
        fn dist_x(&self, x1: &i64, x2: &i64) -> f64 {
            (x2 - x1).unsigned_abs() as f64
        }
        fn dist_y(&self, y1: &i64, y2: &i64) -> f64 {
            (y2 - y1).unsigned_abs() as f64
        }
        fn mid_x(&self, x1: &i64, x2: &i64) -> i64 {
            x1 + (x2 - x1) / 2
        }
        fn mid_y(&self, y1: &i64, y2: &i64) -> i64 {
            y1 + (y2 - y1) / 2
        }
        fn get_full(&self) -> FullRect {
            FullRect
        }
    }

    fn make(x1: i64, x2: i64, y1: i64, y2: i64) -> ImmutableRectangle2D<IntSpace> {
        ImmutableRectangle2D::new(x1, x2, y1, y2, IntSpace)
    }

    fn hash_of(r: &ImmutableRectangle2D<IntSpace>) -> u64 {
        let mut h = DefaultHasher::new();
        r.hash(&mut h);
        h.finish()
    }

    // ── Field accessors ───────────────────────────────────────────────────────

    #[test]
    fn get_x1_returns_stored_value() {
        let r = make(1, 5, 2, 6);
        assert_eq!(r.get_x1(), &1);
    }

    #[test]
    fn get_x2_returns_stored_value() {
        let r = make(1, 5, 2, 6);
        assert_eq!(r.get_x2(), &5);
    }

    #[test]
    fn get_y1_returns_stored_value() {
        let r = make(1, 5, 2, 6);
        assert_eq!(r.get_y1(), &2);
    }

    #[test]
    fn get_y2_returns_stored_value() {
        let r = make(1, 5, 2, 6);
        assert_eq!(r.get_y2(), &6);
    }

    // ── Display / description ─────────────────────────────────────────────────

    #[test]
    fn display_formats_correctly() {
        let r = make(1, 5, 2, 6);
        assert_eq!(r.to_string(), "rect[1-5]x[2-6]");
    }

    #[test]
    fn display_negative_coords() {
        let r = make(-3, -1, -10, 0);
        assert_eq!(r.to_string(), "rect[-3--1]x[-10-0]");
    }

    #[test]
    fn display_degenerate_point_rect() {
        let r = make(4, 4, 7, 7);
        assert_eq!(r.to_string(), "rect[4-4]x[7-7]");
    }

    #[test]
    fn description_matches_to_string() {
        let r = make(0, 10, 0, 20);
        assert_eq!(r.description(), r.to_string());
    }

    // ── PartialEq ─────────────────────────────────────────────────────────────

    #[test]
    fn equal_when_all_coords_match() {
        assert_eq!(make(1, 5, 2, 6), make(1, 5, 2, 6));
    }

    #[test]
    fn not_equal_when_x1_differs() {
        assert_ne!(make(0, 5, 2, 6), make(1, 5, 2, 6));
    }

    #[test]
    fn not_equal_when_x2_differs() {
        assert_ne!(make(1, 4, 2, 6), make(1, 5, 2, 6));
    }

    #[test]
    fn not_equal_when_y1_differs() {
        assert_ne!(make(1, 5, 0, 6), make(1, 5, 2, 6));
    }

    #[test]
    fn not_equal_when_y2_differs() {
        assert_ne!(make(1, 5, 2, 5), make(1, 5, 2, 6));
    }

    // ── Hash ──────────────────────────────────────────────────────────────────

    #[test]
    fn equal_rects_have_same_hash() {
        let a = make(1, 5, 2, 6);
        let b = make(1, 5, 2, 6);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn different_rects_unlikely_to_share_hash() {
        let a = make(1, 5, 2, 6);
        let b = make(0, 5, 2, 6);
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    // ── Constructor ordering assertions (debug builds only) ───────────────────

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn panics_when_x1_greater_than_x2() {
        make(5, 1, 0, 10);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn panics_when_y1_greater_than_y2() {
        make(0, 5, 10, 0);
    }

    #[test]
    fn degenerate_point_rect_is_valid() {
        // x1 == x2 and y1 == y2 must not panic
        let r = make(3, 3, 7, 7);
        assert_eq!(r.get_x1(), &3);
        assert_eq!(r.get_y1(), &7);
    }
}
