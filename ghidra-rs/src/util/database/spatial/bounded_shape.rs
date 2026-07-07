/// A shape that can report its bounding shape.
///
/// Corresponds to `ghidra.util.database.spatial.BoundedShape`.
///
/// In the Java source `S` is bounded by `BoundingShape<S>`, but since
/// [`BoundingShape`] extends `BoundedShape` the two traits form a cycle.
/// The bound is intentionally omitted here and enforced at the call site
/// (or re-added once `BoundingShape` is ported).
pub trait BoundedShape<S> {
    /// Returns the bounding shape that encloses this shape.
    fn get_bounds(&self) -> S;

    /// Returns a human-readable description of this shape.
    fn description(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal bounding-box type used only in tests.
    #[derive(Debug, Clone, PartialEq)]
    struct Rect {
        x: f64,
        y: f64,
        w: f64,
        h: f64,
    }

    /// A point that is bounded by the smallest enclosing `Rect`.
    struct Point {
        x: f64,
        y: f64,
    }

    impl BoundedShape<Rect> for Point {
        fn get_bounds(&self) -> Rect {
            Rect { x: self.x, y: self.y, w: 0.0, h: 0.0 }
        }

        fn description(&self) -> String {
            format!("Point({}, {})", self.x, self.y)
        }
    }

    #[test]
    fn get_bounds_returns_enclosing_rect() {
        let p = Point { x: 3.0, y: 4.0 };
        let b = p.get_bounds();
        assert_eq!(b, Rect { x: 3.0, y: 4.0, w: 0.0, h: 0.0 });
    }

    #[test]
    fn description_returns_human_readable_string() {
        let p = Point { x: 1.5, y: 2.5 };
        assert_eq!(p.description(), "Point(1.5, 2.5)");
    }

    /// A shape that is its own bounding box.
    impl BoundedShape<Rect> for Rect {
        fn get_bounds(&self) -> Rect {
            self.clone()
        }

        fn description(&self) -> String {
            format!("Rect(x={}, y={}, w={}, h={})", self.x, self.y, self.w, self.h)
        }
    }

    #[test]
    fn rect_bounds_is_self() {
        let r = Rect { x: 0.0, y: 0.0, w: 10.0, h: 5.0 };
        assert_eq!(r.get_bounds(), r);
    }

    #[test]
    fn rect_description() {
        let r = Rect { x: 1.0, y: 2.0, w: 3.0, h: 4.0 };
        assert_eq!(r.description(), "Rect(x=1, y=2, w=3, h=4)");
    }
}
