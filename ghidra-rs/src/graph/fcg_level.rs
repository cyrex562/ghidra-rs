//! Port of `functioncalls.graph.FcgLevel`.

use std::cmp::Ordering;
use std::fmt;

use super::fcg_direction::FcgDirection;

/// A container class that represents a [`FunctionCallGraph`](super::function_call_graph::FunctionCallGraph)
/// level, or row. A level is both the row of the vertex (the number of hops from the source
/// vertex) and the direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FcgLevel {
    /// A 1-based row.
    row: i32,
    direction: FcgDirection,
}

impl FcgLevel {
    /// Java: the static factory `sourceLevel()`.
    pub fn source_level() -> Self {
        Self::new(0, FcgDirection::InAndOut)
    }

    /// Java: `FcgLevel(int distance, FcgDirection direction)`.
    ///
    /// # Panics
    /// Panics if the resulting row would be `0`, or if row `1` is requested with a direction
    /// other than [`FcgDirection::InAndOut`] -- mirroring Java's `IllegalArgumentException`s.
    pub fn new(distance: i32, direction: FcgDirection) -> Self {
        let row = Self::to_row(distance, direction);

        if row == 0 {
            panic!("The FcgLevel uses a 1-based row system");
        }
        if row == 1 && direction != FcgDirection::InAndOut {
            panic!("Row 1 must be FcgDirection.IN_AND_OUT");
        }

        Self { row, direction }
    }

    fn to_row(distance: i32, direction: FcgDirection) -> i32 {
        let one_based = distance + 1;
        if direction == FcgDirection::Out {
            -one_based
        } else {
            one_based
        }
    }

    /// Java: `getRow()`.
    pub fn get_row(&self) -> i32 {
        self.row
    }

    /// Java: `getDistance()`.
    pub fn get_distance(&self) -> i32 {
        self.row.abs() - 1
    }

    /// Java: `getDirection()`.
    pub fn get_direction(&self) -> FcgDirection {
        self.direction
    }

    /// Returns true if this level represents the source level from which all other levels
    /// emanate, which is row 1. Java: `isSource()`.
    pub fn is_source(&self) -> bool {
        self.direction.is_source()
    }

    /// Returns the parent level of this level. The parent of a level has the same direction as
    /// this level, with a distance of one less than this level. Java: `parent()`.
    ///
    /// # Panics
    /// Panics if this is the source level, which is row 1 -- mirroring Java's
    /// `IllegalArgumentException`.
    pub fn parent(&self) -> Self {
        if self.direction == FcgDirection::InAndOut {
            // undefined--we are the parent of all
            panic!("To get the parent of the source level you must use the constructor directly");
        }

        let new_distance = self.get_distance() - 1;
        let new_direction =
            if new_distance == 0 { FcgDirection::InAndOut } else { self.direction };
        Self::new(new_distance, new_direction)
    }

    /// Returns the child level of this level. The child of a level has the same direction as this
    /// level, with a distance of one more than this level. Java: `child()`.
    ///
    /// # Panics
    /// Panics if this is the source level, which is row 1 -- mirroring Java's
    /// `IllegalArgumentException`.
    pub fn child(&self) -> Self {
        if self.direction == FcgDirection::InAndOut {
            // undefined--this node goes in both directions
            panic!("To get the child of the source level you must use the constructor directly");
        }

        self.child_with_direction(self.direction)
    }

    /// Returns true if this level is the immediate predecessor of the given other level.
    ///
    /// The source level is the parent of the first level in either direction. Java:
    /// `isParentOf(FcgLevel)`.
    pub fn is_parent_of(&self, other: &FcgLevel) -> bool {
        if self.is_source() {
            return other.get_distance() == 1;
        }

        if self.direction != other.direction {
            return false;
        }

        // e.g., row 2 - row 1 = 1
        other.get_distance() - self.get_distance() == 1
    }

    /// Returns true if this level is the immediate successor of the given other level. Java:
    /// `isChildOf(FcgLevel)`.
    pub fn is_child_of(&self, other: &FcgLevel) -> bool {
        other.is_parent_of(self)
    }

    /// Returns the child level of this level, in the given direction. The child of a level has
    /// the same direction as this level, with a distance of one more than this level. Java:
    /// `child(FcgDirection)`.
    ///
    /// # Panics
    /// Panics if `new_direction` is [`FcgDirection::InAndOut`] -- mirroring Java's
    /// `IllegalArgumentException`.
    pub fn child_with_direction(&self, new_direction: FcgDirection) -> Self {
        if new_direction == FcgDirection::InAndOut {
            // undefined--IN_AND_OUT goes in both directions
            panic!("Direction cannot be IN_AND_OUT");
        }

        let new_distance = self.get_distance() + 1;
        Self::new(new_distance, new_direction)
    }

    /// Returns the row of this vertex, relative to direction (negative for [`FcgDirection::Out`]).
    fn get_relative_row(&self) -> i32 {
        if self.direction == FcgDirection::Out {
            -self.row
        } else {
            self.row
        }
    }
}

impl fmt::Display for FcgLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} - row {}", self.direction, self.get_relative_row())
    }
}

impl PartialOrd for FcgLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FcgLevel {
    /// Java: `compareTo(FcgLevel)`: direction first (In on top; Out on bottom), then row.
    fn cmp(&self, other: &Self) -> Ordering {
        let result = self.get_direction().cmp(&other.get_direction());
        if result != Ordering::Equal {
            return result;
        }

        // same direction, use row
        (other.get_relative_row() - self.get_relative_row()).cmp(&0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_level_is_row_one_in_and_out() {
        let s = FcgLevel::source_level();
        assert_eq!(s.get_row(), 1);
        assert_eq!(s.get_distance(), 0);
        assert_eq!(s.get_direction(), FcgDirection::InAndOut);
        assert!(s.is_source());
    }

    #[test]
    fn new_computes_row_from_distance_and_direction() {
        let in2 = FcgLevel::new(1, FcgDirection::In);
        assert_eq!(in2.get_row(), 2);
        assert!(matches!(in2.get_direction(), FcgDirection::In));

        let in3 = FcgLevel::new(2, FcgDirection::In);
        assert_eq!(in3.get_row(), 3);

        let out1 = FcgLevel::new(0, FcgDirection::Out);
        assert_eq!(out1.get_row(), -1);

        let out2 = FcgLevel::new(1, FcgDirection::Out);
        assert_eq!(out2.get_row(), -2);
    }

    #[test]
    #[should_panic(expected = "Row 1 must be FcgDirection.IN_AND_OUT")]
    fn new_rejects_row_one_with_non_source_direction() {
        // distance 0 + In produces row 1, which Java's constructor restricts to IN_AND_OUT only.
        FcgLevel::new(0, FcgDirection::In);
    }

    #[test]
    fn get_distance_is_absolute_value_of_row_minus_one() {
        let l = FcgLevel::new(4, FcgDirection::In);
        assert_eq!(l.get_distance(), 4);
        let l = FcgLevel::new(4, FcgDirection::Out);
        assert_eq!(l.get_distance(), 4);
    }

    #[test]
    fn parent_reduces_distance_by_one_and_collapses_to_source_at_zero() {
        let l = FcgLevel::new(1, FcgDirection::In);
        let p = l.parent();
        assert_eq!(p, FcgLevel::source_level());

        let l2 = FcgLevel::new(2, FcgDirection::Out);
        let p2 = l2.parent();
        assert_eq!(p2.get_distance(), 1);
        assert_eq!(p2.get_direction(), FcgDirection::Out);
    }

    #[test]
    #[should_panic(expected = "must use the constructor directly")]
    fn parent_of_source_panics() {
        FcgLevel::source_level().parent();
    }

    #[test]
    #[should_panic(expected = "must use the constructor directly")]
    fn child_of_source_panics() {
        FcgLevel::source_level().child();
    }

    #[test]
    fn child_increases_distance_and_keeps_direction() {
        let l = FcgLevel::new(1, FcgDirection::In);
        let c = l.child();
        assert_eq!(c.get_distance(), 2);
        assert_eq!(c.get_direction(), FcgDirection::In);
    }

    #[test]
    #[should_panic(expected = "Direction cannot be IN_AND_OUT")]
    fn child_with_direction_rejects_in_and_out() {
        FcgLevel::new(1, FcgDirection::In).child_with_direction(FcgDirection::InAndOut);
    }

    #[test]
    fn is_parent_of_source_checks_distance_one() {
        let source = FcgLevel::source_level();
        let child_in = FcgLevel::new(1, FcgDirection::In);
        let child_out = FcgLevel::new(1, FcgDirection::Out);
        assert!(source.is_parent_of(&child_in));
        assert!(source.is_parent_of(&child_out));

        let grandchild = FcgLevel::new(2, FcgDirection::In);
        assert!(!source.is_parent_of(&grandchild));
    }

    #[test]
    fn is_parent_of_requires_same_direction_and_adjacent_distance() {
        let row2 = FcgLevel::new(2, FcgDirection::In);
        let row3 = FcgLevel::new(3, FcgDirection::In);
        assert!(row2.is_parent_of(&row3));
        assert!(!row3.is_parent_of(&row2));

        let row3_out = FcgLevel::new(3, FcgDirection::Out);
        assert!(!row2.is_parent_of(&row3_out));
    }

    #[test]
    fn is_child_of_is_the_inverse_of_is_parent_of() {
        let row2 = FcgLevel::new(2, FcgDirection::In);
        let row3 = FcgLevel::new(3, FcgDirection::In);
        assert!(row3.is_child_of(&row2));
        assert!(!row2.is_child_of(&row3));
    }

    #[test]
    fn equality_and_hash_consider_row_and_direction() {
        let a = FcgLevel::new(2, FcgDirection::In);
        let b = FcgLevel::new(2, FcgDirection::In);
        let c = FcgLevel::new(2, FcgDirection::Out);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn ordering_puts_in_above_in_and_out_above_out_and_orders_rows_descending_within_direction() {
        let in_near = FcgLevel::new(1, FcgDirection::In); // row 2
        let in_far = FcgLevel::new(2, FcgDirection::In); // row 3
        let source = FcgLevel::source_level(); // row 1, IN_AND_OUT
        let out_near = FcgLevel::new(1, FcgDirection::Out); // row -2

        // Within the same direction, larger relative row sorts first (descending).
        assert!(in_far < in_near);
        assert_eq!(in_near.cmp(&in_near), Ordering::Equal);

        // Direction ordering matches FcgDirection's own derived Ord (In, InAndOut, Out).
        let mut levels = vec![out_near, in_near, source, in_far];
        levels.sort();
        assert_eq!(levels, vec![in_far, in_near, source, out_near]);
    }

    #[test]
    fn display_matches_direction_and_relative_row() {
        // For FcgDirection::Out the internal row is negative, but getRelativeRow() negates it
        // back to a positive display value.
        let l = FcgLevel::new(1, FcgDirection::Out);
        assert_eq!(l.get_row(), -2);
        let s = l.to_string();
        assert!(s.contains("row 2"));
    }
}
