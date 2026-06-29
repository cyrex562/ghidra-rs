/// Describes the available selection tracking states for Ghidra tables.
///
/// By default Ghidra tables try to track the selected element even if its row
/// changes. Some applications prefer different behaviour — for example keeping
/// the same row index selected rather than following the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TableSelectionTrackingState {
    /// Tracks the user's selected row *value* across sorting changes.
    ///
    /// When the table is re-sorted the same logical element stays selected even
    /// if it moves to a different row index.
    MaintainSelectedRowValue,

    /// Tracks the selected row *index* rather than the value.
    ///
    /// The same row position stays selected even when the value at that
    /// position changes.
    MaintainSelectedRowIndex,

    /// No selection tracking takes place.
    ///
    /// When a selection is lost the table makes no attempt to restore it.
    NoSelectionTracking,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(
            TableSelectionTrackingState::MaintainSelectedRowValue,
            TableSelectionTrackingState::MaintainSelectedRowIndex,
        );
        assert_ne!(
            TableSelectionTrackingState::MaintainSelectedRowIndex,
            TableSelectionTrackingState::NoSelectionTracking,
        );
        assert_ne!(
            TableSelectionTrackingState::MaintainSelectedRowValue,
            TableSelectionTrackingState::NoSelectionTracking,
        );
    }

    #[test]
    fn copy_and_clone() {
        let a = TableSelectionTrackingState::MaintainSelectedRowValue;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.clone(), b);
    }

    #[test]
    fn debug_is_available() {
        let s = format!("{:?}", TableSelectionTrackingState::NoSelectionTracking);
        assert_eq!(s, "NoSelectionTracking");
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = TableSelectionTrackingState::MaintainSelectedRowIndex;
        let b = TableSelectionTrackingState::MaintainSelectedRowIndex;
        assert_eq!(a, b);

        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        a.hash(&mut h1);
        b.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}
