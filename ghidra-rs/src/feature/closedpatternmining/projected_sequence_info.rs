/// Records the index of a sequence in a database and the index of the first character after the
/// prefix sequence (see `ProjectedDatabase`).
///
/// Mirrors `ghidra.closedpatternmining.ProjectedSequenceInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectedSequenceInfo {
    sequence_index: i32,
    projected_index: i32,
}

impl ProjectedSequenceInfo {
    /// Create a new [`ProjectedSequenceInfo`].
    ///
    /// - `sequence_index`: index of a sequence in the database.
    /// - `projected_index`: index in the sequence of the first character after the projection prefix.
    pub fn new(sequence_index: i32, projected_index: i32) -> Self {
        Self {
            sequence_index,
            projected_index,
        }
    }

    /// Returns the sequence index.
    pub fn get_sequence_index(&self) -> i32 {
        self.sequence_index
    }

    /// Returns the projected index.
    pub fn get_projected_index(&self) -> i32 {
        self.projected_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_both_indices() {
        let info = ProjectedSequenceInfo::new(3, 7);
        assert_eq!(info.get_sequence_index(), 3);
        assert_eq!(info.get_projected_index(), 7);
    }

    #[test]
    fn zero_indices() {
        let info = ProjectedSequenceInfo::new(0, 0);
        assert_eq!(info.get_sequence_index(), 0);
        assert_eq!(info.get_projected_index(), 0);
    }

    #[test]
    fn clone_and_copy() {
        let a = ProjectedSequenceInfo::new(1, 2);
        let b = a;
        assert_eq!(a, b);
        let c = a.clone();
        assert_eq!(a, c);
    }

    #[test]
    fn equality() {
        let a = ProjectedSequenceInfo::new(5, 10);
        let b = ProjectedSequenceInfo::new(5, 10);
        let c = ProjectedSequenceInfo::new(5, 11);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn debug_format() {
        let info = ProjectedSequenceInfo::new(1, 2);
        let s = format!("{:?}", info);
        assert!(s.contains("sequence_index: 1"));
        assert!(s.contains("projected_index: 2"));
    }
}
