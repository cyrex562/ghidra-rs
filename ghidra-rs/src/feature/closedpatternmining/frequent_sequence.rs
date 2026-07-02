use super::sequence_item::SequenceItem;

/// A frequent sequence with a list of items and its support.
///
/// Represents a sequence that occurs frequently in the data, tracking the sequence
/// of items and how many times it appears (support).
///
/// Mirrors `ghidra.closedpatternmining.FrequentSequence`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FrequentSequence {
    sequence: Vec<SequenceItem>,
    support: i32,
}

impl FrequentSequence {
    /// Creates a new [`FrequentSequence`] with the given sequence and support.
    pub fn new(sequence: Vec<SequenceItem>, support: i32) -> Self {
        Self { sequence, support }
    }

    /// Returns the sequence.
    pub fn get_sequence(&self) -> &[SequenceItem] {
        &self.sequence
    }

    /// Returns the support.
    pub fn get_support(&self) -> i32 {
        self.support
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_sequence_and_support() {
        let items = vec![SequenceItem::new("A", 0), SequenceItem::new("B", 1)];
        let fs = FrequentSequence::new(items.clone(), 5);
        assert_eq!(fs.get_sequence(), items.as_slice());
        assert_eq!(fs.get_support(), 5);
    }

    #[test]
    fn equality_requires_same_sequence_and_support() {
        let items = vec![SequenceItem::new("A", 0), SequenceItem::new("B", 1)];
        let fs1 = FrequentSequence::new(items.clone(), 5);
        let fs2 = FrequentSequence::new(items.clone(), 5);
        assert_eq!(fs1, fs2);
    }

    #[test]
    fn inequality_on_different_support() {
        let items = vec![SequenceItem::new("A", 0), SequenceItem::new("B", 1)];
        let fs1 = FrequentSequence::new(items.clone(), 5);
        let fs2 = FrequentSequence::new(items.clone(), 6);
        assert_ne!(fs1, fs2);
    }

    #[test]
    fn inequality_on_different_sequence() {
        let items1 = vec![SequenceItem::new("A", 0), SequenceItem::new("B", 1)];
        let items2 = vec![SequenceItem::new("A", 0), SequenceItem::new("C", 1)];
        let fs1 = FrequentSequence::new(items1, 5);
        let fs2 = FrequentSequence::new(items2, 5);
        assert_ne!(fs1, fs2);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;

        let items = vec![SequenceItem::new("A", 0), SequenceItem::new("B", 1)];
        let fs1 = FrequentSequence::new(items.clone(), 5);
        let fs2 = FrequentSequence::new(items.clone(), 5);

        let mut set = HashSet::new();
        set.insert(fs1);
        assert!(set.contains(&fs2));
    }

    #[test]
    fn clone_creates_independent_copy() {
        let items = vec![SequenceItem::new("A", 0)];
        let fs1 = FrequentSequence::new(items, 3);
        let fs2 = fs1.clone();
        assert_eq!(fs1, fs2);
    }

    #[test]
    fn debug_format() {
        let items = vec![SequenceItem::new("X", 0)];
        let fs = FrequentSequence::new(items, 7);
        let debug_str = format!("{:?}", fs);
        assert!(debug_str.contains("FrequentSequence"));
        assert!(debug_str.contains("sequence"));
        assert!(debug_str.contains("support"));
    }

    #[test]
    fn empty_sequence() {
        let fs = FrequentSequence::new(vec![], 0);
        assert_eq!(fs.get_sequence().len(), 0);
        assert_eq!(fs.get_support(), 0);
    }

    #[test]
    fn single_item_sequence() {
        let items = vec![SequenceItem::new("Z", 10)];
        let fs = FrequentSequence::new(items, 1);
        assert_eq!(fs.get_sequence().len(), 1);
        assert_eq!(fs.get_support(), 1);
    }
}
