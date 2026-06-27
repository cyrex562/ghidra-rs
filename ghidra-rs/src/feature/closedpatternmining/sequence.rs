use super::sequence_item::SequenceItem;

/// A string of characters with a count representing the number of occurrences in a database.
///
/// Mirrors `ghidra.closedpatternmining.Sequence`.
pub struct Sequence {
    sequence: String,
    count: i32,
}

impl Sequence {
    /// Creates a new [`Sequence`].
    ///
    /// - `sequence`: the character string.
    /// - `count`: number of times the sequence occurs in the database.
    pub fn new(sequence: String, count: i32) -> Self {
        Self { sequence, count }
    }

    /// Returns the sequence string.
    pub fn get_sequence_as_string(&self) -> &str {
        &self.sequence
    }

    /// Returns the number of times the sequence occurs in the database.
    pub fn get_count(&self) -> i32 {
        self.count
    }

    /// Returns the index immediately after the last item in `prefix_sequence` if the prefix
    /// matches `self.sequence` at every item's declared index position.
    ///
    /// Returns `0` for a `None` or empty prefix. Returns `-1` if the prefix does not match
    /// (out-of-bounds index or symbol mismatch).
    ///
    /// `prefix_sequence` must be sorted in ascending order of `SequenceItem::get_index`.
    pub fn get_index_after_first_instance(&self, prefix_sequence: Option<&[SequenceItem]>) -> i32 {
        let items = match prefix_sequence {
            None | Some([]) => return 0,
            Some(s) => s,
        };

        let seq_chars: Vec<char> = self.sequence.chars().collect();
        let seq_len = seq_chars.len() as i32;
        let mut index: i32 = 0;

        for item in items {
            if item.get_index() + 1 > seq_len {
                return -1;
            }
            let ch = seq_chars[item.get_index() as usize].to_string();
            if ch != item.get_symbol() {
                return -1;
            }
            index = item.get_index() + 1;
        }

        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_item(symbol: &str, index: i32) -> SequenceItem {
        SequenceItem::new(symbol, index)
    }

    #[test]
    fn constructor_and_accessors() {
        let seq = Sequence::new("ABC".to_owned(), 5);
        assert_eq!(seq.get_sequence_as_string(), "ABC");
        assert_eq!(seq.get_count(), 5);
    }

    #[test]
    fn none_prefix_returns_zero() {
        let seq = Sequence::new("ABC".to_owned(), 1);
        assert_eq!(seq.get_index_after_first_instance(None), 0);
    }

    #[test]
    fn empty_prefix_returns_zero() {
        let seq = Sequence::new("ABC".to_owned(), 1);
        assert_eq!(seq.get_index_after_first_instance(Some(&[])), 0);
    }

    #[test]
    fn matching_single_item_prefix() {
        let seq = Sequence::new("ABC".to_owned(), 1);
        let prefix = vec![make_item("A", 0)];
        assert_eq!(seq.get_index_after_first_instance(Some(&prefix)), 1);
    }

    #[test]
    fn matching_full_prefix() {
        let seq = Sequence::new("ABCD".to_owned(), 1);
        let prefix = vec![make_item("A", 0), make_item("B", 1), make_item("C", 2)];
        assert_eq!(seq.get_index_after_first_instance(Some(&prefix)), 3);
    }

    #[test]
    fn matching_sparse_prefix() {
        // prefix checks index 0 and index 2 only
        let seq = Sequence::new("ABCD".to_owned(), 1);
        let prefix = vec![make_item("A", 0), make_item("C", 2)];
        assert_eq!(seq.get_index_after_first_instance(Some(&prefix)), 3);
    }

    #[test]
    fn symbol_mismatch_returns_minus_one() {
        let seq = Sequence::new("ABC".to_owned(), 1);
        let prefix = vec![make_item("X", 0)];
        assert_eq!(seq.get_index_after_first_instance(Some(&prefix)), -1);
    }

    #[test]
    fn out_of_bounds_index_returns_minus_one() {
        let seq = Sequence::new("AB".to_owned(), 1);
        // index 2 + 1 = 3 > seq.len() (2) → -1
        let prefix = vec![make_item("X", 2)];
        assert_eq!(seq.get_index_after_first_instance(Some(&prefix)), -1);
    }

    #[test]
    fn second_item_mismatch_returns_minus_one() {
        let seq = Sequence::new("ABCD".to_owned(), 1);
        let prefix = vec![make_item("A", 0), make_item("X", 1)];
        assert_eq!(seq.get_index_after_first_instance(Some(&prefix)), -1);
    }

    #[test]
    fn prefix_exactly_fills_sequence() {
        let seq = Sequence::new("AB".to_owned(), 1);
        let prefix = vec![make_item("A", 0), make_item("B", 1)];
        assert_eq!(seq.get_index_after_first_instance(Some(&prefix)), 2);
    }

    #[test]
    fn empty_sequence_with_nonempty_prefix_returns_minus_one() {
        let seq = Sequence::new("".to_owned(), 0);
        let prefix = vec![make_item("A", 0)];
        assert_eq!(seq.get_index_after_first_instance(Some(&prefix)), -1);
    }
}
