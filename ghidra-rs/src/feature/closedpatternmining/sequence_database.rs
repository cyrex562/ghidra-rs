use std::collections::{BTreeSet, HashMap};

use super::frequent_sequence_item::FrequentSequenceItem;
use super::sequence::Sequence;
use super::sequence_item::SequenceItem;

/// The collection of sequences to be mined.
///
/// Mirrors `ghidra.closedpatternmining.SequenceDatabase`.
pub struct SequenceDatabase {
    sequence_length: i32,
    sequences: Vec<Sequence>,
    total_num_seqs: i32,
}

impl SequenceDatabase {
    /// Creates a new [`SequenceDatabase`].
    ///
    /// - `sequences_to_mine`: the sequences to mine for closed patterns.
    /// - `sequence_length`: all sequences in the database must be of this length.
    ///
    /// # Panics
    /// Panics if `sequence_length` is not positive, or if any sequence's string does not have
    /// length `sequence_length`.
    pub fn new(sequences_to_mine: Vec<Sequence>, sequence_length: i32) -> Self {
        if sequence_length < 1 {
            panic!("length must be positive!");
        }

        let mut total_num_seqs = 0;
        for seq in &sequences_to_mine {
            if seq.get_sequence_as_string().chars().count() as i32 != sequence_length {
                panic!(
                    "sequence {} does not have length {}",
                    seq.get_sequence_as_string(),
                    sequence_length
                );
            }
            total_num_seqs += seq.get_count();
        }

        Self {
            sequence_length,
            sequences: sequences_to_mine,
            total_num_seqs,
        }
    }

    /// Returns the length of a sequence in the database (all sequences in a database must have
    /// the same length).
    pub fn get_sequence_length(&self) -> i32 {
        self.sequence_length
    }

    /// Returns the sequences in the database.
    pub fn get_sequences(&self) -> &[Sequence] {
        &self.sequences
    }

    /// Returns the total number of sequences in the database.
    pub fn get_total_num_seqs(&self) -> i32 {
        self.total_num_seqs
    }

    /// Returns the set of all items occurring in at least `min_support` sequences in the
    /// database.
    pub fn get_globally_frequent_items(&self, min_support: i32) -> BTreeSet<FrequentSequenceItem> {
        let mut item_bag: HashMap<SequenceItem, i32> = HashMap::new();
        let mut frequent_item_set: BTreeSet<FrequentSequenceItem> = BTreeSet::new();

        // count all items
        for seq in &self.sequences {
            let seq_chars: Vec<char> = seq.get_sequence_as_string().chars().collect();
            for i in 0..self.sequence_length as usize {
                let symbol = seq_chars[i].to_string();
                let f_item = SequenceItem::new(&symbol, i as i32);
                *item_bag.entry(f_item).or_insert(0) += seq.get_count();
            }
        }

        // iterate through item_bag and save the frequent items
        for (item, count) in item_bag {
            if count >= min_support {
                frequent_item_set.insert(FrequentSequenceItem::new(count, item));
            }
        }
        frequent_item_set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_and_accessors() {
        let seqs = vec![Sequence::new("AB".to_owned(), 2), Sequence::new("CD".to_owned(), 3)];
        let db = SequenceDatabase::new(seqs, 2);
        assert_eq!(db.get_sequence_length(), 2);
        assert_eq!(db.get_sequences().len(), 2);
        assert_eq!(db.get_total_num_seqs(), 5);
    }

    #[test]
    #[should_panic(expected = "length must be positive")]
    fn new_panics_on_zero_length() {
        SequenceDatabase::new(Vec::new(), 0);
    }

    #[test]
    #[should_panic(expected = "length must be positive")]
    fn new_panics_on_negative_length() {
        SequenceDatabase::new(Vec::new(), -1);
    }

    #[test]
    #[should_panic(expected = "does not have length")]
    fn new_panics_on_mismatched_sequence_length() {
        let seqs = vec![Sequence::new("ABC".to_owned(), 1)];
        SequenceDatabase::new(seqs, 2);
    }

    #[test]
    fn empty_database() {
        let db = SequenceDatabase::new(Vec::new(), 3);
        assert_eq!(db.get_total_num_seqs(), 0);
        assert!(db.get_sequences().is_empty());
    }

    #[test]
    fn globally_frequent_items_counts_across_sequences() {
        let seqs = vec![
            Sequence::new("AB".to_owned(), 2),
            Sequence::new("AC".to_owned(), 3),
        ];
        let db = SequenceDatabase::new(seqs, 2);
        let frequent = db.get_globally_frequent_items(4);

        // "A" at index 0 occurs with total count 5 (2 + 3) -> frequent
        assert!(frequent
            .iter()
            .any(|f| f.get_item().get_symbol() == "A" && f.get_item().get_index() == 0 && f.get_support() == 5));
        // "B" at index 1 has count 2, "C" at index 1 has count 3 -> neither meets min_support 4
        assert!(!frequent.iter().any(|f| f.get_item().get_symbol() == "B"));
        assert!(!frequent.iter().any(|f| f.get_item().get_symbol() == "C"));
        assert_eq!(frequent.len(), 1);
    }

    #[test]
    fn globally_frequent_items_min_support_zero_returns_all() {
        let seqs = vec![Sequence::new("AB".to_owned(), 1)];
        let db = SequenceDatabase::new(seqs, 2);
        let frequent = db.get_globally_frequent_items(0);
        assert_eq!(frequent.len(), 2);
    }

    #[test]
    fn globally_frequent_items_no_sequences() {
        let db = SequenceDatabase::new(Vec::new(), 2);
        let frequent = db.get_globally_frequent_items(1);
        assert!(frequent.is_empty());
    }
}
