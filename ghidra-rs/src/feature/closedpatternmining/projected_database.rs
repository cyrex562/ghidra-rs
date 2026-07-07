use std::collections::{BTreeSet, HashMap, HashSet};

use super::frequent_sequence_item::FrequentSequenceItem;
use super::projected_sequence_info::ProjectedSequenceInfo;
use super::sequence_database::SequenceDatabase;
use super::sequence_item::SequenceItem;

/// Contains all the suffixes of strings in a [`SequenceDatabase`] which have a prefix
/// consistent with a prefix sequence.
///
/// Mirrors `ghidra.closedpatternmining.ProjectedDatabase`.
pub struct ProjectedDatabase<'a> {
    database: &'a SequenceDatabase,
    prefix_sequence: Vec<SequenceItem>,
    projected_info: Vec<ProjectedSequenceInfo>,
    support: i32,
}

impl<'a> ProjectedDatabase<'a> {
    /// Constructs a [`ProjectedDatabase`] given a database and a prefix sequence.
    ///
    /// `prefix_sequence` is assumed to be in ascending order of item index.
    pub fn new(database: &'a SequenceDatabase, prefix_sequence: Vec<SequenceItem>) -> Self {
        let mut projected_info = Vec::new();
        let mut support = 0;
        let sequences = database.get_sequences();

        for (i, seq) in sequences.iter().enumerate() {
            let projected_index = seq.get_index_after_first_instance(Some(&prefix_sequence));
            // if the projection leaves the empty string, record anyway
            if projected_index != -1 {
                projected_info.push(ProjectedSequenceInfo::new(i as i32, projected_index));
                support += seq.get_count();
            }
        }

        Self {
            database,
            prefix_sequence,
            projected_info,
            support,
        }
    }

    /// Given a [`ProjectedDatabase`], constructs a new [`ProjectedDatabase`] by adding one item
    /// to the prefix sequence.
    ///
    /// # Panics
    /// Panics if `extending_item`'s index is not strictly after the index of the last item of
    /// `proj_database`'s prefix sequence, or if `proj_database`'s prefix sequence is empty.
    pub fn from_extension(proj_database: &ProjectedDatabase<'a>, extending_item: SequenceItem) -> Self {
        let initial_list = proj_database.get_prefix();
        let last_item = initial_list
            .last()
            .expect("prefixSequence of projDatabase must not be empty");
        if last_item.get_index() >= extending_item.get_index() {
            panic!(
                "extending item must be after all items of the prefixSequence of projDatabase!"
            );
        }

        let database = proj_database.get_database();

        let mut prefix_sequence = initial_list.to_vec();
        prefix_sequence.push(extending_item.clone());

        let sequences = database.get_sequences();
        let mut projected_info = Vec::new();
        let mut support = 0;
        let index_to_check = extending_item.get_index();
        let symbol_to_find = extending_item.get_symbol();

        for proj_seq in proj_database.get_projected_info() {
            let sequence = &sequences[proj_seq.get_sequence_index() as usize];
            let seq_chars: Vec<char> = sequence.get_sequence_as_string().chars().collect();
            let symbol = seq_chars[index_to_check as usize].to_string();
            if symbol == symbol_to_find {
                support += sequence.get_count();
                let extended_sequence =
                    ProjectedSequenceInfo::new(proj_seq.get_sequence_index(), index_to_check + 1);
                projected_info.push(extended_sequence);
            }
        }

        Self {
            database,
            prefix_sequence,
            projected_info,
            support,
        }
    }

    /// Returns the database.
    pub fn get_database(&self) -> &'a SequenceDatabase {
        self.database
    }

    /// Returns the prefix sequence.
    pub fn get_prefix(&self) -> &[SequenceItem] {
        &self.prefix_sequence
    }

    /// Returns the projection data.
    pub fn get_projected_info(&self) -> &[ProjectedSequenceInfo] {
        &self.projected_info
    }

    /// for testing
    fn get_projected_sequences_as_set(&self) -> HashSet<String> {
        let sequences = self.database.get_sequences();
        let mut projected_seqs = HashSet::new();
        for proj_seq in &self.projected_info {
            let seq = &sequences[proj_seq.get_sequence_index() as usize];
            let seq_chars: Vec<char> = seq.get_sequence_as_string().chars().collect();
            let end = seq_chars.len();
            let begin = std::cmp::min(proj_seq.get_projected_index() as usize, end);
            projected_seqs.insert(seq_chars[begin..end].iter().collect());
        }
        projected_seqs
    }

    /// Returns the number of sequences in the projected database.
    pub fn get_support(&self) -> i32 {
        self.support
    }

    /// Returns the set of [`FrequentSequenceItem`]s composed of all items in
    /// `globally_frequent_items` which occur after the projection index and in at least
    /// `min_support` sequences in the projected database.
    pub fn get_locally_frequent_items(
        &self,
        globally_frequent_items: &BTreeSet<FrequentSequenceItem>,
        min_support: i32,
    ) -> BTreeSet<FrequentSequenceItem> {
        let mut frequent_item_bag: HashMap<SequenceItem, i32> = HashMap::new();
        let sequences = self.database.get_sequences();

        for current_proj_seq in &self.projected_info {
            for glob_freq_item in globally_frequent_items {
                let global_item = glob_freq_item.get_item();
                let index = global_item.get_index();
                if index < current_proj_seq.get_projected_index() {
                    // the globally frequent item is in a position in the prefix, no need to check
                    continue;
                }
                let full_sequence = &sequences[current_proj_seq.get_sequence_index() as usize];
                let seq_chars: Vec<char> = full_sequence.get_sequence_as_string().chars().collect();
                let symbol = seq_chars[index as usize].to_string();

                if symbol != global_item.get_symbol() {
                    // symbols are different, check next item
                    continue;
                }

                *frequent_item_bag.entry(global_item.clone()).or_insert(0) +=
                    full_sequence.get_count();
            }
        }

        let mut frequent_item_set = BTreeSet::new();
        for (item, count) in frequent_item_bag {
            if count >= min_support {
                frequent_item_set.insert(FrequentSequenceItem::new(count, item));
            }
        }
        frequent_item_set
    }

    /// Returns the subset of `locally_frequent_items` which occur in all sequences in the
    /// projected database.
    pub fn get_forward_extension_items(
        &self,
        locally_frequent_items: &BTreeSet<FrequentSequenceItem>,
    ) -> BTreeSet<FrequentSequenceItem> {
        locally_frequent_items
            .iter()
            .filter(|f_item| f_item.get_support() == self.support)
            .cloned()
            .collect()
    }

    /// Computes the set of backward extension items, i.e., any items that could fill empty
    /// spaces in the projected sequence without changing the support.
    ///
    /// For example, if you create a [`ProjectedDatabase`] with the prefix A.C, and all of the
    /// resulting sequences happen to have a B in the second position (i.e. position 1), the
    /// returned set would consist of the [`FrequentSequenceItem`] with `SequenceItem(B, 1)`.
    pub fn get_backward_extension_items(&self) -> BTreeSet<FrequentSequenceItem> {
        let mut backward_extension_items = BTreeSet::new();
        if self.projected_info.is_empty() {
            return backward_extension_items;
        }

        // record what the first sequence has at each ditted position
        let mut positions_to_symbols: HashMap<i32, String> = HashMap::new();
        let mut ditted_position: i32 = 0;
        let sequences = self.database.get_sequences();
        let first_sequence = &sequences[self.projected_info[0].get_sequence_index() as usize];
        let first_seq_chars: Vec<char> = first_sequence.get_sequence_as_string().chars().collect();
        for current_item in &self.prefix_sequence {
            let fixed_position = current_item.get_index();
            while ditted_position < fixed_position {
                let symbol = first_seq_chars[ditted_position as usize].to_string();
                positions_to_symbols.insert(ditted_position, symbol);
                ditted_position += 1;
            }
            ditted_position += 1; // advance past fixedPosition
        }

        // if all of the preceding positions are filled, there can't be any backward
        // extension items
        if positions_to_symbols.is_empty() {
            return backward_extension_items;
        }

        // check the other projected sequences for consistency with the first sequence
        // if there is an inconsistency, that position can't be a backward extension item
        let num_sequences = self.projected_info.len();
        for i in 1..num_sequences {
            let test_sequence = &sequences[self.projected_info[i].get_sequence_index() as usize];
            let test_seq_chars: Vec<char> = test_sequence.get_sequence_as_string().chars().collect();
            let mut positions_to_remove = Vec::new();
            for (&key, stored_value) in &positions_to_symbols {
                let test_value = test_seq_chars[key as usize].to_string();
                if stored_value != &test_value {
                    positions_to_remove.push(key);
                }
            }
            for position in positions_to_remove {
                positions_to_symbols.remove(&position);
            }
            // exit early if we find that there are conflicting choices for all ditted positions
            if positions_to_symbols.is_empty() {
                return backward_extension_items;
            }
        }

        // return the FrequentItems corresponding to all positions which are not specified
        // in the prefix but which nonetheless have the same value for all projected sequences
        for (position, symbol) in &positions_to_symbols {
            let item = SequenceItem::new(symbol, *position);
            let f_item = FrequentSequenceItem::new(self.support, item);
            backward_extension_items.insert(f_item);
        }
        backward_extension_items
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::sequence::Sequence;

    fn make_item(symbol: &str, index: i32) -> SequenceItem {
        SequenceItem::new(symbol, index)
    }

    fn make_database() -> SequenceDatabase {
        let sequences = vec![
            Sequence::new("AAAA".to_owned(), 2),
            Sequence::new("AAAB".to_owned(), 2),
            Sequence::new("AABB".to_owned(), 2),
            Sequence::new("ABBB".to_owned(), 2),
            Sequence::new("BBBB".to_owned(), 2),
        ];
        SequenceDatabase::new(sequences, 4)
    }

    #[test]
    fn project_empty_string_test() {
        let database = make_database();
        let proj_database = ProjectedDatabase::new(&database, Vec::new());
        let projected_strings = proj_database.get_projected_sequences_as_set();
        assert_eq!(proj_database.get_support(), 10);
        assert_eq!(projected_strings.len(), 5);
        assert!(projected_strings.contains("AAAA"));
        assert!(projected_strings.contains("AAAB"));
        assert!(projected_strings.contains("AABB"));
        assert!(projected_strings.contains("ABBB"));
        assert!(projected_strings.contains("BBBB"));
    }

    #[test]
    fn project_single_char_test() {
        let database = make_database();
        let prefix_sequence = vec![make_item("A", 0)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        assert_eq!(proj_database.get_support(), 8);
        let projected_strings = proj_database.get_projected_sequences_as_set();
        assert_eq!(projected_strings.len(), 4);
        assert!(projected_strings.contains("AAA"));
        assert!(projected_strings.contains("AAB"));
        assert!(projected_strings.contains("ABB"));
        assert!(projected_strings.contains("BBB"));
    }

    #[test]
    fn project_double_char_test() {
        let database = make_database();
        let prefix_sequence = vec![make_item("A", 0), make_item("A", 1)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        assert_eq!(proj_database.get_support(), 6);
        let projected_strings = proj_database.get_projected_sequences_as_set();
        assert_eq!(projected_strings.len(), 3);
        assert!(projected_strings.contains("AA"));
        assert!(projected_strings.contains("AB"));
        assert!(projected_strings.contains("BB"));
    }

    #[test]
    fn project_twice_test1() {
        let database = make_database();
        let prefix_sequence = vec![make_item("A", 0)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let extending_item = make_item("A", 1);
        let second_projection = ProjectedDatabase::from_extension(&proj_database, extending_item);
        assert_eq!(second_projection.get_support(), 6);
        let projected_strings = second_projection.get_projected_sequences_as_set();
        assert_eq!(projected_strings.len(), 3);
        assert!(projected_strings.contains("AA"));
        assert!(projected_strings.contains("AB"));
        assert!(projected_strings.contains("BB"));
    }

    #[test]
    fn project_twice_test2() {
        let database = make_database();
        let prefix_sequence = vec![make_item("A", 0)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let extending_item = make_item("A", 2);
        let second_projection = ProjectedDatabase::from_extension(&proj_database, extending_item);
        assert_eq!(second_projection.get_support(), 4);
        let projected_strings = second_projection.get_projected_sequences_as_set();
        assert_eq!(projected_strings.len(), 2);
        assert!(projected_strings.contains("A"));
        assert!(projected_strings.contains("B"));
    }

    #[test]
    fn project_entire_test() {
        let database = make_database();
        let prefix_sequence = vec![
            make_item("A", 0),
            make_item("A", 1),
            make_item("A", 2),
            make_item("A", 3),
        ];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        assert_eq!(proj_database.get_support(), 2);
        let projected_strings = proj_database.get_projected_sequences_as_set();
        assert_eq!(projected_strings.len(), 1);
    }

    #[test]
    fn project_non_occuring_char_test() {
        let database = make_database();
        let prefix_sequence = vec![make_item("C", 0)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        assert_eq!(proj_database.get_support(), 0);
        let projected_strings = proj_database.get_projected_sequences_as_set();
        assert_eq!(projected_strings.len(), 0);
    }

    #[test]
    fn test_locally_frequent_items_basic() {
        let database = make_database();
        let prefix_sequence = vec![make_item("A", 0), make_item("A", 1)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let globally_frequent = database.get_globally_frequent_items(4);
        let locally_frequent = proj_database.get_locally_frequent_items(&globally_frequent, 4);
        assert_eq!(locally_frequent.len(), 2);
        assert!(locally_frequent.contains(&FrequentSequenceItem::new(4, make_item("B", 3))));
        assert!(locally_frequent.contains(&FrequentSequenceItem::new(4, make_item("A", 2))));
    }

    #[test]
    fn test_locally_frequent_items_empty_projected_database() {
        let database = make_database();
        let prefix_sequence = vec![
            make_item("A", 0),
            make_item("A", 1),
            make_item("A", 2),
            make_item("A", 3),
        ];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let globally_frequent = database.get_globally_frequent_items(4);
        let locally_frequent = proj_database.get_locally_frequent_items(&globally_frequent, 4);
        assert_eq!(locally_frequent.len(), 0);
    }

    #[test]
    fn test_locally_frequent_items_dits() {
        let database = make_database();
        let prefix_sequence = vec![make_item("A", 0)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let globally_frequent = database.get_globally_frequent_items(6);
        let locally_frequent = proj_database.get_locally_frequent_items(&globally_frequent, 6);
        assert_eq!(locally_frequent.len(), 2);
        assert!(locally_frequent.contains(&FrequentSequenceItem::new(6, make_item("A", 1))));
        assert!(locally_frequent.contains(&FrequentSequenceItem::new(6, make_item("B", 3))));
    }

    #[test]
    fn test_locally_frequent_items_no_frequent_items() {
        let database = make_database();
        let prefix_sequence = vec![make_item("A", 0), make_item("A", 1)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let globally_frequent = database.get_globally_frequent_items(6);
        let locally_frequent = proj_database.get_locally_frequent_items(&globally_frequent, 6);
        assert_eq!(locally_frequent.len(), 0);
    }

    #[test]
    fn no_forward_extension_items_test() {
        let database = make_database();
        let prefix_sequence = vec![make_item("A", 0)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let globally_frequent = database.get_globally_frequent_items(6);
        let locally_frequent = proj_database.get_locally_frequent_items(&globally_frequent, 6);
        let extension_items = proj_database.get_forward_extension_items(&locally_frequent);
        assert_eq!(extension_items.len(), 0);
    }

    #[test]
    fn test_forward_extension_items() {
        let sequences = vec![
            Sequence::new("CDAAAA".to_owned(), 2),
            Sequence::new("CDAAAB".to_owned(), 2),
            Sequence::new("CDAABB".to_owned(), 2),
            Sequence::new("CDABBB".to_owned(), 2),
            Sequence::new("CDBBBB".to_owned(), 2),
        ];
        let database = SequenceDatabase::new(sequences, 6);
        let prefix_sequence = vec![make_item("C", 0)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let globally_frequent = database.get_globally_frequent_items(6);
        let locally_frequent = proj_database.get_locally_frequent_items(&globally_frequent, 6);
        let extension_items = proj_database.get_forward_extension_items(&locally_frequent);
        assert_eq!(extension_items.len(), 1);
        assert!(extension_items.contains(&FrequentSequenceItem::new(10, make_item("D", 1))));
    }

    #[test]
    fn no_backward_extension_items_test1() {
        let database = make_database();
        let prefix_sequence = vec![make_item("A", 0), make_item("A", 1)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let backward_extension_items = proj_database.get_backward_extension_items();
        assert_eq!(backward_extension_items.len(), 0);
    }

    #[test]
    fn no_backward_extension_items_test2() {
        let sequences = vec![
            Sequence::new("CDAAAA".to_owned(), 2),
            Sequence::new("CDAAAB".to_owned(), 2),
            Sequence::new("CEAABB".to_owned(), 2),
            Sequence::new("CDABBB".to_owned(), 2),
            Sequence::new("CDABBB".to_owned(), 2),
        ];
        let database = SequenceDatabase::new(sequences, 6);
        let prefix_sequence = vec![make_item("C", 0), make_item("A", 2)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let backward_extension_items = proj_database.get_backward_extension_items();
        assert_eq!(backward_extension_items.len(), 0);
    }

    #[test]
    fn simple_backward_extension_item_test1() {
        let sequences = vec![Sequence::new("AA".to_owned(), 2)];
        let database = SequenceDatabase::new(sequences, 2);
        let prefix_sequence = vec![make_item("A", 1)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let backward_extension_items = proj_database.get_backward_extension_items();
        assert_eq!(backward_extension_items.len(), 1);
    }

    #[test]
    fn simple_backward_extension_item_test2() {
        let sequences = vec![Sequence::new("AAA".to_owned(), 2)];
        let database = SequenceDatabase::new(sequences, 3);
        let prefix_sequence = vec![make_item("A", 1)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let backward_extension_items = proj_database.get_backward_extension_items();
        assert_eq!(backward_extension_items.len(), 1);
    }

    #[test]
    fn one_backward_extension_item_test1() {
        let sequences = vec![
            Sequence::new("CDAAAA".to_owned(), 2),
            Sequence::new("CDAAAB".to_owned(), 2),
            Sequence::new("CDAABB".to_owned(), 2),
            Sequence::new("CDABBB".to_owned(), 2),
            Sequence::new("CDABBE".to_owned(), 2),
        ];
        let database = SequenceDatabase::new(sequences, 6);
        let prefix_sequence = vec![make_item("C", 0), make_item("A", 2)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let backward_extension_items = proj_database.get_backward_extension_items();
        assert_eq!(backward_extension_items.len(), 1);
        assert!(backward_extension_items.contains(&FrequentSequenceItem::new(10, make_item("D", 1))));
    }

    #[test]
    fn one_backward_extension_item_test2() {
        let sequences = vec![
            Sequence::new("CAAFBA".to_owned(), 2),
            Sequence::new("CBAGBB".to_owned(), 2),
            Sequence::new("CCAHBB".to_owned(), 2),
            Sequence::new("CDAIBB".to_owned(), 2),
            Sequence::new("CEAJBB".to_owned(), 2),
        ];
        let database = SequenceDatabase::new(sequences, 6);
        let prefix_sequence = vec![make_item("C", 0), make_item("B", 4)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let backward_extension_items = proj_database.get_backward_extension_items();
        assert_eq!(backward_extension_items.len(), 1);
        assert!(backward_extension_items.contains(&FrequentSequenceItem::new(10, make_item("A", 2))));
    }

    #[test]
    fn two_backward_extension_items_test1() {
        let sequences = vec![
            Sequence::new("CABDBA".to_owned(), 2),
            Sequence::new("CABDBB".to_owned(), 2),
            Sequence::new("CABDBI".to_owned(), 2),
            Sequence::new("CABDBJ".to_owned(), 2),
            Sequence::new("CEAJBB".to_owned(), 2),
        ];
        let database = SequenceDatabase::new(sequences, 6);
        let prefix_sequence = vec![make_item("C", 0), make_item("D", 3)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let backward_extension_items = proj_database.get_backward_extension_items();
        assert_eq!(backward_extension_items.len(), 2);
        assert!(backward_extension_items.contains(&FrequentSequenceItem::new(8, make_item("A", 1))));
        assert!(backward_extension_items.contains(&FrequentSequenceItem::new(8, make_item("B", 2))));
    }

    #[test]
    fn three_backward_extension_items_test3() {
        let sequences = vec![
            Sequence::new("CABDBNGA".to_owned(), 2),
            Sequence::new("CAADBNGB".to_owned(), 2),
            Sequence::new("CAADXNGC".to_owned(), 2),
            Sequence::new("CABDBNGD".to_owned(), 2),
            Sequence::new("CEAJBBHE".to_owned(), 2),
        ];
        let database = SequenceDatabase::new(sequences, 8);
        let prefix_sequence = vec![make_item("C", 0), make_item("G", 6)];
        let proj_database = ProjectedDatabase::new(&database, prefix_sequence);
        let backward_extension_items = proj_database.get_backward_extension_items();
        assert_eq!(backward_extension_items.len(), 3);
        assert!(backward_extension_items.contains(&FrequentSequenceItem::new(8, make_item("A", 1))));
        assert!(backward_extension_items.contains(&FrequentSequenceItem::new(8, make_item("D", 3))));
        assert!(backward_extension_items.contains(&FrequentSequenceItem::new(8, make_item("N", 5))));
    }
}
