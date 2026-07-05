use std::collections::{BTreeSet, HashSet};

use crate::util::task::TaskMonitor;

use super::frequent_sequence::FrequentSequence;
use super::frequent_sequence_item::FrequentSequenceItem;
use super::projected_database::ProjectedDatabase;
use super::sequence_database::SequenceDatabase;

/// Mines patterns (i.e., closed sequences) in collections of sequences of bytes.
///
/// Suppose a sequence S occurs n many times in the database. S is closed if no proper
/// supersequence occurs >= n many times in the database.
///
/// The algorithm implemented in this module is based on that in
/// "BIDE: Efficient Mining of Frequent Closed Sequences" by Wang & Han.
///
/// Mirrors `ghidra.closedpatternmining.ClosedSequenceMiner`.
pub struct ClosedSequenceMiner {
    database: SequenceDatabase,
    min_support: i32,
}

impl ClosedSequenceMiner {
    /// Creates a [`ClosedSequenceMiner`] for a particular database.
    ///
    /// - `database`: the database to mine.
    /// - `min_support`: lower bound for the number of sequences a frequent item must occur in.
    pub fn new(database: SequenceDatabase, min_support: i32) -> Self {
        Self {
            database,
            min_support,
        }
    }

    /// Mines the database for closed sequences, returning the discovered sequences.
    pub fn mine_closed_sequences(&self, monitor: &dyn TaskMonitor) -> HashSet<FrequentSequence> {
        let mut frequent_closed_sequences = HashSet::new();
        let globally_frequent_items = self.database.get_globally_frequent_items(self.min_support);
        monitor.set_maximum(globally_frequent_items.len() as i64);

        for gf_item in &globally_frequent_items {
            if monitor.is_cancelled() {
                break;
            }
            monitor.increment_progress(1);
            let singleton_frequent_item = vec![gf_item.get_item().clone()];
            let projected_database = ProjectedDatabase::new(&self.database, singleton_frequent_item);
            let backward_extension_items = projected_database.get_backward_extension_items();
            if backward_extension_items.is_empty() {
                Self::bide(
                    &projected_database,
                    &globally_frequent_items,
                    self.min_support,
                    monitor,
                    &mut frequent_closed_sequences,
                );
            }
        }
        frequent_closed_sequences
    }

    /// "bide" is short for "BiDirectional Extension", the name of the algorithm in the paper by
    /// Wang & Han.
    fn bide(
        projected_database: &ProjectedDatabase,
        globally_frequent_items: &BTreeSet<FrequentSequenceItem>,
        min_support: i32,
        monitor: &dyn TaskMonitor,
        frequent_closed_sequences: &mut HashSet<FrequentSequence>,
    ) {
        let locally_frequent_items =
            projected_database.get_locally_frequent_items(globally_frequent_items, min_support);
        let forward_extension_items =
            projected_database.get_forward_extension_items(&locally_frequent_items);
        if forward_extension_items.is_empty() {
            frequent_closed_sequences.insert(FrequentSequence::new(
                projected_database.get_prefix().to_vec(),
                projected_database.get_support(),
            ));
        }
        for f_item in &locally_frequent_items {
            if monitor.is_cancelled() {
                return;
            }
            let extended =
                ProjectedDatabase::from_extension(projected_database, f_item.get_item().clone());
            let backward_extension_items = extended.get_backward_extension_items();
            if backward_extension_items.is_empty() {
                Self::bide(
                    &extended,
                    globally_frequent_items,
                    min_support,
                    monitor,
                    frequent_closed_sequences,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frequent_sequence::FrequentSequence;
    use super::super::sequence::Sequence;
    use super::super::sequence_item::SequenceItem;
    use crate::util::task::DummyMonitor;

    fn mine(sequences: Vec<Sequence>, sequence_length: i32, min_support: i32) -> HashSet<FrequentSequence> {
        let database = SequenceDatabase::new(sequences, sequence_length);
        let miner = ClosedSequenceMiner::new(database, min_support);
        miner.mine_closed_sequences(&DummyMonitor)
    }

    #[test]
    fn single_sequence() {
        let sequences = vec![Sequence::new("B".to_owned(), 2)];
        let closed_seqs = mine(sequences, 1, 2);
        assert_eq!(closed_seqs.len(), 1);
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![SequenceItem::new("B", 0)],
            2
        )));
    }

    #[test]
    fn ignores_infrequent_sequence() {
        let sequences = vec![
            Sequence::new("A".to_owned(), 1),
            Sequence::new("B".to_owned(), 2),
        ];
        let closed_seqs = mine(sequences, 1, 2);
        assert_eq!(closed_seqs.len(), 1);
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![SequenceItem::new("B", 0)],
            2
        )));
    }

    #[test]
    fn ignores_multiple_infrequent_sequences() {
        let sequences = vec![
            Sequence::new("A".to_owned(), 1),
            Sequence::new("B".to_owned(), 2),
            Sequence::new("C".to_owned(), 1),
        ];
        let closed_seqs = mine(sequences, 1, 2);
        assert_eq!(closed_seqs.len(), 1);
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![SequenceItem::new("B", 0)],
            2
        )));
    }

    #[test]
    fn multiple_frequent_sequences() {
        let sequences = vec![
            Sequence::new("A".to_owned(), 1),
            Sequence::new("B".to_owned(), 2),
            Sequence::new("C".to_owned(), 2),
        ];
        let closed_seqs = mine(sequences, 1, 2);
        assert_eq!(closed_seqs.len(), 2);
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![SequenceItem::new("B", 0)],
            2
        )));
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![SequenceItem::new("C", 0)],
            2
        )));
    }

    #[test]
    fn entire_sequence_is_closed() {
        let sequences = vec![Sequence::new("ABCD".to_owned(), 2)];
        let closed_seqs = mine(sequences, 4, 2);
        assert_eq!(closed_seqs.len(), 1);
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![
                SequenceItem::new("A", 0),
                SequenceItem::new("B", 1),
                SequenceItem::new("C", 2),
                SequenceItem::new("D", 3),
            ],
            2
        )));
    }

    #[test]
    fn mixed_database_with_gaps() {
        let sequences = vec![
            Sequence::new("ABCD".to_owned(), 2),
            Sequence::new("XBYD".to_owned(), 2),
            Sequence::new("AUCV".to_owned(), 2),
            Sequence::new("AAAA".to_owned(), 2),
        ];
        let closed_seqs = mine(sequences, 4, 3);
        assert_eq!(closed_seqs.len(), 3);
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![SequenceItem::new("B", 1), SequenceItem::new("D", 3)],
            4
        )));
        assert!(closed_seqs.contains(&FrequentSequence::new(vec![SequenceItem::new("A", 0)], 6)));
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![SequenceItem::new("A", 0), SequenceItem::new("C", 2)],
            4
        )));
    }

    #[test]
    fn min_support_too_high_finds_nothing() {
        let sequences = vec![
            Sequence::new("ABCD".to_owned(), 2),
            Sequence::new("XBYD".to_owned(), 2),
            Sequence::new("AUCV".to_owned(), 2),
            Sequence::new("AAAA".to_owned(), 2),
        ];
        let closed_seqs = mine(sequences, 4, 7);
        assert!(closed_seqs.is_empty());
    }

    #[test]
    fn nested_closed_sequences() {
        let sequences = vec![
            Sequence::new("ABCD".to_owned(), 2),
            Sequence::new("AABC".to_owned(), 2),
            Sequence::new("AAAB".to_owned(), 2),
            Sequence::new("AAAA".to_owned(), 2),
        ];
        let closed_seqs = mine(sequences, 4, 3);
        assert_eq!(closed_seqs.len(), 3);
        assert!(closed_seqs.contains(&FrequentSequence::new(vec![SequenceItem::new("A", 0)], 8)));
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![SequenceItem::new("A", 0), SequenceItem::new("A", 1)],
            6
        )));
        assert!(closed_seqs.contains(&FrequentSequence::new(
            vec![
                SequenceItem::new("A", 0),
                SequenceItem::new("A", 1),
                SequenceItem::new("A", 2),
            ],
            4
        )));
    }

    #[test]
    fn cancelled_monitor_stops_early() {
        struct CancelledMonitor;
        impl TaskMonitor for CancelledMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
                Err(crate::util::exception::CancelledException(String::new()))
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                -1
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(
                &self,
                _listener: Box<dyn crate::util::task::CancelledListener>,
            ) {
            }
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let sequences = vec![Sequence::new("B".to_owned(), 2)];
        let database = SequenceDatabase::new(sequences, 1);
        let miner = ClosedSequenceMiner::new(database, 2);
        let closed_seqs = miner.mine_closed_sequences(&CancelledMonitor);
        assert!(closed_seqs.is_empty());
    }
}
