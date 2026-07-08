use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::mem::{Memory, MemoryAccessException};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use super::{ByteTrieNodeIfc, Op, SearchResult};

/// Interface for a byte trie supporting string matching and user item storage.
///
/// Mirrors `ghidra.util.search.trie.ByteTrieIfc<T>`. A trie stores byte sequences
/// (keys) and associated user items (values), supporting queries and searches.
pub trait ByteTrieIfc<T: Clone> {
    /// Returns whether the trie is empty.
    fn is_empty(&self) -> bool;

    /// Returns the number of byte sequences in the trie.
    fn size(&self) -> usize;

    /// Returns the number of nodes in the trie; this is essentially equal
    /// to the sum of the number of characters in all byte sequences present in
    /// the trie, minus their shared prefixes.
    fn number_of_nodes(&self) -> usize;

    /// Adds a byte sequence to the trie, with corresponding user item.
    /// Returns whether the add took place, or if this add was essentially a replacement of
    /// a previously present value (previous user item is lost forever).
    fn add(&mut self, value: &[u8], item: T) -> bool;

    /// Finds a byte sequence in the trie and returns a node interface object for it,
    /// or None if not present.
    fn find(&self, value: &[u8]) -> Option<Box<dyn ByteTrieNodeIfc<T>>>;

    /// Visits all the nodes in the trie such that the visitation order is properly
    /// byte value ordered. The client is responsible for not performing actions on
    /// non-terminal nodes as necessary.
    fn inorder(
        &self,
        monitor: &dyn TaskMonitor,
        op: &mut dyn Op<T>,
    ) -> Result<(), CancelledException>;

    /// Search an array of bytes using the Aho-Corasick multiple string
    /// trie search algorithm.
    fn search(
        &self,
        text: &[u8],
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<SearchResult<usize, T>>, CancelledException>;

    /// Search memory using the Aho-Corasick multiple string trie search algorithm.
    fn search_memory(
        &self,
        memory: &dyn Memory,
        view: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<SearchResult<Address, T>>, Box<dyn std::error::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTrie<T: Clone> {
        items: Vec<(Vec<u8>, T)>,
    }

    impl<T: Clone> MockTrie<T> {
        fn new() -> Self {
            MockTrie {
                items: Vec::new(),
            }
        }
    }

    impl<T: Clone> ByteTrieIfc<T> for MockTrie<T> {
        fn is_empty(&self) -> bool {
            self.items.is_empty()
        }

        fn size(&self) -> usize {
            self.items.len()
        }

        fn number_of_nodes(&self) -> usize {
            1 + self.items.iter().map(|(k, _)| k.len()).sum::<usize>()
        }

        fn add(&mut self, value: &[u8], item: T) -> bool {
            let existing = self.items.iter().position(|(k, _)| k == value);
            if let Some(pos) = existing {
                false
            } else {
                self.items.push((value.to_vec(), item));
                true
            }
        }

        fn find(&self, value: &[u8]) -> Option<Box<dyn ByteTrieNodeIfc<T>>> {
            self.items
                .iter()
                .find(|(k, _)| k == value)
                .map(|_| Box::new(()) as Box<dyn ByteTrieNodeIfc<T>>)
        }

        fn inorder(
            &self,
            monitor: &dyn TaskMonitor,
            _op: &mut dyn Op<T>,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }

        fn search(
            &self,
            _text: &[u8],
            monitor: &dyn TaskMonitor,
        ) -> Result<Vec<SearchResult<usize, T>>, CancelledException> {
            monitor.check_cancelled()?;
            Ok(Vec::new())
        }

        fn search_memory(
            &self,
            _memory: &dyn Memory,
            _view: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<Vec<SearchResult<Address, T>>, Box<dyn std::error::Error>> {
            monitor.check_cancelled()?;
            Ok(Vec::new())
        }
    }

    #[test]
    fn is_empty_returns_true_for_new_trie() {
        let trie: MockTrie<u32> = MockTrie::new();
        assert!(trie.is_empty());
    }

    #[test]
    fn is_empty_returns_false_after_add() {
        let mut trie = MockTrie::new();
        trie.add(b"test", 42u32);
        assert!(!trie.is_empty());
    }

    #[test]
    fn size_returns_zero_for_new_trie() {
        let trie: MockTrie<u32> = MockTrie::new();
        assert_eq!(trie.size(), 0);
    }

    #[test]
    fn size_increments_on_add() {
        let mut trie = MockTrie::new();
        trie.add(b"first", 1u32);
        assert_eq!(trie.size(), 1);
        trie.add(b"second", 2u32);
        assert_eq!(trie.size(), 2);
    }

    #[test]
    fn add_returns_true_for_new_value() {
        let mut trie = MockTrie::new();
        assert!(trie.add(b"test", 42u32));
    }

    #[test]
    fn add_returns_false_for_duplicate() {
        let mut trie = MockTrie::new();
        trie.add(b"test", 42u32);
        assert!(!trie.add(b"test", 99u32));
    }

    #[test]
    fn find_returns_none_for_empty_trie() {
        let trie: MockTrie<u32> = MockTrie::new();
        assert!(trie.find(b"test").is_none());
    }

    #[test]
    fn find_returns_some_for_present_value() {
        let mut trie = MockTrie::new();
        trie.add(b"test", 42u32);
        assert!(trie.find(b"test").is_some());
    }

    #[test]
    fn find_returns_none_for_absent_value() {
        let mut trie = MockTrie::new();
        trie.add(b"test", 42u32);
        assert!(trie.find(b"missing").is_none());
    }

    #[test]
    fn number_of_nodes_includes_root() {
        let trie: MockTrie<u32> = MockTrie::new();
        assert_eq!(trie.number_of_nodes(), 1);
    }

    #[test]
    fn number_of_nodes_includes_sequence_length() {
        let mut trie = MockTrie::new();
        trie.add(b"abc", 1u32);
        assert_eq!(trie.number_of_nodes(), 4);
    }
}
