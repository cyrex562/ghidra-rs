use std::fmt;

use super::byte_trie_node::NodeRef;

/// A search result container returned by [`ByteTrie`] searches.
///
/// Mirrors `ghidra.util.search.trie.SearchResult`.
pub struct SearchResult<P, T> {
    node: NodeRef<T>,
    position: P,
    item: T,
}

impl<P, T: Clone> SearchResult<P, T> {
    pub(crate) fn new(node: NodeRef<T>, position: P, item: T) -> Self {
        SearchResult { node, position, item }
    }

    /// Returns the terminal node encountered during the search.
    pub fn node(&self) -> &NodeRef<T> {
        &self.node
    }

    /// Returns the position at which the byte sequence was found.
    pub fn position(&self) -> &P {
        &self.position
    }

    /// Returns the user item stored in the terminal node.
    pub fn item(&self) -> &T {
        &self.item
    }
}

impl<P: fmt::Display, T: fmt::Display + Clone> fmt::Display for SearchResult<P, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.item, self.position)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::util::search::trie::byte_trie_node::ByteTrieNode;

    fn make_terminal_node(item: u32) -> NodeRef<u32> {
        let rc = Rc::new(RefCell::new(ByteTrieNode::new(b'A', None, 1)));
        rc.borrow_mut().set_terminal(item);
        rc
    }

    #[test]
    fn accessors_return_stored_values() {
        let node = make_terminal_node(42);
        let result = SearchResult::new(Rc::clone(&node), 100usize, 42u32);
        assert_eq!(*result.position(), 100usize);
        assert_eq!(*result.item(), 42u32);
    }

    #[test]
    fn node_accessor_returns_same_node() {
        let node = make_terminal_node(7);
        let result = SearchResult::new(Rc::clone(&node), 0usize, 7u32);
        assert!(Rc::ptr_eq(result.node(), &node));
    }

    #[test]
    fn display_formats_item_colon_position() {
        let node = make_terminal_node(99);
        let result = SearchResult::new(node, 55usize, 99u32);
        assert_eq!(result.to_string(), "99:55");
    }

    #[test]
    fn display_with_string_item_and_position() {
        let node = make_terminal_node(1);
        let result = SearchResult::new(node, "0x1000", 1u32);
        assert_eq!(result.to_string(), "1:0x1000");
    }
}
