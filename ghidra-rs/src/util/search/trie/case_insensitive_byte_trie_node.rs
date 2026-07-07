use std::cell::RefCell;
use std::rc::Rc;

use super::{ByteTrieNode, NodeRef, WeakNodeRef};

/// Folds ASCII lowercase letters to uppercase before trie comparisons.
///
/// Mirrors `CaseInsensitiveByteTrieNode.transformByte`.
pub fn ci_transform(v: u8) -> u8 {
    if v >= b'a' && v <= b'z' {
        v - (b'a' - b'A')
    } else {
        v
    }
}

/// Creates a case-insensitive [`ByteTrieNode`] that normalises ASCII lowercase
/// to uppercase before all child lookups and insertions.
///
/// Mirrors `ghidra.util.search.trie.CaseInsensitiveByteTrieNode`.
pub fn new_case_insensitive_node<T>(
    id: u8,
    parent: Option<WeakNodeRef<T>>,
    length: usize,
) -> ByteTrieNode<T> {
    ByteTrieNode::with_transform(id, parent, length, ci_transform)
}

/// Wraps `new_case_insensitive_node` in a shared reference, matching the
/// [`NodeRef`] type used throughout the trie.
pub fn new_case_insensitive_node_ref<T>(
    id: u8,
    parent: Option<WeakNodeRef<T>>,
    length: usize,
) -> NodeRef<T> {
    Rc::new(RefCell::new(new_case_insensitive_node(id, parent, length)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ByteTrieNodeIfc;

    #[test]
    fn ci_transform_leaves_uppercase_unchanged() {
        for b in b'A'..=b'Z' {
            assert_eq!(ci_transform(b), b, "expected uppercase {:?} unchanged", b as char);
        }
    }

    #[test]
    fn ci_transform_folds_lowercase_to_uppercase() {
        for (lo, hi) in (b'a'..=b'z').zip(b'A'..=b'Z') {
            assert_eq!(
                ci_transform(lo),
                hi,
                "expected {:?} -> {:?}",
                lo as char,
                hi as char,
            );
        }
    }

    #[test]
    fn ci_transform_leaves_non_alpha_unchanged() {
        for b in [0u8, b'0', b'9', b'!', 0x80, 0xFF] {
            assert_eq!(ci_transform(b), b);
        }
    }

    #[test]
    fn new_node_is_not_terminal() {
        let node = new_case_insensitive_node::<()>(b'A', None, 0);
        assert!(!node.is_terminal());
        assert_eq!(node.get_item(), None);
    }

    #[test]
    fn new_node_stores_correct_length() {
        let node = new_case_insensitive_node::<()>(b'x', None, 7);
        assert_eq!(node.length(), 7);
    }

    #[test]
    fn transform_byte_folds_lowercase() {
        let node = new_case_insensitive_node::<()>(0, None, 0);
        assert_eq!(node.transform_byte(b'a'), b'A');
        assert_eq!(node.transform_byte(b'z'), b'Z');
        assert_eq!(node.transform_byte(b'A'), b'A');
        assert_eq!(node.transform_byte(b'Z'), b'Z');
        assert_eq!(node.transform_byte(b'0'), b'0');
    }

    #[test]
    fn case_insensitive_child_lookup() {
        let root_rc = new_case_insensitive_node_ref::<i32>(0, None, 0);
        // Insert child with uppercase 'A'
        let child_rc = new_case_insensitive_node_ref(b'A', Some(Rc::downgrade(&root_rc)), 1);
        root_rc.borrow_mut().add_child(b'A', Rc::clone(&child_rc));
        // Lookup with lowercase should fold to 'A' and find the same child
        let found_upper = root_rc.borrow().get_child(b'A');
        let found_lower = root_rc.borrow().get_child(b'a');
        assert!(found_upper.is_some(), "lookup by 'A' must succeed");
        assert!(found_lower.is_some(), "lookup by 'a' must succeed (case-insensitive)");
        assert_eq!(
            found_upper.unwrap().borrow().get_id(),
            found_lower.unwrap().borrow().get_id(),
        );
    }

    #[test]
    fn node_ref_constructor_returns_shared_ref() {
        let node_ref = new_case_insensitive_node_ref::<u32>(b'B', None, 3);
        assert_eq!(node_ref.borrow().get_id(), b'B');
        assert_eq!(node_ref.borrow().length(), 3);
    }
}
