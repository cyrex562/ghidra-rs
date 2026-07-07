use std::cell::RefCell;
use std::fmt;
use std::rc::{Rc, Weak};

const TERMINAL_MASK: u16 = 0x100;
const ID_MASK: u16 = 0xff;

/// Shared-ownership reference to a [`ByteTrieNode`].
pub type NodeRef<T> = Rc<RefCell<ByteTrieNode<T>>>;

/// Weak (non-owning) reference to a [`ByteTrieNode`], used for parent and suffix links.
pub type WeakNodeRef<T> = Weak<RefCell<ByteTrieNode<T>>>;

/// Interface for a node within a [`ByteTrie`].
///
/// Mirrors `ghidra.util.search.trie.ByteTrieNodeIfc`.
pub trait ByteTrieNodeIfc<T> {
    /// Returns whether this node represents a terminal byte sequence in the trie.
    fn is_terminal(&self) -> bool;

    /// Returns the user item stored in a terminal node, or `None` for internal nodes.
    fn get_item(&self) -> Option<&T>;

    /// Returns the byte sequence represented by this node (rebuilt on every call).
    fn get_value(&self) -> Vec<u8>;

    /// Returns the cached length of the byte sequence.
    fn length(&self) -> usize;
}

/// A (possibly non-terminal) node within a `ByteTrie`.
///
/// Children are kept sorted by `transform(id)` so that binary search can be used
/// for O(log n) child lookup and O(log n) insertion.
///
/// Parent and suffix links are `Weak` references to avoid reference cycles.
///
/// Mirrors `ghidra.util.search.trie.ByteTrieNode`.
pub struct ByteTrieNode<T> {
    /// Sorted child nodes, keyed by `transform(id)`.
    pub children: Vec<NodeRef<T>>,
    /// Low 8 bits: byte ID; bit 8 (0x100): terminal flag.
    id_and_terminality: u16,
    /// Cached depth — length of the byte sequence leading to this node.
    length: usize,
    /// Upward link to the parent node (weak to break ownership cycle).
    parent: Option<WeakNodeRef<T>>,
    /// Aho-Corasick suffix link (weak to break ownership cycle).
    pub suffix: Option<WeakNodeRef<T>>,
    /// User item, present only when this node is terminal.
    item: Option<T>,
    /// Byte transformation applied before all comparisons (identity by default).
    transform: fn(u8) -> u8,
}

impl<T> ByteTrieNode<T> {
    /// Creates a new non-terminal node with the identity byte transform.
    pub fn new(id: u8, parent: Option<WeakNodeRef<T>>, length: usize) -> Self {
        Self::with_transform(id, parent, length, |v| v)
    }

    /// Creates a new non-terminal node with a custom byte transform.
    ///
    /// Used by case-insensitive variants that override `transform_byte`.
    pub fn with_transform(
        id: u8,
        parent: Option<WeakNodeRef<T>>,
        length: usize,
        transform: fn(u8) -> u8,
    ) -> Self {
        ByteTrieNode {
            children: Vec::new(),
            id_and_terminality: id as u16 & ID_MASK,
            length,
            parent,
            suffix: None,
            item: None,
            transform,
        }
    }

    /// Applies the stored byte transformation to `v`.
    ///
    /// The default implementation is the identity. Subclass behaviour (e.g.
    /// case-insensitive folding) is achieved by supplying a custom function to
    /// [`ByteTrieNode::with_transform`].
    pub fn transform_byte(&self, v: u8) -> u8 {
        (self.transform)(v)
    }

    /// Returns the final byte in the byte sequence for this node.
    pub fn get_id(&self) -> u8 {
        (self.id_and_terminality & ID_MASK) as u8
    }

    /// Returns the child whose transformed ID equals `transform(value)`, or `None`.
    pub fn get_child(&self, value: u8) -> Option<NodeRef<T>> {
        let value = self.transform_byte(value);
        match self.children.len() {
            0 => None,
            1 => {
                if self.transform_byte(self.children[0].borrow().get_id()) == value {
                    Some(Rc::clone(&self.children[0]))
                } else {
                    None
                }
            }
            2 => {
                if self.transform_byte(self.children[0].borrow().get_id()) == value {
                    return Some(Rc::clone(&self.children[0]));
                }
                if self.transform_byte(self.children[1].borrow().get_id()) == value {
                    return Some(Rc::clone(&self.children[1]));
                }
                None
            }
            _ => {
                let index = self.find_index(value);
                if index >= self.children.len() {
                    return None;
                }
                let child = &self.children[index];
                if self.transform_byte(child.borrow().get_id()) == value {
                    Some(Rc::clone(child))
                } else {
                    None
                }
            }
        }
    }

    /// Inserts `child` into the children list, maintaining sort order by transformed ID.
    pub fn add_child(&mut self, value: u8, child: NodeRef<T>) {
        let value = self.transform_byte(value);
        if self.children.is_empty() {
            self.children.push(child);
            return;
        }
        if self.children.len() == 1 {
            if value < self.transform_byte(self.children[0].borrow().get_id()) {
                let old = Rc::clone(&self.children[0]);
                self.children[0] = child;
                self.children.push(old);
            } else {
                self.children.push(child);
            }
            return;
        }
        let new_child_index = self.find_index(value);
        self.children.insert(new_child_index, child);
    }

    /// Binary search: returns the index where `value` is found or should be inserted.
    fn find_index(&self, value: u8) -> usize {
        if self.children.is_empty() {
            return 0;
        }
        let mut left: i32 = 0;
        let mut right: i32 = self.children.len() as i32;
        while right >= left {
            let mid = ((left + right) / 2) as usize;
            if mid >= self.children.len() {
                return mid;
            }
            let id = self.transform_byte(self.children[mid].borrow().get_id());
            if id == value {
                return mid;
            } else if id < value {
                left = mid as i32 + 1;
            } else {
                right = mid as i32 - 1;
            }
        }
        left as usize
    }

    /// Marks this node as terminal and stores the user item.
    pub fn set_terminal(&mut self, item: T) {
        self.id_and_terminality |= TERMINAL_MASK;
        self.item = Some(item);
    }

    /// Returns a reference to the parent weak link.
    pub fn parent(&self) -> Option<&WeakNodeRef<T>> {
        self.parent.as_ref()
    }
}

impl<T> ByteTrieNodeIfc<T> for ByteTrieNode<T> {
    fn is_terminal(&self) -> bool {
        (self.id_and_terminality & TERMINAL_MASK) != 0
    }

    fn get_item(&self) -> Option<&T> {
        self.item.as_ref()
    }

    /// Walks up to the root collecting each node's byte ID; the root itself is excluded.
    ///
    /// Equivalent to the Java `getValue()` which allocates a fresh array on every call.
    fn get_value(&self) -> Vec<u8> {
        if self.parent.is_none() {
            return Vec::new();
        }
        let mut ids: Vec<u8> = vec![self.get_id()];
        let mut current = self.parent.as_ref().and_then(|w| w.upgrade());
        loop {
            match current {
                None => break,
                Some(rc) => {
                    let (id_opt, next) = {
                        let node = rc.borrow();
                        let id_opt = if node.parent.is_some() {
                            Some(node.get_id())
                        } else {
                            None
                        };
                        let next = node.parent.as_ref().and_then(|w| w.upgrade());
                        (id_opt, next)
                    };
                    match id_opt {
                        None => break,
                        Some(id) => {
                            ids.push(id);
                            current = next;
                        }
                    }
                }
            }
        }
        ids.reverse();
        ids
    }

    fn length(&self) -> usize {
        self.length
    }
}

fn debug_byte_array(array: &[u8]) -> String {
    let mut s = String::new();
    for &b in array {
        if b > 31 && b < 127 {
            s.push(b as char);
        } else {
            s.push_str(&format!("\\x{:02x}", b));
        }
    }
    s
}

impl<T: fmt::Display> fmt::Display for ByteTrieNode<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let star = if self.is_terminal() { "*" } else { "" };
        if self.parent.is_none() {
            return write!(f, "{}-", star);
        }
        let value = ByteTrieNodeIfc::get_value(self);
        let id = self.get_id() as char;
        let suffix_str = match &self.suffix {
            None => "null".to_string(),
            Some(w) => match w.upgrade() {
                None => "null".to_string(),
                Some(rc) => rc.borrow().to_string(),
            }
        };
        write!(f, "{}{}:{}  s:[{}]", star, debug_byte_array(&value), id, suffix_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_root<T>() -> NodeRef<T> {
        Rc::new(RefCell::new(ByteTrieNode::new(0, None, 0)))
    }

    fn make_child<T>(id: u8, parent: &NodeRef<T>, length: usize) -> NodeRef<T> {
        Rc::new(RefCell::new(ByteTrieNode::new(
            id,
            Some(Rc::downgrade(parent)),
            length,
        )))
    }

    #[test]
    fn new_node_is_not_terminal() {
        let node = ByteTrieNode::<()>::new(42, None, 0);
        assert!(!node.is_terminal());
        assert_eq!(node.get_item(), None);
    }

    #[test]
    fn get_id_returns_correct_byte() {
        let node = ByteTrieNode::<()>::new(0xAB, None, 0);
        assert_eq!(node.get_id(), 0xAB);
    }

    #[test]
    fn set_terminal_marks_node_and_stores_item() {
        let mut node = ByteTrieNode::new(1, None, 0);
        node.set_terminal(99u32);
        assert!(node.is_terminal());
        assert_eq!(node.get_item(), Some(&99u32));
    }

    #[test]
    fn length_reflects_depth() {
        let node = ByteTrieNode::<()>::new(5, None, 7);
        assert_eq!(node.length(), 7);
    }

    #[test]
    fn get_value_root_returns_empty() {
        let root = ByteTrieNode::<()>::new(0, None, 0);
        assert!(root.get_value().is_empty());
    }

    #[test]
    fn get_value_depth_one() {
        let root = make_root::<()>();
        let child = make_child(b'A', &root, 1);
        assert_eq!(child.borrow().get_value(), vec![b'A']);
    }

    #[test]
    fn get_value_depth_two() {
        let root = make_root::<()>();
        let child = make_child(b'A', &root, 1);
        let grandchild = make_child(b'B', &child, 2);
        assert_eq!(grandchild.borrow().get_value(), vec![b'A', b'B']);
    }

    #[test]
    fn get_child_empty_children_returns_none() {
        let root = ByteTrieNode::<()>::new(0, None, 0);
        assert!(root.get_child(b'x').is_none());
    }

    #[test]
    fn add_and_get_child_single() {
        let root_rc = make_root::<i32>();
        let child_rc = make_child(b'Z', &root_rc, 1);
        root_rc.borrow_mut().add_child(b'Z', Rc::clone(&child_rc));
        let found = root_rc.borrow().get_child(b'Z');
        assert!(found.is_some());
        assert_eq!(found.unwrap().borrow().get_id(), b'Z');
    }

    #[test]
    fn add_child_maintains_sorted_order() {
        let root_rc = make_root::<i32>();
        let c1 = make_child(b'C', &root_rc, 1);
        let a1 = make_child(b'A', &root_rc, 1);
        let b1 = make_child(b'B', &root_rc, 1);

        root_rc.borrow_mut().add_child(b'C', Rc::clone(&c1));
        root_rc.borrow_mut().add_child(b'A', Rc::clone(&a1));
        root_rc.borrow_mut().add_child(b'B', Rc::clone(&b1));

        let ids: Vec<u8> = root_rc
            .borrow()
            .children
            .iter()
            .map(|n| n.borrow().get_id())
            .collect();
        assert_eq!(ids, vec![b'A', b'B', b'C']);
    }

    #[test]
    fn get_child_missing_returns_none() {
        let root_rc = make_root::<()>();
        let child = make_child(b'A', &root_rc, 1);
        root_rc.borrow_mut().add_child(b'A', child);
        assert!(root_rc.borrow().get_child(b'B').is_none());
    }

    #[test]
    fn get_child_binary_search_multiple_children() {
        let root_rc = make_root::<()>();
        for b in [b'A', b'C', b'E', b'G', b'I'] {
            let child = make_child(b, &root_rc, 1);
            root_rc.borrow_mut().add_child(b, child);
        }
        for b in [b'A', b'C', b'E', b'G', b'I'] {
            let found = root_rc.borrow().get_child(b);
            assert!(found.is_some(), "should find {:?}", b as char);
            assert_eq!(found.unwrap().borrow().get_id(), b);
        }
        assert!(root_rc.borrow().get_child(b'B').is_none());
        assert!(root_rc.borrow().get_child(b'Z').is_none());
    }

    #[test]
    fn transform_byte_identity_by_default() {
        let node = ByteTrieNode::<()>::new(0, None, 0);
        assert_eq!(node.transform_byte(b'A'), b'A');
        assert_eq!(node.transform_byte(0xFF), 0xFF);
    }

    #[test]
    fn with_transform_uses_custom_function() {
        let node = ByteTrieNode::<()>::with_transform(0, None, 0, |v| v.to_ascii_lowercase());
        // Children added with uppercase should be findable with lowercase
        assert_eq!(node.transform_byte(b'A'), b'a');
    }

    #[test]
    fn display_root_node() {
        let root = ByteTrieNode::<u32>::new(0, None, 0);
        assert_eq!(root.to_string(), "-");
    }

    #[test]
    fn display_terminal_root_node() {
        let mut root = ByteTrieNode::new(0, None, 0);
        root.set_terminal(1u32);
        assert_eq!(root.to_string(), "*-");
    }
}
