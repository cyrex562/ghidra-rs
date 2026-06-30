use std::cell::RefCell;
use std::rc::{Rc, Weak};

/// A reference-counted handle to a [`RedBlackEntry`] node.
pub type NodeRef<K, V> = Rc<RefCell<RedBlackEntry<K, V>>>;

type WeakRef<K, V> = Weak<RefCell<RedBlackEntry<K, V>>>;

/// Color of a red-black tree node. `None` indicates the node has been disposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeColor {
    Red,
    Black,
}

/// A node in a red-black tree that also serves as a map entry.
///
/// Nodes hold strong [`Rc`] references to their children and a weak reference to
/// their parent to avoid reference cycles. The [`NodeRef`] type alias is the
/// canonical way to hold a reference to a node.
///
/// Port of `ghidra.util.datastruct.RedBlackEntry`.
pub struct RedBlackEntry<K, V> {
    key: K,
    value: V,
    pub(crate) color: Option<NodeColor>,
    pub(crate) parent: Option<WeakRef<K, V>>,
    pub(crate) left: Option<NodeRef<K, V>>,
    pub(crate) right: Option<NodeRef<K, V>>,
}

impl<K, V> RedBlackEntry<K, V> {
    /// Creates a new black node wrapped in an `Rc<RefCell<...>>`.
    pub(crate) fn new(key: K, value: V, parent: Option<WeakRef<K, V>>) -> NodeRef<K, V> {
        Rc::new(RefCell::new(Self {
            key,
            value,
            color: Some(NodeColor::Black),
            parent,
            left: None,
            right: None,
        }))
    }

    /// Returns a reference to this entry's key.
    pub fn get_key(&self) -> &K {
        &self.key
    }

    /// Returns a reference to this entry's value.
    pub fn get_value(&self) -> &V {
        &self.value
    }

    /// Replaces the value and returns the previous value.
    pub fn set_value(&mut self, value: V) -> V {
        std::mem::replace(&mut self.value, value)
    }

    /// Returns `true` if this node has been disposed (removed from the tree).
    ///
    /// A disposed node has its color set to `None`.
    pub fn is_disposed(&self) -> bool {
        self.color.is_none()
    }

    /// Returns `true` if `node` is the left child of its parent.
    ///
    /// Uses pointer identity to compare against the parent's left slot.
    pub(crate) fn is_left_child(node: &NodeRef<K, V>) -> bool {
        let parent_weak = node.borrow().parent.clone();
        if let Some(weak) = parent_weak {
            if let Some(parent) = weak.upgrade() {
                if let Some(left) = parent.borrow().left.clone() {
                    return Rc::ptr_eq(&left, node);
                }
            }
        }
        false
    }

    /// Returns `true` if `node` is the right child of its parent.
    pub(crate) fn is_right_child(node: &NodeRef<K, V>) -> bool {
        let parent_weak = node.borrow().parent.clone();
        if let Some(weak) = parent_weak {
            if let Some(parent) = weak.upgrade() {
                if let Some(right) = parent.borrow().right.clone() {
                    return Rc::ptr_eq(&right, node);
                }
            }
        }
        false
    }

    /// Returns the in-order successor of `node`, or `None` if `node` is the maximum.
    ///
    /// If the node has a right subtree the successor is the leftmost node there;
    /// otherwise the successor is found by walking up until a left-child step is taken.
    pub fn get_successor(node: &NodeRef<K, V>) -> Option<NodeRef<K, V>> {
        let right = node.borrow().right.clone();
        if let Some(r) = right {
            let mut current = r;
            loop {
                let left = current.borrow().left.clone();
                match left {
                    Some(l) => current = l,
                    None => return Some(current),
                }
            }
        }
        let mut current = node.clone();
        loop {
            let parent_opt = current.borrow().parent.clone().and_then(|w| w.upgrade());
            match parent_opt {
                None => return None,
                Some(parent) => {
                    if Self::is_left_child(&current) {
                        return Some(parent);
                    }
                    current = parent;
                }
            }
        }
    }

    /// Returns the in-order predecessor of `node`, or `None` if `node` is the minimum.
    ///
    /// If the node has a left subtree the predecessor is the rightmost node there;
    /// otherwise the predecessor is found by walking up until a right-child step is taken.
    pub fn get_predecessor(node: &NodeRef<K, V>) -> Option<NodeRef<K, V>> {
        let left = node.borrow().left.clone();
        if let Some(l) = left {
            let mut current = l;
            loop {
                let right = current.borrow().right.clone();
                match right {
                    Some(r) => current = r,
                    None => return Some(current),
                }
            }
        }
        let mut current = node.clone();
        loop {
            let parent_opt = current.borrow().parent.clone().and_then(|w| w.upgrade());
            match parent_opt {
                None => return None,
                Some(parent) => {
                    if !Self::is_left_child(&current) {
                        return Some(parent);
                    }
                    current = parent;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a small BST:
    ///
    ///        root(5)
    ///       /       \
    ///     left(3)  right(7)
    ///     /    \
    ///  ll(1)  lr(4)
    fn build_tree() -> (NodeRef<i32, &'static str>, NodeRef<i32, &'static str>, NodeRef<i32, &'static str>, NodeRef<i32, &'static str>, NodeRef<i32, &'static str>) {
        let root = RedBlackEntry::new(5, "root", None);

        let left = RedBlackEntry::new(3, "left", Some(Rc::downgrade(&root)));
        let right = RedBlackEntry::new(7, "right", Some(Rc::downgrade(&root)));
        let ll = RedBlackEntry::new(1, "ll", Some(Rc::downgrade(&left)));
        let lr = RedBlackEntry::new(4, "lr", Some(Rc::downgrade(&left)));

        root.borrow_mut().left = Some(left.clone());
        root.borrow_mut().right = Some(right.clone());
        left.borrow_mut().left = Some(ll.clone());
        left.borrow_mut().right = Some(lr.clone());

        (root, left, right, ll, lr)
    }

    #[test]
    fn new_node_is_black_and_not_disposed() {
        let node = RedBlackEntry::new(42, "hello", None);
        let b = node.borrow();
        assert_eq!(b.color, Some(NodeColor::Black));
        assert!(!b.is_disposed());
    }

    #[test]
    fn get_key_and_value() {
        let node = RedBlackEntry::new(10, "val", None);
        let b = node.borrow();
        assert_eq!(*b.get_key(), 10);
        assert_eq!(*b.get_value(), "val");
    }

    #[test]
    fn set_value_returns_old_value() {
        let node = RedBlackEntry::new(1, "old", None);
        let old = node.borrow_mut().set_value("new");
        assert_eq!(old, "old");
        assert_eq!(*node.borrow().get_value(), "new");
    }

    #[test]
    fn is_disposed_when_color_is_none() {
        let node = RedBlackEntry::new(1, "x", None);
        assert!(!node.borrow().is_disposed());
        node.borrow_mut().color = None;
        assert!(node.borrow().is_disposed());
    }

    #[test]
    fn is_left_child_and_right_child() {
        let (_, left, right, ll, lr) = build_tree();
        assert!(RedBlackEntry::is_left_child(&left));
        assert!(!RedBlackEntry::is_left_child(&right));
        assert!(RedBlackEntry::is_right_child(&right));
        assert!(!RedBlackEntry::is_right_child(&left));
        assert!(RedBlackEntry::is_left_child(&ll));
        assert!(!RedBlackEntry::is_left_child(&lr));
        assert!(RedBlackEntry::is_right_child(&lr));
    }

    #[test]
    fn root_is_neither_left_nor_right_child() {
        let (root, _, _, _, _) = build_tree();
        assert!(!RedBlackEntry::is_left_child(&root));
        assert!(!RedBlackEntry::is_right_child(&root));
    }

    #[test]
    fn successor_via_right_subtree() {
        // successor of root(5) goes right then leftmost → right(7), but right has no left
        // so successor of root(5) = right(7)
        let (root, _, right, _, _) = build_tree();
        let succ = RedBlackEntry::get_successor(&root).expect("root has successor");
        assert!(Rc::ptr_eq(&succ, &right));
    }

    #[test]
    fn successor_of_maximum_is_none() {
        let (_, _, right, _, _) = build_tree();
        assert!(RedBlackEntry::get_successor(&right).is_none());
    }

    #[test]
    fn successor_by_walking_up() {
        // successor of lr(4): no right child, lr is a right child → go up to left(3)
        // left(3) is a left child → return root(5)
        let (root, _, _, _, lr) = build_tree();
        let succ = RedBlackEntry::get_successor(&lr).expect("lr has successor");
        assert!(Rc::ptr_eq(&succ, &root));
    }

    #[test]
    fn successor_of_ll_is_left() {
        // ll(1) has no right child; ll is left child of left(3) → successor is left(3)
        let (_, left, _, ll, _) = build_tree();
        let succ = RedBlackEntry::get_successor(&ll).expect("ll has successor");
        assert!(Rc::ptr_eq(&succ, &left));
    }

    #[test]
    fn predecessor_via_left_subtree() {
        // predecessor of root(5): go left to left(3), then rightmost → lr(4)
        let (root, _, _, _, lr) = build_tree();
        let pred = RedBlackEntry::get_predecessor(&root).expect("root has predecessor");
        assert!(Rc::ptr_eq(&pred, &lr));
    }

    #[test]
    fn predecessor_of_minimum_is_none() {
        let (_, _, _, ll, _) = build_tree();
        assert!(RedBlackEntry::get_predecessor(&ll).is_none());
    }

    #[test]
    fn predecessor_of_left_is_ll() {
        // predecessor of left(3): go left to ll(1), ll has no right → ll
        let (_, left, _, ll, _) = build_tree();
        let pred = RedBlackEntry::get_predecessor(&left).expect("left has predecessor");
        assert!(Rc::ptr_eq(&pred, &ll));
    }

    #[test]
    fn predecessor_by_walking_up() {
        // predecessor of right(7): no left child; right is right child → return root(5)
        let (root, _, right, _, _) = build_tree();
        let pred = RedBlackEntry::get_predecessor(&right).expect("right has predecessor");
        assert!(Rc::ptr_eq(&pred, &root));
    }

    #[test]
    fn in_order_successor_traversal() {
        let (root, _, _, ll, _) = build_tree();
        // In-order: ll(1), left(3), lr(4), root(5), right(7)
        let mut keys = Vec::new();
        let mut cur = Some(ll);
        while let Some(node) = cur {
            keys.push(*node.borrow().get_key());
            cur = RedBlackEntry::get_successor(&node);
        }
        assert_eq!(keys, vec![1, 3, 4, 5, 7]);
    }

    #[test]
    fn in_order_predecessor_traversal() {
        let (_, _, right, _, _) = build_tree();
        // Reverse in-order from right(7): 7, 5, 4, 3, 1
        let mut keys = Vec::new();
        let mut cur = Some(right);
        while let Some(node) = cur {
            keys.push(*node.borrow().get_key());
            cur = RedBlackEntry::get_predecessor(&node);
        }
        assert_eq!(keys, vec![7, 5, 4, 3, 1]);
    }
}
