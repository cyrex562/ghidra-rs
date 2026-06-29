use std::fmt;
use std::ptr::NonNull;

/// Color of a red-black tree node, mirroring `NodeColor` in `RedBlackNode.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeColor {
    Red,
    Black,
}

/// Red-black tree node, mirroring `generic.stl.RedBlackNode<K, V>`.
///
/// All tree links are raw non-owning pointers. The owning tree is responsible
/// for calling [`RedBlackNode::dealloc`] on every node it allocated.
pub struct RedBlackNode<K, V> {
    pub key: K,
    pub value: V,
    pub(super) color: NodeColor,
    pub(super) parent: Option<NonNull<RedBlackNode<K, V>>>,
    pub(super) left: Option<NonNull<RedBlackNode<K, V>>>,
    pub(super) right: Option<NonNull<RedBlackNode<K, V>>>,
}

impl<K, V> RedBlackNode<K, V> {
    /// Allocates a new node with the given key, value, and optional parent.
    ///
    /// The initial color is [`NodeColor::Black`], mirroring the Java constructor
    /// `new RedBlackNode<>(key, value, parent)`.
    pub fn alloc(key: K, value: V, parent: Option<NonNull<Self>>) -> NonNull<Self> {
        let raw = Box::into_raw(Box::new(Self {
            key,
            value,
            color: NodeColor::Black,
            parent,
            left: None,
            right: None,
        }));
        // SAFETY: Box::into_raw never returns null.
        unsafe { NonNull::new_unchecked(raw) }
    }

    /// Frees the memory for `ptr`.
    ///
    /// # Safety
    /// - `ptr` must originate from [`Self::alloc`].
    /// - `ptr` must still be valid and not yet freed.
    /// - After this call, no raw pointer into this allocation may be dereferenced.
    pub unsafe fn dealloc(ptr: NonNull<Self>) {
        drop(Box::from_raw(ptr.as_ptr()));
    }

    /// Returns a reference to the node's key.
    ///
    /// Mirrors `getKey()`.
    pub fn get_key(&self) -> &K {
        &self.key
    }

    /// Returns a reference to the node's value.
    ///
    /// Mirrors `getValue()`.
    pub fn get_value(&self) -> &V {
        &self.value
    }

    /// Replaces the node's value.
    ///
    /// Mirrors `setValue(V)`.
    pub fn set_value(&mut self, value: V) {
        self.value = value;
    }

    /// Returns the in-order successor of `node`, or `None` if there is none.
    ///
    /// Mirrors `getSuccessor()`.
    ///
    /// # Safety
    /// `node` and every reachable tree link (`right`, `parent`, `left`) must be
    /// valid non-dangling pointers for the duration of this call.
    pub unsafe fn get_successor(node: NonNull<Self>) -> Option<NonNull<Self>> {
        let n = node.as_ptr();
        if let Some(right) = (*n).right {
            // Leftmost node in the right subtree.
            let mut cur = right;
            while let Some(left) = (*cur.as_ptr()).left {
                cur = left;
            }
            return Some(cur);
        }
        // Walk up until we arrive via a left-child link.
        let mut cur = node;
        while let Some(parent) = (*cur.as_ptr()).parent {
            if Self::is_left_child(cur) {
                return Some(parent);
            }
            cur = parent;
        }
        None
    }

    /// Returns the in-order predecessor of `node`, or `None` if there is none.
    ///
    /// Mirrors `getPredecessor()`.
    ///
    /// # Safety
    /// `node` and every reachable tree link must be valid non-dangling pointers
    /// for the duration of this call.
    pub unsafe fn get_predecessor(node: NonNull<Self>) -> Option<NonNull<Self>> {
        let n = node.as_ptr();
        if let Some(left) = (*n).left {
            // Rightmost node in the left subtree.
            let mut cur = left;
            while let Some(right) = (*cur.as_ptr()).right {
                cur = right;
            }
            return Some(cur);
        }
        // Walk up until we arrive via a right-child link.
        let mut cur = node;
        while let Some(parent) = (*cur.as_ptr()).parent {
            if !Self::is_left_child(cur) {
                return Some(parent);
            }
            cur = parent;
        }
        None
    }

    /// Returns `true` if `node` is the left child of its parent.
    ///
    /// Mirrors `isLeftChild()`.
    ///
    /// # Safety
    /// `node` must be valid and non-dangling, and `node.parent` must be
    /// `Some`, valid, and non-dangling.
    pub(super) unsafe fn is_left_child(node: NonNull<Self>) -> bool {
        let n = node.as_ptr();
        let parent = (*n)
            .parent
            .expect("is_left_child called on a node with no parent")
            .as_ptr();
        match (*parent).left {
            Some(left) => std::ptr::eq(left.as_ptr(), n),
            None => false,
        }
    }

    /// Returns `true` if `node` is the right child of its parent.
    ///
    /// Mirrors `isRightChild()`.
    ///
    /// # Safety
    /// `node` must be valid and non-dangling, and `node.parent` must be
    /// `Some`, valid, and non-dangling.
    pub(super) unsafe fn is_right_child(node: NonNull<Self>) -> bool {
        let n = node.as_ptr();
        let parent = (*n)
            .parent
            .expect("is_right_child called on a node with no parent")
            .as_ptr();
        match (*parent).right {
            Some(right) => std::ptr::eq(right.as_ptr(), n),
            None => false,
        }
    }
}

impl<K, V: fmt::Display> fmt::Display for RedBlackNode<K, V> {
    /// Mirrors `toString()`, which returns the string representation of the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    // Build a three-node tree:
    //       root(5)
    //       /     \
    //    left(3) right(7)
    unsafe fn three_node_tree() -> (
        NonNull<RedBlackNode<i32, i32>>,
        NonNull<RedBlackNode<i32, i32>>,
        NonNull<RedBlackNode<i32, i32>>,
    ) {
        let root = RedBlackNode::alloc(5, 5, None);
        let left = RedBlackNode::alloc(3, 3, Some(root));
        let right = RedBlackNode::alloc(7, 7, Some(root));
        (*root.as_ptr()).left = Some(left);
        (*root.as_ptr()).right = Some(right);
        (root, left, right)
    }

    unsafe fn free_three(
        root: NonNull<RedBlackNode<i32, i32>>,
        left: NonNull<RedBlackNode<i32, i32>>,
        right: NonNull<RedBlackNode<i32, i32>>,
    ) {
        RedBlackNode::dealloc(left);
        RedBlackNode::dealloc(right);
        RedBlackNode::dealloc(root);
    }

    #[test]
    fn alloc_sets_color_black_and_no_children() {
        unsafe {
            let node = RedBlackNode::<i32, &str>::alloc(1, "hello", None);
            let p = node.as_ptr();
            assert_eq!((*p).color, NodeColor::Black);
            assert!((*p).left.is_none());
            assert!((*p).right.is_none());
            assert!((*p).parent.is_none());
            assert_eq!((*p).key, 1);
            assert_eq!((*p).value, "hello");
            RedBlackNode::dealloc(node);
        }
    }

    #[test]
    fn get_key_and_get_value() {
        unsafe {
            let node = RedBlackNode::alloc(42i32, 99i32, None);
            assert_eq!(*(*node.as_ptr()).get_key(), 42);
            assert_eq!(*(*node.as_ptr()).get_value(), 99);
            RedBlackNode::dealloc(node);
        }
    }

    #[test]
    fn set_value_updates_field() {
        unsafe {
            let node = RedBlackNode::alloc(1i32, 10i32, None);
            (*node.as_ptr()).set_value(20);
            assert_eq!((*node.as_ptr()).value, 20);
            RedBlackNode::dealloc(node);
        }
    }

    #[test]
    fn display_shows_value() {
        unsafe {
            let node = RedBlackNode::alloc(0i32, 123i32, None);
            assert_eq!(format!("{}", *node.as_ptr()), "123");
            RedBlackNode::dealloc(node);
        }
    }

    #[test]
    fn is_left_child_and_is_right_child() {
        unsafe {
            let (root, left, right) = three_node_tree();
            assert!(RedBlackNode::is_left_child(left));
            assert!(!RedBlackNode::is_right_child(left));
            assert!(RedBlackNode::is_right_child(right));
            assert!(!RedBlackNode::is_left_child(right));
            free_three(root, left, right);
        }
    }

    #[test]
    fn successor_of_left_child_is_root() {
        unsafe {
            let (root, left, right) = three_node_tree();
            let succ = RedBlackNode::get_successor(left).unwrap();
            assert!(ptr::eq(succ.as_ptr(), root.as_ptr()));
            free_three(root, left, right);
        }
    }

    #[test]
    fn successor_of_root_is_right_child() {
        unsafe {
            let (root, left, right) = three_node_tree();
            let succ = RedBlackNode::get_successor(root).unwrap();
            assert!(ptr::eq(succ.as_ptr(), right.as_ptr()));
            free_three(root, left, right);
        }
    }

    #[test]
    fn successor_of_rightmost_is_none() {
        unsafe {
            let (root, left, right) = three_node_tree();
            assert!(RedBlackNode::get_successor(right).is_none());
            free_three(root, left, right);
        }
    }

    #[test]
    fn predecessor_of_right_child_is_root() {
        unsafe {
            let (root, left, right) = three_node_tree();
            let pred = RedBlackNode::get_predecessor(right).unwrap();
            assert!(ptr::eq(pred.as_ptr(), root.as_ptr()));
            free_three(root, left, right);
        }
    }

    #[test]
    fn predecessor_of_root_is_left_child() {
        unsafe {
            let (root, left, right) = three_node_tree();
            let pred = RedBlackNode::get_predecessor(root).unwrap();
            assert!(ptr::eq(pred.as_ptr(), left.as_ptr()));
            free_three(root, left, right);
        }
    }

    #[test]
    fn predecessor_of_leftmost_is_none() {
        unsafe {
            let (root, left, right) = three_node_tree();
            assert!(RedBlackNode::get_predecessor(left).is_none());
            free_three(root, left, right);
        }
    }

    #[test]
    fn successor_descends_into_right_subtree_leftmost() {
        // Tree:      root(5)
        //            /    \
        //         a(3)   b(8)
        //                /
        //              c(6)
        // Successor of root(5) should be c(6) (leftmost of right subtree).
        unsafe {
            let root = RedBlackNode::alloc(5i32, 5i32, None);
            let a = RedBlackNode::alloc(3, 3, Some(root));
            let b = RedBlackNode::alloc(8, 8, Some(root));
            let c = RedBlackNode::alloc(6, 6, Some(b));
            (*root.as_ptr()).left = Some(a);
            (*root.as_ptr()).right = Some(b);
            (*b.as_ptr()).left = Some(c);

            let succ = RedBlackNode::get_successor(root).unwrap();
            assert!(ptr::eq(succ.as_ptr(), c.as_ptr()));

            // c(6) successor is b(8): c has no right, walk up; c is left child → return b.
            let succ_c = RedBlackNode::get_successor(c).unwrap();
            assert!(ptr::eq(succ_c.as_ptr(), b.as_ptr()));

            RedBlackNode::dealloc(c);
            RedBlackNode::dealloc(b);
            RedBlackNode::dealloc(a);
            RedBlackNode::dealloc(root);
        }
    }

    #[test]
    fn predecessor_ascends_from_right_subtree() {
        // Tree:   root(5)
        //         /    \
        //       a(3)   b(8)
        //               \
        //               c(9)
        // Predecessor of c(9): no left, c is right child → return b(8).
        // Predecessor of b(8): no left, b is right child → return root(5).
        unsafe {
            let root = RedBlackNode::alloc(5i32, 5i32, None);
            let a = RedBlackNode::alloc(3, 3, Some(root));
            let b = RedBlackNode::alloc(8, 8, Some(root));
            let c = RedBlackNode::alloc(9, 9, Some(b));
            (*root.as_ptr()).left = Some(a);
            (*root.as_ptr()).right = Some(b);
            (*b.as_ptr()).right = Some(c);

            let pred_c = RedBlackNode::get_predecessor(c).unwrap();
            assert!(ptr::eq(pred_c.as_ptr(), b.as_ptr()));

            let pred_b = RedBlackNode::get_predecessor(b).unwrap();
            assert!(ptr::eq(pred_b.as_ptr(), root.as_ptr()));

            RedBlackNode::dealloc(c);
            RedBlackNode::dealloc(b);
            RedBlackNode::dealloc(a);
            RedBlackNode::dealloc(root);
        }
    }
}
