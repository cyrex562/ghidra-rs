use super::{NodeColor, NodeRef, RedBlackEntry};
use std::cmp::Ordering;
use std::rc::Rc;

/// A red-black tree mapping `K` keys to `V` values, exposing shared handles
/// ([`NodeRef`]) to individual entries.
///
/// Rebalancing on insertion and deletion follows the classic CLR algorithm, matching
/// the original Java implementation's structure closely so the two stay easy to compare.
///
/// Unlike Java's `Iterable<RedBlackEntry<K, V>>`/`ListIterator` pairing, traversal here
/// is exposed as a simple forward/backward [`Iterator`] ([`RedBlackTreeIter`]) over
/// [`NodeRef`] handles; removing entries mid-traversal is done explicitly via
/// [`RedBlackTree::remove_node`] rather than through the iterator itself.
///
/// Port of `ghidra.util.datastruct.RedBlackTree`.
pub struct RedBlackTree<K, V> {
    root: Option<NodeRef<K, V>>,
    size: usize,
    max_entry: Option<NodeRef<K, V>>,
    min_entry: Option<NodeRef<K, V>>,
}

impl<K, V> RedBlackTree<K, V> {
    /// Creates a new, empty tree.
    pub fn new() -> Self {
        Self {
            root: None,
            size: 0,
            max_entry: None,
            min_entry: None,
        }
    }
}

impl<K, V> Default for RedBlackTree<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord, V> RedBlackTree<K, V> {
    /// Returns the number of keys in this tree.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns `true` if the tree contains no entries.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns `true` if `key` is present in the tree.
    pub fn contains_key(&self, key: &K) -> bool {
        self.get_node(key).is_some()
    }

    /// Returns the entry with the smallest key, or `None` if the tree is empty.
    pub fn get_first(&self) -> Option<NodeRef<K, V>> {
        self.min_entry.clone()
    }

    /// Returns the entry with the largest key, or `None` if the tree is empty.
    pub fn get_last(&self) -> Option<NodeRef<K, V>> {
        self.max_entry.clone()
    }

    /// Returns the entry with the largest key less than or equal to `key`, or `None`
    /// if there is no such entry.
    pub fn get_entry_less_than_equal(&self, key: &K) -> Option<NodeRef<K, V>> {
        let mut best: Option<NodeRef<K, V>> = None;
        let mut node = self.root.clone();
        while let Some(n) = node {
            let cmp = key.cmp(n.borrow().get_key());
            match cmp {
                Ordering::Equal => return Some(n),
                Ordering::Less => {
                    node = n.borrow().left.clone();
                }
                Ordering::Greater => {
                    node = n.borrow().right.clone();
                    best = Some(n);
                }
            }
        }
        best
    }

    /// Returns the entry with the smallest key greater than or equal to `key`, or
    /// `None` if there is no such entry.
    pub fn get_entry_greater_than_equal(&self, key: &K) -> Option<NodeRef<K, V>> {
        let mut best: Option<NodeRef<K, V>> = None;
        let mut node = self.root.clone();
        while let Some(n) = node {
            let cmp = key.cmp(n.borrow().get_key());
            match cmp {
                Ordering::Equal => return Some(n),
                Ordering::Less => {
                    node = n.borrow().left.clone();
                    best = Some(n);
                }
                Ordering::Greater => {
                    node = n.borrow().right.clone();
                }
            }
        }
        best
    }

    /// Returns the entry for `key`, or `None` if it is not present.
    pub fn get_entry(&self, key: &K) -> Option<NodeRef<K, V>> {
        self.get_node(key)
    }

    fn get_node(&self, key: &K) -> Option<NodeRef<K, V>> {
        let node = self.get_entry_less_than_equal(key)?;
        if node.borrow().get_key() == key {
            Some(node)
        } else {
            None
        }
    }

    /// Removes the entry for `key`, if present.
    pub fn remove_node(&mut self, node: &NodeRef<K, V>) {
        self.delete_entry(node.clone());
    }

    /// Removes all entries from the tree.
    ///
    /// Matches the Java original, which leaves the minimum-entry cache stale
    /// rather than clearing it; this is intentional bug-for-bug parity, and
    /// harmless since `min_entry` is never consulted while `root` is `None`.
    pub fn remove_all(&mut self) {
        self.size = 0;
        self.root = None;
        self.max_entry = None;
    }

    /// Returns a forward iterator over all entries in ascending key order.
    pub fn iter(&self) -> RedBlackTreeIter<K, V> {
        self.iter_dir(true)
    }

    /// Returns an iterator over all entries in the given direction.
    pub fn iter_dir(&self, forward: bool) -> RedBlackTreeIter<K, V> {
        let next = if forward {
            self.get_first()
        } else {
            self.get_last()
        };
        RedBlackTreeIter { next, forward }
    }

    /// Returns an iterator starting at `first` and moving in the given direction.
    pub fn iter_from(&self, first: Option<NodeRef<K, V>>, forward: bool) -> RedBlackTreeIter<K, V> {
        RedBlackTreeIter {
            next: first,
            forward,
        }
    }

    /// Returns an iterator starting at the entry nearest `key` and moving in the
    /// given direction (greater-or-equal when moving forward, less-or-equal when
    /// moving backward).
    pub fn iter_by_key(&self, key: &K, forward: bool) -> RedBlackTreeIter<K, V> {
        let first = if forward {
            self.get_entry_greater_than_equal(key)
        } else {
            self.get_entry_less_than_equal(key)
        };
        RedBlackTreeIter {
            next: first,
            forward,
        }
    }

    fn is_root(&self, node: &Option<NodeRef<K, V>>) -> bool {
        Self::same(node, &self.root)
    }

    fn same(a: &Option<NodeRef<K, V>>, b: &Option<NodeRef<K, V>>) -> bool {
        match (a, b) {
            (Some(x), Some(y)) => Rc::ptr_eq(x, y),
            (None, None) => true,
            _ => false,
        }
    }

    fn color_of(node: &Option<NodeRef<K, V>>) -> NodeColor {
        match node {
            None => NodeColor::Black,
            Some(n) => n.borrow().color.unwrap_or(NodeColor::Black),
        }
    }

    fn parent_of(node: &Option<NodeRef<K, V>>) -> Option<NodeRef<K, V>> {
        match node {
            None => None,
            Some(n) => n.borrow().parent.clone().and_then(|w| w.upgrade()),
        }
    }

    fn set_color(node: &Option<NodeRef<K, V>>, color: NodeColor) {
        if let Some(n) = node {
            n.borrow_mut().color = Some(color);
        }
    }

    fn left_of(node: &Option<NodeRef<K, V>>) -> Option<NodeRef<K, V>> {
        match node {
            None => None,
            Some(n) => n.borrow().left.clone(),
        }
    }

    fn right_of(node: &Option<NodeRef<K, V>>) -> Option<NodeRef<K, V>> {
        match node {
            None => None,
            Some(n) => n.borrow().right.clone(),
        }
    }

    /// From CLR.
    fn rotate_left(&mut self, p: &NodeRef<K, V>) {
        let r = p
            .borrow()
            .right
            .clone()
            .expect("rotateLeft requires a right child");
        let r_left = r.borrow().left.clone();

        p.borrow_mut().right = r_left.clone();
        if let Some(rl) = &r_left {
            rl.borrow_mut().parent = Some(Rc::downgrade(p));
        }

        let p_parent_weak = p.borrow().parent.clone();
        let p_parent = p_parent_weak.clone().and_then(|w| w.upgrade());
        r.borrow_mut().parent = p_parent_weak;

        match &p_parent {
            None => self.root = Some(r.clone()),
            Some(pp) => {
                let is_left = pp.borrow().left.as_ref().is_some_and(|l| Rc::ptr_eq(l, p));
                if is_left {
                    pp.borrow_mut().left = Some(r.clone());
                } else {
                    pp.borrow_mut().right = Some(r.clone());
                }
            }
        }

        r.borrow_mut().left = Some(p.clone());
        p.borrow_mut().parent = Some(Rc::downgrade(&r));
    }

    /// From CLR.
    fn rotate_right(&mut self, p: &NodeRef<K, V>) {
        let l = p
            .borrow()
            .left
            .clone()
            .expect("rotateRight requires a left child");
        let l_right = l.borrow().right.clone();

        p.borrow_mut().left = l_right.clone();
        if let Some(lr) = &l_right {
            lr.borrow_mut().parent = Some(Rc::downgrade(p));
        }

        let p_parent_weak = p.borrow().parent.clone();
        let p_parent = p_parent_weak.clone().and_then(|w| w.upgrade());
        l.borrow_mut().parent = p_parent_weak;

        match &p_parent {
            None => self.root = Some(l.clone()),
            Some(pp) => {
                let is_right = pp.borrow().right.as_ref().is_some_and(|r| Rc::ptr_eq(r, p));
                if is_right {
                    pp.borrow_mut().right = Some(l.clone());
                } else {
                    pp.borrow_mut().left = Some(l.clone());
                }
            }
        }

        l.borrow_mut().right = Some(p.clone());
        p.borrow_mut().parent = Some(Rc::downgrade(&l));
    }

    /// From CLR.
    fn fix_after_insertion(&mut self, x_node: NodeRef<K, V>) {
        x_node.borrow_mut().color = Some(NodeColor::Red);

        let mut x: Option<NodeRef<K, V>> = Some(x_node);

        while x.is_some()
            && !self.is_root(&x)
            && Self::color_of(&Self::parent_of(&x)) == NodeColor::Red
        {
            let parent_x = Self::parent_of(&x);
            let grandparent = Self::parent_of(&parent_x);

            if Self::same(&parent_x, &Self::left_of(&grandparent)) {
                let y = Self::right_of(&grandparent);
                if Self::color_of(&y) == NodeColor::Red {
                    Self::set_color(&parent_x, NodeColor::Black);
                    Self::set_color(&y, NodeColor::Black);
                    Self::set_color(&grandparent, NodeColor::Red);
                    x = grandparent;
                } else {
                    if Self::same(&x, &Self::right_of(&parent_x)) {
                        x = parent_x.clone();
                        self.rotate_left(x.as_ref().unwrap());
                    }
                    let parent_x2 = Self::parent_of(&x);
                    Self::set_color(&parent_x2, NodeColor::Black);
                    let grandparent2 = Self::parent_of(&parent_x2);
                    Self::set_color(&grandparent2, NodeColor::Red);
                    if let Some(gp2) = &grandparent2 {
                        self.rotate_right(gp2);
                    }
                }
            } else {
                let y = Self::left_of(&grandparent);
                if Self::color_of(&y) == NodeColor::Red {
                    Self::set_color(&parent_x, NodeColor::Black);
                    Self::set_color(&y, NodeColor::Black);
                    Self::set_color(&grandparent, NodeColor::Red);
                    x = grandparent;
                } else {
                    if Self::same(&x, &Self::left_of(&parent_x)) {
                        x = parent_x.clone();
                        self.rotate_right(x.as_ref().unwrap());
                    }
                    let parent_x2 = Self::parent_of(&x);
                    Self::set_color(&parent_x2, NodeColor::Black);
                    let grandparent2 = Self::parent_of(&parent_x2);
                    Self::set_color(&grandparent2, NodeColor::Red);
                    if let Some(gp2) = &grandparent2 {
                        self.rotate_left(gp2);
                    }
                }
            }
        }

        if let Some(root) = &self.root {
            root.borrow_mut().color = Some(NodeColor::Black);
        }
    }

    /// Delete node `p`, and then rebalance the tree.
    fn delete_entry(&mut self, p: NodeRef<K, V>) {
        self.size -= 1;

        if Self::same(&Some(p.clone()), &self.min_entry) {
            self.min_entry = RedBlackEntry::get_successor(&p);
        }
        if Self::same(&Some(p.clone()), &self.max_entry) {
            self.max_entry = RedBlackEntry::get_predecessor(&p);
        }

        // If strictly internal, first swap position with successor.
        let has_both_children = p.borrow().left.is_some() && p.borrow().right.is_some();
        if has_both_children {
            let successor =
                RedBlackEntry::get_successor(&p).expect("internal node has a successor");
            self.swap_position(&successor, &p);
        }

        // Start fixup at replacement node, if it exists.
        let replacement = {
            let b = p.borrow();
            if b.left.is_some() {
                b.left.clone()
            } else {
                b.right.clone()
            }
        };

        if let Some(replacement) = replacement {
            // Link replacement to parent.
            replacement.borrow_mut().parent = p.borrow().parent.clone();
            let p_parent = Self::parent_of(&Some(p.clone()));
            match &p_parent {
                None => self.root = Some(replacement.clone()),
                Some(pp) => {
                    if RedBlackEntry::is_left_child(&p) {
                        pp.borrow_mut().left = Some(replacement.clone());
                    } else {
                        pp.borrow_mut().right = Some(replacement.clone());
                    }
                }
            }

            // Null out links so they are OK to use by fix_after_deletion.
            p.borrow_mut().left = None;
            p.borrow_mut().right = None;
            p.borrow_mut().parent = None;

            // Fix replacement.
            if p.borrow().color == Some(NodeColor::Black) {
                self.fix_after_deletion(replacement);
            }
        } else if p.borrow().parent.is_none() {
            // We are the only node.
            self.root = None;
        } else {
            // No children. Use self as phantom replacement and unlink.
            if p.borrow().color == Some(NodeColor::Black) {
                self.fix_after_deletion(p.clone());
            }

            let p_parent = Self::parent_of(&Some(p.clone()));
            if let Some(pp) = p_parent {
                if RedBlackEntry::is_left_child(&p) {
                    pp.borrow_mut().left = None;
                } else if RedBlackEntry::is_right_child(&p) {
                    pp.borrow_mut().right = None;
                }
                p.borrow_mut().parent = None;
            }
        }

        p.borrow_mut().color = None; // Mark disposed.
    }

    /// From CLR.
    fn fix_after_deletion(&mut self, x_node: NodeRef<K, V>) {
        let mut x = Some(x_node);

        while !self.is_root(&x) && Self::color_of(&x) == NodeColor::Black {
            let parent_x = Self::parent_of(&x);

            if Self::same(&x, &Self::left_of(&parent_x)) {
                let mut sib = Self::right_of(&parent_x);

                if Self::color_of(&sib) == NodeColor::Red {
                    Self::set_color(&sib, NodeColor::Black);
                    Self::set_color(&parent_x, NodeColor::Red);
                    self.rotate_left(parent_x.as_ref().unwrap());
                    sib = Self::right_of(&parent_x);
                }

                if Self::color_of(&Self::left_of(&sib)) == NodeColor::Black
                    && Self::color_of(&Self::right_of(&sib)) == NodeColor::Black
                {
                    Self::set_color(&sib, NodeColor::Red);
                    x = parent_x;
                } else {
                    if Self::color_of(&Self::right_of(&sib)) == NodeColor::Black {
                        Self::set_color(&Self::left_of(&sib), NodeColor::Black);
                        Self::set_color(&sib, NodeColor::Red);
                        self.rotate_right(sib.as_ref().unwrap());
                        sib = Self::right_of(&parent_x);
                    }
                    Self::set_color(&sib, Self::color_of(&parent_x));
                    Self::set_color(&parent_x, NodeColor::Black);
                    Self::set_color(&Self::right_of(&sib), NodeColor::Black);
                    self.rotate_left(parent_x.as_ref().unwrap());
                    x = self.root.clone();
                }
            } else {
                let mut sib = Self::left_of(&parent_x);

                if Self::color_of(&sib) == NodeColor::Red {
                    Self::set_color(&sib, NodeColor::Black);
                    Self::set_color(&parent_x, NodeColor::Red);
                    self.rotate_right(parent_x.as_ref().unwrap());
                    sib = Self::left_of(&parent_x);
                }

                if Self::color_of(&Self::right_of(&sib)) == NodeColor::Black
                    && Self::color_of(&Self::left_of(&sib)) == NodeColor::Black
                {
                    Self::set_color(&sib, NodeColor::Red);
                    x = parent_x;
                } else {
                    if Self::color_of(&Self::left_of(&sib)) == NodeColor::Black {
                        Self::set_color(&Self::right_of(&sib), NodeColor::Black);
                        Self::set_color(&sib, NodeColor::Red);
                        self.rotate_left(sib.as_ref().unwrap());
                        sib = Self::left_of(&parent_x);
                    }
                    Self::set_color(&sib, Self::color_of(&parent_x));
                    Self::set_color(&parent_x, NodeColor::Black);
                    Self::set_color(&Self::left_of(&sib), NodeColor::Black);
                    self.rotate_right(parent_x.as_ref().unwrap());
                    x = self.root.clone();
                }
            }
        }

        Self::set_color(&x, NodeColor::Black);
    }

    /// Swap the linkages of two nodes in the tree.
    fn swap_position(&mut self, x: &NodeRef<K, V>, y: &NodeRef<K, V>) {
        // Save initial values.
        let px = Self::parent_of(&Some(x.clone()));
        let lx = Self::left_of(&Some(x.clone()));
        let rx = Self::right_of(&Some(x.clone()));
        let py = Self::parent_of(&Some(y.clone()));
        let ly = Self::left_of(&Some(y.clone()));
        let ry = Self::right_of(&Some(y.clone()));
        let x_was_left_child = RedBlackEntry::is_left_child(x);
        let y_was_left_child = RedBlackEntry::is_left_child(y);

        // Swap, handling special cases of one being the other's parent.
        if Self::same(&Some(x.clone()), &py) {
            // x was y's parent.
            x.borrow_mut().parent = Some(Rc::downgrade(y));
            if y_was_left_child {
                y.borrow_mut().left = Some(x.clone());
                y.borrow_mut().right = rx.clone();
            } else {
                y.borrow_mut().right = Some(x.clone());
                y.borrow_mut().left = lx.clone();
            }
        } else {
            x.borrow_mut().parent = py.as_ref().map(Rc::downgrade);
            if let Some(pyn) = &py {
                if y_was_left_child {
                    pyn.borrow_mut().left = Some(x.clone());
                } else {
                    pyn.borrow_mut().right = Some(x.clone());
                }
            }
            y.borrow_mut().left = lx.clone();
            y.borrow_mut().right = rx.clone();
        }

        if Self::same(&Some(y.clone()), &px) {
            // y was x's parent.
            y.borrow_mut().parent = Some(Rc::downgrade(x));
            if x_was_left_child {
                x.borrow_mut().left = Some(y.clone());
                x.borrow_mut().right = ry.clone();
            } else {
                x.borrow_mut().right = Some(y.clone());
                x.borrow_mut().left = ly.clone();
            }
        } else {
            y.borrow_mut().parent = px.as_ref().map(Rc::downgrade);
            if let Some(pxn) = &px {
                if x_was_left_child {
                    pxn.borrow_mut().left = Some(y.clone());
                } else {
                    pxn.borrow_mut().right = Some(y.clone());
                }
            }
            x.borrow_mut().left = ly.clone();
            x.borrow_mut().right = ry.clone();
        }

        // Fix children's parent pointers.
        let x_left = x.borrow().left.clone();
        if let Some(l) = &x_left {
            l.borrow_mut().parent = Some(Rc::downgrade(x));
        }
        let x_right = x.borrow().right.clone();
        if let Some(r) = &x_right {
            r.borrow_mut().parent = Some(Rc::downgrade(x));
        }
        let y_left = y.borrow().left.clone();
        if let Some(l) = &y_left {
            l.borrow_mut().parent = Some(Rc::downgrade(y));
        }
        let y_right = y.borrow().right.clone();
        if let Some(r) = &y_right {
            r.borrow_mut().parent = Some(Rc::downgrade(y));
        }

        // Swap colors.
        let cx = x.borrow().color;
        let cy = y.borrow().color;
        x.borrow_mut().color = cy;
        y.borrow_mut().color = cx;

        // Check if root changed.
        if Self::same(&self.root, &Some(x.clone())) {
            self.root = Some(y.clone());
        } else if Self::same(&self.root, &Some(y.clone())) {
            self.root = Some(x.clone());
        }
    }
}

impl<K: Ord, V: Default> RedBlackTree<K, V> {
    /// Returns the entry for `key`, creating one with a default value if absent.
    pub fn get_or_create_entry(&mut self, key: K) -> NodeRef<K, V> {
        if self.root.is_none() {
            self.size += 1;
            let node = RedBlackEntry::new(key, V::default(), None);
            self.root = Some(node.clone());
            self.max_entry = Some(node.clone());
            self.min_entry = Some(node.clone());
            return node;
        }

        let max_key_exceeded = {
            let max = self.max_entry.as_ref().unwrap();
            key.cmp(max.borrow().get_key()) == Ordering::Greater
        };
        if max_key_exceeded {
            self.size += 1;
            let max = self.max_entry.clone().unwrap();
            let new_node = RedBlackEntry::new(key, V::default(), Some(Rc::downgrade(&max)));
            max.borrow_mut().right = Some(new_node.clone());
            self.max_entry = Some(new_node.clone());
            self.fix_after_insertion(new_node.clone());
            return new_node;
        }

        let mut node = self.root.clone().unwrap();
        loop {
            let comp = key.cmp(node.borrow().get_key());
            match comp {
                Ordering::Equal => return node,
                Ordering::Less => {
                    let left = node.borrow().left.clone();
                    match left {
                        Some(l) => node = l,
                        None => {
                            self.size += 1;
                            let new_node =
                                RedBlackEntry::new(key, V::default(), Some(Rc::downgrade(&node)));
                            node.borrow_mut().left = Some(new_node.clone());
                            if Self::same(&Some(node.clone()), &self.min_entry) {
                                self.min_entry = Some(new_node.clone());
                            }
                            self.fix_after_insertion(new_node.clone());
                            return new_node;
                        }
                    }
                }
                Ordering::Greater => {
                    let right = node.borrow().right.clone();
                    match right {
                        Some(r) => node = r,
                        None => {
                            self.size += 1;
                            let new_node =
                                RedBlackEntry::new(key, V::default(), Some(Rc::downgrade(&node)));
                            node.borrow_mut().right = Some(new_node.clone());
                            if Self::same(&Some(node.clone()), &self.max_entry) {
                                self.max_entry = Some(new_node.clone());
                            }
                            self.fix_after_insertion(new_node.clone());
                            return new_node;
                        }
                    }
                }
            }
        }
    }

    /// Adds `key`/`value` to the tree. If the key already exists, the old value is
    /// replaced and returned.
    pub fn put(&mut self, key: K, value: V) -> V {
        let node = self.get_or_create_entry(key);
        let old_value = node.borrow_mut().set_value(value);
        old_value
    }
}

impl<K: Ord, V: Clone> RedBlackTree<K, V> {
    /// Removes the entry for `key`, returning its value if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let node = self.get_node(key)?;
        let value = node.borrow().get_value().clone();
        self.delete_entry(node);
        Some(value)
    }
}

/// A forward- or backward-moving iterator over [`RedBlackTree`] entries.
///
/// Created via [`RedBlackTree::iter`], [`RedBlackTree::iter_dir`],
/// [`RedBlackTree::iter_from`], or [`RedBlackTree::iter_by_key`].
pub struct RedBlackTreeIter<K, V> {
    next: Option<NodeRef<K, V>>,
    forward: bool,
}

impl<K, V> Iterator for RedBlackTreeIter<K, V> {
    type Item = NodeRef<K, V>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next.take()?;
        self.next = if self.forward {
            RedBlackEntry::get_successor(&current)
        } else {
            RedBlackEntry::get_predecessor(&current)
        };
        Some(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tree_is_empty() {
        let t: RedBlackTree<i32, &str> = RedBlackTree::new();
        assert!(t.is_empty());
        assert_eq!(t.size(), 0);
        assert!(t.get_first().is_none());
        assert!(t.get_last().is_none());
    }

    #[test]
    fn default_equals_new() {
        let t: RedBlackTree<i32, &str> = Default::default();
        assert!(t.is_empty());
    }

    #[test]
    fn put_and_get_single_entry() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        t.put(5, "five");
        assert_eq!(t.size(), 1);
        assert!(t.contains_key(&5));
        let entry = t.get_entry(&5).unwrap();
        assert_eq!(*entry.borrow().get_value(), "five");
    }

    #[test]
    fn put_replacing_key_returns_old_value() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        let old = t.put(5, "five");
        assert_eq!(old, "");
        let old2 = t.put(5, "FIVE");
        assert_eq!(old2, "five");
        assert_eq!(t.size(), 1);
        assert_eq!(*t.get_entry(&5).unwrap().borrow().get_value(), "FIVE");
    }

    #[test]
    fn contains_key_false_for_missing() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        t.put(1, "a");
        assert!(!t.contains_key(&2));
    }

    #[test]
    fn get_first_and_last_track_extremes() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        for k in [5, 1, 9, 3, 7] {
            t.put(k, "v");
        }
        assert_eq!(*t.get_first().unwrap().borrow().get_key(), 1);
        assert_eq!(*t.get_last().unwrap().borrow().get_key(), 9);
    }

    #[test]
    fn get_entry_less_than_equal_and_greater_than_equal() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        for k in [1, 3, 5, 7, 9] {
            t.put(k, "v");
        }
        assert_eq!(
            *t.get_entry_less_than_equal(&6).unwrap().borrow().get_key(),
            5
        );
        assert_eq!(
            *t.get_entry_less_than_equal(&5).unwrap().borrow().get_key(),
            5
        );
        assert!(t.get_entry_less_than_equal(&0).is_none());

        assert_eq!(
            *t.get_entry_greater_than_equal(&6)
                .unwrap()
                .borrow()
                .get_key(),
            7
        );
        assert_eq!(
            *t.get_entry_greater_than_equal(&5)
                .unwrap()
                .borrow()
                .get_key(),
            5
        );
        assert!(t.get_entry_greater_than_equal(&10).is_none());
    }

    #[test]
    fn remove_existing_key_returns_value() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        t.put(1, "a");
        t.put(2, "b");
        let removed = t.remove(&1);
        assert_eq!(removed, Some("a"));
        assert!(!t.contains_key(&1));
        assert_eq!(t.size(), 1);
    }

    #[test]
    fn remove_missing_key_returns_none() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        t.put(1, "a");
        assert_eq!(t.remove(&99), None);
        assert_eq!(t.size(), 1);
    }

    #[test]
    fn remove_all_clears_tree() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        for k in [1, 2, 3] {
            t.put(k, "v");
        }
        t.remove_all();
        assert!(t.is_empty());
        assert_eq!(t.size(), 0);
        assert!(t.get_last().is_none());
    }

    #[test]
    fn forward_iteration_is_sorted() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        for k in [5, 1, 9, 3, 7, 2, 8, 4, 6] {
            t.put(k, "v");
        }
        let keys: Vec<i32> = t.iter().map(|n| *n.borrow().get_key()).collect();
        assert_eq!(keys, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn backward_iteration_is_reverse_sorted() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        for k in [5, 1, 9, 3, 7, 2, 8, 4, 6] {
            t.put(k, "v");
        }
        let keys: Vec<i32> = t.iter_dir(false).map(|n| *n.borrow().get_key()).collect();
        assert_eq!(keys, vec![9, 8, 7, 6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn iter_by_key_forward_starts_at_or_after_key() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        for k in [1, 3, 5, 7, 9] {
            t.put(k, "v");
        }
        let keys: Vec<i32> = t
            .iter_by_key(&4, true)
            .map(|n| *n.borrow().get_key())
            .collect();
        assert_eq!(keys, vec![5, 7, 9]);
    }

    #[test]
    fn iter_by_key_backward_starts_at_or_before_key() {
        let mut t: RedBlackTree<i32, &str> = RedBlackTree::new();
        for k in [1, 3, 5, 7, 9] {
            t.put(k, "v");
        }
        let keys: Vec<i32> = t
            .iter_by_key(&6, false)
            .map(|n| *n.borrow().get_key())
            .collect();
        assert_eq!(keys, vec![5, 3, 1]);
    }

    /// Verifies the standard red-black invariants: a black root, no red node with a
    /// red child, and equal black-height on every root-to-leaf path.
    fn assert_red_black_invariants<V>(tree: &RedBlackTree<i32, V>) {
        if let Some(root) = &tree.root {
            assert_eq!(root.borrow().color, Some(NodeColor::Black));
        }
        fn check<V>(node: &Option<NodeRef<i32, V>>) -> usize {
            match node {
                None => 1,
                Some(n) => {
                    let b = n.borrow();
                    let color = b.color.expect("live node must have a color");
                    if color == NodeColor::Red {
                        for child in [&b.left, &b.right] {
                            if let Some(c) = child {
                                assert_ne!(
                                    c.borrow().color,
                                    Some(NodeColor::Red),
                                    "red node has red child"
                                );
                            }
                        }
                    }
                    let left_height = check(&b.left);
                    let right_height = check(&b.right);
                    assert_eq!(left_height, right_height, "black-height mismatch");
                    left_height + if color == NodeColor::Black { 1 } else { 0 }
                }
            }
        }
        check(&tree.root);
    }

    #[test]
    fn ascending_insertion_stress_maintains_invariants() {
        let mut t: RedBlackTree<i32, i32> = RedBlackTree::new();
        for k in 0..200 {
            t.put(k, k);
        }
        assert_red_black_invariants(&t);
        let keys: Vec<i32> = t.iter().map(|n| *n.borrow().get_key()).collect();
        let expected: Vec<i32> = (0..200).collect();
        assert_eq!(keys, expected);
    }

    #[test]
    fn descending_insertion_stress_maintains_invariants() {
        let mut t: RedBlackTree<i32, i32> = RedBlackTree::new();
        for k in (0..200).rev() {
            t.put(k, k);
        }
        assert_red_black_invariants(&t);
        let keys: Vec<i32> = t.iter().map(|n| *n.borrow().get_key()).collect();
        let expected: Vec<i32> = (0..200).collect();
        assert_eq!(keys, expected);
    }

    #[test]
    fn remove_internal_node_with_two_children_preserves_order() {
        let mut t: RedBlackTree<i32, i32> = RedBlackTree::new();
        for k in [5, 3, 8, 1, 4, 7, 9, 2, 6] {
            t.put(k, k);
        }
        // 5 has two children; removing it exercises swap_position.
        assert_eq!(t.remove(&5), Some(5));
        assert_red_black_invariants(&t);
        let keys: Vec<i32> = t.iter().map(|n| *n.borrow().get_key()).collect();
        assert_eq!(keys, vec![1, 2, 3, 4, 6, 7, 8, 9]);
    }

    #[test]
    fn removing_all_elements_one_by_one_maintains_invariants() {
        let mut t: RedBlackTree<i32, i32> = RedBlackTree::new();
        let mut keys: Vec<i32> = (0..100).collect();
        for &k in &keys {
            t.put(k, k);
        }
        // Remove in a shuffled-ish order (interleaved) to exercise more shapes.
        let mut order: Vec<i32> = Vec::new();
        let (mut lo, mut hi) = (0, 99);
        while lo <= hi {
            order.push(lo);
            if hi != lo {
                order.push(hi);
            }
            lo += 1;
            if hi == 0 {
                break;
            }
            hi -= 1;
        }
        for k in order {
            assert_eq!(t.remove(&k), Some(k));
            assert_red_black_invariants(&t);
        }
        assert!(t.is_empty());
        keys.clear();
        assert!(t.iter().next().is_none());
    }

    #[test]
    fn get_or_create_entry_reuses_existing_node() {
        let mut t: RedBlackTree<i32, i32> = RedBlackTree::new();
        let n1 = t.get_or_create_entry(5);
        n1.borrow_mut().set_value(42);
        let n2 = t.get_or_create_entry(5);
        assert!(Rc::ptr_eq(&n1, &n2));
        assert_eq!(*n2.borrow().get_value(), 42);
        assert_eq!(t.size(), 1);
    }

    #[test]
    fn remove_node_by_reference() {
        let mut t: RedBlackTree<i32, i32> = RedBlackTree::new();
        t.put(1, 1);
        t.put(2, 2);
        let entry = t.get_entry(&2).unwrap();
        t.remove_node(&entry);
        assert!(!t.contains_key(&2));
        assert_eq!(t.size(), 1);
    }
}
