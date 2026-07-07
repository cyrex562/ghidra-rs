use super::ByteTrieNodeIfc;

/// Visitor callback for [`ByteTrie`] traversal.
///
/// Implement this trait to perform an operation on each node visited during
/// trie traversal.  Mirrors `ghidra.util.search.trie.Op`.
pub trait Op<T> {
    /// Perform an operation on `node`.
    fn op(&mut self, node: &dyn ByteTrieNodeIfc<T>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::search::trie::{ByteTrieNode, NodeRef};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct TerminalCounter(usize);

    impl Op<u32> for TerminalCounter {
        fn op(&mut self, node: &dyn ByteTrieNodeIfc<u32>) {
            if node.is_terminal() {
                self.0 += 1;
            }
        }
    }

    fn make_root() -> NodeRef<u32> {
        Rc::new(RefCell::new(ByteTrieNode::new(0, None, 0)))
    }

    #[test]
    fn op_on_non_terminal_node_is_not_counted() {
        let root = make_root();
        let mut counter = TerminalCounter(0);
        counter.op(&*root.borrow() as &dyn ByteTrieNodeIfc<u32>);
        assert_eq!(counter.0, 0);
    }

    #[test]
    fn op_on_terminal_node_increments_counter() {
        let root = make_root();
        root.borrow_mut().set_terminal(42u32);
        let mut counter = TerminalCounter(0);
        counter.op(&*root.borrow() as &dyn ByteTrieNodeIfc<u32>);
        assert_eq!(counter.0, 1);
    }

    #[test]
    fn op_receives_correct_item_from_terminal_node() {
        let root = make_root();
        root.borrow_mut().set_terminal(99u32);

        struct ItemCollector(Vec<u32>);
        impl Op<u32> for ItemCollector {
            fn op(&mut self, node: &dyn ByteTrieNodeIfc<u32>) {
                if let Some(&v) = node.get_item() {
                    self.0.push(v);
                }
            }
        }

        let mut collector = ItemCollector(vec![]);
        collector.op(&*root.borrow() as &dyn ByteTrieNodeIfc<u32>);
        assert_eq!(collector.0, vec![99u32]);
    }

    #[test]
    fn multiple_op_calls_accumulate() {
        let root = make_root();
        let child_a = Rc::new(RefCell::new(ByteTrieNode::new(b'A', Some(Rc::downgrade(&root)), 1)));
        let child_b = Rc::new(RefCell::new(ByteTrieNode::new(b'B', Some(Rc::downgrade(&root)), 1)));
        child_a.borrow_mut().set_terminal(1u32);
        child_b.borrow_mut().set_terminal(2u32);

        let mut counter = TerminalCounter(0);
        counter.op(&*root.borrow() as &dyn ByteTrieNodeIfc<u32>);
        counter.op(&*child_a.borrow() as &dyn ByteTrieNodeIfc<u32>);
        counter.op(&*child_b.borrow() as &dyn ByteTrieNodeIfc<u32>);
        assert_eq!(counter.0, 2);
    }
}
