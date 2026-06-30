/// Trait for elements that support cut/paste operations.
///
/// Implementors can be marked as "cut" so they can be rendered accordingly
/// while awaiting a paste action.
pub trait Cuttable {
    /// Mark or unmark this element as cut.
    ///
    /// When `is_cut` is `true` the element should be rendered to indicate it
    /// will be moved on the next paste.
    fn set_is_cut(&mut self, is_cut: bool);

    /// Returns `true` if this element is currently marked as cut.
    fn is_cut(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Node {
        cut: bool,
    }

    impl Cuttable for Node {
        fn set_is_cut(&mut self, is_cut: bool) {
            self.cut = is_cut;
        }

        fn is_cut(&self) -> bool {
            self.cut
        }
    }

    #[test]
    fn initially_not_cut() {
        let node = Node { cut: false };
        assert!(!node.is_cut());
    }

    #[test]
    fn set_is_cut_true() {
        let mut node = Node { cut: false };
        node.set_is_cut(true);
        assert!(node.is_cut());
    }

    #[test]
    fn set_is_cut_false_clears_flag() {
        let mut node = Node { cut: true };
        node.set_is_cut(false);
        assert!(!node.is_cut());
    }

    #[test]
    fn trait_is_object_safe() {
        let node = Node { cut: false };
        let _boxed: Box<dyn Cuttable> = Box::new(node);
    }
}
