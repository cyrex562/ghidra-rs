//! Port of `ghidra.app.decompiler.ClangNode`.
//!
//! A collection of source code text elements, with associated attributes, grouped in
//! a tree structure.

use crate::program::model::address::Address;

/// A trait for tree-structured source code elements.
///
/// This is a port of the Java interface `ghidra.app.decompiler.ClangNode`, which provides a
/// way to navigate a hierarchy of decompiled source code fragments. Each node represents
/// either a leaf token or a group of tokens, with support for address ranges and parent/child
/// relationships.
///
/// # Bounds
///
/// - `Send + Sync`: Required for thread-safe sharing in concurrent contexts.
/// - `Display`: Implementors must provide a string representation (corresponds to Java's `toString()`).
pub trait ClangNode: Send + Sync + std::fmt::Display {
    /// Get the immediate grouping (parent) containing this text element.
    ///
    /// Corresponds to Java's `ClangNode.Parent()`.
    ///
    /// # Returns
    ///
    /// `Some(&dyn ClangNode)` if this node has a parent, `None` if this is a root node.
    fn parent(&self) -> Option<&dyn ClangNode>;

    /// Get the smallest Program address associated with the code that this text represents.
    ///
    /// Corresponds to Java's `ClangNode.getMinAddress()`.
    ///
    /// # Returns
    ///
    /// The smallest address, or `None` if no address is associated (e.g., for leaf tokens
    /// that are purely structural placeholders).
    fn get_min_address(&self) -> Option<Address>;

    /// Get the largest Program address associated with the code that this text represents.
    ///
    /// Corresponds to Java's `ClangNode.getMaxAddress()`.
    ///
    /// # Returns
    ///
    /// The largest address, or `None` if no address is associated.
    fn get_max_address(&self) -> Option<Address>;

    /// Return the number of immediate child groupings this text breaks up into.
    ///
    /// Corresponds to Java's `ClangNode.numChildren()`.
    fn num_children(&self) -> usize;

    /// Get the i-th child grouping.
    ///
    /// Corresponds to Java's `ClangNode.Child(int)`.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the child to retrieve (0-based).
    ///
    /// # Panics
    ///
    /// If `i` is out of bounds (>= `num_children()`).
    fn child(&self, i: usize) -> &dyn ClangNode;

    /// Get the text representing an entire function of which this is part.
    ///
    /// Corresponds to Java's `ClangNode.getClangFunction()`.
    ///
    /// # Returns
    ///
    /// A boxed trait object representing the containing function.
    fn get_clang_function(&self) -> Box<dyn crate::app::seam_stubs::ClangFunction>;

    /// Flatten this text into a list of tokens (see ClangToken).
    ///
    /// Corresponds to Java's `ClangNode.flatten(List<ClangNode>)`.
    ///
    /// # Arguments
    ///
    /// * `list` - A mutable vector of node references. This method appends all terminal tokens
    ///   from this node (and recursively its children) into the list.
    fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>);

    /// Expose this node as [`std::any::Any`] so callers can recover its concrete type.
    ///
    /// Has no Java counterpart -- Java's `instanceof`/cast checks (e.g. `(ClangTokenGroup)
    /// token.Parent()`, `next instanceof ClangVariableToken`) work directly against the object
    /// graph, but a `&dyn ClangNode` trait object erases that information in Rust. Implementors
    /// return `self`; callers `downcast_ref` to the concrete type they expect.
    fn as_any(&self) -> &dyn std::any::Any;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    // A simple concrete implementation for testing
    struct TestNode {
        name: String,
        min_addr: Option<Address>,
        max_addr: Option<Address>,
        children: Vec<Box<dyn ClangNode>>,
    }

    impl fmt::Display for TestNode {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.name)
        }
    }

    impl ClangNode for TestNode {
        fn parent(&self) -> Option<&dyn ClangNode> {
            None
        }

        fn get_min_address(&self) -> Option<Address> {
            self.min_addr.clone()
        }

        fn get_max_address(&self) -> Option<Address> {
            self.max_addr.clone()
        }

        fn num_children(&self) -> usize {
            self.children.len()
        }

        fn child(&self, i: usize) -> &dyn ClangNode {
            self.children[i].as_ref()
        }

        fn get_clang_function(&self) -> Box<dyn crate::app::seam_stubs::ClangFunction> {
            Box::new(TestFunction)
        }

        fn flatten<'a>(&'a self, list: &mut Vec<&'a dyn ClangNode>) {
            list.push(self);
            for child in &self.children {
                child.flatten(list);
            }
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct TestFunction;

    impl crate::app::seam_stubs::ClangFunction for TestFunction {}

    #[test]
    fn test_display_trait() {
        let node = TestNode {
            name: "test_node".to_string(),
            min_addr: None,
            max_addr: None,
            children: Vec::new(),
        };
        assert_eq!(node.to_string(), "test_node");
    }

    #[test]
    fn test_num_children() {
        let node = TestNode {
            name: "parent".to_string(),
            min_addr: None,
            max_addr: None,
            children: vec![
                Box::new(TestNode {
                    name: "child1".to_string(),
                    min_addr: None,
                    max_addr: None,
                    children: Vec::new(),
                }),
                Box::new(TestNode {
                    name: "child2".to_string(),
                    min_addr: None,
                    max_addr: None,
                    children: Vec::new(),
                }),
            ],
        };
        assert_eq!(node.num_children(), 2);
    }

    #[test]
    fn test_flatten_collects_all_nodes() {
        let child = TestNode {
            name: "child".to_string(),
            min_addr: None,
            max_addr: None,
            children: Vec::new(),
        };
        let parent = TestNode {
            name: "parent".to_string(),
            min_addr: None,
            max_addr: None,
            children: vec![Box::new(child)],
        };

        let mut list = Vec::new();
        parent.flatten(&mut list);
        assert_eq!(list.len(), 2); // parent and child
        assert_eq!(list[0].to_string(), "parent");
        assert_eq!(list[1].to_string(), "child");
    }
}
