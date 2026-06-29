/// A tree-structured string builder for efficient concatenation of string fragments.
///
/// Corresponds to `ghidra.pcode.struct.StringTree`.
pub struct StringTree {
    root: Branch,
}

enum Node {
    Branch(Branch),
    Leaf(String),
}

struct Branch {
    children: Vec<Node>,
}

impl Branch {
    fn new() -> Self {
        Self { children: Vec::new() }
    }

    fn walk(&self, buf: &mut String) {
        for child in &self.children {
            match child {
                Node::Branch(b) => b.walk(buf),
                Node::Leaf(s) => buf.push_str(s),
            }
        }
    }
}

impl StringTree {
    pub fn new() -> Self {
        Self { root: Branch::new() }
    }

    /// Creates a `StringTree` containing a single string fragment.
    pub fn single(seq: &str) -> Self {
        let mut st = Self::new();
        st.append(seq);
        st
    }

    /// Appends a string fragment as a leaf node.
    pub fn append(&mut self, seq: &str) {
        self.root.children.push(Node::Leaf(seq.to_string()));
    }

    /// Merges another `StringTree` into this one by adopting its root as a child branch.
    pub fn append_tree(&mut self, tree: StringTree) {
        self.root.children.push(Node::Branch(tree.root));
    }
}

impl Default for StringTree {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for StringTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = String::new();
        self.root.walk(&mut buf);
        f.write_str(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_produces_correct_string() {
        let st = StringTree::single("hello");
        assert_eq!(st.to_string(), "hello");
    }

    #[test]
    fn append_multiple_fragments() {
        let mut st = StringTree::new();
        st.append("foo");
        st.append("bar");
        st.append("baz");
        assert_eq!(st.to_string(), "foobarbaz");
    }

    #[test]
    fn append_tree_merges_in_order() {
        let mut a = StringTree::new();
        a.append("hello");

        let mut b = StringTree::new();
        b.append(" world");

        a.append_tree(b);
        assert_eq!(a.to_string(), "hello world");
    }

    #[test]
    fn append_tree_then_more_fragments() {
        let mut a = StringTree::new();
        a.append("a");

        let mut b = StringTree::new();
        b.append("b");
        b.append("c");

        a.append_tree(b);
        a.append("d");
        assert_eq!(a.to_string(), "abcd");
    }

    #[test]
    fn empty_tree_displays_empty_string() {
        let st = StringTree::new();
        assert_eq!(st.to_string(), "");
    }

    #[test]
    fn nested_append_tree() {
        let mut inner = StringTree::new();
        inner.append("inner");

        let mut mid = StringTree::new();
        mid.append("mid-");
        mid.append_tree(inner);

        let mut outer = StringTree::new();
        outer.append("outer-");
        outer.append_tree(mid);

        assert_eq!(outer.to_string(), "outer-mid-inner");
    }

    #[test]
    fn default_is_empty() {
        let st = StringTree::default();
        assert_eq!(st.to_string(), "");
    }
}
