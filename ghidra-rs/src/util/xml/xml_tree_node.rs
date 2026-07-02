use super::xml_element::XmlElement;
use super::xml_exception::XmlException;
use super::xml_pull_parser::XmlPullParser;

/// A node representing a corresponding start and end tag, and its children. This is one
/// node on the XML parse tree.
///
/// Port of `ghidra.xml.XmlTreeNode`.
pub(crate) struct XmlTreeNode<E: XmlElement> {
    start_element: E,
    end_element: E,
    children: Vec<XmlTreeNode<E>>,
}

impl<E: XmlElement> XmlTreeNode<E> {
    /// Constructs a new XML tree node given the specified parser.
    ///
    /// Returns an [`XmlException`] if an XML parser error occurs.
    pub(crate) fn new<P>(parser: &mut P) -> Result<Self, XmlException>
    where
        P: XmlPullParser<Element = E>,
    {
        let mut children = Vec::new();
        let start_element = parser.start(&[])?;
        while parser.has_next() && parser.peek().is_start() {
            children.push(XmlTreeNode::new(parser)?);
        }
        let end_element = parser.end_matching(&start_element)?;
        Ok(Self { start_element, end_element, children })
    }

    /// Returns the start element of this node.
    pub(crate) fn get_start_element(&self) -> &E {
        &self.start_element
    }

    /// Returns the end element of this node.
    pub(crate) fn get_end_element(&self) -> &E {
        &self.end_element
    }

    /// Returns the number of children below this node.
    pub(crate) fn get_child_count(&self) -> i32 {
        self.children.len() as i32
    }

    /// Returns an iterator over all of the children of this node.
    pub(crate) fn get_children(&self) -> impl Iterator<Item = &XmlTreeNode<E>> {
        self.children.iter()
    }

    /// Returns an iterator over all of the children of this node with the specified name.
    pub(crate) fn get_children_named<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a XmlTreeNode<E>> {
        self.children.iter().filter(move |child| child.start_element.get_name() == name)
    }

    /// Returns the first child element with the specified name.
    pub(crate) fn get_child<'a>(&'a self, name: &'a str) -> Option<&'a XmlTreeNode<E>> {
        self.get_children_named(name).next()
    }

    /// Returns the child at the given index.
    pub(crate) fn get_child_at(&self, index: usize) -> &XmlTreeNode<E> {
        &self.children[index]
    }

    /// Deletes the specified child node.
    pub(crate) fn delete_child_node(&mut self, node: &XmlTreeNode<E>) {
        if let Some(pos) = self.children.iter().position(|child| std::ptr::eq(child, node)) {
            self.children.remove(pos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xml::xml_element_impl::XmlElementImpl;

    struct QueueParser {
        elements: Vec<XmlElementImpl>,
        pos: usize,
    }

    impl QueueParser {
        fn new(elements: Vec<XmlElementImpl>) -> Self {
            Self { elements, pos: 0 }
        }
    }

    impl XmlPullParser for QueueParser {
        type Element = XmlElementImpl;

        fn get_name(&self) -> &str {
            "queue"
        }

        fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
            None
        }

        fn get_line_number(&self) -> i32 {
            -1
        }

        fn get_column_number(&self) -> i32 {
            -1
        }

        fn is_pulling_content(&self) -> bool {
            false
        }

        fn set_pulling_content(&mut self, _pulling_content: bool) {}

        fn get_current_level(&self) -> i32 {
            if self.has_next() {
                self.peek().get_level()
            } else {
                -1
            }
        }

        fn has_next(&self) -> bool {
            self.pos < self.elements.len()
        }

        fn peek(&self) -> XmlElementImpl {
            self.elements[self.pos].clone()
        }

        fn next(&mut self) -> XmlElementImpl {
            let elem = self.elements[self.pos].clone();
            self.pos += 1;
            elem
        }

        fn start(&mut self, names: &[&str]) -> Result<XmlElementImpl, XmlException> {
            if !self.has_next() {
                return Err(XmlException::with_message("at EOF but expected start element"));
            }
            let next = self.next();
            if !next.is_start() {
                return Err(XmlException::with_message("expected start element"));
            }
            let found = names.is_empty() || names.iter().any(|n| *n == next.get_name());
            if !found {
                return Err(XmlException::with_message("start element name mismatch"));
            }
            Ok(next)
        }

        fn end(&mut self) -> Result<XmlElementImpl, XmlException> {
            if !self.has_next() {
                return Err(XmlException::with_message("at EOF but expected end element"));
            }
            let next = self.next();
            if !next.is_end() {
                return Err(XmlException::with_message("expected end element"));
            }
            Ok(next)
        }

        fn end_matching(
            &mut self,
            element: &XmlElementImpl,
        ) -> Result<XmlElementImpl, XmlException> {
            let name = element.get_name();
            if !self.has_next() {
                return Err(XmlException::with_message("at EOF but expected end element"));
            }
            let next = self.next();
            if next.get_name() != name || !next.is_end() {
                return Err(XmlException::with_message("end element name mismatch"));
            }
            Ok(next)
        }

        fn soft_start(&mut self, names: &[&str]) -> Option<XmlElementImpl> {
            if !self.has_next() {
                return None;
            }
            let peek = self.peek();
            if !peek.is_start() {
                return None;
            }
            let found = names.is_empty() || names.iter().any(|n| *n == peek.get_name());
            if !found {
                return None;
            }
            Some(self.next())
        }

        fn discard_sub_tree(&mut self) -> i32 {
            0
        }

        fn discard_sub_tree_named(&mut self, _name: &str) -> Result<i32, XmlException> {
            Ok(0)
        }

        fn discard_sub_tree_element(&mut self, _element: &XmlElementImpl) -> i32 {
            0
        }

        fn dispose(&mut self) {}
    }

    fn start(name: &str, level: i32) -> XmlElementImpl {
        XmlElementImpl::new(true, false, name, level, Vec::new(), None, 0, 0).unwrap()
    }

    fn end(name: &str, level: i32) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, level, Vec::new(), None, 0, 0).unwrap()
    }

    #[test]
    fn leaf_node_has_no_children() {
        let mut parser = QueueParser::new(vec![start("root", 0), end("root", 0)]);
        let node = XmlTreeNode::new(&mut parser).unwrap();
        assert_eq!(node.get_child_count(), 0);
        assert_eq!(node.get_start_element().get_name(), "root");
        assert_eq!(node.get_end_element().get_name(), "root");
    }

    #[test]
    fn parses_nested_children() {
        let mut parser = QueueParser::new(vec![
            start("root", 0),
            start("a", 1),
            end("a", 1),
            start("b", 1),
            start("c", 2),
            end("c", 2),
            end("b", 1),
            end("root", 0),
        ]);
        let node = XmlTreeNode::new(&mut parser).unwrap();
        assert_eq!(node.get_child_count(), 2);

        let names: Vec<&str> =
            node.get_children().map(|c| c.get_start_element().get_name()).collect();
        assert_eq!(names, vec!["a", "b"]);

        let b = node.get_child("b").unwrap();
        assert_eq!(b.get_child_count(), 1);
        assert_eq!(b.get_child_at(0).get_start_element().get_name(), "c");
    }

    #[test]
    fn get_children_named_filters_by_name() {
        let mut parser = QueueParser::new(vec![
            start("root", 0),
            start("item", 1),
            end("item", 1),
            start("other", 1),
            end("other", 1),
            start("item", 1),
            end("item", 1),
            end("root", 0),
        ]);
        let node = XmlTreeNode::new(&mut parser).unwrap();
        let count = node.get_children_named("item").count();
        assert_eq!(count, 2);
    }

    #[test]
    fn get_child_returns_none_when_missing() {
        let mut parser = QueueParser::new(vec![start("root", 0), end("root", 0)]);
        let node = XmlTreeNode::new(&mut parser).unwrap();
        assert!(node.get_child("missing").is_none());
    }

    #[test]
    fn mismatched_end_tag_returns_error() {
        let mut parser = QueueParser::new(vec![start("root", 0), end("wrong", 0)]);
        assert!(XmlTreeNode::new(&mut parser).is_err());
    }

    #[test]
    fn delete_child_node_removes_matching_child() {
        let mut parser = QueueParser::new(vec![
            start("root", 0),
            start("a", 1),
            end("a", 1),
            start("b", 1),
            end("b", 1),
            end("root", 0),
        ]);
        let mut node = XmlTreeNode::new(&mut parser).unwrap();
        assert_eq!(node.get_child_count(), 2);

        let a_ptr: *const XmlTreeNode<XmlElementImpl> = node.get_child_at(0);
        let a_clone_start = node.get_child_at(0).get_start_element().get_name().to_string();
        assert_eq!(a_clone_start, "a");

        // SAFETY: `a_ptr` is only used to locate the child by identity before removal.
        let a_ref = unsafe { &*a_ptr };
        node.delete_child_node(a_ref);

        assert_eq!(node.get_child_count(), 1);
        assert_eq!(node.get_child_at(0).get_start_element().get_name(), "b");
    }
}
