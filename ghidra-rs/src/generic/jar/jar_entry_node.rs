use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read};
use std::rc::{Rc, Weak};

/// Shared-ownership reference to a [`JarEntryNode`].
pub type NodeRef = Rc<RefCell<JarEntryNode>>;

/// Weak (non-owning) reference to a [`JarEntryNode`], used for the parent link.
pub type WeakNodeRef = Weak<RefCell<JarEntryNode>>;

/// Supplies jar-entry data for the tree rooted by a [`JarEntryNode`].
///
/// Mirrors the abstract `getJarFile()` override that Java's `JarEntryRootNode`
/// supplies: only the root of a `JarEntryNode` tree holds a concrete jar/zip
/// handle, and every other node reaches it by walking up `parent`.
pub trait JarFileAccess {
    /// Opens a stream over the entry at `path`.
    fn get_input_stream(&self, path: &str) -> io::Result<Box<dyn Read>>;
    /// Returns the last-modified time (in the same units as Java's `JarEntry.getTime()`).
    fn last_modified(&self, path: &str) -> u64;
    /// Returns the uncompressed size of the entry at `path`.
    fn length(&self, path: &str) -> u64;
}

/// A node in a jar's entry tree.
///
/// A node with `child_map == None` represents a file; a node with `child_map ==
/// Some(_)` represents a directory (possibly empty). Mirrors `generic.jar.JarEntryNode`.
pub struct JarEntryNode {
    self_ref: WeakNodeRef,
    parent: Option<WeakNodeRef>,
    name: String,
    child_map: Option<HashMap<String, NodeRef>>,
    jar_file: Option<Rc<dyn JarFileAccess>>,
}

impl JarEntryNode {
    /// Creates a new non-root node with the given `parent` and `name`.
    pub(crate) fn new(parent: Option<&NodeRef>, name: impl Into<String>) -> NodeRef {
        Rc::new_cyclic(|weak| {
            RefCell::new(JarEntryNode {
                self_ref: weak.clone(),
                parent: parent.map(Rc::downgrade),
                name: name.into(),
                child_map: None,
                jar_file: None,
            })
        })
    }

    /// Creates the root node of a tree, backed by `jar_file` for entry data.
    pub fn new_root(name: impl Into<String>, jar_file: Rc<dyn JarFileAccess>) -> NodeRef {
        Rc::new_cyclic(|weak| {
            RefCell::new(JarEntryNode {
                self_ref: weak.clone(),
                parent: None,
                name: name.into(),
                child_map: None,
                jar_file: Some(jar_file),
            })
        })
    }

    /// Looks up an immediate child by name; `"."` returns this node and `".."`
    /// returns the parent. Returns `None` if this node is a file (has no children).
    pub fn get_node(&self, child_name: &str) -> Option<NodeRef> {
        let child_map = self.child_map.as_ref()?;
        if child_name == "." {
            return self.self_ref.upgrade();
        }
        if child_name == ".." {
            return self.parent.as_ref().and_then(|w| w.upgrade());
        }
        child_map.get(child_name).cloned()
    }

    /// Walks `path` one component at a time via [`JarEntryNode::get_node`],
    /// returning `None` as soon as a component is missing.
    pub fn get_node_path(&self, path: &[&str]) -> Option<NodeRef> {
        let mut current = self.self_ref.upgrade();
        for child_name in path {
            let node = current?;
            current = node.borrow().get_node(child_name);
        }
        current
    }

    /// Returns the existing child named `child_name`, creating it (and turning
    /// this node into a directory, if it was not already one) if absent.
    pub(crate) fn create_node(&mut self, child_name: &str) -> NodeRef {
        if let Some(existing) = self.get_node(child_name) {
            return existing;
        }
        let parent = self.self_ref.upgrade();
        let child = JarEntryNode::new(parent.as_ref(), child_name);
        self.child_map
            .get_or_insert_with(HashMap::new)
            .insert(child_name.to_string(), Rc::clone(&child));
        child
    }

    /// Returns the `/`-separated path from the root to this node.
    pub(crate) fn get_path(&self) -> String {
        let parent = match self.parent.as_ref().and_then(|w| w.upgrade()) {
            Some(parent) => parent,
            None => return String::new(),
        };
        let parent_path = parent.borrow().get_path();
        if parent_path.is_empty() {
            self.name.clone()
        } else {
            format!("{}/{}", parent_path, self.name)
        }
    }

    /// Returns this node's children, or `None` if this node is a file.
    pub fn get_children(&self) -> Option<Vec<NodeRef>> {
        self.child_map
            .as_ref()
            .map(|map| map.values().cloned().collect())
    }

    /// Returns this node's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns `true` if this node is a directory (has a child map, even if empty).
    pub fn is_directory(&self) -> bool {
        self.child_map.is_some()
    }

    /// Returns `true` if this node is a file (has no child map).
    pub fn is_file(&self) -> bool {
        self.child_map.is_none()
    }

    /// Returns this node's parent, or `None` if this is the root.
    pub fn parent(&self) -> Option<NodeRef> {
        self.parent.as_ref().and_then(|w| w.upgrade())
    }

    /// Opens a stream over this node's entry data.
    pub fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
        self.jar_file_access().get_input_stream(&self.get_path())
    }

    /// Returns this node's last-modified time.
    pub fn last_modified(&self) -> u64 {
        self.jar_file_access().last_modified(&self.get_path())
    }

    /// Returns this node's uncompressed size.
    pub fn length(&self) -> u64 {
        self.jar_file_access().length(&self.get_path())
    }

    fn jar_file_access(&self) -> Rc<dyn JarFileAccess> {
        if let Some(jar_file) = &self.jar_file {
            return Rc::clone(jar_file);
        }
        let parent = self
            .parent
            .as_ref()
            .and_then(|w| w.upgrade())
            .expect("JarEntryNode has no jar file and no parent");
        let access = parent.borrow().jar_file_access();
        access
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockJarFileAccess {
        modified: HashMap<String, u64>,
        lengths: HashMap<String, u64>,
        contents: HashMap<String, Vec<u8>>,
    }

    impl MockJarFileAccess {
        fn new() -> Self {
            Self {
                modified: HashMap::new(),
                lengths: HashMap::new(),
                contents: HashMap::new(),
            }
        }

        fn with_entry(mut self, path: &str, contents: &[u8], modified: u64) -> Self {
            self.lengths.insert(path.to_string(), contents.len() as u64);
            self.contents.insert(path.to_string(), contents.to_vec());
            self.modified.insert(path.to_string(), modified);
            self
        }
    }

    impl JarFileAccess for MockJarFileAccess {
        fn get_input_stream(&self, path: &str) -> io::Result<Box<dyn Read>> {
            let bytes = self.contents.get(path).cloned().unwrap_or_default();
            Ok(Box::new(io::Cursor::new(bytes)))
        }

        fn last_modified(&self, path: &str) -> u64 {
            *self.modified.get(path).unwrap_or(&0)
        }

        fn length(&self, path: &str) -> u64 {
            *self.lengths.get(path).unwrap_or(&0)
        }
    }

    fn make_root() -> NodeRef {
        JarEntryNode::new_root("", Rc::new(MockJarFileAccess::new()))
    }

    #[test]
    fn root_starts_as_file() {
        let root = make_root();
        assert!(root.borrow().is_file());
        assert!(!root.borrow().is_directory());
        assert!(root.borrow().get_children().is_none());
    }

    #[test]
    fn create_node_becomes_directory() {
        let root = make_root();
        let child = root.borrow_mut().create_node("a.txt");
        assert!(root.borrow().is_directory());
        assert_eq!(child.borrow().name(), "a.txt");
        assert!(child.borrow().is_file());
    }

    #[test]
    fn create_node_returns_existing_node() {
        let root = make_root();
        let first = root.borrow_mut().create_node("dir");
        let second = root.borrow_mut().create_node("dir");
        assert!(Rc::ptr_eq(&first, &second));
    }

    #[test]
    fn get_node_dot_returns_self() {
        let root = make_root();
        root.borrow_mut().create_node("child");
        let dot = root.borrow().get_node(".");
        assert!(dot.is_some());
        assert!(Rc::ptr_eq(&dot.unwrap(), &root));
    }

    #[test]
    fn get_node_dotdot_returns_parent() {
        let root = make_root();
        let child = root.borrow_mut().create_node("child");
        let grandchild = child.borrow_mut().create_node("grandchild");
        let back = grandchild.borrow().get_node("..");
        assert!(Rc::ptr_eq(&back.unwrap(), &child));
    }

    #[test]
    fn get_node_on_file_returns_none_even_for_dot() {
        let root = make_root();
        let file = root.borrow_mut().create_node("a.txt");
        assert!(file.borrow().get_node(".").is_none());
        assert!(file.borrow().get_node("missing").is_none());
    }

    #[test]
    fn get_node_missing_child_returns_none() {
        let root = make_root();
        root.borrow_mut().create_node("a.txt");
        assert!(root.borrow().get_node("b.txt").is_none());
    }

    #[test]
    fn get_node_path_walks_multiple_components() {
        let root = make_root();
        let dir = root.borrow_mut().create_node("dir");
        dir.borrow_mut().create_node("file.txt");

        let found = root.borrow().get_node_path(&["dir", "file.txt"]);
        assert!(found.is_some());
        assert_eq!(found.unwrap().borrow().name(), "file.txt");
    }

    #[test]
    fn get_node_path_missing_component_returns_none() {
        let root = make_root();
        root.borrow_mut().create_node("dir");
        assert!(root.borrow().get_node_path(&["dir", "missing"]).is_none());
    }

    #[test]
    fn get_node_path_empty_returns_self() {
        let root = make_root();
        let found = root.borrow().get_node_path(&[]);
        assert!(Rc::ptr_eq(&found.unwrap(), &root));
    }

    #[test]
    fn get_path_builds_slash_separated_path() {
        let root = make_root();
        let dir = root.borrow_mut().create_node("dir");
        let file = dir.borrow_mut().create_node("file.txt");
        assert_eq!(root.borrow().get_path(), "");
        assert_eq!(dir.borrow().get_path(), "dir");
        assert_eq!(file.borrow().get_path(), "dir/file.txt");
    }

    #[test]
    fn get_children_lists_all_children() {
        let root = make_root();
        root.borrow_mut().create_node("a.txt");
        root.borrow_mut().create_node("b.txt");
        let children = root.borrow().get_children().unwrap();
        let mut names: Vec<String> = children.iter().map(|c| c.borrow().name().to_string()).collect();
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn parent_returns_none_for_root() {
        let root = make_root();
        assert!(root.borrow().parent().is_none());
    }

    #[test]
    fn parent_returns_parent_node_for_child() {
        let root = make_root();
        let child = root.borrow_mut().create_node("child");
        let parent = child.borrow().parent();
        assert!(Rc::ptr_eq(&parent.unwrap(), &root));
    }

    #[test]
    fn entry_data_delegates_to_root_jar_file() {
        let jar_file = Rc::new(
            MockJarFileAccess::new().with_entry("dir/file.txt", b"hello", 12345),
        );
        let root = JarEntryNode::new_root("", jar_file);
        let dir = root.borrow_mut().create_node("dir");
        let file = dir.borrow_mut().create_node("file.txt");

        assert_eq!(file.borrow().length(), 5);
        assert_eq!(file.borrow().last_modified(), 12345);

        let mut contents = Vec::new();
        file.borrow()
            .get_input_stream()
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, b"hello");
    }
}
