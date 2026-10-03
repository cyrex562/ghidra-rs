use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use super::ResourceFile;

/// A single node in a [`ClassModuleTree`]'s path trie.
///
/// Port of `generic.jar.ClassModuleTree.FileNode`. Java's `FileNode` keeps a `parent` back-
/// pointer so `getPath()` can walk upward to reconstruct the full slash-separated path; that
/// back-pointer is deliberately dropped here (accumulating a cycle of parent/child references
/// has no idiomatic ownership shape in Rust without `Rc`/`Weak`), and paths are instead built
/// top-down by the traversal methods that need them ([`ClassModuleTree::save_lines`]), which is
/// observably identical. `parent` and `name` are therefore not fields of this struct; the name
/// segment lives only as the owning `HashMap`'s key.
///
/// `children == None` distinguishes "no children map has ever been created" from "created but
/// emptied", mirroring the Java field's `null` vs. an instantiated-but-cleared `HashMap` (the
/// latter never actually occurs in the Java source, but the distinction still matters for
/// [`trim`](Self::trim), which sets `children = null` to prune a subtree).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct FileNode {
    module: Option<String>,
    children: Option<HashMap<String, FileNode>>,
}

impl FileNode {
    /// Port of `FileNode.getCount()`.
    fn get_count(&self) -> usize {
        let mut count = 1;
        if let Some(children) = &self.children {
            for child in children.values() {
                count += child.get_count();
            }
        }
        count
    }

    /// Collapses a subtree that assigns the same module to every leaf into a single node
    /// carrying that module, returning the module name this node now resolves to (or `None`).
    ///
    /// Port of `FileNode.trim()`.
    fn trim(&mut self) -> Option<String> {
        if self.module.is_some() {
            return self.module.clone();
        }
        let Some(children) = self.children.as_mut() else {
            return None;
        };

        // Java collects into a `Set<String>` that may contain a literal `null` element (a child
        // whose own `trim()` returned `null`); `HashSet<Option<String>>` mirrors that directly.
        let set: HashSet<Option<String>> = children.values_mut().map(FileNode::trim).collect();
        if set.len() == 1 {
            let only = set.into_iter().next().unwrap();
            self.module = only;
            if self.module.is_some() {
                self.children = None; // trim the children
            }
        }
        self.module.clone()
    }

    /// Returns the child named `name`, creating it (and the children map, if absent) first if
    /// necessary.
    ///
    /// Port of `FileNode.createNode(String)`.
    fn create_node(&mut self, name: &str) -> &mut FileNode {
        self.children
            .get_or_insert_with(HashMap::new)
            .entry(name.to_string())
            .or_default()
    }

    /// Port of `FileNode.getChild(String)`.
    fn get_child(&self, name: &str) -> Option<&FileNode> {
        self.children.as_ref()?.get(name)
    }
}

/// A trie mapping slash-separated class-file paths to the name of the module that owns them,
/// with adjacent leaves sharing a module collapsible into a single interior node via
/// [`trim`](Self::trim).
///
/// Port of `generic.jar.ClassModuleTree`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassModuleTree {
    root: FileNode,
}

impl ClassModuleTree {
    /// Port of `ClassModuleTree()`.
    pub fn new() -> Self {
        Self {
            root: FileNode::default(),
        }
    }

    /// Loads a tree from a previously [`save_file`](Self::save_file)-written listing: one `path
    /// module` pair per line, `module` being the literal text `null` for an unset module.
    ///
    /// Port of `ClassModuleTree(ResourceFile)`.
    pub fn from_resource_file(tree_file: &ResourceFile) -> io::Result<Self> {
        let mut tree = Self::new();
        let reader = BufReader::new(tree_file.get_input_stream()?);
        for line in reader.lines() {
            let line = line?;
            tree.add_line(&line)?;
        }
        Ok(tree)
    }

    fn add_line(&mut self, line: &str) -> io::Result<()> {
        // Mirrors `line.split(" ")`: `path` and `module` are exactly the first two
        // space-delimited tokens (not the whole line after the first space).
        let mut parts = line.split(' ');
        let path = parts.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing path field in tree line")
        })?;
        let module = parts.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing module field in tree line")
        })?;
        let module = if module == "null" { None } else { Some(module) };
        self.add_node(path, module);
        Ok(())
    }

    /// Records that `path` (a slash-separated sequence of path segments) belongs to
    /// `module_name` (`None` clears/leaves unset the module for that node).
    ///
    /// Port of `ClassModuleTree.addNode(String, String)`.
    pub fn add_node(&mut self, path: &str, module_name: Option<&str>) {
        let mut node = &mut self.root;
        for segment in path.split('/') {
            node = node.create_node(segment);
        }
        node.module = module_name.map(|s| s.to_string());
    }

    /// Collapses subtrees whose leaves all resolve to the same module into a single node.
    ///
    /// Port of `ClassModuleTree.trim()`.
    pub fn trim(&mut self) {
        self.root.trim();
    }

    /// Writes this tree to `output_file` as one `path module` line per node (in the same format
    /// [`from_resource_file`](Self::from_resource_file) reads), `module` being the literal text
    /// `null` for an unset module.
    ///
    /// Port of `ClassModuleTree.saveFile(File)`. Java's `writeRecursively` skips writing a line
    /// for the (unnamed) root node itself, only recursing into its children; this does the same.
    pub fn save_file(&self, output_file: &Path) -> io::Result<()> {
        let mut writer = File::create(output_file)?;
        if let Some(children) = &self.root.children {
            let mut names: Vec<&String> = children.keys().collect();
            names.sort();
            for name in names {
                self.write_recursively(&mut writer, name, &children[name])?;
            }
        }
        Ok(())
    }

    fn write_recursively(&self, writer: &mut impl Write, path: &str, node: &FileNode) -> io::Result<()> {
        writeln!(
            writer,
            "{} {}",
            path,
            node.module.as_deref().unwrap_or("null")
        )?;
        if let Some(children) = &node.children {
            let mut names: Vec<&String> = children.keys().collect();
            names.sort();
            for name in names {
                let child_path = format!("{path}/{name}");
                self.write_recursively(writer, &child_path, &children[name])?;
            }
        }
        Ok(())
    }

    /// Total number of nodes in the tree, including the (unnamed) root.
    ///
    /// Port of `ClassModuleTree.getNodeCount()`.
    pub fn get_node_count(&self) -> usize {
        self.root.get_count()
    }

    /// Looks up the module owning `class_name` (a slash-separated path), returning the module
    /// assigned to the first ancestor (inclusive) that has one set, or `None` if no path segment
    /// exists or none of them have an assigned module.
    ///
    /// Port of `ClassModuleTree.getModuleName(String)`.
    pub fn get_module_name(&self, class_name: &str) -> Option<String> {
        let mut node = &self.root;
        for segment in class_name.split('/') {
            node = node.get_child(segment)?;
            if let Some(module) = &node.module {
                return Some(module.clone());
            }
        }
        None
    }
}

impl Default for ClassModuleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_module_name_resolves_nearest_ancestor() {
        let mut tree = ClassModuleTree::new();
        tree.add_node("a/b/c", Some("module1"));
        tree.add_node("a/b/d", Some("module1"));
        tree.add_node("a/x/a", Some("module2"));
        tree.add_node("a/x/b", Some("module3"));

        assert_eq!(tree.get_module_name("a/b/c"), Some("module1".to_string()));
        assert_eq!(tree.get_module_name("a/x/a"), Some("module2".to_string()));
        assert_eq!(tree.get_module_name("a/x/b"), Some("module3".to_string()));
    }

    #[test]
    fn get_module_name_of_unknown_path_is_none() {
        let mut tree = ClassModuleTree::new();
        tree.add_node("a/b/c", Some("module1"));
        assert_eq!(tree.get_module_name("a/b/z"), None);
        assert_eq!(tree.get_module_name("z"), None);
    }

    #[test]
    fn get_module_name_resolves_from_interior_node_set_by_an_intermediate_path_segment() {
        let mut tree = ClassModuleTree::new();
        tree.add_node("a/b", Some("module1"));
        // "a/b/c/d" should resolve to "module1" via the "a/b" ancestor, without "a/b/c/d" itself
        // ever having been added as a node.
        assert_eq!(tree.get_module_name("a/b/c/d"), Some("module1".to_string()));
    }

    #[test]
    fn get_node_count_includes_root_and_every_descendant() {
        let mut tree = ClassModuleTree::new();
        assert_eq!(tree.get_node_count(), 1); // just the root

        tree.add_node("a/b/c", Some("module1"));
        // root, a, b, c = 4 nodes
        assert_eq!(tree.get_node_count(), 4);
    }

    #[test]
    fn trim_collapses_subtree_with_uniform_module() {
        let mut tree = ClassModuleTree::new();
        tree.add_node("a/b/c", Some("module1"));
        tree.add_node("a/b/d", Some("module1"));
        tree.add_node("a/b/e", Some("module1"));
        // A sibling branch under "a" with a different module. Java's `FileNode.trim()` collapses
        // a node whenever ALL of its children resolve to the same module -- and that collapse
        // cascades upward through every ancestor for which this remains true, all the way to the
        // root if nothing stops it. Without this divergent sibling, `a` (and then `root`) would
        // ALSO collapse into "module1" in the same trim() pass, since each would see a singleton
        // one-module set from its only child -- leaving just the root (node count 1), not "root,
        // a, b" as this test wants to demonstrate.
        tree.add_node("a/f", Some("module2"));
        let before = tree.get_node_count();
        assert_eq!(before, 7); // root, a, b, c, d, e, f

        tree.trim();

        // b's three children all resolved to "module1", so b absorbs the module and drops them.
        // a's own children now resolve to {"module1" (from b), "module2" (from f)} -- not
        // uniform -- so the collapse stops there and a/root remain distinct.
        assert_eq!(tree.get_node_count(), 4); // root, a, b, f
        assert_eq!(tree.get_module_name("a/b/c"), Some("module1".to_string()));
        assert_eq!(tree.get_module_name("a/b/anything"), Some("module1".to_string()));
        assert_eq!(tree.get_module_name("a/f"), Some("module2".to_string()));
    }

    #[test]
    fn trim_does_not_collapse_subtree_with_mixed_modules() {
        let mut tree = ClassModuleTree::new();
        tree.add_node("a/x/a", Some("module2"));
        tree.add_node("a/x/b", Some("module3"));
        let before = tree.get_node_count();

        tree.trim();

        assert_eq!(tree.get_node_count(), before);
        assert_eq!(tree.get_module_name("a/x/a"), Some("module2".to_string()));
        assert_eq!(tree.get_module_name("a/x/b"), Some("module3".to_string()));
    }

    #[test]
    fn save_file_and_from_resource_file_round_trip() {
        let mut tree = ClassModuleTree::new();
        tree.add_node("a/b/c", Some("module1"));
        tree.add_node("a/b/d", None);
        tree.add_node("a/x", Some("module2"));

        let dir = std::env::temp_dir().join(format!(
            "class_module_tree_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tree.txt");

        tree.save_file(&path).unwrap();

        let resource_file = ResourceFile::new(path.clone());
        let restored = ClassModuleTree::from_resource_file(&resource_file).unwrap();

        assert_eq!(restored.get_module_name("a/b/c"), Some("module1".to_string()));
        assert_eq!(restored.get_module_name("a/b/d"), None);
        assert_eq!(restored.get_module_name("a/x"), Some("module2".to_string()));
        assert_eq!(restored.get_node_count(), tree.get_node_count());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn equal_trees_compare_equal_and_differing_trees_do_not() {
        let mut a = ClassModuleTree::new();
        a.add_node("x/y", Some("m"));
        let mut b = ClassModuleTree::new();
        b.add_node("x/y", Some("m"));
        assert_eq!(a, b);

        let mut c = ClassModuleTree::new();
        c.add_node("x/y", Some("other"));
        assert_ne!(a, c);
    }

    #[test]
    fn new_tree_has_no_module_for_any_path() {
        let tree = ClassModuleTree::new();
        assert_eq!(tree.get_module_name("anything"), None);
    }
}
