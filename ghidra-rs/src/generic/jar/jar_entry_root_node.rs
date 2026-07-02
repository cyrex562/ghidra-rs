use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use zip::ZipArchive;

use super::jar_entry_filter::{JarEntry, JarEntryFilter};
use super::jar_entry_node::{JarEntryNode, JarFileAccess, NodeRef};

/// A [`JarEntry`] describing a single entry read from a zip/jar archive.
///
/// Used to feed a [`JarEntryFilter`] the same way Java's `JarEntry` is passed to
/// `JarEntryFilter.accepts`.
struct ZipJarEntry {
    name: String,
    is_directory: bool,
}

impl JarEntry for ZipJarEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_directory(&self) -> bool {
        self.is_directory
    }
}

/// The default [`JarEntryFilter`] used when the caller passes none.
///
/// Mirrors Java's `JarEntryRootNode.DefaultFilter`: rejects `.class`, `.png`,
/// and `.gif` entries, accepts everything else.
pub struct DefaultFilter;

impl JarEntryFilter for DefaultFilter {
    fn accepts(&self, jar_entry: &dyn JarEntry) -> bool {
        let name = jar_entry.name();
        !name.ends_with(".class") && !name.ends_with(".png") && !name.ends_with(".gif")
    }
}

/// Snapshot of a single archive entry's uncompressed data and metadata.
struct EntryData {
    contents: Vec<u8>,
    modified: u64,
    length: u64,
}

/// A [`JarFileAccess`] implementation backed by the contents of a zip/jar
/// archive.
///
/// Java's `JarEntryRootNode` keeps the live `JarFile` open and streams entries
/// on demand via `getJarFile()`. Because the Rust `JarEntryNode` tree only
/// needs read access keyed by path, this eagerly reads each accepted entry into
/// memory when the tree is built, and serves it back through the
/// [`JarFileAccess`] trait that the node tree already understands.
struct JarZipFile {
    entries: HashMap<String, EntryData>,
}

impl JarFileAccess for JarZipFile {
    fn get_input_stream(&self, path: &str) -> io::Result<Box<dyn Read>> {
        match self.entries.get(path) {
            Some(entry) => Ok(Box::new(Cursor::new(entry.contents.clone()))),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no such jar entry: {path}"),
            )),
        }
    }

    fn last_modified(&self, path: &str) -> u64 {
        self.entries.get(path).map(|e| e.modified).unwrap_or(0)
    }

    fn length(&self, path: &str) -> u64 {
        self.entries.get(path).map(|e| e.length).unwrap_or(0)
    }
}

/// The root of a [`JarEntryNode`] tree built from a jar/zip archive.
///
/// Mirrors `generic.jar.JarEntryRootNode`: constructing it opens the archive,
/// walks every non-directory entry (applying a [`JarEntryFilter`]), and builds
/// out the directory tree by splitting each entry name on `/`. The resulting
/// [`NodeRef`] root exposes the same tree the existing [`JarEntryNode`] types
/// use, with the root node holding the archive handle so descendants resolve
/// their data by walking up to it.
pub struct JarEntryRootNode {
    root: NodeRef,
    file: Option<PathBuf>,
}

impl JarEntryRootNode {
    /// Builds a tree from the jar/zip file on disk at `path`, using the given
    /// filter (or the [`DefaultFilter`] when `filter` is `None`).
    pub fn from_path(
        path: impl AsRef<Path>,
        filter: Option<&dyn JarEntryFilter>,
    ) -> io::Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let root = Self::build(file, filter)?;
        Ok(Self {
            root,
            file: Some(path.to_path_buf()),
        })
    }

    /// Builds a tree from any seekable reader over a jar/zip archive (e.g. a
    /// `Cursor<Vec<u8>>` for an in-memory archive), using the given filter (or
    /// the [`DefaultFilter`] when `filter` is `None`).
    pub fn from_reader<R: Read + Seek>(
        reader: R,
        filter: Option<&dyn JarEntryFilter>,
    ) -> io::Result<Self> {
        let root = Self::build(reader, filter)?;
        Ok(Self { root, file: None })
    }

    fn build<R: Read + Seek>(
        reader: R,
        filter: Option<&dyn JarEntryFilter>,
    ) -> io::Result<NodeRef> {
        let default_filter = DefaultFilter;
        let filter: &dyn JarEntryFilter = filter.unwrap_or(&default_filter);

        let mut archive =
            ZipArchive::new(reader).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // First pass: collect the accepted, non-directory entries and their data.
        let mut entries: HashMap<String, EntryData> = HashMap::new();
        let mut accepted_paths: Vec<String> = Vec::new();
        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let is_directory = entry.is_dir();
            let name = entry.name().to_string();
            if is_directory {
                continue;
            }
            let jar_entry = ZipJarEntry {
                name: name.clone(),
                is_directory,
            };
            if !filter.accepts(&jar_entry) {
                continue;
            }
            let modified = entry
                .last_modified()
                .and_then(|dt| dt.to_time().ok())
                .map(|t| t.unix_timestamp() as u64 * 1000)
                .unwrap_or(0);
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents)?;
            let length = contents.len() as u64;
            entries.insert(
                name.clone(),
                EntryData {
                    contents,
                    modified,
                    length,
                },
            );
            accepted_paths.push(name);
        }

        let jar_file: Rc<dyn JarFileAccess> = Rc::new(JarZipFile { entries });
        let root = JarEntryNode::new_root("", jar_file);

        // Second pass: build the tree from the accepted entry names, matching
        // Java's `addFile`: split on '/', creating/reusing a node per component.
        for path in accepted_paths {
            let mut node: NodeRef = Rc::clone(&root);
            for component in path.split('/') {
                let next = node.borrow_mut().create_node(component);
                node = next;
            }
        }

        Ok(root)
    }

    /// Returns the root [`JarEntryNode`] of the tree.
    pub fn root(&self) -> NodeRef {
        Rc::clone(&self.root)
    }

    /// Returns the backing file path, when this tree was built from a path.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// Returns a `file://` URL for the backing file, mirroring Java's `toURL()`.
    ///
    /// Returns `None` when the tree was built from an in-memory reader (no path).
    pub fn to_url(&self) -> Option<String> {
        self.file.as_ref().map(|p| {
            let abs = p
                .canonicalize()
                .unwrap_or_else(|_| p.clone());
            format!("file://{}", abs.display())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Builds a small in-memory zip/jar with a couple of nested entries.
    fn build_test_jar() -> Cursor<Vec<u8>> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default();

            zip.start_file("a/b.txt", opts).unwrap();
            zip.write_all(b"content-b").unwrap();

            zip.start_file("a/c.txt", opts).unwrap();
            zip.write_all(b"content-c").unwrap();

            zip.start_file("d.txt", opts).unwrap();
            zip.write_all(b"content-d").unwrap();

            zip.finish().unwrap();
        }
        buf.set_position(0);
        buf
    }

    fn child_names(node: &NodeRef) -> Vec<String> {
        let mut names: Vec<String> = node
            .borrow()
            .get_children()
            .unwrap_or_default()
            .iter()
            .map(|c| c.borrow().name().to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn builds_root_children_from_jar() {
        let jar = JarEntryRootNode::from_reader(build_test_jar(), None).unwrap();
        let root = jar.root();
        assert_eq!(root.borrow().name(), "");
        assert!(root.borrow().is_directory());
        assert_eq!(child_names(&root), vec!["a".to_string(), "d.txt".to_string()]);
    }

    #[test]
    fn nested_directory_expands() {
        let jar = JarEntryRootNode::from_reader(build_test_jar(), None).unwrap();
        let root = jar.root();
        let a = root.borrow().get_node("a").unwrap();
        assert!(a.borrow().is_directory());
        assert_eq!(child_names(&a), vec!["b.txt".to_string(), "c.txt".to_string()]);
    }

    #[test]
    fn leaf_name_and_content() {
        let jar = JarEntryRootNode::from_reader(build_test_jar(), None).unwrap();
        let root = jar.root();
        let b = root.borrow().get_node_path(&["a", "b.txt"]).unwrap();
        assert_eq!(b.borrow().name(), "b.txt");
        assert!(b.borrow().is_file());
        assert_eq!(b.borrow().length(), b"content-b".len() as u64);

        let mut contents = Vec::new();
        b.borrow()
            .get_input_stream()
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, b"content-b");
    }

    #[test]
    fn top_level_leaf_content() {
        let jar = JarEntryRootNode::from_reader(build_test_jar(), None).unwrap();
        let root = jar.root();
        let d = root.borrow().get_node("d.txt").unwrap();
        assert!(d.borrow().is_file());
        let mut contents = Vec::new();
        d.borrow()
            .get_input_stream()
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();
        assert_eq!(contents, b"content-d");
    }

    #[test]
    fn default_filter_rejects_class_png_gif() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default();
            zip.start_file("keep.txt", opts).unwrap();
            zip.write_all(b"ok").unwrap();
            zip.start_file("Main.class", opts).unwrap();
            zip.write_all(b"nope").unwrap();
            zip.start_file("logo.png", opts).unwrap();
            zip.write_all(b"nope").unwrap();
            zip.start_file("anim.gif", opts).unwrap();
            zip.write_all(b"nope").unwrap();
            zip.finish().unwrap();
        }
        buf.set_position(0);

        let jar = JarEntryRootNode::from_reader(buf, None).unwrap();
        let root = jar.root();
        assert_eq!(child_names(&root), vec!["keep.txt".to_string()]);
    }

    #[test]
    fn custom_filter_is_applied() {
        struct OnlyD;
        impl JarEntryFilter for OnlyD {
            fn accepts(&self, jar_entry: &dyn JarEntry) -> bool {
                jar_entry.name().ends_with("d.txt")
            }
        }

        let jar = JarEntryRootNode::from_reader(build_test_jar(), Some(&OnlyD)).unwrap();
        let root = jar.root();
        assert_eq!(child_names(&root), vec!["d.txt".to_string()]);
    }

    #[test]
    fn from_path_builds_and_to_url() {
        let jar_bytes = build_test_jar().into_inner();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("jar_entry_root_node_test_{}.jar", std::process::id()));
        std::fs::write(&path, &jar_bytes).unwrap();

        let jar = JarEntryRootNode::from_path(&path, None).unwrap();
        assert_eq!(child_names(&jar.root()), vec!["a".to_string(), "d.txt".to_string()]);
        assert_eq!(jar.file(), Some(path.as_path()));
        assert!(jar.to_url().unwrap().starts_with("file://"));

        std::fs::remove_file(&path).ok();
    }
}
