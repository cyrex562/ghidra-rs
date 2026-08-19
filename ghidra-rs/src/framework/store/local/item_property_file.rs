use std::io;
use std::path::Path;

use crate::framework::store::SEPARATOR_CHAR;
use crate::util::property_file::PropertyFile;

/// Property file key used to store the associated item's file id.
const FILE_ID_PROPERTY: &str = "FILE_ID";

/// `ItemPropertyFile` provides basic property storage which is primarily intended to store
/// limited information related to a logical folder item.
///
/// Mirrors `ghidra.framework.store.local.ItemPropertyFile`, which extends `ghidra.util.PropertyFile`
/// (ported here as the [`PropertyFile`] supertrait, see [`crate::util::property_file`]). This port
/// maps the Java class to an object-safe trait so implementations can be depended on via
/// `Box<dyn ItemPropertyFile>`/`Arc<dyn ItemPropertyFile>` rather than any single concrete type,
/// breaking a dependency cycle at this cut-point.
///
/// The Java class's `moveTo(File, String)` override, which is `final` and always throws
/// `UnsupportedOperationException` to force callers through the 4-arg `moveTo`, is not
/// mechanically reproduced here (doing so would require shadowing the supertrait's `move_to` of
/// the same name, which is ambiguous to call through a trait object). Implementations of this
/// trait should treat the inherited [`PropertyFile::move_to`] as internal-only and route external
/// callers through [`ItemPropertyFile::move_item_to`] instead, matching the Java restriction in
/// spirit.
pub trait ItemPropertyFile: PropertyFile {
    /// Return the name of the item associated with this PropertyFile. `None` may be returned if
    /// this is an older property file and the name was not specified at time of construction.
    fn get_name(&self) -> Option<String>;

    /// Return the logical parent path containing the item described by this PropertyFile.
    fn get_parent_path(&self) -> Option<String>;

    /// Return the logical path of the item associated with this PropertyFile. `None` may be
    /// returned if this is an older property file and the name and parent path were not
    /// specified at time of construction.
    fn get_path(&self) -> Option<String> {
        let parent_path = self.get_parent_path()?;
        let name = self.get_name()?;
        if parent_path.len() == 1 {
            Some(format!("{parent_path}{name}"))
        } else {
            Some(format!("{parent_path}{SEPARATOR_CHAR}{name}"))
        }
    }

    /// Returns the FileID associated with this file, or `None` if unset.
    fn get_file_id(&self) -> Option<String> {
        self.get_string(FILE_ID_PROPERTY, None)
    }

    /// Set the FileID associated with this file.
    fn set_file_id(&mut self, file_id: Option<&str>) {
        self.put_string(FILE_ID_PROPERTY, file_id);
    }

    /// Move this PropertyFile to the new storage parent, and update the logical parent path and
    /// item name it reports if they differ from `new_parent_path`/`new_name`.
    ///
    /// # Errors
    /// Returns an error if a file with `new_storage_name` already exists at
    /// `new_storage_parent` (mirrors `DuplicateFileException`), or if an IO error occurs.
    fn move_item_to(
        &mut self,
        new_storage_parent: &Path,
        new_storage_name: &str,
        new_parent_path: &str,
        new_name: &str,
    ) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::DuplicateFileException;
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;

    struct MockItemPropertyFile {
        properties: HashMap<String, String>,
        parent_path: Option<String>,
        name: Option<String>,
        storage_parent: PathBuf,
        storage_name: String,
        occupied: HashSet<PathBuf>,
    }

    impl MockItemPropertyFile {
        fn new(parent_path: Option<&str>, name: Option<&str>) -> Self {
            Self {
                properties: HashMap::new(),
                parent_path: parent_path.map(String::from),
                name: name.map(String::from),
                storage_parent: PathBuf::from("/repo"),
                storage_name: "item".to_string(),
                occupied: HashSet::new(),
            }
        }
    }

    impl PropertyFile for MockItemPropertyFile {
        fn is_read_only(&self) -> bool {
            false
        }

        fn get_parent_storage_directory(&self) -> PathBuf {
            self.storage_parent.clone()
        }

        fn get_storage_name(&self) -> String {
            self.storage_name.clone()
        }

        fn get_int(&self, _property_name: &str, default_value: i32) -> i32 {
            default_value
        }

        fn put_int(&mut self, _property_name: &str, _value: i32) {}

        fn get_long(&self, _property_name: &str, default_value: i64) -> i64 {
            default_value
        }

        fn put_long(&mut self, _property_name: &str, _value: i64) {}

        fn get_string(&self, property_name: &str, default_value: Option<&str>) -> Option<String> {
            self.properties
                .get(property_name)
                .cloned()
                .or_else(|| default_value.map(String::from))
        }

        fn put_string(&mut self, property_name: &str, value: Option<&str>) {
            match value {
                Some(v) => {
                    self.properties.insert(property_name.to_string(), v.to_string());
                }
                None => {
                    self.properties.remove(property_name);
                }
            }
        }

        fn get_boolean(&self, _property_name: &str, default_value: bool) -> bool {
            default_value
        }

        fn put_boolean(&mut self, _property_name: &str, _value: bool) {}

        fn remove(&mut self, property_name: &str) {
            self.properties.remove(property_name);
        }

        fn last_modified(&self) -> i64 {
            0
        }

        fn write_state(&self) -> io::Result<()> {
            Ok(())
        }

        fn read_state(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn move_to(&mut self, new_storage_parent: &Path, new_storage_name: &str) -> io::Result<()> {
            let dest = new_storage_parent.join(new_storage_name);
            if self.occupied.contains(&dest) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    DuplicateFileException::new(format!("{} already exists", dest.display())),
                ));
            }
            self.storage_parent = new_storage_parent.to_path_buf();
            self.storage_name = new_storage_name.to_string();
            Ok(())
        }

        fn exists(&self) -> bool {
            true
        }

        fn delete(&self) {}
    }

    impl ItemPropertyFile for MockItemPropertyFile {
        fn get_name(&self) -> Option<String> {
            self.name.clone()
        }

        fn get_parent_path(&self) -> Option<String> {
            self.parent_path.clone()
        }

        fn move_item_to(
            &mut self,
            new_storage_parent: &Path,
            new_storage_name: &str,
            new_parent_path: &str,
            new_name: &str,
        ) -> io::Result<()> {
            self.move_to(new_storage_parent, new_storage_name)?;
            if self.parent_path.as_deref() != Some(new_parent_path)
                || self.name.as_deref() != Some(new_name)
            {
                self.parent_path = Some(new_parent_path.to_string());
                self.name = Some(new_name.to_string());
            }
            Ok(())
        }
    }

    #[test]
    fn get_path_combines_parent_and_name() {
        let f = MockItemPropertyFile::new(Some("/a/b"), Some("thing"));
        assert_eq!(f.get_path().as_deref(), Some("/a/b/thing"));
    }

    #[test]
    fn get_path_handles_root_parent() {
        let f = MockItemPropertyFile::new(Some("/"), Some("thing"));
        assert_eq!(f.get_path().as_deref(), Some("/thing"));
    }

    #[test]
    fn get_path_none_when_unknown() {
        let f = MockItemPropertyFile::new(None, None);
        assert_eq!(f.get_path(), None);
    }

    #[test]
    fn file_id_round_trips_and_clears() {
        let mut f = MockItemPropertyFile::new(Some("/"), Some("thing"));
        assert_eq!(f.get_file_id(), None);
        f.set_file_id(Some("abc-123"));
        assert_eq!(f.get_file_id().as_deref(), Some("abc-123"));
        f.set_file_id(None);
        assert_eq!(f.get_file_id(), None);
    }

    #[test]
    fn move_item_to_updates_logical_path_and_storage() {
        let mut f = MockItemPropertyFile::new(Some("/a"), Some("old"));
        f.move_item_to(Path::new("/newdir"), "newstorage", "/b", "new")
            .expect("move should succeed");
        assert_eq!(f.get_parent_path().as_deref(), Some("/b"));
        assert_eq!(f.get_name().as_deref(), Some("new"));
        assert_eq!(f.get_path().as_deref(), Some("/b/new"));
        assert_eq!(f.storage_parent, PathBuf::from("/newdir"));
        assert_eq!(f.storage_name, "newstorage");
    }

    #[test]
    fn move_item_to_leaves_state_unchanged_on_duplicate() {
        let mut f = MockItemPropertyFile::new(Some("/a"), Some("old"));
        f.occupied.insert(PathBuf::from("/newdir/newstorage"));
        let err = f
            .move_item_to(Path::new("/newdir"), "newstorage", "/b", "new")
            .expect_err("duplicate destination should fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(f.get_parent_path().as_deref(), Some("/a"));
        assert_eq!(f.get_name().as_deref(), Some("old"));
        assert_eq!(f.storage_name, "item");
    }
}
