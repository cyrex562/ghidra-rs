//! Port of `ghidra.framework.store.local.IndexedPropertyFile`.

use std::io;
use std::path::{Path, PathBuf};

use crate::framework::store::local::item_property_file::ItemPropertyFile;
use crate::framework::store::local::local_property_file::LocalItemPropertyFile;
use crate::util::property_file::{PropertyFile, PROPERTY_EXT};

/// Property file key used to persist the item's logical name.
pub const NAME_PROPERTY: &str = "NAME";
/// Property file key used to persist the item's logical parent path.
pub const PARENT_PATH_PROPERTY: &str = "PARENT";

/// A property file which additionally persists the associated item's logical name and parent
/// path as ordinary properties (`NAME`/`PARENT`), so they can be recovered without the caller
/// supplying them again.
///
/// Mirrors `ghidra.framework.store.local.IndexedPropertyFile`, which extends
/// `ItemPropertyFile`; the Java `extends` relationship is represented here as composition
/// (`base: LocalItemPropertyFile`), per this project's convention. See
/// [`local_property_file`](crate::framework::store::local::local_property_file) for why a
/// concrete `ItemPropertyFile` backing exists in this crate at all.
pub struct IndexedPropertyFile {
    base: LocalItemPropertyFile,
}

impl IndexedPropertyFile {
    /// Construct a new or existing `IndexedPropertyFile`. If the file already carries persisted
    /// `NAME`/`PARENT` properties (i.e. it already existed), those persisted values take
    /// precedence over `parent_path`/`name`; otherwise `parent_path`/`name` are persisted as the
    /// file's initial `NAME`/`PARENT` properties.
    ///
    /// Mirrors `IndexedPropertyFile(File dir, String storageName, String parentPath, String
    /// name)`.
    ///
    /// # Errors
    /// Returns an `io::Error` if a file parse error occurs or an IO error occurs reading an
    /// existing file.
    pub fn new(dir: &Path, storage_name: &str, parent_path: &str, name: &str) -> io::Result<Self> {
        let mut base = LocalItemPropertyFile::new(dir, storage_name, Some(parent_path), Some(name))?;
        if base.contains(NAME_PROPERTY) && base.contains(PARENT_PATH_PROPERTY) {
            base.set_name(base.get_string(NAME_PROPERTY, Some(name)));
            base.set_parent_path(base.get_string(PARENT_PATH_PROPERTY, Some(parent_path)));
        } else {
            base.put_string(NAME_PROPERTY, Some(name));
            base.put_string(PARENT_PATH_PROPERTY, Some(parent_path));
        }
        Ok(Self { base })
    }

    /// Construct an `IndexedPropertyFile` for a file which must already exist, reading its
    /// logical name and parent path from its persisted `NAME`/`PARENT` properties.
    ///
    /// Mirrors `IndexedPropertyFile(File dir, String storageName)`.
    ///
    /// # Errors
    /// Returns an `io::Error` (`NotFound`) if the property file does not exist, or
    /// (`InvalidData`) if it exists but is missing a persisted `NAME` or `PARENT` property.
    pub fn open(dir: &Path, storage_name: &str) -> io::Result<Self> {
        let mut base = LocalItemPropertyFile::new(dir, storage_name, None, None)?;
        if !base.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} not found", dir.join(format!("{storage_name}{PROPERTY_EXT}")).display()),
            ));
        }
        let name = base.get_string(NAME_PROPERTY, None);
        let parent_path = base.get_string(PARENT_PATH_PROPERTY, None);
        if name.is_none() || parent_path.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid indexed property file: {}",
                    dir.join(format!("{storage_name}{PROPERTY_EXT}")).display()
                ),
            ));
        }
        base.set_name(name);
        base.set_parent_path(parent_path);
        Ok(Self { base })
    }

    /// Construct an `IndexedPropertyFile` for an existing property file given its full path.
    ///
    /// Mirrors `IndexedPropertyFile(File file)`, which derives `dir`/`storageName` from `file`
    /// and delegates to the [`open`](Self::open)-equivalent 2-arg constructor.
    ///
    /// # Errors
    /// Returns an `io::Error` (`InvalidInput`) if `file`'s name does not end with
    /// [`PROPERTY_EXT`], or any error [`open`](Self::open) may return.
    pub fn from_file(file: &Path) -> io::Result<Self> {
        let dir = file.parent().unwrap_or_else(|| Path::new(""));
        let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let storage_name = storage_name_from_file_name(file_name)?;
        Self::open(dir, &storage_name)
    }
}

/// Strips the [`PROPERTY_EXT`] extension from a property file name.
///
/// Mirrors the private static `getStorageName(String propertyFileName)` helper, which throws
/// `IllegalArgumentException` if the name does not carry the `.prp` extension.
fn storage_name_from_file_name(property_file_name: &str) -> io::Result<String> {
    property_file_name
        .strip_suffix(PROPERTY_EXT)
        .map(String::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "property file name must have .prp file extension",
            )
        })
}

impl PropertyFile for IndexedPropertyFile {
    fn is_read_only(&self) -> bool {
        self.base.is_read_only()
    }

    fn get_parent_storage_directory(&self) -> PathBuf {
        self.base.get_parent_storage_directory()
    }

    fn get_storage_name(&self) -> String {
        self.base.get_storage_name()
    }

    fn get_int(&self, property_name: &str, default_value: i32) -> i32 {
        self.base.get_int(property_name, default_value)
    }

    fn put_int(&mut self, property_name: &str, value: i32) {
        self.base.put_int(property_name, value);
    }

    fn get_long(&self, property_name: &str, default_value: i64) -> i64 {
        self.base.get_long(property_name, default_value)
    }

    fn put_long(&mut self, property_name: &str, value: i64) {
        self.base.put_long(property_name, value);
    }

    fn get_string(&self, property_name: &str, default_value: Option<&str>) -> Option<String> {
        self.base.get_string(property_name, default_value)
    }

    fn put_string(&mut self, property_name: &str, value: Option<&str>) {
        self.base.put_string(property_name, value);
    }

    fn get_boolean(&self, property_name: &str, default_value: bool) -> bool {
        self.base.get_boolean(property_name, default_value)
    }

    fn put_boolean(&mut self, property_name: &str, value: bool) {
        self.base.put_boolean(property_name, value);
    }

    fn remove(&mut self, property_name: &str) {
        self.base.remove(property_name);
    }

    fn last_modified(&self) -> i64 {
        self.base.last_modified()
    }

    fn write_state(&self) -> io::Result<()> {
        self.base.write_state()
    }

    fn read_state(&mut self) -> io::Result<()> {
        self.base.read_state()
    }

    fn move_to(&mut self, new_storage_parent: &Path, new_storage_name: &str) -> io::Result<()> {
        self.base.move_to(new_storage_parent, new_storage_name)
    }

    fn exists(&self) -> bool {
        self.base.exists()
    }

    fn delete(&self) {
        self.base.delete()
    }
}

impl ItemPropertyFile for IndexedPropertyFile {
    fn get_name(&self) -> Option<String> {
        self.base.get_name()
    }

    fn get_parent_path(&self) -> Option<String> {
        self.base.get_parent_path()
    }

    /// Mirrors the `moveTo(File, String, String, String)` override: after delegating to the
    /// inherited move, if the logical parent path or name actually changed, the new `NAME`/
    /// `PARENT` properties are persisted (and the file re-written) to match.
    fn move_item_to(
        &mut self,
        new_storage_parent: &Path,
        new_storage_name: &str,
        new_parent_path: &str,
        new_name: &str,
    ) -> io::Result<()> {
        let old_name = self.base.get_name();
        let old_parent_path = self.base.get_parent_path();
        self.base
            .move_item_to(new_storage_parent, new_storage_name, new_parent_path, new_name)?;
        if old_parent_path.as_deref() != Some(new_parent_path) || old_name.as_deref() != Some(new_name) {
            self.base.put_string(NAME_PROPERTY, Some(new_name));
            self.base.put_string(PARENT_PATH_PROPERTY, Some(new_parent_path));
            self.base.write_state()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_dir(label: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("indexed_property_file_test_{}_{}_{}", std::process::id(), label, id));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn new_file_persists_name_and_parent_path() {
        let dir = tmp_dir("new");
        let mut pf = IndexedPropertyFile::new(&dir, "item", "/a/b", "thing").unwrap();
        assert_eq!(pf.get_name().as_deref(), Some("thing"));
        assert_eq!(pf.get_parent_path().as_deref(), Some("/a/b"));
        assert_eq!(pf.get_string(NAME_PROPERTY, None).as_deref(), Some("thing"));
        assert_eq!(pf.get_string(PARENT_PATH_PROPERTY, None).as_deref(), Some("/a/b"));
        pf.write_state().unwrap();
    }

    #[test]
    fn reopen_uses_persisted_name_and_parent_path_over_supplied_args() {
        let dir = tmp_dir("reopen");
        {
            let mut pf = IndexedPropertyFile::new(&dir, "item", "/original", "orig-name").unwrap();
            pf.write_state().unwrap();
        }
        // Reopen with *different* parentPath/name args -- since the file already carries
        // persisted NAME/PARENT properties, those persisted values win (matching the Java
        // constructor's `contains(NAME_PROPERTY) && contains(PARENT_PATH_PROPERTY)` branch).
        let pf = IndexedPropertyFile::new(&dir, "item", "/ignored", "ignored-name").unwrap();
        assert_eq!(pf.get_name().as_deref(), Some("orig-name"));
        assert_eq!(pf.get_parent_path().as_deref(), Some("/original"));
    }

    #[test]
    fn open_by_storage_name_reads_persisted_values() {
        let dir = tmp_dir("open");
        {
            let mut pf = IndexedPropertyFile::new(&dir, "item", "/a", "thing").unwrap();
            pf.write_state().unwrap();
        }
        let pf = IndexedPropertyFile::open(&dir, "item").unwrap();
        assert_eq!(pf.get_name().as_deref(), Some("thing"));
        assert_eq!(pf.get_parent_path().as_deref(), Some("/a"));
    }

    #[test]
    fn open_missing_file_is_not_found() {
        let dir = tmp_dir("open_missing");
        let err = IndexedPropertyFile::open(&dir, "nope").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn open_file_missing_name_or_parent_is_invalid() {
        let dir = tmp_dir("open_invalid");
        // Write a plain (non-indexed) property file with no NAME/PARENT recorded.
        let mut base = LocalItemPropertyFile::new(&dir, "item", None, None).unwrap();
        base.write_state().unwrap();
        let err = IndexedPropertyFile::open(&dir, "item").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn from_file_strips_extension_and_opens() {
        let dir = tmp_dir("from_file");
        {
            let mut pf = IndexedPropertyFile::new(&dir, "item", "/a", "thing").unwrap();
            pf.write_state().unwrap();
        }
        let pf = IndexedPropertyFile::from_file(&dir.join("item.prp")).unwrap();
        assert_eq!(pf.get_name().as_deref(), Some("thing"));
    }

    #[test]
    fn from_file_rejects_non_prp_extension() {
        let err = IndexedPropertyFile::from_file(Path::new("/tmp/item.txt")).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn move_item_to_rewrites_persisted_name_and_parent_when_changed() {
        let dir = tmp_dir("move_src");
        let dir2 = tmp_dir("move_dst");
        let mut pf = IndexedPropertyFile::new(&dir, "item", "/a", "thing").unwrap();
        pf.write_state().unwrap();

        pf.move_item_to(&dir2, "item2", "/b", "thing2").unwrap();
        assert_eq!(pf.get_name().as_deref(), Some("thing2"));
        assert_eq!(pf.get_parent_path().as_deref(), Some("/b"));

        // Re-opening from disk confirms the NAME/PARENT properties were actually persisted (not
        // just updated in-memory), since `move_item_to` calls `write_state` when they change.
        let reopened = IndexedPropertyFile::open(&dir2, "item2").unwrap();
        assert_eq!(reopened.get_name().as_deref(), Some("thing2"));
        assert_eq!(reopened.get_parent_path().as_deref(), Some("/b"));
    }

    #[test]
    fn move_item_to_same_logical_path_skips_rewrite() {
        let dir = tmp_dir("move_same_src");
        let dir2 = tmp_dir("move_same_dst");
        let mut pf = IndexedPropertyFile::new(&dir, "item", "/a", "thing").unwrap();
        pf.write_state().unwrap();

        // Same logical parent path and name, only the storage location changes.
        pf.move_item_to(&dir2, "item", "/a", "thing").unwrap();
        assert_eq!(pf.get_name().as_deref(), Some("thing"));
        assert_eq!(pf.get_parent_path().as_deref(), Some("/a"));
        assert!(dir2.join("item.prp").exists());
    }
}
