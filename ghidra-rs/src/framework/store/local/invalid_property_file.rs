//! Port of `ghidra.framework.store.local.InvalidPropertyFile`.

use std::io;
use std::path::{Path, PathBuf};

use crate::framework::store::local::item_property_file::ItemPropertyFile;
use crate::framework::store::local::local_property_file::LocalItemPropertyFile;
use crate::util::property_file::PropertyFile;

/// A substitute [`ItemPropertyFile`] used when one fails to parse. This allows the item's
/// existence to still be managed (e.g. so it can be deleted/repaired) even though its property
/// file cannot be opened normally.
///
/// Mirrors `ghidra.framework.store.local.InvalidPropertyFile`, which extends `ItemPropertyFile`;
/// the Java `extends` relationship is represented here as composition (`base:
/// LocalItemPropertyFile`), per this project's convention. See
/// [`local_property_file`](crate::framework::store::local::local_property_file) for why a
/// concrete `ItemPropertyFile` backing exists in this crate at all.
///
/// The Java class relies on virtual dispatch: its constructor calls the superclass constructor
/// chain, which (if the file already exists) calls `this.readState()` -- and since `readState` is
/// overridden here to a no-op, that call harmlessly does nothing instead of attempting (and
/// possibly failing) to parse a file already known to be corrupt. Rust has no virtual dispatch
/// during construction, so this port instead builds its backing storage via
/// [`LocalItemPropertyFile::new_without_initial_read`], which skips the read entirely -- the same
/// net effect (no parse attempt is ever made), reached by a different mechanism. See that
/// constructor's doc comment for more detail.
pub struct InvalidPropertyFile {
    base: LocalItemPropertyFile,
}

impl InvalidPropertyFile {
    /// Construct an invalid property file instance, standing in for one that previously failed
    /// to parse.
    ///
    /// Mirrors `InvalidPropertyFile(File dir, String storageName, String parentPath, String
    /// name)`. The Java constructor's own doc notes an `IOException` is "never thrown since file
    /// is never read"; this port's constructor is correspondingly infallible for that reason (the
    /// only possible failure, a non-absolute `dir`, is folded into a panic-free `io::Result`
    /// instead, matching [`LocalPropertyFile::new`](crate::framework::store::local::local_property_file::LocalPropertyFile::new)'s
    /// own signature).
    pub fn new(dir: &Path, storage_name: &str, parent_path: &str, name: &str) -> io::Result<Self> {
        let base = LocalItemPropertyFile::new_without_initial_read(
            dir,
            storage_name,
            Some(parent_path),
            Some(name),
        )?;
        Ok(Self { base })
    }
}

impl PropertyFile for InvalidPropertyFile {
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

    /// Overridden to a no-op, mirroring `InvalidPropertyFile.readState()`: "avoid potential parse
    /// failure". Unlike every other method here, this deliberately does **not** delegate to
    /// `self.base.read_state()`.
    fn read_state(&mut self) -> io::Result<()> {
        Ok(())
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

impl ItemPropertyFile for InvalidPropertyFile {
    fn get_name(&self) -> Option<String> {
        self.base.get_name()
    }

    fn get_parent_path(&self) -> Option<String> {
        self.base.get_parent_path()
    }

    fn move_item_to(
        &mut self,
        new_storage_parent: &Path,
        new_storage_name: &str,
        new_parent_path: &str,
        new_name: &str,
    ) -> io::Result<()> {
        self.base
            .move_item_to(new_storage_parent, new_storage_name, new_parent_path, new_name)
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
        path.push(format!("invalid_property_file_test_{}_{}_{}", std::process::id(), label, id));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn construction_over_corrupt_file_never_fails() {
        let dir = tmp_dir("corrupt");
        let path = dir.join("item.prp");
        // Write garbage that a normal `LocalPropertyFile::new`/`LocalItemPropertyFile::new` would
        // fail to parse as a property record.
        fs::write(&path, b"\tnot\ta\tvalid\trecord\tat\tall\n").unwrap();

        let pf = InvalidPropertyFile::new(&dir, "item", "/a", "thing").unwrap();
        assert_eq!(pf.get_name().as_deref(), Some("thing"));
        assert_eq!(pf.get_parent_path().as_deref(), Some("/a"));
        // The broken file's content was never parsed, so no properties were loaded from it.
        assert_eq!(pf.get_string("anything", None), None);
    }

    #[test]
    fn read_state_is_a_permanent_no_op() {
        let dir = tmp_dir("noop");
        let mut pf = InvalidPropertyFile::new(&dir, "item", "/a", "thing").unwrap();
        pf.put_string("k", Some("v"));
        pf.write_state().unwrap();

        // Even though a well-formed file now exists on disk (written by the *base*'s normal
        // `write_state`), calling `read_state()` again must remain a no-op and must not disturb
        // the in-memory properties.
        pf.read_state().unwrap();
        assert_eq!(pf.get_string("k", None).as_deref(), Some("v"));
    }

    #[test]
    fn can_still_be_deleted() {
        let dir = tmp_dir("delete");
        let mut pf = InvalidPropertyFile::new(&dir, "item", "/a", "thing").unwrap();
        pf.write_state().unwrap();
        assert!(pf.exists());
        pf.delete();
        assert!(!pf.exists());
    }
}
