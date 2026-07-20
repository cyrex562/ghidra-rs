use std::io;
use std::path::{Path, PathBuf};

/// File extension indicating the file is a property file.
pub const PROPERTY_EXT: &str = ".prp";

/// Basic property storage backed by a native file. The file extension used is [`PROPERTY_EXT`].
///
/// Mirrors `ghidra.util.PropertyFile`. This port maps the Java class to an object-safe trait so
/// that other core types (e.g.
/// [`ItemPropertyFile`](crate::framework::store::local::ItemPropertyFile), which extends
/// `PropertyFile` in Java) can depend on property-file behavior without depending on any single
/// concrete implementation, breaking a dependency cycle at this cut-point.
///
/// The Java class's constructor, `hashCode`/`equals` overrides, and protected `contains` helper
/// are not mechanically reproduced here: construction is implementation-specific (not part of the
/// trait contract), and `hashCode`/`equals` are ordinary `Object` overrides implementors should
/// derive on their concrete type as usual.
pub trait PropertyFile {
    /// Returns true if the file is read-only as reported by the underlying native file system.
    fn is_read_only(&self) -> bool;

    /// Returns the native parent storage directory containing this `PropertyFile`.
    fn get_parent_storage_directory(&self) -> PathBuf;

    /// Returns the native storage name for this `PropertyFile`. This name does not include the
    /// property file extension ([`PROPERTY_EXT`]).
    fn get_storage_name(&self) -> String;

    /// Returns the int value with the given `property_name`, or `default_value` if the property
    /// does not exist or is not an int.
    fn get_int(&self, property_name: &str, default_value: i32) -> i32;

    /// Assigns the int value to the given `property_name`.
    fn put_int(&mut self, property_name: &str, value: i32);

    /// Returns the long value with the given `property_name`, or `default_value` if the property
    /// does not exist or is not a long.
    fn get_long(&self, property_name: &str, default_value: i64) -> i64;

    /// Assigns the long value to the given `property_name`.
    fn put_long(&mut self, property_name: &str, value: i64);

    /// Returns the string value with the given `property_name`, or `default_value` if the
    /// property is not present.
    fn get_string(&self, property_name: &str, default_value: Option<&str>) -> Option<String>;

    /// Assigns the string value to the given `property_name`. Passing `None` removes the
    /// property, mirroring `putString(name, null)`.
    fn put_string(&mut self, property_name: &str, value: Option<&str>);

    /// Returns the boolean value with the given `property_name`, or `default_value` if the
    /// property does not exist or is not a boolean.
    fn get_boolean(&self, property_name: &str, default_value: bool) -> bool;

    /// Assigns the boolean value to the given `property_name`.
    fn put_boolean(&mut self, property_name: &str, value: bool);

    /// Removes the specified property.
    fn remove(&mut self, property_name: &str);

    /// Returns the time of last modification in number of milliseconds since the epoch.
    fn last_modified(&self) -> i64;

    /// Writes the contents of this `PropertyFile` to its underlying storage.
    ///
    /// # Errors
    /// Returns an `io::Error` if there was a problem writing the file.
    fn write_state(&self) -> io::Result<()>;

    /// Reads this `PropertyFile`'s underlying storage, replacing any in-memory property values.
    ///
    /// # Errors
    /// Returns an `io::Error` if there was a problem reading or parsing the file.
    fn read_state(&mut self) -> io::Result<()>;

    /// Moves this `PropertyFile` to `new_storage_parent`/`new_storage_name`.
    ///
    /// # Errors
    /// Returns an error if a file with `new_storage_name` already exists at
    /// `new_storage_parent` (mirrors `DuplicateFileException`), or if an IO error occurs.
    fn move_to(
        &mut self,
        new_storage_parent: &Path,
        new_storage_name: &str,
    ) -> io::Result<()>;

    /// Returns whether the file for this `PropertyFile` exists.
    fn exists(&self) -> bool;

    /// Deletes the file for this `PropertyFile`.
    fn delete(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::DuplicateFileException;
    use std::collections::{HashMap, HashSet};

    #[derive(Clone, PartialEq)]
    enum Value {
        Int(i32),
        Long(i64),
        String(String),
        Boolean(bool),
    }

    struct MockPropertyFile {
        storage_parent: PathBuf,
        storage_name: String,
        values: HashMap<String, Value>,
        occupied: HashSet<PathBuf>,
        read_only: bool,
        present: bool,
    }

    impl MockPropertyFile {
        fn new(storage_parent: &str, storage_name: &str) -> Self {
            Self {
                storage_parent: PathBuf::from(storage_parent),
                storage_name: storage_name.to_string(),
                values: HashMap::new(),
                occupied: HashSet::new(),
                read_only: false,
                present: true,
            }
        }
    }

    impl PropertyFile for MockPropertyFile {
        fn is_read_only(&self) -> bool {
            self.read_only
        }

        fn get_parent_storage_directory(&self) -> PathBuf {
            self.storage_parent.clone()
        }

        fn get_storage_name(&self) -> String {
            self.storage_name.clone()
        }

        fn get_int(&self, property_name: &str, default_value: i32) -> i32 {
            match self.values.get(property_name) {
                Some(Value::Int(v)) => *v,
                _ => default_value,
            }
        }

        fn put_int(&mut self, property_name: &str, value: i32) {
            self.values.insert(property_name.to_string(), Value::Int(value));
        }

        fn get_long(&self, property_name: &str, default_value: i64) -> i64 {
            match self.values.get(property_name) {
                Some(Value::Long(v)) => *v,
                _ => default_value,
            }
        }

        fn put_long(&mut self, property_name: &str, value: i64) {
            self.values.insert(property_name.to_string(), Value::Long(value));
        }

        fn get_string(&self, property_name: &str, default_value: Option<&str>) -> Option<String> {
            match self.values.get(property_name) {
                Some(Value::String(v)) => Some(v.clone()),
                _ => default_value.map(String::from),
            }
        }

        fn put_string(&mut self, property_name: &str, value: Option<&str>) {
            match value {
                Some(v) => {
                    self.values.insert(property_name.to_string(), Value::String(v.to_string()));
                }
                None => {
                    self.values.remove(property_name);
                }
            }
        }

        fn get_boolean(&self, property_name: &str, default_value: bool) -> bool {
            match self.values.get(property_name) {
                Some(Value::Boolean(v)) => *v,
                _ => default_value,
            }
        }

        fn put_boolean(&mut self, property_name: &str, value: bool) {
            self.values.insert(property_name.to_string(), Value::Boolean(value));
        }

        fn remove(&mut self, property_name: &str) {
            self.values.remove(property_name);
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

        fn move_to(
            &mut self,
            new_storage_parent: &Path,
            new_storage_name: &str,
        ) -> io::Result<()> {
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
            self.present
        }

        fn delete(&self) {
            // no-op for the mock; a real implementation would remove the underlying file.
        }
    }

    #[test]
    fn typed_round_trip_and_default_on_mismatch() {
        let mut f = MockPropertyFile::new("/repo", "item");
        f.put_int("count", 42);
        f.put_long("size", i64::MAX);
        f.put_string("name", Some("thing"));
        f.put_boolean("flag", true);

        assert_eq!(f.get_int("count", -1), 42);
        assert_eq!(f.get_long("size", -1), i64::MAX);
        assert_eq!(f.get_string("name", None).as_deref(), Some("thing"));
        assert!(f.get_boolean("flag", false));

        // Wrong-type reads fall back to the default, matching the Java entry-type check.
        assert_eq!(f.get_int("name", -1), -1);
        assert_eq!(f.get_string("count", None), None);
    }

    #[test]
    fn put_string_none_removes_property() {
        let mut f = MockPropertyFile::new("/repo", "item");
        f.put_string("name", Some("thing"));
        f.put_string("name", None);
        assert_eq!(f.get_string("name", Some("fallback")).as_deref(), Some("fallback"));
    }

    #[test]
    fn remove_clears_property() {
        let mut f = MockPropertyFile::new("/repo", "item");
        f.put_int("count", 1);
        f.remove("count");
        assert_eq!(f.get_int("count", 0), 0);
    }

    #[test]
    fn move_to_updates_storage_location() {
        let mut f = MockPropertyFile::new("/repo", "item");
        f.move_to(Path::new("/newdir"), "newname").expect("move should succeed");
        assert_eq!(f.get_parent_storage_directory(), PathBuf::from("/newdir"));
        assert_eq!(f.get_storage_name(), "newname");
    }

    #[test]
    fn move_to_duplicate_destination_fails_and_leaves_state_unchanged() {
        let mut f = MockPropertyFile::new("/repo", "item");
        f.occupied.insert(PathBuf::from("/newdir/newname"));
        let err = f
            .move_to(Path::new("/newdir"), "newname")
            .expect_err("duplicate destination should fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(f.get_storage_name(), "item");
    }

    #[test]
    fn trait_object_usage() {
        let mut f: Box<dyn PropertyFile> = Box::new(MockPropertyFile::new("/repo", "item"));
        assert!(f.exists());
        assert!(!f.is_read_only());
        f.put_boolean("flag", true);
        assert!(f.get_boolean("flag", false));
    }
}
