//! Concrete, file-backed property storage.
//!
//! Mirrors `ghidra.util.PropertyFile` (concrete class) and
//! `ghidra.framework.store.local.ItemPropertyFile` (concrete class, `extends PropertyFile`).
//! Neither Java class is one of this session's seven assigned ports, but both are marked `DONE`
//! in `PORT_MANIFEST.tsv` as the object-safe traits [`crate::util::property_file::PropertyFile`]
//! and [`crate::framework::store::local::ItemPropertyFile`] -- ports that intentionally left
//! "construction is implementation-specific" / "a concrete implementation is expected to provide
//! its own associated `new`/`create` functions" for a later concrete type to fill in.
//! [`IndexedPropertyFile`](crate::framework::store::local::IndexedPropertyFile) and
//! [`InvalidPropertyFile`](crate::framework::store::local::InvalidPropertyFile) (this session's
//! assigned classes) are concrete Java subclasses of the concrete `ItemPropertyFile`, so a real
//! backing implementation is added here for them to compose over via a `base` field, per this
//! project's composition-over-inheritance convention, rather than leaving them as stubs.
//!
//! On-disk format: unlike Java's `PropertyFile.writeState`, which is pinned to a specific XML
//! schema "to avoid severe incompatibility with older versions of Ghidra", this port uses a small
//! line-oriented format of its own (one `name\ttype\tvalue` record per line, with `\t`/`\n`/`\\`
//! escaped). Nothing else in this codebase parses a real `.prp` file, so byte-for-byte schema
//! compatibility with Java is not required here (mirrors the precedent set by
//! [`ItemVersion`](crate::framework::store::ItemVersion)'s use of plain `serde` over Java's
//! hand-rolled `Serializable` wire format).
//!
//! One behavioral quirk *is* preserved faithfully: like Java's `PropertyFile`, a property fetched
//! with the wrong accessor (e.g. [`PropertyFile::get_int`] on a property that was stored via
//! [`PropertyFile::put_string`]) returns the caller's `default_value` rather than attempting any
//! coercion -- storage is a `HashMap` keyed on name to a single typed entry, exactly as Java's
//! `basicInfoMap` stores one `PropertyMapEntry` (type + value) per name.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::framework::store::local::item_property_file::ItemPropertyFile as ItemPropertyFileTrait;
use crate::util::exception::DuplicateFileException;
use crate::util::property_file::{PropertyFile, PROPERTY_EXT};

#[derive(Clone, PartialEq, Debug)]
enum PropEntry {
    Int(i32),
    Long(i64),
    Bool(bool),
    Str(String),
}

impl PropEntry {
    fn type_tag(&self) -> &'static str {
        match self {
            PropEntry::Int(_) => "int",
            PropEntry::Long(_) => "long",
            PropEntry::Bool(_) => "boolean",
            PropEntry::Str(_) => "string",
        }
    }

    fn value_string(&self) -> String {
        match self {
            PropEntry::Int(v) => v.to_string(),
            PropEntry::Long(v) => v.to_string(),
            PropEntry::Bool(v) => v.to_string(),
            PropEntry::Str(v) => v.clone(),
        }
    }
}

/// Concrete, file-backed implementation of [`PropertyFile`]. Mirrors the concrete
/// `ghidra.util.PropertyFile` class.
pub struct LocalPropertyFile {
    property_file: PathBuf,
    storage_name: String,
    properties: HashMap<String, PropEntry>,
}

impl LocalPropertyFile {
    /// Construct a new or existing PropertyFile. This constructor will not fail if the file does
    /// not exist.
    ///
    /// Mirrors `PropertyFile(File dir, String storageName)`.
    ///
    /// # Errors
    /// Returns an `io::Error` if `dir` is not an absolute path (folding Java's unchecked
    /// `IllegalArgumentException` into this already-fallible constructor), or if the file exists
    /// but could not be read/parsed.
    pub fn new(dir: &Path, storage_name: &str) -> io::Result<Self> {
        Self::construct(dir, storage_name, true)
    }

    /// Construct a new or existing PropertyFile *without* reading any pre-existing content, even
    /// if the file already exists.
    ///
    /// This stands in for the effect of Java's virtual dispatch: `InvalidPropertyFile` overrides
    /// `readState()` to a no-op specifically so the real `PropertyFile(File, String)`
    /// constructor's `if (propertyFile.exists()) { readState(); }` call resolves to that harmless
    /// override rather than attempting (and failing) to parse a file already known to be corrupt.
    /// Rust has no virtual dispatch during construction, so
    /// [`InvalidPropertyFile`](crate::framework::store::local::InvalidPropertyFile) instead builds
    /// its backing storage through this constructor to get the same net effect: no parse attempt
    /// is ever made.
    pub(crate) fn new_without_initial_read(dir: &Path, storage_name: &str) -> io::Result<Self> {
        Self::construct(dir, storage_name, false)
    }

    fn construct(dir: &Path, storage_name: &str, read_if_exists: bool) -> io::Result<Self> {
        if !dir.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dir must be specified by an absolute path",
            ));
        }
        let property_file = dir.join(format!("{storage_name}{PROPERTY_EXT}"));
        let mut me = Self {
            property_file,
            storage_name: storage_name.to_string(),
            properties: HashMap::new(),
        };
        if read_if_exists && me.property_file.exists() {
            me.read_state()?;
        }
        Ok(me)
    }

    /// Mirrors the protected `PropertyFile.contains(String)` helper used by
    /// `IndexedPropertyFile` to detect whether a property file already carries persisted
    /// `NAME`/`PARENT` values.
    pub(crate) fn contains(&self, key: &str) -> bool {
        self.properties.contains_key(key)
    }
}

impl PropertyFile for LocalPropertyFile {
    fn is_read_only(&self) -> bool {
        // Mirrors `!propertyFile.canWrite()`; Java's `File.canWrite()` returns false for a
        // nonexistent file, so a not-yet-written property file reports as read-only too.
        match fs::metadata(&self.property_file) {
            Ok(meta) => meta.permissions().readonly(),
            Err(_) => true,
        }
    }

    fn get_parent_storage_directory(&self) -> PathBuf {
        self.property_file
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_default()
    }

    fn get_storage_name(&self) -> String {
        self.storage_name.clone()
    }

    fn get_int(&self, property_name: &str, default_value: i32) -> i32 {
        match self.properties.get(property_name) {
            Some(PropEntry::Int(v)) => *v,
            _ => default_value,
        }
    }

    fn put_int(&mut self, property_name: &str, value: i32) {
        self.properties.insert(property_name.to_string(), PropEntry::Int(value));
    }

    fn get_long(&self, property_name: &str, default_value: i64) -> i64 {
        match self.properties.get(property_name) {
            Some(PropEntry::Long(v)) => *v,
            _ => default_value,
        }
    }

    fn put_long(&mut self, property_name: &str, value: i64) {
        self.properties.insert(property_name.to_string(), PropEntry::Long(value));
    }

    fn get_string(&self, property_name: &str, default_value: Option<&str>) -> Option<String> {
        match self.properties.get(property_name) {
            Some(PropEntry::Str(v)) => Some(v.clone()),
            _ => default_value.map(String::from),
        }
    }

    fn put_string(&mut self, property_name: &str, value: Option<&str>) {
        match value {
            Some(v) => {
                self.properties.insert(property_name.to_string(), PropEntry::Str(v.to_string()));
            }
            None => {
                self.properties.remove(property_name);
            }
        }
    }

    fn get_boolean(&self, property_name: &str, default_value: bool) -> bool {
        match self.properties.get(property_name) {
            Some(PropEntry::Bool(v)) => *v,
            _ => default_value,
        }
    }

    fn put_boolean(&mut self, property_name: &str, value: bool) {
        self.properties.insert(property_name.to_string(), PropEntry::Bool(value));
    }

    fn remove(&mut self, property_name: &str) {
        self.properties.remove(property_name);
    }

    fn last_modified(&self) -> i64 {
        fs::metadata(&self.property_file)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn write_state(&self) -> io::Result<()> {
        let mut out = File::create(&self.property_file)?;
        for (name, entry) in &self.properties {
            writeln!(
                out,
                "{}\t{}\t{}",
                encode_field(name),
                entry.type_tag(),
                encode_field(&entry.value_string())
            )?;
        }
        Ok(())
    }

    fn read_state(&mut self) -> io::Result<()> {
        let file = File::open(&self.property_file)?;
        let reader = BufReader::new(file);
        let mut props = HashMap::new();
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(3, '\t');
            let parse_err = || {
                io::Error::new(io::ErrorKind::InvalidData, "XML parse error in properties file")
            };
            let name = decode_field(parts.next().ok_or_else(parse_err)?);
            let ty = parts.next().ok_or_else(parse_err)?;
            let val = decode_field(parts.next().ok_or_else(parse_err)?);
            let entry = match ty {
                "int" => PropEntry::Int(val.parse::<i32>().map_err(|_| parse_err())?),
                "long" => PropEntry::Long(val.parse::<i64>().map_err(|_| parse_err())?),
                "boolean" => PropEntry::Bool(val == "true"),
                "string" => PropEntry::Str(val),
                _ => return Err(parse_err()),
            };
            props.insert(name, entry);
        }
        self.properties = props;
        Ok(())
    }

    fn move_to(&mut self, new_storage_parent: &Path, new_storage_name: &str) -> io::Result<()> {
        if new_storage_parent != self.get_parent_storage_directory().as_path()
            || new_storage_name != self.storage_name
        {
            let new_property_file = new_storage_parent.join(format!("{new_storage_name}{PROPERTY_EXT}"));
            if new_property_file.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    DuplicateFileException::new(format!("{} already exists", new_property_file.display())),
                ));
            }
            fs::rename(&self.property_file, &new_property_file)?;
            self.property_file = new_property_file;
            self.storage_name = new_storage_name.to_string();
        }
        Ok(())
    }

    fn exists(&self) -> bool {
        self.property_file.exists()
    }

    fn delete(&self) {
        let _ = fs::remove_file(&self.property_file);
    }
}

/// Escapes `\t`, `\n`, `\r`, and `\\` so a name/value can round-trip through the single-line
/// `name\ttype\tvalue` record format used by [`LocalPropertyFile::write_state`].
fn encode_field(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out
}

fn decode_field(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Concrete, file-backed implementation of [`ItemPropertyFileTrait`]. Mirrors the concrete
/// `ghidra.framework.store.local.ItemPropertyFile` class (`extends PropertyFile`); the Java
/// `extends` relationship is represented here as composition (`base: LocalPropertyFile`), per
/// this project's convention.
pub struct LocalItemPropertyFile {
    base: LocalPropertyFile,
    name: Option<String>,
    parent_path: Option<String>,
}

impl LocalItemPropertyFile {
    /// Mirrors `ItemPropertyFile(File dir, String storageName, String parentPath, String name)`.
    pub fn new(
        dir: &Path,
        storage_name: &str,
        parent_path: Option<&str>,
        name: Option<&str>,
    ) -> io::Result<Self> {
        Ok(Self {
            base: LocalPropertyFile::new(dir, storage_name)?,
            name: name.map(String::from),
            parent_path: parent_path.map(String::from),
        })
    }

    /// See [`LocalPropertyFile::new_without_initial_read`].
    pub(crate) fn new_without_initial_read(
        dir: &Path,
        storage_name: &str,
        parent_path: Option<&str>,
        name: Option<&str>,
    ) -> io::Result<Self> {
        Ok(Self {
            base: LocalPropertyFile::new_without_initial_read(dir, storage_name)?,
            name: name.map(String::from),
            parent_path: parent_path.map(String::from),
        })
    }

    pub(crate) fn contains(&self, key: &str) -> bool {
        self.base.contains(key)
    }

    pub(crate) fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    pub(crate) fn set_parent_path(&mut self, parent_path: Option<String>) {
        self.parent_path = parent_path;
    }
}

impl PropertyFile for LocalItemPropertyFile {
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
        // Mirrors what the Java superclass `PropertyFile.moveTo(File, String)` does. Per
        // `ItemPropertyFile`'s trait doc comment, this inherited/2-arg form is treated as
        // internal-only; `move_item_to` below is the supported external entry point (mirroring
        // Java's `final` override of this same signature that always throws
        // `UnsupportedOperationException` to force callers through the 4-arg `moveTo`).
        self.base.move_to(new_storage_parent, new_storage_name)
    }

    fn exists(&self) -> bool {
        self.base.exists()
    }

    fn delete(&self) {
        self.base.delete()
    }
}

impl ItemPropertyFileTrait for LocalItemPropertyFile {
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
        if self.parent_path.as_deref() != Some(new_parent_path) || self.name.as_deref() != Some(new_name)
        {
            self.parent_path = Some(new_parent_path.to_string());
            self.name = Some(new_name.to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tmp_dir(label: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("local_property_file_test_{}_{}_{}", std::process::id(), label, id));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn rejects_relative_dir() {
        let err = LocalPropertyFile::new(Path::new("relative/dir"), "x").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn round_trips_all_property_types() {
        let dir = tmp_dir("roundtrip");
        {
            let mut pf = LocalPropertyFile::new(&dir, "item").unwrap();
            pf.put_int("age", 42);
            pf.put_long("big", 1_000_000_000_000);
            pf.put_string("name", Some("hello"));
            pf.put_boolean("flag", true);
            pf.write_state().unwrap();
        }
        let pf = LocalPropertyFile::new(&dir, "item").unwrap();
        assert_eq!(pf.get_int("age", -1), 42);
        assert_eq!(pf.get_long("big", -1), 1_000_000_000_000);
        assert_eq!(pf.get_string("name", None).as_deref(), Some("hello"));
        assert!(pf.get_boolean("flag", false));
    }

    #[test]
    fn wrong_accessor_type_returns_default_without_coercion() {
        let mut pf = LocalPropertyFile::new(&tmp_dir("wrongtype"), "item").unwrap();
        pf.put_string("age", Some("42"));
        // Stored as a string, so the int accessor must not coerce it -- matches Java's
        // `PropertyEntryType` mismatch behavior in `getInt`/etc.
        assert_eq!(pf.get_int("age", -7), -7);
    }

    #[test]
    fn put_string_none_removes_property() {
        let mut pf = LocalPropertyFile::new(&tmp_dir("removal"), "item").unwrap();
        pf.put_string("k", Some("v"));
        assert_eq!(pf.get_string("k", None).as_deref(), Some("v"));
        pf.put_string("k", None);
        assert_eq!(pf.get_string("k", None), None);
    }

    #[test]
    fn escapes_tabs_and_newlines_in_values() {
        let dir = tmp_dir("escaping");
        {
            let mut pf = LocalPropertyFile::new(&dir, "item").unwrap();
            pf.put_string("weird", Some("a\tb\nc\\d"));
            pf.write_state().unwrap();
        }
        let pf = LocalPropertyFile::new(&dir, "item").unwrap();
        assert_eq!(pf.get_string("weird", None).as_deref(), Some("a\tb\nc\\d"));
    }

    #[test]
    fn move_to_relocates_file_and_rejects_duplicate() {
        let dir = tmp_dir("move_src");
        let dir2 = tmp_dir("move_dst");
        let mut pf = LocalPropertyFile::new(&dir, "item").unwrap();
        pf.write_state().unwrap();
        pf.move_to(&dir2, "item2").unwrap();
        assert!(pf.exists());
        assert_eq!(pf.get_storage_name(), "item2");
        assert!(!dir.join("item.prp").exists());

        // Now create a duplicate destination and try to move onto it.
        let mut pf2 = LocalPropertyFile::new(&dir, "item3").unwrap();
        pf2.write_state().unwrap();
        let err = pf2.move_to(&dir2, "item2").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn contains_reflects_stored_keys_only() {
        let mut pf = LocalPropertyFile::new(&tmp_dir("contains"), "item").unwrap();
        assert!(!pf.contains("k"));
        pf.put_int("k", 1);
        assert!(pf.contains("k"));
    }

    #[test]
    fn exists_and_delete() {
        let dir = tmp_dir("delete");
        let pf = LocalPropertyFile::new(&dir, "item").unwrap();
        assert!(!pf.exists());
        pf.write_state().unwrap();
        assert!(pf.exists());
        pf.delete();
        assert!(!pf.exists());
    }

    #[test]
    fn item_property_file_get_path_and_move_item_to() {
        let dir = tmp_dir("item_pf");
        let mut ipf = LocalItemPropertyFile::new(&dir, "thing", Some("/a"), Some("thing")).unwrap();
        assert_eq!(ipf.get_name().as_deref(), Some("thing"));
        assert_eq!(ipf.get_parent_path().as_deref(), Some("/a"));
        ipf.write_state().unwrap();

        let dir2 = tmp_dir("item_pf_dst");
        ipf.move_item_to(&dir2, "thing2", "/b", "thing2").unwrap();
        assert_eq!(ipf.get_name().as_deref(), Some("thing2"));
        assert_eq!(ipf.get_parent_path().as_deref(), Some("/b"));
        assert_eq!(ipf.get_storage_name(), "thing2");
    }

    #[test]
    fn new_without_initial_read_never_parses_existing_broken_file() {
        let dir = tmp_dir("no_read");
        let path = dir.join("item.prp");
        fs::write(&path, b"not a valid record\tline\textra\tfields\there").unwrap();
        // A normal `new` would attempt to parse this (and could fail); the "no initial read"
        // constructor must skip that attempt entirely, matching `InvalidPropertyFile`'s use case.
        let pf = LocalPropertyFile::new_without_initial_read(&dir, "item").unwrap();
        assert!(!pf.contains("anything"));
    }
}
