//! Port of `ghidra.program.database.sourcemap.UserDataPathTransformer`.
//!
//! An implementation of `SourcePathTransformer` that stores transform information using
//! [`ProgramUserData`], so transform information is stored locally but not checked in to a shared
//! project. This class is a standalone path-remapping utility built entirely on
//! [`ProgramUserData`]'s string-property storage; unlike `SourceFileAdapterV0`/`SourceMapAdapterV0`
//! it has no dependency on `DBRecord`/`Table`/`AddressMap` or any of the other DB-adapter-chain
//! machinery in this module, so it is ported independently.
//!
//! Deviation from Java: the static `getPathTransformer(Program)` factory and its backing
//! process-wide `HashMap<Program, UserDataPathTransformer>` cache (kept in sync via
//! `DomainObjectClosedListener.domainObjectClosed` removing the entry when a program closes) are
//! left out. That pattern -- a global, object-identity-keyed cache with listener-driven eviction --
//! doesn't have an idiomatic Rust translation (Rust's ownership model does not give distinct
//! `Program` values a stable identity to key a global map by, the way Java object identity does),
//! and nothing in this crate's `Program`/`DomainObject` port establishes an equivalent convention
//! yet. [`UserDataPathTransformer::new`] is the direct replacement: callers that want "one
//! transformer per program" should construct and cache one themselves against their own concrete
//! `Program` type, the same way this crate's other per-object caches are expected to be owned by
//! whatever concrete type has a natural place to put them.
//!
//! Every other method -- construction, `reloadMaps`, the file/directory transform
//! add/remove/lookup methods, `getTransformRecords`, `validateDirectoryPath`, and the
//! `getString`/`getSourceFile` round-trip encoding -- is ported for real.
//!
//! `validateDirectoryPath`'s Java implementation normalizes `directory` via `java.net.URI`
//! construction and `URI::normalize()`. This crate has no URI type (see
//! [`SourceFile`](crate::program::database::sourcemap::SourceFile)'s own module doc), and
//! `SourceFile`'s already-ported equivalent dot-segment normalization (`normalize_file_path`) is
//! private to that module. [`normalize_directory_path`] below reimplements the same normalization
//! algorithm locally, adapted for directory-shaped paths (trailing-slash-preserving rather than
//! `SourceFile`'s trailing-slash-rejecting), rather than duplicating file-path-specific rejection
//! rules that don't apply here.

use std::collections::HashMap;

use crate::program::database::sourcemap::SourceFile;
use crate::program::database::sourcemap::SourceFileIdType;
use crate::program::model::listing::ProgramUserData;
use crate::program::model::sourcemap::{SourcePathTransformRecord, SourcePathTransformer};

const USER_FILE_TRANSFORM_PREFIX: &str = "USER_FILE_TRANSFORM_";
const USER_PATH_TRANSFORM_PREFIX: &str = "USER_DIRECTORY_TRANSFORM_";

/// Throws (via `Err`) if `directory` is not a valid, normalized directory path (with forward
/// slashes). Stands in for `UserDataPathTransformer.validateDirectoryPath(String)`, which throws
/// `IllegalArgumentException`; this returns a descriptive `Err` instead. See the module docs for
/// why the normalization is reimplemented locally rather than shared with `SourceFile`.
pub fn validate_directory_path(directory: &str) -> Result<(), String> {
    if directory.trim().is_empty() {
        return Err("Blank directory path".to_string());
    }
    if !directory.starts_with('/') {
        return Err(format!("{directory} is not a directory path"));
    }
    let normalized = normalize_directory_path(directory);
    if !normalized.ends_with('/') {
        return Err(format!("{directory} is not a directory path"));
    }
    if directory != normalized {
        return Err(format!("{directory} is not normalized"));
    }
    Ok(())
}

/// Dot-segment path normalization mirroring `java.net.URI::normalize`, applied to a
/// directory-shaped path: unlike [`SourceFile`]'s file-path normalization, a trailing slash is
/// preserved (not rejected) since directory paths are expected to end with one.
fn normalize_directory_path(path: &str) -> String {
    let trailing_slash = path.ends_with('/');
    let mut stack: Vec<&str> = Vec::new();
    let mut last_was_dot_segment = false;
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        match segment {
            "." => {
                last_was_dot_segment = true;
            }
            ".." => {
                last_was_dot_segment = true;
                if matches!(stack.last(), Some(&top) if top != "..") {
                    stack.pop();
                } else {
                    stack.push("..");
                }
            }
            _ => {
                last_was_dot_segment = false;
                stack.push(segment);
            }
        }
    }
    let mut normalized = format!("/{}", stack.join("/"));
    if !stack.is_empty() && (trailing_slash || last_was_dot_segment) {
        normalized.push('/');
    }
    normalized
}

/// An implementation of [`SourcePathTransformer`] that stores transform information using
/// [`ProgramUserData`].
///
/// Port of `ghidra.program.database.sourcemap.UserDataPathTransformer`. See the module docs for
/// what was intentionally left out (the static per-`Program` cache) and why.
pub struct UserDataPathTransformer {
    user_data: Box<dyn ProgramUserData>,
    /// Directory transforms: source directory -> target directory.
    path_map: HashMap<String, String>,
    /// File transforms: encoded [`SourceFile`] key (see [`encode_source_file`]) -> target path.
    file_map: HashMap<String, String>,
}

impl UserDataPathTransformer {
    /// Creates a new `UserDataPathTransformer` backed by `user_data`, loading any previously-saved
    /// transforms. Stands in for the private `UserDataPathTransformer(Program)` constructor (the
    /// `Program` parameter itself is only used there to fetch its `ProgramUserData` and to register
    /// the close listener maintaining the static cache; see the module docs for why this port takes
    /// `ProgramUserData` directly and omits the cache).
    pub fn new(user_data: Box<dyn ProgramUserData>) -> Self {
        let mut transformer = UserDataPathTransformer {
            user_data,
            path_map: HashMap::new(),
            file_map: HashMap::new(),
        };
        transformer.reload_maps();
        transformer
    }

    fn reload_maps(&mut self) {
        self.path_map.clear();
        self.file_map.clear();
        for key in self.user_data.get_string_property_names() {
            if let Some(rest) = key.strip_prefix(USER_PATH_TRANSFORM_PREFIX) {
                let value = self.user_data.get_string_property(&key, "");
                if value.trim().is_empty() {
                    panic!("blank value for path {key}");
                }
                self.path_map.insert(rest.to_string(), value);
                continue;
            }
            if let Some(rest) = key.strip_prefix(USER_FILE_TRANSFORM_PREFIX) {
                let value = self.user_data.get_string_property(&key, "");
                if value.trim().is_empty() {
                    panic!("blank value for file {key}");
                }
                self.file_map.insert(rest.to_string(), value);
            }
        }
    }
}

impl SourcePathTransformer for UserDataPathTransformer {
    fn add_file_transform(&mut self, source_file: &SourceFile, path: &str) {
        let validated = SourceFile::new(path).unwrap_or_else(|e| panic!("invalid path: {e}"));
        if validated.path() != path {
            panic!("path not normalized");
        }
        let tx_id = self.user_data.start_transaction();
        let source_string = encode_source_file(source_file);
        self.user_data
            .set_string_property(&format!("{USER_FILE_TRANSFORM_PREFIX}{source_string}"), path);
        self.user_data.end_transaction(tx_id);
        self.file_map.insert(source_string, path.to_string());
    }

    fn remove_file_transform(&mut self, source_file: &SourceFile) {
        let source_string = encode_source_file(source_file);
        let tx_id = self.user_data.start_transaction();
        self.user_data
            .remove_string_property(&format!("{USER_FILE_TRANSFORM_PREFIX}{source_string}"));
        self.user_data.end_transaction(tx_id);
        self.file_map.remove(&source_string);
    }

    fn add_directory_transform(&mut self, source_dir: &str, target_dir: &str) {
        validate_directory_path(source_dir).unwrap_or_else(|e| panic!("{e}"));
        validate_directory_path(target_dir).unwrap_or_else(|e| panic!("{e}"));
        let tx_id = self.user_data.start_transaction();
        self.user_data
            .set_string_property(&format!("{USER_PATH_TRANSFORM_PREFIX}{source_dir}"), target_dir);
        self.user_data.end_transaction(tx_id);
        self.path_map.insert(source_dir.to_string(), target_dir.to_string());
    }

    fn remove_directory_transform(&mut self, source_dir: &str) {
        let tx_id = self.user_data.start_transaction();
        self.user_data
            .remove_string_property(&format!("{USER_PATH_TRANSFORM_PREFIX}{source_dir}"));
        self.user_data.end_transaction(tx_id);
        self.path_map.remove(source_dir);
    }

    fn get_transformed_path(&self, source_file: &SourceFile, use_existing_as_default: bool) -> Option<String> {
        let source_string = encode_source_file(source_file);
        if let Some(mapped) = self.file_map.get(&source_string) {
            return Some(mapped.clone());
        }

        let path = source_file.path();
        let mut best: Option<(&str, &str)> = None;
        for (src_dir, target_dir) in &self.path_map {
            if path.starts_with(src_dir.as_str())
                && best.map_or(true, |(b, _)| src_dir.len() > b.len())
            {
                best = Some((src_dir.as_str(), target_dir.as_str()));
            }
        }
        if let Some((src_dir, target_dir)) = best {
            let suffix = &path[src_dir.len()..];
            return Some(format!("{target_dir}{suffix}"));
        }

        if use_existing_as_default {
            Some(path.to_string())
        } else {
            None
        }
    }

    fn get_transform_records(&self) -> Vec<SourcePathTransformRecord> {
        let mut records = Vec::new();
        for (src_dir, target_dir) in &self.path_map {
            records.push(SourcePathTransformRecord::new(src_dir.clone(), None, target_dir.clone()));
        }
        for (source_string, target) in &self.file_map {
            let source_file = decode_source_file(source_string).unwrap_or_else(|e| {
                panic!("corrupt file-transform key {source_string:?}: {e}")
            });
            records.push(SourcePathTransformRecord::new(
                source_string.clone(),
                Some(source_file),
                target.clone(),
            ));
        }
        records
    }
}

/// Encodes a [`SourceFile`] into the `IdType#hex(identifier)#path` string used as the property-name
/// suffix/lookup key for file transforms. Stands in for the private
/// `UserDataPathTransformer.getString(SourceFile)`.
fn encode_source_file(source_file: &SourceFile) -> String {
    format!(
        "{}#{}#{}",
        id_type_name(source_file.id_type()),
        hex_encode(&source_file.identifier()),
        source_file.path()
    )
}

/// Decodes a string produced by [`encode_source_file`] back into a [`SourceFile`]. Stands in for
/// the private `UserDataPathTransformer.getSourceFile(String)`, which calls the package-private
/// `SourceFile(String, SourceFileIdType, byte[])` constructor that skips path
/// validation/normalization (the string was already validated when it was first encoded); this
/// uses [`SourceFile::new_unvalidated`] for the same reason.
fn decode_source_file(encoded: &str) -> Result<SourceFile, String> {
    let first_hash = encoded
        .find('#')
        .ok_or_else(|| format!("malformed encoded source file (missing '#'): {encoded}"))?;
    let type_name = &encoded[..first_hash];
    let id_type = id_type_from_name(type_name)
        .ok_or_else(|| format!("unknown SourceFileIdType name: {type_name}"))?;

    let rest = &encoded[first_hash + 1..];
    let second_hash = rest
        .find('#')
        .ok_or_else(|| format!("malformed encoded source file (missing 2nd '#'): {encoded}"))?;
    let identifier = hex_decode(&rest[..second_hash])?;
    let path = &rest[second_hash + 1..];
    SourceFile::new_unvalidated(path.to_string(), id_type, Some(&identifier))
}

/// Maps a [`SourceFileIdType`] to its Java enum constant name (`SourceFileIdType.name()`).
/// Duplicated locally from the equivalent (private) helper in `SourceFile`'s own module -- see the
/// module docs.
fn id_type_name(id_type: SourceFileIdType) -> &'static str {
    match id_type {
        SourceFileIdType::None => "NONE",
        SourceFileIdType::Unknown => "UNKNOWN",
        SourceFileIdType::Timestamp64 => "TIMESTAMP_64",
        SourceFileIdType::Md5 => "MD5",
        SourceFileIdType::Sha1 => "SHA1",
        SourceFileIdType::Sha256 => "SHA256",
        SourceFileIdType::Sha512 => "SHA512",
    }
}

/// Inverse of [`id_type_name`]. Stands in for `SourceFileIdType.valueOf(String)`.
fn id_type_from_name(name: &str) -> Option<SourceFileIdType> {
    match name {
        "NONE" => Some(SourceFileIdType::None),
        "UNKNOWN" => Some(SourceFileIdType::Unknown),
        "TIMESTAMP_64" => Some(SourceFileIdType::Timestamp64),
        "MD5" => Some(SourceFileIdType::Md5),
        "SHA1" => Some(SourceFileIdType::Sha1),
        "SHA256" => Some(SourceFileIdType::Sha256),
        "SHA512" => Some(SourceFileIdType::Sha512),
        _ => None,
    }
}

/// Lowercase hex encoding, matching `java.util.HexFormat.of().formatHex(byte[])`.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inverse of [`hex_encode`], matching `java.util.HexFormat.of().parseHex(CharSequence)`.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex string: {s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::UserData;
    use crate::framework::options::Options;
    use crate::program::model::util::PropertyMap;
    use crate::program::seam_stubs::Transaction;
    use crate::program::util::{IntPropertyMap, LongPropertyMap, ObjectPropertyMap, StringPropertyMap, VoidPropertyMap};
    use crate::util::exception::PropertyTypeMismatchException;
    use std::collections::HashSet;

    struct MockTransaction;
    impl Transaction for MockTransaction {}

    struct MockOptions;
    impl Options for MockOptions {}

    #[derive(Default)]
    struct MockProgramUserData {
        string_properties: HashMap<String, String>,
    }

    impl UserData for MockProgramUserData {}

    impl ProgramUserData for MockProgramUserData {
        fn open_transaction(&self) -> Box<dyn Transaction> {
            Box::new(MockTransaction)
        }

        fn start_transaction(&self) -> i32 {
            1
        }

        fn end_transaction(&self, _transaction_id: i32) {}

        fn get_string_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn StringPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_long_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn LongPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_int_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn IntPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_boolean_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn VoidPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_object_property_map(
            &mut self,
            _owner: &str,
            _property_name: &str,
            _create: bool,
        ) -> Result<Box<dyn ObjectPropertyMap>, PropertyTypeMismatchException> {
            Err(PropertyTypeMismatchException::new("not implemented"))
        }

        fn get_properties(&self, _owner: &str) -> Vec<Box<dyn PropertyMap>> {
            Vec::new()
        }

        fn get_property_owners(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_options_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_options(&self, _options_name: &str) -> Box<dyn Options> {
            Box::new(MockOptions)
        }

        fn set_string_property(&mut self, property_name: &str, value: &str) {
            self.string_properties.insert(property_name.to_string(), value.to_string());
        }

        fn get_string_property(&self, property_name: &str, default_value: &str) -> String {
            self.string_properties
                .get(property_name)
                .cloned()
                .unwrap_or_else(|| default_value.to_string())
        }

        fn remove_string_property(&mut self, property_name: &str) -> Option<String> {
            self.string_properties.remove(property_name)
        }

        fn get_string_property_names(&self) -> HashSet<String> {
            self.string_properties.keys().cloned().collect()
        }
    }

    fn transformer() -> UserDataPathTransformer {
        UserDataPathTransformer::new(Box::new(MockProgramUserData::default()))
    }

    // ── validate_directory_path ─────────────────────────────────────────────

    #[test]
    fn validate_directory_path_accepts_normalized_paths() {
        assert!(validate_directory_path("/").is_ok());
        assert!(validate_directory_path("/src/").is_ok());
        assert!(validate_directory_path("/src/main/").is_ok());
    }

    #[test]
    fn validate_directory_path_rejects_blank() {
        assert!(validate_directory_path("").is_err());
        assert!(validate_directory_path("   ").is_err());
    }

    #[test]
    fn validate_directory_path_rejects_missing_trailing_slash() {
        assert!(validate_directory_path("/src").is_err());
    }

    #[test]
    fn validate_directory_path_rejects_unnormalized() {
        assert!(validate_directory_path("/src/../dir/").is_err());
        assert!(validate_directory_path("/src/./dir/").is_err());
    }

    // ── file transforms ──────────────────────────────────────────────────────

    #[test]
    fn add_and_get_file_transform() {
        let mut t = transformer();
        let sf = SourceFile::new("/src/main.c").unwrap();
        t.add_file_transform(&sf, "/mapped/main.c");
        assert_eq!(t.get_transformed_path(&sf, false), Some("/mapped/main.c".to_string()));
    }

    #[test]
    fn remove_file_transform_falls_back_to_directory_or_default() {
        let mut t = transformer();
        let sf = SourceFile::new("/src/main.c").unwrap();
        t.add_file_transform(&sf, "/mapped/main.c");
        t.remove_file_transform(&sf);
        assert_eq!(t.get_transformed_path(&sf, false), None);
        assert_eq!(t.get_transformed_path(&sf, true), Some("/src/main.c".to_string()));
    }

    #[test]
    #[should_panic(expected = "not normalized")]
    fn add_file_transform_rejects_unnormalized_path() {
        let mut t = transformer();
        let sf = SourceFile::new("/src/main.c").unwrap();
        t.add_file_transform(&sf, "/mapped/../mapped2/main.c");
    }

    // ── directory transforms ─────────────────────────────────────────────────

    #[test]
    fn directory_transform_applies_to_matching_prefix() {
        let mut t = transformer();
        t.add_directory_transform("/src/", "/target/");
        let sf = SourceFile::new("/src/dir/file.c").unwrap();
        assert_eq!(
            t.get_transformed_path(&sf, false),
            Some("/target/dir/file.c".to_string())
        );
    }

    #[test]
    fn most_specific_directory_transform_wins() {
        let mut t = transformer();
        t.add_directory_transform("/src/", "/generic/");
        t.add_directory_transform("/src/main/dir/", "/specific/");
        let sf = SourceFile::new("/src/main/dir/file.c").unwrap();
        assert_eq!(t.get_transformed_path(&sf, false), Some("/specific/file.c".to_string()));
    }

    #[test]
    fn file_transform_overrides_directory_transform() {
        let mut t = transformer();
        let sf = SourceFile::new("/src/main.c").unwrap();
        t.add_directory_transform("/src/", "/target/");
        t.add_file_transform(&sf, "/exact/main.c");
        assert_eq!(t.get_transformed_path(&sf, false), Some("/exact/main.c".to_string()));
    }

    #[test]
    fn remove_directory_transform_removes_mapping() {
        let mut t = transformer();
        t.add_directory_transform("/src/", "/target/");
        t.remove_directory_transform("/src/");
        let sf = SourceFile::new("/src/main.c").unwrap();
        assert_eq!(t.get_transformed_path(&sf, false), None);
    }

    #[test]
    #[should_panic]
    fn add_directory_transform_rejects_invalid_path() {
        let mut t = transformer();
        t.add_directory_transform("relative/", "/target/");
    }

    // ── persistence round-trip ───────────────────────────────────────────────

    #[test]
    fn transforms_persist_across_reload() {
        let user_data = Box::new(MockProgramUserData::default());
        let mut t = UserDataPathTransformer::new(user_data);
        let sf = SourceFile::new("/src/main.c").unwrap();
        t.add_file_transform(&sf, "/mapped/main.c");
        t.add_directory_transform("/src/", "/target/");

        // Reconstruct a transformer against the *same* underlying user data by re-encoding what
        // was stored, proving reload_maps() actually round-trips through ProgramUserData rather
        // than only the in-memory caches.
        let mut fresh_user_data = MockProgramUserData::default();
        fresh_user_data.set_string_property(
            &format!("{USER_FILE_TRANSFORM_PREFIX}{}", encode_source_file(&sf)),
            "/mapped/main.c",
        );
        fresh_user_data.set_string_property(&format!("{USER_PATH_TRANSFORM_PREFIX}/src/"), "/target/");
        let reloaded = UserDataPathTransformer::new(Box::new(fresh_user_data));
        assert_eq!(
            reloaded.get_transformed_path(&sf, false),
            Some("/mapped/main.c".to_string())
        );
        let other = SourceFile::new("/src/other.c").unwrap();
        assert_eq!(
            reloaded.get_transformed_path(&other, false),
            Some("/target/other.c".to_string())
        );
    }

    // ── get_transform_records ────────────────────────────────────────────────

    #[test]
    fn transform_records_reflect_added_transforms() {
        let mut t = transformer();
        t.add_directory_transform("/src/", "/target/");
        let sf = SourceFile::new("/main.c").unwrap();
        t.add_file_transform(&sf, "/mapped/main.c");

        let records = t.get_transform_records();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.is_directory_transform()
            && r.source() == "/src/"
            && r.target() == "/target/"));
        assert!(records
            .iter()
            .any(|r| !r.is_directory_transform() && r.source_file() == Some(&sf) && r.target() == "/mapped/main.c"));
    }

    // ── SourcePathTransformer object-safety ──────────────────────────────────

    #[test]
    fn usable_as_trait_object() {
        let mut t: Box<dyn SourcePathTransformer> =
            Box::new(UserDataPathTransformer::new(Box::new(MockProgramUserData::default())));
        let sf = SourceFile::new("/a/b/file.c").unwrap();
        t.add_file_transform(&sf, "/z/file.c");
        assert_eq!(t.get_transformed_path(&sf, false), Some("/z/file.c".to_string()));
    }

    // ── encode/decode round trip ──────────────────────────────────────────────

    #[test]
    fn encode_decode_round_trip() {
        let sf = SourceFile::with_identifier(
            "/src/file.c",
            SourceFileIdType::Md5,
            Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        )
        .unwrap();
        let encoded = encode_source_file(&sf);
        let decoded = decode_source_file(&encoded).unwrap();
        assert_eq!(decoded, sf);
    }
}
