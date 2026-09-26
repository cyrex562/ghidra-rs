//! Rust port of `ghidra.formats.gfilesystem.FSRL`.
//!
//! A _F_ile _S_ystem _R_esource _L_ocator locates a resource (by name) on a "filesystem", in a
//! recursively nested fashion. The string format is `fstype://path?MD5=optional_md5` possibly
//! followed by more `|fstype://path...` parts for nested filesystems -- read right-to-left, ie.
//! `"file://z|y://x"` is "file x inside filesystem y inside container file z".
//!
//! # Shape
//!
//! Java's `FSRL` is a concrete, immutable value class and `FSRLRoot extends FSRL` (a root *is*
//! an FSRL whose `getFS()` is itself and whose `path` field holds the protocol). Both are
//! modelled by the single reference-counted value type [`Fsrl`]: each node holds its Java
//! `parent` (for a plain FSRL always the owning root; for a root, its optional container FSRL),
//! its `path` field and its MD5, plus a flag saying whether it is a root. Because instances are
//! immutable, sharing the parent chain through an [`Arc`] is safe and cloning is cheap.
//! [`FsrlRoot`](super::fsrl_root::FsrlRoot) is a newtype over an [`Fsrl`] known to be a root,
//! and dereferences to it -- the Rust spelling of "`FSRLRoot` is an `FSRL`".

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use crate::filesystem::gfilesystem::fs_utilities::{self, MalformedUrlError};
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::framework::options::options::Options;
use crate::program::model::listing::program::{Program, PROGRAM_INFO};

/// Name of the query parameter used to encode an MD5 hash in a string-ified FSRL.
///
/// Mirrors `FSRL.PARAM_MD5`.
pub const PARAM_MD5: &str = "MD5";

/// Name of the program-info option that records the FSRL a program was imported from.
///
/// Mirrors `FSRL.FSRL_OPTION_NAME`.
pub const FSRL_OPTION_NAME: &str = "FSRL";

/// The shared, immutable state of one FSRL node (Java's three `FSRL` fields plus the
/// `instanceof FSRLRoot` bit).
#[derive(PartialEq, Eq, Hash)]
pub(super) struct FsrlNode {
    /// Java `FSRL.parent`: the owning root for a plain FSRL, the container (if any) for a root.
    pub(super) parent: Option<Fsrl>,
    /// Java `FSRL.path`: the path for a plain FSRL, the protocol for a root.
    pub(super) path: Option<String>,
    /// Java `FSRL.md5` (always `None` for a root).
    pub(super) md5: Option<String>,
    /// `true` if this node is an `FSRLRoot`.
    pub(super) is_root: bool,
}

/// A _F_ile _S_ystem _R_esource _L_ocator. See the [module docs](self) for the string format
/// and representation.
///
/// Equality and hashing mirror Java's `equals`/`hashCode`: the full parent chain, path and MD5
/// all participate.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Fsrl(pub(super) Arc<FsrlNode>);

impl Fsrl {
    /// Mirrors the protected 3-arg `FSRL(FSRL parent, String path, String md5)` constructor for
    /// a plain (non-root) FSRL.
    pub(super) fn new_file(fs: &FsrlRoot, path: Option<String>, md5: Option<String>) -> Fsrl {
        Fsrl(Arc::new(FsrlNode {
            parent: Some(fs.as_fsrl().clone()),
            path,
            md5,
            is_root: false,
        }))
    }

    /// Creates an [`Fsrl`] instance from a FSRL-formatted string, eg.
    /// `"file://path/filename?MD5=1234|subfs://subpath/subfile"`.
    ///
    /// Mirrors `FSRL.fromString(String)`.
    ///
    /// # Errors
    /// [`MalformedUrlError`] if a part lacks a `proto://` prefix or contains a bad `%` escape.
    /// A string with no parts at all (eg. `"|"`, for which Java returns `null`) is also
    /// reported as malformed.
    pub fn from_string(fsrl_str: &str) -> Result<Fsrl, MalformedUrlError> {
        Self::parse_parts(None, fsrl_str)?
            .ok_or_else(|| MalformedUrlError(format!("No FSRL parts in {fsrl_str}")))
    }

    /// Creates an [`Fsrl`] instance from a FSRL-formatted string, using `parent` as the
    /// container of the first (outermost) part. A string with no parts returns `parent`.
    ///
    /// Mirrors `FSRL.fromString(FSRL, String)`.
    ///
    /// # Errors
    /// See [`Fsrl::from_string`].
    ///
    /// # Panics
    /// If `parent` is a filesystem root (Java throws a `RuntimeException` from
    /// `FSRLRoot.nestedFS`).
    pub fn from_string_with_parent(parent: &Fsrl, fsrl_str: &str) -> Result<Fsrl, MalformedUrlError> {
        Ok(Self::parse_parts(Some(parent.clone()), fsrl_str)?.unwrap_or_else(|| parent.clone()))
    }

    fn parse_parts(mut parent: Option<Fsrl>, fsrl_str: &str) -> Result<Option<Fsrl>, MalformedUrlError> {
        for part_str in java_split_pipe(java_trim(fsrl_str)) {
            parent = Some(Self::from_part_string(parent.as_ref(), part_str)?);
        }
        Ok(parent)
    }

    /// Mirrors the private `FSRL.fromPartString(FSRL, String)`.
    fn from_part_string(container_file: Option<&Fsrl>, part_str: &str) -> Result<Fsrl, MalformedUrlError> {
        let part_str = java_trim(part_str);
        let colon_slash_slash = match part_str.find("://") {
            Some(i) if i > 0 => i,
            _ => return Err(MalformedUrlError(format!("Missing protocol in {part_str}"))),
        };
        let proto = &part_str[..colon_slash_slash];
        let mut path = &part_str[colon_slash_slash + 3..];
        let mut md5 = None;
        if let Some(param_start) = path.find('?') {
            let params = &path[param_start + 1..];
            path = &path[..param_start];
            md5 = get_param_map_from_string(params)?.remove(PARAM_MD5);
        }
        let fs_root = FsrlRoot::nested_fs(container_file, proto);
        let decoded_path = fs_utilities::escape_decode(path)?;
        let decoded_path = if decoded_path.is_empty() { None } else { Some(decoded_path) };
        Ok(Fsrl::new_file(&fs_root, decoded_path, md5))
    }

    /// Returns the FSRL stored in `program`'s program-info options, or `None` if it has none or
    /// the stored value does not parse.
    ///
    /// Mirrors `FSRL.fromProgram(Program)`.
    pub fn from_program(program: &(impl Program + ?Sized)) -> Option<Fsrl> {
        Self::from_program_info(&*program.get_options(PROGRAM_INFO))
    }

    /// Writes `fsrl` into `program`'s program-info options.
    ///
    /// Mirrors `FSRL.writeToProgramInfo(Program, FSRL)`.
    pub fn write_to_program_info(program: &(impl Program + ?Sized), fsrl: &Fsrl) {
        let mut options = program.get_options(PROGRAM_INFO);
        Self::write_to_program_info_options(&mut *options, fsrl);
    }

    /// The options-level half of [`Fsrl::from_program`]: reads the [`FSRL_OPTION_NAME`] option
    /// from an already-fetched program-info options list.
    pub fn from_program_info(options: &dyn Options) -> Option<Fsrl> {
        if !options.contains(FSRL_OPTION_NAME) {
            return None;
        }
        Fsrl::from_string(&options.get_string(FSRL_OPTION_NAME, "")).ok()
    }

    /// The options-level half of [`Fsrl::write_to_program_info`].
    pub fn write_to_program_info_options(options: &mut dyn Options, fsrl: &Fsrl) {
        options.set_string(FSRL_OPTION_NAME, &fsrl.to_string());
    }

    /// Returns the container of `fsrl` if it is a filesystem root that has one, otherwise
    /// `fsrl` itself.
    ///
    /// Mirrors `FSRL.convertRootToContainer(FSRL)`.
    pub fn convert_root_to_container(fsrl: &Fsrl) -> Fsrl {
        match fsrl.as_root() {
            Some(root) if root.has_container() => root.container().cloned().unwrap_or_else(|| fsrl.clone()),
            _ => fsrl.clone(),
        }
    }

    /// `true` if this FSRL is a filesystem root (Java `instanceof FSRLRoot`).
    pub fn is_root(&self) -> bool {
        self.0.is_root
    }

    /// This FSRL viewed as a [`FsrlRoot`], if it is one.
    pub fn as_root(&self) -> Option<FsrlRoot> {
        self.is_root().then(|| FsrlRoot::from_root_fsrl(self.clone()))
    }

    /// The [`FsrlRoot`] that represents the entire filesystem this FSRL is located within; a
    /// root returns itself.
    ///
    /// Mirrors `getFS()` (and `FSRLRoot`'s override of it).
    pub fn fs(&self) -> FsrlRoot {
        if self.is_root() {
            FsrlRoot::from_root_fsrl(self.clone())
        } else {
            let parent = self.0.parent.clone().expect("a non-root FSRL always has a root parent");
            FsrlRoot::from_root_fsrl(parent)
        }
    }

    /// The number of [`FsrlRoot`]s there are in this FSRL, minimum 1.
    ///
    /// Mirrors `getNestingDepth()`.
    pub fn nesting_depth(&self) -> u32 {
        let mut depth = 0;
        let mut root = Some(self.fs());
        while let Some(r) = root {
            depth += 1;
            root = r.container().map(Fsrl::fs);
        }
        depth
    }

    /// The full path/filename of this FSRL, not including the filesystem root portion; `None`
    /// for a filesystem root.
    ///
    /// Mirrors `getPath()`.
    pub fn path(&self) -> Option<&str> {
        if self.is_root() { None } else { self.0.path.as_deref() }
    }

    /// The name portion of this FSRL's path, everything after the last `/`; `None` for a
    /// filesystem root or a path-less FSRL.
    ///
    /// Mirrors `getName()`.
    pub fn name(&self) -> Option<String> {
        let path = self.path()?;
        let mut cp = path.rfind('/');
        if let Some(c) = cp {
            if c > 0 && c == path.len() - 1 {
                // path ended with a '/' (typically a windows drive letter path like "/c:/")
                cp = path[..c].rfind('/');
            }
        }
        Some(match cp {
            Some(c) => path[c + 1..].to_string(),
            None => path.to_string(),
        })
    }

    /// The name portion of the FSRL part at parent depth `nested_depth`, where 0 is this
    /// instance, 1 is the parent container's name, etc.
    ///
    /// Mirrors `getName(int)`.
    ///
    /// # Errors
    /// If `nested_depth` is greater than the number of parent containers.
    pub fn name_at_depth(&self, nested_depth: u32) -> io::Result<Option<String>> {
        let mut current = self.clone();
        for _ in 0..nested_depth {
            let parent_container = current.fs().container().cloned();
            match parent_container {
                Some(p) => current = p,
                None => {
                    return Err(io::Error::other(format!(
                        "Unknown requested FSRL parent, requested depth {}, only {} available in {}",
                        nested_depth,
                        self.nesting_depth(),
                        self
                    )));
                }
            }
        }
        Ok(current.name())
    }

    /// The MD5 hash associated with this file, if known.
    ///
    /// Mirrors `getMD5()`.
    pub fn md5(&self) -> Option<&str> {
        self.0.md5.as_deref()
    }

    /// Tests `other_md5` against this FSRL's MD5, case-insensitively.
    ///
    /// Mirrors `isMD5Equal(String)`.
    pub fn is_md5_equal(&self, other_md5: Option<&str>) -> bool {
        match self.md5() {
            None => other_md5.is_none(),
            Some(m) => other_md5.is_some_and(|o| m.eq_ignore_ascii_case(o)),
        }
    }

    /// A FSRL with the same path but a new MD5 value (this same instance if unchanged).
    ///
    /// Mirrors `withMD5(String)`.
    pub fn with_md5(&self, new_md5: Option<&str>) -> Fsrl {
        if self.md5() == new_md5 {
            self.clone()
        } else {
            Fsrl::new_file(&self.fs(), self.path().map(str::to_owned), new_md5.map(str::to_owned))
        }
    }

    /// A new FSRL with the same filesystem root but a new path (and no MD5).
    ///
    /// Mirrors `withPath(String)`.
    pub fn with_path(&self, new_path: &str) -> Fsrl {
        Fsrl::new_file(&self.fs(), Some(new_path.to_string()), None)
    }

    /// A new FSRL with this instance's filesystem root, but the path and MD5 of `copy_path`.
    ///
    /// Mirrors `withPath(FSRL)`.
    pub fn with_path_from(&self, copy_path: &Fsrl) -> Fsrl {
        Fsrl::new_file(
            &self.fs(),
            copy_path.path().map(str::to_owned),
            copy_path.md5().map(str::to_owned),
        )
    }

    /// A new FSRL with `rel_path` appended to this instance's path (and no MD5).
    ///
    /// Mirrors `appendPath(String)`.
    pub fn append_path(&self, rel_path: &str) -> Fsrl {
        let base_path = self.path().unwrap_or("/");
        Fsrl::new_file(&self.fs(), fs_utilities::append_path(&[Some(base_path), Some(rel_path)]), None)
    }

    /// Creates a new filesystem root nested as a child of this FSRL.
    ///
    /// Mirrors `makeNested(String)`.
    ///
    /// # Panics
    /// If this FSRL is itself a filesystem root (see [`FsrlRoot::nested_fs`]).
    pub fn make_nested(&self, fstype: &str) -> FsrlRoot {
        FsrlRoot::nested_fs(Some(self), fstype)
    }

    /// The full FSRL as a string, excluding MD5 portions.
    ///
    /// Mirrors `toPrettyString()`.
    pub fn to_pretty_string(&self) -> String {
        let mut s = String::new();
        self.append_to_string_builder(&mut s, true, false, true);
        s
    }

    /// The full FSRL as a string, excluding MD5 portions and `fstype://` prefixes.
    ///
    /// Mirrors `toPrettyFullpathString()`.
    pub fn to_pretty_fullpath_string(&self) -> String {
        let mut s = String::new();
        self.append_to_string_builder(&mut s, true, false, false);
        s
    }

    /// Just the current FSRL protocol and path, excluding parent filesystem parts.
    ///
    /// Mirrors `toStringPart()`.
    pub fn to_string_part(&self) -> String {
        let mut s = String::new();
        self.append_to_string_builder(&mut s, false, true, true);
        s
    }

    /// Mirrors the protected `appendToStringBuilder` (and `FSRLRoot`'s override of it).
    pub(super) fn append_to_string_builder(
        &self,
        sb: &mut String,
        recurse: bool,
        include_params: bool,
        include_fs_root: bool,
    ) {
        if self.is_root() {
            if let (Some(container), true) = (&self.0.parent, recurse) {
                container.append_to_string_builder(sb, recurse, include_params, include_fs_root);
                sb.push('|');
            }
            if include_fs_root {
                sb.push_str(self.0.path.as_deref().unwrap_or("null"));
                sb.push_str("://");
            }
            return;
        }
        if let Some(parent) = &self.0.parent {
            parent.append_to_string_builder(sb, recurse, include_params, include_fs_root);
        }
        if let Some(p) = &self.0.path {
            sb.push_str(&fs_utilities::escape_encode(p));
        }
        // no need to encode md5 string since all hexdigit chars are safe
        if let (Some(m), true) = (&self.0.md5, include_params) {
            sb.push('?');
            sb.push_str(PARAM_MD5);
            sb.push('=');
            sb.push_str(m);
        }
    }

    /// Splits this FSRL into a list, with each element pointing to each level of the full FSRL,
    /// ordered from the outermost container to this instance.
    ///
    /// Mirrors `split()`.
    pub fn split(&self) -> Vec<Fsrl> {
        let mut result = Vec::new();
        let mut current = Some(self.clone());
        while let Some(c) = current {
            current = c.fs().container().cloned();
            result.push(c);
        }
        result.reverse();
        result
    }

    /// `true` if this FSRL, string-ified, is the same as `fsrl_str`, excluding MD5 values.
    ///
    /// Mirrors `isEquivalent(String)`.
    pub fn is_equivalent_str(&self, fsrl_str: Option<&str>) -> bool {
        let Some(fsrl_str) = fsrl_str else {
            return false;
        };
        let s = self.to_string();
        s == fsrl_str
            || (self.md5().is_some()
                && s.starts_with(fsrl_str)
                && s[fsrl_str.len()..].starts_with("?MD5=")
                && s.len() == fsrl_str.len() + 37)
            || (self.md5().is_none()
                && fsrl_str.starts_with(&s)
                && fsrl_str[s.len()..].starts_with("?MD5=")
                && fsrl_str.len() == s.len() + 37)
    }

    /// `true` if this FSRL is the same as `other`, excluding MD5 values (at every level).
    ///
    /// Mirrors `isEquivalent(FSRL)`.
    pub fn is_equivalent(&self, other: &Fsrl) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) {
            return true;
        }
        let parents_equiv = match (&self.0.parent, &other.0.parent) {
            (None, None) => true,
            (Some(a), Some(b)) => a.is_equivalent(b),
            _ => false,
        };
        parents_equiv && self.0.path == other.0.path
    }

    /// `true` if this FSRL is a child or descendant of `potential_parent`.
    ///
    /// Mirrors `isDescendantOf(FSRL)`.
    pub fn is_descendant_of(&self, potential_parent: &Fsrl) -> bool {
        if self.is_equivalent(potential_parent) {
            return false;
        }
        let parent_fs = potential_parent.fs();
        self.split().iter().rev().any(|my_part| {
            my_part.fs() == parent_fs
                && (my_part.path() == potential_parent.path()
                    || match (potential_parent.path(), my_part.path()) {
                        (Some(pp), Some(mp)) => is_parent_path(pp, mp),
                        _ => false,
                    })
        })
    }
}

/// Mirrors `toString()`, eg. `"file://path|subfs://blah?MD5=1234567"`.
impl fmt::Display for Fsrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        self.append_to_string_builder(&mut s, true, true, true);
        f.write_str(&s)
    }
}

impl fmt::Debug for Fsrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fsrl({self})")
    }
}

/// `true` if `child` is `parent` plus at least one more path segment.
///
/// Mirrors the private static `FSRL.isParentPath`.
fn is_parent_path(parent: &str, child: &str) -> bool {
    child.starts_with(parent)
        && child.len() > parent.len()
        && (parent.ends_with('/') || child.as_bytes()[parent.len()] == b'/')
}

/// Mirrors the private `FSRL.getParamMapFromString`.
fn get_param_map_from_string(params_str: &str) -> Result<HashMap<String, String>, MalformedUrlError> {
    let mut param_map = HashMap::new();
    for field in params_str.split('&') {
        let equal_idx = field.find('=');
        let name = match equal_idx {
            Some(i) if i > 0 => &field[..i],
            _ => "",
        };
        let value = match equal_idx {
            Some(i) => &field[i + 1..],
            None => field,
        };
        param_map.insert(fs_utilities::escape_decode(name)?, fs_utilities::escape_decode(value)?);
    }
    Ok(param_map)
}

/// Java `String.trim()`: strips leading/trailing chars `<= ' '`.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// Java `String.split("\\|")`: splits on `|` and drops trailing empty strings (a string with
/// no `|` at all yields itself, even if empty).
fn java_split_pipe(s: &str) -> Vec<&str> {
    if !s.contains('|') {
        return vec![s];
    }
    let mut parts: Vec<&str> = s.split('|').collect();
    while parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::rc::Rc;

    fn f(s: &str) -> Fsrl {
        Fsrl::from_string(s).unwrap()
    }

    fn hash_of(x: &Fsrl) -> u64 {
        let mut h = DefaultHasher::new();
        x.hash(&mut h);
        h.finish()
    }

    // ── FSRLTest.java ─────────────────────────────────────────────────────────

    #[test]
    fn test_fsrl_builders() {
        let fsrl1 = FsrlRoot::make_root("file").with_path("blah");
        assert_eq!(fsrl1.to_string(), "file://blah");

        let fsrl2 = fsrl1.with_path("newpath");
        assert_eq!(fsrl2.to_string(), "file://newpath");

        let nested_fs = FsrlRoot::nested_fs(Some(&fsrl1), "subfs");
        assert_eq!(nested_fs.to_string(), "file://blah|subfs://");

        assert_eq!(fsrl1.append_path("relpath").to_string(), "file://blah/relpath");
        assert_eq!(fsrl1.append_path("/relpath").to_string(), "file://blah/relpath");
    }

    #[test]
    fn test_empty_fsrl() {
        let fsrl = f("fsrl://");
        assert_eq!(fsrl.fs().protocol(), "fsrl");
        assert_eq!(fsrl.path(), None);
        assert_eq!(fsrl.name(), None);
        assert_eq!(fsrl.md5(), None);
    }

    #[test]
    fn test_empty_str() {
        assert!(Fsrl::from_string("").is_err());
        assert!(Fsrl::from_string("://x").is_err());
        assert!(Fsrl::from_string("nocolon").is_err());
    }

    #[test]
    fn test_special_chars() {
        let fsrl = f("fsrl://a:/path/filename+$dollar%20%7cblah?params");
        assert_eq!(fsrl.fs().protocol(), "fsrl");
        assert_eq!(fsrl.path(), Some("a:/path/filename+$dollar |blah"));
        assert_eq!(fsrl.name().as_deref(), Some("filename+$dollar |blah"));
    }

    #[test]
    fn test_paths_with_backslashes() {
        let fsrl = f("fsrl:///dir/filename\\with\\backslashes");
        assert_eq!(fsrl.fs().protocol(), "fsrl");
        assert_eq!(fsrl.path(), Some("/dir/filename\\with\\backslashes"));
        assert_eq!(fsrl.name().as_deref(), Some("filename\\with\\backslashes"));
    }

    #[test]
    fn test_char_encode_round_trips() {
        let orig: String = (0u32..255).map(|i| char::from_u32(i).unwrap()).collect();
        let encoded = fs_utilities::escape_encode(&orig);
        assert_eq!(fs_utilities::escape_decode(&encoded).unwrap(), orig);

        for orig in ["test\u{01a5}1299", "test\u{01a5}\u{01a6}1299"] {
            let encoded = fs_utilities::escape_encode(orig);
            assert_eq!(fs_utilities::escape_decode(&encoded).unwrap(), orig);
        }
    }

    #[test]
    fn test_escape_decode_errors() {
        assert!(fs_utilities::escape_decode("abc%2").is_err());
        assert!(fs_utilities::escape_decode("abc%zz").is_err());
        assert!(fs_utilities::escape_decode("abc%-1").is_err());
    }

    #[test]
    fn test_string_format() {
        let fsrl = f("fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile");
        assert_eq!(fsrl.to_string(), "fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile");
        assert_eq!(fsrl.to_pretty_string(), "fsrl://path/filename|subfsrl://subpath/subfile");
        assert_eq!(fsrl.to_string_part(), "subfsrl://subpath/subfile");
        assert_eq!(fsrl.to_pretty_fullpath_string(), "path/filename|subpath/subfile");
    }

    #[test]
    fn test_string_format2() {
        let fsrl = f("fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile|sub2://");
        assert_eq!(
            fsrl.to_string(),
            "fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile|sub2://"
        );
        assert_eq!(
            fsrl.to_pretty_string(),
            "fsrl://path/filename|subfsrl://subpath/subfile|sub2://"
        );
        assert_eq!(fsrl.to_string_part(), "sub2://");
        assert_eq!(fsrl.to_pretty_fullpath_string(), "path/filename|subpath/subfile|");
    }

    #[test]
    fn test_string_format3() {
        let fsrl = f("fsrl:///path/filename?MD5=1234|subfsrl:///subpath/subfile|sub2://");
        assert_eq!(
            fsrl.to_string(),
            "fsrl:///path/filename?MD5=1234|subfsrl:///subpath/subfile|sub2://"
        );
        assert_eq!(
            fsrl.to_pretty_string(),
            "fsrl:///path/filename|subfsrl:///subpath/subfile|sub2://"
        );
        assert_eq!(fsrl.to_string_part(), "sub2://");
        assert_eq!(fsrl.to_pretty_fullpath_string(), "/path/filename|/subpath/subfile|");
    }

    #[test]
    fn test_name_depth() {
        let fsrl = f("fsrl://path/rootfile|sub1://path/file1|sub2://path/file2|sub3://path/file3");
        assert_eq!(fsrl.name().as_deref(), Some("file3"));
        assert_eq!(fsrl.name_at_depth(0).unwrap().as_deref(), Some("file3"));
        assert_eq!(fsrl.name_at_depth(1).unwrap().as_deref(), Some("file2"));
        assert_eq!(fsrl.name_at_depth(2).unwrap().as_deref(), Some("file1"));
        assert_eq!(fsrl.name_at_depth(3).unwrap().as_deref(), Some("rootfile"));
        assert!(fsrl.name_at_depth(4).is_err());
        assert_eq!(fsrl.nesting_depth(), 4);
    }

    #[test]
    fn test_equiv1() {
        let fsrl = f("fsrl://path/rootfile?MD5=00000000000000000000000000000000");
        let test_str1 = "fsrl://path/rootfile";
        assert!(fsrl.is_equivalent_str(Some(test_str1)));
        assert!(!fsrl.is_equivalent_str(Some(&test_str1[..test_str1.len() - 1])));
        assert!(!fsrl.is_equivalent_str(Some("fsrl://path/rootfile?MD5=BADBEEF0000000000000000000000000")));
        assert!(!fsrl.is_equivalent_str(None));
    }

    #[test]
    fn test_equiv2() {
        let fsrl = f("fsrl://path/rootfile");
        let test_str1 = "fsrl://path/rootfile?MD5=00000000000000000000000000000000";
        assert!(fsrl.is_equivalent_str(Some(test_str1)));
        assert!(!fsrl.is_equivalent_str(Some(&test_str1[..test_str1.len() - 1])));
    }

    #[test]
    fn test_is_descendant_of1() {
        let parent = f("file:///subdir1/subdir2/containerfile.zip");
        let child = f("file:///subdir1/subdir2/containerfile.zip|subfs:///subfs.file");
        let not_parent = f("file:///subdir1/subdir2/containerfile.zipx");
        assert!(child.is_descendant_of(&parent));
        assert!(!child.is_descendant_of(&not_parent));
        assert!(!child.is_descendant_of(&child));
    }

    #[test]
    fn test_is_descendant_of1a() {
        let base = "file:///subdir1/subdir2/containerfile.zip";
        let child = f(&format!("{base}|file:///containerfile2.zip|subfs:///subfs.file"));
        let sibling = f(&format!("{base}|file:///containerfile2.zip|subfs:///subfs.file2"));
        let root_dir = f(&format!("{base}|file:///containerfile2.zip|subfs:///"));
        let parent = f(&format!("{base}|file:///containerfile2.zip"));
        let not_parent = f(&format!("{base}|notx:///containerfile2.zip"));
        let g_parent = f(base);
        let g_parents_dir = f("file:///subdir1/subdir2");
        let g_parents_almost_dir = f("file:///subdir");
        let not_g_parent = f("file:///subdir1/subdir2/notcontainerfile.zip");

        assert!(child.is_descendant_of(&parent));
        assert!(child.is_descendant_of(&g_parent));
        assert!(child.is_descendant_of(&g_parents_dir));
        assert!(child.is_descendant_of(&root_dir));
        assert!(!child.is_descendant_of(&not_g_parent));
        assert!(!child.is_descendant_of(&not_parent));
        assert!(!child.is_descendant_of(&g_parents_almost_dir));
        assert!(!child.is_descendant_of(&sibling));
        assert!(!child.is_descendant_of(&child));
    }

    #[test]
    fn test_is_descendant_of2() {
        let parent = f("file:///subdir1/subdir2");
        let child = f("file:///subdir1/subdir2/file1.txt");
        assert!(child.is_descendant_of(&parent));
    }

    // ── additional parity cases ───────────────────────────────────────────────

    #[test]
    fn equals_and_hash_include_md5() {
        let a = f("file://a/b.zip|zip://x.txt?MD5=abc");
        let b = f("file://a/b.zip|zip://x.txt?MD5=abc");
        let c = f("file://a/b.zip|zip://x.txt?MD5=ABC");
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
        assert_ne!(a, c);
        assert!(a.is_equivalent(&c));
        assert!(a.is_md5_equal(Some("ABC")));
        assert!(!a.is_md5_equal(None));
    }

    #[test]
    fn with_md5_returns_same_instance_when_unchanged() {
        let a = f("file://x?MD5=11");
        assert!(Arc::ptr_eq(&a.with_md5(Some("11")).0, &a.0));
        let b = a.with_md5(None);
        assert_eq!(b.to_string(), "file://x");
        assert_eq!(a.with_path_from(&b).md5(), None);
        assert_eq!(b.with_path_from(&a).md5(), Some("11"));
    }

    #[test]
    fn split_orders_outermost_first() {
        let fsrl = f("file://a.zip|zip://b.tar|tar://c.txt");
        let parts: Vec<String> = fsrl.split().iter().map(Fsrl::to_string).collect();
        assert_eq!(parts, ["file://a.zip", "file://a.zip|zip://b.tar", "file://a.zip|zip://b.tar|tar://c.txt"]);
    }

    #[test]
    fn name_with_trailing_slash_uses_previous_segment() {
        assert_eq!(f("file:///c:/").name().as_deref(), Some("c:/"));
        assert_eq!(f("file://plain").name().as_deref(), Some("plain"));
    }

    #[test]
    fn root_views_and_convert_root_to_container() {
        let file = f("file://a.zip");
        let root = file.make_nested("zip");
        assert!(root.is_root());
        assert_eq!(root.protocol(), "zip");
        assert_eq!(root.path(), None);
        assert_eq!(root.name(), None);
        assert_eq!(root.fs(), root);
        assert_eq!(Fsrl::convert_root_to_container(&root), file);
        assert_eq!(Fsrl::convert_root_to_container(&file), file);
        let bare = FsrlRoot::make_root("file");
        assert_eq!(Fsrl::convert_root_to_container(&bare), *bare);
    }

    #[test]
    fn from_string_with_parent_nests_under_parent() {
        let parent = f("file://a.zip");
        let child = Fsrl::from_string_with_parent(&parent, "zip://b.txt").unwrap();
        assert_eq!(child.to_string(), "file://a.zip|zip://b.txt");
        assert_eq!(Fsrl::from_string_with_parent(&parent, "|").unwrap(), parent);
        assert!(Fsrl::from_string("|").is_err());
    }

    #[test]
    fn md5_param_is_decoded_among_others() {
        let fsrl = f("file://x?foo=bar&MD5=12%34");
        assert_eq!(fsrl.md5(), Some("12\u{34}"));
    }

    // ── fromProgram / writeToProgramInfo ─────────────────────────────────────

    #[derive(Default, Clone)]
    struct MapOptions(Rc<RefCell<HashMap<String, String>>>);

    impl Options for MapOptions {
        fn contains(&self, option_name: &str) -> bool {
            self.0.borrow().contains_key(option_name)
        }
        fn get_string(&self, option_name: &str, default_value: &str) -> String {
            self.0.borrow().get(option_name).cloned().unwrap_or_else(|| default_value.to_string())
        }
        fn set_string(&mut self, option_name: &str, value: &str) {
            self.0.borrow_mut().insert(option_name.to_string(), value.to_string());
        }
    }

    #[test]
    fn program_info_round_trip() {
        let mut options = MapOptions::default();
        assert_eq!(Fsrl::from_program_info(&options), None);

        let fsrl = f("file://a.zip|zip://b.txt?MD5=ff");
        Fsrl::write_to_program_info_options(&mut options, &fsrl);
        assert_eq!(options.get_string(FSRL_OPTION_NAME, ""), "file://a.zip|zip://b.txt?MD5=ff");
        assert_eq!(Fsrl::from_program_info(&options), Some(fsrl));

        options.set_string(FSRL_OPTION_NAME, "garbage");
        assert_eq!(Fsrl::from_program_info(&options), None);
    }
}
