//! Rust port of `ghidra.formats.gfilesystem.FSRL`.
//!
//! A _F_ile _S_ystem _R_esource _L_ocator locates a resource (by name) on a "filesystem", in a
//! recursively nested fashion. The string format is `fstype://path?MD5=optional_md5` possibly
//! followed by more `|fstype://path...` parts for nested filesystems -- read right-to-left, ie.
//! `"file://z|y://x"` is "file x inside filesystem y inside container file z".
//!
//! This type is a dependency-cycle cut-point: `FSRL` sits at the center of the `gfilesystem`
//! package (referenced by `CryptoSession`, `CachedPasswordProvider`, `FileSystemService`,
//! `GFileImpl`, ...) while itself depending on `FSRLRoot` and (for its two `Program`-related
//! static methods) `Program`'s not-yet-ported `Options` property list. As a trait, `Fsrl` never
//! needs to construct an arbitrary `Self`: the two Java constructors it delegates to internally
//! are exposed as the abstract [`Fsrl::with_parts`]/[`Fsrl::make_nested`] methods that only a
//! concrete implementation can fulfill, so the trait stays object-safe.
//!
//! `FSRL.parent` is always an instance of `FSRLRoot` (`ghidra.formats.gfilesystem.FSRLRoot`, not
//! yet ported); it is represented here by the [`FsrlRootLike`] seam, extended with just the
//! methods this port needs (`protocol`, `has_container`, `get_container`, plus the string/equality
//! helpers `FSRL`'s default methods recurse into).
//!
//! Not ported: `fromString`/`fromPartString` (parsing) and `fromProgram`/`writeToProgramInfo`
//! (need `Program`'s not-yet-ported `Options` property list) -- all four are static factories
//! that need a concrete, constructible `Fsrl` implementation this trait doesn't have.
//! `convertRootToContainer` is also not ported: it exists to normalize a Java reference that
//! might dynamically be either an `FSRL` or an `FSRLRoot` (`instanceof FSRLRoot`) onto the
//! `FSRL` it contains, but this port keeps the two as distinct, non-overlapping trait
//! hierarchies (`Fsrl` vs `FsrlRootLike`), so that ambiguity can't arise here.
//!
//! Also not ported: `getName(int)`'s Java overload throwing on out-of-range depth keeps the
//! same behavior via [`Fsrl::name_at_depth`], but returns an [`io::Result`] instead of throwing.

use std::io;

use crate::filesystem::gfilesystem::fs_utilities;
use crate::filesystem::seam_stubs::FsrlRootLike;

/// Name of the query parameter used to encode an MD5 hash in a string-ified FSRL.
///
/// Mirrors `FSRL.PARAM_MD5`.
pub const PARAM_MD5: &str = "MD5";

/// A _F_ile _S_ystem _R_esource _L_ocator. See the [module docs](self) for the string format.
pub trait Fsrl {
    /// The full path/filename of this FSRL, not including the filesystem root portion.
    ///
    /// Mirrors the protected field `path` (exposed publicly via `getPath()`). `None` for a
    /// bare filesystem root.
    fn path(&self) -> Option<&str>;

    /// The MD5 hash associated with this file, if known.
    ///
    /// Mirrors the private field `md5` (exposed publicly via `getMD5()`).
    fn md5(&self) -> Option<&str>;

    /// The [`FsrlRootLike`] (`FSRLRoot`) that represents the entire filesystem this FSRL is
    /// located within.
    ///
    /// Mirrors `getFS()`.
    fn fs(&self) -> &dyn FsrlRootLike;

    /// Builds a new FSRL sharing this instance's [`fs`](Fsrl::fs) root, with the given `path`
    /// and `md5`.
    ///
    /// Mirrors the internal 3-arg `FSRL(FSRLRoot, String, String)` constructor that
    /// `withMD5`/`withPath`/`appendPath` delegate to; a concrete implementation is the only
    /// thing that knows how to construct a sibling of itself.
    fn with_parts(&self, path: Option<String>, md5: Option<String>) -> Box<dyn Fsrl>;

    /// Creates a new filesystem root nested as a child of this FSRL, with the given filesystem
    /// type string.
    ///
    /// Mirrors `makeNested(String)` / `FSRLRoot.nestedFS(FSRL, String)`.
    fn make_nested(&self, fstype: &str) -> Box<dyn FsrlRootLike>;

    /// The name portion of this FSRL's path, everything after the last `/`.
    ///
    /// Mirrors `getName()`.
    fn name(&self) -> Option<String> {
        let path = self.path()?;
        let mut cp: isize = path.rfind('/').map_or(-1, |i| i as isize);
        if cp > 0 && cp as usize == path.len() - 1 {
            cp = path[..cp as usize].rfind('/').map_or(-1, |i| i as isize);
        }
        Some(if cp >= 0 {
            path[(cp as usize + 1)..].to_string()
        } else {
            path.to_string()
        })
    }

    /// The name portion of the FSRL part at parent depth `nested_depth`, where 0 is this
    /// instance (equivalent to [`Fsrl::name`]), 1 is the parent container's name, etc.
    ///
    /// Mirrors `getName(int)`, but returns an [`io::Result`] instead of throwing.
    fn name_at_depth(&self, nested_depth: u32) -> io::Result<Option<String>>
    where
        Self: Sized,
    {
        let mut current: &dyn Fsrl = self;
        for _ in 0..nested_depth {
            match current.fs().get_container() {
                Some(parent_container) => current = parent_container,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "Unknown requested FSRL parent, requested depth {}, only {} available in {}",
                            nested_depth,
                            self.nesting_depth(),
                            self.fsrl_string()
                        ),
                    ));
                }
            }
        }
        Ok(current.name())
    }

    /// The number of [`FsrlRootLike`] roots there are in this FSRL, minimum 1.
    ///
    /// Mirrors `getNestingDepth()`.
    fn nesting_depth(&self) -> u32 {
        let mut depth = 0u32;
        let mut root: Option<&dyn FsrlRootLike> = Some(self.fs());
        while let Some(r) = root {
            depth += 1;
            root = if r.has_container() {
                r.get_container().map(|c| c.fs())
            } else {
                None
            };
        }
        depth
    }

    /// Tests `other_md5` against this FSRL's MD5, case-insensitively.
    ///
    /// Mirrors `isMD5Equal(String)`.
    fn is_md5_equal(&self, other_md5: Option<&str>) -> bool {
        match self.md5() {
            None => other_md5.is_none(),
            Some(m) => other_md5.is_some_and(|o| m.eq_ignore_ascii_case(o)),
        }
    }

    /// A new FSRL with the same path but a new MD5 value.
    ///
    /// Mirrors `withMD5(String)`. Unlike Java, this always builds a new instance rather than
    /// returning `this` when the MD5 is unchanged, since a trait object has no cheap way to
    /// hand back a reference to itself as an owned `Box<dyn Fsrl>`; the two are value-equal
    /// either way.
    fn with_md5(&self, new_md5: Option<String>) -> Box<dyn Fsrl> {
        self.with_parts(self.path().map(str::to_owned), new_md5)
    }

    /// A new FSRL with the same [`fs`](Fsrl::fs) root but a new path (and no MD5).
    ///
    /// Mirrors `withPath(String)`.
    fn with_path(&self, new_path: &str) -> Box<dyn Fsrl> {
        self.with_parts(Some(new_path.to_string()), None)
    }

    /// A new FSRL with this instance's [`fs`](Fsrl::fs) root, but the path and MD5 copied from
    /// `copy_path`.
    ///
    /// Mirrors `withPath(FSRL)`.
    fn with_path_from(&self, copy_path: &dyn Fsrl) -> Box<dyn Fsrl> {
        self.with_parts(
            copy_path.path().map(str::to_owned),
            copy_path.md5().map(str::to_owned),
        )
    }

    /// A new FSRL with `rel_path` appended to this instance's path (and no MD5).
    ///
    /// Mirrors `appendPath(String)`.
    fn append_path(&self, rel_path: &str) -> Box<dyn Fsrl> {
        let base_path = self.path().unwrap_or("/");
        let joined = fs_utilities::append_path(&[Some(base_path), Some(rel_path)]);
        self.with_parts(joined, None)
    }

    /// Appends this FSRL's string representation to `out`.
    ///
    /// `recurse` includes parent filesystem parts, `include_params` includes the `?MD5=...`
    /// suffix, and `include_fs_root` includes the `fstype://` prefixes.
    ///
    /// Mirrors the protected `appendToStringBuilder`.
    fn append_to_string_builder(
        &self,
        out: &mut String,
        recurse: bool,
        include_params: bool,
        include_fs_root: bool,
    ) {
        self.fs()
            .append_to_string(out, recurse, include_params, include_fs_root);
        if let Some(p) = self.path() {
            out.push_str(&fs_utilities::escape_encode(p));
        }
        if include_params {
            if let Some(m) = self.md5() {
                out.push('?');
                out.push_str(PARAM_MD5);
                out.push('=');
                out.push_str(m);
            }
        }
    }

    /// The full FSRL as a string, eg. `"file://path|subfs://blah?MD5=1234567"`.
    ///
    /// Mirrors `toString()`.
    fn fsrl_string(&self) -> String {
        let mut s = String::new();
        self.append_to_string_builder(&mut s, true, true, true);
        s
    }

    /// The full FSRL as a string, excluding MD5 portions.
    ///
    /// Mirrors `toPrettyString()`.
    fn to_pretty_string(&self) -> String {
        let mut s = String::new();
        self.append_to_string_builder(&mut s, true, false, true);
        s
    }

    /// The full FSRL as a string, excluding MD5 portions and `fstype://` prefixes.
    ///
    /// Mirrors `toPrettyFullpathString()`.
    fn to_pretty_fullpath_string(&self) -> String {
        let mut s = String::new();
        self.append_to_string_builder(&mut s, true, false, false);
        s
    }

    /// Just the current FSRL protocol and path, excluding parent filesystem parts.
    ///
    /// Mirrors `toStringPart()`.
    fn to_string_part(&self) -> String {
        let mut s = String::new();
        self.append_to_string_builder(&mut s, false, true, true);
        s
    }

    /// Splits this FSRL into a list, with each element pointing to each level of the full FSRL,
    /// ordered from the outermost container to this instance.
    ///
    /// Mirrors `split()`.
    fn split(&self) -> Vec<&dyn Fsrl>
    where
        Self: Sized,
    {
        let mut result: Vec<&dyn Fsrl> = Vec::new();
        let mut current: &dyn Fsrl = self;
        loop {
            result.insert(0, current);
            match current.fs().get_container() {
                Some(next) => current = next,
                None => break,
            }
        }
        result
    }

    /// `true` if this FSRL, string-ified, is the same as `fsrl_str`, excluding MD5 values.
    ///
    /// Mirrors `isEquivalent(String)`.
    fn is_equivalent_str(&self, fsrl_str: Option<&str>) -> bool {
        let Some(fsrl_str) = fsrl_str else {
            return false;
        };
        let s = self.fsrl_string();
        if s == fsrl_str {
            return true;
        }
        if self.md5().is_some() && s.starts_with(fsrl_str) {
            let rest = &s[fsrl_str.len()..];
            if rest.starts_with("?MD5=") && s.len() == fsrl_str.len() + 37 {
                return true;
            }
        }
        if self.md5().is_none() && fsrl_str.starts_with(&s) {
            let rest = &fsrl_str[s.len()..];
            if rest.starts_with("?MD5=") && fsrl_str.len() == s.len() + 37 {
                return true;
            }
        }
        false
    }

    /// `true` if this FSRL is the same as `other`, excluding MD5 values.
    ///
    /// Mirrors `isEquivalent(FSRL)`.
    fn is_equivalent(&self, other: &dyn Fsrl) -> bool {
        self.fs().root_equals(other.fs()) && self.path() == other.path()
    }

    /// `true` if this FSRL is a child or descendant of `potential_parent`.
    ///
    /// Mirrors `isDescendantOf(FSRL)`.
    fn is_descendant_of(&self, potential_parent: &dyn Fsrl) -> bool
    where
        Self: Sized,
    {
        if self.is_equivalent(potential_parent) {
            return false;
        }
        for my_part in self.split().into_iter().rev() {
            let fs_match = my_part.fs().root_equals(potential_parent.fs());
            let path_match = my_part.path() == potential_parent.path()
                || match (potential_parent.path(), my_part.path()) {
                    (Some(pp), Some(mp)) => is_parent_path(pp, mp),
                    _ => false,
                };
            if fs_match && path_match {
                return true;
            }
        }
        false
    }

    /// Full value equality (root, path and MD5), mirroring `equals(Object)`.
    fn fsrl_equals(&self, other: &dyn Fsrl) -> bool {
        self.fs().root_equals(other.fs()) && self.path() == other.path() && self.md5() == other.md5()
    }

    /// Mirrors `hashCode()`.
    fn fsrl_hash(&self) -> u64 {
        let mut result: u64 = 1;
        result = result.wrapping_mul(31).wrapping_add(self.fs().root_hash());
        result = result
            .wrapping_mul(31)
            .wrapping_add(hash_opt_str(self.path()));
        result = result
            .wrapping_mul(31)
            .wrapping_add(hash_opt_str(self.md5()));
        result
    }
}

/// `true` if `child` is `parent` plus at least one more path segment.
///
/// Mirrors the private static `FSRL.isParentPath`. Unlike the Java version, this never panics
/// on a `child` shorter than `parent` (Java's `charAt` would throw `StringIndexOutOfBounds` in
/// that case if it were ever reached with mismatched lengths).
fn is_parent_path(parent: &str, child: &str) -> bool {
    child.starts_with(parent)
        && child.len() > parent.len()
        && (parent.ends_with('/') || child.as_bytes()[parent.len()] == b'/')
}

fn hash_opt_str(s: Option<&str>) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    match s {
        None => 0,
        Some(s) => {
            let mut hasher = DefaultHasher::new();
            s.hash(&mut hasher);
            hasher.finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock FSRLRoot / FSRL tree ───────────────────────────────────────────────
    //
    // Builds a small, real (owned, non-cyclic) tree: a "file" root containing
    // "dir/example.zip", nested under a "zip" root containing "readme.txt", to exercise real
    // traversal/rendering behavior rather than trivially-true stubs.

    #[derive(Clone)]
    struct MockRoot {
        protocol: String,
        container: Option<Box<MockFsrl>>,
    }

    impl FsrlRootLike for MockRoot {
        fn protocol(&self) -> &str {
            &self.protocol
        }
        fn has_container(&self) -> bool {
            self.container.is_some()
        }
        fn get_container(&self) -> Option<&dyn Fsrl> {
            self.container.as_deref().map(|c| c as &dyn Fsrl)
        }
    }

    #[derive(Clone)]
    struct MockFsrl {
        root: MockRoot,
        path: Option<String>,
        md5: Option<String>,
    }

    impl Fsrl for MockFsrl {
        fn path(&self) -> Option<&str> {
            self.path.as_deref()
        }
        fn md5(&self) -> Option<&str> {
            self.md5.as_deref()
        }
        fn fs(&self) -> &dyn FsrlRootLike {
            &self.root
        }
        fn with_parts(&self, path: Option<String>, md5: Option<String>) -> Box<dyn Fsrl> {
            Box::new(MockFsrl { root: self.root.clone(), path, md5 })
        }
        fn make_nested(&self, fstype: &str) -> Box<dyn FsrlRootLike> {
            Box::new(MockRoot {
                protocol: fstype.to_string(),
                container: Some(Box::new(self.clone())),
            })
        }
    }

    fn outer() -> MockFsrl {
        MockFsrl {
            root: MockRoot { protocol: "file".to_string(), container: None },
            path: Some("dir/example.zip".to_string()),
            md5: None,
        }
    }

    fn inner() -> MockFsrl {
        MockFsrl {
            root: MockRoot {
                protocol: "zip".to_string(),
                container: Some(Box::new(outer())),
            },
            path: Some("readme.txt".to_string()),
            md5: Some("d41d8cd98f00b204e9800998ecf8427e".to_string()),
        }
    }

    // ── fsrl_string / toString family ───────────────────────────────────────────

    #[test]
    fn fsrl_string_renders_nested_fsrl() {
        assert_eq!(outer().fsrl_string(), "file://dir/example.zip");
        assert_eq!(
            inner().fsrl_string(),
            "file://dir/example.zip|zip://readme.txt?MD5=d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn to_pretty_string_excludes_md5() {
        assert_eq!(
            inner().to_pretty_string(),
            "file://dir/example.zip|zip://readme.txt"
        );
    }

    #[test]
    fn to_pretty_fullpath_string_excludes_fs_roots() {
        assert_eq!(inner().to_pretty_fullpath_string(), "dir/example.zip|readme.txt");
    }

    #[test]
    fn to_string_part_excludes_parent_parts() {
        assert_eq!(
            inner().to_string_part(),
            "zip://readme.txt?MD5=d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    // ── name / name_at_depth ─────────────────────────────────────────────────────

    #[test]
    fn name_returns_last_path_segment() {
        assert_eq!(inner().name().as_deref(), Some("readme.txt"));
        assert_eq!(outer().name().as_deref(), Some("example.zip"));
    }

    #[test]
    fn name_at_depth_walks_up_containers() {
        let f = inner();
        assert_eq!(f.name_at_depth(0).unwrap().as_deref(), Some("readme.txt"));
        assert_eq!(f.name_at_depth(1).unwrap().as_deref(), Some("example.zip"));
    }

    #[test]
    fn name_at_depth_beyond_available_errors() {
        let f = inner();
        assert!(f.name_at_depth(2).is_err());
    }

    // ── nesting_depth / split ────────────────────────────────────────────────────

    #[test]
    fn nesting_depth_counts_roots() {
        assert_eq!(outer().nesting_depth(), 1);
        assert_eq!(inner().nesting_depth(), 2);
    }

    #[test]
    fn split_orders_outermost_first() {
        let f = inner();
        let parts = f.split();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].fsrl_string(), "file://dir/example.zip");
        assert_eq!(
            parts[1].fsrl_string(),
            "file://dir/example.zip|zip://readme.txt?MD5=d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    // ── with_md5 / with_path / append_path ──────────────────────────────────────

    #[test]
    fn with_md5_replaces_hash_keeps_path() {
        let f = outer().with_md5(Some("CAFEBABE".to_string()));
        assert_eq!(f.path(), Some("dir/example.zip"));
        assert_eq!(f.md5(), Some("CAFEBABE"));
    }

    #[test]
    fn with_path_drops_existing_md5() {
        let f = inner().with_path("other.txt");
        assert_eq!(f.path(), Some("other.txt"));
        assert_eq!(f.md5(), None);
    }

    #[test]
    fn append_path_joins_and_drops_md5() {
        let f = inner().append_path("nested.bin");
        assert_eq!(f.path(), Some("readme.txt/nested.bin"));
        assert_eq!(f.md5(), None);
    }

    // ── is_md5_equal ─────────────────────────────────────────────────────────────

    #[test]
    fn is_md5_equal_is_case_insensitive() {
        assert!(inner().is_md5_equal(Some("D41D8CD98F00B204E9800998ECF8427E")));
        assert!(!inner().is_md5_equal(Some("other")));
        assert!(!outer().is_md5_equal(Some("anything")));
        assert!(outer().is_md5_equal(None));
    }

    // ── equivalence / descendant checks ─────────────────────────────────────────

    #[test]
    fn is_equivalent_ignores_md5() {
        let a = inner();
        let b = inner().with_md5(Some("OTHERHASH".to_string()));
        assert!(a.is_equivalent(&*b));
    }

    #[test]
    fn is_equivalent_str_matches_rendered_string() {
        // fsrl_string() with a 32-hexdigit MD5 == fsrl_str + "?MD5=<32 hexdigits>" (37 chars).
        assert!(inner().is_equivalent_str(Some("file://dir/example.zip|zip://readme.txt")));
        assert!(!inner().is_equivalent_str(Some("file://dir/other.zip|zip://readme.txt")));
        assert!(!inner().is_equivalent_str(None));
        assert!(outer().is_equivalent_str(Some("file://dir/example.zip")));
    }

    #[test]
    fn is_descendant_of_true_for_container() {
        assert!(inner().is_descendant_of(&outer()));
    }

    #[test]
    fn is_descendant_of_false_for_unrelated() {
        let unrelated = MockFsrl {
            root: MockRoot { protocol: "tar".to_string(), container: None },
            path: Some("blah".to_string()),
            md5: None,
        };
        assert!(!inner().is_descendant_of(&unrelated));
    }

    #[test]
    fn is_descendant_of_false_for_self() {
        let f = inner();
        assert!(!f.is_descendant_of(&f));
    }

    // ── fsrl_equals / fsrl_hash ──────────────────────────────────────────────────

    #[test]
    fn fsrl_equals_requires_matching_md5() {
        let a = inner();
        let b = inner();
        assert!(a.fsrl_equals(&b));

        let c = inner().with_md5(Some("OTHER".to_string()));
        assert!(!a.fsrl_equals(&*c));
    }

    #[test]
    fn fsrl_hash_matches_for_equal_values() {
        assert_eq!(inner().fsrl_hash(), inner().fsrl_hash());
        assert_ne!(inner().fsrl_hash(), outer().fsrl_hash());
    }

    // ── object safety ────────────────────────────────────────────────────────────

    #[test]
    fn boxed_dyn_fsrl_is_accepted() {
        let f: Box<dyn Fsrl> = Box::new(inner());
        assert_eq!(f.name().as_deref(), Some("readme.txt"));
    }
}
