//! Rust port of `ghidra.formats.gfilesystem.FSRLRoot`.
//!
//! A type of [`Fsrl`] that is specific to the filesystem's identity: a root has no path, its
//! "path" field is the protocol (`"file"` renders as `"file://"`), and it optionally points to
//! the container file it was nested inside of.
//!
//! Java's `FSRLRoot extends FSRL`; here [`FsrlRoot`] is a newtype over an [`Fsrl`] whose root
//! flag is set, and it [`Deref`]s to [`Fsrl`] so every `FSRL` method is available on it with
//! `FSRLRoot`'s overrides (`getFS`, `getPath`, `getName`, `appendToStringBuilder`) applied by
//! [`Fsrl`] itself. Java's cached `hashCode` field is not needed: the value is immutable and the
//! derived hash is identical every time.

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use crate::filesystem::gfilesystem::fsrl::{Fsrl, FsrlNode};

/// A filesystem root FSRL. See the [module docs](self).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FsrlRoot(Fsrl);

impl FsrlRoot {
    /// Wraps an [`Fsrl`] already known to be a root.
    pub(super) fn from_root_fsrl(fsrl: Fsrl) -> FsrlRoot {
        debug_assert!(fsrl.is_root());
        FsrlRoot(fsrl)
    }

    fn new(container: Option<Fsrl>, protocol: &str) -> FsrlRoot {
        FsrlRoot(Fsrl(Arc::new(FsrlNode {
            parent: container,
            path: Some(protocol.to_string()),
            md5: None,
            is_root: true,
        })))
    }

    /// Creates a root-level filesystem [`FsrlRoot`] (one with no container), eg. `"file://"`.
    ///
    /// Mirrors `FSRLRoot.makeRoot(String)`.
    pub fn make_root(protocol: &str) -> FsrlRoot {
        FsrlRoot::new(None, protocol)
    }

    /// Creates a filesystem root nested inside `container_file` (or a root-level one if
    /// `None`), with the given filesystem type.
    ///
    /// Mirrors `FSRLRoot.nestedFS(FSRL, String)`.
    ///
    /// # Panics
    /// If `container_file` is itself a filesystem root, mirroring Java's
    /// `RuntimeException("Can't make nestedFS with FSRLRoot path: ...")`.
    pub fn nested_fs(container_file: Option<&Fsrl>, fstype: &str) -> FsrlRoot {
        if let Some(c) = container_file {
            assert!(!c.is_root(), "Can't make nestedFS with FSRLRoot path: {c}");
        }
        FsrlRoot::new(container_file.cloned(), fstype)
    }

    /// Creates a filesystem root nested inside `container_file`, copying the protocol of
    /// `copy_fsrl`.
    ///
    /// Mirrors `FSRLRoot.nestedFS(FSRL, FSRLRoot)`.
    ///
    /// # Panics
    /// See [`FsrlRoot::nested_fs`].
    pub fn nested_fs_copy(container_file: Option<&Fsrl>, copy_fsrl: &FsrlRoot) -> FsrlRoot {
        FsrlRoot::nested_fs(container_file, copy_fsrl.protocol())
    }

    /// The "protocol" portion of this root, eg. `"file"`.
    ///
    /// Mirrors `getProtocol()`.
    pub fn protocol(&self) -> &str {
        self.0 .0.path.as_deref().unwrap_or_default()
    }

    /// The parent container FSRL, or `None` for a root-level filesystem.
    ///
    /// Mirrors `getContainer()`.
    pub fn container(&self) -> Option<&Fsrl> {
        self.0 .0.parent.as_ref()
    }

    /// `true` if there is a parent container file.
    ///
    /// Mirrors `hasContainer()`.
    pub fn has_container(&self) -> bool {
        self.container().is_some()
    }

    /// Creates a new [`Fsrl`] inside this filesystem with the given path and MD5.
    ///
    /// Mirrors `withPathMD5(String, String)`.
    pub fn with_path_md5(&self, new_path: Option<&str>, new_md5: Option<&str>) -> Fsrl {
        Fsrl::new_file(self, new_path.map(str::to_owned), new_md5.map(str::to_owned))
    }

    /// This root as a plain [`Fsrl`] reference.
    pub fn as_fsrl(&self) -> &Fsrl {
        &self.0
    }

    /// Unwraps this root into a plain [`Fsrl`].
    pub fn into_fsrl(self) -> Fsrl {
        self.0
    }
}

impl Deref for FsrlRoot {
    type Target = Fsrl;

    fn deref(&self) -> &Fsrl {
        &self.0
    }
}

impl From<FsrlRoot> for Fsrl {
    fn from(root: FsrlRoot) -> Fsrl {
        root.0
    }
}

impl PartialEq<Fsrl> for FsrlRoot {
    fn eq(&self, other: &Fsrl) -> bool {
        self.0 == *other
    }
}

impl PartialEq<FsrlRoot> for Fsrl {
    fn eq(&self, other: &FsrlRoot) -> bool {
        *self == other.0
    }
}

impl fmt::Display for FsrlRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for FsrlRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FsrlRoot({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_root_renders_protocol_only() {
        let root = FsrlRoot::make_root("file");
        assert_eq!(root.to_string(), "file://");
        assert_eq!(root.protocol(), "file");
        assert!(!root.has_container());
        assert_eq!(root.container(), None);
        assert_eq!(root.path(), None);
        assert_eq!(root.name(), None);
        assert_eq!(root.nesting_depth(), 1);
    }

    #[test]
    fn nested_fs_points_back_to_container() {
        let container = FsrlRoot::make_root("file").with_path("dir/a.zip");
        let nested = FsrlRoot::nested_fs(Some(&container), "zip");
        assert_eq!(nested.to_string(), "file://dir/a.zip|zip://");
        assert_eq!(nested.to_string_part(), "zip://");
        assert_eq!(nested.container(), Some(&container));
        assert_eq!(nested.nesting_depth(), 2);

        let copy = FsrlRoot::nested_fs_copy(Some(&container), &FsrlRoot::make_root("tar"));
        assert_eq!(copy.to_string(), "file://dir/a.zip|tar://");
    }

    #[test]
    #[should_panic(expected = "Can't make nestedFS with FSRLRoot path")]
    fn nested_fs_rejects_root_container() {
        let root = FsrlRoot::make_root("file");
        FsrlRoot::nested_fs(Some(&root), "zip");
    }

    #[test]
    fn with_path_md5_builds_child() {
        let root = FsrlRoot::make_root("file");
        let child = root.with_path_md5(Some("/x.bin"), Some("aa"));
        assert_eq!(child.to_string(), "file:///x.bin?MD5=aa");
        assert_eq!(child.fs(), root);
        assert!(!child.is_root());
    }

    #[test]
    fn root_equality_ignores_nothing_but_matches_structure() {
        let a = Fsrl::from_string("file://a.zip").unwrap().make_nested("zip");
        let b = Fsrl::from_string("file://a.zip").unwrap().make_nested("zip");
        let c = Fsrl::from_string("file://a.zip?MD5=11").unwrap().make_nested("zip");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.is_equivalent(&c));
        // A root is never equal to a plain FSRL rendering the same text.
        let plain = Fsrl::from_string("file://a.zip|zip://").unwrap();
        assert_eq!(plain.to_string(), a.to_string());
        assert_ne!(*a, plain);
    }
}
