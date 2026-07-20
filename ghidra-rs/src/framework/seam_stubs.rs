//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.framework.data.DomainObjectAdapterDB`, referenced by
/// [`TransactionListener`](crate::framework::model::TransactionListener) before the real class is
/// ported. `TransactionListener` only ever passes this type through as an opaque value, so no
/// members are needed yet.
pub trait DomainObjectAdapterDB {}

/// Placeholder for `ghidra.framework.data.LinkHandler`, referenced by
/// [`DomainFolder`](crate::framework::model::DomainFolder) before the real class is ported.
/// `DomainFolder` only ever passes this type through as an opaque value, so no members are needed
/// yet.
pub trait LinkHandler {}

/// Placeholder for `ghidra.framework.model.ProjectLocator`, referenced by
/// [`DomainFile`](crate::framework::model::DomainFile) before the real class is ported.
/// `DomainFile` only ever returns this type, so no members are needed yet.
pub trait ProjectLocator {}

/// Placeholder for `ghidra.framework.store.Version`, referenced by
/// [`DomainFile`](crate::framework::model::DomainFile) before the real class is ported.
/// `DomainFile` only ever returns a list of these, so no members are needed yet.
pub trait Version {}

/// Placeholder for `ghidra.framework.store.ItemCheckoutStatus`, referenced by
/// [`DomainFile`](crate::framework::model::DomainFile) before the real class is ported.
/// `DomainFile` only ever returns this type, so no members are needed yet.
pub trait ItemCheckoutStatus {}

/// Placeholder for `ghidra.framework.data.LinkedGhidraFolder`, referenced by
/// [`LinkFileInfo`](crate::framework::model::LinkFileInfo) before the real class is ported.
/// `LinkFileInfo` only ever returns this type, so no members are needed yet.
pub trait LinkedGhidraFolder {}

/// Placeholder for the `ghidra.framework.data.LinkHandler.LinkStatus` nested enum, referenced by
/// [`LinkFileInfo`](crate::framework::model::LinkFileInfo) before the real `LinkHandler` class
/// (and its nested `LinkStatus` enum) is ported. Mirrors the four Java enum constants since call
/// sites branch on which status was returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    /// The link-file specified does not refer to a valid file or content-type.
    Broken,
    /// The link-file ultimately refers to a file or folder path within the same project.
    Internal,
    /// The link-file ultimately refers to an external project/repository path with a Ghidra URL.
    External,
    /// The specified file is not a link-file.
    NonLink,
}

/// Placeholder for `ghidra.framework.options.OptionType`, referenced by
/// [`Options`](crate::framework::options::Options) before the real (Java `enum`) type is ported.
/// `Options` only ever passes this type through as an opaque value, so no members are needed yet.
pub trait OptionType {}

/// Placeholder for `java.beans.PropertyEditor`, referenced by
/// [`Options`](crate::framework::options::Options) before a Rust equivalent exists. `Options`
/// only ever passes this type through as an opaque value, so no members are needed yet.
pub trait PropertyEditor {}

/// Placeholder for `ghidra.framework.options.OptionsEditor`, referenced by
/// [`Options`](crate::framework::options::Options) before the real interface is ported. `Options`
/// only ever passes this type through as an opaque value, so no members are needed yet.
pub trait OptionsEditor {}

/// Placeholder for `db.LongKeyNode`, the abstract BTree-node superclass referenced by
/// [`LongKeyRecordNode`](crate::framework::db::long_key_record_node::LongKeyRecordNode) before
/// the real class is ported (`LongKeyRecordNode extends LongKeyNode` in Java). Exposes only the
/// inherited members `LongKeyRecordNode` calls or overrides: `getParent()`, `getKey(int)`,
/// `getRoot()`, and `getLeafNode(long)`.
pub trait LongKeyNode: crate::framework::db::nodes::BTreeNode {
    /// Get the parent node, or `None` if this is the root.
    fn get_parent(&self) -> Option<Box<dyn LongKeyInteriorNode>>;

    /// Get the key value at a specific index.
    fn get_key(&self, index: i32) -> i64;

    /// Get the root for this node's tree. If no parent has been set, this node is assumed to be
    /// the root.
    fn get_root(&self) -> Box<dyn LongKeyNode>;

    /// Get the leaf node which contains the specified key.
    fn get_leaf_node(
        &self,
        key: i64,
    ) -> std::io::Result<Box<dyn crate::framework::db::long_key_record_node::LongKeyRecordNode>>;
}

/// Placeholder for `db.LongKeyInteriorNode`, referenced by
/// [`LongKeyRecordNode`](crate::framework::db::long_key_record_node::LongKeyRecordNode) before
/// the real class is ported (`LongKeyRecordNode.getParent()` returns this type, and its
/// `isConsistent`/`putRecord`/`deleteRecord`/`split`/`appendLeaf`/`removeLeaf` bodies call back
/// into it). Exposes only the parent-callback members `LongKeyRecordNode` needs:
/// `isLeftmostKey`, `isRightmostKey`, `insert`, `deleteChild`, and `keyChanged`.
pub trait LongKeyInteriorNode {
    /// Determine if the specified key corresponds to the leftmost key within the tree.
    fn is_leftmost_key(&self, key: i64) -> bool;

    /// Determine if the specified key corresponds to the rightmost key within the tree.
    fn is_rightmost_key(&self, key: i64) -> bool;

    /// Insert a new child node (key and buffer id) into this interior node. Returns the root
    /// node, which may have changed.
    fn insert(&mut self, id: i32, key: i64) -> std::io::Result<Box<dyn LongKeyNode>>;

    /// Callback method allowing a child node to remove itself from this parent. Returns the root
    /// node, which may have changed.
    fn delete_child(&mut self, key: i64) -> std::io::Result<Box<dyn LongKeyNode>>;

    /// Callback method for when a child node's leftmost key changes.
    fn key_changed(&mut self, old_key: i64, new_key: i64);
}

/// Placeholder for `ghidra.util.HelpLocation`, referenced by
/// [`Options`](crate::framework::options::Options) before the real class is ported. `Options`
/// only ever passes this type through as an opaque value, so no members are needed yet.
pub trait HelpLocation {}

/// Placeholder for `ghidra.framework.options.GProperties`, referenced by
/// [`CustomOption`](crate::framework::options::CustomOption) before the real class is ported.
/// `CustomOption` only ever passes this type through as an opaque value, so no members are
/// needed yet.
pub trait GProperties {}

/// Placeholder for `ghidra.framework.options.ActionTrigger`, referenced by
/// [`Options`](crate::framework::options::Options) before the real class is ported. `Options`
/// only ever passes this type through as an opaque value, so no members are needed yet.
pub trait ActionTrigger {}

/// Placeholder for `java.awt.Color`, referenced by [`Options`](crate::framework::options::Options)
/// before a Rust equivalent exists. `Options` only ever passes this type through as an opaque
/// value, so no members are needed yet.
pub trait Color {}

/// Placeholder for `java.awt.Font`, referenced by [`Options`](crate::framework::options::Options)
/// before a Rust equivalent exists. `Options` only ever passes this type through as an opaque
/// value, so no members are needed yet.
pub trait Font {}

/// Placeholder for `javax.swing.KeyStroke`, referenced by
/// [`Options`](crate::framework::options::Options) before a Rust equivalent exists. `Options`
/// only ever passes this type through as an opaque value, so no members are needed yet.
pub trait KeyStroke {}

/// Placeholder for `ghidra.framework.model.DomainFolderFilter`, referenced by
/// [`DomainFileFilter`](crate::framework::model::DomainFileFilter) before the real interface is
/// ported (`DomainFileFilter extends DomainFolderFilter` in Java). `DomainFileFilter`'s default
/// `followExternallyLinkedFolders()` implementation calls back into `ignoreExternalLinks()` and
/// `ignoreFolderLinks()`, so those default methods are reproduced here to match
/// `ghidra.framework.model.DomainFolderFilter`'s documented Java defaults.
pub trait DomainFolderFilter {
    /// Check if folder-links should be ignored (includes internal and external).
    fn ignore_folder_links(&self) -> bool {
        false
    }

    /// Check if link-files should be ignored if the link is external (i.e., Ghidra-URL).
    fn ignore_external_links(&self) -> bool {
        true
    }

    /// Check if link-files should be ignored if the link is broken.
    fn ignore_broken_links(&self) -> bool {
        true
    }
}

/// Placeholder for `docking.util.image.ToolIconURL`, referenced by
/// [`ToolTemplate`](crate::framework::model::ToolTemplate) before the real class is ported.
/// `ToolTemplate` only ever returns this type, so no members are needed yet.
pub trait ToolIconURL {}

/// Placeholder for `javax.swing.ImageIcon`, referenced by
/// [`ToolTemplate`](crate::framework::model::ToolTemplate) before a Rust equivalent exists.
/// `ToolTemplate` only ever returns this type, so no members are needed yet.
pub trait ImageIcon {}

/// Placeholder for `org.jdom2.Element`, referenced by
/// [`ToolTemplate`](crate::framework::model::ToolTemplate) before a Rust equivalent exists.
/// Distinct from [`crate::util::xml::XmlElement`], which mirrors the unrelated
/// `ghidra.xml.XmlElement` pull-parser interface; `org.jdom2.Element` is a DOM-style tree node.
/// `ToolTemplate` only ever passes this type through as an opaque value, so no members are needed
/// yet.
pub trait JdomElement {}

/// Placeholder for `ghidra.framework.plugintool.PluginTool`, referenced by
/// [`ToolTemplate`](crate::framework::model::ToolTemplate) before the real class is ported.
/// `ToolTemplate` only ever returns this type, so no members are needed yet.
pub trait PluginTool {}

/// Placeholder for `ghidra.framework.client.RemoteAdapterListener`, referenced by
/// [`RepositoryAdapter`](crate::framework::client::RepositoryAdapter) before the real interface is
/// ported. `RepositoryAdapter` only ever registers/unregisters instances of this listener as an
/// opaque value (its single member, `connectionStateChanged`, is invoked internally by
/// `RepositoryAdapter.fireStateChanged()`, which is not itself part of the ported public trait
/// surface), so no members are needed yet.
pub trait RemoteAdapterListener {}

/// Placeholder for `ghidra.framework.model.ToolChest`, referenced by
/// [`ProjectManager`](crate::framework::model::ProjectManager) before the real interface is
/// ported. `ProjectManager` only ever returns this type, so no members are needed yet.
pub trait ToolChest {}

/// Placeholder for `ghidra.framework.model.ToolAssociationInfo`, referenced by
/// [`ToolServices`](crate::framework::model::ToolServices) before the real class is ported.
/// `ToolServices` only ever passes this type through as an opaque value, so no members are
/// needed yet.
pub trait ToolAssociationInfo {}

/// Placeholder for `ghidra.framework.model.WorkspaceChangeListener`, referenced by
/// [`ToolManager`](crate::framework::model::ToolManager) before the real interface is ported.
/// `ToolManager` only ever registers/unregisters this listener, so no members are needed yet.
pub trait WorkspaceChangeListener {}

/// Placeholder for `ghidra.framework.options.SaveState`, referenced by
/// [`Project`](crate::framework::model::Project) before the real class is ported. `Project` only
/// ever passes this type through as an opaque value, so no members are needed yet.
pub trait SaveState {}

/// Placeholder for `ghidra.framework.options.ToolOptions`, referenced by
/// [`OptionsChangeListener`](crate::framework::options::OptionsChangeListener) before the real
/// class is ported. `OptionsChangeListener` only ever passes this type through as an opaque
/// value, so no members are needed yet.
pub trait ToolOptions {}

/// Placeholder for `ghidra.util.bean.opteditor.OptionsVetoException`, referenced by
/// [`OptionsChangeListener`](crate::framework::options::OptionsChangeListener) before the real
/// class is ported. `OptionsChangeListener` only ever returns this type as an error, so no
/// members are needed yet.
pub trait OptionsVetoException {}

/// Placeholder for `db.buffers.BufferFileBlock`, referenced by
/// [`InputBlockStream`](crate::framework::db::buffers::InputBlockStream) before the real class is
/// ported. `InputBlockStream` only ever returns this type, so no members are needed yet.
pub trait BufferFileBlock {}

/// Placeholder for the file-identity surface of `db.buffers.LocalBufferFile`, referenced by
/// [`ChangeMapFile`](crate::framework::db::buffers::ChangeMapFile) before the real class exposes
/// its file id. `ChangeMapFile::is_valid_for` only ever compares file ids, so no other members
/// are needed yet.
pub trait LocalBufferFileLike {
    /// Returns the unique identifier for this buffer file.
    fn get_file_id(&self) -> u64;
}

/// Placeholder for `ghidra.framework.store.db.VersionedDatabase`, referenced by
/// [`VersionedDBListener`](crate::framework::store::VersionedDBListener) before the real class is
/// ported. `VersionedDBListener` only ever passes this type through as an opaque value, so no
/// members are needed yet.
pub trait VersionedDatabase {}

/// Placeholder for `ghidra.framework.Architecture`, referenced by
/// [`Platform`](crate::framework::Platform) before the real (Java `enum`) type is ported.
/// `Platform` only ever returns this type and formats it via `Display` (mirroring
/// `Platform.toString()`, which concatenates `operatingSystem.toString()` and
/// `architecture.toString()`), so no other members are needed yet.
pub trait Architecture: std::fmt::Display {}

/// Placeholder for the static `ghidra.framework.store.db.PackedDatabase.cleanupOldTempDatabases()`
/// utility method, referenced by
/// [`FileSystemInitializer`](crate::framework::store::FileSystemInitializer) before a concrete
/// `store::db` implementation exists to call it directly. The
/// [`PackedDatabase`](crate::framework::store::db::PackedDatabase) trait intentionally omits
/// static/factory methods to remain object-safe, so this seam exposes just the one operation
/// `FileSystemInitializer::run()` needs, keeping `store` decoupled from any concrete `store::db`
/// type.
pub trait TempDatabaseCleaner {
    /// Deletes any temporary unpacked database directories left over from prior packed-database
    /// use which are no longer in use (e.g., left behind by an abnormal process termination).
    fn cleanup_old_temp_databases(&self);
}

/// Placeholder for `ghidra.framework.remote.RepositoryItem`, referenced by
/// [`RepositoryHandle`](crate::framework::remote::RepositoryHandle) before the real class is
/// ported. `RepositoryHandle` only ever returns this type, so no members are needed yet.
pub trait RepositoryItem {}

/// Placeholder for `javax.security.auth.callback.Callback`, referenced by
/// [`GhidraServerHandle`](crate::framework::remote::GhidraServerHandle) before a Rust equivalent
/// exists. `Callback` is itself a marker interface with no members in `javax.security.auth`, and
/// `GhidraServerHandle` only ever passes implementors through as opaque values (returned from
/// `getAuthenticationCallbacks()` and accepted by `getRepositoryServer()`), so no members are
/// needed here either.
pub trait AuthCallback {}

/// Placeholder for `ghidra.framework.store.CheckoutType`, referenced by
/// [`LocalFolderItem`](crate::framework::store::local::LocalFolderItem) before the real (Java
/// `enum`) type is ported. Mirrors the three Java enum constants since call sites branch on which
/// checkout type was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutType {
    /// Checkout is a normal non-exclusive checkout.
    Normal,
    /// Persistent exclusive checkout which ensures no other checkout can occur while it persists.
    Exclusive,
    /// Similar to `Exclusive`, but only persists while the associated client connection is alive;
    /// only permitted for remote versioned file systems which support its use.
    Transient,
}
