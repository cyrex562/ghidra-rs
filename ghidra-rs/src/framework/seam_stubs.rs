//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use std::path::PathBuf;

use crate::framework::application_properties::ApplicationProperties;
use crate::generic::jar::ResourceFile;

/// Placeholder for `utility.application.ApplicationLayout`, referenced by
/// [`GenericRunInfo`](crate::framework::generic_run_info::GenericRunInfo) before the real class is
/// ported. `GenericRunInfo` only ever reads the application properties and installation directory
/// off of the layout returned by [`ApplicationLike::application_layout`], so no other members are
/// needed yet.
pub trait ApplicationLayoutLike {
    /// Gets the application properties from the application layout, mirroring
    /// `ApplicationLayout.getApplicationProperties()`.
    fn application_properties(&self) -> &dyn ApplicationProperties;

    /// Gets the application installation directory from the application layout, mirroring
    /// `ApplicationLayout.getApplicationInstallationDir()` (`None` if not set, matching the Java
    /// method's documented `null` return).
    fn application_installation_dir(&self) -> Option<&ResourceFile>;
}

/// Placeholder for `ghidra.framework.Application`, referenced by
/// [`GenericRunInfo`](crate::framework::generic_run_info::GenericRunInfo) before the real
/// (static-method-only) class is ported. Only the three accessors `GenericRunInfo` calls are
/// declared here; the real port carries application initialization, module discovery, and the
/// rest of `Application`'s static surface.
pub trait ApplicationLike {
    /// Gets the application layout, mirroring `Application.getApplicationLayout()`.
    fn application_layout(&self) -> Box<dyn ApplicationLayoutLike>;

    /// Gets the user's current settings directory, mirroring
    /// `Application.getUserSettingsDirectory()`.
    fn user_settings_directory(&self) -> PathBuf;

    /// Gets the application's name, mirroring `Application.getName()`.
    fn name(&self) -> String;
}

/// Placeholder for the static
/// `utility.application.ApplicationUtilities.getLegacyUserSettingsDir(ApplicationProperties, ResourceFile)`
/// utility method, referenced by
/// [`GenericRunInfo`](crate::framework::generic_run_info::GenericRunInfo) before a concrete
/// `ApplicationUtilities` implementation exists that `GenericRunInfo` can call directly without
/// re-introducing the package-level import cycle that method sits at one end of (see
/// [`crate::util::application_utilities::ApplicationUtilities`]'s own cycle-breaking doc comment).
/// Mirrors the Java method's contract of returning `None` in place of a thrown
/// `FileNotFoundException` (the one case `GenericRunInfo` catches and ignores).
pub trait LegacyUserSettingsLocator {
    /// Computes the legacy (pre-Ghidra 11.1) user settings directory for the given application
    /// properties and installation directory, or `None` if it could not be determined.
    fn legacy_user_settings_dir(
        &self,
        application_properties: &dyn ApplicationProperties,
        installation_dir: Option<&ResourceFile>,
    ) -> Option<PathBuf>;
}

/// Placeholder for `ghidra.framework.preferences.Preferences.APPLICATION_PREFERENCES_FILENAME`,
/// referenced by [`GenericRunInfo`](crate::framework::generic_run_info::GenericRunInfo) before the
/// real class is ported.
pub const PREFERENCES_APPLICATION_PREFERENCES_FILENAME: &str = "preferences";

/// Placeholder for `ghidra.framework.preferences.Preferences.PROJECT_DIRECTORY`, referenced by
/// [`GenericRunInfo`](crate::framework::generic_run_info::GenericRunInfo) before the real class is
/// ported.
pub const PREFERENCES_PROJECT_DIRECTORY: &str = "ProjectDirectory";

/// Placeholder for `ghidra.framework.preferences.Preferences`, referenced by
/// [`GenericRunInfo`](crate::framework::generic_run_info::GenericRunInfo) before the real
/// (static-method-only) class is ported; that class in turn calls
/// `GenericRunInfo.getPreviousApplicationSettingsFile()` from its own `store()`/`clear()` methods,
/// so the two classes form the cycle this seam breaks. Only the get/set accessors `GenericRunInfo`
/// calls are declared here; the real port carries the rest of `Preferences`'s static surface
/// (property-file persistence, plugin paths, etc). Methods take `&self` rather than `&mut self`
/// since the Java original models a single shared, globally-mutable property store rather than
/// per-instance state; implementations are expected to back this with interior mutability.
pub trait PreferencesLike {
    /// Gets the property with the given name, optionally falling back to the last used
    /// installation's value when `use_historical_value` is true and no current value is set,
    /// mirroring `Preferences.getProperty(String, String, boolean)`.
    fn get_property(
        &self,
        name: &str,
        default_value: Option<&str>,
        use_historical_value: bool,
    ) -> Option<String>;

    /// Sets the property value, mirroring `Preferences.setProperty(String, String)`.
    fn set_property(&self, name: &str, value: &str);
}

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

/// Placeholder for `ghidra.framework.model.ToolChest`, referenced by
/// [`ProjectManager`](crate::framework::model::ProjectManager) before the real interface is
/// ported. `ProjectManager` only ever returns this type, so no members are needed yet.
pub trait ToolChest {}

/// Placeholder for `ghidra.framework.model.ToolAssociationInfo`, referenced by
/// [`ToolServices`](crate::framework::model::ToolServices) before the real class is ported.
/// `ToolServices` only ever passes this type through as an opaque value, so no members are
/// needed yet.
pub trait ToolAssociationInfo {}

/// Placeholder for `java.beans.PropertyChangeEvent`, referenced by
/// [`WorkspaceChangeListener`](crate::framework::model::WorkspaceChangeListener) before a Rust
/// equivalent exists. `WorkspaceChangeListener` only ever passes this type through as an opaque
/// value to `property_change`, so no members are needed yet.
pub trait PropertyChangeEvent {}

/// Placeholder for `ghidra.framework.options.SaveState`, referenced by
/// [`Project`](crate::framework::model::Project) (as an opaque pass-through value) and by
/// [`AutoConfigState`](crate::framework::plugintool::auto_config_state)'s `ConfigFieldCodec`
/// implementations (which need its typed get/put accessors) before the real class is ported.
/// Mirrors the subset of `SaveState`'s get/put accessor pairs the ported codecs call; the real
/// port also carries XML (de)serialization and nested-state support that no ported caller needs
/// yet.
pub trait SaveState {
    /// Returns whether a value has been stored under `name`, mirroring `SaveState.hasValue`.
    fn has_value(&self, name: &str) -> bool;

    /// Gets a `boolean` value, mirroring `SaveState.getBoolean`.
    fn get_boolean(&self, name: &str, default_value: bool) -> bool;
    /// Stores a `boolean` value, mirroring `SaveState.putBoolean`.
    fn put_boolean(&mut self, name: &str, value: bool);

    /// Gets a `byte` value, mirroring `SaveState.getByte`.
    fn get_byte(&self, name: &str, default_value: i8) -> i8;
    /// Stores a `byte` value, mirroring `SaveState.putByte`.
    fn put_byte(&mut self, name: &str, value: i8);

    /// Gets a `short` value, mirroring `SaveState.getShort`.
    fn get_short(&self, name: &str, default_value: i16) -> i16;
    /// Stores a `short` value, mirroring `SaveState.putShort`.
    fn put_short(&mut self, name: &str, value: i16);

    /// Gets an `int` value, mirroring `SaveState.getInt`.
    fn get_int(&self, name: &str, default_value: i32) -> i32;
    /// Stores an `int` value, mirroring `SaveState.putInt`.
    fn put_int(&mut self, name: &str, value: i32);

    /// Gets a `long` value, mirroring `SaveState.getLong`.
    fn get_long(&self, name: &str, default_value: i64) -> i64;
    /// Stores a `long` value, mirroring `SaveState.putLong`.
    fn put_long(&mut self, name: &str, value: i64);

    /// Gets a `float` value, mirroring `SaveState.getFloat`.
    fn get_float(&self, name: &str, default_value: f32) -> f32;
    /// Stores a `float` value, mirroring `SaveState.putFloat`.
    fn put_float(&mut self, name: &str, value: f32);

    /// Gets a `double` value, mirroring `SaveState.getDouble`.
    fn get_double(&self, name: &str, default_value: f64) -> f64;
    /// Stores a `double` value, mirroring `SaveState.putDouble`.
    fn put_double(&mut self, name: &str, value: f64);

    /// Gets a `String` value, mirroring `SaveState.getString`.
    fn get_string(&self, name: &str, default_value: Option<&str>) -> Option<String>;
    /// Stores a `String` value, mirroring `SaveState.putString`.
    fn put_string(&mut self, name: &str, value: Option<&str>);

    /// Gets a `boolean[]` value, mirroring `SaveState.getBooleans`.
    fn get_booleans(&self, name: &str, default_value: Option<&[bool]>) -> Option<Vec<bool>>;
    /// Stores a `boolean[]` value, mirroring `SaveState.putBooleans`.
    fn put_booleans(&mut self, name: &str, value: Option<&[bool]>);

    /// Gets a `byte[]` value, mirroring `SaveState.getBytes`.
    fn get_bytes(&self, name: &str, default_value: Option<&[u8]>) -> Option<Vec<u8>>;
    /// Stores a `byte[]` value, mirroring `SaveState.putBytes`.
    fn put_bytes(&mut self, name: &str, value: Option<&[u8]>);

    /// Gets a `short[]` value, mirroring `SaveState.getShorts`.
    fn get_shorts(&self, name: &str, default_value: Option<&[i16]>) -> Option<Vec<i16>>;
    /// Stores a `short[]` value, mirroring `SaveState.putShorts`.
    fn put_shorts(&mut self, name: &str, value: Option<&[i16]>);

    /// Gets an `int[]` value, mirroring `SaveState.getInts`.
    fn get_ints(&self, name: &str, default_value: Option<&[i32]>) -> Option<Vec<i32>>;
    /// Stores an `int[]` value, mirroring `SaveState.putInts`.
    fn put_ints(&mut self, name: &str, value: Option<&[i32]>);

    /// Gets a `long[]` value, mirroring `SaveState.getLongs`.
    fn get_longs(&self, name: &str, default_value: Option<&[i64]>) -> Option<Vec<i64>>;
    /// Stores a `long[]` value, mirroring `SaveState.putLongs`.
    fn put_longs(&mut self, name: &str, value: Option<&[i64]>);

    /// Gets a `float[]` value, mirroring `SaveState.getFloats`.
    fn get_floats(&self, name: &str, default_value: Option<&[f32]>) -> Option<Vec<f32>>;
    /// Stores a `float[]` value, mirroring `SaveState.putFloats`.
    fn put_floats(&mut self, name: &str, value: Option<&[f32]>);

    /// Gets a `double[]` value, mirroring `SaveState.getDoubles`.
    fn get_doubles(&self, name: &str, default_value: Option<&[f64]>) -> Option<Vec<f64>>;
    /// Stores a `double[]` value, mirroring `SaveState.putDoubles`.
    fn put_doubles(&mut self, name: &str, value: Option<&[f64]>);

    /// Gets a `String[]` value, mirroring `SaveState.getStrings`.
    fn get_strings(&self, name: &str, default_value: Option<&[String]>) -> Option<Vec<String>>;
    /// Stores a `String[]` value, mirroring `SaveState.putStrings`.
    fn put_strings(&mut self, name: &str, value: Option<&[String]>);

    /// Gets a `File` value, mirroring `SaveState.getFile`.
    fn get_file(
        &self,
        name: &str,
        default_value: Option<&std::path::Path>,
    ) -> Option<std::path::PathBuf>;
    /// Stores a `File` value, mirroring `SaveState.putFile`.
    fn put_file(&mut self, name: &str, value: Option<&std::path::Path>);

    /// Gets an enum constant's name, mirroring `SaveState.getEnum` (which in Java resolves the
    /// stored name back to a `T` via reflection on the caller-supplied default's class; here the
    /// name/value mapping is instead the ported
    /// [`EnumConfigFieldCodec`](crate::framework::plugintool::auto_config_state::EnumConfigFieldCodec)'s
    /// job).
    fn get_enum_name(&self, name: &str) -> Option<String>;
    /// Stores an enum constant's name, mirroring `SaveState.putEnum`.
    fn put_enum_name(&mut self, name: &str, value: Option<&str>);
}

/// Placeholder for `ghidra.async.AsyncReference`, referenced by
/// [`AutoConfigState`](crate::framework::plugintool::auto_config_state)'s
/// `GenericAsyncConfigFieldCodec` before the real class is ported. `GenericAsyncConfigFieldCodec`
/// only ever reads the current value and sets a new one on an existing reference (never
/// constructs one), so only `get`/`set` are declared here. Java's `AsyncReference` is a single
/// mutable object shared by reference (its `set` also notifies listeners and completes pending
/// futures, none of which any ported caller needs yet), so `set` takes `&self` here too, with the
/// expectation that implementations back it with interior mutability -- matching the convention
/// already used by [`PreferencesLike`].
pub trait AsyncReferenceLike<T> {
    /// Gets the current value, mirroring `AsyncReference.get()`.
    fn get(&self) -> T;

    /// Sets a new value (with no change-cause), mirroring `AsyncReference.set(value, null)`.
    fn set(&self, value: T);
}

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

/// Placeholder for `db.FixedKeyInteriorNode`, the concrete BTree interior-node subclass of the
/// ported [`FixedKeyNode`](crate::framework::db::fixed_key_node::FixedKeyNode) (and implementor
/// of the already-ported
/// [`FieldKeyInteriorNode`](crate::framework::db::field_key_interior_node::FieldKeyInteriorNode))
/// referenced by
/// [`FixedKeyRecordNode`](crate::framework::db::fixed_key_record_node::FixedKeyRecordNode) as the
/// type of its inherited `parent` field, before the real class is ported. Exposes only the
/// package-private members `FixedKeyRecordNode` calls directly on its parent: `isLeftmostKey`,
/// `isRightmostKey`, `insert`, and `deleteChild`; `keyChanged` is inherited from the
/// `FieldKeyInteriorNode` supertrait it already implements in Java.
pub trait FixedKeyInteriorNodeLike:
    crate::framework::db::field_key_interior_node::FieldKeyInteriorNode
{
    /// Determine if the specified key corresponds to the leftmost key within the tree.
    fn is_leftmost_key(&self, key: &crate::framework::db::field::Field) -> bool;

    /// Determine if the specified key corresponds to the rightmost key within the tree.
    fn is_rightmost_key(&self, key: &crate::framework::db::field::Field) -> bool;

    /// Insert a new child node (key and buffer id) into this interior node. Returns the root
    /// node, which may have changed.
    fn insert(
        &mut self,
        id: i32,
        key: &crate::framework::db::field::Field,
    ) -> std::io::Result<Box<dyn crate::framework::db::fixed_key_node::FixedKeyNode>>;

    /// Callback method allowing a child node to remove itself from this parent. Returns the root
    /// node, which may have changed.
    fn delete_child(
        &mut self,
        key: &crate::framework::db::field::Field,
    ) -> std::io::Result<Box<dyn crate::framework::db::fixed_key_node::FixedKeyNode>>;
}

/// Placeholder for `ghidra.framework.plugintool.Plugin`, referenced by
/// [`PluginInstaller`](crate::framework::plugintool::PluginInstaller) before the real class is
/// ported. `PluginInstaller` only ever returns/accepts this type as an opaque value, so no
/// members are needed yet.
pub trait PluginLike {}

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
