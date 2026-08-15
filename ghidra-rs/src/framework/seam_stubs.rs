//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use crate::framework::application_properties::ApplicationProperties;
use crate::generic::jar::ResourceFile;

/// Placeholder for `utility.application.ApplicationLayout`, referenced by
/// [`GenericRunInfo`](crate::framework::generic_run_info::GenericRunInfo) before the real class is
/// ported. `GenericRunInfo` only ever reads the application properties and installation directory
/// off of the layout returned by [`ApplicationLike::application_layout`], so no other members are
/// needed yet.
///
/// Extended for [`Application`](crate::framework::application::Application), which additionally
/// needs the application root directories, modules, single-jar-mode flag, and the user
/// temp/cache/settings directories `ApplicationLayout` also carries. Each addition defaults to an
/// empty/`None`/`false` value so the existing [`GenericRunInfo`](crate::framework::GenericRunInfo)
/// mock implementors (which only ever exercised `application_properties`/
/// `application_installation_dir`) are unaffected.
///
/// Extended again for [`ExtensionDetails`](crate::util::extensions::ExtensionDetails), which
/// additionally needs the extension installation search path (`getExtensionInstallationDirs()`)
/// to determine whether an extension lives under an installation/repo folder. Defaults to empty
/// for the same reason as the other additions.
///
/// Extended once more for [`ExtensionUtils`](crate::util::extensions::ExtensionUtils), which
/// additionally needs the extension archive directory (`getExtensionArchiveDir()`) to search for
/// extensions bundled by the build process. Defaults to `None` for the same reason as the other
/// additions.
pub trait ApplicationLayoutLike {
    /// Gets the application properties from the application layout, mirroring
    /// `ApplicationLayout.getApplicationProperties()`.
    fn application_properties(&self) -> &dyn ApplicationProperties;

    /// Gets the application installation directory from the application layout, mirroring
    /// `ApplicationLayout.getApplicationInstallationDir()` (`None` if not set, matching the Java
    /// method's documented `null` return).
    fn application_installation_dir(&self) -> Option<&ResourceFile>;

    /// Gets the application root directories from the application layout, mirroring
    /// `ApplicationLayout.getApplicationRootDirs()`.
    fn application_root_dirs(&self) -> Vec<ResourceFile> {
        Vec::new()
    }

    /// Gets the application's modules from the application layout, mirroring
    /// `ApplicationLayout.getModules()` (Java's `Map<String, GModule>`, flattened to a `Vec` here
    /// since [`GModuleLike`] trait objects can't be used as `HashMap` keys/values ergonomically).
    fn modules(&self) -> Vec<Box<dyn GModuleLike>> {
        Vec::new()
    }

    /// Looks up a single module by name, mirroring `ApplicationLayout.getModules().get(name)`.
    fn module_named(&self, _name: &str) -> Option<Box<dyn GModuleLike>> {
        None
    }

    /// Gets the user temp directory from the application layout, mirroring
    /// `ApplicationLayout.getUserTempDir()`.
    fn user_temp_dir(&self) -> Option<PathBuf> {
        None
    }

    /// Gets the user cache directory from the application layout, mirroring
    /// `ApplicationLayout.getUserCacheDir()`.
    fn user_cache_dir(&self) -> Option<PathBuf> {
        None
    }

    /// Gets the user settings directory from the application layout, mirroring
    /// `ApplicationLayout.getUserSettingsDir()`.
    fn user_settings_dir(&self) -> Option<PathBuf> {
        None
    }

    /// Checks whether the application layout uses a "single jar" layout, mirroring
    /// `ApplicationLayout.inSingleJarMode()`.
    fn in_single_jar_mode(&self) -> bool {
        false
    }

    /// Gets the ordered extension installation search directories from the application layout
    /// (the user extension directory first, followed by installation/repo `Extensions`
    /// directories), mirroring `ApplicationLayout.getExtensionInstallationDirs()`.
    fn extension_installation_dirs(&self) -> Vec<ResourceFile> {
        Vec::new()
    }

    /// Gets the directory containing extensions archived as part of the build process, mirroring
    /// `ApplicationLayout.getExtensionArchiveDir()` (`None` if there is no archive directory,
    /// matching the Java method's documented `null` return).
    fn extension_archive_dir(&self) -> Option<ResourceFile> {
        None
    }
}

/// Placeholder for `ghidra.framework.GModule`, referenced by
/// [`ApplicationLayoutLike`] and [`Application`](crate::framework::application::Application)
/// before the real class is ported. Exposes the module-relative file/directory search operations
/// `Application` calls directly on each module (`getModuleRoot`, `accumulateDataFilesByExtension`,
/// `findModuleFile`, `collectExistingModuleDirs`); `GModule`'s constructor, shadow-module
/// resolution across repos, and manifest-driven search-root/ignore-dir setup are all
/// implementation details of how a real port would populate those search results, not part of the
/// contract callers need.
pub trait GModuleLike {
    /// Gets the module's root directory, mirroring `GModule.getModuleRoot()`.
    fn module_root(&self) -> ResourceFile;

    /// Accumulates all files within the module's search roots (including its `data` directory)
    /// that end with the given extension, mirroring
    /// `GModule.accumulateDataFilesByExtension(List, String)`.
    fn accumulate_data_files_by_extension(&self, accumulator: &mut Vec<ResourceFile>, extension: &str);

    /// Finds the first file with the given module-relative path across the module's search roots,
    /// mirroring `GModule.findModuleFile(String)`.
    fn find_module_file(&self, relative_path: &str) -> Option<ResourceFile>;

    /// Accumulates every existing directory with the given module-relative path across the
    /// module's search roots, mirroring `GModule.collectExistingModuleDirs(List, String)`.
    fn collect_existing_module_dirs(&self, accumulator: &mut Vec<ResourceFile>, relative_path: &str);
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

/// Placeholder for `ghidra.framework.data.LinkHandler`, referenced by
/// [`DomainFolder`](crate::framework::model::DomainFolder) before the real class is ported.
/// `DomainFolder` only ever passes this type through as an opaque value, so no members are needed
/// yet.
pub trait LinkHandler {}

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

// `DomainFolderFilter` is ported; this was a placeholder standing in for it. Re-exported so
// every importer converges on one type instead of two same-named ones.
pub use crate::framework::model::domain_folder_filter::DomainFolderFilter;

/// Placeholder for `docking.util.image.ToolIconURL`, referenced by
/// [`ToolTemplate`](crate::framework::model::ToolTemplate) before the real class is ported.
/// `ToolTemplate` only ever returns this type, so no members are needed yet.
pub trait ToolIconURL {}

/// Placeholder for `javax.swing.ImageIcon`, referenced by
/// [`ToolTemplate`](crate::framework::model::ToolTemplate) before a Rust equivalent exists.
/// `ToolTemplate` only ever returns this type, so no members are needed yet.
pub trait ImageIcon {}

/// Placeholder for `org.jdom2.Element`, referenced by
/// [`ToolTemplate`](crate::framework::model::ToolTemplate) and
/// [`PluginsConfiguration`](crate::framework::plugintool::PluginsConfiguration) before a Rust
/// equivalent exists. Distinct from [`crate::util::xml::XmlElement`], which mirrors the unrelated
/// `ghidra.xml.XmlElement` pull-parser interface; `org.jdom2.Element` is a DOM-style tree node.
///
/// `ToolTemplate` only ever passes this type through as an opaque value, so all methods default
/// to inert no-ops; `PluginsConfiguration` is the first port that actually builds/reads an
/// element tree (`savePluginsToXml`/`getPluginClassNames`), so it overrides all of them. Rust has
/// no free-standing `new Element(name)` constructor call through a trait object, so
/// [`new_child`](JdomElement::new_child) doubles as the virtual constructor: implementations
/// create a detached child of their own concrete type, which the caller then fills in and attaches
/// with [`add_content`](JdomElement::add_content).
pub trait JdomElement {
    /// Creates a new, detached child element with the given tag name, mirroring `new
    /// Element(String)`. Defaults to an inert placeholder that ignores all further calls.
    fn new_child(&self, _name: &str) -> Box<dyn JdomElement> {
        Box::new(NullJdomElement)
    }

    /// Gets this element's own tag name, mirroring `Element.getName()`. Returns an empty string
    /// by default.
    fn tag_name(&self) -> String {
        String::new()
    }

    /// Sets an attribute on this element, mirroring `Element.setAttribute(String, String)`.
    /// No-op by default.
    fn set_attribute(&mut self, _name: &str, _value: &str) {}

    /// Gets the value of an attribute on this element, mirroring
    /// `Element.getAttributeValue(String)`. Returns `None` by default.
    fn attribute_value(&self, _name: &str) -> Option<String> {
        None
    }

    /// Adds a child element as content of this element, mirroring `Element.addContent(Content)`.
    /// No-op by default.
    fn add_content(&mut self, _child: Box<dyn JdomElement>) {}

    /// Gets this element's direct children with the given tag name, mirroring
    /// `Element.getChildren(String)`. Returns empty by default.
    fn children(&self, _name: &str) -> Vec<&dyn JdomElement> {
        Vec::new()
    }
}

/// Inert fallback [`JdomElement`] used by [`JdomElement::new_child`]'s default body. Carries no
/// state; every method uses the trait's own no-op defaults.
struct NullJdomElement;
impl JdomElement for NullJdomElement {}

/// Placeholder for `ghidra.framework.plugintool.PluginTool`, referenced by
/// [`ToolTemplate`](crate::framework::model::ToolTemplate) before the real class is ported.
/// `ToolTemplate` only ever returns this type, so no members are needed yet.
///
/// Extended for [`AutoService`](crate::framework::plugintool::AutoService), which additionally
/// needs the two `ServiceProvider` members `PluginTool` inherits in Java (`getService`,
/// `addServiceListener`) to query already-available services and register for future ones.
/// Both take `&self`, matching the convention already used by [`PreferencesLike`], since the real
/// `PluginTool` is a single shared, mutable object rather than per-call state; both default to
/// inert no-ops so existing opaque-placeholder implementors are unaffected.
///
/// Extended again for [`Plugin`](crate::framework::plugintool::Plugin), which additionally needs
/// `getServices(Class<?>)` (all active providers of a service, used by
/// `Plugin::is_only_provider_of_service`) and `firePluginEvent(PluginEvent)` (used by
/// `Plugin::fire_plugin_event`). Both default to inert placeholders for the same reason as
/// above.
pub trait PluginTool {
    /// Returns the service implementing `iface`, if currently provided, mirroring
    /// `PluginTool.getService(Class<?>)`.
    fn get_service(&self, _iface: &str) -> Option<Arc<dyn Any + Send + Sync>> {
        None
    }

    /// Returns every currently active provider of `iface`, mirroring
    /// `PluginTool.getServices(Class<?>)`.
    fn get_services(&self, _iface: &str) -> Vec<Arc<dyn Any + Send + Sync>> {
        Vec::new()
    }

    /// Registers a listener to be notified when services are added to or removed from this tool,
    /// mirroring `PluginTool.addServiceListener(ServiceListener)`.
    fn add_service_listener(
        &self,
        _listener: Arc<dyn crate::framework::plugintool::util::ServiceListener>,
    ) {
    }

    /// Notifies all other plugins interested in receiving the given event, mirroring
    /// `PluginTool.firePluginEvent(PluginEvent)`.
    fn fire_plugin_event(&self, _event: crate::framework::plugintool::PluginEvent) {}

    /// The tool's display name: the tool name on its own, or `toolName(instanceName)` when this
    /// tool is a second-or-later instance of that tool. Mirrors `PluginTool.getName()`, which
    /// returns the `fullName` recomputed by `putInstanceName`.
    fn get_name(&self) -> String {
        let instance_name = self.get_instance_name();
        if instance_name.is_empty() {
            self.get_tool_name()
        } else {
            format!("{}({})", self.get_tool_name(), instance_name)
        }
    }

    /// The generic (instance-independent) name of this tool, mirroring
    /// `PluginTool.getToolName()`.
    fn get_tool_name(&self) -> String {
        String::new()
    }

    /// Renames the tool, mirroring `PluginTool.setToolName(String)`. Takes `&self` for the same
    /// reason the service members above do.
    fn set_tool_name(&self, _name: &str) {}

    /// The one-up suffix distinguishing this tool from other running instances of the same tool
    /// (empty for the first instance), mirroring `PluginTool.getInstanceName()`.
    fn get_instance_name(&self) -> String {
        String::new()
    }

    /// Assigns this tool's instance suffix, mirroring `PluginTool.putInstanceName(String)`.
    fn put_instance_name(&self, _instance_name: &str) {}

    /// The names of the events this tool produces, mirroring `PluginTool.getToolEventNames()`.
    fn get_tool_event_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// The names of the events this tool consumes, mirroring
    /// `PluginTool.getConsumedToolEventNames()`.
    fn get_consumed_tool_event_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Whether the tool's plugin configuration has changed since it was last saved, mirroring
    /// `PluginTool.hasConfigChanged()`.
    fn has_config_changed(&self) -> bool {
        false
    }

    /// Whether this tool should be saved, mirroring `PluginTool.shouldSave()`.
    fn should_save(&self) -> bool {
        false
    }

    /// Saves this tool's configuration to the tool chest, mirroring `PluginTool.saveTool()`.
    fn save_tool(&self) {}

    /// Closes the tool, mirroring `PluginTool.close()`.
    fn close(&self) {}

    /// Stops forwarding tool events to `listener`, mirroring
    /// `PluginTool.removeToolListener(ToolListener)`.
    fn remove_tool_listener(&self, _listener: &dyn crate::framework::model::ToolListener) {}
}

/// Adapts a shared [`PluginTool`] handle to the owned `Box<dyn PluginTool>` that the ported
/// interfaces ([`Workspace::get_tools`](crate::framework::model::Workspace::get_tools),
/// [`ToolManager::get_running_tools`](crate::framework::model::ToolManager::get_running_tools),
/// ...) hand back. Java passes the tool objects themselves around by reference; the ported
/// signatures return owned boxes, so a manager that keeps its tools alive in an `Arc` wraps them
/// in this newtype rather than cloning tool state (which would break the identity comparisons
/// Java relies on). Every member forwards to the shared tool, so the box observes and mutates the
/// same tool the manager holds.
pub struct SharedPluginTool(Arc<dyn PluginTool>);

impl SharedPluginTool {
    /// Wraps a shared tool handle.
    pub fn new(tool: Arc<dyn PluginTool>) -> Self {
        Self(tool)
    }

    /// Returns the shared handle this wrapper forwards to.
    pub fn handle(&self) -> &Arc<dyn PluginTool> {
        &self.0
    }
}

impl PluginTool for SharedPluginTool {
    fn get_service(&self, iface: &str) -> Option<Arc<dyn Any + Send + Sync>> {
        self.0.get_service(iface)
    }

    fn get_services(&self, iface: &str) -> Vec<Arc<dyn Any + Send + Sync>> {
        self.0.get_services(iface)
    }

    fn add_service_listener(
        &self,
        listener: Arc<dyn crate::framework::plugintool::util::ServiceListener>,
    ) {
        self.0.add_service_listener(listener);
    }

    fn fire_plugin_event(&self, event: crate::framework::plugintool::PluginEvent) {
        self.0.fire_plugin_event(event);
    }

    fn get_name(&self) -> String {
        self.0.get_name()
    }

    fn get_tool_name(&self) -> String {
        self.0.get_tool_name()
    }

    fn set_tool_name(&self, name: &str) {
        self.0.set_tool_name(name);
    }

    fn get_instance_name(&self) -> String {
        self.0.get_instance_name()
    }

    fn put_instance_name(&self, instance_name: &str) {
        self.0.put_instance_name(instance_name);
    }

    fn get_tool_event_names(&self) -> Vec<String> {
        self.0.get_tool_event_names()
    }

    fn get_consumed_tool_event_names(&self) -> Vec<String> {
        self.0.get_consumed_tool_event_names()
    }

    fn has_config_changed(&self) -> bool {
        self.0.has_config_changed()
    }

    fn should_save(&self) -> bool {
        self.0.should_save()
    }

    fn save_tool(&self) {
        self.0.save_tool();
    }

    fn close(&self) {
        self.0.close();
    }

    fn remove_tool_listener(&self, listener: &dyn crate::framework::model::ToolListener) {
        self.0.remove_tool_listener(listener);
    }
}

/// Inert fallback [`PluginTool`] used by [`PluginLike::tool`]'s default body, mirroring how
/// [`NullJdomElement`] backs [`JdomElement::new_child`]'s default. Carries no state; every method
/// uses the trait's own no-op defaults.
struct NullPluginTool;
impl PluginTool for NullPluginTool {}

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
/// [`GhidraServerHandle`](crate::framework::remote::GhidraServerHandle) and
/// [`AuthenticationModule`](crate::server::security::AuthenticationModule) before a Rust
/// equivalent exists. `Callback` is itself a marker interface with no members in
/// `javax.security.auth`, and most callers only ever pass implementors through as opaque values
/// (returned from `getAuthenticationCallbacks()` and accepted by `getRepositoryServer()`). The
/// one exception is `AuthenticationModule.getFirstCallbackOfType`, a generic static utility that
/// looks a callback up by its exact runtime class; `as_any` supplies the equivalent capability
/// in Rust via [`Any::downcast_ref`].
pub trait AuthCallback: std::any::Any {
    /// Returns `self` as `&dyn Any`, enabling exact-type lookup via `downcast_ref`.
    fn as_any(&self) -> &dyn std::any::Any;
}

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
/// [`PluginInstaller`](crate::framework::plugintool::PluginInstaller) and
/// [`PluginsConfiguration`](crate::framework::plugintool::PluginsConfiguration) before the real
/// class is ported. `PluginInstaller` only ever returns/accepts this type as an opaque value.
/// `PluginsConfiguration::save_plugins_to_xml` additionally needs the plugin's class name
/// (`plugin.getClass().getName()`) to look up its `PluginDescription`, so `plugin_class_name` is
/// declared with a default (empty-string) body -- implementations that only used the opaque form
/// are unaffected, and real implementations override it.
///
/// Extended for [`AutoService`](crate::framework::plugintool::AutoService), which additionally
/// needs `registerServiceProvided` (to register a provided service) and `getTool` (to resolve the
/// tool for the `wireServicesConsumed(Plugin, Object)` overload). Both default to inert
/// no-ops/placeholders so existing opaque-placeholder implementors are unaffected;
/// `register_service_provided` takes `&self` for the same reason `PluginTool`'s members do.
pub trait PluginLike {
    /// Fully-qualified name of this plugin's class, mirroring `getClass().getName()`.
    fn plugin_class_name(&self) -> String {
        String::new()
    }

    /// Registers `service` as this plugin's implementation of `iface`, mirroring
    /// `Plugin.registerServiceProvided(Class<?>, Object)`.
    fn register_service_provided(&self, _iface: &str, _service: Arc<dyn Any + Send + Sync>) {}

    /// Gets this plugin's parent tool, mirroring `Plugin.getTool()`.
    fn tool(&self) -> Arc<dyn PluginTool> {
        Arc::new(NullPluginTool)
    }
}

/// Placeholder for `ghidra.framework.plugintool.testplugins.CircularServiceA`, referenced by
/// [`CircularPluginA`](crate::framework::plugintool::testplugins::CircularPluginA) before the real
/// interface is ported. Mirrors `CircularServiceA`, an empty service interface (annotated
/// `@ServiceInfo(defaultProvider = CircularPluginA.class, description = "Test service")`), so this
/// trait declares no methods; the default-provider association is recorded only in this doc
/// comment rather than as a code dependency, matching how the already-ported
/// [`CircularServiceB`](crate::framework::plugintool::testplugins::CircularServiceB) records its
/// own `defaultProvider` association.
pub trait CircularServiceALike {}

/// Placeholder for `ghidra.framework.plugintool.util.PluginPackage`, referenced by
/// [`DefaultPluginPackagingProvider`](crate::framework::plugintool::default_plugin_packaging_provider::DefaultPluginPackagingProvider)
/// before the real (abstract, `Comparable`) class is ported. `DefaultPluginPackagingProvider`
/// itself only ever passes this type through as an opaque value; `name` is included anyway since
/// it mirrors `PluginPackage.getName()`, the property implementations need to identify which
/// package was passed to `getPluginDescriptions(PluginPackage)`.
pub trait PluginPackageLike {
    /// Gets the name of this plugin package, mirroring `PluginPackage.getName()`.
    fn name(&self) -> String;
}

/// Placeholder for `ghidra.framework.protocol.ghidra.TransientProjectManager`, referenced by
/// [`TransientProjectData`](crate::framework::protocol::ghidra::TransientProjectData) before the
/// real (cache-owning) class is ported. `TransientProjectData::forced_dispose` only ever calls
/// back into it to remove itself from the manager's cache, so only that one callback is declared
/// here.
pub trait TransientProjectManagerLike {
    /// Removes the given transient project data from the manager's cache, keyed by repository
    /// info, mirroring `TransientProjectManager.cleanupProjectData(RepositoryInfo,
    /// TransientProjectData)`.
    fn cleanup_project_data(
        &self,
        repository_info: &crate::framework::protocol::ghidra::RepositoryInfo,
        project_data: &dyn crate::framework::protocol::ghidra::TransientProjectData,
    );
}

/// Placeholder for `ghidra.framework.data.GhidraFileData`, referenced by
/// [`GhidraFolderData`](crate::framework::data::GhidraFolderData) before the real class is
/// ported. `GhidraFolderData` only ever returns this type as an opaque value (from
/// `get_file_data`), so no members are needed yet. Unlike `GhidraFolder`/`GhidraFile` (which
/// implement the already-ported `DomainFolder`/`DomainFile` interfaces and so are represented by
/// those trait objects directly), `GhidraFileData` implements no such interface, hence this
/// dedicated marker.
pub trait GhidraFileDataLike {}

/// Placeholder for `ghidra.framework.protocol.ghidra.GhidraURLWrappedContent`, referenced by
/// [`GhidraURLConnection`](crate::framework::protocol::ghidra::GhidraURLConnection) before the
/// real class is ported. `GhidraURLConnection::get_content` only ever constructs and returns this
/// type as an opaque value (wrapping the connection itself, to be unwrapped later via its own
/// `getContent()`/`release()` methods once ported), so no members are needed yet.
pub trait GhidraURLWrappedContentLike {}

/// Placeholder for `ghidra.framework.protocol.ghidra.Handler` (a `java.net.URLStreamHandler`
/// registered for the `ghidra:` protocol), referenced by
/// [`GhidraURL`](crate::framework::protocol::ghidra::GhidraURL) before the real class -- and the
/// [`GhidraProtocolHandler`](crate::framework::protocol::ghidra::GhidraProtocolHandler) extension
/// registry it consults -- is ported. `GhidraURL::is_supported_server_url` only ever calls
/// `Handler.isSupportedURL(URL)`, so no other members are needed yet.
pub trait GhidraUrlHandlerLike {
    /// Determine if the given Ghidra URL is supported, i.e. it either specifies no protocol
    /// extension or specifies one which has a registered, matching
    /// [`GhidraProtocolHandler`](crate::framework::protocol::ghidra::GhidraProtocolHandler)
    /// extension, mirroring `Handler.isSupportedURL(URL)`.
    fn is_supported_url(&self, url: &str) -> bool;
}

/// Placeholder for `ghidra.framework.data.ProjectLock`, referenced by
/// [`DefaultProjectData`](crate::framework::data::DefaultProjectData) before the real class is
/// ported. `DefaultProjectData::is_locked` only ever constructs a fresh lock for a given
/// `ProjectLocator` and immediately queries whether it is held, so only that one query is
/// declared here; construction itself is left to implementations, mirroring how
/// [`PropertyFile`](crate::util::property_file::PropertyFile)'s construction is
/// implementation-specific rather than part of that trait's contract.
pub trait ProjectLockLike {
    /// Determine if this represents a currently held project lock, mirroring
    /// `ProjectLock.isLocked()`.
    fn is_locked(&self) -> bool;
}

/// Placeholder for `ghidra.framework.plugintool.util.AutoServiceListener`, referenced by
/// [`AutoService`](crate::framework::plugintool::AutoService) before the real class is ported. In
/// Java, `AutoServiceListener<R>` reflectively discovers every `@AutoServiceConsumed`-annotated
/// field/method on a receiver's class (and its superclasses/interfaces) to build a
/// `ReceiverProfile`, then uses that profile to push newly-(un)available services into the
/// receiver, and to answer `notifyCurrentServices(PluginTool)` by querying the tool for each
/// consumed interface it already knows about. Rust has no field reflection, so `AutoService` leaves
/// discovery and application of services entirely to implementations of this trait; `AutoService`
/// itself only needs the one operation it calls directly on the listener,
/// `notify_current_services` (a real `AutoServiceListener` also implements `ServiceListener`
/// directly, so it can be registered with the tool; here [`AutoService::listener_for`] returns both
/// views of one implementor instead, since Rust trait objects cannot be upcast to an unrelated
/// trait).
pub trait AutoServiceListenerLike: Send + Sync {
    /// Pushes every currently-available service this listener already knows its receiver consumes,
    /// mirroring `AutoServiceListener.notifyCurrentServices(PluginTool)`.
    fn notify_current_services(&self, tool: &dyn PluginTool);
}

/// Placeholder for `ghidra.framework.data.DBDomainObjectSupport`, referenced by
/// [`DBCachedDomainObjectAdapter`](crate::util::database::DBCachedDomainObjectAdapter) as its
/// superclass (`DBCachedDomainObjectAdapter extends DBDomainObjectSupport` in Java) before the
/// real class is ported. `DBDomainObjectSupport` in turn extends the already-ported
/// [`DomainObjectAdapterDB`](crate::framework::data::DomainObjectAdapterDB), so that real
/// relationship is kept as a supertrait bound here rather than re-declared. Only `init` (the one
/// public member besides the inherited `DomainObjectAdapterDB`/`DomainObject` surface) is
/// exposed; `finishedCreatingManagers`/`createManager` are protected extension points that no
/// ported caller needs yet.
pub trait DBDomainObjectSupport: crate::framework::data::DomainObjectAdapterDB {
    /// Resolves this object's dependent managers and finalizes construction, mirroring
    /// `DBDomainObjectSupport.init()`.
    fn init(&mut self) -> std::io::Result<()>;
}

/// Placeholder for `ghidra.framework.project.tool.GhidraTool`, referenced by
/// [`ToolManagerImpl`](crate::framework::project::tool::ToolManagerImpl) (`createEmptyTool()`
/// launches `new GhidraTool(project, "Untitled")`) before the real class is ported. The real
/// `GhidraTool` is a full `PluginTool` — plugins, windowing, actions, extension checks; this
/// placeholder carries only the naming and save state `ToolManagerImpl` observes, so that a
/// manager can create, name and count empty tools before the real tool exists.
///
/// All state is behind [`RefCell`]/[`Cell`] because [`PluginTool`]'s mutating members take
/// `&self` (see the trait's own note: the real tool is one shared, mutable object).
pub struct GhidraTool {
    tool_name: RefCell<String>,
    instance_name: RefCell<String>,
    config_changed: Cell<bool>,
    closed: Cell<bool>,
    saved: Cell<bool>,
}

impl GhidraTool {
    /// Creates an unsaved, open tool with the given generic tool name and no instance suffix.
    pub fn new(tool_name: impl Into<String>) -> Self {
        Self {
            tool_name: RefCell::new(tool_name.into()),
            instance_name: RefCell::new(String::new()),
            config_changed: Cell::new(false),
            closed: Cell::new(false),
            saved: Cell::new(false),
        }
    }

    /// Whether [`PluginTool::close`] has been called on this tool.
    pub fn is_closed(&self) -> bool {
        self.closed.get()
    }

    /// Whether [`PluginTool::save_tool`] has been called on this tool.
    pub fn was_saved(&self) -> bool {
        self.saved.get()
    }

    /// Marks the tool's plugin configuration dirty, standing in for the plugin add/remove that
    /// sets `configChangedFlag` on the real tool.
    pub fn set_config_changed(&self, changed: bool) {
        self.config_changed.set(changed);
    }
}

impl PluginTool for GhidraTool {
    fn get_tool_name(&self) -> String {
        self.tool_name.borrow().clone()
    }

    fn set_tool_name(&self, name: &str) {
        *self.tool_name.borrow_mut() = name.to_string();
    }

    fn get_instance_name(&self) -> String {
        self.instance_name.borrow().clone()
    }

    fn put_instance_name(&self, instance_name: &str) {
        *self.instance_name.borrow_mut() = instance_name.to_string();
    }

    fn has_config_changed(&self) -> bool {
        self.config_changed.get()
    }

    fn should_save(&self) -> bool {
        self.config_changed.get()
    }

    fn save_tool(&self) {
        self.saved.set(true);
        self.config_changed.set(false);
    }

    fn close(&self) {
        self.closed.set(true);
    }
}

/// Placeholder for `ghidra.framework.project.tool.WorkspaceImpl`, referenced by
/// [`ToolManagerImpl`](crate::framework::project::tool::ToolManagerImpl), which creates,
/// activates, serializes and disposes the workspaces it manages, before the real class is ported.
///
/// The Java class holds a back-reference to its `ToolManagerImpl` and calls up into it
/// (`setActive`, `closeRunningTool`, `setName` all delegate to the manager). That back-reference is
/// the dependency cycle this stub exists to break, so it is *not* reproduced: the manager drives
/// the workspace instead (see [`ToolManagerImpl::set_active_workspace`] and friends), and this
/// type is a passive record of one workspace's name, visibility and running tools. Consequently
/// [`Workspace::create_tool`]/[`Workspace::run_tool`] here launch a detached
/// [`GhidraTool`] that is *not* registered with any manager; the real class routes both through
/// `ToolManagerImpl`.
///
/// [`ToolManagerImpl::set_active_workspace`]: crate::framework::project::tool::ToolManagerImpl::set_active_workspace
pub struct WorkspaceImpl {
    name: String,
    tools: Vec<Arc<dyn PluginTool>>,
    active: bool,
}

impl WorkspaceImpl {
    /// Creates an empty, inactive workspace with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), tools: Vec::new(), active: false }
    }

    /// The workspace name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Renames this workspace. Unlike `WorkspaceImpl.setName(String)` this does not check the
    /// name against the manager's other workspaces; [`ToolManagerImpl::set_workspace_name`] does
    /// that before calling here.
    ///
    /// [`ToolManagerImpl::set_workspace_name`]: crate::framework::project::tool::ToolManagerImpl::set_workspace_name
    pub fn rename(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// The tools running in this workspace, mirroring `WorkspaceImpl.getTools()` but handing back
    /// the shared handles instead of owned boxes so callers can compare tool identity.
    pub fn tools(&self) -> &[Arc<dyn PluginTool>] {
        &self.tools
    }

    /// Adds an already-created tool to this workspace's running set.
    pub fn add_tool(&mut self, tool: Arc<dyn PluginTool>) {
        self.tools.push(tool);
    }

    /// Removes a tool from this workspace's running set, returning whether it was there. Mirrors
    /// the `runningTools.remove(tool)` half of `WorkspaceImpl.closeRunningTool(PluginTool)`; the
    /// manager-notification half lives in
    /// [`ToolManagerImpl::close_tool`](crate::framework::project::tool::ToolManagerImpl::close_tool).
    pub fn remove_tool(&mut self, tool: &Arc<dyn PluginTool>) -> bool {
        let before = self.tools.len();
        self.tools.retain(|t| !Arc::ptr_eq(t, tool));
        self.tools.len() != before
    }

    /// Shows or hides every tool in this workspace, mirroring `WorkspaceImpl.setVisible(boolean)`.
    pub fn set_visible(&mut self, state: bool) {
        self.active = state;
    }

    /// Whether this workspace is the active (visible) one.
    pub fn is_visible(&self) -> bool {
        self.active
    }

    /// Closes and forgets every running tool, mirroring `WorkspaceImpl.dispose()`.
    pub fn dispose(&mut self) {
        for tool in &self.tools {
            tool.close();
        }
        self.tools.clear();
    }

    /// Writes this workspace as a `WORKSPACE` child of `parent`, mirroring
    /// `WorkspaceImpl.saveToXml()`. `parent` is only used as the element factory, following the
    /// [`JdomElement::new_child`] convention.
    pub fn save_to_xml(&self, parent: &dyn JdomElement) -> Box<dyn JdomElement> {
        let mut root = parent.new_child("WORKSPACE");
        root.set_attribute("NAME", &self.name);
        root.set_attribute("ACTIVE", &self.active.to_string());
        for tool in &self.tools {
            let mut elem = root.new_child("RUNNING_TOOL");
            elem.set_attribute("TOOL_NAME", &tool.get_tool_name());
            root.add_content(elem);
        }
        root
    }

    /// Reads this workspace's name and active flag back, mirroring
    /// `WorkspaceImpl.restoreFromXml(Element)`. Restoring the running tools themselves needs the
    /// real `PluginTool`, so it is left to the real port.
    pub fn restore_from_xml(&mut self, root: &dyn JdomElement) {
        if let Some(name) = root.attribute_value("NAME") {
            self.name = name;
        }
        self.active = root
            .attribute_value("ACTIVE")
            .is_some_and(|active| active.eq_ignore_ascii_case("true"));
    }
}

impl crate::framework::model::Workspace for WorkspaceImpl {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_tools(&self) -> Vec<Box<dyn PluginTool>> {
        self.tools
            .iter()
            .map(|t| Box::new(SharedPluginTool::new(Arc::clone(t))) as Box<dyn PluginTool>)
            .collect()
    }

    fn create_tool(&mut self) -> Box<dyn PluginTool> {
        let tool: Arc<dyn PluginTool> = Arc::new(GhidraTool::new("Untitled"));
        self.tools.push(Arc::clone(&tool));
        Box::new(SharedPluginTool::new(tool))
    }

    fn run_tool(
        &mut self,
        template: &dyn crate::framework::model::ToolTemplate,
    ) -> Box<dyn PluginTool> {
        let tool: Arc<dyn PluginTool> = Arc::new(GhidraTool::new(template.get_name()));
        self.tools.push(Arc::clone(&tool));
        Box::new(SharedPluginTool::new(tool))
    }

    fn set_name(
        &mut self,
        new_name: &str,
    ) -> Result<(), crate::util::exception::DuplicateNameException> {
        self.name = new_name.to_string();
        Ok(())
    }

    fn set_active(&mut self) {
        self.set_visible(true);
    }
}

/// Placeholder for `ghidra.framework.project.tool.ToolConnectionImpl`, referenced by
/// [`ToolManagerImpl`](crate::framework::project::tool::ToolManagerImpl), which caches one per
/// producer/consumer pair, before the real class is ported.
///
/// Java hands the very same connection object back out of `ToolManagerImpl.getConnection`, and
/// the caller then mutates it with `connect`/`disconnect`; the ported
/// [`ToolManager::get_connection`](crate::framework::model::ToolManager::get_connection) returns
/// an owned `Box<dyn ToolConnection>` instead, so this type is a cheap handle whose state lives
/// behind a shared [`Rc`]: cloning it out of the manager's map keeps the caller and the manager
/// looking at one connection.
///
/// [`update_event_list`](ToolConnectionImpl::update_event_list) reproduces the real class's
/// producer-events ∩ consumer-events rule, since the manager's own `updateConnectMap` depends on
/// it; the event *delivery* half (`processToolEvent`, registering as the producer's
/// [`ToolListener`](crate::framework::model::ToolListener)) is left inert for the real port.
#[derive(Clone)]
pub struct ToolConnectionImpl {
    producer: Arc<dyn PluginTool>,
    consumer: Arc<dyn PluginTool>,
    state: Rc<RefCell<ToolConnectionState>>,
}

#[derive(Default)]
struct ToolConnectionState {
    events: Vec<String>,
    connected: BTreeSet<String>,
    changed: bool,
}

impl ToolConnectionImpl {
    /// Creates the connection between `producer` and `consumer`, seeding the event list with the
    /// events they have in common.
    pub fn new(producer: Arc<dyn PluginTool>, consumer: Arc<dyn PluginTool>) -> Self {
        let connection =
            Self { producer, consumer, state: Rc::new(RefCell::new(ToolConnectionState::default())) };
        connection.update_event_list();
        connection
    }

    /// The shared producer handle (the [`ToolConnection`](crate::framework::model::ToolConnection)
    /// member can only hand back a borrow).
    pub fn producer(&self) -> &Arc<dyn PluginTool> {
        &self.producer
    }

    /// The shared consumer handle.
    pub fn consumer(&self) -> &Arc<dyn PluginTool> {
        &self.consumer
    }

    /// Recomputes the events this connection covers as the intersection of what the producer
    /// produces and what the consumer consumes, dropping any connection made for an event that no
    /// longer applies. Mirrors `ToolConnectionImpl.updateEventList()`.
    pub fn update_event_list(&self) {
        let consumed: BTreeSet<String> =
            self.consumer.get_consumed_tool_event_names().into_iter().collect();
        let events: Vec<String> = self
            .producer
            .get_tool_event_names()
            .into_iter()
            .filter(|e| consumed.contains(e))
            .collect();
        let mut state = self.state.borrow_mut();
        state.connected.retain(|e| events.contains(e));
        state.events = events;
    }

    /// Whether a connection has been made or broken since the last
    /// [`clear_changed`](ToolConnectionImpl::clear_changed), mirroring
    /// `ToolConnectionImpl.hasChanged()`.
    pub fn has_changed(&self) -> bool {
        self.state.borrow().changed
    }

    /// Resets the changed flag, as saving the project does.
    pub fn clear_changed(&self) {
        self.state.borrow_mut().changed = false;
    }

    /// Writes this connection as a `CONNECTION` child of `parent`, mirroring
    /// `ToolConnectionImpl.saveToXml()`.
    pub fn save_to_xml(&self, parent: &dyn JdomElement) -> Box<dyn JdomElement> {
        let mut root = parent.new_child("CONNECTION");
        root.set_attribute("PRODUCER", &self.producer.get_name());
        root.set_attribute("CONSUMER", &self.consumer.get_name());
        for event in &self.state.borrow().connected {
            let mut elem = root.new_child("EVENT");
            elem.set_attribute("NAME", event);
            root.add_content(elem);
        }
        root
    }

    /// Reads the connected event names back, mirroring
    /// `ToolConnectionImpl.restoreFromXml(Element)`.
    pub fn restore_from_xml(&self, root: &dyn JdomElement) {
        let names: Vec<String> = root
            .children("EVENT")
            .iter()
            .filter_map(|child| child.attribute_value("NAME"))
            .collect();
        let mut state = self.state.borrow_mut();
        for name in names {
            if state.events.contains(&name) {
                state.connected.insert(name);
            }
        }
        state.changed = false;
    }
}

impl crate::framework::model::ToolConnection for ToolConnectionImpl {
    fn get_producer(&self) -> &dyn PluginTool {
        self.producer.as_ref()
    }

    fn get_consumer(&self) -> &dyn PluginTool {
        self.consumer.as_ref()
    }

    fn get_events(&self) -> Vec<String> {
        self.state.borrow().events.clone()
    }

    fn connect(&mut self, event_name: &str) -> Result<(), String> {
        let mut state = self.state.borrow_mut();
        if !state.events.iter().any(|e| e == event_name) {
            return Err(format!("invalid event name: {event_name}"));
        }
        if state.connected.insert(event_name.to_string()) {
            state.changed = true;
        }
        Ok(())
    }

    fn disconnect(&mut self, event_name: &str) -> Result<(), String> {
        let mut state = self.state.borrow_mut();
        if !state.events.iter().any(|e| e == event_name) {
            return Err(format!("invalid event name: {event_name}"));
        }
        if state.connected.remove(event_name) {
            state.changed = true;
        }
        Ok(())
    }

    fn is_connected(&self, event_name: &str) -> bool {
        self.state.borrow().connected.contains(event_name)
    }
}

impl crate::framework::model::ToolListener for ToolConnectionImpl {
    fn process_tool_event(&mut self, _tool_event: &crate::framework::plugintool::PluginEvent) {}
}
