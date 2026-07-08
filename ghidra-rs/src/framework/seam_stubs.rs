//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.framework.model.DomainObjectChangedEvent`, referenced by
/// [`DomainObjectListener`](crate::framework::model::DomainObjectListener) before the real class
/// is ported. `DomainObjectListener` only ever passes this type through as an opaque value, so no
/// members are needed yet.
pub trait DomainObjectChangedEvent {}

/// Placeholder for `ghidra.framework.model.TransactionListener`, referenced by
/// [`DomainObject`](crate::framework::model::DomainObject) before the real interface is ported.
/// `DomainObject` only ever registers/unregisters this listener, so no members are needed yet.
pub trait TransactionListener {}

/// Placeholder for `ghidra.framework.model.ProjectData`, referenced by
/// [`DomainFolder`](crate::framework::model::DomainFolder) before the real class is ported.
/// `DomainFolder` only ever returns this type, so no members are needed yet.
pub trait ProjectData {}

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

/// Placeholder for `ghidra.framework.model.LinkFileInfo`, referenced by
/// [`DomainFile`](crate::framework::model::DomainFile) before the real interface is ported.
/// `DomainFile` only ever returns this type, so no members are needed yet.
pub trait LinkFileInfo {}

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

/// Placeholder for `ghidra.util.HelpLocation`, referenced by
/// [`Options`](crate::framework::options::Options) before the real class is ported. `Options`
/// only ever passes this type through as an opaque value, so no members are needed yet.
pub trait HelpLocation {}

/// Placeholder for `ghidra.framework.options.CustomOption`, referenced by
/// [`Options`](crate::framework::options::Options) before the real interface is ported. `Options`
/// only ever passes this type through as an opaque value, so no members are needed yet.
pub trait CustomOption {}

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

/// Placeholder for `ghidra.framework.model.Project`, referenced by
/// [`ToolTemplate`](crate::framework::model::ToolTemplate) and
/// [`ProjectManager`](crate::framework::model::ProjectManager) before the real interface is
/// ported. Only ever returned/passed through as an opaque value, so no members are needed yet.
pub trait Project {}

/// Placeholder for `ghidra.framework.client.RepositoryAdapter`, referenced by
/// [`ProjectManager`](crate::framework::model::ProjectManager) before the real class is ported.
/// `ProjectManager` only ever passes this type through as an opaque value, so no members are
/// needed yet.
pub trait RepositoryAdapter {}

/// Placeholder for `ghidra.framework.client.RepositoryServerAdapter`, referenced by
/// [`ProjectManager`](crate::framework::model::ProjectManager) before the real class is ported.
/// `ProjectManager` only ever returns this type, so no members are needed yet.
pub trait RepositoryServerAdapter {}

/// Placeholder for `ghidra.framework.model.ToolChest`, referenced by
/// [`ProjectManager`](crate::framework::model::ProjectManager) before the real interface is
/// ported. `ProjectManager` only ever returns this type, so no members are needed yet.
pub trait ToolChest {}

/// Placeholder for `ghidra.framework.model.ToolAssociationInfo`, referenced by
/// [`ToolServices`](crate::framework::model::ToolServices) before the real class is ported.
/// `ToolServices` only ever passes this type through as an opaque value, so no members are
/// needed yet.
pub trait ToolAssociationInfo {}
