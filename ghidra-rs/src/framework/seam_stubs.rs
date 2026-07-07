//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.framework.model.DomainObjectListener`, referenced by
/// [`DomainObject`](crate::framework::model::DomainObject) before the real interface is ported.
/// `DomainObject` only ever registers/unregisters this listener, never calls
/// `domainObjectChanged` on it, so no members are needed yet.
pub trait DomainObjectListener {}

/// Placeholder for `ghidra.framework.model.DomainObjectClosedListener`, referenced by
/// [`DomainObject`](crate::framework::model::DomainObject) before the real interface is ported.
/// `DomainObject` only ever registers/unregisters this listener, so no members are needed yet.
pub trait DomainObjectClosedListener {}

/// Placeholder for `ghidra.framework.data.DomainObjectFileListener`, referenced by
/// [`DomainObject`](crate::framework::model::DomainObject) before the real interface is ported.
/// `DomainObject` only ever registers/unregisters this listener, so no members are needed yet.
pub trait DomainObjectFileListener {}

/// Placeholder for `ghidra.framework.options.Options`, referenced by
/// [`DomainObject`](crate::framework::model::DomainObject) before the real interface is ported.
/// `DomainObject` only ever returns this type, so no members are needed yet.
pub trait Options {}

/// Placeholder for `ghidra.framework.model.TransactionListener`, referenced by
/// [`DomainObject`](crate::framework::model::DomainObject) before the real interface is ported.
/// `DomainObject` only ever registers/unregisters this listener, so no members are needed yet.
pub trait TransactionListener {}

/// Placeholder for `ghidra.framework.model.DomainFolder`, referenced by
/// [`DomainFile`](crate::framework::model::DomainFile) before the real interface is ported.
/// `DomainFile` only ever passes this type through (as a parent or move/copy destination), so no
/// members are needed yet.
pub trait DomainFolder {}

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
