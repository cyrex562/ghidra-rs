pub mod ghidra_bundle_activator;
pub mod osgi_exception;
pub mod osgi_utils;

pub use ghidra_bundle_activator::GhidraBundleActivator;
pub use osgi_exception::OSGiException;
pub use osgi_utils::{BundleCapability, BundleEventType, BundleRequirement, BundleState, OSGiUtils};

/// Represents the OSGi bundle context. This is a marker type for the context in which
/// a bundle operates. In the full OSGi framework, this would contain references to services,
/// registered bundles, etc. For porting purposes, this is a simplified representation.
#[derive(Clone, Debug)]
pub struct BundleContext;

/// Trait representing the OSGi BundleActivator interface.
/// Implementations are notified when the bundle is started and stopped.
pub trait BundleActivator: Send + Sync {
    /// Called when the bundle is started.
    fn start(&self, context: &BundleContext) -> Result<(), String>;

    /// Called when the bundle is stopped.
    fn stop(&self, context: &BundleContext) -> Result<(), String>;
}
