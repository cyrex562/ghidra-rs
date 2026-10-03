//! Service to query auto-map settings.
//!
//! Port of `ghidra.app.services.DebuggerAutoMappingService`. The Java `@ServiceInfo` annotation
//! (default provider `DebuggerModulesPlugin`) has no Rust equivalent and is omitted.
//!
//! Java's overloaded `getAutoMapSpec()`/`getAutoMapSpec(Trace)` are each given a distinct Rust
//! name, since Rust traits cannot overload on parameter type alone: the no-argument overload
//! stays `get_auto_map_spec`, while the `Trace` overload becomes `get_auto_map_spec_for_trace`.

use crate::app::seam_stubs::AutoMapSpec;
use crate::trace::model::trace::Trace;

/// The service to query auto-map settings.
///
/// Port of `ghidra.app.services.DebuggerAutoMappingService`.
pub trait DebuggerAutoMappingService {
    /// Sets the current auto-map specification in the Modules provider.
    fn set_auto_map_spec(&mut self, spec: Box<dyn AutoMapSpec>);

    /// Gets the auto-map setting currently active in the Modules provider.
    fn get_auto_map_spec(&self) -> Box<dyn AutoMapSpec>;

    /// Gets the current auto-map setting for the given trace, or the setting in the Modules
    /// provider, if the trace does not have its own setting.
    fn get_auto_map_spec_for_trace(&self, trace: &dyn Trace) -> Box<dyn AutoMapSpec>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAutoMapSpec;
    impl AutoMapSpec for MockAutoMapSpec {}

    struct MockDebuggerAutoMappingService;

    impl DebuggerAutoMappingService for MockDebuggerAutoMappingService {
        fn set_auto_map_spec(&mut self, _spec: Box<dyn AutoMapSpec>) {}

        fn get_auto_map_spec(&self) -> Box<dyn AutoMapSpec> {
            Box::new(MockAutoMapSpec)
        }

        fn get_auto_map_spec_for_trace(&self, _trace: &dyn Trace) -> Box<dyn AutoMapSpec> {
            Box::new(MockAutoMapSpec)
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn DebuggerAutoMappingService> =
            Box::new(MockDebuggerAutoMappingService);
        service.set_auto_map_spec(Box::new(MockAutoMapSpec));
        let _ = service.get_auto_map_spec();
    }
}
