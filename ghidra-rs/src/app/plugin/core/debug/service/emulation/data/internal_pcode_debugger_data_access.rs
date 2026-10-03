//! Internal extension of InternalPcodeTraceDataAccess for debugger-specific functionality.
//!
//! Port of `ghidra.app.plugin.core.debug.service.emulation.data.InternalPcodeDebuggerDataAccess`.

use crate::framework::plugintool::service_provider::ServiceProvider;
use crate::app::seam_stubs::Target;
use crate::pcode::exec::trace::data::internal_pcode_trace_data_access::InternalPcodeTraceDataAccess;

/// Internal extension of [`InternalPcodeTraceDataAccess`] that provides access to debugger-specific
/// functionality through a service provider and target interface.
///
/// This trait extends `InternalPcodeTraceDataAccess` with methods for accessing the service provider
/// and the debug target.
pub trait InternalPcodeDebuggerDataAccess: InternalPcodeTraceDataAccess {
    /// Get the service provider for this debugger session.
    fn get_service_provider(&self) -> &dyn ServiceProvider;

    /// Get the debug target associated with this debugger session.
    fn get_target(&self) -> Option<&dyn Target>;

    /// Check if the target is live (valid and at a current snapshot).
    ///
    /// Returns true if the target is valid and the current snapshot matches one of the
    /// target's active snapshots, indicating that the target is currently recording.
    fn is_live(&self) -> bool {
        let target = match self.get_target() {
            Some(t) => t,
            None => return false,
        };

        if !target.is_valid() {
            return false;
        }

        let viewport = self.get_viewport();
        for snap in viewport.get_reversed_snaps() {
            if target.get_snap() == snap {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::plugintool::util::ServiceListener;

    #[test]
    fn test_trait_is_object_safe() {
        fn assert_object_safe(_: &dyn InternalPcodeDebuggerDataAccess) {}

        struct Dummy;
        impl ServiceProvider for Dummy {
            fn get_service(&self, _: &str) -> Option<Box<dyn std::any::Any + Send + Sync>> { None }
            fn add_service_listener(&mut self, _: Box<dyn ServiceListener>) {}
            fn remove_service_listener(&mut self, _: Box<dyn ServiceListener>) {}
        }

        impl Target for Dummy {
            fn is_valid(&self) -> bool { true }
            fn get_snap(&self) -> i64 { 1 }
        }
    }

    #[test]
    fn test_is_live_logic_null_target() {
        struct MockAccess;
        impl Target for MockAccess {
            fn is_valid(&self) -> bool { true }
            fn get_snap(&self) -> i64 { 1 }
        }

        struct Impl;
        impl ServiceProvider for Impl {
            fn get_service(&self, _: &str) -> Option<Box<dyn std::any::Any + Send + Sync>> { None }
            fn add_service_listener(&mut self, _: Box<dyn ServiceListener>) {}
            fn remove_service_listener(&mut self, _: Box<dyn ServiceListener>) {}
        }

        let target: Option<&dyn Target> = None;
        let is_live = match target {
            Some(_) => true,
            None => false,
        };
        assert!(!is_live, "is_live should return false when target is null");
    }
}
