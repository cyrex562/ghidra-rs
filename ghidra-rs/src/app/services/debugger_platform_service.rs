//! Service to manage the current platform mapper for active traces.
//!
//! Port of `ghidra.app.services.DebuggerPlatformService`.

use crate::app::seam_stubs::{DebuggerPlatformMapper, TraceObject};
use crate::trace::model::trace::Trace;

/// A service to manage the current mapper for active traces.
///
/// Port of `ghidra.app.services.DebuggerPlatformService`.
pub trait DebuggerPlatformService {
    /// Get the current mapper for the given trace.
    fn get_current_mapper_for(
        &self,
        trace: &dyn Trace,
    ) -> Option<Box<dyn DebuggerPlatformMapper>>;

    /// Get a mapper applicable to the given object.
    ///
    /// If the trace's current mapper is applicable to the object, it will be returned.
    /// Otherwise, the service will query the opinions for a new mapper, as in
    /// [`get_new_mapper`](Self::get_new_mapper), and set it as the current mapper before
    /// returning. If a new mapper is set, the trace is also initialized for that mapper.
    fn get_mapper(
        &self,
        trace: &dyn Trace,
        object: &dyn TraceObject,
        snap: i64,
    ) -> Option<Box<dyn DebuggerPlatformMapper>>;

    /// Get a new mapper for the given object, ignoring the trace's current mapper.
    ///
    /// This will not replace the trace's current mapper, nor will it initialize the trace for
    /// the mapper.
    fn get_new_mapper(
        &self,
        trace: &dyn Trace,
        object: &dyn TraceObject,
        snap: i64,
    ) -> Option<Box<dyn DebuggerPlatformMapper>>;

    /// Set the current mapper for the trace and initialize the trace for the mapper.
    fn set_current_mapper_for(
        &mut self,
        trace: &dyn Trace,
        focus: &dyn TraceObject,
        mapper: Box<dyn DebuggerPlatformMapper>,
        snap: i64,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockMapper;
    impl DebuggerPlatformMapper for MockMapper {}

    struct MockDebuggerPlatformService;

    impl DebuggerPlatformService for MockDebuggerPlatformService {
        fn get_current_mapper_for(
            &self,
            _trace: &dyn Trace,
        ) -> Option<Box<dyn DebuggerPlatformMapper>> {
            Some(Box::new(MockMapper))
        }

        fn get_mapper(
            &self,
            _trace: &dyn Trace,
            _object: &dyn TraceObject,
            _snap: i64,
        ) -> Option<Box<dyn DebuggerPlatformMapper>> {
            Some(Box::new(MockMapper))
        }

        fn get_new_mapper(
            &self,
            _trace: &dyn Trace,
            _object: &dyn TraceObject,
            _snap: i64,
        ) -> Option<Box<dyn DebuggerPlatformMapper>> {
            None
        }

        fn set_current_mapper_for(
            &mut self,
            _trace: &dyn Trace,
            _focus: &dyn TraceObject,
            _mapper: Box<dyn DebuggerPlatformMapper>,
            _snap: i64,
        ) {
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn DebuggerPlatformService> = Box::new(MockDebuggerPlatformService);
        let _ = service;
    }
}
