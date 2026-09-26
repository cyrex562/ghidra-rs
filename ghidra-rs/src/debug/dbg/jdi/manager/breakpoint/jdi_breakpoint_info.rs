use std::fmt;
use std::hash::{Hash, Hasher};

use super::jdi_breakpoint_type::JdiBreakpointType;
use crate::debug::dbg::jdi::manager::jdi_thread_info::ThreadReference;

/// Opaque handle for a JDI EventRequest (BreakpointRequest, AccessWatchpointRequest,
/// or ModificationWatchpointRequest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventRequest(pub u64);

/// Opaque handle for a JDI ObjectReference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectReference(pub u64);

/// Opaque handle for a JDI ReferenceType.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReferenceType(pub u64);

/// Captured information about a JDI breakpoint.
///
/// This is not a live handle to the breakpoint; it is a snapshot of information
/// from an event or request. If other commands have been executed since this
/// snapshot was taken, the information may be stale.
///
/// Mirrors `JdiBreakpointInfo` from `ghidra.dbg.jdi.manager.breakpoint`.
pub struct JdiBreakpointInfo {
    request: EventRequest,
    ty: JdiBreakpointType,
    enabled: bool,
    object_filter: Option<ObjectReference>,
    thread_filter: Option<ThreadReference>,
    class_filter: Option<ReferenceType>,
    filter_pattern: Option<String>,
    #[allow(dead_code)]
    exclude_pattern: bool,
}

impl JdiBreakpointInfo {
    /// Create info for a breakpoint request.
    pub fn from_breakpoint(request: EventRequest) -> Self {
        Self::new(request, JdiBreakpointType::Breakpoint)
    }

    /// Create info for an access-watchpoint request.
    pub fn from_access_watchpoint(request: EventRequest) -> Self {
        Self::new(request, JdiBreakpointType::AccessWatchpoint)
    }

    /// Create info for a modification-watchpoint request.
    pub fn from_modification_watchpoint(request: EventRequest) -> Self {
        Self::new(request, JdiBreakpointType::ModificationWatchpoint)
    }

    fn new(request: EventRequest, ty: JdiBreakpointType) -> Self {
        Self {
            request,
            ty,
            enabled: false,
            object_filter: None,
            thread_filter: None,
            class_filter: None,
            filter_pattern: None,
            exclude_pattern: false,
        }
    }

    /// Get the type of this breakpoint.
    pub fn get_type(&self) -> JdiBreakpointType {
        self.ty
    }

    /// Get the underlying event request handle.
    pub fn get_request(&self) -> EventRequest {
        self.request
    }

    /// Returns true if this breakpoint or watchpoint is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable this breakpoint or watchpoint.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the object filter, if set.
    pub fn get_object_filter(&self) -> Option<ObjectReference> {
        self.object_filter
    }

    /// Set or clear the object filter.
    pub fn set_object_filter(&mut self, filter: Option<ObjectReference>) {
        self.object_filter = filter;
    }

    /// Get the thread filter, if set.
    pub fn get_thread_filter(&self) -> Option<ThreadReference> {
        self.thread_filter
    }

    /// Set or clear the thread filter.
    pub fn set_thread_filter(&mut self, filter: Option<ThreadReference>) {
        self.thread_filter = filter;
    }

    /// Get the class (reference type) filter, if set.
    pub fn get_class_filter(&self) -> Option<ReferenceType> {
        self.class_filter
    }

    /// Set or clear the class filter.
    pub fn set_class_filter(&mut self, filter: Option<ReferenceType>) {
        self.class_filter = filter;
    }

    /// Get the class filter pattern, if set.
    pub fn get_filter_pattern(&self) -> Option<&str> {
        self.filter_pattern.as_deref()
    }

    /// Set or clear the class filter pattern.
    pub fn set_filter_pattern(&mut self, pattern: Option<String>) {
        self.filter_pattern = pattern;
    }
}

impl PartialEq for JdiBreakpointInfo {
    /// Two infos are equal when they refer to the same underlying request, mirroring
    /// the Java reference-equality check (`this.request == that.request`).
    fn eq(&self, other: &Self) -> bool {
        self.request == other.request
    }
}

impl Eq for JdiBreakpointInfo {}

impl Hash for JdiBreakpointInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.request.hash(state);
    }
}

impl fmt::Display for JdiBreakpointInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.request)
    }
}

impl fmt::Debug for JdiBreakpointInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JdiBreakpointInfo")
            .field("request", &self.request)
            .field("ty", &self.ty)
            .field("enabled", &self.enabled)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn req(id: u64) -> EventRequest {
        EventRequest(id)
    }

    #[test]
    fn from_breakpoint_sets_type() {
        let info = JdiBreakpointInfo::from_breakpoint(req(1));
        assert_eq!(info.get_type(), JdiBreakpointType::Breakpoint);
    }

    #[test]
    fn from_access_watchpoint_sets_type() {
        let info = JdiBreakpointInfo::from_access_watchpoint(req(2));
        assert_eq!(info.get_type(), JdiBreakpointType::AccessWatchpoint);
    }

    #[test]
    fn from_modification_watchpoint_sets_type() {
        let info = JdiBreakpointInfo::from_modification_watchpoint(req(3));
        assert_eq!(info.get_type(), JdiBreakpointType::ModificationWatchpoint);
    }

    #[test]
    fn get_request_returns_handle() {
        let info = JdiBreakpointInfo::from_breakpoint(req(42));
        assert_eq!(info.get_request(), EventRequest(42));
    }

    #[test]
    fn initially_disabled() {
        let info = JdiBreakpointInfo::from_breakpoint(req(1));
        assert!(!info.is_enabled());
    }

    #[test]
    fn set_enabled_true() {
        let mut info = JdiBreakpointInfo::from_breakpoint(req(1));
        info.set_enabled(true);
        assert!(info.is_enabled());
    }

    #[test]
    fn set_enabled_false_after_true() {
        let mut info = JdiBreakpointInfo::from_breakpoint(req(1));
        info.set_enabled(true);
        info.set_enabled(false);
        assert!(!info.is_enabled());
    }

    #[test]
    fn object_filter_initially_none() {
        let info = JdiBreakpointInfo::from_breakpoint(req(1));
        assert!(info.get_object_filter().is_none());
    }

    #[test]
    fn set_object_filter() {
        let mut info = JdiBreakpointInfo::from_breakpoint(req(1));
        info.set_object_filter(Some(ObjectReference(99)));
        assert_eq!(info.get_object_filter(), Some(ObjectReference(99)));
    }

    #[test]
    fn clear_object_filter() {
        let mut info = JdiBreakpointInfo::from_breakpoint(req(1));
        info.set_object_filter(Some(ObjectReference(99)));
        info.set_object_filter(None);
        assert!(info.get_object_filter().is_none());
    }

    #[test]
    fn thread_filter_initially_none() {
        let info = JdiBreakpointInfo::from_breakpoint(req(1));
        assert!(info.get_thread_filter().is_none());
    }

    #[test]
    fn set_thread_filter() {
        let mut info = JdiBreakpointInfo::from_breakpoint(req(1));
        info.set_thread_filter(Some(ThreadReference(7)));
        assert_eq!(info.get_thread_filter(), Some(ThreadReference(7)));
    }

    #[test]
    fn class_filter_initially_none() {
        let info = JdiBreakpointInfo::from_breakpoint(req(1));
        assert!(info.get_class_filter().is_none());
    }

    #[test]
    fn set_class_filter() {
        let mut info = JdiBreakpointInfo::from_breakpoint(req(1));
        info.set_class_filter(Some(ReferenceType(5)));
        assert_eq!(info.get_class_filter(), Some(ReferenceType(5)));
    }

    #[test]
    fn filter_pattern_initially_none() {
        let info = JdiBreakpointInfo::from_breakpoint(req(1));
        assert!(info.get_filter_pattern().is_none());
    }

    #[test]
    fn set_filter_pattern() {
        let mut info = JdiBreakpointInfo::from_breakpoint(req(1));
        info.set_filter_pattern(Some("com.example.*".to_string()));
        assert_eq!(info.get_filter_pattern(), Some("com.example.*"));
    }

    #[test]
    fn clear_filter_pattern() {
        let mut info = JdiBreakpointInfo::from_breakpoint(req(1));
        info.set_filter_pattern(Some("com.example.*".to_string()));
        info.set_filter_pattern(None);
        assert!(info.get_filter_pattern().is_none());
    }

    #[test]
    fn equality_based_on_request() {
        let a = JdiBreakpointInfo::from_breakpoint(req(10));
        let b = JdiBreakpointInfo::from_breakpoint(req(10));
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_requests() {
        let a = JdiBreakpointInfo::from_breakpoint(req(1));
        let b = JdiBreakpointInfo::from_breakpoint(req(2));
        assert_ne!(a, b);
    }

    #[test]
    fn equality_ignores_enabled_state() {
        let mut a = JdiBreakpointInfo::from_breakpoint(req(10));
        let b = JdiBreakpointInfo::from_breakpoint(req(10));
        a.set_enabled(true);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_consistent_with_equality() {
        let mut set = HashSet::new();
        set.insert(JdiBreakpointInfo::from_breakpoint(req(1)));
        set.insert(JdiBreakpointInfo::from_breakpoint(req(1)));
        set.insert(JdiBreakpointInfo::from_breakpoint(req(2)));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn display_shows_request() {
        let info = JdiBreakpointInfo::from_breakpoint(req(5));
        assert!(format!("{info}").contains("5"));
    }

    #[test]
    fn debug_includes_request_and_type() {
        let info = JdiBreakpointInfo::from_breakpoint(req(3));
        let s = format!("{info:?}");
        assert!(s.contains("JdiBreakpointInfo"));
        assert!(s.contains("Breakpoint"));
    }
}
