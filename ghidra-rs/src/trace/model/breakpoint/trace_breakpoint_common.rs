//! Behavior common to both trace breakpoint specifications and locations.
//!
//! Port of `ghidra.trace.model.breakpoint.TraceBreakpointCommon`.
//!
//! Java's `setName(Lifespan, String)`/`setName(long, String)`, `setEnabled(Lifespan,
//! boolean)`/`setEnabled(long, boolean)`, and `setComment(Lifespan, String)`/`setComment(long,
//! String)` overload pairs are given distinct names, following the convention used throughout
//! this module (e.g. [`TraceBreakpointSpec::set_kinds`](crate::trace::model::breakpoint::trace_breakpoint_spec::TraceBreakpointSpec::set_kinds)):
//! the lifespan form keeps the base name, while the single-snap form gets an `_at` suffix.

use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_unique_object::TraceUniqueObject;

/// Behavior common to both trace breakpoint specifications and locations.
pub trait TraceBreakpointCommon: TraceUniqueObject + TraceObjectInterface {
    /// Get the trace containing this breakpoint.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the "full name" of this breakpoint.
    ///
    /// This is a name unique to this breakpoint, which may not be suitable for display on the
    /// screen.
    fn get_path(&self) -> String;

    /// Set the "short name" of this breakpoint across the given span of time.
    ///
    /// This should be a name suitable for display on the screen.
    fn set_name(&mut self, lifespan: Lifespan, name: &str);

    /// Set the "short name" of this breakpoint from the given snap on.
    ///
    /// This should be a name suitable for display on the screen.
    fn set_name_at(&mut self, snap: i64, name: &str);

    /// Get the "short name" of this breakpoint.
    ///
    /// This defaults to the "full name," but can be modified via [`Self::set_name_at`].
    fn get_name(&self, snap: i64) -> String;

    /// Set whether this breakpoint was enabled or disabled across the given span of time.
    fn set_enabled(&mut self, lifespan: Lifespan, enabled: bool);

    /// Set whether this breakpoint was enabled or disabled from the given snap on.
    fn set_enabled_at(&mut self, snap: i64, enabled: bool);

    /// Check whether this breakpoint is enabled or disabled at the given snap.
    fn is_enabled(&self, snap: i64) -> bool;

    /// Set a comment on this breakpoint across the given span of time.
    fn set_comment(&mut self, lifespan: Lifespan, comment: Option<&str>);

    /// Set a comment on this breakpoint from the given snap on.
    fn set_comment_at(&mut self, snap: i64, comment: Option<&str>);

    /// Get the comment on this breakpoint.
    fn get_comment(&self, snap: i64) -> Option<String>;

    /// Remove this breakpoint from the given snap on.
    fn remove(&mut self, snap: i64);

    /// Delete this breakpoint from the trace.
    fn delete(&mut self);

    /// Check if the breakpoint is present at the given snapshot.
    ///
    /// In object mode, a breakpoint's life may be disjoint, so checking if the snap occurs
    /// between creation and destruction is not quite sufficient. This method encapsulates
    /// validity. In object mode, it checks that the breakpoint object has a canonical parent at
    /// the given snapshot. In table mode, it checks that the lifespan contains the snap.
    fn is_valid(&self, snap: i64) -> bool;

    /// Check if the breakpoint is present for any of the given span.
    fn is_alive(&self, span: Lifespan) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::seam_stubs::ObjectKey;
    use std::sync::Mutex;

    struct MockObjectKey(i32);

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>()
                .is_some_and(|other| other.0 == self.0)
        }

        fn hash_code(&self) -> i32 {
            self.0
        }

        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    /// A minimal in-memory breakpoint backing a single, unversioned name/enabled/comment triple,
    /// used to prove the trait is object-safe and behaves as expected.
    struct MockBreakpoint {
        path: String,
        name: Mutex<String>,
        enabled: Mutex<bool>,
        comment: Mutex<Option<String>>,
        lifespan: Mutex<Lifespan>,
        deleted: bool,
    }

    impl TraceUniqueObject for MockBreakpoint {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }
    }

    impl TraceObjectInterface for MockBreakpoint {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }

    impl TraceBreakpointCommon for MockBreakpoint {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_path(&self) -> String {
            self.path.clone()
        }

        fn set_name(&mut self, _lifespan: Lifespan, name: &str) {
            *self.name.lock().unwrap() = name.to_string();
        }

        fn set_name_at(&mut self, _snap: i64, name: &str) {
            *self.name.lock().unwrap() = name.to_string();
        }

        fn get_name(&self, _snap: i64) -> String {
            self.name.lock().unwrap().clone()
        }

        fn set_enabled(&mut self, _lifespan: Lifespan, enabled: bool) {
            *self.enabled.lock().unwrap() = enabled;
        }

        fn set_enabled_at(&mut self, _snap: i64, enabled: bool) {
            *self.enabled.lock().unwrap() = enabled;
        }

        fn is_enabled(&self, _snap: i64) -> bool {
            *self.enabled.lock().unwrap()
        }

        fn set_comment(&mut self, _lifespan: Lifespan, comment: Option<&str>) {
            *self.comment.lock().unwrap() = comment.map(str::to_string);
        }

        fn set_comment_at(&mut self, _snap: i64, comment: Option<&str>) {
            *self.comment.lock().unwrap() = comment.map(str::to_string);
        }

        fn get_comment(&self, _snap: i64) -> Option<String> {
            self.comment.lock().unwrap().clone()
        }

        fn remove(&mut self, snap: i64) {
            let mut lifespan = self.lifespan.lock().unwrap();
            *lifespan = lifespan.min_snap().map_or(Lifespan::EMPTY, |min| {
                if snap <= min {
                    Lifespan::EMPTY
                } else {
                    Lifespan::span(min, snap - 1)
                }
            });
        }

        fn delete(&mut self) {
            self.deleted = true;
        }

        fn is_valid(&self, snap: i64) -> bool {
            !self.deleted && self.lifespan.lock().unwrap().contains(snap)
        }

        fn is_alive(&self, span: Lifespan) -> bool {
            let lifespan = self.lifespan.lock().unwrap();
            !self.deleted
                && !lifespan.is_empty()
                && !span.is_empty()
                && lifespan.lmin() <= span.lmax()
                && span.lmin() <= lifespan.lmax()
        }
    }

    fn make_breakpoint() -> MockBreakpoint {
        MockBreakpoint {
            path: "Breakpoints[0]".to_string(),
            name: Mutex::new("bp0".to_string()),
            enabled: Mutex::new(true),
            comment: Mutex::new(None),
            lifespan: Mutex::new(Lifespan::span(0, 10)),
            deleted: false,
        }
    }

    #[test]
    fn set_and_get_name_roundtrip() {
        let mut bp = make_breakpoint();
        assert_eq!(bp.get_name(0), "bp0");
        bp.set_name_at(0, "renamed");
        assert_eq!(bp.get_name(0), "renamed");
    }

    #[test]
    fn set_and_check_enabled() {
        let mut bp = make_breakpoint();
        assert!(bp.is_enabled(0));
        bp.set_enabled_at(0, false);
        assert!(!bp.is_enabled(0));
    }

    #[test]
    fn set_and_get_comment_allows_none() {
        let mut bp = make_breakpoint();
        assert_eq!(bp.get_comment(0), None);
        bp.set_comment_at(0, Some("why"));
        assert_eq!(bp.get_comment(0), Some("why".to_string()));
        bp.set_comment_at(0, None);
        assert_eq!(bp.get_comment(0), None);
    }

    #[test]
    fn remove_truncates_lifespan_and_affects_validity() {
        let mut bp = make_breakpoint();
        assert!(bp.is_valid(10));
        bp.remove(5);
        assert!(bp.is_valid(4));
        assert!(!bp.is_valid(5));
        assert!(!bp.is_valid(10));
    }

    #[test]
    fn is_alive_checks_span_intersection() {
        let bp = make_breakpoint();
        assert!(bp.is_alive(Lifespan::span(8, 20)));
        assert!(!bp.is_alive(Lifespan::span(20, 30)));
    }

    #[test]
    fn delete_marks_invalid() {
        let mut bp = make_breakpoint();
        assert!(bp.is_valid(0));
        bp.delete();
        assert!(!bp.is_valid(0));
    }

    #[test]
    fn trait_object_is_object_safe() {
        let mut bp: Box<dyn TraceBreakpointCommon> = Box::new(make_breakpoint());
        assert!(bp.is_enabled(0));
        bp.set_enabled_at(0, false);
        assert!(!bp.is_enabled(0));
    }
}
