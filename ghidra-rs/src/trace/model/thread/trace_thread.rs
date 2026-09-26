//! A thread in a trace.
//!
//! Port of `ghidra.trace.model.thread.TraceThread`.
//!
//! Java's `setName(Lifespan, String)`/`setName(long, String)` overloads are given distinct names,
//! mirroring the convention used for
//! [`TraceModule`](crate::trace::model::modules::trace_module::TraceModule): the lifespan form
//! keeps the base name ([`TraceThread::set_name`]), while the single-snap form gets an `_at`
//! suffix ([`TraceThread::set_name_at`]).
//!
//! This object must be associated with a suitable
//! [`TraceExecutionStateful`](crate::trace::model::target::iface::trace_execution_stateful::TraceExecutionStateful).
//! In most cases, the object should just implement it.

use crate::program::model::lang::register::RegisterRef;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::iface::trace_object_interface::{KEY_COMMENT, KEY_DISPLAY};
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_unique_object::TraceUniqueObject;

/// The object attribute key that gives the TID, as assigned by the target's platform.
///
/// Mirrors `ghidra.trace.model.thread.TraceThread.KEY_TID`.
pub const KEY_TID: &str = "_tid";

/// A thread in a trace.
pub trait TraceThread: TraceUniqueObject + TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceThread`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new("Thread", "thread", [KEY_TID], [KEY_DISPLAY, KEY_COMMENT])
    }

    /// Get the trace containing this thread.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get a key identifying this thread, unique among all threads in this trace for all time.
    fn get_key(&self) -> i64;

    /// Get the "full name" of this thread.
    fn get_path(&self) -> String;

    /// Get the "short name" of this thread.
    fn get_name(&self, snap: i64) -> String;

    /// Set the "short name" of this thread across the given span of time.
    fn set_name(&mut self, lifespan: Lifespan, name: &str);

    /// Set the "short name" of this thread from the given snap on.
    ///
    /// See [`Self::set_name`].
    fn set_name_at(&mut self, snap: i64, name: &str);

    /// Set a comment on this thread.
    fn set_comment(&mut self, snap: i64, comment: Option<&str>);

    /// Get the comment on this thread.
    fn get_comment(&self, snap: i64) -> Option<String>;

    /// A convenience to obtain the registers from the containing trace's base language.
    fn get_registers(&self) -> Vec<RegisterRef> {
        self.get_trace().get_base_language().get_registers()
    }

    /// Delete this thread from the trace.
    fn delete(&mut self);

    /// Remove this thread from the given snapshot on.
    fn remove(&mut self, snap: i64);

    /// Check if the thread is valid at the given snapshot.
    ///
    /// In object mode, a thread's life may be disjoint, so checking if the snap occurs between
    /// creation and destruction is not quite sufficient. This method encapsulates validity. In
    /// object mode, it checks that the thread object has a canonical parent at the given
    /// snapshot. In table mode, it checks that the lifespan contains the snap.
    fn is_valid(&self, snap: i64) -> bool;

    /// Check if the thread is alive for any of the given span.
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

    /// A minimal in-memory thread backing a path, a name, and a comment, used to prove the
    /// trait is object-safe and that `isValid`/`isAlive` behave per Java's contract of comparing
    /// against the thread's own lifespan.
    struct MockThread {
        path: String,
        name: Mutex<String>,
        comment: Mutex<Option<String>>,
        lifespan: Lifespan,
        deleted: bool,
    }

    impl TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }
    }

    impl TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }

    impl TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_key(&self) -> i64 {
            1
        }

        fn get_path(&self) -> String {
            self.path.clone()
        }

        fn get_name(&self, _snap: i64) -> String {
            self.name.lock().unwrap().clone()
        }

        fn set_name(&mut self, _lifespan: Lifespan, name: &str) {
            *self.name.lock().unwrap() = name.to_string();
        }

        fn set_name_at(&mut self, _snap: i64, name: &str) {
            *self.name.lock().unwrap() = name.to_string();
        }

        fn set_comment(&mut self, _snap: i64, comment: Option<&str>) {
            *self.comment.lock().unwrap() = comment.map(|c| c.to_string());
        }

        fn get_comment(&self, _snap: i64) -> Option<String> {
            self.comment.lock().unwrap().clone()
        }

        fn delete(&mut self) {}

        fn remove(&mut self, _snap: i64) {}

        fn is_valid(&self, snap: i64) -> bool {
            match self.lifespan {
                Lifespan::Empty => false,
                Lifespan::Span { min, max } => min <= snap && snap <= max,
            }
        }

        fn is_alive(&self, span: Lifespan) -> bool {
            match (self.lifespan, span) {
                (Lifespan::Span { min: a_min, max: a_max }, Lifespan::Span { min: b_min, max: b_max }) => {
                    a_min <= b_max && b_min <= a_max
                }
                _ => false,
            }
        }
    }

    fn make_thread(path: &str, min: i64, max: i64) -> MockThread {
        MockThread {
            path: path.to_string(),
            name: Mutex::new(path.to_string()),
            comment: Mutex::new(None),
            lifespan: Lifespan::span(min, max),
            deleted: false,
        }
    }

    #[test]
    fn set_name_updates_short_name() {
        let mut t = make_thread("Threads[0]", 0, 10);
        assert_eq!(t.get_name(0), "Threads[0]");
        t.set_name_at(0, "main");
        assert_eq!(t.get_name(0), "main");
    }

    #[test]
    fn set_comment_and_get_comment_roundtrip() {
        let mut t = make_thread("Threads[0]", 0, 10);
        assert_eq!(t.get_comment(0), None);
        t.set_comment(0, Some("hello"));
        assert_eq!(t.get_comment(0), Some("hello".to_string()));
        t.set_comment(0, None);
        assert_eq!(t.get_comment(0), None);
    }

    #[test]
    fn is_valid_reflects_lifespan_containment() {
        let t = make_thread("Threads[0]", 5, 15);
        assert!(!t.is_valid(4));
        assert!(t.is_valid(5));
        assert!(t.is_valid(15));
        assert!(!t.is_valid(16));
    }

    #[test]
    fn is_alive_reflects_span_intersection() {
        let t = make_thread("Threads[0]", 5, 15);
        assert!(t.is_alive(Lifespan::span(10, 20)));
        assert!(!t.is_alive(Lifespan::span(16, 20)));
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = <MockThread as TraceThread>::trace_object_info();
        assert_eq!(info.schema_name, "Thread");
        assert_eq!(info.short_name, "thread");
        assert_eq!(info.attributes, vec![KEY_TID.to_string()]);
        assert_eq!(info.fixed_keys, vec![KEY_DISPLAY.to_string(), KEY_COMMENT.to_string()]);
    }

    #[test]
    fn trait_object_is_object_safe() {
        let t = make_thread("Threads[0]", 0, 10);
        let obj: &dyn TraceThread = &t;
        assert_eq!(obj.get_path(), "Threads[0]");
        assert!(obj.is_valid(0));
    }
}
