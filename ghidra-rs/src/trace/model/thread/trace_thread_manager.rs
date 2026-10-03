//! A store for observed threads over time in a trace.
//!
//! Port of `ghidra.trace.model.thread.TraceThreadManager`.
//!
//! Java's default `createThread(String, long)`/`createThread(String, String, long)` construct a
//! `Lifespan.nowOn(creationSnap)` and delegate to the [`Lifespan`]-taking `addThread` overloads.
//! This crate's [`Lifespan`] is a trait with no concrete, generically-constructible implementor
//! yet (unlike Java's sealed `Lifespan`, whose `nowOn` factory always produces a usable `Impl`),
//! so there is no way to build that span from just a `snap` inside a default method body. The
//! snap-taking overloads (`create_thread`, `create_thread_with_display`) are therefore required
//! methods here rather than defaults, following the precedent set by
//! [`TraceModuleManager::add_loaded_module`](crate::trace::model::modules::TraceModuleManager::add_loaded_module).

use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::thread::TraceThread;
use crate::util::exception::DuplicateNameException;

/// A store for observed threads over time in a trace.
///
/// Note that the methods returning collections of threads order them eldest first. "Eldest"
/// means lowest database key, which does not necessarily correlate to earliest creation snap.
pub trait TraceThreadManager {
    /// Add a thread with the given lifespan.
    ///
    /// # Arguments
    /// * `path` - the "full name" of the thread
    /// * `lifespan` - the lifespan of the thread
    ///
    /// # Errors
    /// Returns an error if a thread with the given full name already exists within an
    /// overlapping snap.
    fn add_thread(
        &mut self,
        path: &str,
        lifespan: Lifespan,
    ) -> Result<Box<dyn TraceThread>, DuplicateNameException>;

    /// Add a thread with the given lifespan and a short display name.
    ///
    /// # Arguments
    /// * `path` - the "full name" of the thread
    /// * `display` - the "short name" of the thread
    /// * `lifespan` - the lifespan of the thread
    ///
    /// # Errors
    /// Returns an error if a thread with the given full name already exists within an
    /// overlapping snap.
    fn add_thread_with_display(
        &mut self,
        path: &str,
        display: &str,
        lifespan: Lifespan,
    ) -> Result<Box<dyn TraceThread>, DuplicateNameException>;

    /// Add a thread with the given creation snap.
    ///
    /// Mirrors Java's default `createThread(String, long)`, which delegates to
    /// [`Self::add_thread`] with `Lifespan.nowOn(creationSnap)`. See the module-level docs for
    /// why this is a required rather than default method in this port.
    ///
    /// # Errors
    /// Returns an error if a thread with the given full name already exists within an
    /// overlapping snap.
    fn create_thread(
        &mut self,
        path: &str,
        creation_snap: i64,
    ) -> Result<Box<dyn TraceThread>, DuplicateNameException>;

    /// Add a thread with the given creation snap and a short display name.
    ///
    /// Mirrors Java's default `createThread(String, String, long)`. See
    /// [`Self::create_thread`] for why this is a required rather than default method here.
    ///
    /// # Errors
    /// Returns an error if a thread with the given full name already exists within an
    /// overlapping snap.
    fn create_thread_with_display(
        &mut self,
        path: &str,
        display: &str,
        creation_snap: i64,
    ) -> Result<Box<dyn TraceThread>, DuplicateNameException>;

    /// Get all threads, ordered eldest first.
    fn get_all_threads(&self) -> Vec<Box<dyn TraceThread>>;

    /// Get all threads with the given name, ordered eldest first.
    fn get_threads_by_path(&self, name: &str) -> Vec<Box<dyn TraceThread>>;

    /// Get the live thread at the given snap by the given path, or `None` if no thread matches.
    fn get_live_thread_by_path(&self, snap: i64, path: &str) -> Option<Box<dyn TraceThread>>;

    /// Get the thread with the given key, or `None` if no thread matches.
    fn get_thread(&self, key: i64) -> Option<Box<dyn TraceThread>>;

    /// Get live threads at the given snap, ordered eldest first.
    ///
    /// Note that a thread whose destruction was observed at the given snap is not considered
    /// alive, i.e., the upper end of the lifespan is treated as open.
    fn get_live_threads(&self, snap: i64) -> Vec<Box<dyn TraceThread>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;



    #[derive(Clone)]
    struct MockThread {
        key: i64,
        path: String,
        min: i64,
        max: i64,
    }

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl crate::trace::model::target::iface::TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_key(&self) -> i64 {
            self.key
        }
        fn get_path(&self) -> String {
            self.path.clone()
        }
        fn get_name(&self, _snap: i64) -> String {
            self.path.clone()
        }
        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {}
        fn set_name_at(&mut self, _snap: i64, _name: &str) {}
        fn set_comment(&mut self, _snap: i64, _comment: Option<&str>) {}
        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }
        fn delete(&mut self) {}
        fn remove(&mut self, _snap: i64) {}
        fn is_valid(&self, snap: i64) -> bool {
            self.min <= snap && snap < self.max
        }
        fn is_alive(&self, span: Lifespan) -> bool {
            self.min <= span.lmax() && span.lmin() < self.max
        }
    }

    /// A minimal in-memory manager holding threads keyed by path, used to prove
    /// `TraceThreadManager` is object-safe and that `add_thread`/lookup-by-path/lookup-live
    /// actually store and filter (not just return everything or nothing).
    #[derive(Default)]
    struct MockManager {
        threads: RefCell<Vec<MockThread>>,
        next_key: RefCell<i64>,
    }

    impl TraceThreadManager for MockManager {
        fn add_thread(
            &mut self,
            path: &str,
            lifespan: Lifespan,
        ) -> Result<Box<dyn TraceThread>, DuplicateNameException> {
            self.add_thread_with_display(path, path, lifespan)
        }

        fn add_thread_with_display(
            &mut self,
            path: &str,
            _display: &str,
            lifespan: Lifespan,
        ) -> Result<Box<dyn TraceThread>, DuplicateNameException> {
            if self
                .threads
                .borrow()
                .iter()
                .any(|t| t.path == path && t.max >= lifespan.lmin() && t.min <= lifespan.lmax())
            {
                return Err(DuplicateNameException::with_message(path));
            }
            let mut next_key = self.next_key.borrow_mut();
            let key = *next_key;
            *next_key += 1;
            let t = MockThread {
                key,
                path: path.to_string(),
                min: lifespan.lmin(),
                max: lifespan.lmax(),
            };
            self.threads.borrow_mut().push(t.clone());
            Ok(Box::new(t))
        }

        fn create_thread(
            &mut self,
            path: &str,
            creation_snap: i64,
        ) -> Result<Box<dyn TraceThread>, DuplicateNameException> {
            self.add_thread(path, Lifespan::span(creation_snap, i64::MAX))
        }

        fn create_thread_with_display(
            &mut self,
            path: &str,
            display: &str,
            creation_snap: i64,
        ) -> Result<Box<dyn TraceThread>, DuplicateNameException> {
            self.add_thread_with_display(
                path,
                display,
                Lifespan::span(creation_snap, i64::MAX),
            )
        }

        fn get_all_threads(&self) -> Vec<Box<dyn TraceThread>> {
            self.threads
                .borrow()
                .iter()
                .cloned()
                .map(|t| Box::new(t) as Box<dyn TraceThread>)
                .collect()
        }

        fn get_threads_by_path(&self, name: &str) -> Vec<Box<dyn TraceThread>> {
            self.threads
                .borrow()
                .iter()
                .filter(|t| t.path == name)
                .cloned()
                .map(|t| Box::new(t) as Box<dyn TraceThread>)
                .collect()
        }

        fn get_live_thread_by_path(&self, snap: i64, path: &str) -> Option<Box<dyn TraceThread>> {
            self.threads
                .borrow()
                .iter()
                .find(|t| t.path == path && t.min <= snap && snap < t.max)
                .cloned()
                .map(|t| Box::new(t) as Box<dyn TraceThread>)
        }

        fn get_thread(&self, key: i64) -> Option<Box<dyn TraceThread>> {
            self.threads
                .borrow()
                .iter()
                .find(|t| t.key == key)
                .cloned()
                .map(|t| Box::new(t) as Box<dyn TraceThread>)
        }

        fn get_live_threads(&self, snap: i64) -> Vec<Box<dyn TraceThread>> {
            self.threads
                .borrow()
                .iter()
                .filter(|t| t.min <= snap && snap < t.max)
                .cloned()
                .map(|t| Box::new(t) as Box<dyn TraceThread>)
                .collect()
        }
    }

    #[test]
    fn add_thread_rejects_duplicate_overlapping_path() {
        let mut mgr = MockManager::default();
        assert!(mgr
            .add_thread("Threads[0]", Lifespan::span(0, 10))
            .is_ok());
        let result = mgr.add_thread("Threads[0]", Lifespan::span(5, 15));
        match result {
            Ok(_) => panic!("expected duplicate-name error"),
            Err(err) => assert!(err.0.contains("Threads[0]")),
        }
    }

    #[test]
    fn create_thread_and_lookups_find_added_thread() {
        let mut mgr = MockManager::default();
        mgr.create_thread("Threads[1]", 5).unwrap();

        assert_eq!(mgr.get_all_threads().len(), 1);
        assert_eq!(mgr.get_threads_by_path("Threads[1]").len(), 1);
        assert!(mgr.get_threads_by_path("Threads[missing]").is_empty());

        assert!(mgr.get_live_thread_by_path(5, "Threads[1]").is_some());
        assert!(mgr.get_live_thread_by_path(4, "Threads[1]").is_none());

        assert_eq!(mgr.get_live_threads(5).len(), 1);
        assert!(mgr.get_live_threads(4).is_empty());

        // MockManager assigns keys starting at 0, so the thread just created has key 0.
        assert!(mgr.get_thread(0).is_some());
        assert!(mgr.get_thread(1).is_none());
    }

    #[test]
    fn trait_object_is_object_safe() {
        let mut mgr = MockManager::default();
        let ops: &mut dyn TraceThreadManager = &mut mgr;
        assert!(ops.create_thread("Threads[x]", 0).is_ok());
        assert_eq!(ops.get_all_threads().len(), 1);
    }
}
