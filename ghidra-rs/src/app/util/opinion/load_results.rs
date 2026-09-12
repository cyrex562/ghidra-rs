//! Port of `ghidra.app.util.opinion.LoadResults`.
//!
//! The result of a [`Loader::load`](crate::app::util::opinion::loader::Loader::load): a
//! non-empty ordered collection of [`Loaded`] domain objects, with convenient access to the
//! "primary" one and bulk operations (`save`, `close`, ...) over all of them.
//!
//! A lightweight placeholder trait of the same name already exists at
//! [`crate::app::seam_stubs::LoadResultsLike`], used opaquely by
//! [`Loader`](crate::app::util::opinion::loader::Loader) and
//! [`load_spec_chooser`](crate::app::util::importer::load_spec_chooser) before this real class
//! was ported. This module ports the real Java class independently, following the same
//! "independent, full-fidelity type coexists with an existing opaque placeholder" precedent
//! [`QueryResult`](crate::app::util::opinion::query_result) and
//! [`LanguageCompilerSpecPair`](crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair)
//! already set; rewiring `Loader`'s existing `LoadResultsLike` call sites to this concrete type
//! is a separate, larger refactor and out of scope here.
//!
//! Java's `LoadResults<T extends DomainObject>` generic parameter is dropped in favor of `dyn
//! Loaded` uniformly, the same simplification [`Loaded`] itself already made for `dyn
//! DomainObject` (see that module's docs).
//!
//! `Iterable<Loaded<T>>` becomes [`IntoIterator`] for `&LoadResults`, yielding `&dyn Loaded`.
//! `AutoCloseable` becomes an explicit [`LoadResults::close`] plus a [`Drop`] impl that calls it,
//! mirroring the `close()`-plus-`Drop` pattern already established for
//! [`Transaction`](crate::framework::db::transaction::Transaction) in this crate; `close()` stays
//! idempotent so calling it explicitly and then dropping (or dropping twice via `mem::drop`) is
//! safe, matching Java's `Loaded::close()`/`DomainObject::release()` idempotence.
//!
//! Both deprecated no-arg/unsafe methods (`getPrimaryDomainObject()`, `release(Object)`,
//! `release(Object, Predicate)`, `releaseNonPrimary(Object)`) are ported as-is (marked
//! `#[deprecated]`, same as their `Loaded` counterparts) rather than dropped, since Java keeps
//! them for backwards compatibility and callers of this port may still need them during a
//! migration.

use crate::app::util::opinion::loaded::{Loaded, SaveError};
use crate::framework::model::{DomainObject, DomainObjectConsumer};
use crate::util::task::TaskMonitor;

/// The result of a [`Loader::load`](crate::app::util::opinion::loader::Loader::load). Provides
/// convenient access to and operations on the underlying [`Loaded`] domain objects that got
/// loaded.
///
/// Port of `ghidra.app.util.opinion.LoadResults`.
pub struct LoadResults {
    loaded_list: Vec<Box<dyn Loaded>>,
}

impl LoadResults {
    /// Creates a new [`LoadResults`] that contains the given non-empty list of [`Loaded`] domain
    /// objects. The first entry in the list is assumed to be the
    /// [`primary`](LoadResults::get_primary) one.
    ///
    /// Port of `LoadResults(List<Loaded<T>>)`.
    ///
    /// # Panics
    /// Panics if `loaded_list` is empty, mirroring Java's `IllegalArgumentException` (an
    /// unchecked exception, so a Rust panic is the faithful analogue; see the identical
    /// precedent in
    /// [`LanguageCompilerSpecPair::new`](crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair::new)).
    /// Java also null-checks the list; that has no port since a `Vec` cannot be null.
    pub fn new(loaded_list: Vec<Box<dyn Loaded>>) -> Self {
        assert!(!loaded_list.is_empty(), "The loaded list must not be empty");
        LoadResults { loaded_list }
    }

    /// Creates a new [`LoadResults`] that contains the given single [`Loaded`] domain object,
    /// which is assumed to be the [`primary`](LoadResults::get_primary) one.
    ///
    /// Port of `LoadResults(Loaded<T>)`.
    pub fn single(loaded: Box<dyn Loaded>) -> Self {
        LoadResults::new(vec![loaded])
    }

    /// Gets the "primary" [`Loaded`] domain object, whose meaning is defined by each `Loader`
    /// implementation.
    ///
    /// Port of `LoadResults.getPrimary()`.
    pub fn get_primary(&self) -> &dyn Loaded {
        self.loaded_list[0].as_ref()
    }

    /// Mutable access to the "primary" [`Loaded`] domain object.
    ///
    /// Not present in Java (whose `getPrimary()` returns a mutable reference by default, since
    /// Java has no separate mutable/immutable borrow distinction); added so callers of this port
    /// can still mutate the primary `Loaded` (e.g. to `save` or `close` it individually) without
    /// needing unsafe interior mutability.
    pub fn get_primary_mut(&mut self) -> &mut dyn Loaded {
        self.loaded_list[0].as_mut()
    }

    /// Gets the "non-primary" [`Loaded`] domain objects, whose meaning is defined by each
    /// `Loader` implementation.
    ///
    /// Port of `LoadResults.getNonPrimary()`.
    pub fn get_non_primary(&self) -> Vec<&dyn Loaded> {
        self.loaded_list.iter().skip(1).map(|l| l.as_ref()).collect()
    }

    /// Gets the "primary" domain object, whose meaning is defined by each `Loader`
    /// implementation.
    ///
    /// NOTE: It is the responsibility of the caller to properly release it (via the returned
    /// domain object's own release mechanism) when done. Releasing it does not replace the
    /// requirement to [`close`](LoadResults::close) this [`LoadResults`] when done.
    ///
    /// Port of `LoadResults.getPrimaryDomainObject(Object)`.
    pub fn get_primary_domain_object(&mut self, consumer: DomainObjectConsumer) -> &mut dyn DomainObject {
        self.loaded_list[0].get_domain_object(consumer)
    }

    /// Gets the "primary" loaded domain object, whose meaning is defined by each `Loader`
    /// implementation. Unsafe resource management is used. Temporarily exists to provide
    /// backwards compatibility.
    ///
    /// Port of the deprecated no-arg `LoadResults.getPrimaryDomainObject()`.
    #[deprecated(note = "This class's internal domain objects are now cleaned up with the \
                          close() method. If the primary domain object needs to be retrieved \
                          from this class, instead use get_primary_domain_object() and \
                          independently clean up the new reference separately.")]
    pub fn get_primary_domain_object_unsafe(&self) -> &dyn DomainObject {
        #[allow(deprecated)]
        self.loaded_list[0].get_domain_object_unsafe()
    }

    /// Gets the number of [`Loaded`] domain objects in this [`LoadResults`]. Always greater
    /// than 0.
    ///
    /// Port of `LoadResults.size()`.
    pub fn size(&self) -> usize {
        self.loaded_list.len()
    }

    /// [`Loaded::save`]s each [`Loaded`] domain object to its project.
    ///
    /// Port of `LoadResults.save(TaskMonitor)`.
    ///
    /// # Errors
    /// Returns `Err` if the operation was cancelled, or an IO/naming error occurred. A returned
    /// error may mean only some of the [`Loaded`] elements got saved; it is the responsibility of
    /// the caller to clean things up appropriately, exactly as documented on the Java method.
    pub fn save(&mut self, monitor: &dyn TaskMonitor) -> Result<(), SaveError> {
        for loaded in &mut self.loaded_list {
            loaded.save(monitor)?;
        }
        Ok(())
    }

    /// Unsafely notifies all of the [`Loaded`] domain objects that the specified consumer is no
    /// longer using them. Temporarily exists to provide backwards compatibility.
    ///
    /// Port of `LoadResults.release(Object)`.
    #[deprecated(note = "use close() instead")]
    pub fn release(&mut self, consumer: DomainObjectConsumer) {
        for loaded in &mut self.loaded_list {
            #[allow(deprecated)]
            loaded.release(consumer.clone());
        }
    }

    /// Unsafely notifies the filtered [`Loaded`] domain objects that the specified consumer is no
    /// longer using them. Temporarily exists to provide backwards compatibility.
    ///
    /// Port of `LoadResults.release(Object, Predicate)`. Renamed from the overloaded Java
    /// `release` since Rust has no method overloading.
    #[deprecated(note = "use close() instead")]
    pub fn release_filtered(&mut self, consumer: DomainObjectConsumer, filter: &dyn Fn(&dyn Loaded) -> bool) {
        for loaded in self.loaded_list.iter_mut().filter(|l| filter(l.as_ref())) {
            #[allow(deprecated)]
            loaded.release(consumer.clone());
        }
    }

    /// Notifies the non-primary [`Loaded`] domain objects that the specified consumer is no
    /// longer using them. When the last consumer invokes this method, the non-primary [`Loaded`]
    /// domain objects will be closed and will become invalid.
    ///
    /// Port of `LoadResults.releaseNonPrimary(Object)`.
    #[deprecated(note = "use get_non_primary() and Loaded::close() on the elements instead")]
    pub fn release_non_primary(&mut self, consumer: DomainObjectConsumer) {
        for (i, loaded) in self.loaded_list.iter_mut().enumerate() {
            if i > 0 {
                #[allow(deprecated)]
                loaded.release(consumer.clone());
            }
        }
    }

    /// Closes this [`LoadResults`] and releases the reference on the object consuming it.
    ///
    /// NOTE: Any domain objects obtained via
    /// [`get_primary_domain_object`](LoadResults::get_primary_domain_object) must still be
    /// explicitly released after calling this method, since they were obtained with their own
    /// consumers.
    ///
    /// Port of `LoadResults.close()`. Idempotent (delegates to [`Loaded::close`], which is itself
    /// idempotent), so it is safe to call this both explicitly and implicitly via [`Drop`].
    pub fn close(&mut self) {
        for loaded in &mut self.loaded_list {
            loaded.close();
        }
    }

    /// Returns an iterator over the [`Loaded`] domain objects, in order (primary first).
    ///
    /// Backs the [`IntoIterator`] impl for `&LoadResults`, standing in for Java's
    /// `Iterable<Loaded<T>>.iterator()`.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Loaded> + '_ {
        self.loaded_list.iter().map(|l| l.as_ref())
    }
}

impl Drop for LoadResults {
    /// Calls [`LoadResults::close`] automatically, mirroring Java's `AutoCloseable` plus
    /// try-with-resources.
    fn drop(&mut self) {
        self.close();
    }
}

impl<'a> IntoIterator for &'a LoadResults {
    type Item = &'a dyn Loaded;
    type IntoIter = std::iter::Map<std::slice::Iter<'a, Box<dyn Loaded>>, fn(&'a Box<dyn Loaded>) -> &'a dyn Loaded>;

    /// Port of `LoadResults.iterator()`.
    fn into_iter(self) -> Self::IntoIter {
        self.loaded_list.iter().map(|l| l.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::cell::Cell;
    use std::io;
    use std::rc::Rc;
    use std::sync::Arc;

    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::framework::model::{DomainFile, Project};
    use crate::util::task::DummyMonitor;

    // -- Mock DomainObject with real consumer bookkeeping ---------------------------------

    struct MockDomainObject {
        name: String,
        consumers: Vec<DomainObjectConsumer>,
        closed: bool,
    }

    impl MockDomainObject {
        fn new(name: &str) -> Self {
            Self { name: name.to_string(), consumers: Vec::new(), closed: false }
        }
    }

    impl DomainObject for MockDomainObject {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn is_closed(&self) -> bool {
            self.closed
        }

        fn add_consumer(&mut self, consumer: DomainObjectConsumer) -> bool {
            if self.closed {
                return false;
            }
            self.consumers.push(consumer);
            true
        }

        fn is_used_by(&self, consumer: &DomainObjectConsumer) -> bool {
            self.consumers.iter().any(|c| Arc::ptr_eq(c, consumer))
        }

        fn release(&mut self, consumer: DomainObjectConsumer) {
            self.consumers.retain(|c| !Arc::ptr_eq(c, &consumer));
            if self.consumers.is_empty() {
                self.closed = true;
            }
        }
    }

    // -- Minimal MockLoaded: no save()/mirror() exercise needed here (that machinery is fully
    // tested in `loaded.rs`); these tests focus on LoadResults' own aggregation logic. ----------

    struct MockLoaded {
        domain_object: MockDomainObject,
        name: String,
        loaded_consumer: Option<DomainObjectConsumer>,
        save_calls: Rc<Cell<usize>>,
    }

    impl MockLoaded {
        fn new(name: &str, consumer: DomainObjectConsumer) -> Self {
            Self::with_save_counter(name, consumer, Rc::new(Cell::new(0)))
        }

        fn with_save_counter(name: &str, consumer: DomainObjectConsumer, save_calls: Rc<Cell<usize>>) -> Self {
            let mut domain_object = MockDomainObject::new(name);
            domain_object.add_consumer(consumer.clone());
            Self { domain_object, name: name.to_string(), loaded_consumer: Some(consumer), save_calls }
        }
    }

    impl Loaded for MockLoaded {
        fn domain_object(&self) -> &dyn DomainObject {
            &self.domain_object
        }

        fn domain_object_mut(&mut self) -> &mut dyn DomainObject {
            &mut self.domain_object
        }

        fn domain_object_type(&self) -> TypeId {
            TypeId::of::<MockDomainObject>()
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn fsrl(&self) -> Option<&dyn Fsrl> {
            None
        }

        fn get_project(&self) -> Option<&dyn Project> {
            None
        }

        fn get_project_folder_path(&self) -> &str {
            "/"
        }

        fn store_project_folder_path(&mut self, _project_root_path: String) {}

        fn mirror_fs_layout(&self) -> bool {
            false
        }

        fn loaded_consumer(&self) -> Option<&DomainObjectConsumer> {
            self.loaded_consumer.as_ref()
        }

        fn saved_domain_file(&self) -> Option<&dyn DomainFile> {
            None
        }

        fn store_saved_domain_file(&mut self, _domain_file: Option<Box<dyn DomainFile>>) {}

        fn mirror(
            &mut self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn DomainFile>, SaveError> {
            unimplemented!("not exercised by LoadResults tests")
        }

        // Override `save` directly (rather than relying on the default impl, which needs a real
        // `Project`) so these tests can focus purely on LoadResults aggregating calls/errors
        // across its list, which is already independently proven for a single `Loaded` in
        // `loaded.rs`'s own test suite.
        fn save(&mut self, _monitor: &dyn TaskMonitor) -> Result<&dyn DomainFile, SaveError> {
            self.save_calls.set(self.save_calls.get() + 1);
            Err(SaveError::Io(io::Error::new(io::ErrorKind::Other, "no project configured in mock")))
        }
    }

    fn consumer() -> DomainObjectConsumer {
        Arc::new(42i32)
    }

    fn mock_loaded(name: &str, consumer: DomainObjectConsumer) -> Box<dyn Loaded> {
        Box::new(MockLoaded::new(name, consumer))
    }

    #[test]
    #[should_panic(expected = "The loaded list must not be empty")]
    fn new_panics_on_empty_list() {
        let empty: Vec<Box<dyn Loaded>> = Vec::new();
        LoadResults::new(empty);
    }

    #[test]
    fn new_panic_message_matches_exactly() {
        // Verify the panic happens at the exact call, not merely somewhere in a larger test, per
        // this crate's testing policy for #[should_panic] claims.
        let result = std::panic::catch_unwind(|| {
            let empty: Vec<Box<dyn Loaded>> = Vec::new();
            LoadResults::new(empty);
        });
        let err = result.expect_err("expected LoadResults::new to panic on an empty list");
        let message = err.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| err.downcast_ref::<String>().cloned());
        assert_eq!(message, Some("The loaded list must not be empty".to_string()));
    }

    #[test]
    fn single_constructor_wraps_one_loaded_as_primary() {
        let results = LoadResults::single(mock_loaded("a.bin", consumer()));
        assert_eq!(results.size(), 1);
        assert_eq!(results.get_primary().get_name(), "a.bin");
        assert!(results.get_non_primary().is_empty());
    }

    #[test]
    fn get_primary_is_first_element_and_non_primary_is_the_rest() {
        let results = LoadResults::new(vec![
            mock_loaded("first.bin", consumer()),
            mock_loaded("second.bin", consumer()),
            mock_loaded("third.bin", consumer()),
        ]);

        assert_eq!(results.size(), 3);
        assert_eq!(results.get_primary().get_name(), "first.bin");

        let non_primary = results.get_non_primary();
        assert_eq!(non_primary.len(), 2);
        assert_eq!(non_primary[0].get_name(), "second.bin");
        assert_eq!(non_primary[1].get_name(), "third.bin");
    }

    #[test]
    fn get_primary_domain_object_registers_consumer() {
        let mut results = LoadResults::single(mock_loaded("a.bin", consumer()));
        let fetch_consumer: DomainObjectConsumer = Arc::new(7i32);
        let domain_object = results.get_primary_domain_object(fetch_consumer.clone());
        assert!(domain_object.is_used_by(&fetch_consumer));
    }

    #[test]
    fn iteration_visits_every_loaded_in_order() {
        let results = LoadResults::new(vec![
            mock_loaded("first.bin", consumer()),
            mock_loaded("second.bin", consumer()),
        ]);

        let names: Vec<String> = (&results).into_iter().map(|l| l.get_name()).collect();
        assert_eq!(names, vec!["first.bin".to_string(), "second.bin".to_string()]);
    }

    #[test]
    fn save_propagates_first_error_and_stops() {
        let first_calls = Rc::new(Cell::new(0));
        let second_calls = Rc::new(Cell::new(0));
        let mut results = LoadResults::new(vec![
            Box::new(MockLoaded::with_save_counter("first.bin", consumer(), first_calls.clone())),
            Box::new(MockLoaded::with_save_counter("second.bin", consumer(), second_calls.clone())),
        ]);

        let monitor = DummyMonitor;
        let err = results.save(&monitor).expect_err("mock always fails to save");
        assert!(matches!(err, SaveError::Io(_)));

        // Mirrors `LoadResults.save`'s plain `for` loop over the list: the first element's error
        // propagates immediately via `?`, so the second element's save() is never reached.
        assert_eq!(first_calls.get(), 1);
        assert_eq!(second_calls.get(), 0);
    }

    #[test]
    fn close_releases_every_loaded_domain_object() {
        let owner_a = consumer();
        let owner_b = consumer();
        let mut results =
            LoadResults::new(vec![mock_loaded("a.bin", owner_a.clone()), mock_loaded("b.bin", owner_b.clone())]);

        results.close();

        assert!(results.get_primary().domain_object().is_closed());
        assert!(results.get_non_primary()[0].domain_object().is_closed());
    }

    #[test]
    fn close_is_idempotent() {
        let mut results = LoadResults::single(mock_loaded("a.bin", consumer()));
        results.close();
        // Calling close() a second time must not panic (mirrors Loaded::close's own
        // is_closed()/is_used_by() guards).
        results.close();
        assert!(results.get_primary().domain_object().is_closed());
    }

    #[test]
    fn drop_closes_automatically() {
        let owner = consumer();
        // `LoadResults` hides its internal list, so the only way to observe that `Drop` called
        // `close()` is to record it from inside a `Loaded::close()` override, via a side channel
        // (`flag`) that outlives the dropped `LoadResults`.
        struct FlaggedLoaded {
            inner: MockLoaded,
            flag: Arc<std::sync::atomic::AtomicBool>,
        }
        impl Loaded for FlaggedLoaded {
            fn domain_object(&self) -> &dyn DomainObject {
                self.inner.domain_object()
            }
            fn domain_object_mut(&mut self) -> &mut dyn DomainObject {
                self.inner.domain_object_mut()
            }
            fn domain_object_type(&self) -> TypeId {
                self.inner.domain_object_type()
            }
            fn get_name(&self) -> String {
                self.inner.get_name()
            }
            fn fsrl(&self) -> Option<&dyn Fsrl> {
                self.inner.fsrl()
            }
            fn get_project(&self) -> Option<&dyn Project> {
                self.inner.get_project()
            }
            fn get_project_folder_path(&self) -> &str {
                self.inner.get_project_folder_path()
            }
            fn store_project_folder_path(&mut self, p: String) {
                self.inner.store_project_folder_path(p)
            }
            fn mirror_fs_layout(&self) -> bool {
                self.inner.mirror_fs_layout()
            }
            fn loaded_consumer(&self) -> Option<&DomainObjectConsumer> {
                self.inner.loaded_consumer()
            }
            fn saved_domain_file(&self) -> Option<&dyn DomainFile> {
                self.inner.saved_domain_file()
            }
            fn store_saved_domain_file(&mut self, f: Option<Box<dyn DomainFile>>) {
                self.inner.store_saved_domain_file(f)
            }
            fn mirror(&mut self, m: &dyn TaskMonitor) -> Result<Box<dyn DomainFile>, SaveError> {
                self.inner.mirror(m)
            }
            fn close(&mut self) {
                self.inner.close();
                self.flag.store(self.inner.domain_object().is_closed(), std::sync::atomic::Ordering::SeqCst);
            }
        }

        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let loaded: Box<dyn Loaded> =
                Box::new(FlaggedLoaded { inner: MockLoaded::new("a.bin", owner), flag: flag.clone() });
            let _results = LoadResults::single(loaded);
            assert!(!flag.load(std::sync::atomic::Ordering::SeqCst));
        }
        // `_results` (and the `Loaded` it owns) has now dropped; Drop::drop should have called
        // close(), which our FlaggedLoaded::close() records into `flag`.
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    #[allow(deprecated)]
    fn get_primary_domain_object_unsafe_returns_domain_object() {
        let results = LoadResults::single(mock_loaded("a.bin", consumer()));
        assert_eq!(results.get_primary_domain_object_unsafe().get_name(), "a.bin");
    }

    #[test]
    #[allow(deprecated)]
    fn release_only_affects_registered_consumer() {
        let owner = consumer();
        let mut results = LoadResults::single(mock_loaded("a.bin", owner.clone()));

        let other: DomainObjectConsumer = Arc::new(99i32);
        results.get_primary_domain_object(other.clone());

        results.release(other.clone());
        assert!(!results.get_primary().domain_object().is_closed());
        assert!(!results.get_primary().domain_object().is_used_by(&other));
    }

    #[test]
    #[allow(deprecated)]
    fn release_non_primary_leaves_primary_untouched() {
        let primary_owner = consumer();
        let non_primary_owner = consumer();
        let mut results = LoadResults::new(vec![
            mock_loaded("first.bin", primary_owner.clone()),
            mock_loaded("second.bin", non_primary_owner.clone()),
        ]);

        results.release_non_primary(non_primary_owner);

        assert!(!results.get_primary().domain_object().is_closed());
        assert!(results.get_non_primary()[0].domain_object().is_closed());
    }

    #[test]
    #[allow(deprecated)]
    fn release_filtered_only_releases_matching_entries() {
        let owner_a = consumer();
        let owner_b = consumer();
        let mut results =
            LoadResults::new(vec![mock_loaded("keep.bin", owner_a.clone()), mock_loaded("drop.bin", owner_b.clone())]);

        results.release_filtered(owner_b, &|l| l.get_name() == "drop.bin");

        assert!(!results.get_primary().domain_object().is_closed());
        assert!(results.get_non_primary()[0].domain_object().is_closed());
    }
}
