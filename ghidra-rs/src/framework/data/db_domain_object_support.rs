use crate::framework::data::domain_object_adapter_db::DomainObjectAdapterDB;
use crate::framework::data::open_mode::OpenMode;
use crate::generic::depends::err::ServiceConstructionException;
use crate::generic::depends::DependentServiceResolver;
use crate::util::exception::{CancelledException, VersionException};
use crate::util::task::TaskMonitor;

/// Error returned by [`DBDomainObjectSupport::create_manager`].
///
/// Mirrors the `throws CancelledException, IOException` clause on
/// `DBDomainObjectSupport.createManager(String, ManagerSupplier)`. A thrown
/// `VersionException` is *not* represented here: Java catches it internally and folds
/// it into the pending `versionExc` field instead of propagating it, which this port
/// mirrors by returning `Ok(None)` in that case (see [`create_manager`](
/// DBDomainObjectSupport::create_manager)'s doc).
#[derive(Debug)]
pub enum CreateManagerError {
    Io(std::io::Error),
    Cancelled(CancelledException),
}

/// The checked exceptions a [`ManagerSupplier`]-style closure passed to
/// [`DBDomainObjectSupport::create_manager`] may fail with.
///
/// Mirrors the `throws IOException, VersionException, CancelledException` clause on
/// `DBDomainObjectSupport.ManagerSupplier<T>.create(OpenMode, TaskMonitor)`.
#[derive(Debug)]
pub enum ManagerSupplyError {
    Io(std::io::Error),
    Version(VersionException),
    Cancelled(CancelledException),
}

/// Error returned by [`DBDomainObjectSupport::init`].
///
/// Mirrors the `throws CancelledException, IOException, VersionException,
/// ServiceConstructionException` clause on `DBDomainObjectSupport.init()`. Java's
/// `catch (UnsatisfiedParameterException | UnsatisfiedFieldsException e)` branch (which
/// wraps either into an `AssertionError`) has no counterpart here: those two exception
/// types are only produced by `DependentServiceResolver.compile()`, which in this port's
/// explicit-registration design (see `generic::depends::dependent_service_resolver`) is a
/// step the caller performs *before* calling `init` (to build the `resolver` argument),
/// not something `init` itself can encounter.
#[derive(Debug)]
pub enum DBDomainObjectInitError {
    Version(VersionException),
    Cancelled(CancelledException),
    Io(std::io::Error),
    ServiceConstruction(ServiceConstructionException),
}

/// Shared support for database-backed [`DomainObjectAdapterDB`] implementations that
/// build their manager objects during construction and need a two-phase
/// construct-then-`init` lifecycle.
///
/// Port of `ghidra.framework.data.DBDomainObjectSupport`, an abstract class that extends
/// `DomainObjectAdapterDB` and adds `openMode`/`monitor`/`versionExc` state plus the
/// `init()` and `createManager()` methods used by concrete domain objects (e.g.
/// `ProgramDB`) to build their manager fields via dependency injection
/// (`generic.depends.DependentServiceResolver`).
///
/// Per this crate's composition-over-inheritance convention, this is a plain struct meant
/// to be held as a field by a concrete type that itself implements
/// [`DomainObjectAdapterDB`], rather than a trait extending it: unlike
/// `DomainObjectAdapterDB` (already ported as a trait, since its own contribution is
/// entirely default-bodied accessors), `DBDomainObjectSupport` carries real per-instance
/// state (`openMode`, `monitor`, `versionExc`) and Java's `super(dbh, name, timeInterval,
/// consumer)` call in its constructor exists solely to forward those parameters to
/// `DomainObjectAdapterDB`'s own constructor -- which has no Rust analogue since that
/// trait holds no fields of its own. Those parameters (`dbh`, `name`, `timeInterval`,
/// `consumer`) are therefore dropped from [`new`](Self::new): a concrete composing type
/// owns them directly as part of implementing [`DomainObjectAdapterDB`] itself.
///
/// Java's protected `DependentServiceResolver.inject(this)` call (a static, per-class
/// cached, reflection-driven resolver) is replaced here by an explicit `build_managers`
/// closure argument to [`init`](Self::init), which gets `&mut Self` (for
/// [`create_manager`](Self::create_manager)) and `&mut T` (for assigning constructed
/// managers to fields) together -- see [`init`](Self::init)'s own doc for why a bare
/// `&DependentServiceResolver<T>` argument alone can't play this role.
pub struct DBDomainObjectSupport {
    open_mode: OpenMode,
    monitor: Option<Box<dyn TaskMonitor>>,
    version_exc: Option<VersionException>,
}

impl DBDomainObjectSupport {
    /// Creates a new support object for a domain object being opened in `open_mode`,
    /// using `monitor` to report progress and cancellation while managers are created.
    ///
    /// Mirrors `DBDomainObjectSupport(DBHandle, OpenMode, TaskMonitor, String, int, int,
    /// Object)`. `dbh`, `name`, `timeInterval`, and `consumer` are dropped -- see the
    /// type's own docs for why.
    ///
    /// `buf_size` is accepted purely for signature fidelity with the Java constructor
    /// and genuinely has **no effect**: reading `DBDomainObjectSupport.java`'s
    /// constructor body (lines 38-42) shows it is neither assigned to a field nor even
    /// forwarded to `super(dbh, name, timeInterval, consumer)` -- `bufSize` is a dead
    /// parameter in the original Java source too, not something this port silently
    /// drops the meaning of. [`buf_size_parameter_has_no_observable_effect`] below
    /// proves this faithfully-reproduced quirk.
    ///
    /// [`buf_size_parameter_has_no_observable_effect`]: tests::buf_size_parameter_has_no_observable_effect
    pub fn new(open_mode: OpenMode, monitor: Box<dyn TaskMonitor>, buf_size: i32) -> Self {
        let _ = buf_size; // Faithful port of Java's unused `bufSize` constructor parameter.
        DBDomainObjectSupport {
            open_mode,
            monitor: Some(monitor),
            version_exc: None,
        }
    }

    /// The `OpenMode` this instance was constructed with.
    ///
    /// Java exposes this only implicitly (as the private `openMode` field read by
    /// `createManager`); surfaced here as an accessor since Rust has no protected-field
    /// access for a future composing type to fall back on.
    pub fn open_mode(&self) -> OpenMode {
        self.open_mode
    }

    /// Creates one manager, mirroring `DBDomainObjectSupport.createManager(String,
    /// ManagerSupplier)`.
    ///
    /// Checks for cancellation and reports `"Creating " + managerName"` on the monitor,
    /// then invokes `supplier`. A `VersionException` from `supplier` is not propagated:
    /// it is combined into this instance's pending version exception (mirroring
    /// `versionExc = e.combine(versionExc)`, where Java's `VersionException.combine`
    /// mutates and returns its receiver) and `Ok(None)` is returned in its place --
    /// callers must be prepared to receive `None` back, exactly as Java callers receive
    /// `null` here (see the `// TODO: (see GP-1238)` comment in the original source
    /// noting this will likely induce an NPE down the line; faithfully preserved as
    /// `None`, not silently upgraded to a proper error).
    ///
    /// # Panics
    /// Panics if called after [`init`](Self::init) has already completed successfully,
    /// since Java's `monitor` field is nulled out at the end of a successful `init()`
    /// and any post-`init` call to `createManager` would dereference that null monitor
    /// and throw `NullPointerException` in Java; this port raises an analogous panic
    /// instead of silently treating a missing monitor as "not cancelled".
    pub fn create_manager<M>(
        &mut self,
        manager_name: &str,
        supplier: impl FnOnce(OpenMode, &dyn TaskMonitor) -> Result<M, ManagerSupplyError>,
    ) -> Result<Option<M>, CreateManagerError> {
        let monitor = self.monitor.as_deref().unwrap_or_else(|| {
            panic!(
                "DBDomainObjectSupport::create_manager called after init() already completed \
                 (monitor already cleared); Java would NullPointerException here"
            )
        });
        monitor
            .check_cancelled()
            .map_err(CreateManagerError::Cancelled)?;
        monitor.set_message(&format!("Creating {manager_name}"));

        match supplier(self.open_mode, monitor) {
            Ok(value) => Ok(Some(value)),
            Err(ManagerSupplyError::Version(mut ve)) => {
                // Java: `versionExc = e.combine(versionExc)`. `VersionException.combine`
                // mutates its receiver using the argument's fields (a no-op if the
                // argument is null) and returns the receiver; here `ve` (the newly
                // caught exception, i.e. the receiver) is combined with the
                // previously-pending exception, if any, then stored back.
                if let Some(previous) = self.version_exc.take() {
                    ve.combine(&previous);
                }
                self.version_exc = Some(ve);
                Ok(None)
            }
            Err(ManagerSupplyError::Io(io)) => Err(CreateManagerError::Io(io)),
            Err(ManagerSupplyError::Cancelled(c)) => Err(CreateManagerError::Cancelled(c)),
        }
    }

    /// Completes initialization: runs `build_managers` to construct and inject `target`'s
    /// manager fields, surfaces any version exception left pending afterward, and finally
    /// invokes `finished_creating_managers` before clearing the monitor.
    ///
    /// Mirrors `DBDomainObjectSupport.init()`, whose body is, in order: reset
    /// `versionExc` to `null`; run `DependentServiceResolver.inject(this)` (reflective,
    /// static, per-class cached -- discovers and invokes every `@DependentService`
    /// factory method on `this`, most of which call `this.createManager(...)`
    /// internally); check the now-possibly-repopulated `versionExc` and throw if set;
    /// call `finishedCreatingManagers()`; null out `monitor`.
    ///
    /// Java's factory methods are ordinary instance methods, so each one has direct
    /// access to both `this.createManager` *and* `this`'s own manager fields at once.
    /// This crate's [`DependentServiceResolver`] (used for other, unrelated ports) can't
    /// stand in for that role here: its registered constructors are deliberately pure
    /// functions of already-resolved dependencies, with no side-channel back to the
    /// resolver's caller -- so a constructor registered on it could never call back into
    /// [`create_manager`](Self::create_manager) the way a Java factory method calls
    /// `this.createManager`. `build_managers` closes that gap directly: it receives both
    /// `&mut Self` (for [`create_manager`](Self::create_manager) calls, which accumulate
    /// into this instance's pending version exception exactly as in Java) and `&mut T`
    /// (to assign the constructed managers to `target`'s fields), mirroring the "both at
    /// once" access a Java factory method has via `this`. A `build_managers`
    /// implementation that still wants `DependentServiceResolver`'s topological
    /// ordering for services with no version-exception concerns of their own can call
    /// [`inject_via_resolver`] from inside it.
    ///
    /// `finishedCreatingManagers()` (Java's no-arg protected "Extension point", empty by
    /// default) becomes the `finished_creating_managers` closure, invoked with `target`
    /// so an override can still reach whatever state it needs, called only once
    /// `build_managers` and the pending version-exception check have both succeeded,
    /// exactly where Java calls it.
    pub fn init<T: DomainObjectAdapterDB>(
        &mut self,
        target: &mut T,
        build_managers: impl FnOnce(&mut Self, &mut T) -> Result<(), DBDomainObjectInitError>,
        finished_creating_managers: impl FnOnce(&mut T),
    ) -> Result<(), DBDomainObjectInitError> {
        self.version_exc = None;

        build_managers(self, target)?;

        if let Some(ve) = self.version_exc.take() {
            return Err(DBDomainObjectInitError::Version(ve));
        }

        finished_creating_managers(target);
        self.monitor = None;
        Ok(())
    }
}

/// Runs `resolver.inject_services(target)` and translates a resulting
/// `ServiceConstructionException` the way `DBDomainObjectSupport.init()` translates
/// whatever `DependentServiceResolver.inject(this)` throws: unwrapping a
/// `VersionException`/`CancelledException`/`IOException` cause back into its own error
/// variant (Java: `catch (ServiceConstructionException e) { ... instanceof ... }`), or
/// passing the `ServiceConstructionException` through unchanged for any other cause.
///
/// Meant to be called from inside a [`DBDomainObjectSupport::init`] `build_managers`
/// closure for the subset of a domain object's fields that suit
/// [`DependentServiceResolver`]'s pure dependency-graph model (see
/// [`init`](DBDomainObjectSupport::init)'s own doc for why `DependentServiceResolver`
/// alone can't cover fields built via [`DBDomainObjectSupport::create_manager`]).
pub fn inject_via_resolver<T>(
    resolver: &DependentServiceResolver<T>,
    target: &mut T,
) -> Result<(), DBDomainObjectInitError> {
    if let Err(e) = resolver.inject_services(target) {
        if let Some(ve) = e.cause().downcast_ref::<VersionException>() {
            return Err(DBDomainObjectInitError::Version(ve.clone()));
        }
        if let Some(ce) = e.cause().downcast_ref::<CancelledException>() {
            return Err(DBDomainObjectInitError::Cancelled(CancelledException(
                ce.0.clone(),
            )));
        }
        if let Some(ioe) = e.cause().downcast_ref::<std::io::Error>() {
            return Err(DBDomainObjectInitError::Io(std::io::Error::new(
                ioe.kind(),
                ioe.to_string(),
            )));
        }
        return Err(DBDomainObjectInitError::ServiceConstruction(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::data::domain_object_db_change_set::DomainObjectDBChangeSet;
    use crate::framework::db::util::ErrorHandler;
    use crate::framework::db::DBHandle;
    use crate::framework::model::DomainObject;
    use crate::util::task::CancelledListener;
    use std::any::Any;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A [`TaskMonitor`] test double that records every `setMessage` call and can be
    /// pre-cancelled, so tests can observe `create_manager`'s progress reporting and
    /// exercise its cancellation check.
    ///
    /// Uses `AtomicBool`/`Mutex` rather than `Cell`/`RefCell` because `TaskMonitor: Send
    /// + Sync` (see `util::task::TaskMonitor`), and `Cell`/`RefCell` are not `Sync`.
    #[derive(Default)]
    struct RecordingMonitor {
        cancelled: AtomicBool,
        messages: Mutex<Vec<String>>,
    }

    impl TaskMonitor for RecordingMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn get_message(&self) -> String {
            self.messages.lock().unwrap().last().cloned().unwrap_or_default()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            if self.cancelled.load(Ordering::SeqCst) {
                Err(CancelledException::new(CancelledException::DEFAULT_MESSAGE))
            } else {
                Ok(())
            }
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {
            self.cancelled.store(false, Ordering::SeqCst);
        }
    }

    /// A minimal concrete [`DomainObjectAdapterDB`] used only so `init`'s `T: DomainObjectAdapterDB`
    /// bound is satisfiable in tests; no test exercises its `DomainObjectAdapterDB` surface itself.
    struct MockDomainObject {
        dbh: DBHandle,
        finished_creating_managers_called: bool,
    }

    impl MockDomainObject {
        fn new() -> Self {
            Self {
                dbh: DBHandle::new().unwrap(),
                finished_creating_managers_called: false,
            }
        }
    }

    impl DomainObject for MockDomainObject {}

    impl ErrorHandler for MockDomainObject {
        fn db_error(&self, _e: std::io::Error) {}
    }

    impl DomainObjectAdapterDB for MockDomainObject {
        fn get_db_handle(&self) -> &DBHandle {
            &self.dbh
        }
        fn get_change_set(&self) -> Option<&dyn DomainObjectDBChangeSet> {
            None
        }
    }

    fn monitor() -> Box<RecordingMonitor> {
        Box::new(RecordingMonitor::default())
    }

    #[test]
    fn new_stores_open_mode_and_makes_monitor_available_to_create_manager() {
        let mut support = DBDomainObjectSupport::new(OpenMode::Update, monitor(), 4096);
        assert_eq!(support.open_mode(), OpenMode::Update);

        let result = support.create_manager("Widget", |open_mode, _monitor| {
            assert_eq!(open_mode, OpenMode::Update);
            Ok::<_, ManagerSupplyError>(42)
        });
        assert_eq!(result.unwrap(), Some(42));
    }

    /// Java: `DBDomainObjectSupport`'s constructor accepts `bufSize` but its body (lines
    /// 38-42) never reads it -- not stored in a field, not forwarded to `super(...)`.
    /// Two instances built with wildly different `buf_size` values must therefore behave
    /// identically in every other respect.
    #[test]
    fn buf_size_parameter_has_no_observable_effect() {
        let mut small = DBDomainObjectSupport::new(OpenMode::Create, monitor(), 0);
        let mut huge = DBDomainObjectSupport::new(OpenMode::Create, monitor(), i32::MAX);

        assert_eq!(small.open_mode(), huge.open_mode());

        let small_result = small.create_manager("X", |m, _mon| Ok::<_, ManagerSupplyError>(m));
        let huge_result = huge.create_manager("X", |m, _mon| Ok::<_, ManagerSupplyError>(m));
        assert_eq!(small_result.unwrap(), huge_result.unwrap());
    }

    #[test]
    fn create_manager_reports_creating_message_before_invoking_supplier() {
        let mut support = DBDomainObjectSupport::new(OpenMode::Update, monitor(), 0);

        let _ = support.create_manager("MemoryManager", |_om, monitor| {
            // The message is set on the monitor before `supplier` runs, so it must
            // already be visible through the very `monitor` reference passed in here.
            assert_eq!(monitor.get_message(), "Creating MemoryManager");
            Ok::<_, ManagerSupplyError>(())
        });
    }

    #[test]
    fn create_manager_propagates_cancellation_before_invoking_supplier() {
        let mon = monitor();
        mon.cancel();
        let mut support = DBDomainObjectSupport::new(OpenMode::Update, mon, 0);

        let mut supplier_invoked = false;
        let result = support.create_manager("Never", |_om, _mon| {
            supplier_invoked = true;
            Ok::<_, ManagerSupplyError>(())
        });

        assert!(!supplier_invoked);
        match result {
            Err(CreateManagerError::Cancelled(_)) => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    #[test]
    fn create_manager_propagates_io_error() {
        let mut support = DBDomainObjectSupport::new(OpenMode::Update, monitor(), 0);
        let result = support.create_manager("Disk", |_om, _mon| {
            Err::<(), _>(ManagerSupplyError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "disk full",
            )))
        });
        match result {
            Err(CreateManagerError::Io(e)) => assert_eq!(e.to_string(), "disk full"),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn create_manager_swallows_version_exception_and_returns_none() {
        let mut support = DBDomainObjectSupport::new(OpenMode::Update, monitor(), 0);
        let result = support.create_manager("Old", |_om, _mon| {
            Err::<(), _>(ManagerSupplyError::Version(VersionException::new()))
        });
        // Java: returns `null`, not an exception -- the manager is simply absent.
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn create_manager_combines_successive_version_exceptions() {
        // Drives two `create_manager` calls from *inside* `build_managers`, mirroring how
        // a real Java `@DependentService` factory method (invoked from within
        // `DependentServiceResolver.inject(this)`, i.e. from inside `init()`) has direct
        // `this.createManager(...)` access. `combine`'s upgradeability-ANDing is what's
        // under test: the second exception was not upgradeable, so the combined result
        // surfaced by `init()` must not be either.
        let mut support = DBDomainObjectSupport::new(OpenMode::Update, monitor(), 0);
        let mut target = MockDomainObject::new();

        let result = support.init(
            &mut target,
            |support, _target| {
                let first = VersionException::with_upgradeable(true);
                let _ = support.create_manager("A", |_om, _mon| {
                    Err::<(), _>(ManagerSupplyError::Version(first))
                });
                let second = VersionException::with_upgradeable(false);
                let _ = support.create_manager("B", |_om, _mon| {
                    Err::<(), _>(ManagerSupplyError::Version(second))
                });
                Ok(())
            },
            |_t| {},
        );

        match result {
            Err(DBDomainObjectInitError::Version(ve)) => assert!(!ve.is_upgradable()),
            other => panic!("expected Version error, got {other:?}"),
        }
    }

    #[test]
    fn init_succeeds_with_no_managers_and_invokes_finished_creating_managers() {
        let mut support = DBDomainObjectSupport::new(OpenMode::Create, monitor(), 0);
        let mut target = MockDomainObject::new();

        let result = support.init(
            &mut target,
            |_support, _target| Ok(()),
            |t| {
                t.finished_creating_managers_called = true;
            },
        );

        assert!(result.is_ok());
        assert!(target.finished_creating_managers_called);
    }

    #[test]
    fn init_does_not_run_finished_creating_managers_when_a_version_exception_is_pending() {
        // `version_exc` can only become (re-)populated *during* `build_managers`: `init()`
        // unconditionally resets it to `None` immediately beforehand (Java: the identical
        // `this.versionExc = null;` as literally the first statement of `init()` --
        // DBDomainObjectSupport.java:47). This drives that scenario the same way a real
        // Java `@DependentService` factory method would: by calling `create_manager` from
        // inside `build_managers`, which has `&mut Self` access for exactly this purpose.
        let mut support = DBDomainObjectSupport::new(OpenMode::Create, monitor(), 0);
        let mut target = MockDomainObject::new();

        let result = support.init(
            &mut target,
            |support, _target| {
                let _ = support.create_manager("Old", |_om, _mon| {
                    Err::<(), _>(ManagerSupplyError::Version(VersionException::new()))
                });
                Ok(())
            },
            |t| {
                t.finished_creating_managers_called = true;
            },
        );

        assert!(matches!(result, Err(DBDomainObjectInitError::Version(_))));
        assert!(!target.finished_creating_managers_called);
    }

    #[test]
    fn init_translates_version_exception_cause_out_of_service_construction_exception() {
        let mut support = DBDomainObjectSupport::new(OpenMode::Create, monitor(), 0);

        let mut resolver: DependentServiceResolver<MockDomainObject> = DependentServiceResolver::new();
        resolver.register_constructor(std::any::TypeId::of::<i32>(), [], |_deps| {
            Err(ServiceConstructionException::new(
                "bad version",
                VersionException::with_upgradeable(true),
            ))
        });
        resolver.register_field(
            std::any::TypeId::of::<i32>(),
            Box::new(|_t: &mut MockDomainObject, _v: &dyn Any| {}),
        );
        resolver.compile().expect("compile should succeed");

        let mut target = MockDomainObject::new();
        let result = support.init(
            &mut target,
            |_support, target| inject_via_resolver(&resolver, target),
            |_t| {},
        );
        match result {
            Err(DBDomainObjectInitError::Version(ve)) => assert!(ve.is_upgradable()),
            other => panic!("expected Version error, got {other:?}"),
        }
    }

    #[test]
    fn init_translates_cancelled_exception_cause_out_of_service_construction_exception() {
        let mut support = DBDomainObjectSupport::new(OpenMode::Create, monitor(), 0);

        let mut resolver: DependentServiceResolver<MockDomainObject> = DependentServiceResolver::new();
        resolver.register_constructor(std::any::TypeId::of::<i32>(), [], |_deps| {
            Err(ServiceConstructionException::new(
                "cancelled",
                CancelledException::new("stop"),
            ))
        });
        resolver.register_field(
            std::any::TypeId::of::<i32>(),
            Box::new(|_t: &mut MockDomainObject, _v: &dyn Any| {}),
        );
        resolver.compile().expect("compile should succeed");

        let mut target = MockDomainObject::new();
        let result = support.init(
            &mut target,
            |_support, target| inject_via_resolver(&resolver, target),
            |_t| {},
        );
        assert!(matches!(result, Err(DBDomainObjectInitError::Cancelled(_))));
    }

    #[test]
    fn init_translates_io_error_cause_out_of_service_construction_exception() {
        let mut support = DBDomainObjectSupport::new(OpenMode::Create, monitor(), 0);

        let mut resolver: DependentServiceResolver<MockDomainObject> = DependentServiceResolver::new();
        resolver.register_constructor(std::any::TypeId::of::<i32>(), [], |_deps| {
            Err(ServiceConstructionException::new(
                "io",
                std::io::Error::new(std::io::ErrorKind::NotFound, "missing file"),
            ))
        });
        resolver.register_field(
            std::any::TypeId::of::<i32>(),
            Box::new(|_t: &mut MockDomainObject, _v: &dyn Any| {}),
        );
        resolver.compile().expect("compile should succeed");

        let mut target = MockDomainObject::new();
        let result = support.init(
            &mut target,
            |_support, target| inject_via_resolver(&resolver, target),
            |_t| {},
        );
        match result {
            Err(DBDomainObjectInitError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn init_passes_through_service_construction_exception_for_unrecognized_cause() {
        #[derive(Debug)]
        struct Boom;
        impl std::fmt::Display for Boom {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "boom")
            }
        }
        impl std::error::Error for Boom {}

        let mut support = DBDomainObjectSupport::new(OpenMode::Create, monitor(), 0);

        let mut resolver: DependentServiceResolver<MockDomainObject> = DependentServiceResolver::new();
        resolver.register_constructor(std::any::TypeId::of::<i32>(), [], |_deps| {
            Err(ServiceConstructionException::new("boom", Boom))
        });
        resolver.register_field(
            std::any::TypeId::of::<i32>(),
            Box::new(|_t: &mut MockDomainObject, _v: &dyn Any| {}),
        );
        resolver.compile().expect("compile should succeed");

        let mut target = MockDomainObject::new();
        let result = support.init(
            &mut target,
            |_support, target| inject_via_resolver(&resolver, target),
            |_t| {},
        );
        match result {
            Err(DBDomainObjectInitError::ServiceConstruction(e)) => {
                assert_eq!(e.message(), "boom");
            }
            other => panic!("expected ServiceConstruction error, got {other:?}"),
        }
    }

    #[test]
    fn init_clears_monitor_so_a_later_create_manager_call_panics() {
        let mut support = DBDomainObjectSupport::new(OpenMode::Create, monitor(), 0);
        let resolver: DependentServiceResolver<MockDomainObject> = DependentServiceResolver::new();
        let mut target = MockDomainObject::new();
        support.init(
            &mut target,
            |_support, target| inject_via_resolver(&resolver, target),
            |_t| {},
        ).unwrap();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            support.create_manager("TooLate", |_om, _mon| Ok::<_, ManagerSupplyError>(()))
        }));
        assert!(result.is_err());
    }
}
