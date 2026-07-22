use std::io;

use crate::framework::model::ProjectData;
use crate::framework::protocol::ghidra::RepositoryInfo;

/// Backing store for a temporary, on-demand local project used to access a remote repository via
/// a `ghidra://` URL without an active local Ghidra project (e.g. for headless scripts, or
/// read-only browsing of a repository's content). Instances are cached and reference-counted by a
/// project manager keyed off [`RepositoryInfo`], and are torn down by an idle cleanup timer once
/// no consumer holds a reference and no repository file handles remain open.
///
/// Port of `ghidra.framework.protocol.ghidra.TransientProjectData`, which `extends
/// ghidra.framework.data.DefaultProjectData` (not yet ported in this crate). `DefaultProjectData`
/// itself `implements ghidra.framework.model.ProjectData`, already ported as
/// [`ProjectData`](crate::framework::model::ProjectData); this trait is declared as a subtrait of
/// `ProjectData` directly, skipping the unported intermediate concrete class, matching the
/// convention used elsewhere in this crate for extends-chains with a missing link (see e.g.
/// [`LongKeyRecordNode`](crate::framework::db::long_key_record_node::LongKeyRecordNode), which
/// mirrors `db.LongKeyRecordNode extends LongKeyNode` via a supertrait bound on the placeholder
/// [`LongKeyNode`](crate::framework::seam_stubs::LongKeyNode) trait).
///
/// Selected as a dependency-cycle cut-point, so every method here takes `&self` and returns
/// owned/boxed values, matching the object-safety rationale used elsewhere in this crate (e.g.
/// [`RepositoryAdapter`](crate::framework::client::RepositoryAdapter)): the Java original guards
/// all of its mutable state (instance-use count, cleanup-timer readiness, disposed flag) behind
/// `synchronized (cleanupTimer)` blocks, so implementations are expected to back these methods
/// with interior mutability rather than requiring `&mut self`.
///
/// The Java class's `close()` override (of `ProjectData`) and its `getSharedProjectURL()`/
/// `getLocalProjectURL()` overrides are not redeclared here, since `close`/`get_shared_project_url`/
/// `get_local_project_url` already exist as [`ProjectData`] methods with defaults; implementors of
/// this trait should override those `ProjectData` methods directly on their concrete type rather
/// than through this subtrait (mirroring how
/// [`DomainFileFilter`](crate::framework::model::DomainFileFilter) never redeclares
/// [`DomainFolderFilter`](crate::framework::model::DomainFolderFilter) methods it customizes --
/// it only adds new methods that call back into them). The Java `dispose()` override is
/// `protected`, has no `ProjectData` counterpart, and its behavior (disconnecting the repository)
/// belongs to the unported `DefaultProjectData`, so it is out of scope here --
/// [`forced_dispose`](Self::forced_dispose) is the entry point real implementations should route
/// through instead.
pub trait TransientProjectData: ProjectData {
    /// Returns the repository info this transient project was opened against, mirroring the
    /// package-private `repositoryInfo` field.
    fn repository_info(&self) -> &RepositoryInfo;

    /// Returns `true` if this project data has not yet been disposed (either directly, or via the
    /// idle cleanup timer), mirroring the package-private `isValid()`.
    fn is_valid(&self) -> bool;

    /// Stops the idle cleanup timer if this project data is still valid, mirroring the
    /// package-private `stopCleanupTimer()`.
    ///
    /// # Returns
    /// `true` if the timer was running and has been stopped.
    fn stop_cleanup_timer(&self) -> bool;

    /// (Re)starts the idle cleanup timer, mirroring the package-private `startCleanupTimer()`.
    fn start_cleanup_timer(&self);

    /// Increments the number of active consumers of this project data, mirroring
    /// `incrementInstanceUseCount()`.
    ///
    /// # Errors
    /// Returns `Err` if this project data has already been disposed.
    fn increment_instance_use_count(&self) -> io::Result<()>;

    /// Immediately disposes this project data regardless of its current use count (real
    /// implementations should log a premature-removal warning if consumers still hold
    /// references), removes it from its owning manager's cache, disconnects its repository, and
    /// deletes its temporary project storage. Mirrors the package-private `forcedDispose()`.
    fn forced_dispose(&self);
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io;

    use super::*;

    struct MockTransientProjectData {
        info: RepositoryInfo,
        use_count: Cell<i32>,
        timer_running: Cell<bool>,
        disposed: Cell<bool>,
        forced_dispose_called: Cell<bool>,
    }

    impl MockTransientProjectData {
        fn new(info: RepositoryInfo) -> Self {
            Self {
                info,
                use_count: Cell::new(0),
                timer_running: Cell::new(true),
                disposed: Cell::new(false),
                forced_dispose_called: Cell::new(false),
            }
        }
    }

    impl ProjectData for MockTransientProjectData {}

    impl TransientProjectData for MockTransientProjectData {
        fn repository_info(&self) -> &RepositoryInfo {
            &self.info
        }

        fn is_valid(&self) -> bool {
            !self.disposed.get()
        }

        fn stop_cleanup_timer(&self) -> bool {
            if !self.is_valid() || !self.timer_running.get() {
                return false;
            }
            self.timer_running.set(false);
            true
        }

        fn start_cleanup_timer(&self) {
            self.timer_running.set(true);
        }

        fn increment_instance_use_count(&self) -> io::Result<()> {
            if self.disposed.get() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Remote transient project has been disposed",
                ));
            }
            self.use_count.set(self.use_count.get() + 1);
            Ok(())
        }

        fn forced_dispose(&self) {
            if self.disposed.get() {
                return;
            }
            self.stop_cleanup_timer();
            self.disposed.set(true);
            self.forced_dispose_called.set(true);
        }
    }

    #[test]
    fn usable_as_trait_object_and_tracks_use_count_and_disposal() {
        let info = RepositoryInfo::new("ghidra://host/Repo", "Repo", false);
        let data = MockTransientProjectData::new(info.clone());
        let dyn_data: &dyn TransientProjectData = &data;

        assert!(dyn_data.is_valid());
        assert_eq!(dyn_data.repository_info(), &info);

        dyn_data.increment_instance_use_count().unwrap();
        dyn_data.increment_instance_use_count().unwrap();
        assert_eq!(data.use_count.get(), 2);

        assert!(dyn_data.stop_cleanup_timer());
        // Already stopped: stopping again is a no-op that reports nothing changed.
        assert!(!dyn_data.stop_cleanup_timer());
        dyn_data.start_cleanup_timer();
        assert!(data.timer_running.get());

        dyn_data.forced_dispose();
        assert!(!dyn_data.is_valid());
        assert!(data.forced_dispose_called.get());

        let err = dyn_data.increment_instance_use_count().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
