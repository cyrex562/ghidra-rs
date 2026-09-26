//! Port of `ghidra.framework.model.DomainFolderListenerAdapter`.
//!
//! The Java class is an abstract "adapter" (per the well-known Java listener-adapter idiom):
//! it implements every [`DomainFolderChangeListener`] method with a body that forwards to a
//! single consolidated `stateChanged(newPath, oldPath, isFolder)` callback, letting subclasses
//! override just `stateChanged` instead of all nine-plus individual callbacks. Four callbacks are
//! deliberately left out of that consolidation and keep pure no-op bodies:
//! `domainFolderSetActive`, `domainFileObjectOpenedForUpdate`, `domainFileObjectClosed` (and, per
//! the Java class's own javadoc, a nonexistent fourth entry `domainFileObjectReplaced` that
//! `DomainFolderChangeListener` doesn't actually declare -- a stale doc reference in the original
//! source, reproduced here only as this note rather than as dead code).
//!
//! The Java constructor uses reflection (`getClass().getMethod("stateChanged", ...)` plus a
//! `getDeclaringClass()` check) to detect, once, whether a subclass actually overrode
//! `stateChanged`; if not, the consolidated callback is never invoked at all (not even with a
//! no-op), avoiding pointless `getPathname()` string-building work on every event for listeners
//! that don't care. Rust has no reflection equivalent, so this port uses the presence of a
//! caller-supplied callback as the enabling signal instead: [`DomainFolderListenerAdapter::new`]
//! produces an adapter with the callback disabled (matching a subclass that never overrides
//! `stateChanged`), and [`DomainFolderListenerAdapter::with_state_changed`] enables it by
//! supplying the callback that would have lived in the overridden method body. This preserves the
//! "callback runs only when the caller actually wants it" behavior without needing runtime
//! reflection.
//!
//! Two of the per-event handlers (`domainFolderRenamed`, `domainFileRenamed`) call
//! `folder.getParent()` / `file.getParent()` unconditionally and immediately dereference the
//! result via the private `getPathname` helper. In real Java this is a latent
//! `NullPointerException` if `getParent()` ever returns `null` (which can't happen for a folder or
//! file being renamed in practice, since only the root folder has no parent and the root cannot be
//! renamed -- but the code does not guard against it). This port reproduces that faithfully with
//! `.expect(..)` rather than silently substituting an empty path; see the
//! `domain_folder_renamed_panics_when_folder_has_no_parent` test below.

use crate::framework::model::domain_file::DomainFile;
use crate::framework::model::domain_folder::DomainFolder;
use crate::framework::model::domain_folder_change_listener::DomainFolderChangeListener;
use crate::framework::store::SEPARATOR;

/// Callback signature for the consolidated `stateChanged` notification.
///
/// Port of `DomainFolderListenerAdapter.stateChanged(String affectedNewPath, String
/// affectedOldPath, boolean isFolder)`. `None` stands in for Java's `null` (used for "item was
/// removed" and "item is new", respectively).
pub type StateChangedCallback = Box<dyn Fn(Option<&str>, Option<&str>, bool) + Send + Sync>;

/// Adapter for [`DomainFolderChangeListener`] that funnels most notifications through a single
/// consolidated `state_changed` callback.
///
/// Port of `ghidra.framework.model.DomainFolderListenerAdapter`. See the module docs for the
/// reflection-vs-explicit-opt-in divergence and the faithfully-reproduced `getParent()` panic
/// behavior on rename.
pub struct DomainFolderListenerAdapter {
    state_changed: Option<StateChangedCallback>,
}

impl DomainFolderListenerAdapter {
    /// Constructs a new adapter with the consolidated callback disabled, matching a Java
    /// subclass that never overrides `stateChanged`.
    ///
    /// Port of `DomainFolderListenerAdapter()`.
    pub fn new() -> Self {
        Self { state_changed: None }
    }

    /// Constructs a new adapter that invokes `callback` for every notification not in the
    /// excluded set (`domain_folder_set_active`, `domain_file_object_opened_for_update`,
    /// `domain_file_object_closed`).
    ///
    /// Stands in for a Java subclass that overrides `stateChanged`; supplying a callback here is
    /// what makes the Java reflection check (`enableStateChangeCallback`) evaluate to `true`.
    pub fn with_state_changed(callback: StateChangedCallback) -> Self {
        Self {
            state_changed: Some(callback),
        }
    }

    /// Returns whether the consolidated callback will fire for incoming notifications.
    ///
    /// Port of the Java constructor's `enableStateChangeCallback` field, computed here from
    /// whether a callback was supplied rather than via reflection (see module docs).
    pub fn is_state_change_callback_enabled(&self) -> bool {
        self.state_changed.is_some()
    }

    /// Builds the full pathname of `child_name` within `parent_folder`.
    ///
    /// Port of the private `getPathname(DomainFolder parentFolder, String childName)` helper.
    fn get_pathname(parent_folder: &dyn DomainFolder, child_name: &str) -> String {
        let mut path = parent_folder.get_pathname();
        if path.len() != SEPARATOR.len() {
            path.push_str(SEPARATOR);
        }
        path.push_str(child_name);
        path
    }

    /// Invokes the consolidated callback, if enabled.
    fn fire_state_changed(
        &self,
        affected_new_path: Option<&str>,
        affected_old_path: Option<&str>,
        is_folder: bool,
    ) {
        if let Some(callback) = &self.state_changed {
            callback(affected_new_path, affected_old_path, is_folder);
        }
    }
}

impl Default for DomainFolderListenerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainFolderChangeListener for DomainFolderListenerAdapter {
    fn domain_folder_added(&mut self, folder: &dyn DomainFolder) {
        let new_path = folder.get_pathname();
        self.fire_state_changed(Some(&new_path), None, true);
    }

    fn domain_file_added(&mut self, file: &dyn DomainFile) {
        let new_path = file.get_pathname();
        self.fire_state_changed(Some(&new_path), None, false);
    }

    fn domain_folder_removed(&mut self, parent: &dyn DomainFolder, name: &str) {
        let old_path = Self::get_pathname(parent, name);
        self.fire_state_changed(None, Some(&old_path), true);
    }

    fn domain_file_removed(&mut self, parent: &dyn DomainFolder, name: &str, _file_id: Option<&str>) {
        let old_path = Self::get_pathname(parent, name);
        self.fire_state_changed(None, Some(&old_path), false);
    }

    fn domain_folder_renamed(&mut self, folder: &dyn DomainFolder, old_name: &str) {
        let new_path = folder.get_pathname();
        // Java: getPathname(folder.getParent(), oldName) -- NPEs if getParent() is null. See
        // module docs; faithfully reproduced rather than silently tolerated.
        let parent = folder
            .get_parent()
            .expect("Java NPEs here too: folder.getParent() must be non-null to rename a folder");
        let old_path = Self::get_pathname(parent.as_ref(), old_name);
        self.fire_state_changed(Some(&new_path), Some(&old_path), true);
    }

    fn domain_file_renamed(&mut self, file: &dyn DomainFile, old_name: &str) {
        let new_path = file.get_pathname();
        // Java: getPathname(file.getParent(), oldName) -- same NPE-on-null-parent hazard as
        // domain_folder_renamed above.
        let parent = file
            .get_parent()
            .expect("Java NPEs here too: file.getParent() must be non-null to rename a file");
        let old_path = Self::get_pathname(parent.as_ref(), old_name);
        self.fire_state_changed(Some(&new_path), Some(&old_path), false);
    }

    fn domain_folder_moved(&mut self, folder: &dyn DomainFolder, old_parent: &dyn DomainFolder) {
        let new_path = folder.get_pathname();
        let old_path = Self::get_pathname(old_parent, &folder.get_name());
        self.fire_state_changed(Some(&new_path), Some(&old_path), true);
    }

    fn domain_file_moved(&mut self, file: &dyn DomainFile, old_parent: &dyn DomainFolder, old_name: &str) {
        let new_path = file.get_pathname();
        let old_path = Self::get_pathname(old_parent, old_name);
        self.fire_state_changed(Some(&new_path), Some(&old_path), false);
    }

    fn domain_file_status_changed(&mut self, file: &dyn DomainFile, _file_id_set: bool) {
        // Java passes the *same* path for both the new and old path here: `String path =
        // file.getPathname(); stateChanged(path, path, false);` -- reproduced as-is even though
        // it means a listener can't distinguish "renamed" from "status changed" purely from
        // whether new/old differ.
        let path = file.get_pathname();
        self.fire_state_changed(Some(&path), Some(&path), false);
    }

    // domain_folder_set_active, domain_file_object_opened_for_update, and
    // domain_file_object_closed are intentionally NOT overridden here, matching Java (they fall
    // through to `DomainFolderChangeListener`'s own no-op defaults and never reach
    // `stateChanged`).
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockDomainFolder {
        pathname: String,
        name: String,
        parent: Option<Arc<MockDomainFolder>>,
    }

    impl DomainFolder for MockDomainFolder {
        fn get_pathname(&self) -> String {
            self.pathname.clone()
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_parent(&self) -> Option<Box<dyn DomainFolder>> {
            self.parent
                .as_ref()
                .map(|p| Box::new((**p).clone()) as Box<dyn DomainFolder>)
        }
    }

    struct MockDomainFile {
        pathname: String,
        parent: Option<Arc<MockDomainFolder>>,
    }

    impl DomainFile for MockDomainFile {
        fn get_pathname(&self) -> String {
            self.pathname.clone()
        }

        fn get_parent(&self) -> Option<Box<dyn DomainFolder>> {
            self.parent
                .as_ref()
                .map(|p| Box::new((**p).clone()) as Box<dyn DomainFolder>)
        }
    }

    fn root_folder() -> MockDomainFolder {
        MockDomainFolder {
            pathname: SEPARATOR.to_string(),
            name: "".to_string(),
            parent: None,
        }
    }

    /// Records every `state_changed` invocation as an owned tuple so assertions don't need to
    /// juggle borrowed lifetimes across the callback boundary.
    type Recorded = Arc<Mutex<Vec<(Option<String>, Option<String>, bool)>>>;

    fn recording_adapter() -> (DomainFolderListenerAdapter, Recorded) {
        let recorded: Recorded = Arc::new(Mutex::new(Vec::new()));
        let recorded_clone = Arc::clone(&recorded);
        let adapter = DomainFolderListenerAdapter::with_state_changed(Box::new(
            move |new_path, old_path, is_folder| {
                recorded_clone.lock().unwrap().push((
                    new_path.map(|s| s.to_string()),
                    old_path.map(|s| s.to_string()),
                    is_folder,
                ));
            },
        ));
        (adapter, recorded)
    }

    #[test]
    fn default_adapter_has_callback_disabled_and_stays_silent() {
        let mut adapter = DomainFolderListenerAdapter::new();
        assert!(!adapter.is_state_change_callback_enabled());

        let folder = root_folder();
        // Should not panic and should not (observably) do anything; there's nothing to assert on
        // besides "this doesn't blow up", since there is no callback wired in.
        adapter.domain_folder_added(&folder);
    }

    #[test]
    fn with_state_changed_enables_the_callback() {
        let (adapter, _recorded) = recording_adapter();
        assert!(adapter.is_state_change_callback_enabled());
    }

    #[test]
    fn domain_folder_added_reports_new_path_only() {
        let (mut adapter, recorded) = recording_adapter();
        let folder = MockDomainFolder {
            pathname: "/a/b".to_string(),
            name: "b".to_string(),
            parent: None,
        };
        adapter.domain_folder_added(&folder);

        assert_eq!(
            *recorded.lock().unwrap(),
            vec![(Some("/a/b".to_string()), None, true)]
        );
    }

    #[test]
    fn domain_file_added_reports_new_path_only_and_is_folder_false() {
        let (mut adapter, recorded) = recording_adapter();
        let file = MockDomainFile {
            pathname: "/a/b.exe".to_string(),
            parent: None,
        };
        adapter.domain_file_added(&file);

        assert_eq!(
            *recorded.lock().unwrap(),
            vec![(Some("/a/b.exe".to_string()), None, false)]
        );
    }

    #[test]
    fn domain_folder_removed_builds_old_path_from_parent_and_name() {
        let (mut adapter, recorded) = recording_adapter();
        let parent = root_folder();
        adapter.domain_folder_removed(&parent, "sub");

        assert_eq!(
            *recorded.lock().unwrap(),
            vec![(None, Some("/sub".to_string()), true)]
        );
    }

    #[test]
    fn get_pathname_does_not_double_the_separator_for_a_non_root_parent() {
        let (mut adapter, recorded) = recording_adapter();
        let parent = MockDomainFolder {
            pathname: "/a".to_string(),
            name: "a".to_string(),
            parent: None,
        };
        adapter.domain_folder_removed(&parent, "sub");

        assert_eq!(
            *recorded.lock().unwrap(),
            vec![(None, Some("/a/sub".to_string()), true)]
        );
    }

    #[test]
    fn domain_file_removed_ignores_the_file_id_argument() {
        let (mut adapter, recorded) = recording_adapter();
        let parent = root_folder();
        adapter.domain_file_removed(&parent, "f.exe", Some("some-file-id"));

        assert_eq!(
            *recorded.lock().unwrap(),
            vec![(None, Some("/f.exe".to_string()), false)]
        );
    }

    #[test]
    fn domain_folder_renamed_uses_current_parent_for_the_old_path() {
        let (mut adapter, recorded) = recording_adapter();
        let parent = Arc::new(root_folder());
        let folder = MockDomainFolder {
            pathname: "/newname".to_string(),
            name: "newname".to_string(),
            parent: Some(Arc::clone(&parent)),
        };
        adapter.domain_folder_renamed(&folder, "oldname");

        assert_eq!(
            *recorded.lock().unwrap(),
            vec![(
                Some("/newname".to_string()),
                Some("/oldname".to_string()),
                true
            )]
        );
    }

    #[test]
    #[should_panic(expected = "getParent() must be non-null")]
    fn domain_folder_renamed_panics_when_folder_has_no_parent() {
        // Faithfully reproduces the Java NullPointerException that would occur from
        // `getPathname(folder.getParent(), oldName)` when `getParent()` returns null.
        let (mut adapter, _recorded) = recording_adapter();
        let folder = MockDomainFolder {
            pathname: SEPARATOR.to_string(),
            name: "".to_string(),
            parent: None,
        };
        adapter.domain_folder_renamed(&folder, "oldname");
    }

    #[test]
    fn domain_file_renamed_uses_current_parent_for_the_old_path() {
        let (mut adapter, recorded) = recording_adapter();
        let parent = Arc::new(root_folder());
        let file = MockDomainFile {
            pathname: "/newname.exe".to_string(),
            parent: Some(Arc::clone(&parent)),
        };
        adapter.domain_file_renamed(&file, "oldname.exe");

        assert_eq!(
            *recorded.lock().unwrap(),
            vec![(
                Some("/newname.exe".to_string()),
                Some("/oldname.exe".to_string()),
                false
            )]
        );
    }

    #[test]
    fn domain_folder_moved_builds_old_path_from_old_parent_and_current_name() {
        let (mut adapter, recorded) = recording_adapter();
        let old_parent = MockDomainFolder {
            pathname: "/old".to_string(),
            name: "old".to_string(),
            parent: None,
        };
        let folder = MockDomainFolder {
            pathname: "/new/thing".to_string(),
            name: "thing".to_string(),
            parent: None,
        };
        adapter.domain_folder_moved(&folder, &old_parent);

        assert_eq!(
            *recorded.lock().unwrap(),
            vec![(
                Some("/new/thing".to_string()),
                Some("/old/thing".to_string()),
                true
            )]
        );
    }

    #[test]
    fn domain_file_moved_builds_old_path_from_old_parent_and_old_name() {
        let (mut adapter, recorded) = recording_adapter();
        let old_parent = MockDomainFolder {
            pathname: "/old".to_string(),
            name: "old".to_string(),
            parent: None,
        };
        let file = MockDomainFile {
            pathname: "/new/thing.exe".to_string(),
            parent: None,
        };
        adapter.domain_file_moved(&file, &old_parent, "thing_old_name.exe");

        assert_eq!(
            *recorded.lock().unwrap(),
            vec![(
                Some("/new/thing.exe".to_string()),
                Some("/old/thing_old_name.exe".to_string()),
                false
            )]
        );
    }

    #[test]
    fn domain_file_status_changed_reports_the_same_path_as_both_new_and_old() {
        // Faithfully reproduces the Java quirk: `stateChanged(path, path, false)` passes the
        // identical path for both the new and old slots, unlike every other callback.
        let (mut adapter, recorded) = recording_adapter();
        let file = MockDomainFile {
            pathname: "/unchanged.exe".to_string(),
            parent: None,
        };
        adapter.domain_file_status_changed(&file, true);

        let calls = recorded.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (new_path, old_path, is_folder) = &calls[0];
        assert_eq!(new_path, old_path);
        assert_eq!(new_path.as_deref(), Some("/unchanged.exe"));
        assert!(!is_folder);
    }

    #[test]
    fn excluded_callbacks_never_reach_state_changed() {
        let (mut adapter, recorded) = recording_adapter();
        let folder = root_folder();

        // These three are explicitly documented in Java as NOT routed through stateChanged, and
        // this adapter doesn't override them, so they fall through to
        // DomainFolderChangeListener's no-op defaults.
        adapter.domain_folder_set_active(&folder);

        assert!(recorded.lock().unwrap().is_empty());
    }

    #[test]
    fn adapter_usable_as_mut_trait_object() {
        let (adapter, recorded) = recording_adapter();
        let mut listener: Box<dyn DomainFolderChangeListener> = Box::new(adapter);
        let folder = root_folder();
        listener.domain_folder_added(&folder);

        assert_eq!(recorded.lock().unwrap().len(), 1);
    }
}
