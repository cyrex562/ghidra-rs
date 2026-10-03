//! Service for running Ghidra scripts.
//!
//! Mirrors `ghidra.app.services.GhidraScriptService`.

use crate::generic::jar::resource_file::ResourceFile;
use crate::util::task::task_listener::TaskListener;

/// Service for running Ghidra scripts and managing script-related functionality.
pub trait GhidraScriptService {
    /// Runs a script with the given name and notifies the listener when complete.
    fn run_script(&self, script_name: &str, listener: &dyn TaskListener);

    /// Refreshes the list of available scripts.
    fn refresh_script_list(&self);

    /// Attempts to edit the provided file in Eclipse.
    ///
    /// Returns `true` if the file opened in Eclipse; otherwise, `false`.
    fn try_to_edit_file_in_eclipse(&self, file: &ResourceFile) -> bool;

    /// Attempts to edit the provided file in Visual Studio Code.
    ///
    /// Returns `true` if the file opened in Visual Studio Code; otherwise, `false`.
    fn try_to_edit_file_in_vs_code(&self, file: &ResourceFile) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct MockTask;
    impl crate::util::seam_stubs::Task for MockTask {}

    struct RecordingTaskListener {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl TaskListener for RecordingTaskListener {
        fn task_completed(&self, _task: &dyn crate::util::seam_stubs::Task) {
            self.calls.lock().unwrap().push("completed".to_string());
        }

        fn task_cancelled(&self, _task: &dyn crate::util::seam_stubs::Task) {
            self.calls.lock().unwrap().push("cancelled".to_string());
        }
    }

    struct MockGhidraScriptService {
        run_count: Arc<Mutex<i32>>,
        refresh_count: Arc<Mutex<i32>>,
        eclipse_edits: Arc<Mutex<i32>>,
        vscode_edits: Arc<Mutex<i32>>,
        eclipse_success: bool,
        vscode_success: bool,
    }

    impl GhidraScriptService for MockGhidraScriptService {
        fn run_script(&self, _script_name: &str, _listener: &dyn TaskListener) {
            *self.run_count.lock().unwrap() += 1;
        }

        fn refresh_script_list(&self) {
            *self.refresh_count.lock().unwrap() += 1;
        }

        fn try_to_edit_file_in_eclipse(&self, _file: &ResourceFile) -> bool {
            *self.eclipse_edits.lock().unwrap() += 1;
            self.eclipse_success
        }

        fn try_to_edit_file_in_vs_code(&self, _file: &ResourceFile) -> bool {
            *self.vscode_edits.lock().unwrap() += 1;
            self.vscode_success
        }
    }

    #[test]
    fn test_run_script() {
        let run_count = Arc::new(Mutex::new(0));
        let refresh_count = Arc::new(Mutex::new(0));
        let eclipse_edits = Arc::new(Mutex::new(0));
        let vscode_edits = Arc::new(Mutex::new(0));

        let service = MockGhidraScriptService {
            run_count: Arc::clone(&run_count),
            refresh_count: Arc::clone(&refresh_count),
            eclipse_edits: Arc::clone(&eclipse_edits),
            vscode_edits: Arc::clone(&vscode_edits),
            eclipse_success: true,
            vscode_success: true,
        };

        let listener = RecordingTaskListener {
            calls: Arc::new(Mutex::new(Vec::new())),
        };

        service.run_script("my_script", &listener);
        service.run_script("another_script", &listener);

        assert_eq!(*run_count.lock().unwrap(), 2);
    }

    #[test]
    fn test_refresh_script_list() {
        let refresh_count = Arc::new(Mutex::new(0));
        let service = MockGhidraScriptService {
            run_count: Arc::new(Mutex::new(0)),
            refresh_count: Arc::clone(&refresh_count),
            eclipse_edits: Arc::new(Mutex::new(0)),
            vscode_edits: Arc::new(Mutex::new(0)),
            eclipse_success: true,
            vscode_success: true,
        };

        service.refresh_script_list();
        service.refresh_script_list();
        service.refresh_script_list();

        assert_eq!(*refresh_count.lock().unwrap(), 3);
    }

    #[test]
    fn test_try_to_edit_file_in_eclipse_success() {
        let eclipse_edits = Arc::new(Mutex::new(0));
        let service = MockGhidraScriptService {
            run_count: Arc::new(Mutex::new(0)),
            refresh_count: Arc::new(Mutex::new(0)),
            eclipse_edits: Arc::clone(&eclipse_edits),
            vscode_edits: Arc::new(Mutex::new(0)),
            eclipse_success: true,
            vscode_success: true,
        };

        let file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.py"));
        let result = service.try_to_edit_file_in_eclipse(&file);

        assert!(result);
        assert_eq!(*eclipse_edits.lock().unwrap(), 1);
    }

    #[test]
    fn test_try_to_edit_file_in_eclipse_failure() {
        let eclipse_edits = Arc::new(Mutex::new(0));
        let service = MockGhidraScriptService {
            run_count: Arc::new(Mutex::new(0)),
            refresh_count: Arc::new(Mutex::new(0)),
            eclipse_edits: Arc::clone(&eclipse_edits),
            vscode_edits: Arc::new(Mutex::new(0)),
            eclipse_success: false,
            vscode_success: true,
        };

        let file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.py"));
        let result = service.try_to_edit_file_in_eclipse(&file);

        assert!(!result);
        assert_eq!(*eclipse_edits.lock().unwrap(), 1);
    }

    #[test]
    fn test_try_to_edit_file_in_vscode_success() {
        let vscode_edits = Arc::new(Mutex::new(0));
        let service = MockGhidraScriptService {
            run_count: Arc::new(Mutex::new(0)),
            refresh_count: Arc::new(Mutex::new(0)),
            eclipse_edits: Arc::new(Mutex::new(0)),
            vscode_edits: Arc::clone(&vscode_edits),
            eclipse_success: true,
            vscode_success: true,
        };

        let file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.py"));
        let result = service.try_to_edit_file_in_vs_code(&file);

        assert!(result);
        assert_eq!(*vscode_edits.lock().unwrap(), 1);
    }

    #[test]
    fn test_try_to_edit_file_in_vscode_failure() {
        let vscode_edits = Arc::new(Mutex::new(0));
        let service = MockGhidraScriptService {
            run_count: Arc::new(Mutex::new(0)),
            refresh_count: Arc::new(Mutex::new(0)),
            eclipse_edits: Arc::new(Mutex::new(0)),
            vscode_edits: Arc::clone(&vscode_edits),
            eclipse_success: true,
            vscode_success: false,
        };

        let file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.py"));
        let result = service.try_to_edit_file_in_vs_code(&file);

        assert!(!result);
        assert_eq!(*vscode_edits.lock().unwrap(), 1);
    }

    #[test]
    fn test_service_as_trait_object() {
        let service: Box<dyn GhidraScriptService> = Box::new(MockGhidraScriptService {
            run_count: Arc::new(Mutex::new(0)),
            refresh_count: Arc::new(Mutex::new(0)),
            eclipse_edits: Arc::new(Mutex::new(0)),
            vscode_edits: Arc::new(Mutex::new(0)),
            eclipse_success: true,
            vscode_success: true,
        });

        let listener = RecordingTaskListener {
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.py"));

        service.run_script("script1", &listener);
        service.refresh_script_list();
        let _eclipse_result = service.try_to_edit_file_in_eclipse(&file);
        let _vscode_result = service.try_to_edit_file_in_vs_code(&file);
    }

    #[test]
    fn test_multiple_services() {
        let run_count1 = Arc::new(Mutex::new(0));
        let run_count2 = Arc::new(Mutex::new(0));

        let service1 = MockGhidraScriptService {
            run_count: Arc::clone(&run_count1),
            refresh_count: Arc::new(Mutex::new(0)),
            eclipse_edits: Arc::new(Mutex::new(0)),
            vscode_edits: Arc::new(Mutex::new(0)),
            eclipse_success: true,
            vscode_success: true,
        };

        let service2 = MockGhidraScriptService {
            run_count: Arc::clone(&run_count2),
            refresh_count: Arc::new(Mutex::new(0)),
            eclipse_edits: Arc::new(Mutex::new(0)),
            vscode_edits: Arc::new(Mutex::new(0)),
            eclipse_success: true,
            vscode_success: true,
        };

        let listener = RecordingTaskListener {
            calls: Arc::new(Mutex::new(Vec::new())),
        };

        service1.run_script("script1", &listener);
        service2.run_script("script2", &listener);
        service1.run_script("script3", &listener);

        assert_eq!(*run_count1.lock().unwrap(), 2);
        assert_eq!(*run_count2.lock().unwrap(), 1);
    }
}
