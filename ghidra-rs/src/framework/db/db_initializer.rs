use super::buffer_mgr::BufferMgr;
use crate::framework::application::Application;
use crate::framework::module_initializer::ModuleInitializer;
use crate::util::classfinder::ExtensionPoint;

/// Module initializer for the `db` package: deletes stale buffer cache files left over from a
/// previous, uncleanly-terminated session.
///
/// Port of `db.DBInitializer`, which implements `ghidra.framework.ModuleInitializer` and simply
/// calls `BufferMgr.cleanupOldCacheFiles()`. Since that cleanup needs access to the user's temp
/// directory and this crate avoids Java-style static singleton access to the running
/// `Application` (see [`crate::framework::application::Application`]'s doc comment and
/// [`BufferMgr::cleanup_old_cache_files`]), `DBInitializer` carries a reference to the
/// `Application` it should clean up on behalf of, supplied at construction time instead of
/// reached for globally inside `run()`.
pub struct DBInitializer<'a> {
    // `+ Send + Sync` (rather than plain `&'a dyn Application`) so that `DBInitializer` itself
    // satisfies `ModuleInitializer: ExtensionPoint + Send + Sync` -- a bare `&dyn Trait` is only
    // `Send`/`Sync` when the trait object itself is known to be, which requires spelling it out
    // on the object type since `Application` has no such supertrait bound of its own.
    app: &'a (dyn Application + Send + Sync),
}

impl<'a> DBInitializer<'a> {
    /// Construct a new `DBInitializer` that will clean up cache files under `app`'s user temp
    /// directory when [`run`](ModuleInitializer::run) is invoked.
    pub fn new(app: &'a (dyn Application + Send + Sync)) -> Self {
        Self { app }
    }
}

impl ExtensionPoint for DBInitializer<'_> {}

impl ModuleInitializer for DBInitializer<'_> {
    /// Mirrors `DBInitializer.run()`: deletes stale buffer cache files.
    fn run(&self) {
        // Java's `BufferMgr.cleanupOldCacheFiles()` swallows any error (a `null` directory
        // listing is simply skipped, and individual `File.delete()` failures are unchecked); the
        // Rust port's `io::Result` is likewise never surfaced here, matching that same
        // fire-and-forget contract.
        let _ = BufferMgr::cleanup_old_cache_files(self.app);
    }

    /// Mirrors `DBInitializer.getName()`.
    fn get_name(&self) -> String {
        "DB Module".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::platform::Platform;
    use crate::framework::seam_stubs::ApplicationLayoutLike;
    use std::path::PathBuf;

    struct MockApp {
        temp_dir: PathBuf,
    }

    impl Application for MockApp {
        fn application_layout(&self) -> Box<dyn ApplicationLayoutLike> {
            unimplemented!("not exercised by DBInitializer tests")
        }

        fn current_platform(&self) -> Box<dyn Platform> {
            unimplemented!("not exercised by DBInitializer tests")
        }

        fn user_temp_directory(&self) -> PathBuf {
            self.temp_dir.clone()
        }
    }

    #[test]
    fn test_get_name() {
        let app = MockApp { temp_dir: std::env::temp_dir() };
        let initializer = DBInitializer::new(&app);
        assert_eq!(initializer.get_name(), "DB Module");
    }

    #[test]
    fn test_run_deletes_stale_cache_files() {
        let dir = tempfile::tempdir().unwrap();
        let cache_file = dir.path().join("ghidra999.cache");
        std::fs::write(&cache_file, b"stale").unwrap();

        let app = MockApp { temp_dir: dir.path().to_path_buf() };
        let initializer = DBInitializer::new(&app);
        initializer.run();

        assert!(!cache_file.exists());
    }

    #[test]
    fn test_is_usable_as_boxed_module_initializer() {
        let app = MockApp { temp_dir: std::env::temp_dir() };
        let initializer: Box<dyn ModuleInitializer> = Box::new(DBInitializer::new(&app));
        assert_eq!(initializer.get_name(), "DB Module");
        initializer.run();
    }
}
