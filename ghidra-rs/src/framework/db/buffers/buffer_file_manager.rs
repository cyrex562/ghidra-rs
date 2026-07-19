use std::io;
use std::path::PathBuf;

/// Provides an interface for a `BufferFile` manager who understands the storage for the various
/// versions of `BufferFile`s associated with a single database.
///
/// Mirrors `db.buffers.BufferFileManager`.
pub trait BufferFileManager {
    /// Returns the current version. A value of 0 indicates that the first buffer file has not
    /// yet been created.
    fn get_current_version(&self) -> i32;

    /// Get the buffer file corresponding to a specified version.
    fn get_buffer_file(&self, version: i32) -> PathBuf;

    /// Get the buffer version file corresponding to a specified version. This file contains data
    /// corresponding to a specified buffer file version and those buffers which have been
    /// modified in the next version (version+1). Returns `None` if version files not used.
    fn get_version_file(&self, version: i32) -> Option<PathBuf>;

    /// Get the change data buffer file corresponding to the specified version. This file
    /// contains application specific changes which were made going from the specified version to
    /// the next version (version+1). Returns `None` if change data files are not used.
    fn get_change_data_file(&self, version: i32) -> Option<PathBuf>;

    /// Returns the change map file corresponding to this DB if one is defined.
    /// This file tracks all buffers which have been modified during a save operation.
    fn get_change_map_file(&self) -> Option<PathBuf>;

    /// Callback for when a buffer file is created.
    ///
    /// Returns `Err` if the database files are not found (mirrors Java's
    /// `FileNotFoundException`).
    fn version_created(&mut self, version: i32, comment: &str, checkin_id: i64) -> io::Result<()>;

    /// Callback indicating that a buffer file update has ended without creating a new version.
    /// This method terminates the checkin session.
    fn update_ended(&mut self, checkin_id: i64);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBufferFileManager {
        version: i32,
    }

    impl BufferFileManager for MockBufferFileManager {
        fn get_current_version(&self) -> i32 {
            self.version
        }

        fn get_buffer_file(&self, version: i32) -> PathBuf {
            PathBuf::from(format!("/db/buffer.{version}"))
        }

        fn get_version_file(&self, _version: i32) -> Option<PathBuf> {
            None
        }

        fn get_change_data_file(&self, _version: i32) -> Option<PathBuf> {
            None
        }

        fn get_change_map_file(&self) -> Option<PathBuf> {
            None
        }

        fn version_created(
            &mut self,
            version: i32,
            _comment: &str,
            _checkin_id: i64,
        ) -> io::Result<()> {
            self.version = version;
            Ok(())
        }

        fn update_ended(&mut self, _checkin_id: i64) {}
    }

    #[test]
    fn test_buffer_file_manager_object_safety() {
        let mut mgr: Box<dyn BufferFileManager> = Box::new(MockBufferFileManager { version: 0 });

        assert_eq!(mgr.get_current_version(), 0);
        assert_eq!(mgr.get_buffer_file(1), PathBuf::from("/db/buffer.1"));
        assert!(mgr.get_version_file(1).is_none());
        assert!(mgr.get_change_data_file(1).is_none());
        assert!(mgr.get_change_map_file().is_none());
        assert!(mgr.version_created(1, "created", 42).is_ok());
        mgr.update_ended(42);
        assert_eq!(mgr.get_current_version(), 1);
    }
}
