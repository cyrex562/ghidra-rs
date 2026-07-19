use std::io;

use crate::framework::db::buffers::BufferFile;

/// Facilitates read/write access to a buffer oriented file, and access to related resources such
/// as parameters and change data.
///
/// Mirrors `db.buffers.ManagedBufferFile`, which extends `BufferFile`.
pub trait ManagedBufferFile: BufferFile {
    /// Get the next change data file which corresponds to this buffer file. This method acts
    /// like an iterator which each successive invocation returning the next available file.
    /// `None` is returned when no more files are available. The invoker is responsible for
    /// closing each file returned. It is highly recommended that each file be closed prior to
    /// requesting the next file.
    ///
    /// `get_first` causes the iterator to reset and return the first available file.
    fn get_next_change_data_file(
        &mut self,
        get_first: bool,
    ) -> io::Result<Option<Box<dyn BufferFile>>>;

    /// Returns a temporary change data buffer file which should be used to store an
    /// application-level ChangeSet associated with this new buffer file version, or `None` if one
    /// is not available. `get_save_file` must be successfully invoked prior to invoking this
    /// method.
    fn get_save_change_data_file(&mut self) -> io::Result<Option<Box<dyn BufferFile>>>;

    /// Returns a bit map corresponding to all buffers modified since `old_version`. This
    /// identifies all buffers contained within `old_version` which have been modified during any
    /// revision up until this file version. Buffers added since `old_version` are not identified.
    ///
    /// NOTE: The bit mask may identify empty/free buffers within this file version.
    ///
    /// This method may only be invoked if this file is at version 2 or higher, has an associated
    /// buffer file manager, and the `old_version` related files still exist.
    fn get_forward_mod_map_data(&self, old_version: i32) -> io::Result<Vec<u8>>;

    /// Returns a save file if available, or `None` if a save can not be performed. This method
    /// may block for an extended period of time if the pre-save process has not already
    /// completed.
    fn get_save_file(&mut self) -> io::Result<Option<Box<dyn ManagedBufferFile>>>;

    /// After getting the save file, this method must be invoked to terminate the save.
    ///
    /// If `commit` is true the save file will be reopened as read-only for update. If false, the
    /// save file will be deleted and the object will become invalid.
    fn save_completed(&mut self, commit: bool) -> io::Result<()>;

    /// Returns true if a save file is provided for creating a new version of this buffer file.
    /// See [`ManagedBufferFile::get_save_file`].
    fn can_save(&self) -> io::Result<bool>;

    /// Set the comment which will be associated with this buffer file if saved. The comment must
    /// be set prior to invoking close or set_read_only.
    fn set_version_comment(&mut self, comment: &str) -> io::Result<()>;

    /// Returns the checkin ID corresponding to this buffer file. The returned value is only valid
    /// if this buffer file has an associated buffer file manager and is either being created (see
    /// `is_read_only`) or is intended for update (see `can_save`).
    fn get_checkin_id(&self) -> io::Result<i64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::DataBuffer;

    struct MockManagedBufferFile {
        read_only: bool,
        checkin_id: i64,
    }

    impl BufferFile for MockManagedBufferFile {
        fn is_read_only(&self) -> bool {
            self.read_only
        }

        fn set_read_only(&mut self) -> io::Result<bool> {
            self.read_only = true;
            Ok(true)
        }

        fn get_buffer_size(&self) -> usize {
            4096
        }

        fn get_index_count(&self) -> usize {
            0
        }

        fn get_free_indexes(&self) -> Vec<i32> {
            Vec::new()
        }

        fn set_free_indexes(&mut self, _indexes: &[i32]) -> io::Result<()> {
            Ok(())
        }

        fn get_parameter(&self, _name: &str) -> Option<i32> {
            None
        }

        fn set_parameter(&mut self, _name: &str, _value: i32) {}

        fn get_parameter_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get(&self, index: i32) -> io::Result<DataBuffer> {
            Ok(DataBuffer::from_data(index, vec![0u8; 4]))
        }

        fn put(&mut self, _buf: &DataBuffer, _index: i32) -> io::Result<()> {
            Ok(())
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn delete(&mut self) -> io::Result<bool> {
            Ok(!self.read_only)
        }
    }

    impl ManagedBufferFile for MockManagedBufferFile {
        fn get_next_change_data_file(
            &mut self,
            _get_first: bool,
        ) -> io::Result<Option<Box<dyn BufferFile>>> {
            Ok(None)
        }

        fn get_save_change_data_file(&mut self) -> io::Result<Option<Box<dyn BufferFile>>> {
            Ok(None)
        }

        fn get_forward_mod_map_data(&self, _old_version: i32) -> io::Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn get_save_file(&mut self) -> io::Result<Option<Box<dyn ManagedBufferFile>>> {
            Ok(None)
        }

        fn save_completed(&mut self, _commit: bool) -> io::Result<()> {
            Ok(())
        }

        fn can_save(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn set_version_comment(&mut self, _comment: &str) -> io::Result<()> {
            Ok(())
        }

        fn get_checkin_id(&self) -> io::Result<i64> {
            Ok(self.checkin_id)
        }
    }

    #[test]
    fn test_managed_buffer_file_object_safety() {
        let mut file: Box<dyn ManagedBufferFile> =
            Box::new(MockManagedBufferFile { read_only: false, checkin_id: 42 });

        assert!(!file.is_read_only());
        assert!(file.get_next_change_data_file(true).unwrap().is_none());
        assert!(file.get_save_change_data_file().unwrap().is_none());
        assert!(file.get_forward_mod_map_data(1).unwrap().is_empty());
        assert!(file.get_save_file().unwrap().is_none());
        assert!(file.save_completed(true).is_ok());
        assert!(!file.can_save().unwrap());
        assert!(file.set_version_comment("comment").is_ok());
        assert_eq!(file.get_checkin_id().unwrap(), 42);
    }
}
