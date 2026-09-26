use std::io;

use crate::framework::seam_stubs::LocalBufferFileLike;

/// Tracks which buffers within a buffer file have been modified between an older and newer
/// version. The older file is also referred to as the target file.
///
/// Mirrors `db.buffers.ChangeMapFile`. Its two Java constructors (create-for-output and
/// open-for-read) are factory operations rather than instance API, so they are not part of this
/// trait; concrete implementations are expected to provide their own construction.
pub trait ChangeMapFile {
    /// Returns true if this change map corresponds to the specified target file.
    fn is_valid_for(&self, target_file: &dyn LocalBufferFileLike) -> bool;

    /// Abort the creation/update of this file. This method should be invoked in place of
    /// [`Self::close`] on a failure condition. An attempt is made to restore the version file to
    /// its initial state or remove it if it was new.
    fn abort(&mut self);

    /// Close the file.
    fn close(&mut self) -> io::Result<()>;

    /// Mark buffer as changed.
    fn buffer_changed(&mut self, index: i32, empty: bool) -> io::Result<()>;

    /// Returns data suitable for use by the `ChangeMap` class.
    fn get_mod_data(&self) -> io::Result<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTargetFile {
        file_id: u64,
    }

    impl LocalBufferFileLike for MockTargetFile {
        fn get_file_id(&self) -> u64 {
            self.file_id
        }
    }

    struct MockChangeMapFile {
        target_file_id: u64,
        mod_data: Vec<u8>,
        aborted: bool,
    }

    impl ChangeMapFile for MockChangeMapFile {
        fn is_valid_for(&self, target_file: &dyn LocalBufferFileLike) -> bool {
            self.target_file_id == target_file.get_file_id()
        }

        fn abort(&mut self) {
            self.aborted = true;
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn buffer_changed(&mut self, index: i32, empty: bool) -> io::Result<()> {
            let idx = index as usize;
            if idx >= self.mod_data.len() * 8 {
                return Ok(());
            }
            let byte_offset = idx / 8;
            let bit_mask = 1u8 << (idx % 8);
            if empty {
                self.mod_data[byte_offset] &= !bit_mask;
            } else {
                self.mod_data[byte_offset] |= bit_mask;
            }
            Ok(())
        }

        fn get_mod_data(&self) -> io::Result<Vec<u8>> {
            Ok(self.mod_data.clone())
        }
    }

    #[test]
    fn test_change_map_file_object_safety() {
        let mut map: Box<dyn ChangeMapFile> =
            Box::new(MockChangeMapFile { target_file_id: 42, mod_data: vec![0u8; 2], aborted: false });

        let matching = MockTargetFile { file_id: 42 };
        let other = MockTargetFile { file_id: 7 };
        assert!(map.is_valid_for(&matching));
        assert!(!map.is_valid_for(&other));

        map.buffer_changed(3, false).unwrap();
        assert_eq!(map.get_mod_data().unwrap(), vec![0b0000_1000, 0]);

        map.buffer_changed(3, true).unwrap();
        assert_eq!(map.get_mod_data().unwrap(), vec![0, 0]);

        map.close().unwrap();
        map.abort();
    }
}
