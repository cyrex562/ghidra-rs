use std::io;

use crate::framework::store::FolderItem;

/// Corresponds to a private serialized data file within a FileSystem. Methods are provided for
/// opening the underlying file as an input or output stream.
///
/// Mirrors `ghidra.framework.store.DataFileItem`, which extends `FolderItem`.
///
/// NOTE: The use of DataFile is not encouraged and is not fully supported.
pub trait DataFileItem: FolderItem {
    /// Opens the current version of this item for reading.
    ///
    /// # Errors
    /// Returns an `io::Error` (a `NotFound` error if the underlying file does not exist) or
    /// another IO error.
    fn get_input_stream(&self) -> io::Result<Box<dyn io::Read>>;

    /// Opens a new version of this item for writing.
    ///
    /// # Errors
    /// Returns an `io::Error` (a `NotFound` error if the underlying file does not exist) or
    /// another IO error.
    fn get_output_stream(&self) -> io::Result<Box<dyn io::Write>>;

    /// Opens a specific version of this item for reading.
    ///
    /// # Errors
    /// Returns an `io::Error` (a `NotFound` error if the underlying file does not exist) or
    /// another IO error.
    fn get_input_stream_for_version(&self, version: i32) -> io::Result<Box<dyn io::Read>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::{Cursor, Read as _, Write as _};

    struct MockDataFileItem {
        versions: RefCell<Vec<Vec<u8>>>,
    }

    impl FolderItem for MockDataFileItem {
        fn get_name(&self) -> String {
            "MockDataFileItem".to_string()
        }

        fn get_file_id(&self) -> Option<String> {
            None
        }

        fn reset_file_id(&mut self) -> io::Result<String> {
            Ok("new-file-id".to_string())
        }

        fn length(&self) -> io::Result<i64> {
            Ok(self.versions.borrow().last().map_or(0, |v| v.len() as i64))
        }

        fn get_content_type(&self) -> String {
            "DataFile".to_string()
        }

        fn get_parent_path(&self) -> String {
            "/".to_string()
        }

        fn get_path_name(&self) -> String {
            "/MockDataFileItem".to_string()
        }

        fn is_read_only(&self) -> bool {
            false
        }

        fn set_read_only(&mut self, _state: bool) -> io::Result<()> {
            Ok(())
        }

        fn get_content_type_version(&self) -> i32 {
            1
        }

        fn set_content_type_version(&mut self, _version: i32) -> io::Result<()> {
            Ok(())
        }

        fn last_modified(&self) -> i64 {
            0
        }

        fn get_current_version(&self) -> i32 {
            self.versions.borrow().len() as i32
        }

        fn is_checked_out(&self) -> bool {
            false
        }

        fn is_checked_out_exclusive(&self) -> bool {
            false
        }

        fn is_versioned(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_checkout_id(&self) -> io::Result<i64> {
            Ok(crate::framework::store::folder_item::DEFAULT_CHECKOUT_ID)
        }

        fn get_checkout_version(&self) -> io::Result<i32> {
            Ok(-1)
        }

        fn get_local_checkout_version(&self) -> i32 {
            -1
        }

        fn set_checkout(
            &mut self,
            _checkout_id: i64,
            _exclusive: bool,
            _checkout_version: i32,
            _local_version: i32,
        ) -> io::Result<()> {
            Ok(())
        }

        fn clear_checkout(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn delete(&mut self, _version: i32, _user: &str) -> io::Result<()> {
            Ok(())
        }

        fn get_versions(&self) -> io::Result<Option<Vec<crate::framework::store::ItemVersion>>> {
            Ok(None)
        }

        fn checkout(
            &mut self,
            _checkout_type: &dyn crate::framework::store::checkout_type::CheckoutType,
            _user: &str,
            _project_path: &str,
        ) -> io::Result<Option<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not versioned"))
        }

        fn terminate_checkout(&mut self, _checkout_id: i64, _notify: bool) -> io::Result<()> {
            Ok(())
        }

        fn has_checkouts(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn can_recover(&self) -> bool {
            false
        }

        fn get_checkout(
            &self,
            _checkout_id: i64,
        ) -> io::Result<Option<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Ok(None)
        }

        fn get_checkouts(
            &self,
        ) -> io::Result<Vec<Box<dyn crate::framework::seam_stubs::ItemCheckoutStatus>>> {
            Ok(Vec::new())
        }

        fn is_checkin_active(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn update_checkout_version(
            &mut self,
            _checkout_id: i64,
            _checkout_version: i32,
            _user: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn output(
            &self,
            _output_file: &std::path::Path,
            _version: i32,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), crate::framework::store::local::OutputItemError> {
            Ok(())
        }

        fn refresh(&mut self) -> io::Result<Option<Box<dyn FolderItem>>> {
            Ok(None)
        }
    }

    impl DataFileItem for MockDataFileItem {
        fn get_input_stream(&self) -> io::Result<Box<dyn io::Read>> {
            match self.versions.borrow().last() {
                Some(data) => Ok(Box::new(Cursor::new(data.clone()))),
                None => Err(io::Error::new(io::ErrorKind::NotFound, "no data written yet")),
            }
        }

        fn get_output_stream(&self) -> io::Result<Box<dyn io::Write>> {
            self.versions.borrow_mut().push(Vec::new());
            let index = self.versions.borrow().len() - 1;
            Ok(Box::new(MockOutputStream {
                versions: &self.versions,
                index,
            }))
        }

        fn get_input_stream_for_version(&self, version: i32) -> io::Result<Box<dyn io::Read>> {
            let versions = self.versions.borrow();
            match versions.get(version as usize) {
                Some(data) => Ok(Box::new(Cursor::new(data.clone()))),
                None => Err(io::Error::new(io::ErrorKind::NotFound, "version not found")),
            }
        }
    }

    struct MockOutputStream<'a> {
        versions: &'a RefCell<Vec<Vec<u8>>>,
        index: usize,
    }

    impl io::Write for MockOutputStream<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.versions.borrow_mut()[self.index].extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_missing_data_file_reports_not_found() {
        let item = MockDataFileItem {
            versions: RefCell::new(Vec::new()),
        };
        let err = item.get_input_stream().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_object_safety_and_write_read_roundtrip() {
        let item: Box<dyn DataFileItem> = Box::new(MockDataFileItem {
            versions: RefCell::new(Vec::new()),
        });

        {
            let mut out = item.get_output_stream().unwrap();
            out.write_all(b"hello world").unwrap();
        }

        let mut buf = String::new();
        item.get_input_stream().unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello world");
        assert_eq!(item.get_current_version(), 1);
    }

    #[test]
    fn test_get_input_stream_for_version_selects_correct_version() {
        let item: Box<dyn DataFileItem> = Box::new(MockDataFileItem {
            versions: RefCell::new(Vec::new()),
        });

        item.get_output_stream().unwrap().write_all(b"v0").unwrap();
        item.get_output_stream().unwrap().write_all(b"v1").unwrap();

        let mut buf = String::new();
        item.get_input_stream_for_version(0)
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        assert_eq!(buf, "v0");

        assert!(item.get_input_stream_for_version(5).is_err());
    }
}
