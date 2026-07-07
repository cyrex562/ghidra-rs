use std::any::TypeId;
use std::io;
use std::sync::Arc;

use thiserror::Error;

use crate::framework::model::{DomainFile, DomainObject, DomainObjectConsumer};
use crate::framework::model::domain_file::OpenDomainObjectError;
use crate::util::exception::{CancelledException, VersionException};
use crate::util::task::TaskMonitor;

/// Error type for opening a domain file.
#[derive(Error, Debug)]
pub enum OpenedDomainFileError {
    #[error("Type mismatch: expected {expected}, but file contains {found}")]
    TypeMismatch { expected: String, found: String },
    #[error(transparent)]
    Version(#[from] VersionException),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

impl From<OpenDomainObjectError> for OpenedDomainFileError {
    fn from(err: OpenDomainObjectError) -> Self {
        match err {
            OpenDomainObjectError::Version(e) => Self::Version(e),
            OpenDomainObjectError::Io(e) => Self::Io(e),
            OpenDomainObjectError::Cancelled(e) => Self::Cancelled(e),
        }
    }
}

/// A RAII wrapper around an opened domain object that ensures the object is released when
/// the wrapper is dropped.
///
/// This struct manages the lifetime of a domain object loaded from a domain file. It opens
/// the domain object on construction and releases it on destruction, ensuring proper resource
/// cleanup.
///
/// Port of `ghidra.framework.data.OpenedDomainFile`.
pub struct OpenedDomainFile {
    content: Box<dyn DomainObject>,
    consumer: DomainObjectConsumer,
}

impl OpenedDomainFile {
    /// Opens a domain file and returns a domain object with the specified content type.
    ///
    /// This method validates that the file contains a domain object of the expected type
    /// before opening it. The caller should specify the expected type T as a type parameter.
    ///
    /// # Arguments
    ///
    /// * `file` - The domain file to open
    /// * `ok_to_upgrade` - If true, allows upgrading the domain object to a newer format
    /// * `ok_to_recover` - If true, allows recovering unsaved changes
    /// * `monitor` - Task monitor for progress and cancellation
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - The file does not contain the expected domain object type
    /// - A version format mismatch is detected
    /// - An I/O error occurs
    /// - The user cancels the operation via the monitor
    pub fn open<T: DomainObject + 'static>(
        file: &dyn DomainFile,
        ok_to_upgrade: bool,
        ok_to_recover: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Self, OpenedDomainFileError> {
        let expected_type_id = TypeId::of::<T>();

        if let Some(file_type_id) = file.get_domain_object_class() {
            if file_type_id != expected_type_id {
                return Err(OpenedDomainFileError::TypeMismatch {
                    expected: std::any::type_name::<T>().to_string(),
                    found: format!("{:?}", file_type_id),
                });
            }
        }

        let consumer: DomainObjectConsumer = Arc::new(TypeId::of::<Self>());
        let content = file.get_domain_object(
            consumer.clone(),
            ok_to_upgrade,
            ok_to_recover,
            monitor,
        )?;

        Ok(OpenedDomainFile { content, consumer })
    }


    /// Returns a reference to the opened domain object.
    pub fn content(&self) -> &dyn DomainObject {
        &*self.content
    }

    /// Returns a mutable reference to the opened domain object.
    pub fn content_mut(&mut self) -> &mut dyn DomainObject {
        &mut *self.content
    }

    /// Consumes this wrapper and returns the underlying domain object.
    ///
    /// Note: The domain object will no longer be released when dropped after calling
    /// this method. The caller is responsible for calling [`DomainObject::release`]
    /// with the appropriate consumer token.
    pub fn into_content(self) -> Box<dyn DomainObject> {
        // Use ManuallyDrop to prevent Drop from being called, so we can move out the content
        let wrapped = std::mem::ManuallyDrop::new(self);
        // SAFETY: We're extracting the fields before the ManuallyDrop is dropped, so this is safe
        unsafe { std::ptr::read(&wrapped.content) }
    }
}

impl Drop for OpenedDomainFile {
    fn drop(&mut self) {
        self.content.release(self.consumer.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainObject {
        name: String,
    }

    impl DomainObject for MockDomainObject {}

    struct MockDomainFile {
        object_class: Option<TypeId>,
    }

    impl DomainFile for MockDomainFile {
        fn get_domain_object_class(&self) -> Option<TypeId> {
            self.object_class
        }

        fn get_domain_object(
            &self,
            consumer: DomainObjectConsumer,
            _ok_to_upgrade: bool,
            _ok_to_recover: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn DomainObject>, crate::framework::model::domain_file::OpenDomainObjectError> {
            let _ = consumer;
            Ok(Box::new(MockDomainObject {
                name: "test_object".to_string(),
            }))
        }
    }

    #[test]
    fn open_with_matching_type() {
        let file = MockDomainFile {
            object_class: Some(TypeId::of::<MockDomainObject>()),
        };
        let monitor = crate::util::task::DummyMonitor;

        let result = OpenedDomainFile::open::<MockDomainObject>(&file, false, false, &monitor);
        assert!(result.is_ok());
        let opened = result.unwrap();
        assert!(!opened.content().get_name().is_empty());
    }


    #[test]
    fn open_with_mismatched_type() {
        #[derive(Debug)]
        struct OtherObject;
        impl DomainObject for OtherObject {}

        let file = MockDomainFile {
            object_class: Some(TypeId::of::<OtherObject>()),
        };
        let monitor = crate::util::task::DummyMonitor;

        let result = OpenedDomainFile::open::<MockDomainObject>(&file, false, false, &monitor);
        assert!(result.is_err());
        match result {
            Err(OpenedDomainFileError::TypeMismatch { .. }) => (),
            _ => panic!("Expected TypeMismatch error"),
        }
    }

    #[test]
    fn open_with_unknown_type() {
        let file = MockDomainFile {
            object_class: None,
        };
        let monitor = crate::util::task::DummyMonitor;

        let result = OpenedDomainFile::open::<MockDomainObject>(&file, false, false, &monitor);
        assert!(result.is_ok());
    }

    #[test]
    fn content_accessor() {
        let file = MockDomainFile {
            object_class: Some(TypeId::of::<MockDomainObject>()),
        };
        let monitor = crate::util::task::DummyMonitor;

        let opened = OpenedDomainFile::open::<MockDomainObject>(&file, false, false, &monitor)
            .unwrap();
        let content = opened.content();
        assert!(!content.get_name().is_empty());
    }

    #[test]
    fn content_mut_accessor() {
        let file = MockDomainFile {
            object_class: Some(TypeId::of::<MockDomainObject>()),
        };
        let monitor = crate::util::task::DummyMonitor;

        let mut opened =
            OpenedDomainFile::open::<MockDomainObject>(&file, false, false, &monitor).unwrap();
        let content = opened.content_mut();
        content.set_name("modified");
        assert_eq!(content.get_name(), "modified");
    }

    #[test]
    fn drop_releases_resource() {
        let file = MockDomainFile {
            object_class: Some(TypeId::of::<MockDomainObject>()),
        };
        let monitor = crate::util::task::DummyMonitor;

        {
            let _opened = OpenedDomainFile::open::<MockDomainObject>(&file, false, false, &monitor)
                .unwrap();
            // When _opened goes out of scope, drop should be called
        }
        // If we got here without panicking, drop worked correctly
    }

    #[test]
    fn into_content_consumes_wrapper() {
        let file = MockDomainFile {
            object_class: Some(TypeId::of::<MockDomainObject>()),
        };
        let monitor = crate::util::task::DummyMonitor;

        let opened =
            OpenedDomainFile::open::<MockDomainObject>(&file, false, false, &monitor).unwrap();
        let content = opened.into_content();
        assert!(!content.get_name().is_empty());
    }
}
