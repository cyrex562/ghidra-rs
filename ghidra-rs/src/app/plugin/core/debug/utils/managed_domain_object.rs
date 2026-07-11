use std::sync::Arc;

use crate::framework::model::domain_file::OpenDomainObjectError;
use crate::framework::model::{DomainFile, DomainObject, DomainObjectConsumer};
use crate::util::task::TaskMonitor;

/// Manages the lifecycle of a domain object, automatically releasing it when dropped.
///
/// Port of `ghidra.app.plugin.core.debug.utils.ManagedDomainObject`.
/// This provides RAII-style resource management for domain objects, ensuring they are properly
/// released when the managed object is dropped.
pub struct ManagedDomainObject {
    obj: Option<Box<dyn DomainObject>>,
    consumer: DomainObjectConsumer,
}

impl ManagedDomainObject {
    /// Creates a new managed domain object by opening the file.
    ///
    /// # Arguments
    /// * `file` - The domain file to open
    /// * `ok_to_upgrade` - Whether upgrade is permitted if needed
    /// * `ok_to_recover` - Whether recovery is permitted if needed
    /// * `monitor` - Task monitor for progress reporting
    ///
    /// # Errors
    /// Returns an error if the domain object cannot be opened due to version issues, I/O errors,
    /// or cancellation.
    pub fn new(
        file: &dyn DomainFile,
        ok_to_upgrade: bool,
        ok_to_recover: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Self, OpenDomainObjectError> {
        let consumer: DomainObjectConsumer = Arc::new(ManagedDomainObjectConsumer);

        let obj = file.get_domain_object(
            Arc::clone(&consumer),
            ok_to_upgrade,
            ok_to_recover,
            monitor,
        )?;

        Ok(ManagedDomainObject {
            obj: Some(obj),
            consumer,
        })
    }

    /// Returns a reference to the managed domain object.
    ///
    /// # Errors
    /// Returns an error string if the domain object has been released (closed).
    pub fn get(&self) -> Result<&dyn DomainObject, String> {
        self.obj.as_ref()
            .map(|obj| obj.as_ref())
            .ok_or_else(|| "Domain object is closed".to_string())
    }
}

impl Drop for ManagedDomainObject {
    fn drop(&mut self) {
        if let Some(mut obj) = self.obj.take() {
            obj.release(Arc::clone(&self.consumer));
        }
    }
}

/// Identity token used as the consumer for domain object operations.
struct ManagedDomainObjectConsumer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::domain_file::OpenDomainObjectError;

    struct MockDomainFile;

    impl DomainFile for MockDomainFile {
        fn get_domain_object(
            &self,
            _consumer: DomainObjectConsumer,
            _ok_to_upgrade: bool,
            _ok_to_recover: bool,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn DomainObject>, OpenDomainObjectError> {
            Ok(Box::new(MockDomainObject))
        }
    }

    struct MockDomainObject;

    impl DomainObject for MockDomainObject {
        fn release(&mut self, _consumer: DomainObjectConsumer) {}
    }

    #[test]
    fn create_managed_domain_object() {
        let file = MockDomainFile;
        let monitor = crate::util::task::DummyMonitor;

        let result = ManagedDomainObject::new(
            &file,
            false,
            false,
            &monitor,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn get_returns_domain_object() {
        let file = MockDomainFile;
        let monitor = crate::util::task::DummyMonitor;

        let managed = ManagedDomainObject::new(
            &file,
            false,
            false,
            &monitor,
        ).unwrap();

        assert!(managed.get().is_ok());
    }

    #[test]
    fn drop_releases_object() {
        let file = MockDomainFile;
        let monitor = crate::util::task::DummyMonitor;

        let managed = ManagedDomainObject::new(
            &file,
            false,
            false,
            &monitor,
        ).unwrap();

        drop(managed);
    }
}
