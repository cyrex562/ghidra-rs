use std::sync::Arc;

use crate::framework::model::domain_object::{DomainObject, DomainObjectConsumer};
use crate::framework::model::domain_file::DomainFile;

/// Provides a RAII wrapper for opened domain objects, automatically releasing them when dropped.
///
/// Temporarily opens a domain object from a domain file, maintaining a consumer reference for
/// resource management. The domain object is released (returned to the file's cache) when this
/// wrapper is dropped.
///
/// Java equivalent: `ghidra.app.plugin.core.debug.service.modules.PeekOpenedDomainObject`
pub struct PeekOpenedDomainObject {
    object: Option<Box<dyn DomainObject>>,
    consumer: Option<DomainObjectConsumer>,
}

impl PeekOpenedDomainObject {
    /// Creates a new `PeekOpenedDomainObject`, retrieving the opened domain object from the file.
    ///
    /// The consumer token used internally is derived from the object itself (represented as an
    /// Arc wrapping a unit value), following the Java pattern where the object acts as its own
    /// consumer for resource tracking.
    pub fn new(domain_file: &dyn DomainFile) -> Self {
        let consumer: DomainObjectConsumer = Arc::new(());
        let object = domain_file.get_opened_domain_object(consumer.clone());
        PeekOpenedDomainObject {
            object,
            consumer: Some(consumer),
        }
    }

    /// Returns a reference to the opened domain object, if one exists.
    pub fn get_object(&self) -> Option<&dyn DomainObject> {
        self.object.as_ref().map(|b| b.as_ref())
    }

    /// Consumes this wrapper and returns the domain object without releasing it.
    ///
    /// The caller becomes responsible for releasing the object via [`DomainObject::release`].
    pub fn into_object(mut self) -> Option<Box<dyn DomainObject>> {
        self.consumer = None;
        self.object.take()
    }
}

impl Drop for PeekOpenedDomainObject {
    fn drop(&mut self) {
        if let (Some(ref mut obj), Some(ref consumer)) = (&mut self.object, &self.consumer) {
            obj.release(consumer.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockDomainObject {
        released: Arc<AtomicBool>,
    }

    impl DomainObject for MockDomainObject {
        fn release(&mut self, _consumer: DomainObjectConsumer) {
            self.released.store(true, Ordering::SeqCst);
        }

        fn is_closed(&self) -> bool {
            self.released.load(Ordering::SeqCst)
        }
    }

    struct MockDomainFile {
        released: Option<Arc<AtomicBool>>,
    }

    impl DomainFile for MockDomainFile {
        fn get_opened_domain_object(
            &self,
            _consumer: DomainObjectConsumer,
        ) -> Option<Box<dyn DomainObject>> {
            self.released.as_ref().map(|flag| {
                Box::new(MockDomainObject {
                    released: flag.clone(),
                }) as Box<dyn DomainObject>
            })
        }
    }

    #[test]
    fn new_returns_wrapper_with_object() {
        let file = MockDomainFile {
            released: Some(Arc::new(AtomicBool::new(false))),
        };
        let wrapper = PeekOpenedDomainObject::new(&file);
        assert!(wrapper.get_object().is_some());
    }

    #[test]
    fn new_returns_wrapper_without_object_when_none_available() {
        let file = MockDomainFile { released: None };
        let wrapper = PeekOpenedDomainObject::new(&file);
        assert!(wrapper.get_object().is_none());
    }

    #[test]
    fn get_object_returns_reference() {
        let released_flag = Arc::new(AtomicBool::new(false));
        let file = MockDomainFile {
            released: Some(released_flag.clone()),
        };
        let wrapper = PeekOpenedDomainObject::new(&file);
        assert!(wrapper.get_object().is_some());
        let obj = wrapper.get_object().unwrap();
        assert!(!obj.is_closed());
    }

    #[test]
    fn drop_releases_object() {
        let released_flag = Arc::new(AtomicBool::new(false));
        let file = MockDomainFile {
            released: Some(released_flag.clone()),
        };
        {
            let _wrapper = PeekOpenedDomainObject::new(&file);
        }
        assert!(released_flag.load(Ordering::SeqCst));
    }

    #[test]
    fn into_object_returns_object_without_releasing() {
        let released_flag = Arc::new(AtomicBool::new(false));
        let file = MockDomainFile {
            released: Some(released_flag.clone()),
        };
        let wrapper = PeekOpenedDomainObject::new(&file);
        let _obj = wrapper.into_object();
        assert!(!released_flag.load(Ordering::SeqCst));
    }

    #[test]
    fn drop_noop_when_object_is_none() {
        let file = MockDomainFile { released: None };
        let _wrapper = PeekOpenedDomainObject::new(&file);
    }
}
