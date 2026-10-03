//! Port of `ghidra.framework.main.datatree.CheckoutInfo`.
//!
//! Java:
//!
//! ```java
//! class CheckoutInfo {
//!     private DomainFile file;
//!     private ItemCheckoutStatus status;
//!
//!     CheckoutInfo(DomainFile file) throws IOException {
//!         this.file = file;
//!         this.status = file.getCheckoutStatus();
//!     }
//!
//!     DomainFile getFile() {
//!         return file;
//!     }
//!
//!     ItemCheckoutStatus getStatus() {
//!         return status;
//!     }
//! }
//! ```
//!
//! A small, package-private (no Java `public` modifier) value holder pairing a checked-out
//! [`DomainFile`] with its [`ItemCheckoutStatus`] snapshot, as obtained at construction time via
//! `DomainFile.getCheckoutStatus()`. Since that Java class is package-private, this port is
//! `pub(crate)`, matching its real visibility.
//!
//! `DomainFile.getCheckoutStatus()` can return `null` in Java when the file has no checkout
//! status; this port's [`DomainFile::get_checkout_status`] already models that as `Option`, so
//! `status` here is `Option<Box<dyn ItemCheckoutStatus>>` rather than a bare (implicitly
//! nullable) value.

use std::io;

use crate::framework::model::DomainFile;
use crate::framework::seam_stubs::ItemCheckoutStatus;

/// Port of `ghidra.framework.main.datatree.CheckoutInfo`.
pub(crate) struct CheckoutInfo {
    file: Box<dyn DomainFile>,
    status: Option<Box<dyn ItemCheckoutStatus>>,
}

impl CheckoutInfo {
    /// `CheckoutInfo(DomainFile)`.
    ///
    /// # Errors
    /// Propagates any `io::Error` from `file.get_checkout_status()`, mirroring the Java
    /// constructor's `throws IOException`.
    pub(crate) fn new(file: Box<dyn DomainFile>) -> io::Result<Self> {
        let status = file.get_checkout_status()?;
        Ok(Self { file, status })
    }

    /// `getFile()`.
    pub(crate) fn get_file(&self) -> &dyn DomainFile {
        self.file.as_ref()
    }

    /// `getStatus()`.
    pub(crate) fn get_status(&self) -> Option<&dyn ItemCheckoutStatus> {
        self.status.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockItemCheckoutStatus;
    impl ItemCheckoutStatus for MockItemCheckoutStatus {}

    struct MockDomainFile {
        name: String,
        status_result: fn() -> io::Result<Option<Box<dyn ItemCheckoutStatus>>>,
    }

    impl DomainFile for MockDomainFile {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_checkout_status(&self) -> io::Result<Option<Box<dyn ItemCheckoutStatus>>> {
            (self.status_result)()
        }
    }

    #[test]
    fn new_captures_file_and_none_status() {
        let file = Box::new(MockDomainFile {
            name: "foo.exe".to_string(),
            status_result: || Ok(None),
        });
        let info = CheckoutInfo::new(file).expect("should not fail");
        assert_eq!(info.get_file().get_name(), "foo.exe");
        assert!(info.get_status().is_none());
    }

    #[test]
    fn new_captures_file_and_some_status() {
        let file = Box::new(MockDomainFile {
            name: "bar.exe".to_string(),
            status_result: || Ok(Some(Box::new(MockItemCheckoutStatus))),
        });
        let info = CheckoutInfo::new(file).expect("should not fail");
        assert_eq!(info.get_file().get_name(), "bar.exe");
        assert!(info.get_status().is_some());
    }

    #[test]
    fn new_propagates_io_error_from_get_checkout_status() {
        // Mirrors the Java constructor's `throws IOException`: a failure fetching the checkout
        // status must fail construction rather than be swallowed.
        let file = Box::new(MockDomainFile {
            name: "baz.exe".to_string(),
            status_result: || Err(io::Error::new(io::ErrorKind::Other, "boom")),
        });
        let result = CheckoutInfo::new(file);
        match result {
            Err(e) => assert_eq!(e.to_string(), "boom"),
            Ok(_) => panic!("expected an io::Error, got Ok"),
        }
    }

    #[test]
    fn get_file_and_get_status_are_simple_accessors() {
        let file = Box::new(MockDomainFile {
            name: "quux.exe".to_string(),
            status_result: || Ok(Some(Box::new(MockItemCheckoutStatus))),
        });
        let info = CheckoutInfo::new(file).unwrap();
        assert_eq!(info.get_file().get_name(), "quux.exe");
        assert!(info.get_status().is_some());
    }
}
