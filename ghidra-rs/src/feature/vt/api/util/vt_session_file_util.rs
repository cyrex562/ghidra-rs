//! Port of `ghidra.feature.vt.api.util.VTSessionFileUtil`.
//!
//! Provides functions for checking `VTSessionDB` source and destination program files prior to
//! being opened and used during session instantiation. The Java type is a statics-only utility
//! class (private constructor, no instance state); this port represents that directly as a
//! module of free functions rather than a field-less struct.

use std::any::TypeId;
use std::io;

use crate::feature::seam_stubs::CheckoutDialog;
use crate::framework::model::domain_file::{DomainFile, IoCancelledError};
use crate::program::database::program_db::ProgramDB;
use crate::util::msg::Msg;
use crate::util::system_utilities::SystemUtilities;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// Validates a VT source program to ensure it meets minimum criteria to open with a VT session.
///
/// The following validation check is performed:
/// - file must correspond to a `ProgramDB`
///
/// Port of `VTSessionFileUtil.validateSourceProgramFile`. If an error is returned it is intended
/// to be augmented for proper presentation by the caller.
///
/// # Arguments
/// * `file` - VT session source program domain file
/// * `include_file_path_in_error` - if true, the file path is appended to the returned error
pub fn validate_source_program_file(
    file: &dyn DomainFile,
    include_file_path_in_error: bool,
) -> io::Result<()> {
    if file.get_domain_object_class() != Some(TypeId::of::<ProgramDB>()) {
        return Err(invalid_argument(
            "Source file does not correspond to a Program",
            file,
            include_file_path_in_error,
        ));
    }
    Ok(())
}

/// Validates a VT destination program to ensure it meets minimum criteria to open with a VT
/// session.
///
/// GUI mode only: if `file` is versioned and not checked-out the user may be prompted to perform
/// an optional checkout of the file. Prompting for checkout will not occur if `silent` is true —
/// this should be true if a filesystem lock is currently held.
///
/// The following validation checks are performed:
/// - file must correspond to a `ProgramDB`
/// - file must be contained within the active project
/// - file must not be marked read-only
/// - if file is versioned it must be checked-out (user may be prompted to do this)
///
/// Port of `VTSessionFileUtil.validateDestinationProgramFile`. If an error is returned it is
/// intended to be augmented for proper presentation by the caller.
///
/// # Arguments
/// * `file` - VT session destination program domain file
/// * `include_file_path_in_error` - if true, the file path is appended to the returned error
/// * `silent` - if user interaction should not be performed
pub fn validate_destination_program_file(
    file: &mut dyn DomainFile,
    include_file_path_in_error: bool,
    silent: bool,
) -> io::Result<()> {
    if file.get_domain_object_class() != Some(TypeId::of::<ProgramDB>()) {
        return Err(invalid_argument(
            "Destination file does not correspond to a Program",
            file,
            include_file_path_in_error,
        ));
    }

    let in_writable_project = file
        .get_parent()
        .is_some_and(|folder| folder.is_in_writable_project());
    if !in_writable_project {
        return Err(invalid_argument(
            "Destination file must be from active project",
            file,
            include_file_path_in_error,
        ));
    }

    if file.is_read_only() {
        return Err(invalid_argument(
            "Destination file must not be read-only",
            file,
            include_file_path_in_error,
        ));
    }

    if file.is_versioned() {
        if !silent {
            do_optional_destination_program_checkout(file);
        }
        if !file.is_checked_out() {
            return Err(invalid_argument(
                "Versioned destination file must be checked-out for update",
                file,
                include_file_path_in_error,
            ));
        }
    }

    Ok(())
}

/// Determines if the specified domain file will permit update.
///
/// Port of `VTSessionFileUtil.canUpdate`.
pub fn can_update(file: &dyn DomainFile) -> bool {
    let Some(folder) = file.get_parent() else {
        return false;
    };
    if !folder.is_in_writable_project() {
        return false;
    }
    if file.is_read_only() {
        return false;
    }
    if file.is_versioned() {
        return false;
    }
    true
}

fn invalid_argument(
    message: &str,
    file: &dyn DomainFile,
    include_file_path_in_error: bool,
) -> io::Error {
    let mut error = message.to_string();
    if include_file_path_in_error {
        error.push_str(":\n");
        error.push_str(&file.get_pathname());
    }
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

/// Port of the private `VTSessionFileUtil.doOptionalDestinationProgramCheckout` helper.
///
/// No-ops in headless mode or when the file cannot be checked out. Otherwise offers the user an
/// optional checkout via [`CheckoutDialog`]; if accepted, performs the checkout. This collapses
/// the original `Task`/`TaskLauncher` GUI dispatch (launching the checkout on a background
/// thread behind a progress dialog) into a direct synchronous call, since this port has no GUI
/// thread to dispatch onto.
fn do_optional_destination_program_checkout(file: &mut dyn DomainFile) {
    if SystemUtilities::is_in_headless_mode() || !file.can_checkout() {
        return;
    }

    let user = file
        .get_parent()
        .and_then(|folder| folder.get_project_data().get_user());
    let dialog = CheckoutDialog::new(file.get_pathname(), user);
    if dialog.show_dialog() == CheckoutDialog::CHECKOUT {
        checkout_destination_program(file, dialog.exclusive_checkout());
    }
}

/// Port of the private nested `VTSessionFileUtil.CheckoutDestinationProgramTask.run` body.
fn checkout_destination_program(file: &mut dyn DomainFile, exclusive_checkout: bool) {
    let monitor = DummyMonitor;
    monitor.set_message(&format!("Checking Out {}", file.get_pathname()));
    match file.checkout(exclusive_checkout, &monitor) {
        Ok(true) => {}
        Ok(false) => {
            Msg::show_error(
                "ProgramOpener",
                "Checkout Failed",
                &format!(
                    "Exclusive checkout failed for: {}\nOne or more users have file checked out!",
                    file.get_pathname()
                ),
            );
        }
        Err(IoCancelledError::Cancelled(_)) => {}
        Err(IoCancelledError::Io(e)) => {
            Msg::show_error(
                "ProgramOpener",
                "Checkout Failed",
                &format!("Checkout failed for: {}\n{}", file.get_pathname(), e),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::domain_folder::DomainFolder;

    /// Every [`DomainFile`]/[`DomainFolder`] method has a default implementation (see their
    /// trait docs), so these mocks only override the handful of methods these tests care about.
    struct MockDomainFile {
        domain_object_class: Option<TypeId>,
        parent: Option<MockDomainFolder>,
        read_only: bool,
        versioned: bool,
        checked_out: bool,
        pathname: String,
    }

    impl DomainFile for MockDomainFile {
        fn get_pathname(&self) -> String {
            self.pathname.clone()
        }
        fn get_domain_object_class(&self) -> Option<TypeId> {
            self.domain_object_class
        }
        fn get_parent(&self) -> Option<Box<dyn DomainFolder>> {
            self.parent
                .clone()
                .map(|folder| Box::new(folder) as Box<dyn DomainFolder>)
        }
        fn is_checked_out(&self) -> bool {
            self.checked_out
        }
        fn is_read_only(&self) -> bool {
            self.read_only
        }
        fn is_versioned(&self) -> bool {
            self.versioned
        }
    }

    #[derive(Clone)]
    struct MockDomainFolder {
        writable: bool,
    }

    impl DomainFolder for MockDomainFolder {
        fn is_in_writable_project(&self) -> bool {
            self.writable
        }
    }

    fn program_file(
        parent_writable: Option<bool>,
        read_only: bool,
        versioned: bool,
        checked_out: bool,
    ) -> MockDomainFile {
        MockDomainFile {
            domain_object_class: Some(TypeId::of::<ProgramDB>()),
            parent: parent_writable.map(|writable| MockDomainFolder { writable }),
            read_only,
            versioned,
            checked_out,
            pathname: "/vt/DestProgram".to_string(),
        }
    }

    #[test]
    fn validate_source_program_file_accepts_program_db() {
        let file = program_file(Some(true), false, false, false);
        assert!(validate_source_program_file(&file, false).is_ok());
    }

    #[test]
    fn validate_source_program_file_rejects_non_program() {
        let mut file = program_file(Some(true), false, false, false);
        file.domain_object_class = Some(TypeId::of::<String>());
        let err = validate_source_program_file(&file, true).unwrap_err();
        assert!(err.to_string().contains("Source file does not correspond to a Program"));
        assert!(err.to_string().contains("/vt/DestProgram"));
    }

    #[test]
    fn validate_destination_program_file_accepts_unversioned_writable_file() {
        let mut file = program_file(Some(true), false, false, false);
        assert!(validate_destination_program_file(&mut file, false, true).is_ok());
    }

    #[test]
    fn validate_destination_program_file_rejects_non_program() {
        let mut file = program_file(Some(true), false, false, false);
        file.domain_object_class = Some(TypeId::of::<String>());
        let err = validate_destination_program_file(&mut file, false, true).unwrap_err();
        assert!(err.to_string().contains("Destination file does not correspond to a Program"));
    }

    #[test]
    fn validate_destination_program_file_rejects_missing_parent() {
        let mut file = program_file(None, false, false, false);
        let err = validate_destination_program_file(&mut file, false, true).unwrap_err();
        assert!(err.to_string().contains("Destination file must be from active project"));
    }

    #[test]
    fn validate_destination_program_file_rejects_read_only_project() {
        let mut file = program_file(Some(false), false, false, false);
        let err = validate_destination_program_file(&mut file, false, true).unwrap_err();
        assert!(err.to_string().contains("Destination file must be from active project"));
    }

    #[test]
    fn validate_destination_program_file_rejects_read_only_file() {
        let mut file = program_file(Some(true), true, false, false);
        let err = validate_destination_program_file(&mut file, false, true).unwrap_err();
        assert!(err.to_string().contains("Destination file must not be read-only"));
    }

    #[test]
    fn validate_destination_program_file_rejects_versioned_not_checked_out_when_silent() {
        let mut file = program_file(Some(true), false, true, false);
        let err = validate_destination_program_file(&mut file, false, true).unwrap_err();
        assert!(err.to_string().contains("Versioned destination file must be checked-out for update"));
    }

    #[test]
    fn validate_destination_program_file_accepts_versioned_checked_out() {
        let mut file = program_file(Some(true), false, true, true);
        assert!(validate_destination_program_file(&mut file, false, true).is_ok());
    }

    #[test]
    fn can_update_accepts_unversioned_writable_file() {
        let file = program_file(Some(true), false, false, false);
        assert!(can_update(&file));
    }

    #[test]
    fn can_update_rejects_missing_parent() {
        let file = program_file(None, false, false, false);
        assert!(!can_update(&file));
    }

    #[test]
    fn can_update_rejects_read_only_project() {
        let file = program_file(Some(false), false, false, false);
        assert!(!can_update(&file));
    }

    #[test]
    fn can_update_rejects_read_only_file() {
        let file = program_file(Some(true), true, false, false);
        assert!(!can_update(&file));
    }

    #[test]
    fn can_update_rejects_versioned_file() {
        let file = program_file(Some(true), false, true, false);
        assert!(!can_update(&file));
    }
}
