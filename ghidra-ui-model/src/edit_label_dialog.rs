//! Java `AddEditDialog` as "Edit Label" opens it on a label: the name in an
//! editable combo; OK renames (Java `RenameLabelCmd`, USER_DEFINED).

use crate::dialogs::{ComboSpec, DialogModel, DialogReply, DialogSpec};

/// Renames the label; the error is shown as the dialog's status.
pub type Rename = Box<dyn FnMut(&str) -> Result<(), String> + Send>;

/// The "Edit Label at <address>" dialog.
pub struct EditLabelDialog {
    address: String,
    name: String,
    rename: Rename,
    status: String,
}

impl EditLabelDialog {
    /// Editing label `name` at `address` (as the listing shows it).
    pub fn new(address: impl Into<String>, name: impl Into<String>, rename: Rename) -> Self {
        Self { address: address.into(), name: name.into(), rename, status: String::new() }
    }
}

impl DialogModel for EditLabelDialog {
    fn spec(&self) -> DialogSpec {
        DialogSpec {
            title: format!("Edit Label at {}", self.address),
            message: "Enter Label:".into(),
            combo: Some(ComboSpec { text: self.name.clone(), items: vec![self.name.clone()] }),
            status: self.status.clone(),
            ..DialogSpec::default()
        }
    }

    fn ok(&mut self, text: &str, _checks: &[(String, bool)]) -> DialogReply {
        let name = text.trim();
        if name.is_empty() {
            self.status = "Name cannot be blank".into();
            return DialogReply::Stay(self.spec());
        }
        match (self.rename)(name) {
            Ok(()) => DialogReply::Close,
            Err(message) => {
                self.status = message;
                DialogReply::Stay(self.spec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn ok_renames_trimmed_and_failures_stay_with_the_status() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let mut d = EditLabelDialog::new(
            "00401000",
            "f",
            Box::new(move |n| {
                log.lock().unwrap().push(n.to_owned());
                if n == "taken" { Err("taken is already defined".into()) } else { Ok(()) }
            }),
        );
        assert_eq!(d.spec().title, "Edit Label at 00401000");
        match d.ok("taken", &[]) {
            DialogReply::Stay(s) => assert_eq!(s.status, "taken is already defined"),
            r => panic!("{r:?}"),
        }
        assert_eq!(d.ok("  g  ", &[]), DialogReply::Close);
        assert_eq!(*seen.lock().unwrap(), vec!["taken", "g"]);
    }
}
