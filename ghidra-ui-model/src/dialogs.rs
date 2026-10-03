//! Rust-described dialogs (spec §3: no domain logic in the renderer): a
//! [`DialogModel`] says what its dialog shows ([`DialogSpec`]) and decides
//! what OK does; the renderer draws the spec and reports OK/Cancel.

/// A check box in a dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckSpec {
    /// Stable key reported back on OK.
    pub key: String,
    /// Label.
    pub label: String,
    /// Tooltip (may be empty).
    pub tooltip: String,
    /// Checked.
    pub checked: bool,
}

/// An editable combo box (text plus history entries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComboSpec {
    /// Current text.
    pub text: String,
    /// Drop-down entries, first shown first.
    pub items: Vec<String>,
}

/// An extra dialog button (OK and Cancel are always present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ButtonSpec {
    /// Stable key passed to [`DialogModel::button`].
    pub key: String,
    /// Label.
    pub label: String,
    /// Ask the user with this text first (renderer yes/no), if set.
    pub confirm: Option<String>,
}

/// Everything a dialog shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DialogSpec {
    /// Window title.
    pub title: String,
    /// Message above the inputs.
    pub message: String,
    /// The text input, if any.
    pub combo: Option<ComboSpec>,
    /// Check boxes below it.
    pub checks: Vec<CheckSpec>,
    /// Status line (errors, "No results for ...").
    pub status: String,
    /// Extra buttons beside OK/Cancel.
    pub buttons: Vec<ButtonSpec>,
    /// Shows a tree pane beside a form pane ([`DialogModel::panes`]).
    pub has_panes: bool,
}

/// What OK did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogReply {
    /// The dialog is done.
    Close,
    /// Keep it open and show this spec (status message, new history...).
    Stay(DialogSpec),
}

/// A dialog's behaviour.
pub trait DialogModel: Send {
    /// What to show now.
    fn spec(&self) -> DialogSpec;
    /// OK with the combo text and each check box's state.
    fn ok(&mut self, text: &str, checks: &[(String, bool)]) -> DialogReply;
    /// Cancel / escape.
    fn cancel(&mut self) {}
    /// One of the spec's extra buttons was pressed.
    fn button(&mut self, _key: &str) -> DialogReply {
        DialogReply::Stay(self.spec())
    }
    /// The tree and form panes' view models (shared with this dialog's state).
    fn panes(&self) -> Option<(Box<dyn crate::view_models::TreeModel>, Box<dyn crate::view_models::FormModel>)> {
        None
    }
}

/// Open dialogs by id.
#[derive(Default)]
pub struct Dialogs {
    next_id: u64,
    open: std::collections::BTreeMap<u64, Box<dyn DialogModel>>,
}

impl Dialogs {
    /// Registers an open dialog; returns its id.
    pub fn open(&mut self, model: Box<dyn DialogModel>) -> u64 {
        self.next_id += 1;
        self.open.insert(self.next_id, model);
        self.next_id
    }

    /// The spec of open dialog `id`.
    pub fn spec(&self, id: u64) -> Result<DialogSpec, String> {
        self.open.get(&id).map(|m| m.spec()).ok_or_else(|| format!("no open dialog {id}"))
    }

    /// OK on dialog `id`; a `Close` reply forgets it.
    pub fn ok(&mut self, id: u64, text: &str, checks: &[(String, bool)]) -> Result<DialogReply, String> {
        let model = self.open.get_mut(&id).ok_or_else(|| format!("no open dialog {id}"))?;
        let reply = model.ok(text, checks);
        if reply == DialogReply::Close {
            self.open.remove(&id);
        }
        Ok(reply)
    }

    /// Dialog `id`'s pane view models.
    pub fn panes(
        &self,
        id: u64,
    ) -> Result<Option<(Box<dyn crate::view_models::TreeModel>, Box<dyn crate::view_models::FormModel>)>, String> {
        self.open.get(&id).map(|m| m.panes()).ok_or_else(|| format!("no open dialog {id}"))
    }

    /// Removes dialog `id` so its model can run without the registry locked.
    pub fn take(&mut self, id: u64) -> Option<Box<dyn DialogModel>> {
        self.open.remove(&id)
    }

    /// Puts a taken dialog back under its id.
    pub fn put_back(&mut self, id: u64, model: Box<dyn DialogModel>) {
        self.open.insert(id, model);
    }

    /// Cancel on dialog `id` (forgets it).
    pub fn cancel(&mut self, id: u64) -> Result<(), String> {
        let mut model = self.open.remove(&id).ok_or_else(|| format!("no open dialog {id}"))?;
        model.cancel();
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Closes on "yes", otherwise stays with a status.
    pub(crate) struct YesDialog(pub std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl DialogModel for YesDialog {
        fn spec(&self) -> DialogSpec {
            DialogSpec { title: "Q".into(), message: "Say yes".into(), ..DialogSpec::default() }
        }
        fn ok(&mut self, text: &str, _checks: &[(String, bool)]) -> DialogReply {
            self.0.lock().unwrap().push(text.to_owned());
            if text == "yes" {
                DialogReply::Close
            } else {
                DialogReply::Stay(DialogSpec { status: format!("not {text}"), ..self.spec() })
            }
        }
        fn cancel(&mut self) {
            self.0.lock().unwrap().push("<cancel>".into());
        }
    }

    #[test]
    fn ok_stays_until_the_model_closes_then_the_id_is_gone() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut d = Dialogs::default();
        let id = d.open(Box::new(YesDialog(log.clone())));
        assert_eq!(d.spec(id).unwrap().message, "Say yes");
        match d.ok(id, "no", &[]).unwrap() {
            DialogReply::Stay(s) => assert_eq!(s.status, "not no"),
            other => panic!("{other:?}"),
        }
        assert_eq!(d.ok(id, "yes", &[]).unwrap(), DialogReply::Close);
        assert!(d.spec(id).is_err());
        assert!(d.ok(id, "yes", &[]).is_err());
        assert_eq!(*log.lock().unwrap(), vec!["no", "yes"]);
    }

    #[test]
    fn cancel_forgets_the_dialog_and_tells_the_model() {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut d = Dialogs::default();
        let a = d.open(Box::new(YesDialog(log.clone())));
        let b = d.open(Box::new(YesDialog(log.clone())));
        assert_ne!(a, b);
        d.cancel(a).unwrap();
        assert!(d.cancel(a).is_err());
        assert!(d.spec(b).is_ok());
        assert_eq!(*log.lock().unwrap(), vec!["<cancel>"]);
    }
}
