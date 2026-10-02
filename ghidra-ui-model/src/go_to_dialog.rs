//! Port of `ghidra.app.util.navigation.GoToAddressLabelDialog`'s behaviour:
//! an editable combo with a newest-first history (default 10 entries),
//! "Case sensitive" and "Dynamic labels" options, and a status line. The
//! query itself is the GoToService's (`goToQuery`), injected as a closure;
//! label search arrives with symbols.

use std::sync::{Arc, Mutex, PoisonError};

use ghidra_rs::framework::options::g_properties::GPropertyValue;
use ghidra_rs::framework::options::save_state::SaveState;

use crate::dialogs::{CheckSpec, ComboSpec, DialogModel, DialogReply, DialogSpec};

/// Java `DEFAULT_MAX_GOTO_ENTRIES`.
pub const DEFAULT_MAX_GOTO_ENTRIES: usize = 10;
const CASE_SENSITIVE: &str = "case_sensitive";
const INCLUDE_DYNAMIC: &str = "include_dynamic";

/// One Go To request (Java `QueryData`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryData {
    /// The trimmed input.
    pub query: String,
    /// Case-sensitive label matching.
    pub case_sensitive: bool,
    /// Include dynamic labels.
    pub include_dynamic: bool,
}

/// Runs a query: `Ok(true)` went there, `Ok(false)` found nothing, `Err` failed.
pub type GoToQuery = Box<dyn FnMut(&QueryData) -> Result<bool, String> + Send>;

/// The dialog's state; one per tool, kept across openings (history).
pub struct GoToAddressLabelDialog {
    history: Vec<String>,
    max_entries: usize,
    case_sensitive: bool,
    include_dynamic: bool,
    status: String,
    /// The combo's text on the next opening (Java: after a success the new
    /// history model selects its first entry; close/cancel clear it).
    combo_text: String,
    query: GoToQuery,
}

impl GoToAddressLabelDialog {
    /// A dialog running `query`.
    pub fn new(query: GoToQuery) -> Self {
        Self {
            history: Vec::new(),
            max_entries: DEFAULT_MAX_GOTO_ENTRIES,
            case_sensitive: false,
            include_dynamic: true,
            status: String::new(),
            combo_text: String::new(),
            query,
        }
    }

    /// History, newest first.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Java `maxEntrysChanged`: the tool option changed.
    pub fn set_max_entries(&mut self, max: usize) {
        self.max_entries = max;
        self.history.truncate(max);
    }

    /// Java `writeConfigState`.
    pub fn write_config_state(&self, state: &mut SaveState) {
        state.put_object("GO_TO_HISTORY", GPropertyValue::Strings(self.history.clone()));
        state.put_object("CASE_SENSITIVE", GPropertyValue::Boolean(self.case_sensitive));
        state.put_object("INCLUDE_DYNAMIC", GPropertyValue::Boolean(self.include_dynamic));
    }

    /// Java `readConfigState`.
    pub fn read_config_state(&mut self, state: &SaveState) {
        if let Some(GPropertyValue::Strings(entries)) = state.get_object("GO_TO_HISTORY") {
            for e in entries {
                if !self.history.contains(e) {
                    self.history.push(e.clone());
                }
            }
            self.history.truncate(self.max_entries);
        }
        let flag = |key: &str, default: bool| match state.get_object(key) {
            Some(GPropertyValue::Boolean(b)) => *b,
            _ => default,
        };
        self.case_sensitive = flag("CASE_SENSITIVE", false);
        self.include_dynamic = flag("INCLUDE_DYNAMIC", true);
    }

    fn add_to_history(&mut self, input: &str) {
        self.history.retain(|h| h != input);
        self.history.insert(0, input.to_owned());
        self.history.truncate(self.max_entries);
    }
}

impl DialogModel for GoToAddressLabelDialog {
    fn spec(&self) -> DialogSpec {
        DialogSpec {
            title: "Go To ...".into(),
            message: "Enter an address, label, expression, or file offset:".into(),
            combo: Some(ComboSpec { text: self.combo_text.clone(), items: self.history.clone() }),
            checks: vec![
                CheckSpec { key: CASE_SENSITIVE.into(), label: "Case sensitive".into(), tooltip: String::new(), checked: self.case_sensitive },
                CheckSpec {
                    key: INCLUDE_DYNAMIC.into(),
                    label: "Dynamic labels".into(),
                    tooltip: "Include dynamic labels in the search (slower)".into(),
                    checked: self.include_dynamic,
                },
            ],
            status: self.status.clone(),
        }
    }

    /// Java `okCallback` + `gotoCompleted`/`gotoFailed`.
    fn ok(&mut self, text: &str, checks: &[(String, bool)]) -> DialogReply {
        for (key, on) in checks {
            match key.as_str() {
                CASE_SENSITIVE => self.case_sensitive = *on,
                INCLUDE_DYNAMIC => self.include_dynamic = *on,
                _ => {}
            }
        }
        let input = text.trim();
        if input.is_empty() {
            self.status.clear();
            self.combo_text.clear();
            return DialogReply::Close; // escapeCallback
        }
        let data = QueryData { query: input.to_owned(), case_sensitive: self.case_sensitive, include_dynamic: self.include_dynamic };
        self.status = match (self.query)(&data) {
            Ok(true) => {
                self.status.clear();
                self.add_to_history(input);
                self.combo_text = input.to_owned();
                return DialogReply::Close;
            }
            Ok(false) => format!("No results for {input}"),
            Err(e) => format!("ERROR: {e}"),
        };
        DialogReply::Stay(self.spec())
    }

    /// Java `close` → `clearAll`.
    fn cancel(&mut self) {
        self.status.clear();
        self.combo_text.clear();
    }
}

/// The dialog shared between its action (which keeps it across openings)
/// and the session's open-dialog registry.
#[derive(Clone)]
pub struct SharedGoToDialog(pub Arc<Mutex<GoToAddressLabelDialog>>);

impl DialogModel for SharedGoToDialog {
    fn spec(&self) -> DialogSpec {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).spec()
    }
    fn ok(&mut self, text: &str, checks: &[(String, bool)]) -> DialogReply {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).ok(text, checks)
    }
    fn cancel(&mut self) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).cancel()
    }
}

impl crate::session::ConfigState for SharedGoToDialog {
    fn write_config_state(&self, state: &mut SaveState) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).write_config_state(state);
    }
    fn read_config_state(&mut self, state: &SaveState) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).read_config_state(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Goes to "found*" inputs, fails on "boom", finds nothing otherwise.
    fn dialog() -> (GoToAddressLabelDialog, Arc<Mutex<Vec<QueryData>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let d = GoToAddressLabelDialog::new(Box::new(move |q: &QueryData| {
            s.lock().unwrap().push(q.clone());
            match q.query.as_str() {
                "boom" => Err("bad expression".into()),
                q => Ok(q.starts_with("found")),
            }
        }));
        (d, seen)
    }

    fn checks(case: bool, dynamic: bool) -> Vec<(String, bool)> {
        vec![(CASE_SENSITIVE.into(), case), (INCLUDE_DYNAMIC.into(), dynamic)]
    }

    #[test]
    fn the_spec_matches_ghidras_dialog() {
        let (d, _) = dialog();
        let s = d.spec();
        assert_eq!(s.title, "Go To ...");
        assert_eq!(s.message, "Enter an address, label, expression, or file offset:");
        assert_eq!(s.combo, Some(ComboSpec { text: String::new(), items: Vec::new() }));
        let labels: Vec<(&str, bool)> = s.checks.iter().map(|c| (c.label.as_str(), c.checked)).collect();
        assert_eq!(labels, vec![("Case sensitive", false), ("Dynamic labels", true)]);
        assert_eq!(s.checks[1].tooltip, "Include dynamic labels in the search (slower)");
    }

    #[test]
    fn success_closes_and_records_history_newest_first_without_duplicates() {
        let (mut d, seen) = dialog();
        for q in ["found1", "found2", "found1"] {
            assert_eq!(d.ok(&format!("  {q} "), &checks(true, false)), DialogReply::Close);
        }
        assert_eq!(d.history(), &["found1".to_string(), "found2".to_string()]);
        assert_eq!(seen.lock().unwrap()[0], QueryData { query: "found1".into(), case_sensitive: true, include_dynamic: false });
        assert_eq!(d.spec().combo.unwrap().items, vec!["found1", "found2"]);
        assert!(!d.spec().checks[1].checked, "options are remembered");
    }

    #[test]
    fn no_results_and_errors_stay_open_with_ghidras_messages() {
        let (mut d, _) = dialog();
        match d.ok("zz", &checks(false, true)) {
            DialogReply::Stay(s) => assert_eq!(s.status, "No results for zz"),
            other => panic!("{other:?}"),
        }
        match d.ok("boom", &checks(false, true)) {
            DialogReply::Stay(s) => assert_eq!(s.status, "ERROR: bad expression"),
            other => panic!("{other:?}"),
        }
        assert!(d.history().is_empty());
        d.cancel();
        assert_eq!(d.spec().status, "");
    }

    #[test]
    fn after_a_success_the_next_opening_offers_the_last_target_and_cancel_clears_it() {
        let (mut d, _) = dialog();
        assert_eq!(d.ok("found1", &checks(false, true)), DialogReply::Close);
        assert_eq!(d.spec().combo.unwrap().text, "found1"); // G + Enter repeats it
        d.cancel();
        assert_eq!(d.spec().combo.unwrap().text, "");
        d.ok("found2", &checks(false, true));
        assert_eq!(d.ok("  ", &checks(false, true)), DialogReply::Close);
        assert_eq!(d.spec().combo.unwrap().text, "");
    }

    #[test]
    fn empty_input_cancels_without_a_query() {
        let (mut d, seen) = dialog();
        assert_eq!(d.ok("   ", &checks(false, true)), DialogReply::Close);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn history_is_capped_at_the_max_entries() {
        let (mut d, _) = dialog();
        for i in 0..12 {
            d.ok(&format!("found{i}"), &checks(false, true));
        }
        assert_eq!(d.history().len(), DEFAULT_MAX_GOTO_ENTRIES);
        assert_eq!(d.history()[0], "found11");
        d.set_max_entries(3);
        assert_eq!(d.history(), &["found11", "found10", "found9"].map(String::from));
    }

    #[test]
    fn config_state_round_trips_history_and_options() {
        let (mut d, _) = dialog();
        d.ok("found1", &checks(true, false));
        d.ok("found2", &checks(true, false));
        let mut state = SaveState::new();
        d.write_config_state(&mut state);
        assert_eq!(state.get_object("GO_TO_HISTORY"), Some(&GPropertyValue::Strings(vec!["found2".into(), "found1".into()])));
        let (mut d2, _) = dialog();
        d2.read_config_state(&state);
        assert_eq!(d2.history(), d.history());
        let s = d2.spec();
        assert!(s.checks[0].checked && !s.checks[1].checked);
    }
}
