//! Light/dark theme choice (Java `ThemeManagerPlugin` "Switch Theme" →
//! `ThemeChooserDialog` "Change Theme"). Rust owns the choice, the icon
//! variant and persistence; the renderer applies a matching palette.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use ghidra_rs::generic::theme::theme_icon_resolver::{ThemeIconResolver, ThemeVariant};

use crate::dialogs::{ComboSpec, DialogModel, DialogReply, DialogSpec};
use crate::events::{UiEvent, UiEventQueue};
use crate::icons::IconResolver;

/// The themes this build supports (Ghidra's builtin Flat themes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiTheme {
    /// "Flat Light Theme".
    FlatLight,
    /// "Flat Dark Theme".
    FlatDark,
}

impl UiTheme {
    /// Every supported theme, sorted by name (as the chooser lists them).
    pub const ALL: [UiTheme; 2] = [UiTheme::FlatDark, UiTheme::FlatLight];

    /// Ghidra's theme name.
    pub fn name(self) -> &'static str {
        match self {
            UiTheme::FlatLight => "Flat Light Theme",
            UiTheme::FlatDark => "Flat Dark Theme",
        }
    }

    /// The theme with this name.
    pub fn from_name(name: &str) -> Option<UiTheme> {
        Self::ALL.into_iter().find(|t| t.name() == name.trim())
    }

    /// Whether it uses the dark defaults.
    pub fn is_dark(self) -> bool {
        self == UiTheme::FlatDark
    }
}

/// The current theme, shared by the chooser, the icon resolver and persistence.
pub type SharedTheme = Arc<Mutex<UiTheme>>;

fn get(theme: &SharedTheme) -> UiTheme {
    *theme.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Switches to `theme`: tells the renderer (palette) and rebuilds toolbars
/// (icons follow the variant). No-op when unchanged.
pub fn set_theme(theme: &SharedTheme, events: &UiEventQueue, new: UiTheme) {
    let changed = {
        let mut t = theme.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *t, new) != new
    };
    if changed {
        events.post(UiEvent::ThemeChanged { dark: new.is_dark() });
        events.post(UiEvent::ActionsChanged);
    }
}

/// Theme icons for the current theme's variant (dark defaults when dark).
pub struct ThemedIcons {
    light: ThemeIconResolver,
    dark: ThemeIconResolver,
    theme: SharedTheme,
}

impl ThemedIcons {
    /// Loads both variants from Ghidra theme files under `root`.
    pub fn load(root: &std::path::Path, theme: SharedTheme) -> std::io::Result<Self> {
        Ok(Self {
            light: ThemeIconResolver::from_ghidra_root(root, ThemeVariant::Light)?,
            dark: ThemeIconResolver::from_ghidra_root(root, ThemeVariant::Dark)?,
            theme,
        })
    }
}

impl IconResolver for ThemedIcons {
    fn resolve(&self, id: &str) -> Option<PathBuf> {
        if get(&self.theme).is_dark() { &self.dark } else { &self.light }.resolve_icon_path(id)
    }
}

/// The "Change Theme" chooser.
pub struct ChangeThemeDialog {
    /// The theme to change.
    pub theme: SharedTheme,
    /// Where change notices go.
    pub events: UiEventQueue,
    status: String,
}

impl ChangeThemeDialog {
    /// A chooser over `theme`.
    pub fn new(theme: SharedTheme, events: UiEventQueue) -> Self {
        Self { theme, events, status: String::new() }
    }
}

impl DialogModel for ChangeThemeDialog {
    fn spec(&self) -> DialogSpec {
        DialogSpec {
            title: "Change Theme".into(),
            combo: Some(ComboSpec {
                text: get(&self.theme).name().to_owned(),
                items: UiTheme::ALL.iter().map(|t| t.name().to_owned()).collect(),
            }),
            status: self.status.clone(),
            ..DialogSpec::default()
        }
    }

    fn ok(&mut self, text: &str, _checks: &[(String, bool)]) -> DialogReply {
        match UiTheme::from_name(text) {
            Some(t) => {
                self.status.clear();
                set_theme(&self.theme, &self.events, t);
                DialogReply::Close
            }
            None => {
                self.status = format!("Unknown theme: {}", text.trim());
                DialogReply::Stay(self.spec())
            }
        }
    }
}

/// The chosen theme saved with the tool configuration (Java keeps it in
/// preferences; this build has only the tool config).
pub struct ThemeConfig {
    /// The theme.
    pub theme: SharedTheme,
    /// Where the restored choice is announced.
    pub events: UiEventQueue,
}

impl crate::session::ConfigState for ThemeConfig {
    fn write_config_state(&self, state: &mut ghidra_rs::framework::options::SaveState) {
        state.put_string("Theme", Some(get(&self.theme).name()));
    }
    fn read_config_state(&mut self, state: &ghidra_rs::framework::options::SaveState) {
        if let Some(t) = state.get_string("Theme", None).as_deref().and_then(UiTheme::from_name) {
            set_theme(&self.theme, &self.events, t);
        }
    }
    fn phase(&self) -> u8 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared(t: UiTheme) -> SharedTheme {
        Arc::new(Mutex::new(t))
    }

    #[test]
    fn the_chooser_lists_themes_sorted_and_switches_on_ok() {
        let (events, _w) = UiEventQueue::new();
        let theme = shared(UiTheme::FlatLight);
        let mut d = ChangeThemeDialog::new(theme.clone(), events.clone());
        let spec = d.spec();
        assert_eq!(spec.title, "Change Theme");
        assert_eq!(spec.combo.as_ref().unwrap().items, vec!["Flat Dark Theme", "Flat Light Theme"]);
        assert_eq!(spec.combo.unwrap().text, "Flat Light Theme");
        assert_eq!(d.ok("Flat Dark Theme", &[]), DialogReply::Close);
        assert_eq!(get(&theme), UiTheme::FlatDark);
        assert_eq!(events.drain(), vec![UiEvent::ThemeChanged { dark: true }, UiEvent::ActionsChanged]);
        assert_eq!(d.ok("Flat Dark Theme", &[]), DialogReply::Close);
        assert!(events.drain().is_empty(), "unchanged: no notices");
    }

    #[test]
    fn an_unknown_theme_name_stays_open_with_a_status() {
        let (events, _w) = UiEventQueue::new();
        let mut d = ChangeThemeDialog::new(shared(UiTheme::FlatLight), events);
        match d.ok("Solarized", &[]) {
            DialogReply::Stay(s) => assert_eq!(s.status, "Unknown theme: Solarized"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn icons_follow_the_theme_variant() {
        let Some(root) = crate::icons::default_theme_root() else { return };
        let theme = shared(UiTheme::FlatLight);
        let icons = ThemedIcons::load(&root, theme.clone()).unwrap();
        let id = "icon.plugin.symboltree.node.namespace";
        assert!(icons.resolve(id).unwrap().ends_with("Namespace.gif"));
        *theme.lock().unwrap() = UiTheme::FlatDark;
        assert!(icons.resolve(id).unwrap().ends_with("Namespace.dark.gif"));
    }

    #[test]
    fn the_choice_persists_and_is_announced_on_load() {
        use crate::session::ConfigState;
        let (events, _w) = UiEventQueue::new();
        let saved = ThemeConfig { theme: shared(UiTheme::FlatDark), events: events.clone() };
        let mut state = ghidra_rs::framework::options::SaveState::new();
        saved.write_config_state(&mut state);
        let mut loaded = ThemeConfig { theme: shared(UiTheme::FlatLight), events: events.clone() };
        loaded.read_config_state(&state);
        assert_eq!(get(&loaded.theme), UiTheme::FlatDark);
        assert!(events.drain().contains(&UiEvent::ThemeChanged { dark: true }));
    }
}
