//! Toolkit-neutral docking layout: which providers are visible and where
//! (Ghidra's `WindowPosition` placement intent), plus an opaque geometry blob
//! owned by the renderer (the ADS `saveState()` bytes). Persisted through the
//! real `SaveState` (Qt6 UI spec §4).

use std::collections::BTreeMap;

use crate::docking::WindowPosition;
use crate::framework::options::SaveState;

const PROVIDER_PREFIX: &str = "PROVIDER:";
const GEOMETRY: &str = "GEOMETRY";

/// Java `WindowPosition` constant name.
pub fn position_name(p: WindowPosition) -> &'static str {
    match p {
        WindowPosition::Top => "TOP",
        WindowPosition::Bottom => "BOTTOM",
        WindowPosition::Left => "LEFT",
        WindowPosition::Right => "RIGHT",
        WindowPosition::Window => "WINDOW",
        WindowPosition::Stack => "STACK",
    }
}

/// Parses a Java `WindowPosition` constant name.
pub fn position_from_str(s: &str) -> Option<WindowPosition> {
    Some(match s {
        "TOP" => WindowPosition::Top,
        "BOTTOM" => WindowPosition::Bottom,
        "LEFT" => WindowPosition::Left,
        "RIGHT" => WindowPosition::Right,
        "WINDOW" => WindowPosition::Window,
        "STACK" => WindowPosition::Stack,
        _ => return None,
    })
}

/// One provider's placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutEntry {
    /// Shown or hidden.
    pub visible: bool,
    /// Where it docks.
    pub position: WindowPosition,
    /// Its window group.
    pub group: String,
}

/// Placement of every known provider plus the renderer's geometry blob.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DockLayout {
    entries: BTreeMap<String, LayoutEntry>,
    geometry: Option<Vec<u8>>,
}

impl DockLayout {
    /// The entry for a provider layout key (`"<owner>.<name>"`).
    pub fn entry(&self, key: &str) -> Option<&LayoutEntry> {
        self.entries.get(key)
    }

    /// Inserts or replaces an entry.
    pub fn set_entry(&mut self, key: impl Into<String>, entry: LayoutEntry) {
        self.entries.insert(key.into(), entry);
    }

    /// Removes an entry.
    pub fn remove_entry(&mut self, key: &str) -> Option<LayoutEntry> {
        self.entries.remove(key)
    }

    /// All entries by key.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &LayoutEntry)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// The renderer's opaque geometry (ADS `saveState()`), if any.
    pub fn geometry(&self) -> Option<&[u8]> {
        self.geometry.as_deref()
    }

    /// Replaces the geometry blob.
    pub fn set_geometry(&mut self, geometry: Option<Vec<u8>>) {
        self.geometry = geometry;
    }

    /// Serialises to a `SaveState` (`PROVIDER:<key>` children + `GEOMETRY`).
    pub fn to_save_state(&self) -> SaveState {
        let mut s = SaveState::new();
        for (key, e) in &self.entries {
            let mut child = SaveState::new();
            child.put_boolean("VISIBLE", e.visible);
            child.put_string("POSITION", Some(position_name(e.position)));
            child.put_string("GROUP", Some(&e.group));
            s.put_save_state(&format!("{PROVIDER_PREFIX}{key}"), child);
        }
        if let Some(g) = &self.geometry {
            s.put_bytes(GEOMETRY, Some(g));
        }
        s
    }

    /// Reads a layout saved by [`Self::to_save_state`]; entries with an
    /// unknown position are skipped.
    pub fn from_save_state(s: &SaveState) -> Self {
        let mut layout = DockLayout::default();
        for name in s.get_names() {
            let Some(key) = name.strip_prefix(PROVIDER_PREFIX) else { continue };
            let Some(child) = s.get_save_state(&name) else { continue };
            let Some(position) = child.get_string("POSITION", None).as_deref().and_then(position_from_str) else {
                tracing::warn!("Skipping layout entry {key}: missing or unknown position");
                continue;
            };
            layout.entries.insert(
                key.to_owned(),
                LayoutEntry {
                    visible: child.get_boolean("VISIBLE", false),
                    position,
                    group: child.get_string("GROUP", Some(crate::docking::DEFAULT_WINDOW_GROUP)).unwrap_or_default(),
                },
            );
        }
        layout.geometry = s.get_bytes(GEOMETRY, None);
        layout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_position_names_round_trip() {
        for p in [WindowPosition::Top, WindowPosition::Bottom, WindowPosition::Left, WindowPosition::Right, WindowPosition::Window, WindowPosition::Stack] {
            assert_eq!(position_from_str(position_name(p)), Some(p));
        }
        assert_eq!(position_from_str("SIDEWAYS"), None);
    }

    #[test]
    fn save_state_round_trip() {
        let mut l = DockLayout::default();
        l.set_entry("O.A", LayoutEntry { visible: true, position: WindowPosition::Left, group: "Default".into() });
        l.set_geometry(Some(vec![9, 8]));
        let s = l.to_save_state();
        let back = DockLayout::from_save_state(&s);
        assert_eq!(back.entry("O.A"), l.entry("O.A"));
        assert_eq!(back.geometry(), Some(&[9u8, 8][..]));
    }

    #[test]
    fn malformed_entries_are_skipped() {
        let mut s = SaveState::new();
        let mut bad = SaveState::new();
        bad.put_string("POSITION", Some("SIDEWAYS"));
        s.put_save_state("PROVIDER:O.Bad", bad);
        assert!(DockLayout::from_save_state(&s).entry("O.Bad").is_none());
    }
}
