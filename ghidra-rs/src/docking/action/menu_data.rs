//! Port of `docking.action.MenuData` (and its `MenuBarData`/`PopupMenuData`
//! subclasses, which only differed by notifying their owning action; the
//! owning `DockingAction` now records those changes itself).

use std::fmt;

use crate::docking::IconId;

/// `MenuData.NO_SUBGROUP`: sorts after every real sub-group.
pub const NO_SUBGROUP: &str = "\u{ffff}";

/// Errors from [`MenuData`] construction or mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuDataError {
    /// The menu path was empty.
    EmptyPath,
    /// A parent group was set on a top-level item.
    NoParentMenu,
}

impl fmt::Display for MenuDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("Menu path cannot be null or empty"),
            Self::NoParentMenu => f.write_str("Cannot set the parent menu group for a menu item that has no parent"),
        }
    }
}

impl std::error::Error for MenuDataError {}

/// Menu placement for an action: path, icon, group, mnemonic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuData {
    menu_path: Vec<String>,
    icon: Option<IconId>,
    mnemonic: Option<char>,
    menu_group: Option<String>,
    parent_menu_group: Option<String>,
    menu_sub_group: String,
}

impl MenuData {
    /// `new MenuData(String[] menuPath)`.
    pub fn new(path: &[&str]) -> Result<Self, MenuDataError> {
        Self::full(path, None, None, None, None)
    }

    /// `new MenuData(menuPath, group)`.
    pub fn with_group(path: &[&str], group: &str) -> Result<Self, MenuDataError> {
        Self::full(path, None, Some(group), None, None)
    }

    /// `new MenuData(menuPath, icon, menuGroup, mnemonic, menuSubGroup)`.
    /// A `None` mnemonic is derived from the last path element's `&`.
    pub fn full(
        path: &[&str],
        icon: Option<IconId>,
        group: Option<&str>,
        mnemonic: Option<char>,
        sub_group: Option<&str>,
    ) -> Result<Self, MenuDataError> {
        let last = *path.last().ok_or(MenuDataError::EmptyPath)?;
        Ok(Self {
            menu_path: process_menu_path(path),
            icon,
            mnemonic: mnemonic.or_else(|| Self::mnemonic_of(last)),
            menu_group: group.map(str::to_owned),
            parent_menu_group: None,
            menu_sub_group: sub_group.unwrap_or(NO_SUBGROUP).to_owned(),
        })
    }

    /// `getMenuPath()`
    pub fn menu_path(&self) -> &[String] {
        &self.menu_path
    }

    /// `getMenuPathAsString()`: elements joined by `->`.
    pub fn menu_path_as_string(&self) -> String {
        self.menu_path.join("->")
    }

    /// `getMenuPathDisplayString()`: like [`Self::menu_path_as_string`] with
    /// mnemonic `&`s stripped from the parent elements.
    pub fn menu_path_display_string(&self) -> String {
        let n = self.menu_path.len();
        self.menu_path
            .iter()
            .enumerate()
            .map(|(i, p)| if i + 1 < n { Self::strip_mnemonic_amp(p) } else { p.clone() })
            .collect::<Vec<_>>()
            .join("->")
    }

    /// `getMnemonic()`
    pub fn mnemonic(&self) -> Option<char> {
        self.mnemonic
    }

    /// `getMenuIcon()`
    pub fn icon(&self) -> Option<&IconId> {
        self.icon.as_ref()
    }

    /// `getMenuGroup()`
    pub fn menu_group(&self) -> Option<&str> {
        self.menu_group.as_deref()
    }

    /// `getMenuSubGroup()` ([`NO_SUBGROUP`] when unset).
    pub fn menu_sub_group(&self) -> &str {
        &self.menu_sub_group
    }

    /// `getParentMenuGroup()`
    pub fn parent_menu_group(&self) -> Option<&str> {
        self.parent_menu_group.as_deref()
    }

    /// `getMenuItemName()`: the last path element.
    pub fn menu_item_name(&self) -> &str {
        self.menu_path.last().map(String::as_str).unwrap_or("Missing Menu Path!")
    }

    /// `setIcon`
    pub fn set_icon(&mut self, icon: Option<IconId>) {
        self.icon = icon;
    }

    /// `setMenuGroup`
    pub fn set_menu_group(&mut self, group: Option<&str>) {
        self.menu_group = group.map(str::to_owned);
    }

    /// `setMenuSubGroup`; `None` resets to [`NO_SUBGROUP`].
    pub fn set_menu_sub_group(&mut self, sub_group: Option<&str>) {
        self.menu_sub_group = sub_group.unwrap_or(NO_SUBGROUP).to_owned();
    }

    /// `setParentMenuGroup`; only valid for items with a parent menu.
    pub fn set_parent_menu_group(&mut self, group: Option<&str>) -> Result<(), MenuDataError> {
        if self.menu_path.len() <= 1 {
            return Err(MenuDataError::NoParentMenu);
        }
        self.parent_menu_group = group.map(str::to_owned);
        Ok(())
    }

    /// `setMenuPath`; recomputes the mnemonic.
    pub fn set_menu_path(&mut self, path: &[&str]) -> Result<(), MenuDataError> {
        let last = *path.last().ok_or(MenuDataError::EmptyPath)?;
        self.menu_path = process_menu_path(path);
        self.mnemonic = Self::mnemonic_of(last);
        Ok(())
    }

    /// `setMenuItemName`: strips `&` and recomputes the mnemonic.
    pub fn set_menu_item_name(&mut self, name: &str) {
        let stripped = Self::strip_mnemonic_amp(name);
        if self.menu_path.last().map(String::as_str) == Some(stripped.as_str()) {
            return;
        }
        if let Some(last) = self.menu_path.last_mut() {
            *last = stripped;
        }
        self.mnemonic = Self::mnemonic_of(name);
    }

    /// `setMenuItemNamePlain`: no `&` processing.
    pub fn set_menu_item_name_plain(&mut self, name: &str) {
        if let Some(last) = self.menu_path.last_mut() {
            *last = name.to_owned();
        }
    }

    /// `setMnemonic`
    pub fn set_mnemonic(&mut self, mnemonic: char) {
        self.mnemonic = Some(mnemonic);
    }

    /// `clearMnemonic`
    pub fn clear_mnemonic(&mut self) {
        self.mnemonic = None;
    }

    /// `getMnemonic(String)`: the character after the first single `&`.
    pub fn mnemonic_of(menu_name: &str) -> Option<char> {
        let cleaned: Vec<char> = menu_name.replace("&&", "").chars().collect();
        let first = cleaned.iter().position(|c| *c == '&')?;
        cleaned.get(first + 1).copied()
    }

    /// `stripMnemonicAmp`: removes single `&`s; `&&` becomes a literal `&`.
    pub fn strip_mnemonic_amp(name: &str) -> String {
        if !name.contains('&') {
            return name.to_owned();
        }
        let mut out = String::with_capacity(name.len());
        let mut previous_was_amp = false;
        for c in name.chars() {
            if c != '&' {
                out.push(c);
                previous_was_amp = false;
                continue;
            }
            if previous_was_amp {
                out.push('&');
            }
            previous_was_amp = !previous_was_amp;
        }
        out
    }
}

fn process_menu_path(path: &[&str]) -> Vec<String> {
    let mut copy: Vec<String> = path.iter().map(|s| (*s).to_owned()).collect();
    if let Some(last) = copy.last_mut() {
        *last = MenuData::strip_mnemonic_amp(last);
    }
    copy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_is_rejected() {
        assert!(MenuData::new(&[]).is_err());
    }

    #[test]
    fn mnemonic_comes_from_last_element_ampersand_and_is_stripped() {
        let m = MenuData::new(&["&File", "Save &As..."]).unwrap();
        assert_eq!(m.mnemonic(), Some('A'));
        // only the LAST element is stripped (Java processMenuPath)
        assert_eq!(m.menu_path(), &["&File".to_string(), "Save As...".to_string()]);
        assert_eq!(m.menu_item_name(), "Save As...");
    }

    #[test]
    fn double_ampersand_is_a_literal() {
        assert_eq!(MenuData::strip_mnemonic_amp("Fish && Chips"), "Fish & Chips");
        assert_eq!(MenuData::mnemonic_of("Fish && Chips"), None);
        assert_eq!(MenuData::mnemonic_of("&Edit"), Some('E'));
        assert_eq!(MenuData::mnemonic_of("Trailing&"), None);
    }

    #[test]
    fn path_strings() {
        let m = MenuData::new(&["&Edit", "Copy &Special"]).unwrap();
        assert_eq!(m.menu_path_as_string(), "&Edit->Copy Special");
        assert_eq!(m.menu_path_display_string(), "Edit->Copy Special");
    }

    #[test]
    fn sub_group_defaults_to_no_subgroup() {
        let mut m = MenuData::new(&["A"]).unwrap();
        assert_eq!(m.menu_sub_group(), NO_SUBGROUP);
        m.set_menu_sub_group(Some("x"));
        assert_eq!(m.menu_sub_group(), "x");
        m.set_menu_sub_group(None);
        assert_eq!(m.menu_sub_group(), NO_SUBGROUP);
    }

    #[test]
    fn parent_group_requires_a_parent_menu() {
        let mut top = MenuData::new(&["Top"]).unwrap();
        assert!(top.set_parent_menu_group(Some("g")).is_err());
        let mut nested = MenuData::new(&["Top", "Item"]).unwrap();
        nested.set_parent_menu_group(Some("g")).unwrap();
        assert_eq!(nested.parent_menu_group(), Some("g"));
    }

    #[test]
    fn renaming_the_item_updates_mnemonic_and_strips() {
        let mut m = MenuData::new(&["Edit", "Copy"]).unwrap();
        m.set_menu_item_name("Pa&ste");
        assert_eq!(m.menu_item_name(), "Paste");
        assert_eq!(m.mnemonic(), Some('s'));
        m.set_menu_item_name_plain("Raw &Name");
        assert_eq!(m.menu_item_name(), "Raw &Name");
    }
}
