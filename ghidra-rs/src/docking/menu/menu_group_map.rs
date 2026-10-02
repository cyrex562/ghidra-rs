//! Port of `docking.menu.MenuGroupMap`: preferred group/sub-group for menus
//! (not items), keyed by menu path, used to order sub-menus.

use std::collections::HashMap;

use crate::docking::action::NO_SUBGROUP;

/// Preferred menu groups by menu path.
#[derive(Debug, Clone, Default)]
pub struct MenuGroupMap {
    groups: HashMap<String, String>,
    sub_groups: HashMap<String, String>,
}

fn key(path: &[&str]) -> String {
    path.iter().map(|p| format!("/{p}")).collect()
}

impl MenuGroupMap {
    /// `setMenuGroup(menuPath, group, menuSubGroup)`: a `None` group clears it;
    /// a `None` sub-group stores [`NO_SUBGROUP`].
    pub fn set_menu_group(&mut self, path: &[&str], group: Option<&str>, sub_group: Option<&str>) {
        let k = key(path);
        match group {
            Some(g) => {
                self.groups.insert(k.clone(), g.to_owned());
            }
            None => {
                self.groups.remove(&k);
            }
        }
        self.sub_groups.insert(k, sub_group.unwrap_or(NO_SUBGROUP).to_owned());
    }

    /// `getMenuGroup(menuPath)`
    pub fn menu_group(&self, path: &[&str]) -> Option<&str> {
        self.groups.get(&key(path)).map(String::as_str)
    }

    /// `getMenuSubGroup(menuPath)`
    pub fn menu_sub_group(&self, path: &[&str]) -> Option<&str> {
        self.sub_groups.get(&key(path)).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_and_clear() {
        let mut m = MenuGroupMap::default();
        m.set_menu_group(&["File"], Some("0"), None);
        assert_eq!(m.menu_group(&["File"]), Some("0"));
        assert_eq!(m.menu_sub_group(&["File"]), Some(NO_SUBGROUP));
        m.set_menu_group(&["File"], None, Some("s"));
        assert_eq!(m.menu_group(&["File"]), None);
        assert_eq!(m.menu_sub_group(&["File"]), Some("s"));
        assert_eq!(m.menu_group(&["Edit"]), None);
    }
}
