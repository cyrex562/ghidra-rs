//! Port of `docking.action.ToolBarData`.

use super::NO_SUBGROUP;
use crate::docking::IconId;

/// Toolbar placement for an action (`docking.action.ToolBarData`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolBarData {
    icon: IconId,
    group: Option<String>,
    sub_group: String,
}

impl ToolBarData {
    /// `new ToolBarData(icon, toolBarGroup, toolBarSubGroup)`.
    pub fn new(icon: IconId, group: Option<&str>, sub_group: Option<&str>) -> Self {
        Self {
            icon,
            group: group.map(str::to_owned),
            sub_group: sub_group.unwrap_or(NO_SUBGROUP).to_owned(),
        }
    }

    /// The toolbar icon.
    pub fn icon(&self) -> &IconId {
        &self.icon
    }

    /// The toolbar group, if any.
    pub fn tool_bar_group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// The toolbar sub-group ([`NO_SUBGROUP`] when unset).
    pub fn tool_bar_sub_group(&self) -> &str {
        &self.sub_group
    }

    /// `setIcon`
    pub fn set_icon(&mut self, icon: IconId) {
        self.icon = icon;
    }

    /// `setToolBarGroup`
    pub fn set_tool_bar_group(&mut self, group: Option<&str>) {
        self.group = group.map(str::to_owned);
    }

    /// `setToolBarSubGroup`; `None` resets to [`NO_SUBGROUP`].
    pub fn set_tool_bar_sub_group(&mut self, sub_group: Option<&str>) {
        self.sub_group = sub_group.unwrap_or(NO_SUBGROUP).to_owned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_group_defaults_and_resets_to_no_subgroup() {
        let mut t = ToolBarData::new(IconId::new("icon.refresh"), Some("Nav"), None);
        assert_eq!(t.tool_bar_sub_group(), NO_SUBGROUP);
        assert_eq!(t.tool_bar_group(), Some("Nav"));
        t.set_tool_bar_sub_group(Some("a"));
        assert_eq!(t.tool_bar_sub_group(), "a");
        t.set_tool_bar_sub_group(None);
        assert_eq!(t.tool_bar_sub_group(), NO_SUBGROUP);
        assert_eq!(t.icon(), &IconId::new("icon.refresh"));
    }
}
