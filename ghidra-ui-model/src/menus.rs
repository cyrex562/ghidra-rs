//! Menu bar, popup and toolbar construction with Ghidra's ordering rules
//! (`MenuManager`, `ManagedMenuItemComparator`, `PopupGroupComparator`,
//! `ToolBarManager`). The renderer receives these pre-ordered entries and
//! only draws them (Qt6 UI spec §4: no domain logic in C++).

use std::cmp::Ordering;

use ghidra_rs::docking::action::{ActionId, DockingActionIf, MenuData, NO_SUBGROUP};
use ghidra_rs::docking::actions::ActionScope;
use ghidra_rs::docking::{ActionContext, DockingTool, ProviderId};

/// One entry of a menu, pre-ordered for rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuEntry {
    /// A sub-menu.
    Submenu {
        /// Title without mnemonic markers.
        title: String,
        /// Mnemonic character.
        mnemonic: Option<char>,
        /// Ordered children.
        children: Vec<MenuEntry>,
    },
    /// An action item.
    Item {
        /// The action to invoke.
        action: ActionId,
        /// Item text.
        text: String,
        /// Mnemonic character.
        mnemonic: Option<char>,
        /// Key binding in Ghidra form (`"Ctrl-C"`), or empty.
        key_text: String,
        /// Enabled for the current context.
        enabled: bool,
        /// A toggle action.
        checkable: bool,
        /// Toggle state.
        checked: bool,
    },
    /// A group separator.
    Separator,
}

/// One toolbar entry, pre-ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolBarEntry {
    /// An action button.
    Button {
        /// The action to invoke.
        action: ActionId,
        /// Theme icon id.
        icon: String,
        /// Tooltip (the action name).
        tooltip: String,
        /// Enabled for the current context.
        enabled: bool,
    },
    /// A group separator.
    Separator,
}

/// Group comparator: menubar puts null last, popups put null first.
fn cmp_group(a: Option<&str>, b: Option<&str>, null_first: bool) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => if null_first { Ordering::Less } else { Ordering::Greater },
        (Some(_), None) => if null_first { Ordering::Greater } else { Ordering::Less },
        (Some(x), Some(y)) => x.cmp(y),
    }
}

/// A node while building: either a submenu or an item.
enum Node {
    Menu { name: String, path: Vec<String>, group: Option<String>, sub_group: String, children: Vec<Node> },
    Item { id: ActionId, name: String, group: Option<String>, sub_group: String },
}

impl Node {
    fn name(&self) -> &str {
        match self {
            Node::Menu { name, .. } | Node::Item { name, .. } => name,
        }
    }
    fn group(&self) -> Option<&str> {
        match self {
            Node::Menu { group, .. } | Node::Item { group, .. } => group.as_deref(),
        }
    }
    fn sub_group(&self) -> &str {
        match self {
            Node::Menu { sub_group, .. } | Node::Item { sub_group, .. } => sub_group,
        }
    }
}

fn enabled_in(a: &dyn DockingActionIf, ctx: &dyn ActionContext) -> bool {
    a.is_valid_context(ctx) && a.is_enabled_for_context(ctx)
}

fn item_entry(tool: &DockingTool, id: ActionId, text: &str, mnemonic: Option<char>, ctx: &dyn ActionContext) -> MenuEntry {
    let a = tool.actions().get(id).expect("action present while building menus");
    let toggle = a.as_toggle();
    MenuEntry::Item {
        action: id,
        text: text.to_owned(),
        mnemonic,
        key_text: a.key_binding().map(|k| k.to_ghidra_string()).unwrap_or_default(),
        enabled: enabled_in(a, ctx),
        checkable: toggle.is_some(),
        checked: toggle.is_some_and(|t| t.is_selected()),
    }
}

fn insert(tool: &DockingTool, nodes: &mut Vec<Node>, prefix: &[String], data: &MenuData, id: ActionId, depth: usize, popup: bool) {
    let path = data.menu_path();
    if depth + 1 == path.len() {
        nodes.push(Node::Item {
            id,
            name: data.menu_item_name().to_owned(),
            group: data.menu_group().map(str::to_owned),
            sub_group: data.menu_sub_group().to_owned(),
        });
        return;
    }
    let raw = &path[depth];
    let name = MenuData::strip_mnemonic_amp(raw);
    let mut sub_path: Vec<String> = prefix.to_vec();
    sub_path.push(raw.clone());
    let pos = nodes.iter().position(|n| matches!(n, Node::Menu { name: n2, .. } if *n2 == name));
    let idx = match pos {
        Some(i) => i,
        None => {
            let keys: Vec<&str> = sub_path.iter().map(String::as_str).collect();
            let groups = tool.menu_groups();
            // Java MenuManager.getSubMenuGroup: the pull-right group from the
            // leaf's MenuData (only for the leaf's direct parent), else the
            // tool's MenuGroupMap, else the menu's own name. Menubar top-level
            // menus are ordered separately (MenuBarManager) and get no group.
            let group = if !popup && depth == 0 {
                None
            } else {
                let pull_right = if depth + 2 == path.len() { data.parent_menu_group().map(str::to_owned) } else { None };
                Some(pull_right.or_else(|| groups.menu_group(&keys).map(str::to_owned)).unwrap_or_else(|| name.clone()))
            };
            let sub_group = groups.menu_sub_group(&keys).unwrap_or(NO_SUBGROUP).to_owned();
            nodes.push(Node::Menu { name, path: sub_path.clone(), group, sub_group, children: Vec::new() });
            nodes.len() - 1
        }
    };
    if let Node::Menu { children, .. } = &mut nodes[idx] {
        insert(tool, children, &sub_path, data, id, depth + 1, popup);
    }
}

/// How separators are inserted (they differ between Java's menus).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Separators {
    /// The menu bar itself: none (`MenuBarManager`).
    None,
    /// `MenuManager.getMenu`: when the previous item's group is non-null and differs.
    Menu,
    /// `MenuManager.getPopupMenu` (popup root): null groups compare as a named
    /// group, separator on any change after the first item.
    PopupRoot,
}

/// `MenuBarManager.getMenuBar`: File, Edit, the rest by name, then Window, Help.
fn menubar_rank(name: &str) -> u8 {
    match name {
        "File" => 0,
        "Edit" => 1,
        "Window" => 3,
        "Help" => 4,
        _ => 2,
    }
}

fn render(tool: &DockingTool, mut nodes: Vec<Node>, ctx: &dyn ActionContext, null_first: bool, popup: bool, separators: Separators) -> Vec<MenuEntry> {
    if separators == Separators::None {
        nodes.sort_by(|a, b| menubar_rank(a.name()).cmp(&menubar_rank(b.name())).then_with(|| a.name().cmp(b.name())));
    } else {
        nodes.sort_by(|a, b| {
            cmp_group(a.group(), b.group(), null_first)
                .then_with(|| a.sub_group().cmp(b.sub_group()))
                .then_with(|| a.name().cmp(b.name()))
        });
    }
    let mut out = Vec::new();
    let mut last_group: Option<Option<String>> = None;
    for n in nodes {
        let g = n.group().map(str::to_owned);
        if let Some(prev) = &last_group {
            let sep = match separators {
                Separators::None => false,
                Separators::Menu => prev.is_some() && *prev != g,
                Separators::PopupRoot => *prev != g,
            };
            if sep {
                out.push(MenuEntry::Separator);
            }
        }
        last_group = Some(g);
        match n {
            Node::Item { id, name, .. } => {
                let data = if popup {
                    tool.actions().get(id).and_then(|a| a.popup_menu_data())
                } else {
                    tool.actions().get(id).and_then(|a| a.menu_bar_data())
                };
                let mnemonic = data.and_then(MenuData::mnemonic);
                out.push(item_entry(tool, id, &name, mnemonic, ctx));
            }
            Node::Menu { name, path, children, .. } => {
                let mnemonic = path.last().and_then(|p| MenuData::mnemonic_of(p));
                out.push(MenuEntry::Submenu {
                    title: name,
                    mnemonic,
                    children: render(tool, children, ctx, null_first, popup, Separators::Menu),
                });
            }
        }
    }
    out
}

/// The main window's menu bar (`MenuBarManager`): every global action with
/// menu-bar data that belongs in the main window.
pub fn menu_bar(tool: &DockingTool, ctx: &dyn ActionContext) -> Vec<MenuEntry> {
    let mut roots: Vec<Node> = Vec::new();
    for id in tool.actions().global_actions().collect::<Vec<_>>() {
        let a = tool.actions().get(id).expect("listed action exists");
        if !a.state().should_add_to_window(true, &[]) {
            continue;
        }
        if let Some(data) = a.menu_bar_data() {
            insert(tool, &mut roots, &[], data, id, 0, false);
        }
    }
    render(tool, roots, ctx, false, false, Separators::None)
}

/// A provider's popup menu: global and that provider's local actions with
/// popup data whose `is_add_to_popup(ctx)` holds. No-group items sort first.
pub fn popup(tool: &DockingTool, provider: Option<ProviderId>, ctx: &dyn ActionContext) -> Vec<MenuEntry> {
    let mut roots: Vec<Node> = Vec::new();
    let ids: Vec<ActionId> = tool
        .actions()
        .global_actions()
        .chain(provider.into_iter().flat_map(|p| tool.actions().local_actions(p)))
        .collect();
    for id in ids {
        let a = tool.actions().get(id).expect("listed action exists");
        let (Some(data), true) = (a.popup_menu_data(), a.is_valid_context(ctx) && a.is_add_to_popup(ctx)) else { continue };
        insert(tool, &mut roots, &[], data, id, 0, true);
    }
    render(tool, roots, ctx, true, true, Separators::PopupRoot)
}

/// The main toolbar: global actions with toolbar data, by group then sub-group
/// then name, with a separator between groups.
pub fn tool_bar(tool: &DockingTool, ctx: &dyn ActionContext) -> Vec<ToolBarEntry> {
    let mut items: Vec<(Option<String>, String, String, ActionId)> = tool
        .actions()
        .global_actions()
        .filter(|id| tool.actions().scope(*id) == Some(ActionScope::Global))
        .filter_map(|id| {
            let a = tool.actions().get(id)?;
            let t = a.tool_bar_data()?;
            Some((t.tool_bar_group().map(str::to_owned), t.tool_bar_sub_group().to_owned(), a.name().to_owned(), id))
        })
        .collect();
    items.sort_by(|a, b| cmp_group(a.0.as_deref(), b.0.as_deref(), false).then_with(|| a.1.cmp(&b.1)).then_with(|| a.2.cmp(&b.2)));
    let mut out = Vec::new();
    let mut last: Option<Option<String>> = None;
    for (group, _, name, id) in items {
        if let Some(prev) = &last {
            if *prev != group {
                out.push(ToolBarEntry::Separator);
            }
        }
        last = Some(group);
        let a = tool.actions().get(id).expect("listed action exists");
        out.push(ToolBarEntry::Button {
            action: id,
            icon: a.tool_bar_data().map(|t| t.icon().to_string()).unwrap_or_default(),
            tooltip: name,
            enabled: enabled_in(a, ctx),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_rs::docking::action::{DockingAction, DockingActionIf, MenuData};
    use ghidra_rs::docking::{ActionContext, DefaultActionContext};

    struct Act(DockingAction);
    impl DockingActionIf for Act {
        fn state(&self) -> &DockingAction {
            &self.0
        }
        fn state_mut(&mut self) -> &mut DockingAction {
            &mut self.0
        }
        fn action_performed(&mut self, _c: &dyn ActionContext) {}
    }

    fn menu_action_sub(name: &str, path: &[&str], group: Option<&str>, sub: Option<&str>) -> Act {
        let mut s = DockingAction::new(name, "T");
        s.set_menu_bar_data(MenuData::full(path, None, group, None, sub).ok());
        Act(s)
    }
    fn menu_action(name: &str, path: &[&str], group: Option<&str>) -> Act {
        menu_action_sub(name, path, group, None)
    }
    fn popup_action(name: &str, group: Option<&str>) -> Act {
        let mut s = DockingAction::new(name, "T");
        s.set_popup_menu_data(MenuData::full(&[name], None, group, None, None).ok());
        Act(s)
    }
    fn entry_name(e: &MenuEntry) -> String {
        match e {
            MenuEntry::Submenu { title, .. } => title.clone(),
            MenuEntry::Item { text, .. } => text.clone(),
            MenuEntry::Separator => "---".into(),
        }
    }
    fn names(entries: &[MenuEntry]) -> Vec<String> {
        entries.iter().map(entry_name).collect()
    }

    #[test]
    fn null_group_sorts_last_in_menubar_first_in_popup_with_separators() {
        let mut t = DockingTool::new("T");
        t.add_action(Box::new(menu_action("B", &["Edit", "B"], None)));
        t.add_action(Box::new(menu_action("A", &["Edit", "A"], Some("x"))));
        t.add_action(Box::new(menu_action("C", &["Edit", "C"], Some("x"))));
        let bar = menu_bar(&t, &DefaultActionContext::new());
        let MenuEntry::Submenu { children, .. } = &bar[0] else { panic!("{bar:?}") };
        assert_eq!(names(children), vec!["A", "C", "---", "B"]);

        let mut p = DockingTool::new("P");
        p.add_action(Box::new(popup_action("B", None)));
        p.add_action(Box::new(popup_action("A", Some("x"))));
        let pop = popup(&p, None, &DefaultActionContext::new());
        assert_eq!(names(&pop), vec!["B", "---", "A"]);
    }

    #[test]
    fn equal_groups_order_by_sub_group_then_text() {
        let mut t = DockingTool::new("T");
        t.add_action(Box::new(menu_action_sub("Z", &["M", "Z"], Some("g"), Some("a"))));
        t.add_action(Box::new(menu_action_sub("A", &["M", "A"], Some("g"), Some("b"))));
        let bar = menu_bar(&t, &DefaultActionContext::new());
        let MenuEntry::Submenu { children, .. } = &bar[0] else { panic!() };
        assert_eq!(names(children), vec!["Z", "A"]);
    }

    #[test]
    fn nested_paths_build_submenus_and_disabled_items_are_marked() {
        let mut t = DockingTool::new("T");
        let mut a = menu_action("a.out", &["File", "Recent", "a.out"], None);
        a.0.set_enabled(false);
        t.add_action(Box::new(a));
        t.add_action(Box::new(menu_action("Open", &["File", "Open"], Some("a"))));
        let bar = menu_bar(&t, &DefaultActionContext::new());
        let MenuEntry::Submenu { title, children, .. } = &bar[0] else { panic!() };
        assert_eq!(title, "File");
        // Java: an ungrouped pull-right's group defaults to its own name, and
        // "Recent" < "a" in String.compareTo
        assert_eq!(names(children), vec!["Recent", "---", "Open"]);
        let MenuEntry::Submenu { children: recent, .. } = &children[0] else { panic!() };
        match &recent[0] {
            MenuEntry::Item { text, enabled, .. } => assert_eq!((text.as_str(), *enabled), ("a.out", false)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn top_level_menus_follow_tool_menu_groups() {
        let mut t = DockingTool::new("T");
        t.add_action(Box::new(menu_action("x", &["Search", "x"], None)));
        t.add_action(Box::new(menu_action("y", &["&Edit", "y"], None)));
        t.add_action(Box::new(menu_action("z", &["&File", "z"], None)));
        t.set_menu_group(&["&File"], Some("0"), None);
        t.set_menu_group(&["&Edit"], Some("1"), None);
        let bar = menu_bar(&t, &DefaultActionContext::new());
        assert_eq!(names(&bar), vec!["File", "Edit", "Search"]);
        let MenuEntry::Submenu { mnemonic, .. } = &bar[0] else { panic!() };
        assert_eq!(*mnemonic, Some('F'));
    }

    #[test]
    fn menubar_order_is_file_edit_alphabetical_window_help() {
        let mut t = DockingTool::new("T");
        for top in ["Help", "Window", "Navigation", "&File", "Analysis", "&Edit"] {
            t.add_action(Box::new(menu_action(top, &[top, "x"], None)));
        }
        let bar = menu_bar(&t, &DefaultActionContext::new());
        assert_eq!(names(&bar), vec!["File", "Edit", "Analysis", "Navigation", "Window", "Help"]);
    }

    #[test]
    fn parent_menu_group_wins_over_map_but_not_at_the_menubar_root() {
        let mut t = DockingTool::new("T");
        let mut a = DockingAction::new("Deep", "T");
        let mut md = MenuData::new(&["File", "Sub", "Deep"]).unwrap();
        md.set_parent_menu_group(Some("aaa")).unwrap();
        a.set_menu_bar_data(Some(md));
        t.add_action(Box::new(Act(a)));
        t.add_action(Box::new(menu_action("Z", &["File", "Z"], Some("m"))));
        t.set_menu_group(&["File", "Sub"], Some("zzz"), None);
        let bar = menu_bar(&t, &DefaultActionContext::new());
        let MenuEntry::Submenu { children, .. } = &bar[0] else { panic!() };
        // "Sub" uses its parentMenuGroup "aaa" (< "m"), not the map's "zzz"
        assert_eq!(names(children), vec!["Sub", "---", "Z"]);
    }

    #[test]
    fn popup_submenus_have_no_separator_after_null_group_items() {
        let mut p = DockingTool::new("P");
        let mut a = DockingAction::new("A", "T");
        a.set_popup_menu_data(MenuData::full(&["More", "A"], None, None, None, None).ok());
        let mut b = DockingAction::new("B", "T");
        b.set_popup_menu_data(MenuData::full(&["More", "B"], None, Some("x"), None, None).ok());
        p.add_action(Box::new(Act(a)));
        p.add_action(Box::new(Act(b)));
        let pop = popup(&p, None, &DefaultActionContext::new());
        let MenuEntry::Submenu { children, .. } = &pop[0] else { panic!("{pop:?}") };
        // Java MenuManager.getMenu: no separator when the previous group is null
        assert_eq!(names(children), vec!["A", "B"]);
    }

    #[test]
    fn key_text_uses_ghidra_form() {
        use ghidra_rs::docking::action::KeyBindingData;
        use ghidra_rs::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};
        use ghidra_rs::util::awt::KeyStroke;
        let mut t = DockingTool::new("T");
        let mut c = menu_action("Copy", &["Edit", "Copy"], None);
        c.0.set_key_binding_data(Some(KeyBindingData::new(KeyStroke::new(vk::C, CTRL_DOWN_MASK))));
        t.add_action(Box::new(c));
        let bar = menu_bar(&t, &DefaultActionContext::new());
        let MenuEntry::Submenu { children, .. } = &bar[0] else { panic!() };
        match &children[0] {
            MenuEntry::Item { key_text, .. } => assert_eq!(key_text, "Ctrl-C"),
            other => panic!("{other:?}"),
        }
    }
}
